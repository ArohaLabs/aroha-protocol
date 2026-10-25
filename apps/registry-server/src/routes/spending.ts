// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/spending — remote spending ledger for orchestrators without a D1 binding.
 *
 * Node.js / Python orchestrators that cannot hold a Cloudflare D1 binding
 * directly call these endpoints to enforce mandate spending constraints.
 * Orchestrators running as Cloudflare Workers should use D1SpendingLedger
 * from @aroha-sdk/credentials with their own D1 binding instead.
 *
 * Endpoints:
 *   POST   /v1/spending/budgets                       init a budget from a verified mandate token
 *   POST   /v1/spending/allocate                      atomic deduct from parent budget
 *   POST   /v1/spending/release/:allocationId         return allocation to parent pool
 *   GET    /v1/spending/status/:mandateId?grantor=…   query budget state
 *
 * All endpoints require a valid API key (Authorization: Bearer <key>).
 *
 * LIMIT FROM THE VERIFIED MANDATE (migration 018). POST /budgets used to take
 * limitUsd from the request body, so any API key holder could open a pool of
 * any size under any mandateId — the ledger then enforced a number nobody
 * had signed. It now takes the mandate token, verifies it with the same path
 * as /v1/mandates (verifyMandateChain + this registry's key resolver, KELs
 * and revocations), and derives the limit as min(spendLimitUsd,
 * sessionLimitUsd) of the VERIFIED leaf and the expiry as the earliest
 * expiresAt in the chain (a caller may only shorten it).
 *
 * IDENTITY. A budget is keyed by mandateRedemptionKey — `<grantor>#<mandateId>`
 * — exactly like redemptions: a mandateId is chosen by its minter, so keyed
 * by id alone anyone could open (and so squat) a pool under someone else's
 * id. allocate / release / status therefore take `grantor` alongside the id.
 *
 * LEGACY ROWS. Pre-018 budgets (limit_source = 'caller') carry an unverified
 * limit and are never served: allocate / release / status answer 404 for
 * them, and POST /budgets with the mandate token replaces one with the same
 * key. They are kept in the table for the operator's inspection.
 *
 * Authorization model:
 *   The API key that calls POST /budgets becomes the budget owner (stored as
 *   owner_key_hash). All subsequent allocate / release / status calls for
 *   that budget must present the same key. Cross-key access returns 403.
 *
 * Atomicity:
 *   The allocate endpoint uses a single conditional UPDATE with owner,
 *   expiry and revocation checks:
 *     UPDATE spending_budgets
 *     SET allocated_usd = allocated_usd + ?
 *     WHERE mandate_id = ? AND owner_key_hash = ? AND allocated_usd + ? <= limit_usd
 *       AND <not expired> AND <no link of chain_keys revoked here>
 *
 *   SQLite serialises writes — meta.changes === 0 unambiguously means the
 *   budget was exhausted, expired, revoked, not found, or belongs to another key.
 *
 * Audit: budget creation and every allocation are recorded with
 * recordAuditAction (admin_audit_log), actor = the calling org.
 */

import { Hono, type Context } from "hono";
import { verifyMandateChain, mandateRedemptionKey } from "@aroha-sdk/credentials/mandates";
import { authMiddleware } from "../auth.js";
import { allocateLimiter, budgetInitLimiter, clientIp } from "../middleware/rate-limit.js";
import type { HonoEnv } from "../index.js";
import { viewerDependentMiddleware } from "../visibility.js";
import { kelSourceFor, registryKeyResolver, revocationRow } from "./mandates.js";

export const spendingRoutes = new Hono<HonoEnv>();
// Every answer here is about the calling org's own spaces / budgets — never
// cacheable, and never the same for two Authorization headers.
spendingRoutes.use("*", viewerDependentMiddleware);

/** Only budgets created from a verified mandate are served — see LEGACY ROWS. */
const VERIFIED = "mandate";

/** `<grantor>#<mandateId>`, or null when either part is unusable. */
function budgetKey(mandateId: unknown, grantor: unknown): string | null {
  if (typeof mandateId !== "string" || mandateId.length === 0 || mandateId.length > 256) return null;
  if (typeof grantor !== "string" || grantor.length === 0 || grantor.length > 512 || grantor.includes("#")) return null;
  return mandateRedemptionKey({ grantor, mandateId });
}

function audit(c: Context<HonoEnv>, action: string, target: string): void {
  // Fire-and-forget, never an unhandled rejection: a failed audit write must
  // not fail the spend operation, and is logged so the gap is visible.
  void c.get("repo").recordAuditAction(action, c.get("orgName"), target, clientIp(c))
    .catch((err) => console.error(`[audit] ${action} not recorded:`, err));
}

/**
 * Revocation guard used inside allocate's UPDATE: true when any link of the
 * budget's verified chain has been revoked at this registry since creation.
 */
const CHAIN_REVOKED_SQL = `EXISTS (
  SELECT 1 FROM mandate_revocations r, json_each(COALESCE(spending_budgets.chain_keys, '[]')) j
  WHERE j.value = r.grantor || '#' || r.mandate_id
)`;

// ─── POST /v1/spending/budgets ───────────────────────────────────────────────

/**
 * Body: { token, expiresAt? }
 *   token      the mandate token whose verified leaf the budget is for
 *   expiresAt  optional Unix ms; may only shorten the chain's own expiry
 *
 *   201 { ok, mandateId, grantor, budgetKey, limitUsd, expiresAt, existing? }
 *   400 malformed / token does not verify / non-positive derived limit
 *   409 a budget for this mandate is already owned by another API key
 */
spendingRoutes.post("/budgets", budgetInitLimiter, authMiddleware, async (c) => {
  const body = await c.req.json<{ token?: unknown; expiresAt?: unknown }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  if (typeof body.token !== "string") {
    // limitUsd is no longer accepted: the limit is the verified mandate's.
    return c.json({ error: "token (the mandate token) is required — the limit is derived from the verified mandate" }, 400);
  }
  if (body.expiresAt !== undefined && (typeof body.expiresAt !== "number" || body.expiresAt <= Date.now())) {
    return c.json({ error: "expiresAt must be a future Unix ms timestamp" }, 400);
  }

  const db = c.env.DB;
  const repo = c.get("repo");
  const verified = await verifyMandateChain(body.token, registryKeyResolver(repo), {
    kelSource: kelSourceFor(repo),
    // This registry's own revocations, on every link.
    isRevoked: async (id, grantor) => (await revocationRow(db, id, grantor)) !== null,
  });
  if (!verified.valid || !verified.mandate || !verified.chain) {
    return c.json({ error: `mandate chain does not verify: ${verified.reason ?? "unknown"}` }, 400);
  }
  const leaf = verified.mandate;
  const limitUsd = Math.min(leaf.constraints.spendLimitUsd, leaf.constraints.sessionLimitUsd ?? Infinity);
  if (!Number.isFinite(limitUsd) || limitUsd <= 0) {
    return c.json({ error: "the verified mandate's limit is not a positive amount" }, 400);
  }
  const chainExpiry = Math.min(...verified.chain.map((m) => Date.parse(m.expiresAt)));
  const expiresAt = typeof body.expiresAt === "number" ? Math.min(body.expiresAt, chainExpiry) : chainExpiry;
  const key = mandateRedemptionKey(leaf);
  const chainKeys = JSON.stringify(verified.chain.map((m) => mandateRedemptionKey(m)));
  const keyHash = c.get("keyHash");
  const now = Date.now();

  // A legacy (unverified-limit) row with the same key is replaced, together
  // with its allocations; a verified row is never overwritten (INSERT OR IGNORE).
  const results = await db.batch([
    db.prepare(
      `DELETE FROM spending_allocations WHERE mandate_id IN
         (SELECT mandate_id FROM spending_budgets WHERE mandate_id = ? AND limit_source <> ?)`,
    ).bind(key, VERIFIED),
    db.prepare(`DELETE FROM spending_budgets WHERE mandate_id = ? AND limit_source <> ?`).bind(key, VERIFIED),
    db.prepare(
      `INSERT OR IGNORE INTO spending_budgets
         (mandate_id, limit_usd, allocated_usd, owner_key_hash, expires_at, created_at, limit_source, chain_keys)
       VALUES (?, ?, 0, ?, ?, ?, ?, ?)`,
    ).bind(key, limitUsd, keyHash, expiresAt, now, VERIFIED, chainKeys),
  ]);

  if ((results[2]?.meta.changes ?? 0) === 0) {
    const existing = await db
      .prepare(`SELECT owner_key_hash, limit_usd, expires_at FROM spending_budgets WHERE mandate_id = ?`)
      .bind(key)
      .first<{ owner_key_hash: string; limit_usd: number; expires_at: number | null }>();
    if (existing && existing.owner_key_hash !== keyHash) {
      // Registered under a different key — don't reveal which key.
      return c.json({ error: "A budget for this mandate already exists" }, 409);
    }
    // Caller owns the existing budget — idempotent OK, with the stored terms.
    return c.json({
      ok: true, mandateId: leaf.mandateId, grantor: leaf.grantor, budgetKey: key,
      limitUsd: existing?.limit_usd ?? limitUsd, expiresAt: existing?.expires_at ?? expiresAt, existing: true,
    }, 201);
  }

  audit(c, "spending.budget_created", `${key} limitUsd=${limitUsd}`);
  return c.json({ ok: true, mandateId: leaf.mandateId, grantor: leaf.grantor, budgetKey: key, limitUsd, expiresAt }, 201);
});

// ─── POST /v1/spending/allocate ─────────────────────────────────────────────

/**
 * Body: { parentMandateId, grantor, amountUsd }
 *   200 { allocationId, parentMandateId, grantor, allocatedUsd, remainingUsd }
 *   403 another key's budget · 404 no (verified) budget · 409 BUDGET_EXHAUSTED
 *   410 BUDGET_EXPIRED / MANDATE_REVOKED
 */
spendingRoutes.post("/allocate", allocateLimiter, authMiddleware, async (c) => {
  const body = await c.req.json<{ parentMandateId?: unknown; grantor?: unknown; amountUsd?: unknown }>().catch(
    () => ({} as Record<string, never>),
  );

  const key = budgetKey(body.parentMandateId, body.grantor);
  if (!key || typeof body.amountUsd !== "number") {
    return c.json({ error: "parentMandateId (string), grantor (the mandate's grantor DID) and amountUsd (number) are required" }, 400);
  }
  if (!Number.isFinite(body.amountUsd) || body.amountUsd <= 0) {
    return c.json({ error: "amountUsd must be positive" }, 400);
  }
  const amountUsd = body.amountUsd;

  const db = c.env.DB;
  const keyHash = c.get("keyHash");
  const allocationId = crypto.randomUUID();
  const now = Date.now();

  // Two-statement batch: atomic conditional UPDATE + INSERT guarded by changes().
  // owner_key_hash + expires_at + revocation guard cross-tenant, expired and
  // withdrawn access. If the UPDATE guard rejects, changes() = 0 and the
  // INSERT is a no-op. (Writable CTEs are not supported in all SQLite builds;
  // batch+changes() is portable.)
  const [updateResult] = await db.batch([
    db
      .prepare(
        `UPDATE spending_budgets
         SET allocated_usd = allocated_usd + ?
         WHERE mandate_id = ?
           AND limit_source = ?
           AND owner_key_hash = ?
           AND allocated_usd + ? <= limit_usd
           AND (expires_at IS NULL OR expires_at > ?)
           AND NOT ${CHAIN_REVOKED_SQL}`,
      )
      .bind(amountUsd, key, VERIFIED, keyHash, amountUsd, now),
    db
      .prepare(
        `INSERT INTO spending_allocations (allocation_id, mandate_id, amount_usd, allocated_at)
         SELECT ?, ?, ?, ? WHERE (SELECT changes()) > 0`,
      )
      .bind(allocationId, key, amountUsd, now),
  ]);

  if (updateResult!.meta.changes === 0) {
    // Distinguish: not found / wrong owner / expired / revoked / budget exhausted.
    const budget = await db
      .prepare(
        `SELECT limit_usd, allocated_usd, owner_key_hash, expires_at, ${CHAIN_REVOKED_SQL} AS revoked
         FROM spending_budgets WHERE mandate_id = ? AND limit_source = ?`,
      )
      .bind(key, VERIFIED)
      .first<{ limit_usd: number; allocated_usd: number; owner_key_hash: string; expires_at: number | null; revoked: number }>();

    if (!budget) {
      return c.json({ error: `No budget registered for mandate ${body.parentMandateId as string}` }, 404);
    }
    if (budget.owner_key_hash !== keyHash) {
      return c.json({ error: "Forbidden — this budget belongs to another API key" }, 403);
    }
    if (budget.expires_at !== null && budget.expires_at <= now) {
      return c.json({ error: "BUDGET_EXPIRED", mandateId: body.parentMandateId }, 410);
    }
    if (budget.revoked) {
      return c.json({ error: "MANDATE_REVOKED", mandateId: body.parentMandateId }, 410);
    }

    const remaining = budget.limit_usd - budget.allocated_usd;
    return c.json(
      {
        error: "BUDGET_EXHAUSTED",
        mandateId: body.parentMandateId,
        requestedUsd: amountUsd,
        remainingUsd: remaining,
      },
      409,
    );
  }

  const budget = await db
    .prepare(`SELECT limit_usd, allocated_usd FROM spending_budgets WHERE mandate_id = ?`)
    .bind(key)
    .first<{ limit_usd: number; allocated_usd: number }>();

  audit(c, "spending.allocated", `${key} allocation=${allocationId} amountUsd=${amountUsd}`);
  return c.json({
    allocationId,
    parentMandateId: body.parentMandateId,
    grantor: body.grantor,
    allocatedUsd: amountUsd,
    remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0,
  });
});

// ─── POST /v1/spending/release/:allocationId ─────────────────────────────────

/** Body: { parentMandateId, grantor } — 200 { ok, released, releasedUsd?, remainingUsd }. */
spendingRoutes.post("/release/:allocationId", authMiddleware, async (c) => {
  const allocationId = c.req.param("allocationId")!;
  const body = await c.req.json<{ parentMandateId?: unknown; grantor?: unknown }>().catch(
    () => ({} as Record<string, never>),
  );

  const key = budgetKey(body.parentMandateId, body.grantor);
  if (!key) {
    return c.json({ error: "parentMandateId and grantor (the mandate's grantor DID) are required in the request body" }, 400);
  }

  const db = c.env.DB;
  const keyHash = c.get("keyHash");
  const now = Date.now();

  // Verify ownership by JOINing through to spending_budgets.owner_key_hash.
  const alloc = await db
    .prepare(
      `SELECT a.amount_usd
       FROM spending_allocations a
       JOIN spending_budgets b ON b.mandate_id = a.mandate_id
       WHERE a.allocation_id = ? AND a.mandate_id = ? AND b.limit_source = ?
         AND b.owner_key_hash = ? AND a.released_at IS NULL`,
    )
    .bind(allocationId, key, VERIFIED, keyHash)
    .first<{ amount_usd: number }>();

  if (!alloc) {
    // Check if this is a 403 (wrong owner) vs idempotent no-op.
    const anyAlloc = await db
      .prepare(
        `SELECT b.owner_key_hash
         FROM spending_allocations a
         JOIN spending_budgets b ON b.mandate_id = a.mandate_id
         WHERE a.allocation_id = ? AND a.mandate_id = ? AND b.limit_source = ?`,
      )
      .bind(allocationId, key, VERIFIED)
      .first<{ owner_key_hash: string }>();

    if (anyAlloc && anyAlloc.owner_key_hash !== keyHash) {
      return c.json({ error: "Forbidden — this allocation belongs to another API key" }, 403);
    }

    // Already released or allocation not found — idempotent, return current balance.
    const budget = await db
      .prepare(
        `SELECT limit_usd, allocated_usd FROM spending_budgets
         WHERE mandate_id = ? AND owner_key_hash = ? AND limit_source = ?`,
      )
      .bind(key, keyHash, VERIFIED)
      .first<{ limit_usd: number; allocated_usd: number }>();
    return c.json({
      ok: true,
      released: false,
      remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0,
    });
  }

  await db.batch([
    db
      .prepare(`UPDATE spending_allocations SET released_at = ? WHERE allocation_id = ?`)
      .bind(now, allocationId),
    db
      .prepare(
        `UPDATE spending_budgets
         SET allocated_usd = MAX(0, allocated_usd - ?)
         WHERE mandate_id = ? AND owner_key_hash = ?`,
      )
      .bind(alloc.amount_usd, key, keyHash),
  ]);

  const budget = await db
    .prepare(
      `SELECT limit_usd, allocated_usd FROM spending_budgets
       WHERE mandate_id = ? AND owner_key_hash = ?`,
    )
    .bind(key, keyHash)
    .first<{ limit_usd: number; allocated_usd: number }>();

  return c.json({
    ok: true,
    released: true,
    releasedUsd: alloc.amount_usd,
    remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0,
  });
});

// ─── GET /v1/spending/status/:mandateId?grantor=… ────────────────────────────

spendingRoutes.get("/status/:mandateId", authMiddleware, async (c) => {
  const mandateId = decodeURIComponent(c.req.param("mandateId") ?? "");
  const grantor = c.req.query("grantor");
  const key = budgetKey(mandateId, grantor);
  if (!key) return c.json({ error: "?grantor=<the mandate's grantor DID> is required" }, 400);
  const db = c.env.DB;
  const keyHash = c.get("keyHash");

  const row = await db
    .prepare(
      `SELECT b.limit_usd, b.allocated_usd, b.created_at, b.owner_key_hash, b.expires_at,
              COUNT(CASE WHEN a.released_at IS NULL THEN 1 END) AS active_allocations
       FROM spending_budgets b
       LEFT JOIN spending_allocations a ON a.mandate_id = b.mandate_id
       WHERE b.mandate_id = ? AND b.limit_source = ?
       GROUP BY b.mandate_id`,
    )
    .bind(key, VERIFIED)
    .first<{
      limit_usd: number;
      allocated_usd: number;
      created_at: number;
      owner_key_hash: string;
      expires_at: number | null;
      active_allocations: number;
    }>();

  if (!row) return c.json({ error: "Budget not found for mandate" }, 404);
  if (row.owner_key_hash !== keyHash) {
    return c.json({ error: "Forbidden — this budget belongs to another API key" }, 403);
  }

  // Opportunistic GC: prune a batch of expired budgets while we hold the DB.
  // Runs fire-and-forget so it never delays the response.
  db.prepare(
    `DELETE FROM spending_budgets
     WHERE mandate_id IN (
       SELECT mandate_id FROM spending_budgets
       WHERE expires_at IS NOT NULL AND expires_at < ?
       LIMIT 50
     )`,
  )
    .bind(Date.now())
    .run()
    .catch(() => {/* intentionally silent */});

  return c.json({
    mandateId,
    grantor,
    limitUsd: row.limit_usd,
    allocatedUsd: row.allocated_usd,
    remainingUsd: row.limit_usd - row.allocated_usd,
    allocationCount: row.active_allocations,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? null,
  });
});
