// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/mandates — spending-mandate revocation and shared redemption.
 *
 *   POST /v1/mandates/:mandateId/revoke                    revoke (signed by a grantor in the chain) — no API key, rate limited
 *   GET  /v1/mandates/:mandateId/revoked?grantor=…         { revoked, revokedAt?, checkedAt, statusSignature, statusKeyId } — public
 *   POST /v1/mandates/:mandateId/redeem                    atomic cumulative redemption             — API key
 *   GET  /v1/mandates/:mandateId/redemptions?grantor=…     { redeemedMicros }                       — API key
 *
 * Clients: @aroha-sdk/credentials revokeMandate / httpRevocationCheck /
 * httpRedemptionStore.
 *
 * WHY THE REGISTRY. The SDK's verifier has always asked an `isRevoked` hook
 * about every link, and its redemption has always gone through a
 * RedemptionStore — but nothing answered either question outside one
 * process. A human who wanted to withdraw the intent mandate they gave an
 * agent had nowhere to say so, and two payees honouring one payment mandate
 * each kept their own running total. The registry is already the place
 * verifiers look up keys and KELs; it is the natural shared memory for these
 * two facts as well.
 *
 * WHY THE SAME VERIFIER. Both write endpoints run the token through
 * @aroha-sdk/credentials' verifyMandateChain (via the Worker-safe
 * `./mandates` entry point) — not a server-side re-implementation. A second
 * copy of the chain rules would drift, and a drift here is either a
 * revocation an attacker can forge or a redemption cap a payee can dodge.
 *
 * KEYS. Chain keys are resolved the way the registry vouches for keys
 * elsewhere: a content-addressed `did:aroha:z…` from the DID itself; a
 * rotatable `did:aroha:E…` from the registry's stored, verified KEL (current
 * key; revoked identities and revoked controllers refuse); a named DID from
 * its ACTIVE agent row.
 *
 * WHO MAY REVOKE. The revoker must be the grantor of the token's leaf or of
 * any ancestor — authority flows down a chain, so anyone above a mandate may
 * withdraw it, and nobody else. The token must verify (so a forged
 * "ancestor" cannot be inserted), the revoker must appear as a grantor in
 * it, and the signature over mandateRevocationPayload(mandateId, revokedAt)
 * must verify under the revoker's resolved key. Revocations are permanent and
 * first-wins (a later signed revocation of the same mandate changes nothing).
 * An already-expired chain cannot be revoked: it no longer authorises
 * anything, and verifying it would fail the time window anyway.
 *
 * IDENTITY. A mandate is (grantor, mandateId), never the bare id. The id is
 * chosen by whoever mints the mandate, so anyone holding a key can mint a
 * perfectly valid chain of their own that reuses a victim's id. Keyed by id
 * alone, revoking that chain would revoke the victim's mandate, and redeeming
 * against it would spend the victim's cap. The grantor is fixed by the
 * mandate's signature, so both tables and both GETs are keyed by the pair.
 *
 * SHARED SIGNALS. A newly recorded revocation is also emitted as signed
 * SETs (CAEP session-revoked + Aroha mandate-revoked) to every subscribed
 * SSF stream — see ssf.ts and routes/ssf.ts.
 *
 * REDEMPTION LIMIT. The caller's idea of the limit is never used. The
 * registry verifies the token (chain, revocation — including this registry's
 * own revocations — tier, expiry), requires a payment mandate, applies the
 * merchant allow-list, and derives the limit as min(spendLimitUsd,
 * sessionLimitUsd) of the VERIFIED leaf, in integer micro-USD. The add is a
 * D1RedemptionStore check-and-add, atomic in one D1 batch.
 *
 * SIGNED STATUS. The revocation answer decides whether money moves, yet it
 * used to be plain JSON — only as trustworthy as the transport and every
 * cache or proxy in between. It is now signed with the registry key
 * (registry-signing.ts) over JCS of { purpose: "aroha.revocation-status/v1",
 * mandateId, grantor, revoked, revokedAt?, checkedAt }; checkedAt lets a
 * verifier refuse a stale (replayed) "not revoked". With no usable
 * REGISTRY_SIGNING_KEY the endpoint answers 503 rather than an unsigned
 * status a pinned verifier would reject anyway.
 */

import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { isInceptionDid, type KelSource } from "@aroha-sdk/core/identity";
import {
  verifyMandateChain,
  decodeMandateToken,
  resolveContentAddressedKey,
  mandateRevocationPayload,
  mandateRedemptionKey,
  D1RedemptionStore,
  type MandateKeyResolver,
} from "@aroha-sdk/credentials/mandates";
import type { HonoEnv } from "../index.js";
import type { RegistryRepository } from "../repository.js";
import { authMiddleware } from "../auth.js";
import { rateLimiter, authKeyId } from "../middleware/rate-limit.js";
import { RepositoryKelStore } from "../kel-store.js";
import { hashDID } from "./agents.js";
import { REGISTRY_SIGNING_UNCONFIGURED_MESSAGE, currentSigningKey, signJcs } from "../registry-signing.js";
import { emitSecurityEvents, mandateRevokedEvents, settleInBackground } from "../ssf.js";

export const REVOCATION_STATUS_PURPOSE = "aroha.revocation-status/v1";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** A mandate token carries its chain (≤ 8 links by default); 64 KiB is generous. */
const MAX_MANDATE_BODY_BYTES = 64 * 1024;
/** A revocation's signed revokedAt may not lie further in the future than this. */
const MAX_REVOCATION_FUTURE_SKEW_MS = 5 * 60_000;
const MICROS_PER_USD = 1_000_000;

const mandateBodyLimit = bodyLimit({
  maxSize: MAX_MANDATE_BODY_BYTES,
  onError: (c) => c.json({ error: `request body exceeds ${MAX_MANDATE_BODY_BYTES} bytes` }, 413),
});

/** Revocation needs no API key (the signature is the authority) — bound its CPU per IP. */
const revokeLimiter = rateLimiter({
  windowMs: 60_000,
  max: 30,
  keyFn: (c) => `mandate-revoke:${c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown"}`,
  message: "Too many revocation requests — try again later",
});

/** Each redemption re-verifies a chain; 120/min per API key, like allocate. */
const redeemLimiter = rateLimiter({
  windowMs: 60_000,
  max: 120,
  keyFn: async (c) => `mandate-redeem:${await authKeyId(c)}`,
  message: "Too many redemption requests — wait 60 seconds",
});

function b64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Resolver for chain keys — see "KEYS" above. E-DIDs go through kelSource instead. */
export function registryKeyResolver(repo: RegistryRepository): MandateKeyResolver {
  return async (did) => {
    if (isInceptionDid(did)) return null; // only via the verified KEL (kelSource)
    const derived = await resolveContentAddressedKey(did);
    if (derived) return derived;
    if (did.startsWith("did:aroha:z")) return null; // look-alike; never fall through to a row
    const agent = await repo.getAgent(hashDID(did));
    if (!agent || !agent.active || agent.did !== did) return null;
    const key = b64ToBytes(agent.publicKeyB64);
    return key && key.length === 32 ? key : null;
  };
}

export function kelSourceFor(repo: RegistryRepository): KelSource {
  const store = new RepositoryKelStore(repo);
  return (did) => store.get(did);
}

export async function revocationRow(
  db: D1Database,
  mandateId: string,
  grantor: string,
): Promise<{ revoked_at: number; revoked_by: string } | null> {
  return db
    .prepare(`SELECT revoked_at, revoked_by FROM mandate_revocations WHERE mandate_id = ? AND grantor = ?`)
    .bind(mandateId, grantor)
    .first<{ revoked_at: number; revoked_by: string }>();
}

function mandateIdParam(raw: string | undefined): string {
  return decodeURIComponent(raw ?? "");
}

/** The `grantor` query parameter both GETs require — see IDENTITY above. */
function grantorQuery(raw: string | undefined): string | null {
  return typeof raw === "string" && raw.length > 0 && raw.length <= 512 && !raw.includes("#") ? raw : null;
}

export const mandateRoutes = new Hono<HonoEnv>();

// ─── POST /v1/mandates/:mandateId/revoke ──────────────────────────────────────

/**
 * Body: { token, revokedAt, revoker, signature }
 *   token      the mandate token whose LEAF is :mandateId (its chain proves the revoker's place)
 *   revokedAt  ISO 8601 instant, signed
 *   revoker    DID of the grantor (leaf or ancestor) signing the revocation
 *   signature  base64url Ed25519 over mandateRevocationPayload(mandateId, revokedAt)
 *
 *   200 { mandateId, revoked: true, revokedAt, revokedBy, existing? }
 *   400 malformed / token does not verify / leaf is not :mandateId
 *   403 revoker is not a grantor in the chain, or the signature does not verify
 */
mandateRoutes.post("/:mandateId/revoke", revokeLimiter, mandateBodyLimit, async (c) => {
  const mandateId = mandateIdParam(c.req.param("mandateId"));
  const body = await c.req
    .json<{ token?: unknown; revokedAt?: unknown; revoker?: unknown; signature?: unknown }>()
    .catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const { token, revokedAt, revoker, signature } = body;
  if (typeof token !== "string" || typeof revokedAt !== "string" || typeof revoker !== "string" || typeof signature !== "string") {
    return c.json({ error: "token, revokedAt, revoker and signature (strings) are required" }, 400);
  }
  const revokedAtMs = Date.parse(revokedAt);
  if (Number.isNaN(revokedAtMs)) return c.json({ error: "revokedAt must be an ISO 8601 date" }, 400);
  if (revokedAtMs > Date.now() + MAX_REVOCATION_FUTURE_SKEW_MS) {
    return c.json({ error: "revokedAt is in the future" }, 400);
  }

  try {
    if (decodeMandateToken(token).mandate.mandateId !== mandateId) {
      return c.json({ error: "the token's mandate is not :mandateId" }, 400);
    }
  } catch (e) {
    return c.json({ error: `token: ${(e as Error).message}` }, 400);
  }

  const repo = c.get("repo");
  const resolveKey = registryKeyResolver(repo);
  const kelSource = kelSourceFor(repo);
  const verified = await verifyMandateChain(token, resolveKey, { kelSource });
  if (!verified.valid || !verified.chain || !verified.mandate) {
    return c.json({ error: `mandate chain does not verify: ${verified.reason ?? "unknown"}` }, 400);
  }
  // The revoked mandate's own grantor, as its verified signature fixes it.
  const grantor = verified.mandate.grantor;
  if (!verified.chain.some((m) => m.grantor === revoker)) {
    return c.json({ error: "revoker is not a grantor in this mandate's chain" }, 403);
  }

  // The revoker's key, resolved exactly as the chain's keys were.
  let revokerKey: Uint8Array | null;
  if (isInceptionDid(revoker)) {
    const { kelKeyResolver } = await import("@aroha-sdk/core/identity");
    revokerKey = await kelKeyResolver(kelSource)(revoker);
  } else {
    revokerKey = await resolveKey(revoker);
  }
  if (!revokerKey) return c.json({ error: `cannot resolve a current key for ${revoker}` }, 403);
  const sigBytes = b64ToBytes(signature);
  let ok = false;
  try {
    ok = sigBytes !== null && (await ed.verifyAsync(
      sigBytes,
      new TextEncoder().encode(mandateRevocationPayload(mandateId, revokedAt)),
      revokerKey,
    ));
  } catch {
    ok = false;
  }
  if (!ok) return c.json({ error: "revocation signature does not verify under the revoker's key" }, 403);

  const db = c.env.DB;
  const insert = await db
    .prepare(
      `INSERT OR IGNORE INTO mandate_revocations (mandate_id, grantor, revoked_at, revoked_by, signature, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(mandateId, grantor, revokedAtMs, revoker, signature, Date.now())
    .run();
  const row = await revocationRow(db, mandateId, grantor);
  // A NEW revocation is announced to Shared Signals receivers (ssf.ts):
  // queued durably here, pushed within this request's lifetime. A repeat of
  // an existing revocation announces nothing. Emission never fails the revoke.
  if (insert.meta.changes !== 0) {
    const { pushes } = await emitSecurityEvents(c.env, mandateRevokedEvents({
      mandateId,
      grantor,
      revokedBy: row?.revoked_by ?? revoker,
      revokedAtMs: row?.revoked_at ?? revokedAtMs,
    }));
    await settleInBackground(c, pushes);
  }
  return c.json({
    mandateId,
    grantor,
    revoked: true,
    revokedAt: new Date(row?.revoked_at ?? revokedAtMs).toISOString(),
    revokedBy: row?.revoked_by ?? revoker,
    ...(insert.meta.changes === 0 ? { existing: true } : {}),
  });
});

// ─── GET /v1/mandates/:mandateId/revoked ──────────────────────────────────────

/**
 * { mandateId, grantor, revoked, revokedAt?, revokedBy?, checkedAt, statusSignature, statusKeyId } — public.
 * statusSignature: base64url Ed25519 over JCS of
 *   { purpose: "aroha.revocation-status/v1", mandateId, grantor, revoked, revokedAt?, checkedAt }
 * (revokedBy is informational and not signed). 503 when no signing key is configured.
 */
mandateRoutes.get("/:mandateId/revoked", async (c) => {
  const mandateId = mandateIdParam(c.req.param("mandateId"));
  const grantor = grantorQuery(c.req.query("grantor"));
  if (!grantor) return c.json({ error: "?grantor=<the mandate's grantor DID> is required" }, 400);
  const key = currentSigningKey(c.env);
  if (!key) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
  const row = await revocationRow(c.env.DB, mandateId, grantor);
  const checkedAt = new Date().toISOString();
  const status = row
    ? { purpose: REVOCATION_STATUS_PURPOSE, mandateId, grantor, revoked: true, revokedAt: new Date(row.revoked_at).toISOString(), checkedAt }
    : { purpose: REVOCATION_STATUS_PURPOSE, mandateId, grantor, revoked: false, checkedAt };
  // Revocation status is meant to be checked by every verifier, on every
  // link, so it must not be cached by an intermediary past the moment it changes.
  c.header("Cache-Control", "no-store");
  const { purpose: _purpose, ...unsigned } = status;
  return c.json({
    ...unsigned,
    ...(row ? { revokedBy: row.revoked_by } : {}),
    statusSignature: signJcs(status, key),
    statusKeyId: key.keyId,
  });
});

// ─── POST /v1/mandates/:mandateId/redeem ──────────────────────────────────────

/**
 * Body: { token, amountMicros, merchant, redemptionId? }
 *
 *   200 { accepted: true,  redeemedMicros, limitMicros, redemptionId }
 *   409 { accepted: false, redeemedMicros, limitMicros }   would exceed the cumulative limit
 *   409 { error }                                         redemptionId already used for this mandate
 *   400 malformed / token does not verify / not a payment mandate / leaf is not :mandateId
 *   403 merchant not in the mandate's allowedMerchants
 */
mandateRoutes.post("/:mandateId/redeem", redeemLimiter, authMiddleware, mandateBodyLimit, async (c) => {
  const mandateId = mandateIdParam(c.req.param("mandateId"));
  const body = await c.req
    .json<{ token?: unknown; amountMicros?: unknown; merchant?: unknown; redemptionId?: unknown }>()
    .catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const { token, amountMicros, merchant } = body;
  if (typeof token !== "string") return c.json({ error: "token (string) is required" }, 400);
  if (typeof amountMicros !== "number" || !Number.isSafeInteger(amountMicros) || amountMicros <= 0) {
    return c.json({ error: "amountMicros must be a positive integer (micro-USD)" }, 400);
  }
  if (typeof merchant !== "string" || merchant.length === 0) return c.json({ error: "merchant (DID) is required" }, 400);
  const redemptionId =
    typeof body.redemptionId === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(body.redemptionId)
      ? body.redemptionId
      : crypto.randomUUID();

  const db = c.env.DB;
  const repo = c.get("repo");
  const verified = await verifyMandateChain(token, registryKeyResolver(repo), {
    kelSource: kelSourceFor(repo),
    // This registry's own revocations, on every link.
    isRevoked: async (id, grantor) => (await revocationRow(db, id, grantor)) !== null,
  });
  if (!verified.valid || !verified.mandate) {
    return c.json({ error: `mandate chain does not verify: ${verified.reason ?? "unknown"}` }, 400);
  }
  const leaf = verified.mandate;
  if (leaf.mandateId !== mandateId) return c.json({ error: "the token's mandate is not :mandateId" }, 400);
  if (leaf.mandateTier !== "payment") {
    return c.json({ error: `only payment mandates can be redeemed (got ${leaf.mandateTier})` }, 400);
  }
  const { constraints } = leaf;
  if (constraints.allowedMerchants != null && !constraints.allowedMerchants.includes(merchant)) {
    return c.json({ error: `merchant ${merchant} is not in the mandate's allowed merchant list` }, 403);
  }
  const limitMicros = Math.round(
    Math.min(constraints.spendLimitUsd, constraints.sessionLimitUsd ?? Infinity) * MICROS_PER_USD,
  );

  // redemptionId is unique per mandate (migration 017 keys the table by
  // (mandate_id, redemption_id)), so another mandate's ids never collide
  // with this one's. A repeat within this mandate is the caller's own
  // duplicate: answered 409 up front, and — should two requests race past
  // this read — the primary key refuses the second inside the store's
  // batch, which rolls the total back with it; that too is a 409, not a 500.
  const redemptionKey = mandateRedemptionKey(leaf);
  const dupMessage = { error: `redemptionId ${redemptionId} was already used for this mandate` };
  const existing = await db
    .prepare(`SELECT 1 AS ok FROM mandate_redemptions WHERE mandate_id = ? AND redemption_id = ?`)
    .bind(redemptionKey, redemptionId)
    .first<{ ok: number }>();
  if (existing) return c.json(dupMessage, 409);

  const store = new D1RedemptionStore(db, { actor: c.get("keyHash") });
  let result: { accepted: boolean; redeemedMicros: number };
  try {
    result = await store.tryRedeem(redemptionKey, amountMicros, limitMicros, {
      redemptionId,
      mandateId,
      amountUsd: amountMicros / MICROS_PER_USD,
      merchant,
      redeemedAt: new Date().toISOString(),
    });
  } catch (err) {
    if (/UNIQUE constraint failed|SQLITE_CONSTRAINT/i.test(String(err))) return c.json(dupMessage, 409);
    throw err;
  }
  if (!result.accepted) {
    return c.json({ accepted: false, redeemedMicros: result.redeemedMicros, limitMicros }, 409);
  }
  return c.json({ accepted: true, redeemedMicros: result.redeemedMicros, limitMicros, redemptionId });
});

// ─── GET /v1/mandates/:mandateId/redemptions ──────────────────────────────────

/** { mandateId, grantor, redeemedMicros } — API key (spend totals are not public). */
mandateRoutes.get("/:mandateId/redemptions", authMiddleware, async (c) => {
  const mandateId = mandateIdParam(c.req.param("mandateId"));
  const grantor = grantorQuery(c.req.query("grantor"));
  if (!grantor) return c.json({ error: "?grantor=<the mandate's grantor DID> is required" }, 400);
  const redeemedMicros = await new D1RedemptionStore(c.env.DB).redeemedMicros(mandateRedemptionKey({ grantor, mandateId }));
  return c.json({ mandateId, grantor, redeemedMicros });
});
