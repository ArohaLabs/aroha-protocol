// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * D1SpendingLedger — Cloudflare D1 (SQLite) implementation of ISpendingLedger.
 *
 * Drop-in replacement for MapSpendingLedger in Cloudflare Worker orchestrators.
 * Provides SQLite-level atomicity via a conditional UPDATE guard:
 *
 *   UPDATE spending_budgets
 *   SET allocated_usd = allocated_usd + ?
 *   WHERE mandate_id = ? AND allocated_usd + ? <= limit_usd
 *
 * SQLite serialises writes — this UPDATE is atomic. meta.changes === 0 means
 * either the mandate was not found or the budget is exhausted.
 * No SELECT FOR UPDATE or explicit transaction needed.
 *
 * Required schema (include in your Worker's D1 migration):
 *
 *   CREATE TABLE IF NOT EXISTS spending_budgets (
 *     mandate_id     TEXT PRIMARY KEY,
 *     limit_usd      REAL NOT NULL CHECK (limit_usd > 0),
 *     allocated_usd  REAL NOT NULL DEFAULT 0 CHECK (allocated_usd >= 0),
 *     owner_key_hash TEXT NOT NULL DEFAULT '',  -- tenant scope; '' = unscoped
 *     expires_at     INTEGER,                   -- Unix ms; NULL = no expiry
 *     created_at     INTEGER NOT NULL
 *   );
 *
 *   CREATE TABLE IF NOT EXISTS spending_allocations (
 *     allocation_id TEXT    PRIMARY KEY,
 *     mandate_id    TEXT    NOT NULL,
 *     amount_usd    REAL    NOT NULL CHECK (amount_usd > 0),
 *     allocated_at  INTEGER NOT NULL,
 *     released_at   INTEGER,
 *     FOREIGN KEY (mandate_id) REFERENCES spending_budgets (mandate_id) ON DELETE CASCADE
 *   );
 *
 * Usage (inside a Cloudflare Worker):
 *
 *   const ledger = new D1SpendingLedger(env.DB);
 *   const mandate = await issueIntentMandate(
 *     grantor, grantee, { spendLimitUsd: 500 }, privateKey, undefined,
 *     { ledger }
 *   );
 */

import type {
  ISpendingLedger,
  AllocationResult,
  BudgetStatus,
} from "./spending-ledger.js";
import { BudgetExhaustedError } from "./spending-ledger.js";

// ─── Minimal duck-typed D1 interface ─────────────────────────────────────────
// Avoids a hard dep on @cloudflare/workers-types in the SDK.
// The real D1Database satisfies this by structural subtyping.

interface D1RunResult {
  meta: { changes: number };
}

interface D1Statement {
  bind(...values: unknown[]): D1Statement;
  run(): Promise<D1RunResult>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export interface D1LikeDatabase {
  prepare(query: string): D1Statement;
  batch(statements: D1Statement[]): Promise<D1RunResult[]>;
}

// ─── D1SpendingLedger ─────────────────────────────────────────────────────────

export class D1SpendingLedger implements ISpendingLedger {
  /**
   * @param db            D1-compatible database (D1Database in Workers, SqliteD1 in tests).
   * @param ownerKeyHash  SHA-256 hex of the API key that owns all budgets managed by this
   *                      instance. Stored on init() and checked on allocate/release/status.
   *                      Pass "" (default) for single-tenant Workers where one ledger = one org.
   */
  constructor(
    private readonly db: D1LikeDatabase,
    private readonly ownerKeyHash = "",
  ) {}

  /**
   * Register a mandate's budget. Idempotent — subsequent calls with the same
   * mandateId are silently ignored (INSERT OR IGNORE).
   *
   * @param expiresAt  Unix ms timestamp matching the mandate token's own expiry.
   *                   allocate() will reject once this time passes.
   */
  async init(mandateId: string, limitUsd: number, expiresAt?: number): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO spending_budgets
           (mandate_id, limit_usd, allocated_usd, owner_key_hash, expires_at, created_at)
         VALUES (?, ?, 0, ?, ?, ?)`,
      )
      .bind(mandateId, limitUsd, this.ownerKeyHash, expiresAt ?? null, Date.now())
      .run();
  }

  /**
   * Atomically deduct amountUsd from the parent mandate's remaining balance.
   *
   * The guard is a single conditional UPDATE — no explicit transaction required.
   * SQLite serialises writes, so this is equivalent to a compare-and-swap.
   *
   * Throws BudgetExhaustedError if insufficient balance or mandate not found.
   */
  async allocate(parentMandateId: string, amountUsd: number): Promise<AllocationResult> {
    const allocationId = crypto.randomUUID();
    const now = Date.now();

    // batch() executes both statements in a single D1 transaction.
    // Statement 1: Atomic CAS — the WHERE guard atomically checks AND deducts.
    // Statement 2: INSERT only if statement 1 changed a row. SQLite's changes()
    //   reads the previous statement's affected-row count within the same connection.
    //   If the UPDATE guard rejects, changes() = 0 and INSERT is a no-op.
    // (SQLite writable CTEs are not supported in all builds, so changes() is used.)
    const [updateResult] = await this.db.batch([
      this.db
        .prepare(
          `UPDATE spending_budgets
           SET allocated_usd = allocated_usd + ?
           WHERE mandate_id = ?
             AND (? = '' OR owner_key_hash = ?)
             AND allocated_usd + ? <= limit_usd
             AND (expires_at IS NULL OR expires_at > ?)`,
        )
        .bind(amountUsd, parentMandateId, this.ownerKeyHash, this.ownerKeyHash, amountUsd, now),
      this.db
        .prepare(
          `INSERT INTO spending_allocations (allocation_id, mandate_id, amount_usd, allocated_at)
           SELECT ?, ?, ?, ? WHERE (SELECT changes()) > 0`,
        )
        .bind(allocationId, parentMandateId, amountUsd, now),
    ]);

    if (updateResult.meta.changes === 0) {
      const budget = await this.db
        .prepare(`SELECT limit_usd, allocated_usd FROM spending_budgets WHERE mandate_id = ?`)
        .bind(parentMandateId)
        .first<{ limit_usd: number; allocated_usd: number }>();

      const remaining = budget ? budget.limit_usd - budget.allocated_usd : 0;
      throw new BudgetExhaustedError(parentMandateId, amountUsd, remaining);
    }

    const budget = await this.db
      .prepare(`SELECT limit_usd, allocated_usd FROM spending_budgets WHERE mandate_id = ?`)
      .bind(parentMandateId)
      .first<{ limit_usd: number; allocated_usd: number }>();

    return {
      allocationId,
      remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0,
    };
  }

  /**
   * Return an allocated amount to the parent's available pool.
   * Called during saga compensation or on mandate expiry.
   * Idempotent — unknown or already-released allocationIds are silently ignored.
   */
  async release(
    parentMandateId: string,
    allocationId: string,
  ): Promise<{ remainingUsd: number }> {
    const now = Date.now();

    const alloc = await this.db
      .prepare(
        `SELECT sa.amount_usd FROM spending_allocations sa
         JOIN spending_budgets sb ON sb.mandate_id = sa.mandate_id
         WHERE sa.allocation_id = ? AND sa.mandate_id = ? AND sa.released_at IS NULL
           AND (? = '' OR sb.owner_key_hash = ?)`,
      )
      .bind(allocationId, parentMandateId, this.ownerKeyHash, this.ownerKeyHash)
      .first<{ amount_usd: number }>();

    if (!alloc) {
      // Already released or allocation_id unknown — idempotent no-op.
      const budget = await this.db
        .prepare(`SELECT limit_usd, allocated_usd FROM spending_budgets WHERE mandate_id = ?`)
        .bind(parentMandateId)
        .first<{ limit_usd: number; allocated_usd: number }>();
      return { remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0 };
    }

    // Mark released + decrement atomically — both or neither.
    await this.db.batch([
      this.db
        .prepare(`UPDATE spending_allocations SET released_at = ? WHERE allocation_id = ?`)
        .bind(now, allocationId),
      this.db
        .prepare(
          `UPDATE spending_budgets
           SET allocated_usd = MAX(0, allocated_usd - ?)
           WHERE mandate_id = ?`,
        )
        .bind(alloc.amount_usd, parentMandateId),
    ]);

    const budget = await this.db
      .prepare(`SELECT limit_usd, allocated_usd FROM spending_budgets WHERE mandate_id = ?`)
      .bind(parentMandateId)
      .first<{ limit_usd: number; allocated_usd: number }>();

    return { remainingUsd: budget ? budget.limit_usd - budget.allocated_usd : 0 };
  }

  /** Current state of a mandate's budget pool. Returns null if not registered or owner mismatch. */
  async status(mandateId: string): Promise<BudgetStatus | null> {
    const row = await this.db
      .prepare(
        `SELECT b.limit_usd, b.allocated_usd,
                COUNT(CASE WHEN a.released_at IS NULL THEN 1 END) AS allocation_count
         FROM spending_budgets b
         LEFT JOIN spending_allocations a ON a.mandate_id = b.mandate_id
         WHERE b.mandate_id = ?
           AND (? = '' OR b.owner_key_hash = ?)
         GROUP BY b.mandate_id`,
      )
      .bind(mandateId, this.ownerKeyHash, this.ownerKeyHash)
      .first<{ limit_usd: number; allocated_usd: number; allocation_count: number }>();

    if (!row) return null;

    // Opportunistic GC: prune a batch of expired budgets while we have the DB.
    // Fire-and-forget — a failure here doesn't affect the status result.
    this.db
      .prepare(
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

    return {
      mandateId,
      limitUsd: row.limit_usd,
      allocatedUsd: row.allocated_usd,
      remainingUsd: row.limit_usd - row.allocated_usd,
      allocationCount: row.allocation_count,
    };
  }
}
