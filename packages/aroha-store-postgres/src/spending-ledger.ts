// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import {
  BudgetExhaustedError,
  type AllocationResult, type BudgetStatus, type ISpendingLedger,
} from "@aroha-sdk/credentials/mandates";
import {
  type PgQueryable, type PostgresStoreOptions,
  assertAmount, assertKey, num, requireQueryable, tableNames, toMicros, toUsd, DEFAULT_TABLE_PREFIX,
} from "./internal.js";

/**
 * ISpendingLedger backed by Postgres — running totals that survive restarts
 * and are shared by every process using the database. Same semantics as
 * MapSpendingLedger: integer micro-USD, idempotent `init`, `allocate` throws
 * BudgetExhaustedError past the limit (or after `expiresAt`), `release` is
 * safe to repeat and a no-op for an unknown allocation.
 *
 * Atomicity: `allocate` is ONE statement — a conditional UPDATE that checks
 * and adds in the same row operation, with the allocation row inserted by a
 * data-modifying CTE that only fires when the UPDATE did:
 *
 *   WITH b AS (UPDATE <prefix>spending_budgets
 *              SET allocated_micros = allocated_micros + $amount
 *              WHERE key = $key AND allocated_micros + $amount <= limit_micros
 *                AND (expires_at_ms IS NULL OR expires_at_ms >= $now)
 *              RETURNING …),
 *        a AS (INSERT INTO <prefix>spending_allocations … SELECT … FROM b)
 *   SELECT … FROM b
 *
 * Concurrent allocations on one budget serialise on its row lock; under READ
 * COMMITTED each waiter re-evaluates the WHERE guard against the committed
 * total, so the limit can never be crossed. `release` deletes the allocation
 * row and subtracts its amount (floored at 0) in one statement
 * (`WITH r AS (DELETE … RETURNING amount_micros) UPDATE …`), so a repeated or
 * concurrent release returns the money once.
 *
 * Any database error rejects; verifyHttpSpendRequest maps that to LEDGER_UNAVAILABLE.
 */
export class PostgresSpendingLedger implements ISpendingLedger {
  private readonly t: ReturnType<typeof tableNames>;

  constructor(private readonly db: PgQueryable, options: PostgresStoreOptions = {}) {
    requireQueryable("PostgresSpendingLedger", db);
    this.t = tableNames(options.tablePrefix ?? DEFAULT_TABLE_PREFIX);
  }

  async init(mandateId: string, limitUsd: number, expiresAt?: number): Promise<void> {
    assertKey("mandateId", mandateId);
    assertAmount("limitUsd", limitUsd);
    if (expiresAt !== undefined && (typeof expiresAt !== "number" || !Number.isFinite(expiresAt))) {
      throw new TypeError(`expiresAt must be Unix milliseconds or undefined (got ${String(expiresAt)})`);
    }
    await this.db.query(
      `INSERT INTO ${this.t.budgets} (key, limit_micros, allocated_micros, expires_at_ms)
       VALUES ($1, $2, 0, $3)
       ON CONFLICT (key) DO NOTHING`,
      [mandateId, toMicros(limitUsd), expiresAt === undefined ? null : Math.floor(expiresAt)],
    );
  }

  async allocate(parentMandateId: string, amountUsd: number): Promise<AllocationResult> {
    assertKey("parentMandateId", parentMandateId);
    // A negative allocation would ADD budget back; NaN would slip past a comparison.
    assertAmount("amountUsd", amountUsd);
    const amount = toMicros(amountUsd);
    const allocationId = crypto.randomUUID();
    const now = Date.now();
    const r = await this.db.query(
      `WITH b AS (
         UPDATE ${this.t.budgets}
            SET allocated_micros = allocated_micros + $2::bigint
          WHERE key = $1::text
            AND allocated_micros + $2::bigint <= limit_micros
            AND (expires_at_ms IS NULL OR expires_at_ms >= $4::bigint)
          RETURNING limit_micros, allocated_micros
       ), a AS (
         INSERT INTO ${this.t.allocations} (key, allocation_id, amount_micros)
         SELECT $1::text, $3::text, $2::bigint FROM b
         RETURNING allocation_id
       )
       SELECT b.limit_micros, b.allocated_micros, (SELECT count(*) FROM a) AS inserted FROM b`,
      [parentMandateId, amount, allocationId, now],
    );
    const row = r.rows[0];
    if (row) {
      if (num(row.inserted) !== 1) throw new Error("PostgresSpendingLedger: allocation row was not recorded");
      return { allocationId, remainingUsd: toUsd(num(row.limit_micros) - num(row.allocated_micros)) };
    }

    // Refused: say why, from a fresh read.
    const s = await this.db.query(
      `SELECT limit_micros, allocated_micros, expires_at_ms FROM ${this.t.budgets} WHERE key = $1`,
      [parentMandateId],
    );
    const b = s.rows[0];
    if (!b) {
      throw new Error(
        `No budget registered for mandate ${parentMandateId}. ` +
        `Pass { ledger } to issueIntentMandate() so the root budget is initialised before any children are issued.`,
      );
    }
    if (b.expires_at_ms !== null && num(b.expires_at_ms) < now) {
      throw new BudgetExhaustedError(parentMandateId, amountUsd, 0);
    }
    throw new BudgetExhaustedError(parentMandateId, amountUsd, toUsd(num(b.limit_micros) - num(b.allocated_micros)));
  }

  async release(parentMandateId: string, allocationId: string): Promise<{ remainingUsd: number }> {
    assertKey("parentMandateId", parentMandateId);
    if (typeof allocationId !== "string") throw new TypeError("allocationId must be a string");
    const r = await this.db.query(
      `WITH r AS (
         DELETE FROM ${this.t.allocations}
          WHERE key = $1::text AND allocation_id = $2::text
          RETURNING amount_micros
       ), b AS (
         UPDATE ${this.t.budgets}
            SET allocated_micros = GREATEST(0, allocated_micros - r.amount_micros)
           FROM r
          WHERE key = $1::text
          RETURNING limit_micros, allocated_micros
       )
       SELECT limit_micros, allocated_micros FROM b`,
      [parentMandateId, allocationId],
    );
    let row = r.rows[0];
    if (!row) {
      // Unknown or already released: a no-op that still reports the balance.
      row = (await this.db.query(
        `SELECT limit_micros, allocated_micros FROM ${this.t.budgets} WHERE key = $1`,
        [parentMandateId],
      )).rows[0];
      if (!row) return { remainingUsd: 0 };
    }
    return { remainingUsd: toUsd(num(row.limit_micros) - num(row.allocated_micros)) };
  }

  async status(mandateId: string): Promise<BudgetStatus | null> {
    assertKey("mandateId", mandateId);
    const r = await this.db.query(
      `SELECT b.limit_micros, b.allocated_micros,
              (SELECT count(*) FROM ${this.t.allocations} a WHERE a.key = b.key) AS allocation_count
         FROM ${this.t.budgets} b
        WHERE b.key = $1`,
      [mandateId],
    );
    const row = r.rows[0];
    if (!row) return null;
    const limit = num(row.limit_micros);
    const allocated = num(row.allocated_micros);
    return {
      mandateId,
      limitUsd: toUsd(limit),
      allocatedUsd: toUsd(allocated),
      remainingUsd: toUsd(limit - allocated),
      allocationCount: num(row.allocation_count),
    };
  }

  /**
   * Delete budgets (and, by cascade, their allocations) whose `expiresAt`
   * is before `nowMs` (default: now). Safe as long as callers re-`init` an
   * expiring budget with its expiresAt: a re-created budget is already
   * expired and refuses every allocation. Budgets without an expiry (such as
   * those verifyHttpSpendRequest creates) are never pruned. Returns the
   * number of budgets deleted.
   */
  async prune(nowMs: number = Date.now()): Promise<number> {
    const r = await this.db.query(
      `DELETE FROM ${this.t.budgets} WHERE expires_at_ms IS NOT NULL AND expires_at_ms < $1`,
      [Math.floor(nowMs)],
    );
    return r.rowCount ?? 0;
  }
}
