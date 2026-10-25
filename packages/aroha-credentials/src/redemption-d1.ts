// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * D1RedemptionStore — a durable, shared RedemptionStore on Cloudflare D1
 * (or any SQLite reachable through the same duck-typed interface).
 *
 * WHY THIS EXISTS. redeemPaymentMandate's cumulative cap is only as wide as
 * the store behind it. InMemoryRedemptionStore stops ONE process honouring a
 * payment mandate twice; two payee instances (or a restart) each start from
 * zero, so the same $50 mandate could be spent once per process. The README
 * told integrators to "share a durable store" without shipping one. This is
 * that store, built the same way as D1SpendingLedger: SQLite serialises
 * writes, so a conditional UPDATE is a compare-and-swap, and D1's batch()
 * runs the statements in one transaction.
 *
 * The check-and-add (one batch, one transaction):
 *
 *   1. INSERT OR IGNORE the mandate's totals row (first redemption creates it,
 *      recording the limit the first redeemer derived);
 *   2. UPDATE … SET redeemed_micros = redeemed_micros + :amount
 *        WHERE mandate_id = :id
 *          AND redeemed_micros + :amount <= MIN(limit_micros, :limit)
 *      — the guard IS the check; meta.changes === 0 means "would exceed";
 *   3. INSERT the redemption row only if (2) changed a row (SQLite changes()).
 *
 * MIN(stored, passed) limit: whichever is tighter wins. A later redeemer can
 * never RAISE the cap the first one recorded (they would have to forge a
 * different mandate, which has a different mandateId), and an honest
 * redeemer that derived a lower limit (e.g. a tighter sessionLimitUsd) is
 * held to it.
 *
 * Amounts are integer micro-USD, exactly as RedemptionStore specifies, so no
 * floating-point drift can creep past the limit.
 *
 * Required schema (include it in your D1 migration — the Aroha registry's
 * migration 016_mandate_revocations_redemptions.sql creates the same tables):
 *
 *   CREATE TABLE IF NOT EXISTS mandate_redemption_totals (
 *     mandate_id      TEXT    PRIMARY KEY,
 *     limit_micros    INTEGER NOT NULL CHECK (limit_micros >= 0),
 *     redeemed_micros INTEGER NOT NULL DEFAULT 0 CHECK (redeemed_micros >= 0),
 *     created_at      INTEGER NOT NULL
 *   );
 *   CREATE TABLE IF NOT EXISTS mandate_redemptions (
 *     redemption_id TEXT    PRIMARY KEY,
 *     mandate_id    TEXT    NOT NULL,
 *     amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
 *     merchant      TEXT    NOT NULL,
 *     redeemed_at   INTEGER NOT NULL,
 *     actor         TEXT    NOT NULL DEFAULT ''
 *   );
 *   CREATE INDEX IF NOT EXISTS idx_mandate_redemptions_mandate ON mandate_redemptions (mandate_id);
 */

import type { D1LikeDatabase } from "./spending-ledger-d1.js";
import type { RedemptionRecord, RedemptionStore } from "./redemption.js";

export interface D1RedemptionStoreOptions {
  /**
   * Recorded in mandate_redemptions.actor for audit (e.g. the API-key hash
   * of the payee that redeemed). Not used for authorisation.
   */
  actor?: string;
}

function assertMicros(name: string, n: number, allowZero: boolean): void {
  if (!Number.isSafeInteger(n) || n < 0 || (!allowZero && n === 0)) {
    throw new RangeError(`${name} must be a ${allowZero ? "non-negative" : "positive"} safe integer (micro-USD), got ${String(n)}`);
  }
}

export class D1RedemptionStore implements RedemptionStore {
  constructor(
    private readonly db: D1LikeDatabase,
    private readonly options: D1RedemptionStoreOptions = {},
  ) {}

  async tryRedeem(
    mandateId: string,
    amountMicros: number,
    limitMicros: number,
    record: RedemptionRecord,
  ): Promise<{ accepted: boolean; redeemedMicros: number }> {
    assertMicros("amountMicros", amountMicros, false);
    assertMicros("limitMicros", limitMicros, true);
    const now = Date.now();
    const redeemedAt = Number.isNaN(Date.parse(record.redeemedAt)) ? now : Date.parse(record.redeemedAt);

    const [, update] = await this.db.batch([
      this.db
        .prepare(
          `INSERT OR IGNORE INTO mandate_redemption_totals (mandate_id, limit_micros, redeemed_micros, created_at)
           VALUES (?, ?, 0, ?)`,
        )
        .bind(mandateId, limitMicros, now),
      this.db
        .prepare(
          `UPDATE mandate_redemption_totals
           SET redeemed_micros = redeemed_micros + ?
           WHERE mandate_id = ?
             AND redeemed_micros + ? <= MIN(limit_micros, ?)`,
        )
        .bind(amountMicros, mandateId, amountMicros, limitMicros),
      this.db
        .prepare(
          `INSERT INTO mandate_redemptions (redemption_id, mandate_id, amount_micros, merchant, redeemed_at, actor)
           SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT changes()) > 0`,
        )
        .bind(record.redemptionId, mandateId, amountMicros, record.merchant, redeemedAt, this.options.actor ?? ""),
    ]);

    return { accepted: update.meta.changes > 0, redeemedMicros: await this.redeemedMicros(mandateId) };
  }

  async redeemedMicros(mandateId: string): Promise<number> {
    const row = await this.db
      .prepare(`SELECT redeemed_micros FROM mandate_redemption_totals WHERE mandate_id = ?`)
      .bind(mandateId)
      .first<{ redeemed_micros: number }>();
    return row ? Number(row.redeemed_micros) : 0;
  }

  /** Redemption history for a mandate, oldest first (audit). */
  async history(mandateId: string): Promise<Array<{ redemptionId: string; amountMicros: number; merchant: string; redeemedAt: number; actor: string }>> {
    type Row = { redemption_id: string; amount_micros: number; merchant: string; redeemed_at: number; actor: string };
    // D1's statement has all(); D1LikeDatabase declares only what the write
    // path needs, so reach for it structurally here (audit-only method).
    const stmt = this.db
      .prepare(
        `SELECT redemption_id, amount_micros, merchant, redeemed_at, actor
         FROM mandate_redemptions WHERE mandate_id = ? ORDER BY redeemed_at, redemption_id`,
      )
      .bind(mandateId) as unknown as { all?: () => Promise<{ results: Row[] }> };
    if (typeof stmt.all !== "function") throw new Error("history() needs a D1 statement with all()");
    const { results } = await stmt.all();
    return results.map((r) => ({
      redemptionId: r.redemption_id,
      amountMicros: Number(r.amount_micros),
      merchant: r.merchant,
      redeemedAt: Number(r.redeemed_at),
      actor: r.actor,
    }));
  }
}
