// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { EnrollmentChallengeRecord, EnrollmentStore } from "@aroha-sdk/credentials/mandates";
import {
  type PgQueryable, type PostgresStoreOptions,
  assertKey, assertMs, num, requireQueryable, tableNames, DEFAULT_TABLE_PREFIX,
} from "./internal.js";

export interface PostgresEnrollmentStoreOptions extends PostgresStoreOptions {
  /**
   * Refuse to issue a challenge while this many unexpired challenges are
   * outstanding (default 100 000, as InMemoryEnrollmentStore). Checked in the
   * same statement as the insert; concurrent issuers can overshoot it by at
   * most the number of inserts running at that instant.
   */
  maxChallenges?: number;
  /** Delete expired challenges every N issues (default 64; 0 turns it off — then call `prune()`). */
  pruneEvery?: number;
}

/**
 * EnrollmentStore backed by Postgres.
 *
 * Atomicity: `consumeChallenge` is ONE statement,
 * `DELETE FROM <prefix>enrollment_challenges WHERE challenge = $1 RETURNING …`.
 * Concurrent deletes of one row serialise on its row lock; the second finds
 * the row gone and returns nothing, so a challenge is spent exactly once.
 * Any database error rejects, which completeEnrollment maps to STORE_UNAVAILABLE.
 */
export class PostgresEnrollmentStore implements EnrollmentStore {
  private readonly t: ReturnType<typeof tableNames>;
  private readonly maxChallenges: number;
  private readonly pruneEvery: number;
  private puts = 0;

  constructor(private readonly db: PgQueryable, options: PostgresEnrollmentStoreOptions = {}) {
    requireQueryable("PostgresEnrollmentStore", db);
    this.t = tableNames(options.tablePrefix ?? DEFAULT_TABLE_PREFIX);
    this.maxChallenges = options.maxChallenges ?? 100_000;
    if (!Number.isSafeInteger(this.maxChallenges) || this.maxChallenges < 1) {
      throw new TypeError("PostgresEnrollmentStore: maxChallenges must be a positive integer");
    }
    this.pruneEvery = options.pruneEvery ?? 64;
  }

  async putChallenge(challenge: string, record: EnrollmentChallengeRecord, nowMs: number): Promise<void> {
    assertKey("challenge", challenge);
    assertKey("record.accountId", record?.accountId);
    assertMs("record.expiresAtMs", record.expiresAtMs);
    assertMs("nowMs", nowMs);
    if (this.pruneEvery > 0 && ++this.puts % this.pruneEvery === 0) await this.prune(nowMs);
    let inserted: number | null;
    try {
      // Expired-but-unpruned rows do not count toward the bound.
      inserted = (await this.db.query(
        `INSERT INTO ${this.t.challenges} (challenge, account_id, expires_at_ms)
         SELECT $1::text, $2::text, $3::bigint
         WHERE (SELECT count(*) FROM ${this.t.challenges} WHERE expires_at_ms > $4::bigint) < $5::bigint`,
        [challenge, record.accountId, Math.floor(record.expiresAtMs), Math.floor(nowMs), this.maxChallenges],
      )).rowCount;
    } catch (e) {
      if ((e as { code?: unknown })?.code === "23505") throw new Error("PostgresEnrollmentStore: challenge already issued");
      throw e;
    }
    if (inserted !== 1) throw new Error("PostgresEnrollmentStore: too many outstanding challenges");
  }

  async consumeChallenge(challenge: string): Promise<EnrollmentChallengeRecord | null> {
    assertKey("challenge", challenge);
    const r = await this.db.query(
      `DELETE FROM ${this.t.challenges} WHERE challenge = $1 RETURNING account_id, expires_at_ms`,
      [challenge],
    );
    const row = r.rows[0];
    return row ? { accountId: String(row.account_id), expiresAtMs: num(row.expires_at_ms) } : null;
  }

  async getBinding(accountId: string): Promise<string | null> {
    assertKey("accountId", accountId);
    const r = await this.db.query(`SELECT did FROM ${this.t.bindings} WHERE account_id = $1`, [accountId]);
    return r.rows[0] ? String(r.rows[0].did) : null;
  }

  async setBinding(accountId: string, did: string): Promise<void> {
    assertKey("accountId", accountId);
    assertKey("did", did);
    await this.db.query(
      `INSERT INTO ${this.t.bindings} (account_id, did) VALUES ($1, $2)
       ON CONFLICT (account_id) DO UPDATE SET did = EXCLUDED.did, updated_at = now()`,
      [accountId, did],
    );
  }

  /** Delete challenges that expired at or before `nowMs` (default: now). Returns the number deleted. */
  async prune(nowMs: number = Date.now()): Promise<number> {
    const r = await this.db.query(`DELETE FROM ${this.t.challenges} WHERE expires_at_ms <= $1`, [Math.floor(nowMs)]);
    return r.rowCount ?? 0;
  }

  /** Number of unexpired outstanding challenges (for tests and metrics). */
  async pendingChallenges(nowMs: number = Date.now()): Promise<number> {
    const r = await this.db.query(`SELECT count(*) AS n FROM ${this.t.challenges} WHERE expires_at_ms > $1`, [Math.floor(nowMs)]);
    return num(r.rows[0]?.n ?? 0);
  }
}
