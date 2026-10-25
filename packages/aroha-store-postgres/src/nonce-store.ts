// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { HttpPresentationNonceStore } from "@aroha-sdk/credentials/mandates";
import {
  type PgQueryable, type PostgresStoreOptions,
  assertKey, assertMs, requireQueryable, tableNames, DEFAULT_TABLE_PREFIX,
} from "./internal.js";

export interface PostgresNonceStoreOptions extends PostgresStoreOptions {
  /**
   * Delete a batch of expired rows every N claims (default 256; 0 turns it
   * off — then call `prune()` on a schedule). A failure here fails the claim:
   * the store refuses rather than guesses.
   */
  pruneEvery?: number;
  /** Rows deleted per opportunistic prune (default 1000). */
  pruneBatch?: number;
}

/**
 * HttpPresentationNonceStore backed by Postgres — replay protection that
 * survives restarts and is shared by every process using the database.
 *
 * Atomicity: `claim` is ONE statement,
 *
 *   INSERT INTO <prefix>http_nonces (key, expires_at_ms) VALUES ($1, $2)
 *   ON CONFLICT (key) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms
 *     WHERE <prefix>http_nonces.expires_at_ms < $3
 *   RETURNING 1
 *
 * The primary key serialises concurrent claims of one key: the loser waits
 * for the winner's commit, then sees a live row and returns no row → false.
 * An entry whose presentation has expired may be claimed again (it can no
 * longer be replayed: the verifier refuses an expired presentation first),
 * matching InMemoryHttpPresentationNonces. Any database error rejects, which
 * verifyHttpPresentation maps to NONCE_STORE_UNAVAILABLE.
 */
export class PostgresNonceStore implements HttpPresentationNonceStore {
  private readonly t: ReturnType<typeof tableNames>;
  private readonly pruneEvery: number;
  private readonly pruneBatch: number;
  private claims = 0;

  constructor(private readonly db: PgQueryable, options: PostgresNonceStoreOptions = {}) {
    requireQueryable("PostgresNonceStore", db);
    this.t = tableNames(options.tablePrefix ?? DEFAULT_TABLE_PREFIX);
    this.pruneEvery = options.pruneEvery ?? 256;
    this.pruneBatch = options.pruneBatch ?? 1000;
  }

  async claim(key: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    assertKey("key", key);
    assertMs("expiresAtMs", expiresAtMs);
    assertMs("nowMs", nowMs);
    if (this.pruneEvery > 0 && ++this.claims % this.pruneEvery === 0) await this.prune(nowMs, this.pruneBatch);
    const r = await this.db.query(
      `INSERT INTO ${this.t.nonces} (key, expires_at_ms) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms
         WHERE ${this.t.nonces}.expires_at_ms < $3
       RETURNING 1 AS claimed`,
      [key, Math.floor(expiresAtMs), Math.floor(nowMs)],
    );
    return r.rowCount === 1;
  }

  /**
   * Delete entries that expired before `nowMs` (default: now). `limit` caps
   * the rows deleted in one call (default: all). Returns the number deleted.
   */
  async prune(nowMs: number = Date.now(), limit?: number): Promise<number> {
    const r = limit === undefined
      ? await this.db.query(`DELETE FROM ${this.t.nonces} WHERE expires_at_ms < $1`, [Math.floor(nowMs)])
      : await this.db.query(
        `DELETE FROM ${this.t.nonces} WHERE key IN (
           SELECT key FROM ${this.t.nonces} WHERE expires_at_ms < $1 LIMIT $2
         )`,
        [Math.floor(nowMs), limit],
      );
    return r.rowCount ?? 0;
  }
}
