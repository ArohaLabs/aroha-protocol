// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Schema and migration.
 *
 * The layout is shared with the Python stores (aroha-py), so a TypeScript
 * and a Python server can use one database with the same table prefix.
 *
 * `schemaSql(prefix)` is the single source of the DDL. The shipped file
 * `migrations/001_init.sql` is its rendering for the default prefix
 * `aroha_` (a test keeps the two identical), for teams that apply migrations
 * with their own tool. Every statement is idempotent (`IF NOT EXISTS`).
 *
 * Times are Unix milliseconds (BIGINT) supplied by the application, so the
 * stores judge expiry by the same clock the verifier uses. Money is integer
 * micro-USD (BIGINT), as in MapSpendingLedger.
 *
 * `spending_budgets.expires_at_ms` (nullable; NULL = never expires) is the
 * one addition to the shared layout: ISpendingLedger.init takes an optional
 * expiresAt. It is added with ADD COLUMN IF NOT EXISTS, so it also upgrades a
 * table first created by another implementation; one that ignores the
 * column leaves it NULL, which means "no expiry".
 */

import { type PgQueryable, DEFAULT_TABLE_PREFIX, requireQueryable, tableNames } from "./internal.js";

/** The DDL for one table prefix. Throws TypeError for a prefix outside `^[a-z_][a-z0-9_]{0,40}$`. */
export function schemaSql(prefix: string = DEFAULT_TABLE_PREFIX): string {
  const t = tableNames(prefix);
  return `-- @aroha-sdk/store-postgres schema v1 (table prefix "${prefix}")
-- Shared with the Python stores. Idempotent: every statement is IF NOT EXISTS.

-- HttpPresentationNonceStore: one row per claimed "<holder> <nonce>".
CREATE TABLE IF NOT EXISTS ${t.nonces} (
  key            TEXT   PRIMARY KEY,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ${t.nonces}_expires_idx ON ${t.nonces} (expires_at_ms);

-- EnrollmentStore: outstanding single-use challenges.
CREATE TABLE IF NOT EXISTS ${t.challenges} (
  challenge      TEXT   PRIMARY KEY,
  account_id     TEXT   NOT NULL,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ${t.challenges}_expires_idx ON ${t.challenges} (expires_at_ms);

-- EnrollmentStore: account -> enrolled DID.
CREATE TABLE IF NOT EXISTS ${t.bindings} (
  account_id  TEXT        PRIMARY KEY,
  did         TEXT        NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ISpendingLedger: one budget per ledger key (grantor#mandateId), integer micro-USD.
CREATE TABLE IF NOT EXISTS ${t.budgets} (
  key               TEXT   PRIMARY KEY,
  limit_micros      BIGINT NOT NULL CHECK (limit_micros >= 0),
  allocated_micros  BIGINT NOT NULL DEFAULT 0 CHECK (allocated_micros >= 0)
);
-- Optional budget expiry (Unix ms; NULL = never expires).
ALTER TABLE ${t.budgets} ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT;

-- ISpendingLedger: one row per live allocation; release() deletes it.
CREATE TABLE IF NOT EXISTS ${t.allocations} (
  key            TEXT   NOT NULL REFERENCES ${t.budgets} (key) ON DELETE CASCADE,
  allocation_id  TEXT   NOT NULL,
  amount_micros  BIGINT NOT NULL CHECK (amount_micros >= 0),
  PRIMARY KEY (key, allocation_id)
);
`;
}

/** A pool (whose `connect()` gives a dedicated client) or a single client. */
export interface PgMigratable extends PgQueryable {
  connect?(): Promise<unknown>;
}

interface PoolLike {
  connect(): Promise<PgQueryable & { release(err?: unknown): void }>;
  totalCount: number;
}

/**
 * Create the tables for `tablePrefix` (default `aroha_`) if they do not
 * exist. Safe to run on every start, and from several processes at once: it
 * runs in one transaction under a transaction-scoped advisory lock, so
 * concurrent callers queue instead of racing on CREATE TABLE.
 *
 * Pass a `pg.Pool` (a client is checked out for the transaction) or a
 * connected `pg.Client`.
 */
export async function migrate(db: PgMigratable, options: { tablePrefix?: string } = {}): Promise<void> {
  requireQueryable("migrate", db);
  const prefix = options.tablePrefix ?? DEFAULT_TABLE_PREFIX;
  const ddl = schemaSql(prefix);
  // pg.Client also has connect() (it opens the connection); only a Pool has totalCount.
  const pool = typeof (db as Partial<PoolLike>).totalCount === "number" ? (db as unknown as PoolLike) : null;
  const client = pool ? await pool.connect() : null;
  const q: PgQueryable = client ?? db;
  try {
    await q.query("BEGIN");
    try {
      await q.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`aroha-store:migrate:${prefix}`]);
      await q.query(ddl);
      await q.query("COMMIT");
    } catch (e) {
      await q.query("ROLLBACK").catch(() => { /* the original error is the one to report */ });
      throw e;
    }
  } finally {
    client?.release();
  }
}
