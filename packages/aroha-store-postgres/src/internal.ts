// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared plumbing: the minimal client shape the stores need, table-prefix
 * validation, and the integer micro-dollar conversions the ledger uses.
 */

/** Result shape every store reads from a query. `pg.Pool`, `pg.Client` and `pg.PoolClient` all satisfy it. */
export interface PgQueryResult {
  // Rows are read field by field and converted explicitly (BIGINT arrives as a string).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rows: any[];
  rowCount: number | null;
}

/**
 * Anything that runs a parameterised query: a `pg.Pool` (recommended — the
 * stores issue single statements, so a pool gives real concurrency), a
 * `pg.Client`, or a `pg.PoolClient`.
 */
export interface PgQueryable {
  query(text: string, values?: unknown[]): Promise<PgQueryResult>;
}

/** Options every Postgres store accepts. */
export interface PostgresStoreOptions {
  /**
   * Prefix for every table name (default `"aroha_"`). Must match
   * `^[a-z_][a-z0-9_]{0,40}$`: it is the only part of any statement that is
   * not a bound parameter, so it is validated rather than quoted. Use the
   * same prefix for `migrate()` and for the stores.
   */
  tablePrefix?: string;
}

export const DEFAULT_TABLE_PREFIX = "aroha_";
const PREFIX_RE = /^[a-z_][a-z0-9_]{0,40}$/;

/** Validate a table prefix; throws TypeError on anything outside `^[a-z_][a-z0-9_]{0,40}$`. */
export function tablePrefix(prefix: unknown = DEFAULT_TABLE_PREFIX): string {
  if (typeof prefix !== "string" || !PREFIX_RE.test(prefix)) {
    throw new TypeError(`tablePrefix must match ${PREFIX_RE.source} (got ${JSON.stringify(prefix)})`);
  }
  return prefix;
}

/** Physical table names for a prefix. */
export function tableNames(prefix: string) {
  const p = tablePrefix(prefix);
  return {
    nonces: `${p}http_nonces`,
    challenges: `${p}enrollment_challenges`,
    bindings: `${p}enrollment_bindings`,
    budgets: `${p}spending_budgets`,
    allocations: `${p}spending_allocations`,
  } as const;
}

export function requireQueryable(name: string, db: unknown): asserts db is PgQueryable {
  if (!db || typeof (db as PgQueryable).query !== "function") {
    throw new TypeError(`${name}: a pg Pool or Client is required`);
  }
}

// ─── Money ───────────────────────────────────────────────────────────────────

// Integer micro-USD, exactly as MapSpendingLedger keeps it: decimal dollars
// added as floats drift (0.1 + 0.2 !== 0.3).
const MICROS_PER_USD = 1_000_000;
export const toMicros = (usd: number): number => Math.round(usd * MICROS_PER_USD);
export const toUsd = (micros: number): number => micros / MICROS_PER_USD;

export function assertAmount(name: string, usd: number): void {
  if (typeof usd !== "number" || !Number.isFinite(usd) || usd < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number of USD (got ${String(usd)})`);
  }
  if (!Number.isSafeInteger(toMicros(usd))) {
    throw new RangeError(`${name} is too large to account for exactly (got ${String(usd)})`);
  }
}

export function assertKey(name: string, v: unknown): asserts v is string {
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${name} must be a non-empty string`);
}

export function assertMs(name: string, v: unknown): asserts v is number {
  if (typeof v !== "number" || !Number.isSafeInteger(Math.floor(v))) {
    throw new TypeError(`${name} must be a finite number of Unix milliseconds (got ${String(v)})`);
  }
}

/** BIGINT columns arrive from node-postgres as strings. */
export const num = (v: unknown): number => (typeof v === "number" ? v : Number(v));
