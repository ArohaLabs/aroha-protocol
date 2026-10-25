// Test-only SQLite adapter using Node.js built-in `node:sqlite` (stable in Node 22+).
// No native compilation needed — uses the SQLite bundled with Node.js.
// Satisfies D1LikeDatabase so D1SpendingLedger can run in Node.js vitest tests.

import { DatabaseSync } from "node:sqlite";
import type { D1LikeDatabase } from "../spending-ledger-d1.js";

class SqliteStatement {
  private values: unknown[] = [];

  constructor(private readonly stmt: ReturnType<DatabaseSync["prepare"]>) {}

  bind(...values: unknown[]): this {
    this.values = values;
    return this;
  }

  // Runs synchronously; used inside batch() transaction.
  _runSync(): number {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return Number((this.stmt.run as any)(...this.values).changes);
  }

  run(): Promise<{ meta: { changes: number } }> {
    return Promise.resolve({ meta: { changes: this._runSync() } });
  }

  all<T>(): Promise<{ results: T[] }> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return Promise.resolve({ results: (this.stmt.all as any)(...this.values) as T[] });
  }

  first<T>(): Promise<T | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const row = (this.stmt.get as any)(...this.values) as T | undefined;
    return Promise.resolve(row ?? null);
  }
}

export class SqliteD1 implements D1LikeDatabase {
  constructor(private readonly db: DatabaseSync) {}

  prepare(sql: string): SqliteStatement {
    return new SqliteStatement(this.db.prepare(sql));
  }

  batch(statements: SqliteStatement[]): Promise<{ meta: { changes: number } }[]> {
    const results: { meta: { changes: number } }[] = [];
    this.db.exec("BEGIN");
    try {
      for (const s of statements) {
        results.push({ meta: { changes: s._runSync() } });
      }
      this.db.exec("COMMIT");
    } catch (err) {
      try { this.db.exec("ROLLBACK"); } catch { /* ignore */ }
      throw err;
    }
    return Promise.resolve(results);
  }
}

export function openSpendingDb(): D1LikeDatabase {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE IF NOT EXISTS spending_budgets (
      mandate_id      TEXT PRIMARY KEY,
      limit_usd       REAL NOT NULL CHECK (limit_usd > 0),
      allocated_usd   REAL NOT NULL DEFAULT 0 CHECK (allocated_usd >= 0),
      owner_key_hash  TEXT NOT NULL DEFAULT '',
      expires_at      INTEGER,
      created_at      INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spending_allocations (
      allocation_id TEXT    PRIMARY KEY,
      mandate_id    TEXT    NOT NULL,
      amount_usd    REAL    NOT NULL CHECK (amount_usd > 0),
      allocated_at  INTEGER NOT NULL,
      released_at   INTEGER
    );
  `);
  return new SqliteD1(db);
}

/** Schema of D1RedemptionStore (same tables as registry migration 016). */
export function openRedemptionDb(): D1LikeDatabase {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE IF NOT EXISTS mandate_redemption_totals (
      mandate_id      TEXT    PRIMARY KEY,
      limit_micros    INTEGER NOT NULL CHECK (limit_micros >= 0),
      redeemed_micros INTEGER NOT NULL DEFAULT 0 CHECK (redeemed_micros >= 0),
      created_at      INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mandate_redemptions (
      redemption_id TEXT    PRIMARY KEY,
      mandate_id    TEXT    NOT NULL,
      amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
      merchant      TEXT    NOT NULL,
      redeemed_at   INTEGER NOT NULL,
      actor         TEXT    NOT NULL DEFAULT ''
    );
  `);
  return new SqliteD1(db);
}
