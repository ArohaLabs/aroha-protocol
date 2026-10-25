// Test-only D1Database adapter using Node.js built-in `node:sqlite` (stable in Node 22+).
// No native compilation needed — uses the SQLite bundled with Node.js.
//
// Usage:
//   const { db, adapter } = openDb(SCHEMA);
//   const repo = new D1Repository(adapter as unknown as D1Database);

import { DatabaseSync } from "node:sqlite";

class SqliteStatement {
  private values: unknown[] = [];

  constructor(
    private readonly stmt: ReturnType<DatabaseSync["prepare"]>,
    private readonly sql: string,
  ) {}

  bind(...values: unknown[]): this {
    this.values = values;
    return this;
  }

  // Returns rows + changes. SELECT uses stmt.all(); DML uses stmt.run().
  _execSync(): { results: unknown[]; meta: { changes: number } } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if (/^\s*SELECT\b/i.test(this.sql)) {
      const rows = (this.stmt.all as any)(...this.values) as unknown[];
      return { results: rows, meta: { changes: 0 } };
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const info = (this.stmt.run as any)(...this.values) as { changes: number };
    return { results: [], meta: { changes: Number(info.changes) } };
  }

  _runSync(): number {
    return this._execSync().meta.changes;
  }

  run(): Promise<{ meta: { changes: number } }> {
    return Promise.resolve({ meta: { changes: this._runSync() } });
  }

  first<T>(): Promise<T | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const row = (this.stmt.get as any)(...this.values) as T | undefined;
    return Promise.resolve(row ?? null);
  }

  all<T>(): Promise<{ results: T[] }> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return Promise.resolve({ results: (this.stmt.all as any)(...this.values) as T[] });
  }
}

export class SqliteD1 {
  constructor(private readonly db: DatabaseSync) {}

  prepare(sql: string): SqliteStatement {
    return new SqliteStatement(this.db.prepare(sql), sql);
  }

  batch(statements: SqliteStatement[]): Promise<{ results: unknown[]; meta: { changes: number } }[]> {
    const out: { results: unknown[]; meta: { changes: number } }[] = [];
    this.db.exec("BEGIN");
    try {
      for (const s of statements) {
        out.push(s._execSync());
      }
      this.db.exec("COMMIT");
    } catch (err) {
      try { this.db.exec("ROLLBACK"); } catch { /* ignore */ }
      throw err;
    }
    return Promise.resolve(out);
  }
}

export const NONCE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS rotation_nonces (
    nonce      TEXT PRIMARY KEY,
    did_hash   TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_nonce_expires ON rotation_nonces (expires_at);
`;

export const ROTATE_KEY_SCHEMA = `
  CREATE TABLE IF NOT EXISTS agent_records (
    did_hash         TEXT PRIMARY KEY,
    did              TEXT NOT NULL UNIQUE,
    owner_key_hash   TEXT NOT NULL,
    org_name         TEXT NOT NULL DEFAULT '',
    manifest_cid     TEXT NOT NULL DEFAULT '',
    public_key_b64   TEXT NOT NULL,
    staked_wei       TEXT NOT NULL DEFAULT '0',
    reputation_score INTEGER NOT NULL DEFAULT 5000,
    active           INTEGER NOT NULL DEFAULT 1,
    registered_at    INTEGER NOT NULL,
    last_updated_at  INTEGER NOT NULL,
    endpoint_url     TEXT,
    key_version      INTEGER NOT NULL DEFAULT 1,
    key_rotated_at   INTEGER
  );

  CREATE TABLE IF NOT EXISTS revoked_keys (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    did_hash       TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    key_version    INTEGER NOT NULL,
    rotated_at     INTEGER NOT NULL
  );

  ${NONCE_SCHEMA}
`;

export function openDb(schema: string): { db: DatabaseSync; adapter: SqliteD1 } {
  const db = new DatabaseSync(":memory:");
  db.exec(schema);
  return { db, adapter: new SqliteD1(db) };
}

/** api_keys as of migration 013 — enough of it to exercise minting and listing. */
export const API_KEYS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT PRIMARY KEY,
    org_name   TEXT NOT NULL,
    owner_id   TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    label      TEXT
  );
`;
