// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Postgres-specific checks: table-prefix validation, the shipped migration
 * file, concurrent migrate(), prune(), and the shared table layout (rows as
 * the Python stores write them are read here, and vice versa).
 */

import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { BudgetExhaustedError } from "@aroha-sdk/credentials/mandates";
import {
  migrate, schemaSql, tableNames,
  PostgresEnrollmentStore, PostgresNonceStore, PostgresSpendingLedger,
} from "./index.js";

describe("table prefix", () => {
  it("accepts ^[a-z_][a-z0-9_]{0,40}$ and refuses anything else, everywhere", () => {
    expect(tableNames("aroha_").nonces).toBe("aroha_http_nonces");
    expect(tableNames("_x9").budgets).toBe("_x9spending_budgets");
    const fake = { query: async () => ({ rows: [], rowCount: 0 }) };
    for (const bad of ["", "Aroha_", "9x", "a-b", "a;drop table x;--", "a b", "a\"", "x".repeat(42)]) {
      expect(() => schemaSql(bad)).toThrow(TypeError);
      expect(() => new PostgresNonceStore(fake, { tablePrefix: bad })).toThrow(TypeError);
      expect(() => new PostgresEnrollmentStore(fake, { tablePrefix: bad })).toThrow(TypeError);
      expect(() => new PostgresSpendingLedger(fake, { tablePrefix: bad })).toThrow(TypeError);
    }
  });

  it("refuses a missing client", () => {
    expect(() => new PostgresNonceStore(undefined as never)).toThrow(TypeError);
  });

  it("ships migrations/001_init.sql identical to schemaSql('aroha_')", () => {
    const file = readFileSync(new URL("../migrations/001_init.sql", import.meta.url), "utf8").replace(/\r\n/g, "\n");
    expect(file).toBe(schemaSql("aroha_"));
  });
});

const PG_URL = process.env.AROHA_TEST_POSTGRES_URL;

if (!PG_URL) {
  describe("Postgres 16 — migration, prune and shared layout", () => {
    it.skip("SKIPPED: set AROHA_TEST_POSTGRES_URL to run the Postgres-specific tests", () => {});
  });
} else {
  const PREFIX = `l${crypto.randomUUID().replace(/-/g, "").slice(0, 10)}_`;
  const t = tableNames(PREFIX);
  let pool: pg.Pool;

  beforeAll(() => {
    pool = new pg.Pool({ connectionString: PG_URL, max: 10 });
  });

  afterAll(async () => {
    try {
      await pool.query(`DROP TABLE IF EXISTS ${t.allocations}, ${t.budgets}, ${t.bindings}, ${t.challenges}, ${t.nonces}`);
    } finally {
      await pool.end();
    }
  });

  describe("Postgres 16 — migration, prune and shared layout", () => {
    it("migrate() is safe to run concurrently, also with a pg.Client", async () => {
      await Promise.all([migrate(pool, { tablePrefix: PREFIX }), migrate(pool, { tablePrefix: PREFIX }), migrate(pool, { tablePrefix: PREFIX })]);
      const client = new pg.Client({ connectionString: PG_URL });
      await client.connect();
      try {
        await migrate(client, { tablePrefix: PREFIX });
      } finally {
        await client.end();
      }
      const cols = await pool.query(
        `SELECT table_name, column_name, data_type FROM information_schema.columns
          WHERE table_name = ANY($1) ORDER BY table_name, ordinal_position`,
        [[t.nonces, t.challenges, t.bindings, t.budgets, t.allocations]],
      );
      expect(cols.rows.map((r) => `${r.table_name.slice(PREFIX.length)}.${r.column_name}:${r.data_type}`)).toEqual([
        "enrollment_bindings.account_id:text",
        "enrollment_bindings.did:text",
        "enrollment_bindings.updated_at:timestamp with time zone",
        "enrollment_challenges.challenge:text",
        "enrollment_challenges.account_id:text",
        "enrollment_challenges.expires_at_ms:bigint",
        "http_nonces.key:text",
        "http_nonces.expires_at_ms:bigint",
        "spending_allocations.key:text",
        "spending_allocations.allocation_id:text",
        "spending_allocations.amount_micros:bigint",
        "spending_budgets.key:text",
        "spending_budgets.limit_micros:bigint",
        "spending_budgets.allocated_micros:bigint",
        "spending_budgets.expires_at_ms:bigint",
      ]);
    });

    it("upgrades a spending_budgets table created without expires_at_ms (as another implementation may)", async () => {
      const p = `${PREFIX}u_`;
      const u = tableNames(p);
      await pool.query(`CREATE TABLE ${u.budgets} (key TEXT PRIMARY KEY, limit_micros BIGINT NOT NULL CHECK (limit_micros >= 0),
        allocated_micros BIGINT NOT NULL DEFAULT 0 CHECK (allocated_micros >= 0))`);
      await pool.query(`INSERT INTO ${u.budgets} (key, limit_micros) VALUES ('k', 1000000)`);
      try {
        await migrate(pool, { tablePrefix: p });
        const ledger = new PostgresSpendingLedger(pool, { tablePrefix: p });
        expect((await ledger.allocate("k", 0.5)).remainingUsd).toBe(0.5); // NULL expiry = never expires
      } finally {
        await pool.query(`DROP TABLE IF EXISTS ${u.allocations}, ${u.budgets}, ${u.bindings}, ${u.challenges}, ${u.nonces}`);
      }
    });

    it("reads and writes the shared rows", async () => {
      const now = Date.now();
      // Nonce recorded elsewhere is honoured; ours lands in the documented columns.
      await pool.query(`INSERT INTO ${t.nonces} (key, expires_at_ms) VALUES ($1, $2)`, ["did:aroha:zH py", now + 60_000]);
      const nonces = new PostgresNonceStore(pool, { tablePrefix: PREFIX });
      expect(await nonces.claim("did:aroha:zH py", now + 60_000, now)).toBe(false);
      expect(await nonces.claim("did:aroha:zH ts", now + 60_000, now)).toBe(true);
      expect((await pool.query(`SELECT expires_at_ms FROM ${t.nonces} WHERE key = $1`, ["did:aroha:zH ts"])).rows[0].expires_at_ms).toBe(String(now + 60_000));

      const enrollment = new PostgresEnrollmentStore(pool, { tablePrefix: PREFIX });
      await pool.query(`INSERT INTO ${t.challenges} (challenge, account_id, expires_at_ms) VALUES ('c-py', 'acct-py', $1)`, [now + 1_000]);
      expect(await enrollment.consumeChallenge("c-py")).toEqual({ accountId: "acct-py", expiresAtMs: now + 1_000 });
      await pool.query(`INSERT INTO ${t.bindings} (account_id, did) VALUES ('acct-py', 'did:aroha:zPy')`);
      expect(await enrollment.getBinding("acct-py")).toBe("did:aroha:zPy");
      await enrollment.setBinding("acct-py", "did:aroha:zTs");
      expect((await pool.query(`SELECT did FROM ${t.bindings} WHERE account_id = 'acct-py'`)).rows[0].did).toBe("did:aroha:zTs");

      const ledger = new PostgresSpendingLedger(pool, { tablePrefix: PREFIX });
      await pool.query(`INSERT INTO ${t.budgets} (key, limit_micros, allocated_micros) VALUES ('did:aroha:zG#m', 500000000, 450000000)`);
      await pool.query(`INSERT INTO ${t.allocations} (key, allocation_id, amount_micros) VALUES ('did:aroha:zG#m', 'py-1', 450000000)`);
      expect(await ledger.status("did:aroha:zG#m")).toEqual({ mandateId: "did:aroha:zG#m", limitUsd: 500, allocatedUsd: 450, remainingUsd: 50, allocationCount: 1 });
      await expect(ledger.allocate("did:aroha:zG#m", 50.01)).rejects.toBeInstanceOf(BudgetExhaustedError);
      const { allocationId } = await ledger.allocate("did:aroha:zG#m", 0.25);
      expect((await pool.query(`SELECT amount_micros FROM ${t.allocations} WHERE key = $1 AND allocation_id = $2`, ["did:aroha:zG#m", allocationId])).rows[0].amount_micros).toBe("250000");
      expect(await ledger.release("did:aroha:zG#m", "py-1")).toEqual({ remainingUsd: 499.75 });
      expect((await pool.query(`SELECT count(*)::int AS n FROM ${t.allocations} WHERE key = 'did:aroha:zG#m'`)).rows[0].n).toBe(1);
    });

    it("prune() removes expired nonces, challenges and expiring budgets only", async () => {
      const now = Date.now();
      const nonces = new PostgresNonceStore(pool, { tablePrefix: PREFIX });
      const enrollment = new PostgresEnrollmentStore(pool, { tablePrefix: PREFIX });
      const ledger = new PostgresSpendingLedger(pool, { tablePrefix: PREFIX });
      await nonces.claim("old", now - 10, now - 1_000);
      await nonces.claim("live", now + 60_000, now);
      await enrollment.putChallenge("c-old-0123456789", { accountId: "a", expiresAtMs: now - 10 }, now - 1_000);
      await ledger.init("b-old", 10, now - 10);
      await ledger.init("b-forever", 10);
      expect(await nonces.prune(now)).toBeGreaterThanOrEqual(1);
      expect(await enrollment.prune(now)).toBeGreaterThanOrEqual(1);
      expect(await ledger.prune(now)).toBe(1);
      expect(await nonces.claim("live", now + 60_000, now)).toBe(false);
      expect(await ledger.status("b-old")).toBeNull();
      expect(await ledger.status("b-forever")).not.toBeNull();
      expect(await enrollment.consumeChallenge("c-old-0123456789")).toBeNull();
    });
  });
}
