// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The store contract against the in-memory reference stores (always) and
 * against a real Postgres (when AROHA_TEST_POSTGRES_URL is set).
 *
 *   AROHA_TEST_POSTGRES_URL=postgres://user:pass@127.0.0.1:5432/db npm test
 *
 * Each run uses its own random table prefix and drops its tables afterwards.
 */

import { afterAll, beforeAll, describe, it } from "vitest";
import pg from "pg";
import {
  InMemoryEnrollmentStore,
  InMemoryHttpPresentationNonces,
  MapSpendingLedger,
} from "@aroha-sdk/credentials/mandates";
import { migrate, PostgresEnrollmentStore, PostgresNonceStore, PostgresSpendingLedger, tableNames } from "./index.js";
import { runStoreContract, type StoreSet } from "./test-utils/store-contract.js";

// ─── In-memory reference ─────────────────────────────────────────────────────

const memory: StoreSet = {
  nonces: new InMemoryHttpPresentationNonces(),
  enrollment: new InMemoryEnrollmentStore(),
  ledger: new MapSpendingLedger(),
};
runStoreContract("in-memory", () => ({
  clients: 1,
  open: () => memory,
  openBounded: async (maxChallenges) => new InMemoryEnrollmentStore({ maxChallenges }),
}));

// ─── Postgres ────────────────────────────────────────────────────────────────

const PG_URL = process.env.AROHA_TEST_POSTGRES_URL;

if (!PG_URL) {
  describe("Postgres 16", () => {
    it.skip("SKIPPED: set AROHA_TEST_POSTGRES_URL (e.g. postgres://aroha:aroha@127.0.0.1:5432/aroha_test) to run the store contract against a real Postgres", () => {});
  });
} else {
  const PREFIX = `t${crypto.randomUUID().replace(/-/g, "").slice(0, 10)}_`;
  const CLIENTS = 3;
  const prefixes = [PREFIX];
  const newPools = () => Array.from({ length: CLIENTS }, () => new pg.Pool({ connectionString: PG_URL, max: 20 }));
  let pools: pg.Pool[] = [];

  beforeAll(async () => {
    pools = newPools();
    await migrate(pools[0], { tablePrefix: PREFIX });
    await migrate(pools[1], { tablePrefix: PREFIX }); // idempotent
  });

  afterAll(async () => {
    const admin = new pg.Pool({ connectionString: PG_URL });
    try {
      for (const p of prefixes) {
        const t = tableNames(p);
        await admin.query(`DROP TABLE IF EXISTS ${t.allocations}, ${t.budgets}, ${t.bindings}, ${t.challenges}, ${t.nonces}`);
      }
    } finally {
      await admin.end();
      await Promise.all(pools.map((p) => p.end()));
    }
  });

  const storesOn = (db: pg.Pool, tablePrefix: string): StoreSet => ({
    // Small prune intervals so the opportunistic prune paths run during the suite.
    nonces: new PostgresNonceStore(db, { tablePrefix, pruneEvery: 7 }),
    enrollment: new PostgresEnrollmentStore(db, { tablePrefix, pruneEvery: 5 }),
    ledger: new PostgresSpendingLedger(db, { tablePrefix }),
  });

  runStoreContract("Postgres 16", () => ({
    clients: CLIENTS,
    open: (o = {}) => storesOn(pools[(o.client ?? 0) % CLIENTS], PREFIX),
    async openBounded(maxChallenges) {
      const tablePrefix = `${PREFIX}b${prefixes.length}_`;
      prefixes.push(tablePrefix);
      await migrate(pools[0], { tablePrefix });
      return new PostgresEnrollmentStore(pools[0], { tablePrefix, maxChallenges });
    },
    async restart() {
      const old = pools;
      pools = newPools();
      await Promise.all(old.map((p) => p.end()));
    },
    async broken() {
      const dead = new pg.Pool({ connectionString: PG_URL });
      await dead.end();
      return storesOn(dead, PREFIX);
    },
  }));
}
