// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The store contract (shared with @aroha-sdk/store-postgres) against a real
 * Redis, when AROHA_TEST_REDIS_URL is set; plus checks that the stores read
 * and write exactly the documented key layout the Python stores share.
 *
 *   AROHA_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
 *
 * Each run uses its own random key prefix and deletes its keys afterwards.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redis } from "ioredis";
import { BudgetExhaustedError, mandateRedemptionKey } from "@aroha-sdk/credentials/mandates";
import { RedisEnrollmentStore, RedisNonceStore, RedisSpendingLedger } from "./index.js";
import { keyPrefix } from "./internal.js";
// One contract suite for every implementation; it lives with the Postgres package.
import { runStoreContract, type StoreSet } from "../../aroha-store-postgres/src/test-utils/store-contract.js";

describe("key prefix validation", () => {
  it("accepts namespaces and Cluster hash tags, refuses anything else", () => {
    expect(keyPrefix("aroha:")).toBe("aroha:");
    expect(keyPrefix("{aroha}:prod:")).toBe("{aroha}:prod:");
    for (const bad of ["", "a b", "a\n", "x".repeat(65), "é:"]) expect(() => keyPrefix(bad)).toThrow(TypeError);
  });
});

const REDIS_URL = process.env.AROHA_TEST_REDIS_URL;

if (!REDIS_URL) {
  describe("Redis 7", () => {
    it.skip("SKIPPED: set AROHA_TEST_REDIS_URL (e.g. redis://127.0.0.1:6379) to run the store contract against a real Redis", () => {});
  });
} else {
  const RUN = `aroha-test-${crypto.randomUUID().slice(0, 8)}`;
  const PREFIX = `${RUN}:`;
  const CLIENTS = 3;
  const newClients = () => Array.from({ length: CLIENTS }, () => new Redis(REDIS_URL, { maxRetriesPerRequest: 1 }));
  let clients: Redis[] = [];
  let bounded = 0;

  beforeAll(() => {
    clients = newClients();
  });

  afterAll(async () => {
    const admin = new Redis(REDIS_URL);
    try {
      let cursor = "0";
      do {
        const [next, keys] = await admin.scan(cursor, "MATCH", `${RUN}*`, "COUNT", 500);
        if (keys.length) await admin.del(...keys);
        cursor = next;
      } while (cursor !== "0");
    } finally {
      admin.disconnect();
      clients.forEach((c) => c.disconnect());
    }
  });

  const storesOn = (r: Redis, prefix = PREFIX): StoreSet => ({
    nonces: new RedisNonceStore(r, { keyPrefix: prefix }),
    enrollment: new RedisEnrollmentStore(r, { keyPrefix: prefix }),
    ledger: new RedisSpendingLedger(r, { keyPrefix: prefix }),
  });

  runStoreContract("Redis 7", () => ({
    clients: CLIENTS,
    open: (o = {}) => storesOn(clients[(o.client ?? 0) % CLIENTS]),
    async openBounded(maxChallenges) {
      return new RedisEnrollmentStore(clients[0], { keyPrefix: `${RUN}-b${++bounded}:`, maxChallenges });
    },
    async restart() {
      const old = clients;
      clients = newClients();
      await Promise.all(old.map((c) => c.quit()));
    },
    async broken() {
      // Connected, then closed for good: ioredis does not reconnect after quit(),
      // so every later command rejects ("Connection is closed").
      const dead = new Redis(REDIS_URL, { lazyConnect: true, enableOfflineQueue: false, maxRetriesPerRequest: 0 });
      await dead.connect();
      await dead.quit();
      return storesOn(dead);
    },
  }));

  // ─── The shared layout, byte for byte ──────────────────────────────────────

  describe("Redis 7 — shared key layout (as the Python stores write it)", () => {
    const P = `${RUN}-layout:`;
    const raw = () => clients[0];

    it("nonces: <prefix>nonce:<key> = \"1\" with a TTL of expiresAtMs - nowMs + 1", async () => {
      const now = Date.now();
      expect(await new RedisNonceStore(raw(), { keyPrefix: P }).claim("did:aroha:zH n1", now + 60_000, now)).toBe(true);
      expect(await raw().get(`${P}nonce:did:aroha:zH n1`)).toBe("1");
      const ttl = await raw().pttl(`${P}nonce:did:aroha:zH n1`);
      expect(ttl).toBeGreaterThan(59_000);
      expect(ttl).toBeLessThanOrEqual(60_001);
      // A nonce another implementation recorded is honoured.
      await raw().set(`${P}nonce:did:aroha:zH n2`, "1", "PX", 60_000, "NX");
      expect(await new RedisNonceStore(raw(), { keyPrefix: P }).claim("did:aroha:zH n2", now + 60_000, now)).toBe(false);
    });

    it("enrollment: challenge JSON, the challenges index and binding strings", async () => {
      const store = new RedisEnrollmentStore(raw(), { keyPrefix: P });
      const now = Date.now();
      await store.putChallenge("chal-0123456789abcdef", { accountId: "acct-1", expiresAtMs: now + 60_000 }, now);
      expect(await raw().get(`${P}enroll:challenge:chal-0123456789abcdef`)).toBe(`{"accountId":"acct-1","expiresAtMs":${now + 60_000}}`);
      expect(await raw().zscore(`${P}enroll:challenges`, "chal-0123456789abcdef")).toBe(String(now + 60_000));

      // Written by another implementation, consumed here — once.
      await raw().set(`${P}enroll:challenge:chal-fromPython000000`, `{"accountId":"acct-2","expiresAtMs":${now + 30_000}}`, "PX", 30_000);
      await raw().zadd(`${P}enroll:challenges`, now + 30_000, "chal-fromPython000000");
      expect(await store.consumeChallenge("chal-fromPython000000")).toEqual({ accountId: "acct-2", expiresAtMs: now + 30_000 });
      expect(await raw().zscore(`${P}enroll:challenges`, "chal-fromPython000000")).toBeNull();
      expect(await store.consumeChallenge("chal-fromPython000000")).toBeNull();

      await store.setBinding("acct-1", "did:aroha:zA");
      expect(await raw().get(`${P}enroll:binding:acct-1`)).toBe("did:aroha:zA");
      await raw().set(`${P}enroll:binding:acct-3`, "did:aroha:zB");
      expect(await store.getBinding("acct-3")).toBe("did:aroha:zB");

      // A value outside the layout fails closed rather than reading as "unknown".
      await raw().set(`${P}enroll:challenge:chal-garbage000000000`, "not json");
      await expect(store.consumeChallenge("chal-garbage000000000")).rejects.toThrow();
    });

    it("ledger: budget and allocation hashes in integer micro-USD, keyed by grantor#mandateId", async () => {
      const ledger = new RedisSpendingLedger(raw(), { keyPrefix: P });
      const key = mandateRedemptionKey({ grantor: "did:aroha:zGrantor", mandateId: "m-1" });
      expect(key).toBe("did:aroha:zGrantor#m-1");
      await ledger.init(key, 500.25);
      expect(await raw().hgetall(`${P}ledger:budget:${key}`)).toEqual({ limit: "500250000", allocated: "0" });
      const { allocationId } = await ledger.allocate(key, 0.1);
      expect(await raw().hgetall(`${P}ledger:budget:${key}`)).toEqual({ limit: "500250000", allocated: "100000" });
      expect(await raw().hgetall(`${P}ledger:alloc:${key}`)).toEqual({ [allocationId]: "100000" });
      expect(await raw().ttl(`${P}ledger:budget:${key}`)).toBe(-1); // never expires

      // A budget and allocation another implementation wrote.
      const k2 = "did:aroha:zOther#m-2";
      await raw().hset(`${P}ledger:budget:${k2}`, { limit: "500000000", allocated: "450000000" });
      await raw().hset(`${P}ledger:alloc:${k2}`, { "py-alloc-1": "450000000" });
      expect(await ledger.status(k2)).toEqual({ mandateId: k2, limitUsd: 500, allocatedUsd: 450, remainingUsd: 50, allocationCount: 1 });
      await expect(ledger.allocate(k2, 50.01)).rejects.toBeInstanceOf(BudgetExhaustedError);
      expect(await ledger.release(k2, "py-alloc-1")).toEqual({ remainingUsd: 500 });
      expect(await raw().hgetall(`${P}ledger:budget:${k2}`)).toEqual({ limit: "500000000", allocated: "0" });
      expect(await raw().hlen(`${P}ledger:alloc:${k2}`)).toBe(0);
    });
  });
}
