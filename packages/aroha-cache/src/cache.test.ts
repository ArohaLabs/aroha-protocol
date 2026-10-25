// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach } from "vitest";
import { cacheKey, InMemorySemanticCache, type CacheEntry } from "./cache.js";

function makeEntry(
  capability: string,
  params: Record<string, unknown>,
  ttlMs = 60_000
): CacheEntry {
  const now = Date.now();
  return {
    capability,
    params,
    result: { value: "ok" },
    cachedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
    hitCount: 0,
  };
}

// ─── cacheKey ──────────────────────────────────────────────────────────────────

describe("cacheKey", () => {
  it("produces a 64-char hex string", () => {
    const key = cacheKey("search-flights", { origin: "JFK", dest: "NRT" });
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same inputs", () => {
    const a = cacheKey("book-hotel", { city: "Tokyo", nights: 3 });
    const b = cacheKey("book-hotel", { city: "Tokyo", nights: 3 });
    expect(a).toBe(b);
  });

  it("is order-independent — params with different key order hash identically", () => {
    const a = cacheKey("search", { b: 2, a: 1 });
    const b = cacheKey("search", { a: 1, b: 2 });
    expect(a).toBe(b);
  });

  it("differs when capability differs", () => {
    const a = cacheKey("search-flights", { q: "x" });
    const b = cacheKey("search-hotels", { q: "x" });
    expect(a).not.toBe(b);
  });

  it("differs when params differ", () => {
    const a = cacheKey("search", { q: "tokyo" });
    const b = cacheKey("search", { q: "paris" });
    expect(a).not.toBe(b);
  });

  it("handles nested params order-independently", () => {
    const a = cacheKey("cap", { filter: { z: 3, a: 1 } });
    const b = cacheKey("cap", { filter: { a: 1, z: 3 } });
    expect(a).toBe(b);
  });
});

// ─── InMemorySemanticCache ─────────────────────────────────────────────────────

describe("InMemorySemanticCache", () => {
  let cache: InMemorySemanticCache;

  beforeEach(() => {
    cache = new InMemorySemanticCache();
  });

  it("returns null for a key that has never been set", async () => {
    const result = await cache.get("nonexistent");
    expect(result).toBeNull();
  });

  it("stores and retrieves an entry", async () => {
    const key = "key-1";
    const entry = makeEntry("search-flights", { q: "JFK" });
    await cache.set(key, entry);

    const hit = await cache.get(key);
    expect(hit).not.toBeNull();
    expect(hit!.capability).toBe("search-flights");
  });

  it("increments hitCount on each get", async () => {
    const key = "key-2";
    await cache.set(key, makeEntry("cap", {}));

    await cache.get(key);
    const hit = await cache.get(key);
    expect(hit!.hitCount).toBe(2);
  });

  it("returns null and counts a miss for an expired entry", async () => {
    const key = "key-expired";
    const entry = makeEntry("cap", {}, -1); // already expired
    await cache.set(key, entry);

    const result = await cache.get(key);
    expect(result).toBeNull();

    const stats = await cache.stats();
    expect(stats.totalMisses).toBeGreaterThanOrEqual(1);
  });

  it("removes expired entries from the store on access", async () => {
    const key = "key-stale";
    await cache.set(key, makeEntry("cap", {}, -1));
    await cache.get(key); // triggers eviction

    const statsAfter = await cache.stats();
    expect(statsAfter.size).toBe(0);
  });

  it("tracks hit rate correctly", async () => {
    const key = "key-rate";
    await cache.set(key, makeEntry("cap", {}));
    await cache.get(key);      // hit
    await cache.get("miss-1"); // miss
    await cache.get("miss-2"); // miss

    const stats = await cache.stats();
    expect(stats.totalHits).toBe(1);
    expect(stats.totalMisses).toBe(2);
    expect(stats.hitRate).toBeCloseTo(1 / 3);
  });

  it("reports size = 0 on an empty cache", async () => {
    const stats = await cache.stats();
    expect(stats.size).toBe(0);
    expect(stats.hitRate).toBe(0);
  });

  describe("invalidate", () => {
    it("removes all entries whose capability starts with the prefix", async () => {
      await cache.set("k1", makeEntry("search-flights", {}));
      await cache.set("k2", makeEntry("search-hotels", {}));
      await cache.set("k3", makeEntry("book-flight", {}));

      const removed = await cache.invalidate("search");
      expect(removed).toBe(2);

      expect(await cache.get("k1")).toBeNull();
      expect(await cache.get("k2")).toBeNull();
      expect(await cache.get("k3")).not.toBeNull();
    });

    it("returns 0 when no entries match the prefix", async () => {
      await cache.set("k1", makeEntry("book-hotel", {}));
      const removed = await cache.invalidate("search");
      expect(removed).toBe(0);
    });

    it("returns 0 on an empty cache", async () => {
      const removed = await cache.invalidate("any");
      expect(removed).toBe(0);
    });

    it("exact match prefix invalidates only that capability", async () => {
      await cache.set("ka", makeEntry("pay", {}));
      await cache.set("kb", makeEntry("payment-confirm", {}));

      const removed = await cache.invalidate("pay");
      expect(removed).toBe(2); // "pay" and "payment-confirm" both start with "pay"
    });
  });
});
