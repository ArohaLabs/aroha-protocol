// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Idempotency store — a retried capability call must return the cached
 * response instead of running twice, and one sender must never be able to
 * read another sender's cached response.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  InMemoryIdempotencyStore,
  checkIdempotency,
  storeIdempotency,
} from "./idempotency.js";
import type { ArohaEnvelope } from "./envelope.js";

const stores: InMemoryIdempotencyStore[] = [];
function newStore(cfg?: ConstructorParameters<typeof InMemoryIdempotencyStore>[0]) {
  const s = new InMemoryIdempotencyStore(cfg);
  stores.push(s);
  return s;
}
afterEach(() => {
  for (const s of stores.splice(0)) s.destroy();
  vi.useRealTimers();
});

function envelope(from: string, body: Record<string, unknown>, id = "e1"): ArohaEnvelope {
  return { id, type: "ArohaRequest", from, to: "did:aroha:server", body } as unknown as ArohaEnvelope;
}

describe("InMemoryIdempotencyStore", () => {
  it("returns what was stored, scoped to the sender", async () => {
    const store = newStore();
    const resp = envelope("did:aroha:server", { result: 1 }, "r1");
    await store.set("did:aroha:alice", "k1", resp);
    expect(await store.get("did:aroha:alice", "k1")).toBe(resp);
    expect(await store.get("did:aroha:bob", "k1")).toBeNull();
  });

  it("does not let a colon in the key collide with a longer sender DID", async () => {
    // Regression: the composite key used to be `${sender}:${key}`, so these
    // two (sender, key) pairs were the same entry.
    const store = newStore();
    const resp = envelope("did:aroha:server", { secret: "alice-only" }, "r1");
    await store.set("did:aroha:a", "b:c", resp);
    expect(await store.get("did:aroha:a:b", "c")).toBeNull();
  });

  it("expires entries after their TTL", async () => {
    vi.useFakeTimers();
    const store = newStore({ defaultTtlMs: 1_000 });
    await store.set("did:aroha:alice", "k", envelope("s", {}));
    vi.advanceTimersByTime(1_001);
    expect(await store.get("did:aroha:alice", "k")).toBeNull();
    expect(store.size).toBe(0);
  });

  it("honours a per-entry TTL override", async () => {
    vi.useFakeTimers();
    const store = newStore({ defaultTtlMs: 1_000 });
    await store.set("did:aroha:alice", "k", envelope("s", {}), 10_000);
    vi.advanceTimersByTime(5_000);
    expect(await store.get("did:aroha:alice", "k")).not.toBeNull();
  });

  it("the periodic sweep evicts expired entries nobody reads again", async () => {
    vi.useFakeTimers();
    const store = newStore({ defaultTtlMs: 1_000, cleanupIntervalMs: 2_000 });
    await store.set("did:aroha:alice", "k", envelope("s", {}));
    expect(store.size).toBe(1);
    vi.advanceTimersByTime(2_001);
    expect(store.size).toBe(0);
  });
});

describe("checkIdempotency / storeIdempotency", () => {
  it("round-trips a response for a request carrying an idempotencyKey", async () => {
    const store = newStore();
    const req = envelope("did:aroha:alice", { capability: "book", idempotencyKey: "trip-1" });
    expect(await checkIdempotency(store, req)).toBeNull();
    const resp = envelope("did:aroha:server", { result: "booked" }, "r1");
    await storeIdempotency(store, req, resp);
    expect(await checkIdempotency(store, req)).toBe(resp);
  });

  it("is a no-op for requests without an idempotencyKey", async () => {
    const store = newStore();
    const req = envelope("did:aroha:alice", { capability: "book" });
    await storeIdempotency(store, req, envelope("s", {}));
    expect(store.size).toBe(0);
    expect(await checkIdempotency(store, req)).toBeNull();
  });

  it("the same key from a different sender is a different request", async () => {
    const store = newStore();
    await storeIdempotency(
      store,
      envelope("did:aroha:alice", { idempotencyKey: "k" }),
      envelope("s", { result: "alice" }),
    );
    expect(await checkIdempotency(store, envelope("did:aroha:mallory", { idempotencyKey: "k" }))).toBeNull();
  });
});
