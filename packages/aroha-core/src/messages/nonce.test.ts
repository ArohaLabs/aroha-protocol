// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { NonceRegistry, MapNonceStore, type NonceStore } from "./nonce.js";

describe("MapNonceStore (default)", () => {
  it("accepts a fresh nonce", () => {
    const r = new NonceRegistry();
    const exp = new Date(Date.now() + 60_000).toISOString();
    expect(r.check("abc", exp)).toBe(true);
  });

  it("rejects a replayed nonce", () => {
    const r = new NonceRegistry();
    const exp = new Date(Date.now() + 60_000).toISOString();
    r.check("abc", exp);
    expect(r.check("abc", exp)).toBe(false);
  });

  it("evicts expired nonces", async () => {
    const r = new NonceRegistry(100);
    const exp = new Date(Date.now() - 1).toISOString(); // already expired
    r.check("stale", exp);
    await new Promise((res) => setTimeout(res, 150));
    expect(r.size).toBe(0);
  });

  it("accepts a fresh nonce after expired one is evicted", async () => {
    const r = new NonceRegistry(100);
    const expiredAt = new Date(Date.now() - 1).toISOString();
    r.check("stale", expiredAt);
    await new Promise((res) => setTimeout(res, 150));
    const freshExp = new Date(Date.now() + 60_000).toISOString();
    expect(r.check("stale", freshExp)).toBe(true); // evicted, so fresh again
  });
});

describe("custom NonceStore injection", () => {
  it("delegates check to custom store", async () => {
    const calls: string[] = [];
    const store: NonceStore = {
      async setIfAbsent(nonce, _expiryMs) {
        calls.push(nonce);
        return !calls.slice(0, -1).includes(nonce);
      },
      async evictExpired() {},
    };
    const r = new NonceRegistry(60_000, store);
    const exp = new Date(Date.now() + 60_000).toISOString();
    expect(await r.checkAsync("n1", exp)).toBe(true);
    expect(await r.checkAsync("n1", exp)).toBe(false);
    expect(calls).toEqual(["n1", "n1"]);
  });
});

describe("NonceRegistry async path — injected store usage", () => {
  it("calls the injected store, not the in-process map", async () => {
    const calls: string[] = [];
    const mockStore: NonceStore = {
      setIfAbsent: async (nonce) => {
        calls.push(nonce);
        return true;
      },
      evictExpired: async () => {},
    };
    const registry = new NonceRegistry(60_000, mockStore);
    const fresh = await registry.checkAsync(
      "abc123",
      new Date(Date.now() + 60_000).toISOString()
    );
    registry.destroy();
    expect(fresh).toBe(true);
    expect(calls).toContain("abc123");
  });

  it("returns false for a replayed nonce via injected store", async () => {
    const seen = new Set<string>();
    const mockStore: NonceStore = {
      setIfAbsent: async (nonce) => {
        if (seen.has(nonce)) return false;
        seen.add(nonce);
        return true;
      },
      evictExpired: async () => {},
    };
    const registry = new NonceRegistry(60_000, mockStore);
    const expires = new Date(Date.now() + 60_000).toISOString();
    const first = await registry.checkAsync("replay-me", expires);
    const second = await registry.checkAsync("replay-me", expires);
    registry.destroy();
    expect(first).toBe(true);
    expect(second).toBe(false);
  });
});
