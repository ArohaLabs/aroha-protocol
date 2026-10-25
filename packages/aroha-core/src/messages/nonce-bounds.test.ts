// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** L3/L4: nonce length cap, bounded MapNonceStore, one store for check()/checkAsync(). */

import { describe, it, expect } from "vitest";
import { NonceRegistry, MapNonceStore, type NonceStore } from "./nonce.js";
import { buildEnvelope, validateEnvelope, MAX_NONCE_LENGTH } from "./envelope.js";
import { generateDID } from "../identity/did.js";

describe("MapNonceStore bounds", () => {
  it("evicts the soonest-expiring entry past maxEntries", () => {
    const s = new MapNonceStore({ maxEntries: 2 });
    const now = Date.now();
    expect(s.setIfAbsentSync("late", now + 60_000)).toBe(true);
    expect(s.setIfAbsentSync("soon", now + 1_000)).toBe(true);
    expect(s.setIfAbsentSync("third", now + 30_000)).toBe(true);
    expect(s.size).toBe(2);
    expect(s.setIfAbsentSync("late", now + 60_000)).toBe(false); // still remembered
    expect(s.setIfAbsentSync("soon", now + 1_000)).toBe(true);   // was evicted
  });

  it("refuses a NaN expiry instead of storing a never-evicted entry", () => {
    const s = new MapNonceStore();
    expect(s.setIfAbsentSync("x", NaN)).toBe(false);
    expect(s.size).toBe(0);
  });
});

describe("NonceRegistry.check / checkAsync share one store", () => {
  it("a nonce seen by checkAsync is a replay to check, and vice versa", async () => {
    const r = new NonceRegistry();
    const exp = new Date(Date.now() + 60_000).toISOString();
    expect(await r.checkAsync("a", exp)).toBe(true);
    expect(r.check("a", exp)).toBe(false);
    expect(r.check("b", exp)).toBe(true);
    expect(await r.checkAsync("b", exp)).toBe(false);
    r.destroy();
  });

  it("check() throws when a custom store is configured", () => {
    const store: NonceStore = { async setIfAbsent() { return true; }, async evictExpired() {} };
    const r = new NonceRegistry(60_000, store);
    expect(() => r.check("a", new Date(Date.now() + 1000).toISOString())).toThrow(/checkAsync/);
    r.destroy();
  });

  it("checkAsync refuses an unparseable expiry", async () => {
    const r = new NonceRegistry();
    expect(await r.checkAsync("a", "garbage")).toBe(false);
    r.destroy();
  });
});

describe("validateEnvelope nonce length cap", () => {
  it(`rejects a nonce longer than ${MAX_NONCE_LENGTH}`, async () => {
    const s = await generateDID("nonce-sender", "http://127.0.0.1");
    const env = await buildEnvelope("ArohaRequest", s.did, "did:aroha:r", { capability: "x", params: {} }, "c", s.privateKey);
    const long = { ...env, nonce: "a".repeat(MAX_NONCE_LENGTH + 1) };
    const reg = new NonceRegistry();
    const r = await validateEnvelope(long, s.publicKey, "did:aroha:r", reg);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Nonce longer/);
    reg.destroy();
  });
});
