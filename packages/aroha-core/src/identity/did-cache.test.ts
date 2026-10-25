// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DidResolutionCache — the TTL policy per DID method is a security property,
 * not a performance detail: a key that can rotate or be revoked must not be
 * cached forever, and a multi-key DID must not answer every key id with the
 * first key it happened to resolve.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { DidResolutionCache, DidNotFoundError } from "./did-cache.js";
import { generateContentAddressedDID } from "./did.js";

afterEach(() => { vi.useRealTimers(); });

const key = (n: number) => new Uint8Array(32).fill(n);

describe("DidResolutionCache", () => {
  it("serves a second lookup from cache without calling the resolver", async () => {
    const cache = new DidResolutionCache();
    const resolver = vi.fn(async () => key(1));
    const wrapped = cache.wrap(resolver);
    expect(await wrapped("did:aroha:alice")).toEqual(key(1));
    expect(await wrapped("did:aroha:alice")).toEqual(key(1));
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it("caches a content-addressed did:aroha:z… permanently (the key is the DID)", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ defaultTtlMs: 1_000 });
    const z = await generateContentAddressedDID("http://localhost");
    const resolver = vi.fn(async () => z.publicKey);
    const wrapped = cache.wrap(resolver);
    expect(await wrapped(z.did)).toEqual(z.publicKey);
    vi.advanceTimersByTime(365 * 24 * 3_600_000);
    expect(await wrapped(z.did)).toEqual(z.publicKey);
    // L5: the primary key is derived from the DID — no resolver call at all.
    expect(resolver).toHaveBeenCalledTimes(0);
  });

  it("never trusts or caches a resolver key that contradicts a z-DID (L5)", async () => {
    const cache = new DidResolutionCache();
    const z = await generateContentAddressedDID("http://localhost");
    const resolver = vi.fn(async () => key(9));
    const wrapped = cache.wrap(resolver);
    // Primary: derived locally, the lying resolver is never consulted.
    expect(await wrapped(z.did)).toEqual(z.publicKey);
    // A named verification method: passed through, but not cached.
    const vm = `${z.did}#device-2`;
    expect(await wrapped(z.did, vm)).toEqual(key(9));
    await wrapped(z.did, vm);
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("expires a named DID after defaultTtlMs, so a rotated/revoked key is re-resolved", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ defaultTtlMs: 1_000 });
    const resolver = vi.fn(async () => key(2));
    const wrapped = cache.wrap(resolver);
    await wrapped("did:aroha:bob");
    vi.advanceTimersByTime(999);
    await wrapped("did:aroha:bob");
    expect(resolver).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(2);
    await wrapped("did:aroha:bob");
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("does NOT cache a rotatable did:aroha:E… forever", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ defaultTtlMs: 1_000 });
    const resolver = vi.fn(async () => key(3));
    const wrapped = cache.wrap(resolver);
    const eDid = "did:aroha:EAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg";
    await wrapped(eDid);
    vi.advanceTimersByTime(1_001);
    await wrapped(eDid);
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("uses webDidTtlMs for did:aroha-web:", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ webDidTtlMs: 5_000, defaultTtlMs: 1_000 });
    const resolver = vi.fn(async () => key(4));
    const wrapped = cache.wrap(resolver);
    await wrapped("did:aroha-web:acme.com:agent");
    vi.advanceTimersByTime(4_000);
    await wrapped("did:aroha-web:acme.com:agent");
    expect(resolver).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1_500);
    await wrapped("did:aroha-web:acme.com:agent");
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("caches per verification method — a device key is not answered with the primary key", async () => {
    const cache = new DidResolutionCache();
    const resolver = vi.fn(async (_did: string, vm?: string) => (vm?.endsWith("#device-2") ? key(9) : key(1)));
    const wrapped = cache.wrap(resolver);
    expect(await wrapped("did:aroha:carol", "did:aroha:carol#key-1")).toEqual(key(1));
    expect(await wrapped("did:aroha:carol", "did:aroha:carol#device-2")).toEqual(key(9));
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("does not cache a plain null (may be transient) or a thrown error (L5)", async () => {
    const cache = new DidResolutionCache();
    const resolver = vi.fn(async () => null);
    const wrapped = cache.wrap(resolver);
    expect(await wrapped("did:aroha:ghost")).toBeNull();
    expect(await wrapped("did:aroha:ghost")).toBeNull();
    expect(resolver).toHaveBeenCalledTimes(2);
    const flaky = vi.fn(async () => { throw new Error("ETIMEDOUT"); });
    const w2 = cache.wrap(flaky);
    await expect(w2("did:aroha:flaky")).rejects.toThrow(/ETIMEDOUT/);
    await expect(w2("did:aroha:flaky")).rejects.toThrow(/ETIMEDOUT/);
    expect(flaky).toHaveBeenCalledTimes(2);
  });

  it("caches a definitive not-found (DidNotFoundError) for notFoundTtlMs", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ notFoundTtlMs: 1_000 });
    const resolver = vi.fn(async (did: string) => { throw new DidNotFoundError(did); });
    const wrapped = cache.wrap(resolver);
    expect(await wrapped("did:aroha:ghost")).toBeNull();
    expect(await wrapped("did:aroha:ghost")).toBeNull();
    expect(resolver).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1_001);
    await wrapped("did:aroha:ghost");
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("invalidate() drops the DID and every per-verification-method entry for it", async () => {
    const cache = new DidResolutionCache();
    const resolver = vi.fn(async () => key(5));
    const wrapped = cache.wrap(resolver);
    await wrapped("did:aroha:dave");
    await wrapped("did:aroha:dave", "did:aroha:dave#device-2");
    await wrapped("did:aroha:dave2");
    expect(cache.size).toBe(3);
    cache.invalidate("did:aroha:dave");
    expect(cache.size).toBe(1); // did:aroha:dave2 is a different DID and stays
    await wrapped("did:aroha:dave");
    expect(resolver).toHaveBeenCalledTimes(4);
  });

  it("evicts the least-recently-used entry at maxSize", async () => {
    vi.useFakeTimers();
    const cache = new DidResolutionCache({ maxSize: 2 });
    cache.set("did:aroha:a", key(1));
    vi.advanceTimersByTime(10);
    cache.set("did:aroha:b", key(2));
    vi.advanceTimersByTime(10);
    expect(cache.get("did:aroha:a")).toEqual(key(1)); // touch a — b is now LRU
    vi.advanceTimersByTime(10);
    cache.set("did:aroha:c", key(3));
    expect(cache.size).toBe(2);
    expect(cache.get("did:aroha:b")).toBeUndefined();
    expect(cache.get("did:aroha:a")).toEqual(key(1));
    expect(cache.get("did:aroha:c")).toEqual(key(3));
  });

  it("get() returns undefined on a miss", () => {
    expect(new DidResolutionCache().get("did:aroha:nobody")).toBeUndefined();
  });
});
