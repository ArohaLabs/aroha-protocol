// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Security properties of aroha-sig request signing. Every negative case here is
// an attack the scheme is meant to stop; if one starts passing, the guarantee
// it encodes is gone.

import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import {
  signRequest, verifySignedRequest, createNonceGuard, canonicalString, SIG_HEADERS,
  registryKeyResolver,
} from "./signing.js";

const CALLER = "did:aroha:caller";
const OTHER = "did:aroha:other";

let priv: Uint8Array;
let pub: Uint8Array;
let otherPriv: Uint8Array;
let otherPub: Uint8Array;

async function generate(): Promise<{ priv: Uint8Array; pub: Uint8Array }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", (kp as CryptoKeyPair).privateKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", (kp as CryptoKeyPair).publicKey));
  return { priv: pkcs8, pub: raw };
}

beforeAll(async () => {
  ({ priv, pub } = await generate());
  const other = await generate();
  otherPriv = other.priv;
  otherPub = other.pub;
});

const resolver = (map: Record<string, Uint8Array>) => (did: string) => map[did] ?? null;

async function signed(body: string, overrides: Partial<Parameters<typeof signRequest>[0]> = {}) {
  return signRequest({
    did: CALLER, privateKey: priv, method: "POST", path: "/v1/run", body, ...overrides,
  });
}

describe("signRequest / verifySignedRequest", () => {
  it("accepts a correctly signed request", async () => {
    const body = JSON.stringify({ message: "hello" });
    const headers = await signed(body);

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(true);
    expect(result.did).toBe(CALLER);
  });

  it("rejects a tampered body — the signature covers a hash of it", async () => {
    const body = JSON.stringify({ message: "transfer $10" });
    const headers = await signed(body);

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run",
      body: JSON.stringify({ message: "transfer $10000" }),
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Invalid signature");
  });

  it("rejects a signature replayed against a different path", async () => {
    const body = "{}";
    const headers = await signed(body);

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/admin", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a signature replayed with a different method", async () => {
    const body = "{}";
    const headers = await signed(body);

    const result = await verifySignedRequest({
      headers, method: "DELETE", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a request signed by the wrong key (impersonation)", async () => {
    const body = "{}";
    // Attacker signs with their own key but claims the victim's DID.
    const headers = await signRequest({
      did: CALLER, privateKey: otherPriv, method: "POST", path: "/v1/run", body,
    });

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Invalid signature");
  });

  it("rejects an unknown caller whose key cannot be resolved", async () => {
    const body = "{}";
    const headers = await signRequest({
      did: "did:aroha:ghost", privateKey: priv, method: "POST", path: "/v1/run", body,
    });

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Unknown caller key");
  });

  it("rejects a stale timestamp", async () => {
    const body = "{}";
    const headers = await signed(body, {
      timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    });

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Timestamp outside the accepted window");
  });

  it("rejects a future timestamp beyond the skew window", async () => {
    const body = "{}";
    const headers = await signed(body, {
      timestamp: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    });
    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects missing signature headers", async () => {
    const result = await verifySignedRequest({
      headers: {}, method: "POST", path: "/v1/run", body: "{}",
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Missing signature headers");
  });

  it("fails closed when the key resolver throws", async () => {
    const body = "{}";
    const headers = await signed(body);
    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: () => { throw new Error("registry down"); },
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Could not resolve caller key");
  });

  it("reads headers from a Headers instance as well as a plain object", async () => {
    const body = "{}";
    const plain = await signed(body);
    const headers = new Headers(plain);

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
    });
    expect(result.ok).toBe(true);
  });
});

describe("allowedCallers", () => {
  it("permits a caller on the list", async () => {
    const body = "{}";
    const headers = await signed(body);
    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
      allowedCallers: [CALLER, OTHER],
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a valid signature from a caller not on the list", async () => {
    const body = "{}";
    const headers = await signRequest({
      did: OTHER, privateKey: otherPriv, method: "POST", path: "/v1/run", body,
    });
    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [OTHER]: otherPub }),
      allowedCallers: [CALLER],
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("Caller not permitted");
  });

  it("an empty allow-list permits nobody", async () => {
    const body = "{}";
    const headers = await signed(body);
    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
      allowedCallers: [],
    });
    expect(result.ok).toBe(false);
  });

  // Ordering is the security property, not just the outcome. If the key is
  // resolved before the allow-list is consulted, the verifier performs a
  // registry lookup on behalf of an unauthorised caller — which turns a private
  // endpoint into an oracle for "does this DID exist?", observable through
  // latency, and lets an attacker drive traffic to the registry for free.
  //
  // Asserting the resolver was never called tests the ordering directly,
  // rather than trying to infer it from timing.
  it("does not resolve a key for a caller who is not on the list", async () => {
    const body = "{}";
    const headers = await signRequest({
      did: OTHER, privateKey: otherPriv, method: "POST", path: "/v1/run", body,
    });

    let resolveCalls = 0;
    const countingResolver = async (did: string) => {
      resolveCalls++;
      return did === OTHER ? otherPub : null;
    };

    const result = await verifySignedRequest({
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: countingResolver,
      allowedCallers: [CALLER],
    });

    expect(result.ok).toBe(false);
    expect(resolveCalls).toBe(0);
  });
});

describe("replay protection", () => {
  it("rejects a byte-identical replay of a valid request", async () => {
    const body = "{}";
    const headers = await signed(body);
    const guard = createNonceGuard();
    const args = {
      headers, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }),
      consumeNonce: guard,
    };

    expect((await verifySignedRequest(args)).ok).toBe(true);
    const replay = await verifySignedRequest(args);
    expect(replay.ok).toBe(false);
    expect(replay.reason).toBe("Replayed nonce");
  });

  it("does not consume a nonce for a request that fails verification", async () => {
    const body = "{}";
    const guard = createNonceGuard();
    const nonce = "fixed-nonce";

    // A bad signature must not burn the nonce, or an attacker could grief a
    // caller by pre-consuming their nonces with junk requests.
    const forged = await signRequest({
      did: CALLER, privateKey: otherPriv, method: "POST", path: "/v1/run", body, nonce,
    });
    expect((await verifySignedRequest({
      headers: forged, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }), consumeNonce: guard,
    })).ok).toBe(false);

    const genuine = await signed(body, { nonce });
    expect((await verifySignedRequest({
      headers: genuine, method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }), consumeNonce: guard,
    })).ok).toBe(true);
  });

  it("allows distinct nonces from the same caller", async () => {
    const body = "{}";
    const guard = createNonceGuard();
    const base = {
      method: "POST", path: "/v1/run", body,
      resolvePublicKey: resolver({ [CALLER]: pub }), consumeNonce: guard,
    };
    expect((await verifySignedRequest({ ...base, headers: await signed(body) })).ok).toBe(true);
    expect((await verifySignedRequest({ ...base, headers: await signed(body) })).ok).toBe(true);
  });
});

describe("canonicalString", () => {
  it("is stable and order-sensitive", async () => {
    const a = await canonicalString("post", "/v1/run", "T", "N", "{}");
    const b = await canonicalString("POST", "/v1/run", "T", "N", "{}");
    expect(a).toBe(b);                       // method is upper-cased
    expect(a.split("\n")).toHaveLength(5);

    const different = await canonicalString("POST", "/v1/other", "T", "N", "{}");
    expect(different).not.toBe(a);
  });

  it("emits the header names the verifier reads", async () => {
    const headers = await signed("{}");
    expect(Object.keys(headers).sort()).toEqual(
      [SIG_HEADERS.did, SIG_HEADERS.nonce, SIG_HEADERS.signature, SIG_HEADERS.timestamp].sort(),
    );
  });
});

describe("registryKeyResolver — cache expiry", () => {
  // Regression coverage for a real bug found via live end-to-end testing of
  // the local runtime: a DID that resolved to null on first lookup (not yet
  // registered) cached that null forever, permanently breaking every future
  // request from a caller who registered moments too late. Fixed by giving
  // both hits and misses a TTL; misses expire faster since "registration
  // just completed" is the likely near-term change.

  afterEach(() => vi.unstubAllGlobals());

  it("re-fetches after a miss's TTL expires, rather than caching null forever", async () => {
    vi.useFakeTimers();
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls++;
      return new Response(null, { status: 404 });
    });

    const resolve = registryKeyResolver("http://registry.invalid");
    expect(await resolve("did:aroha:not-yet-registered")).toBeNull();
    expect(calls).toBe(1);

    // Immediately after: still within the miss TTL, so the cached null is
    // reused rather than re-fetching.
    expect(await resolve("did:aroha:not-yet-registered")).toBeNull();
    expect(calls).toBe(1);

    // Past the miss TTL: must re-fetch, giving a since-completed
    // registration a chance to actually resolve.
    vi.advanceTimersByTime(31_000);
    expect(await resolve("did:aroha:not-yet-registered")).toBeNull();
    expect(calls).toBe(2);

    vi.useRealTimers();
  });

  it("serves a resolved key from cache within the hit TTL without re-fetching", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const keyB64 = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");
    vi.stubGlobal("fetch", async () => {
      calls++;
      return new Response(JSON.stringify({ publicKeyB64: keyB64 }), { status: 200 });
    });

    const resolve = registryKeyResolver("http://registry.invalid");
    const first = await resolve("did:aroha:known");
    expect(first).not.toBeNull();
    expect(calls).toBe(1);

    vi.advanceTimersByTime(60_000); // well within the 5-minute hit TTL
    await resolve("did:aroha:known");
    expect(calls).toBe(1);

    vi.useRealTimers();
  });

  it("eventually re-resolves a cached hit so key rotation can propagate", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const keyB64 = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");
    vi.stubGlobal("fetch", async () => {
      calls++;
      return new Response(JSON.stringify({ publicKeyB64: keyB64 }), { status: 200 });
    });

    const resolve = registryKeyResolver("http://registry.invalid");
    await resolve("did:aroha:known");
    vi.advanceTimersByTime(5 * 60_000 + 1_000); // past the hit TTL
    await resolve("did:aroha:known");

    expect(calls).toBe(2);
    vi.useRealTimers();
  });

  it("does not cache a transient network failure at all", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls++;
      throw new Error("network down");
    });

    const resolve = registryKeyResolver("http://registry.invalid");
    await resolve("did:aroha:x");
    await resolve("did:aroha:x");
    expect(calls).toBe(2); // every call re-attempts — nothing was cached
  });
});
