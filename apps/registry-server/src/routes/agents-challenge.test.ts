/**
 * Tests for POST /v1/agents/challenge and the challengeNonce/challengeSignature
 * fields on POST /v1/agents (M6) — proving a registrant actually holds the
 * private key for the DID being registered, not just a valid API key.
 *
 * The property under test throughout: registration must fail when the
 * signature doesn't genuinely prove key possession, and succeed only when
 * it does — with real Ed25519 keys and real WebCrypto verification, not a
 * mocked crypto layer.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { makeApp } from "../test-utils/make-app.js";
import { sha256hex } from "../auth.js";
import { generateDid } from "@aroha-sdk/core/identity";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

function stubFetch() {
  return vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

async function realKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

async function signChallenge(privateKey: Uint8Array, did: string, nonce: string): Promise<string> {
  const message = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did, nonce }));
  const sig = await ed.signAsync(message, privateKey);
  return toB64(sig);
}

describe("POST /v1/agents/challenge", () => {
  it("issues a nonce with an expiry", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did: "did:aroha:x" }) },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string; expiresAt: number };
    expect(body.nonce).toBeTruthy();
    expect(body.expiresAt).toBeGreaterThan(Date.now());
  });

  it("requires authentication", async () => {
    const { app, env } = await makeApp();
    const res = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ did: "did:aroha:x" }) },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("requires a did", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({}) },
      env,
    );
    expect(res.status).toBe(400);
  });
});

describe("POST /v1/agents with a real challenge proof", () => {
  it("succeeds with a genuine signature over the issued nonce", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:proven-agent";

    const challengeRes = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    );
    const { nonce } = (await challengeRes.json()) as { nonce: string };
    const challengeSignature = await signChallenge(kp.privateKey, did, nonce);

    const res = await app.request(
      "/v1/agents",
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey),
          challengeNonce: nonce, challengeSignature,
        }),
      },
      env,
    );
    expect(res.status).toBe(201);
  });

  it("rejects a signature from a key OTHER than the one being registered — the whole point", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const owner = await realKeypair();
    const attacker = await realKeypair();
    const did = "did:aroha:impersonation-target";

    const challengeRes = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    );
    const { nonce } = (await challengeRes.json()) as { nonce: string };
    // Attacker signs with THEIR key but claims OWNER's publicKeyB64 — this
    // is exactly the impersonation attempt the challenge exists to stop.
    const forgedSignature = await signChallenge(attacker.privateKey, did, nonce);

    const res = await app.request(
      "/v1/agents",
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          did, manifestCID: "QmAbc", publicKeyB64: toB64(owner.publicKey),
          challengeNonce: nonce, challengeSignature: forgedSignature,
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("rejects a replayed (already-consumed) nonce", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:replay-target";

    const challengeRes = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    );
    const { nonce } = (await challengeRes.json()) as { nonce: string };
    const challengeSignature = await signChallenge(kp.privateKey, did, nonce);
    const body = JSON.stringify({ did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: nonce, challengeSignature });

    const first = await app.request("/v1/agents", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body }, env);
    expect(first.status).toBe(201);

    // Same nonce+signature again, now targeting a fresh DID (registering the
    // first DID again would 409 for an unrelated reason) — the nonce itself
    // must not be redeemable twice regardless.
    const secondBody = JSON.stringify({ did: "did:aroha:replay-target-2", manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: nonce, challengeSignature });
    const second = await app.request("/v1/agents", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: secondBody }, env);
    expect(second.status).toBe(403);
  });

  it("rejects a nonce issued to a different API key", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Org A");
    // A second, genuinely valid key on the SAME database — inserted the same
    // way makeApp() seeds its own key, so this exercises "two real keys, one
    // DB" rather than accidentally testing "invalid key" (401) instead of
    // "valid key, wrong owner" (403), which was the first version of this
    // test's own bug: two separate makeApp() calls create two separate
    // in-memory databases, so otherKey would never exist in env's DB at all.
    const otherKey = "test-other-key-" + Math.random().toString(36).slice(2);
    const otherKeyHash = await sha256hex(otherKey);
    const db = env.DB as unknown as { prepare: (q: string) => { bind: (...a: unknown[]) => { run: () => Promise<unknown> } } };
    await db.prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
      .bind(otherKeyHash, "Org B", Date.now())
      .run();

    const kp = await realKeypair();
    const did = "did:aroha:cross-key-target";

    const challengeRes = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    );
    const { nonce } = (await challengeRes.json()) as { nonce: string };
    const challengeSignature = await signChallenge(kp.privateKey, did, nonce);

    // Reuse the SAME app/env (same DB) but authenticate as otherKey, which
    // was never used to request this nonce.
    const res = await app.request(
      "/v1/agents",
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${otherKey}` },
        body: JSON.stringify({ did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: nonce, challengeSignature }),
      },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("rejects an expired challenge", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:expired-target";

    vi.useFakeTimers();
    try {
      const challengeRes = await app.request(
        "/v1/agents/challenge",
        { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
        env,
      );
      const { nonce } = (await challengeRes.json()) as { nonce: string };
      const challengeSignature = await signChallenge(kp.privateKey, did, nonce);

      vi.advanceTimersByTime(6 * 60_000); // past the 5-minute TTL

      const res = await app.request(
        "/v1/agents",
        {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({ did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: nonce, challengeSignature }),
        },
        env,
      );
      expect(res.status).toBe(403);
    } finally {
      vi.useRealTimers();
    }
  });

  it("requires both fields together, not just one", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const res = await app.request(
      "/v1/agents",
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ did: "did:aroha:partial", manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: "some-nonce" }),
      },
      env,
    );
    expect(res.status).toBe(400);
  });

  // The challenge used to be optional "for backward compatibility", which
  // left the gap it was meant to close open for every caller that skipped it.
  it("refuses a registration with no challenge fields", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const res = await app.request(
      "/v1/agents",
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ did: "did:aroha:unproven", manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey) }),
      },
      env,
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toMatch(/challenge/);
  });

  it("refuses a nonce without its signature", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:half-proof";
    const { nonce } = (await (await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    )).json()) as { nonce: string };
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey), challengeNonce: nonce }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("refuses a publicKeyB64 that is not 32 bytes", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did: "did:aroha:short-key", manifestCID: "QmAbc", publicKeyB64: btoa("too-short") }),
    }, env);
    expect(res.status).toBe(400);
  });
});

// ─── Content-addressed z-DIDs ────────────────────────────────────────────────

describe("POST /v1/agents — a did:aroha:z… DID is bound to the key it encodes", () => {
  async function challengeFor(app: Awaited<ReturnType<typeof makeApp>>["app"], env: unknown, apiKey: string, did: string) {
    const res = await app.request(
      "/v1/agents/challenge",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did }) },
      env,
    );
    return ((await res.json()) as { nonce: string }).nonce;
  }

  it("registers a z-DID with the key it encodes, sent as base64url", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = generateDid(kp.publicKey);
    const nonce = await challengeFor(app, env, apiKey, did);
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        did, manifestCID: "QmAbc",
        publicKeyB64: Buffer.from(kp.publicKey).toString("base64url"),
        challengeNonce: nonce, challengeSignature: await signChallenge(kp.privateKey, did, nonce),
      }),
    }, env);
    expect(res.status).toBe(201);
  });

  // The attack this closes: someone else's z-DID, registered with a key the
  // registrant DOES hold — the challenge alone would pass, because it proves
  // possession of publicKeyB64, not that publicKeyB64 belongs to the DID.
  it("refuses a z-DID registered with a key other than the one it encodes, even with a valid challenge", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const victim = await realKeypair();
    const registrant = await realKeypair();
    const did = generateDid(victim.publicKey);
    const nonce = await challengeFor(app, env, apiKey, did);
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        did, manifestCID: "QmAbc", publicKeyB64: toB64(registrant.publicKey),
        challengeNonce: nonce, challengeSignature: await signChallenge(registrant.privateKey, did, nonce),
      }),
    }, env);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toMatch(/content-addressed/);
  });

  it("refuses a malformed z-DID", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:zNotARealMultibaseKey";
    const nonce = await challengeFor(app, env, apiKey, did);
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey),
        challengeNonce: nonce, challengeSignature: await signChallenge(kp.privateKey, did, nonce),
      }),
    }, env);
    expect(res.status).toBe(400);
  });
});
