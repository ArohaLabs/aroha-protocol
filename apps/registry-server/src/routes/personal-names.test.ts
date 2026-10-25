// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Tests for POST/GET /v1/personal-names (M7 — spec §7.10). The property
// under test throughout: a label is only ever accepted when it genuinely
// derives from the DID's own committed public key, with real Ed25519 keys
// and the real scrypt-based derivation — not a mocked crypto layer.

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent, seedAgentRow } from "../test-utils/register.js";
import { sha256hex } from "../auth.js";
import { hashDID } from "./agents.js";
import { derivePersonalLabel } from "@aroha-sdk/registry/personal-name";
import { generateDid } from "@aroha-sdk/core/identity";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

/** A real content-addressed did:aroha:<multibase-pubkey> DID, matching @aroha-sdk/core's toMultibase/generateDid. */
function contentAddressedDid(publicKey: Uint8Array): string {
  // The real derivation, not a local base58: the registry now refuses a
  // z-DID whose key does not round-trip through generateDid, and the local
  // encoder dropped leading zero bytes (about 1 key in 256), which made the
  // registration in these tests fail at random.
  return generateDid(publicKey);
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

async function registerAgent(
  app: import("hono").Hono, env: unknown, apiKey: string, did: string, publicKey: Uint8Array, privateKey: Uint8Array,
) {
  return postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(publicKey) }, privateKey);
}

describe("POST /v1/personal-names", () => {
  it("mints a label that genuinely derives from the agent's own key", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    expect((await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey)).status).toBe(201);

    const label = derivePersonalLabel(kp.publicKey);
    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label }) },
      env,
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true, label, did });
  });

  it("is idempotent — re-minting your own correct label succeeds again", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);
    const label = derivePersonalLabel(kp.publicKey);
    const body = JSON.stringify({ did, label });

    const first = await app.request("/v1/personal-names", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body }, env);
    const second = await app.request("/v1/personal-names", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body }, env);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
  });

  it("rejects a label that doesn't derive from the DID's key — the whole point", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);

    const attacker = await realKeypair();
    const wrongLabel = derivePersonalLabel(attacker.publicKey); // valid shape, wrong key

    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label: wrongLabel }) },
      env,
    );
    expect(res.status).toBe(422);
  });

  it("rejects a malformed label without attempting derivation", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);

    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label: "not-a-real-label" }) },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("rejects a namespaced (non-content-addressed) DID — no key to derive from", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:acme.research"; // namespaced form
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);

    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label: derivePersonalLabel(kp.publicKey) }) },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("rejects minting for a DID owned by a different API key", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Org A");
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);

    const { apiKey: otherKey } = await makeApp("Org B");
    // otherKey belongs to a different in-memory DB than `env` — simulate a
    // real cross-tenant attempt by inserting it into THIS test's DB directly,
    // mirroring the pattern agents-challenge.test.ts uses for the same reason.
    const { sha256hex } = await import("../auth.js");
    const otherKeyHash = await sha256hex(otherKey);
    const db = env.DB as unknown as { prepare: (q: string) => { bind: (...a: unknown[]) => { run: () => Promise<unknown> } } };
    await db.prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
      .bind(otherKeyHash, "Org B", Date.now())
      .run();

    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otherKey}` }, body: JSON.stringify({ did, label: derivePersonalLabel(kp.publicKey) }) },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("rejects minting for a DID that was never registered", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);

    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label: derivePersonalLabel(kp.publicKey) }) },
      env,
    );
    expect(res.status).toBe(404);
  });

  it("requires authentication", async () => {
    const { app, env } = await makeApp();
    const res = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ did: "did:aroha:zAbc", label: "x" }) },
      env,
    );
    expect(res.status).toBe(401);
  });
});

describe("GET /v1/personal-names/:label", () => {
  it("resolves a minted label to its DID", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = contentAddressedDid(kp.publicKey);
    await registerAgent(app, env, apiKey, did, kp.publicKey, kp.privateKey);
    const label = derivePersonalLabel(kp.publicKey);
    await app.request("/v1/personal-names", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label }) }, env);

    const res = await app.request(`/v1/personal-names/${label}`, {}, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ label, did });
  });

  // Replaces the pinning tests of the Worker's former private copy of the
  // derivation (deleted — the route now uses @aroha-sdk/registry/personal-name
  // itself). What still needs pinning is the WIRE value: the label this route
  // accepts for a known key is the cross-SDK test vector, so a change to the
  // package's derivation that would rename every agent fails here, at the
  // endpoint, not just in the package's unit tests.
  it("accepts exactly the cross-SDK test vector for a known key, end to end", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const publicKey = new Uint8Array(32).fill(7);
    const did = contentAddressedDid(publicKey);
    // Nobody holds the private half of this fixed vector, so it cannot pass
    // the registration challenge; seed the row the route would have written.
    await seedAgentRow(env, { did, didHash: hashDID(did), publicKeyB64: toB64(publicKey), ownerKeyHash: await sha256hex(apiKey) });
    const label = "broccoli-hotel-manual-position-crew-word";
    const minted = await app.request(
      "/v1/personal-names",
      { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ did, label }) },
      env,
    );
    expect(minted.status).toBe(201);
    expect(await (await app.request(`/v1/personal-names/${label}`, {}, env)).json()).toEqual({ label, did });
  });

  it("404s for a well-formed but unminted label", async () => {
    const { app, env } = await makeApp();
    const label = "broccoli-hotel-manual-position-crew-word"; // real wordlist tokens (§7.10 shape), never minted
    const res = await app.request(`/v1/personal-names/${label}`, {}, env);
    expect(res.status).toBe(404);
  });

  it("404s (not a crash) for a malformed label", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/personal-names/not-a-label", {}, env);
    expect(res.status).toBe(404);
  });
});
