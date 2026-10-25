// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createArohaRegistryServer } from "./http-server.js";
import type { ArohaRegistryServerHandle } from "./http-server.js";
import { InMemoryRegistry } from "./memory-registry.js";
import * as ed from "@noble/ed25519";
import { signRegistrationChallenge } from "./registration-proof.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function json(res: Response) {
  return res.json() as Promise<Record<string, unknown>>;
}

const TEST_DID = "did:aroha:test-agent";
// A real keypair: registration now requires proving possession of the key.
const TEST_PRIV = new Uint8Array(32).fill(1);
const TEST_KEY_B64 = Buffer.from(await ed.getPublicKeyAsync(TEST_PRIV)).toString("base64url");

/** Run the challenge exchange and return the fields POST /v1/agents now requires. */
async function proof(base: string, did: string, token?: string): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${base}/v1/agents/challenge`, { method: "POST", headers, body: JSON.stringify({ did }) });
  const { nonce } = (await res.json()) as { nonce: string };
  const sig = await signRegistrationChallenge({ privateKey: TEST_PRIV }, did, nonce);
  return { challengeNonce: nonce, challengeSignature: Buffer.from(sig).toString("base64url") };
}
const TEST_CID = "QmTestManifestCID123";
const TEST_CAPABILITIES = ["search-flights", "book-hotel"];
const API_KEY = "test-secret-key";

// ─── Unauthenticated server ───────────────────────────────────────────────────

describe("createArohaRegistryServer — no auth (dev mode)", () => {
  let server: ArohaRegistryServerHandle;
  let base: string;

  beforeAll(async () => {
    server = createArohaRegistryServer({ port: 0 as unknown as number });
    // port 0 is not supported by the implementation — use a fixed free port
    server = createArohaRegistryServer({ port: 47201 });
    await server.listen();
    base = `http://127.0.0.1:${server.port}`;
  });

  afterAll(() => server.close());

  it("GET /healthz returns { status: 'ok' }", async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ status: "ok" });
  });

  it("POST /v1/agents registers an agent and returns didHash", async () => {
    const res = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: TEST_DID,
        manifestCID: TEST_CID,
        publicKeyB64: TEST_KEY_B64,
        capabilityIds: TEST_CAPABILITIES,
        ...(await proof(base, TEST_DID)),
      }),
    });
    expect(res.status).toBe(201);
    const body = await json(res);
    expect(typeof body.didHash).toBe("string");
    expect((body.didHash as string).startsWith("0x")).toBe(true);
    expect(body.did).toBe(TEST_DID);
  });

  it("GET /v1/agents?capabilities=search-flights returns the registered agent", async () => {
    const res = await fetch(`${base}/v1/agents?capabilities=search-flights`);
    expect(res.status).toBe(200);
    const agents = await res.json() as unknown[];
    expect(agents.length).toBeGreaterThan(0);
  });

  it("GET /v1/agents/:didHash resolves the registered agent", async () => {
    // First register to get the didHash
    const regRes = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:aroha:resolve-test",
        manifestCID: TEST_CID,
        publicKeyB64: TEST_KEY_B64,
        capabilityIds: [],
        ...(await proof(base, "did:aroha:resolve-test")),
      }),
    });
    const { didHash } = await json(regRes) as { didHash: string };

    const res = await fetch(`${base}/v1/agents/${didHash}`);
    expect(res.status).toBe(200);
    const record = await json(res);
    expect(record.manifestCID).toBe(TEST_CID);
    expect(record.active).toBe(true);
  });

  it("GET /v1/agents/:didHash returns 404 for unknown hash", async () => {
    const res = await fetch(`${base}/v1/agents/0xdeadbeef`);
    expect(res.status).toBe(404);
  });

  it("PUT /v1/agents/:didHash/manifest updates the manifest CID", async () => {
    const regRes = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:aroha:manifest-update-test",
        manifestCID: "QmOriginal",
        publicKeyB64: TEST_KEY_B64,
        capabilityIds: [],
        ...(await proof(base, "did:aroha:manifest-update-test")),
      }),
    });
    const { didHash } = await json(regRes) as { didHash: string };

    const putRes = await fetch(`${base}/v1/agents/${didHash}/manifest`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ manifestCID: "QmUpdated" }),
    });
    expect(putRes.status).toBe(200);
    expect(await json(putRes)).toEqual({ updated: true });

    const getRes = await fetch(`${base}/v1/agents/${didHash}`);
    const record = await json(getRes);
    expect(record.manifestCID).toBe("QmUpdated");
  });

  it("DELETE /v1/agents/:didHash deactivates the agent", async () => {
    const regRes = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:aroha:deactivate-test",
        manifestCID: TEST_CID,
        publicKeyB64: TEST_KEY_B64,
        capabilityIds: [],
        ...(await proof(base, "did:aroha:deactivate-test")),
      }),
    });
    const { didHash } = await json(regRes) as { didHash: string };

    const delRes = await fetch(`${base}/v1/agents/${didHash}`, { method: "DELETE" });
    expect(delRes.status).toBe(200);
    expect(await json(delRes)).toEqual({ deactivated: true });

    const getRes = await fetch(`${base}/v1/agents/${didHash}`);
    expect(getRes.status).toBe(404);
  });

  it("POST /v1/agents without required fields returns 400", async () => {
    const res = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:aroha:incomplete" }),
    });
    expect(res.status).toBe(400);
  });

  it("GET /v1/agents without capabilities param returns 400", async () => {
    const res = await fetch(`${base}/v1/agents`);
    expect(res.status).toBe(400);
  });

  it("unknown route returns 404", async () => {
    const res = await fetch(`${base}/not-a-real-path`);
    expect(res.status).toBe(404);
  });
});

// ─── Authenticated server ─────────────────────────────────────────────────────

describe("createArohaRegistryServer — with apiKey", () => {
  let server: ArohaRegistryServerHandle;
  let base: string;

  beforeAll(async () => {
    server = createArohaRegistryServer({ port: 47202, apiKey: API_KEY });
    await server.listen();
    base = `http://127.0.0.1:${server.port}`;
  });

  afterAll(() => server.close());

  it("GET /healthz is accessible without auth", async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
  });

  it("POST /v1/agents without auth returns 401", async () => {
    const res = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: TEST_DID, manifestCID: TEST_CID, publicKeyB64: TEST_KEY_B64 }),
    });
    expect(res.status).toBe(401);
  });

  it("POST /v1/agents with wrong token returns 401", async () => {
    const res = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-key" },
      body: JSON.stringify({ did: TEST_DID, manifestCID: TEST_CID, publicKeyB64: TEST_KEY_B64 }),
    });
    expect(res.status).toBe(401);
  });

  it("POST /v1/agents with correct Bearer token succeeds", async () => {
    const res = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        did: "did:aroha:auth-test",
        manifestCID: TEST_CID,
        publicKeyB64: TEST_KEY_B64,
        capabilityIds: [],
        ...(await proof(base, "did:aroha:auth-test", API_KEY)),
      }),
    });
    expect(res.status).toBe(201);
  });

  it("GET /v1/agents (read) does not require auth", async () => {
    const res = await fetch(`${base}/v1/agents?capabilities=search-flights`);
    // 200 (no results) or 400 — either way, not 401
    expect(res.status).not.toBe(401);
  });
});
