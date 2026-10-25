/**
 * HTTP route tests for /v1/agents — exercising the full Hono request/response
 * cycle with an in-memory SQLite database (no Cloudflare Workers runtime needed).
 *
 * Uses `app.request(path, init, env)` — Hono's test helper that drives the
 * router without a real HTTP server. The third argument is passed as `c.env`,
 * so the same D1Database / ADMIN_SECRET bindings work as in production.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { verifyMandate, issueIntentMandate } from "@aroha-sdk/credentials";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent, manifestWith, stubManifestFetch } from "../test-utils/register.js";
import { buildCIDv0 } from "../test-utils/cid-builder.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// Build a base64-standard (not url) encoded string from a Uint8Array.
function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

// Stub fetch so IPFS manifest lookups return [] without real network calls.
// Return an empty capabilities manifest for all gateway URLs.
function stubFetch(capabilities: Array<{ id: string }> = []) {
  return vi.stubGlobal("fetch", async () =>
    new Response(JSON.stringify({ capabilities }), { status: 200 }),
  );
}

// Stub fetch to return a raw IPLD block (exercises the CID-verification path).
function stubFetchRaw(block: Uint8Array) {
  return vi.stubGlobal("fetch", async () =>
    new Response(block, {
      status: 200,
      headers: { "Content-Type": "application/vnd.ipld.raw" },
    }),
  );
}

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

// ─── GET /v1/agents ─────────────────────────────────────────────────────────

describe("GET /v1/agents", () => {
  it("returns empty list when no agents registered", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents", {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as unknown[];
    expect(body).toEqual([]);
  });

  it("returns registered agents after POST once the 48 h cooldown has elapsed", async () => {
    stubFetch([{ id: "cap-search" }]);
    vi.useFakeTimers();
    const baseTime = Date.now();
    const { app, apiKey, env } = await makeApp();

    await postAgent(app, env, apiKey, { did: "did:aroha:test1", manifestCID: "Qm1", publicKeyB64: btoa("x".repeat(32)) });

    // New agents are hidden from discovery for 48 h — advance past the cooldown.
    vi.setSystemTime(baseTime + 49 * 60 * 60 * 1000);

    const res = await app.request("/v1/agents", {}, env);
    const body = await res.json() as { did: string }[];
    expect(body).toHaveLength(1);
    expect(body[0].did).toBe("did:aroha:test1");
  });

  it("hides newly registered agents from the list during the 48 h cooldown", async () => {
    stubFetch([{ id: "cap-search" }]);
    const { app, apiKey, env } = await makeApp();

    await postAgent(app, env, apiKey, { did: "did:aroha:test1", manifestCID: "Qm1", publicKeyB64: btoa("x".repeat(32)) });

    // List immediately after registration — agent should be in cooldown and invisible
    const res = await app.request("/v1/agents", {}, env);
    const body = await res.json() as { did: string }[];
    expect(body).toHaveLength(0);
  });
});

// ─── POST /v1/agents ────────────────────────────────────────────────────────

describe("POST /v1/agents", () => {
  it("201 with valid payload and API key", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const res = await postAgent(app, env, apiKey, { did: "did:aroha:agent1", manifestCID: "QmAbc", publicKeyB64: btoa("a".repeat(32)) });
    expect(res.status).toBe(201);
    const body = await res.json() as { didHash: string };
    expect(body.didHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("401 without Authorization header", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:aroha:x", manifestCID: "Qm1", publicKeyB64: btoa("a".repeat(32)) }),
    }, env);
    expect(res.status).toBe(401);
  });

  it("400 when required fields are missing", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await postAgent(app, env, apiKey, { did: "did:aroha:no-key" });
    expect(res.status).toBe(400);
  });

  it("409 on duplicate DID registration", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const payload = { did: "did:aroha:dup", manifestCID: "QmDup", publicKeyB64: btoa("d".repeat(32)) };
    expect((await postAgent(app, env, apiKey, payload)).status).toBe(201);
    const res2 = await postAgent(app, env, apiKey, payload);
    expect(res2.status).toBe(409);
  });

  it("400 when endpointUrl is not http(s)", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await postAgent(app, env, apiKey, { did: "did:aroha:bad-url", manifestCID: "Qm1", publicKeyB64: btoa("a".repeat(32)), endpointUrl: "ftp://bad" });
    expect(res.status).toBe(400);
  });
});

// ─── GET /v1/agents/:didHash ─────────────────────────────────────────────────

describe("GET /v1/agents/:did", () => {
  it("404 for unknown DID", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents/did:aroha:unknown", {}, env);
    expect(res.status).toBe(404);
  });

  it("returns agent record by DID string", async () => {
    stubManifestFetch();
    const cid = await manifestWith(["cap-translate"]);
    const { app, apiKey, env } = await makeApp();

    const registerRes = await postAgent(app, env, apiKey, { did: "did:aroha:lookup", manifestCID: cid, publicKeyB64: btoa("l".repeat(32)) });
    const { didHash } = await registerRes.json() as { didHash: string };

    const res = await app.request(`/v1/agents/did:aroha:lookup`, {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { didHash: string; capabilityIds: string[] };
    expect(body.didHash).toBe(didHash);
    expect(body.capabilityIds).toContain("cap-translate");
  });
});

// ─── DELETE /v1/agents/:didHash ───────────────────────────────────────────────

describe("DELETE /v1/agents/:didHash", () => {
  it("deactivates own agent", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();

    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:delete-me", manifestCID: "QmD", publicKeyB64: btoa("d".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const del = await app.request(`/v1/agents/${didHash}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${apiKey}` },
    }, env);
    expect(del.status).toBe(200);

    const get = await app.request(`/v1/agents/${didHash}`, {}, env);
    expect(get.status).toBe(404);
  });

  it("404 when deleting an agent owned by another key", async () => {
    stubFetch();
    const { app, apiKey: key1, env } = await makeApp("Org1");
    const { apiKey: key2 } = await (async () => {
      const { sha256hex } = await import("../auth.js");
      const k2 = "other-key-xyz";
      const h2 = await sha256hex(k2);
      await (env.DB as import("../test-utils/sqlite-d1.js").SqliteD1)
        .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, 'Org2', ?, 1)`)
        .bind(h2, Date.now())
        .run();
      return { apiKey: k2 };
    })();

    const reg = await postAgent(app, env, key1, { did: "did:aroha:owned-by-1", manifestCID: "QmO", publicKeyB64: btoa("o".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const del = await app.request(`/v1/agents/${didHash}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${key2}` },
    }, env);
    expect(del.status).toBe(404);
  });
});

// ─── PUT /v1/agents/:didHash/rotate-key ──────────────────────────────────────

async function registerWithKey(
  app: Awaited<ReturnType<typeof makeApp>>["app"],
  env: Awaited<ReturnType<typeof makeApp>>["env"],
  apiKey: string,
  privKey: Uint8Array,
  did: string,
) {
  stubFetch();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const reg = await postAgent(app, env, apiKey, { did, manifestCID: "QmTest", publicKeyB64: toB64(pubKey) }, privKey);
  const { didHash } = await reg.json() as { didHash: string };
  return { didHash, pubKey };
}

async function buildRotateRequest(
  privKey: Uint8Array,
  didHash: string,
  newPubKeyB64: string,
  nonce: string,
  issuedAt: string,
) {
  const message = JSON.stringify({ action: "rotate-key", didHash, issuedAt, newPublicKeyB64: newPubKeyB64, nonce });
  const msgBytes = new TextEncoder().encode(message);
  const sig = await ed.signAsync(msgBytes, privKey);
  return { signature: toB64(sig), nonce, issuedAt, newPublicKeyB64: newPubKeyB64 };
}

describe("PUT /v1/agents/:didHash/rotate-key", () => {
  it("rotates the key and returns keyVersion 2", async () => {
    const { app, apiKey, env } = await makeApp();
    const privKey = ed.utils.randomPrivateKey();
    const { didHash } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:rotate-ok");

    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const body = await buildRotateRequest(privKey, didHash, toB64(newPub), crypto.randomUUID(), new Date().toISOString());

    const res = await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }, env);
    expect(res.status).toBe(200);
    const result = await res.json() as { ok: boolean; keyVersion: number };
    expect(result.ok).toBe(true);
    expect(result.keyVersion).toBe(2);
  });

  it("refuses a valid current-key signature presented with someone else's API key (403)", async () => {
    // The stolen-device case: the thief holds the agent key, so the signature
    // is genuine. Any registered API key used to be enough to finish the
    // takeover; now only the owner's is.
    const { app, apiKey, env } = await makeApp("Owner");
    const { sha256hex } = await import("../auth.js");
    const otherKey = "thief-key-xyz";
    await (env.DB as import("../test-utils/sqlite-d1.js").SqliteD1)
      .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, 'Thief', ?, 1)`)
      .bind(await sha256hex(otherKey), Date.now())
      .run();

    const privKey = ed.utils.randomPrivateKey();
    const { didHash } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:rotate-stolen");
    const thiefPub = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
    const body = await buildRotateRequest(privKey, didHash, toB64(thiefPub), crypto.randomUUID(), new Date().toISOString());

    const res = await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${otherKey}` },
      body: JSON.stringify(body),
    }, env);
    expect(res.status).toBe(403);
  });

  it("rejects replay of the same nonce (409)", async () => {
    const { app, apiKey, env } = await makeApp();
    const privKey = ed.utils.randomPrivateKey();
    const { didHash } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:nonce-replay");

    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const nonce = crypto.randomUUID();
    const issuedAt = new Date().toISOString();
    const body = await buildRotateRequest(privKey, didHash, toB64(newPub), nonce, issuedAt);

    // First rotation succeeds; after this the current key is newPriv.
    await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }, env);

    // Second request: sign with the NEW current key but reuse the same nonce → 409.
    const newPriv2 = ed.utils.randomPrivateKey();
    const newPub2 = await ed.getPublicKeyAsync(newPriv2);
    const body2 = await buildRotateRequest(newPriv, didHash, toB64(newPub2), nonce, new Date().toISOString());
    const res = await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body2),
    }, env);
    expect(res.status).toBe(409);
  });

  it("rejects an invalid signature (403)", async () => {
    const { app, apiKey, env } = await makeApp();
    const privKey = ed.utils.randomPrivateKey();
    const { didHash } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:bad-sig");

    const wrongPriv = ed.utils.randomPrivateKey(); // different key — signature won't verify
    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const body = await buildRotateRequest(wrongPriv, didHash, toB64(newPub), crypto.randomUUID(), new Date().toISOString());

    const res = await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }, env);
    expect(res.status).toBe(403);
  });

  it("rejects issuedAt older than 5 minutes (400)", async () => {
    const { app, apiKey, env } = await makeApp();
    const privKey = ed.utils.randomPrivateKey();
    const { didHash } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:stale-iat");

    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const staleIssuedAt = new Date(Date.now() - 6 * 60 * 1000).toISOString();
    const body = await buildRotateRequest(privKey, didHash, toB64(newPub), crypto.randomUUID(), staleIssuedAt);

    const res = await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }, env);
    expect(res.status).toBe(400);
  });

  it("archives old key in revoked_keys after rotation", async () => {
    const { app, apiKey, env } = await makeApp();
    const privKey = ed.utils.randomPrivateKey();
    const { didHash, pubKey } = await registerWithKey(app, env, apiKey, privKey, "did:aroha:audit-trail");

    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const body = await buildRotateRequest(privKey, didHash, toB64(newPub), crypto.randomUUID(), new Date().toISOString());

    await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }, env);

    const res = await app.request(`/v1/agents/${didHash}/revoked-keys`, {}, env);
    expect(res.status).toBe(200);
    const keys = await res.json() as { publicKeyB64: string }[];
    expect(keys).toHaveLength(1);
    expect(keys[0].publicKeyB64).toBe(toB64(pubKey));
  });
});

// ─── PUT /v1/agents/:didHash/manifest ────────────────────────────────────────

describe("PUT /v1/agents/:didHash/manifest", () => {
  it("updates manifest CID and capability index", async () => {
    stubManifestFetch();
    const v1 = await manifestWith(["cap-v1"]);
    const v2 = await manifestWith(["cap-v2"]);
    const { app, apiKey, env } = await makeApp();
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:manifest-update", manifestCID: v1, publicKeyB64: btoa("m".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/manifest`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ manifestCID: v2 }),
    }, env);
    expect(res.status).toBe(200);
    expect((await res.json() as { ok: boolean }).ok).toBe(true);

    const agent = await app.request(`/v1/agents/${didHash}`, {}, env);
    const record = await agent.json() as { capabilityIds: string[] };
    expect(record.capabilityIds).toContain("cap-v2");
    expect(record.capabilityIds).not.toContain("cap-v1");
  });

  it("404 when trying to update manifest owned by another key", async () => {
    stubFetch();
    const { app, apiKey: key1, env } = await makeApp();
    const { sha256hex } = await import("../auth.js");
    const key2 = "manifest-intruder";
    await (env.DB as import("../test-utils/sqlite-d1.js").SqliteD1)
      .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, 'Org2', ?, 1)`)
      .bind(await sha256hex(key2), Date.now())
      .run();

    const reg = await postAgent(app, env, key1, { did: "did:aroha:manifest-owned", manifestCID: "QmO", publicKeyB64: btoa("o".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/manifest`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${key2}` },
      body: JSON.stringify({ manifestCID: "QmHijacked" }),
    }, env);
    expect(res.status).toBe(404);
  });
});

// ─── PUT /v1/agents/:didHash/manifest/admin ──────────────────────────────────

describe("PUT /v1/agents/:didHash/manifest/admin", () => {
  it("admin updates manifest CID and rebuilds capability index by orgName", async () => {
    stubManifestFetch();
    const initial = await manifestWith(["initial-cap"]);
    const updated = await manifestWith(["admin-cap-v2"]);
    const { app, apiKey, env } = await makeApp("ManifestAdminOrg");
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:manifest-admin-test", manifestCID: initial, publicKeyB64: btoa("x".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/manifest/admin`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ manifestCID: updated, orgName: "ManifestAdminOrg" }),
    }, env);
    expect(res.status).toBe(200);
    expect((await res.json() as { ok: boolean }).ok).toBe(true);

    const agentRes = await app.request(`/v1/agents/${didHash}`, {}, env);
    const record = await agentRes.json() as { capabilityIds: string[]; manifestCID: string };
    expect(record.manifestCID).toBe(updated);
    expect(record.capabilityIds).toContain("admin-cap-v2");
    expect(record.capabilityIds).not.toContain("initial-cap");
  });

  it("403 with wrong admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents/0x1234/manifest/admin", {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-secret" },
      body: JSON.stringify({ manifestCID: "QmX", orgName: "X" }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("404 when orgName does not match the agent owner", async () => {
    stubFetch([{ id: "cap" }]);
    const { app, apiKey, env } = await makeApp("OwnerOrg");
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:manifest-admin-wrong-org", manifestCID: "QmO", publicKeyB64: btoa("y".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/manifest/admin`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ manifestCID: "QmNew", orgName: "ImpostorOrg" }),
    }, env);
    expect(res.status).toBe(404);
  });

  it("400 when manifestCID is missing from body", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents/0x1234/manifest/admin", {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "SomeOrg" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("400 when orgName is missing from body", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents/0x1234/manifest/admin", {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ manifestCID: "QmZ" }),
    }, env);
    expect(res.status).toBe(400);
  });
});

// ─── DELETE /v1/agents/:didHash/admin ────────────────────────────────────────

describe("DELETE /v1/agents/:didHash/admin", () => {
  it("deactivates agent by orgName with admin secret", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("TestOrg");
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:admin-delete", manifestCID: "QmA", publicKeyB64: btoa("a".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "TestOrg" }),
    }, env);
    expect(res.status).toBe(200);

    const get = await app.request(`/v1/agents/${didHash}`, {}, env);
    expect(get.status).toBe(404);
  });

  it("403 with wrong admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents/0x1234/admin", {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-secret" },
      body: JSON.stringify({ orgName: "TestOrg" }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("404 when orgName does not match the agent owner", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("RealOrg");
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:wrong-org", manifestCID: "QmW", publicKeyB64: btoa("w".repeat(32)) });
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/agents/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "ImpostorOrg" }),
    }, env);
    expect(res.status).toBe(404);
  });
});

// ─── GET /v1/agents?capabilities=... ─────────────────────────────────────────

describe("GET /v1/agents?capabilities=...", () => {
  it("returns only agents matching the requested capability", async () => {
    const { app, apiKey, env } = await makeApp();

    stubManifestFetch();
    await postAgent(app, env, apiKey, { did: "did:aroha:searcher", manifestCID: await manifestWith(["cap-search"]), publicKeyB64: btoa("s".repeat(32)) });
    await postAgent(app, env, apiKey, { did: "did:aroha:translator", manifestCID: await manifestWith(["cap-translate"]), publicKeyB64: btoa("t".repeat(32)) });

    const res = await app.request("/v1/agents?capabilities=cap-search", {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { did: string }[];
    expect(body).toHaveLength(1);
    expect(body[0].did).toBe("did:aroha:searcher");
  });

  it("returns [] when no agent has the requested capability", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/agents?capabilities=cap-nonexistent", {}, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);
  });
});

// ─── End-to-end: key rotation invalidates pre-rotation mandates ───────────────

describe("E2E: key rotation + mandate rejection", () => {
  it("mandate issued before rotation is rejected when keyRotatedAt is enforced", async () => {
    const { app, apiKey, env } = await makeApp();

    // Register agent with a known Ed25519 key
    const agentPriv = ed.utils.randomPrivateKey();
    const agentPub = await ed.getPublicKeyAsync(agentPriv);
    stubFetch();
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:e2e-rotate", manifestCID: "QmE", publicKeyB64: toB64(agentPub) }, agentPriv);
    const { didHash } = await reg.json() as { didHash: string };

    // Issue a mandate signed by the agent's CURRENT (pre-rotation) key
    const mandate = await issueIntentMandate(
      "did:aroha:user", "did:aroha:e2e-rotate",
      { spendLimitUsd: 100 }, agentPriv,
    );

    // Verify the mandate is valid before rotation
    const beforeRotation = await verifyMandate(mandate.token, agentPub);
    expect(beforeRotation.valid).toBe(true);

    // Rotate the agent's key
    const newPriv = ed.utils.randomPrivateKey();
    const newPub = await ed.getPublicKeyAsync(newPriv);
    const rotateBody = await buildRotateRequest(agentPriv, didHash, toB64(newPub), crypto.randomUUID(), new Date().toISOString());
    await app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(rotateBody),
    }, env);

    // Read the agent record — keyRotatedAt is now populated
    const agentRes = await app.request(`/v1/agents/${didHash}`, {}, env);
    const agentRecord = await agentRes.json() as { keyRotatedAt: number };
    expect(agentRecord.keyRotatedAt).toBeGreaterThan(0);

    // The verifier reads keyRotatedAt from the registry response and enforces it.
    // The mandate was signed with the old key BEFORE the rotation → rejected.
    const afterRotation = await verifyMandate(
      mandate.token, agentPub, undefined,
      { keyRotatedAt: agentRecord.keyRotatedAt },
    );
    expect(afterRotation.valid).toBe(false);
    expect(afterRotation.reason).toMatch(/rotated/i);
  });
});

// ─── fetchCapabilityIds — CID-verification (raw block path) ──────────────────
//
// The default `stubFetch` helper returns JSON without a Content-Type header,
// so existing tests always exercise the unverified fallback path. These tests
// use `stubFetchRaw` to simulate a gateway that honours Accept: application/vnd.ipld.raw,
// exercising the SHA-256 verification branch in fetchCapabilityIds.

describe("fetchCapabilityIds — CID verification via raw IPLD block", () => {
  it("populates capabilities from a verified CIDv0 raw block", async () => {
    const manifest = { capabilities: [{ id: "verified-cap" }] };
    const { cid, block } = await buildCIDv0(manifest);

    stubFetchRaw(block);
    const { app, apiKey, env } = await makeApp();
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:verified-cid", manifestCID: cid, publicKeyB64: btoa("v".repeat(32)) });
    expect(reg.status).toBe(201);
    const { didHash } = await reg.json() as { didHash: string };

    const agentRes = await app.request(`/v1/agents/${didHash}`, {}, env);
    const record = await agentRes.json() as { capabilityIds: string[] };
    expect(record.capabilityIds).toContain("verified-cap");
  });

  // A gateway that ignores Accept: application/vnd.ipld.raw and serves the
  // manifest as JSON gives nothing to check against the CID — so nothing is
  // indexed from it, however plausible its contents look.
  it("indexes no capabilities from a manifest served as plain JSON (unverifiable)", async () => {
    stubFetch([{ id: "unverified-cap" }]);
    const { app, apiKey, env } = await makeApp();
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:unverified-json", manifestCID: "QmJson", publicKeyB64: btoa("j".repeat(32)) });
    expect(reg.status).toBe(201);
    const { didHash } = await reg.json() as { didHash: string };
    const record = await (await app.request(`/v1/agents/${didHash}`, {}, env)).json() as { capabilityIds: string[] };
    expect(record.capabilityIds).toEqual([]);
  });

  it("registers with empty capabilities when the block is tampered (fail-closed)", async () => {
    const manifest = { capabilities: [{ id: "legit-cap" }] };
    const { cid } = await buildCIDv0(manifest);

    // Gateway returns correct Content-Type but wrong bytes — SHA-256 will mismatch.
    // fetchCapabilityIds must reject the block and return [] rather than trust it.
    const tamperedBlock = new Uint8Array(64).fill(0xde);
    stubFetchRaw(tamperedBlock);

    const { app, apiKey, env } = await makeApp();
    const reg = await postAgent(app, env, apiKey, { did: "did:aroha:tampered-cid", manifestCID: cid, publicKeyB64: btoa("t".repeat(32)) });
    // Registration still succeeds — IPFS capabilities are best-effort.
    expect(reg.status).toBe(201);
    const { didHash } = await reg.json() as { didHash: string };

    const agentRes = await app.request(`/v1/agents/${didHash}`, {}, env);
    const record = await agentRes.json() as { capabilityIds: string[] };
    expect(record.capabilityIds).toHaveLength(0);
  });
});
