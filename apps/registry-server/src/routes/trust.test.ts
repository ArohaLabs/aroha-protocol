// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end route tests for the caller-uniqueness layer: real Ed25519
// keypairs, real Chaum-Pedersen proofs from @aroha-sdk/trust, POSTed through
// the actual Hono app — not mocked at the crypto boundary, since that's
// exactly where the wire-format bug (Uint8Array through JSON.stringify) was
// caught during implementation. A route-level test with a fake proof
// wouldn't have caught it; only a real proof serialized the way a real
// client would serialize it does.

import { describe, it, expect, vi, afterEach } from "vitest";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent } from "../test-utils/register.js";
import { generateCredentialSecret, proveUniqueness, issueCertificate } from "@aroha-sdk/trust";

afterEach(() => { vi.unstubAllGlobals(); });

type App = Awaited<ReturnType<typeof makeApp>>["app"];
type Env = Awaited<ReturnType<typeof makeApp>>["env"];

function authHeaders(apiKey: string) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` };
}

async function generateEd25519() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const pubRaw = new Uint8Array(await (crypto.subtle.exportKey("raw", kp.publicKey) as Promise<ArrayBuffer>));
  return { privateKey: kp.privateKey, publicKeyB64: Buffer.from(pubRaw).toString("base64") };
}

/** Registers an agent DID with a REAL Ed25519 key — the requests below sign with the matching private key. */
async function registerCallerAgent(app: App, env: Env, apiKey: string, did: string) {
  const { privateKey, publicKeyB64 } = await generateEd25519();
  const res = await postAgent(app, env, apiKey, { did, manifestCID: "QmC", publicKeyB64 }, privateKey);
  expect(res.status).toBe(201);
  return { privateKey };
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

async function signPayload(privateKey: CryptoKey, payload: Record<string, unknown>): Promise<string> {
  const message = new TextEncoder().encode(JSON.stringify(sortKeysDeep(payload)));
  const sig = await crypto.subtle.sign("Ed25519", privateKey, message);
  return Buffer.from(sig).toString("base64");
}

function nullifierProofWire(secret: Uint8Array, scope: string) {
  const p = proveUniqueness(secret, scope);
  return {
    commitment: Buffer.from(p.commitment).toString("base64url"),
    scope: p.scope,
    nullifier: Buffer.from(p.nullifier).toString("base64url"),
    r1: Buffer.from(p.r1).toString("base64url"),
    r2: Buffer.from(p.r2).toString("base64url"),
    z: Buffer.from(p.z).toString("base64url"),
  };
}

function stubWellKnown(issuerPublicKeyB64: string) {
  vi.stubGlobal("fetch", async () =>
    new Response(JSON.stringify({ issuerPublicKeyB64 }), { status: 200 }));
}

// ─── POST /v1/kyc-issuers ───────────────────────────────────────────────────

describe("POST /v1/kyc-issuers", () => {
  it("registers an issuer when the well-known file matches the submitted key", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await generateEd25519();
    stubWellKnown(issuer.publicKeyB64);

    const res = await app.request("/v1/kyc-issuers", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ issuerDid: "did:aroha:kyc:test-co", publicKeyB64: issuer.publicKeyB64, domain: "kyc-test.example.com" }),
    }, env);

    expect(res.status).toBe(201);
  });

  it("rejects when the well-known key does not match the submitted key", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await generateEd25519();
    const impostorKey = (await generateEd25519()).publicKeyB64;
    stubWellKnown(impostorKey); // well-known hosts a DIFFERENT key than what's submitted

    const res = await app.request("/v1/kyc-issuers", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ issuerDid: "did:aroha:kyc:test-co", publicKeyB64: issuer.publicKeyB64, domain: "kyc-test.example.com" }),
    }, env);

    expect(res.status).toBe(422);
  });

  it("rejects an unreachable domain", async () => {
    const { app, apiKey, env } = await makeApp();
    vi.stubGlobal("fetch", async () => { throw new Error("network error"); });
    const issuer = await generateEd25519();

    const res = await app.request("/v1/kyc-issuers", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ issuerDid: "did:aroha:kyc:test-co", publicKeyB64: issuer.publicKeyB64, domain: "unreachable.example.com" }),
    }, env);

    expect(res.status).toBe(422);
  });
});

// ─── POST /v1/verify-caller ─────────────────────────────────────────────────

describe("POST /v1/verify-caller", () => {
  async function setupIssuer(app: App, env: Env, apiKey: string, issuerDid = "did:aroha:kyc:test-co") {
    const issuer = await generateEd25519();
    stubWellKnown(issuer.publicKeyB64);
    await app.request("/v1/kyc-issuers", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ issuerDid, publicKeyB64: issuer.publicKeyB64, domain: "kyc-test.example.com" }),
    }, env);
    return issuer;
  }

  it("verifies a caller end to end with a real proof and real signatures", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await setupIssuer(app, env, apiKey);
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:alice");

    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:test-co", await exportRawPriv(issuer));
    const nullifierProof = nullifierProofWire(cred.secret, "verified-caller");

    const callerDid = "did:aroha:alice";
    const payload = { callerDid, kycCertificate, nullifierProof };
    const callerSignature = await signPayload(callerKey, payload);

    const res = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid, callerSignature, kycCertificate, nullifierProof }),
    }, env);

    const body = await res.json();
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body).toMatchObject({ callerDid, tier: "kyc-verified" });
  });

  it("rejects the same certified secret used twice — the actual Sybil-resistance check", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await setupIssuer(app, env, apiKey);
    const issuerPriv = await exportRawPriv(issuer);

    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:test-co", issuerPriv);
    const nullifierProof = nullifierProofWire(cred.secret, "verified-caller");

    const { privateKey: aliceKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:alice2");
    const { privateKey: bobKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:bob2");

    const payloadA = { callerDid: "did:aroha:alice2", kycCertificate, nullifierProof };
    const sigA = await signPayload(aliceKey, payloadA);
    const first = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:alice2", callerSignature: sigA, kycCertificate, nullifierProof }),
    }, env);
    expect(first.status).toBe(201);

    // Bob tries to reuse the SAME certified secret (same nullifier) to become verified too.
    const payloadB = { callerDid: "did:aroha:bob2", kycCertificate, nullifierProof };
    const sigB = await signPayload(bobKey, payloadB);
    const second = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:bob2", callerSignature: sigB, kycCertificate, nullifierProof }),
    }, env);
    expect(second.status).toBe(409);
  });

  it("rejects a certificate from an issuer that never proved domain ownership", async () => {
    const { app, apiKey, env } = await makeApp();
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:carol");

    const fakeIssuer = await generateEd25519(); // never registered via /v1/kyc-issuers
    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:untrusted", await exportRawPriv(fakeIssuer));
    const nullifierProof = nullifierProofWire(cred.secret, "verified-caller");

    const payload = { callerDid: "did:aroha:carol", kycCertificate, nullifierProof };
    const callerSignature = await signPayload(callerKey, payload);

    const res = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:carol", callerSignature, kycCertificate, nullifierProof }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("rejects a proof forged for a scope other than verified-caller", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await setupIssuer(app, env, apiKey);
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:dave");

    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:test-co", await exportRawPriv(issuer));
    const nullifierProof = nullifierProofWire(cred.secret, "some-other-scope"); // wrong scope

    const payload = { callerDid: "did:aroha:dave", kycCertificate, nullifierProof };
    const callerSignature = await signPayload(callerKey, payload);

    const res = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:dave", callerSignature, kycCertificate, nullifierProof }),
    }, env);
    expect(res.status).toBe(422);
  });

  it("rejects impersonation — signing with a key that doesn't belong to callerDid", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await setupIssuer(app, env, apiKey);
    await registerCallerAgent(app, env, apiKey, "did:aroha:eve");
    const { privateKey: malloryKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:mallory");

    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:test-co", await exportRawPriv(issuer));
    const nullifierProof = nullifierProofWire(cred.secret, "verified-caller");

    // Mallory signs but claims to be Eve.
    const payload = { callerDid: "did:aroha:eve", kycCertificate, nullifierProof };
    const forgedSignature = await signPayload(malloryKey, payload);

    const res = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:eve", callerSignature: forgedSignature, kycCertificate, nullifierProof }),
    }, env);
    expect(res.status).toBe(401);
  });
});

// ─── POST /v1/signals/attest ────────────────────────────────────────────────

describe("POST /v1/signals/attest", () => {
  it("records an attestation from an unverified caller at reduced weight", async () => {
    const { app, apiKey, env } = await makeApp();
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:frank");
    const agentRes = await postAgent(app, env, apiKey, { did: "did:aroha:target-agent", manifestCID: "QmC", publicKeyB64: btoa("t".repeat(32)) });
    expect(agentRes.status).toBe(201);

    const payload = { callerDid: "did:aroha:frank", sagaId: "saga-1", agentDid: "did:aroha:target-agent", success: true, domain: "general" };
    const callerSignature = await signPayload(callerKey, payload);

    const res = await app.request("/v1/signals/attest", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, callerSignature }),
    }, env);

    const body = await res.json();
    expect(res.status, JSON.stringify(body)).toBe(201);
    expect(body).toMatchObject({ callerTier: "unverified", callerWeight: 0.05 });
  });

  it("records an attestation from a verified caller at full weight", async () => {
    const { app, apiKey, env } = await makeApp();
    const issuer = await generateEd25519();
    stubWellKnown(issuer.publicKeyB64);
    await app.request("/v1/kyc-issuers", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ issuerDid: "did:aroha:kyc:test-co", publicKeyB64: issuer.publicKeyB64, domain: "kyc-test.example.com" }),
    }, env);

    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:grace");
    await postAgent(app, env, apiKey, { did: "did:aroha:target-agent-2", manifestCID: "QmC", publicKeyB64: btoa("t".repeat(32)) });

    const cred = generateCredentialSecret();
    const kycCertificate = await issueCertificate(cred.commitment, "did:aroha:kyc:test-co", await exportRawPriv(issuer));
    const nullifierProof = nullifierProofWire(cred.secret, "verified-caller");
    const vcPayload = { callerDid: "did:aroha:grace", kycCertificate, nullifierProof };
    const vcSig = await signPayload(callerKey, vcPayload);
    const verifyRes = await app.request("/v1/verify-caller", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callerDid: "did:aroha:grace", callerSignature: vcSig, kycCertificate, nullifierProof }),
    }, env);
    expect(verifyRes.status).toBe(201);

    const payload = { callerDid: "did:aroha:grace", sagaId: "saga-2", agentDid: "did:aroha:target-agent-2", success: true, domain: "general" };
    const callerSignature = await signPayload(callerKey, payload);
    const res = await app.request("/v1/signals/attest", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, callerSignature }),
    }, env);

    const body = await res.json();
    expect(body).toMatchObject({ callerTier: "kyc-verified", callerWeight: 1.0 });
  });

  it("rejects a duplicate attestation for the same (sagaId, callerDid)", async () => {
    const { app, apiKey, env } = await makeApp();
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:henry");
    await postAgent(app, env, apiKey, { did: "did:aroha:target-agent-3", manifestCID: "QmC", publicKeyB64: btoa("t".repeat(32)) });

    const payload = { callerDid: "did:aroha:henry", sagaId: "saga-3", agentDid: "did:aroha:target-agent-3", success: true, domain: "general" };
    const callerSignature = await signPayload(callerKey, payload);
    const body = JSON.stringify({ ...payload, callerSignature });

    const first = await app.request("/v1/signals/attest", { method: "POST", headers: { "Content-Type": "application/json" }, body }, env);
    expect(first.status).toBe(201);

    const second = await app.request("/v1/signals/attest", { method: "POST", headers: { "Content-Type": "application/json" }, body }, env);
    expect(second.status).toBe(409);
  });

  it("rejects an attestation for an unregistered agent", async () => {
    const { app, apiKey, env } = await makeApp();
    const { privateKey: callerKey } = await registerCallerAgent(app, env, apiKey, "did:aroha:ivy");

    const payload = { callerDid: "did:aroha:ivy", sagaId: "saga-4", agentDid: "did:aroha:nonexistent", success: true, domain: "general" };
    const callerSignature = await signPayload(callerKey, payload);

    const res = await app.request("/v1/signals/attest", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, callerSignature }),
    }, env);
    expect(res.status).toBe(404);
  });
});

/** generateEd25519() only exports the public key; re-derive raw private key bytes for @aroha-sdk/trust's Ed25519 (pkcs8-free) API. */
async function exportRawPriv(kp: { privateKey: CryptoKey }): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(await (crypto.subtle.exportKey("pkcs8", kp.privateKey) as Promise<ArrayBuffer>));
  // PKCS8 Ed25519 wraps the 32-byte raw seed in a fixed 16-byte ASN.1 prefix.
  return pkcs8.slice(pkcs8.length - 32);
}
