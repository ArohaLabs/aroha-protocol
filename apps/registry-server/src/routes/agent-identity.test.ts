// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-02),
// the agent JWKS behind them, the certification tier and the signed
// monitoring summary.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { incept, rotateKel, revokeKelSelf, canonicalizeJcs } from "@aroha-sdk/core";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { registerAgent } from "../test-utils/register.js";
import { hashDID } from "./agents.js";
import { AGENT_MONITORING_PURPOSE } from "./agent-identity.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let t: TestApp;
let ip = 0;
beforeEach(async () => {
  t = await makeApp();
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
});
afterEach(() => vi.unstubAllGlobals());

const req = (path: string, init: RequestInit = {}, auth: string | null = null) => {
  const headers = new Headers(init.headers);
  headers.set("x-forwarded-for", `10.88.${(ip >> 8) & 255}.${ip++ & 255}`);
  if (auth) headers.set("authorization", `Bearer ${auth}`);
  if (init.body) headers.set("content-type", "application/json");
  return t.app.request(path, { ...init, headers }, t.env as never);
};
const post = (path: string, body: unknown, auth: string | null = null) => req(path, { method: "POST", body: JSON.stringify(body) }, auth);
const getJson = async (path: string, auth: string | null = null) => {
  const res = await req(path, {}, auth);
  return { status: res.status, headers: res.headers, json: (await res.json()) as Record<string, any> };
};

/** Draft -02 §3/§4 requirements a client metadata document must satisfy. */
function assertValidCimd(doc: Record<string, any>, fetchedFrom: string) {
  expect(doc.client_id).toBe(fetchedFrom);
  const u = new URL(doc.client_id);
  expect(u.pathname.length).toBeGreaterThan(1);
  expect(u.hash).toBe("");
  expect(u.username).toBe("");
  expect(u.pathname.split("/")).not.toContain("..");
  expect(["client_secret_post", "client_secret_basic", "client_secret_jwt"]).not.toContain(doc.token_endpoint_auth_method);
  expect(doc.token_endpoint_auth_method).toBe("private_key_jwt");
  expect(doc).not.toHaveProperty("client_secret");
  expect(doc).not.toHaveProperty("client_secret_expires_at");
  expect(typeof doc.jwks_uri).toBe("string");
  expect(JSON.stringify(doc)).not.toMatch(/"d"\s*:/); // no private key material
}

async function registerEAgent(extra: Record<string, unknown> = {}, controlled = true) {
  const person = await incept({ kind: "person" });
  const agent = await incept({ kind: "agent", ...(controlled ? { controller: person.did } : {}) });
  if (controlled) expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: person.kel })).status).toBe(200);
  expect((await post("/v1/agents", { did: agent.did, manifestCID: "QmAbc", kel: agent.kel, ...extra }, t.apiKey)).status).toBe(201);
  return { person, agent, didHash: hashDID(agent.did) };
}

describe("GET /v1/agents/:didHash/client-metadata.json", () => {
  it("serves a document meeting the draft's requirements, with redirect_uris from an https endpoint", async () => {
    const { didHash, agent } = await registerEAgent({ endpointUrl: "https://agent.example.com/base/" });
    const path = `/v1/agents/${didHash}/client-metadata.json`;
    const { status, headers, json } = await getJson(path);
    expect(status).toBe(200);
    assertValidCimd(json, `http://localhost${path}`);
    expect(json).toMatchObject({
      jwks_uri: `http://localhost/v1/agents/${didHash}/jwks.json`,
      token_endpoint_auth_signing_alg: "EdDSA",
      redirect_uris: ["https://agent.example.com/base/oauth/callback"],
      grant_types: ["authorization_code", "client_credentials"],
      aroha_did: agent.did,
      aroha_certification_tier: "kel_person_rooted",
    });
    expect(headers.get("cache-control")).toBe("public, max-age=300");
  });

  it("offers only client_credentials when no https endpoint is declared", async () => {
    const r = await registerAgent(t.app, t.env, t.apiKey, { did: `did:aroha:named-${Math.random().toString(36).slice(2)}` });
    const { json } = await getJson(`/v1/agents/${r.didHash}/client-metadata.json`);
    expect(json.grant_types).toEqual(["client_credentials"]);
    expect(json).not.toHaveProperty("redirect_uris");
  });

  it("404s (uncached) for unknown, private and revoked agents", async () => {
    const unknown = await req(`/v1/agents/0xdead/client-metadata.json`);
    expect(unknown.status).toBe(404);
    expect(unknown.headers.get("cache-control")).toBe("no-store");

    const { didHash } = await registerEAgent();
    await req(`/v1/agents/${didHash}/visibility`, { method: "PATCH", body: JSON.stringify({ visibility: "private" }) }, t.apiKey);
    expect((await req(`/v1/agents/${didHash}/client-metadata.json`)).status).toBe(404);

    const { agent, didHash: h2 } = await registerEAgent({}, false);
    expect((await post(`/v1/kel/${encodeURIComponent(agent.did)}`, { events: await revokeKelSelf(agent) })).status).toBe(200);
    expect((await req(`/v1/agents/${h2}/client-metadata.json`)).status).toBe(404);
    expect((await req(`/v1/agents/${h2}/jwks.json`)).status).toBe(404);
  });
});

describe("GET /v1/agents/:didHash/jwks.json", () => {
  it("follows a KEL rotation: the key and its kid change", async () => {
    const { agent, didHash } = await registerEAgent({}, false);
    const before = (await getJson(`/v1/agents/${didHash}/jwks.json`)).json.keys[0];
    expect(before).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA" });
    expect(Buffer.from(before.x, "base64url")).toHaveLength(32);

    const rotated = await rotateKel(agent);
    expect((await post(`/v1/kel/${encodeURIComponent(agent.did)}`, { events: rotated.kel })).status).toBe(200);
    const after = (await getJson(`/v1/agents/${didHash}/jwks.json`)).json.keys[0];
    expect(after.x).not.toBe(before.x);
    expect(after.kid).not.toBe(before.kid);
  });
});

describe("GET /v1/agents/:didHash/monitoring", () => {
  async function verifySummary(body: Record<string, any>) {
    const keys = (await getJson("/.well-known/aroha-registry-keys.json")).json.keys as Array<{ keyId: string; publicKeyB64: string }>;
    const key = keys.find((k) => k.keyId === body.keyId)!;
    const signed = { purpose: AGENT_MONITORING_PURPOSE, ...body.summary };
    return ed.verify(
      Buffer.from(body.signature, "base64url"),
      new TextEncoder().encode(canonicalizeJcs(signed)),
      Buffer.from(key.publicKeyB64, "base64url"),
    );
  }

  it("signs counts and the tier; a tampered summary does not verify; the notice disclaims reputation", async () => {
    const { agent, didHash } = await registerEAgent();
    const { status, json } = await getJson(`/v1/agents/${didHash}/monitoring`);
    expect(status).toBe(200);
    expect(json.summary).toMatchObject({
      did: agent.did,
      certificationTier: "kel_person_rooted",
      counts: { kelEvents: 1, kelRevoked: false, duplicityAlarms: 0, attestations: 0, rotatedKeys: 0 },
    });
    expect(json.summary.notice).toMatch(/Not a reputation score/);
    expect(json.summary.lastSeenAt).toEqual(expect.any(String));
    expect(await verifySummary(json)).toBe(true);
    json.summary.counts.duplicityAlarms = 0;
    json.summary.certificationTier = "audited";
    expect(await verifySummary(json)).toBe(false);
  });

  it("derives unverified → audited from facts, and an operator can set and clear audited", async () => {
    const r = await registerAgent(t.app, t.env, t.apiKey, { did: `did:aroha:named-${Math.random().toString(36).slice(2)}` });
    const tier = async () => (await getJson(`/v1/agents/${r.didHash}/monitoring`)).json.summary.certificationTier;
    expect(await tier()).toBe("unverified");

    await (t.env.DB as D1Database).prepare(`UPDATE agent_records SET domain_verified = 1, domain = 'acme.example' WHERE did_hash = ?`).bind(r.didHash).run();
    expect(await tier()).toBe("domain_verified");

    expect((await post(`/v1/agents/${r.didHash}/audited`, { audited: true })).status).toBe(403);
    expect((await post(`/v1/agents/${r.didHash}/audited`, { audited: true }, t.env.ADMIN_SECRET)).status).toBe(400);
    const set = await post(`/v1/agents/${r.didHash}/audited`, { audited: true, reference: "https://auditor.example/r/1" }, t.env.ADMIN_SECRET);
    expect(set.status).toBe(200);
    const m = (await getJson(`/v1/agents/${r.didHash}/monitoring`)).json.summary;
    expect(m).toMatchObject({ certificationTier: "audited", facts: { audited: true, auditReference: "https://auditor.example/r/1" } });
    expect((await post(`/v1/agents/${r.didHash}/audited`, { audited: false }, t.env.ADMIN_SECRET)).status).toBe(200);
    expect(await tier()).toBe("domain_verified");
  });

  it("drops kel_person_rooted once the controller revokes, and still reports the revoked agent", async () => {
    const { person, didHash } = await registerEAgent();
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: await revokeKelSelf(person) })).status).toBe(200);
    const { status, json } = await getJson(`/v1/agents/${didHash}/monitoring`);
    expect(status).toBe(200);
    expect(json.summary.facts).toMatchObject({ active: false, kelPersonRooted: false });
    expect(json.summary.certificationTier).toBe("unverified");
  });

  it("answers 503 without a signing key and 404 for a private agent to strangers", async () => {
    const { didHash } = await registerEAgent();
    await req(`/v1/agents/${didHash}/visibility`, { method: "PATCH", body: JSON.stringify({ visibility: "private" }) }, t.apiKey);
    expect((await req(`/v1/agents/${didHash}/monitoring`)).status).toBe(404);
    expect((await req(`/v1/agents/${didHash}/monitoring`, {}, t.apiKey)).status).toBe(200);
    delete t.env.REGISTRY_SIGNING_KEY;
    expect((await req(`/v1/agents/${didHash}/monitoring`, {}, t.apiKey)).status).toBe(503);
  });
});
