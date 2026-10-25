// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Request-hygiene and authorization regressions from the registry review:
// pagination clamps, malformed JSON, one-time invite redemption, caller
// signatures from taken-down agents, private-agent visibility on sibling
// routes, and rotate-key freshness.

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { registerAgent, toB64 } from "../test-utils/register.js";
import { sha256hex } from "../auth.js";
import { D1Repository } from "../d1-repository.js";
import { verifyCallerSignature, callerCanonicalString } from "../caller-signature.js";
import { clampPagination } from "../pagination.js";

afterEach(() => { vi.unstubAllGlobals(); });

function stubFetch() {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
}

async function addKey(t: TestApp, raw: string, orgName: string) {
  await (t.env.DB as D1Database)
    .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
    .bind(await sha256hex(raw), orgName, Date.now())
    .run();
  return raw;
}

const auth = (k: string) => ({ Authorization: `Bearer ${k}`, "Content-Type": "application/json" });

describe("pagination clamps (M4)", () => {
  it("clamps limit to [1,100], offset to >= 0, and ignores non-numbers", () => {
    expect(clampPagination("-1", "0")).toEqual({ limit: 1, offset: 0 });
    expect(clampPagination("NaN", "NaN")).toEqual({ limit: 50, offset: 0 });
    expect(clampPagination("abc", "-5")).toEqual({ limit: 50, offset: 0 });
    expect(clampPagination("100000", "3")).toEqual({ limit: 100, offset: 3 });
    expect(clampPagination(undefined, undefined)).toEqual({ limit: 50, offset: 0 });
    expect(clampPagination("Infinity", "Infinity")).toEqual({ limit: 50, offset: 0 });
  });

  it.each(["/v1/agents", "/v1/mcps", "/v1/skills", "/v1/sar"])("%s answers 200 to ?limit=-1 and ?limit=NaN", async (path) => {
    const t = await makeApp();
    for (const q of ["limit=-1&offset=-1", "limit=NaN&offset=NaN"]) {
      const res = await t.app.request(`${path}?${q}`, {}, t.env);
      expect(res.status).toBe(200);
    }
  });
});

describe("malformed JSON is a 400, not a 500 (L3)", () => {
  it.each(["/v1/agents", "/v1/mcps", "/v1/skills"])("POST %s", async (path) => {
    const t = await makeApp();
    const res = await t.app.request(path, { method: "POST", headers: auth(t.apiKey), body: "{not json" }, t.env);
    expect(res.status).toBe(400);
  });

  it("PUT /v1/agents/:didHash/manifest and POST /v1/auth/keys", async () => {
    const t = await makeApp();
    const a = await t.app.request("/v1/agents/0x01/manifest", { method: "PUT", headers: auth(t.apiKey), body: "{" }, t.env);
    expect(a.status).toBe(400);
    const b = await t.app.request("/v1/auth/keys", { method: "POST", headers: auth(t.env.ADMIN_SECRET), body: "{" }, t.env);
    expect(b.status).toBe(400);
  });
});

describe("space invites are one-time under concurrency (M5)", () => {
  it("admits exactly one of two concurrent redeemers", async () => {
    const t = await makeApp("Owner");
    const k1 = await addKey(t, "redeemer-one", "Firm One");
    const k2 = await addKey(t, "redeemer-two", "Firm Two");
    const space = await (await t.app.request("/v1/spaces", {
      method: "POST", headers: auth(t.apiKey), body: JSON.stringify({ name: "Deal room" }),
    }, t.env)).json() as { space: { id: string } };
    const invite = await (await t.app.request(`/v1/spaces/${space.space.id}/invites`, {
      method: "POST", headers: auth(t.apiKey), body: "{}",
    }, t.env)).json() as { invite: { code: string } };

    const join = (k: string) => t.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(k), body: JSON.stringify({ code: invite.invite.code }),
    }, t.env);
    const results = await Promise.all([join(k1), join(k2)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 404]);

    const { results: members } = await (t.env.DB as D1Database)
      .prepare(`SELECT member_key_hash FROM space_members WHERE space_id = ?`).bind(space.space.id).all();
    expect(members).toHaveLength(1);
  });
});

describe("caller signatures from taken-down agents (M6)", () => {
  async function signed(privateKey: Uint8Array, payload: Record<string, unknown>) {
    return toB64(await ed.signAsync(new TextEncoder().encode(callerCanonicalString(payload)), privateKey));
  }

  it("accepts an active agent, refuses it once deactivated or marked with a deactivated_reason", async () => {
    stubFetch();
    const t = await makeApp();
    const did = "did:aroha:caller-m6";
    const { didHash, privateKey } = await registerAgent(t.app, t.env, t.apiKey, { did });
    const repo = new D1Repository(t.env.DB as D1Database);
    const payload = { action: "probe", did };
    const sig = await signed(privateKey, payload);

    expect((await verifyCallerSignature(repo, did, payload, sig)).ok).toBe(true);

    await (t.env.DB as D1Database)
      .prepare(`UPDATE agent_records SET deactivated_reason = 'controller-revoked' WHERE did_hash = ?`)
      .bind(didHash).run();
    expect((await verifyCallerSignature(repo, did, payload, sig)).ok).toBe(false);

    await (t.env.DB as D1Database)
      .prepare(`UPDATE agent_records SET deactivated_reason = NULL, active = 0 WHERE did_hash = ?`)
      .bind(didHash).run();
    expect((await verifyCallerSignature(repo, did, payload, sig)).ok).toBe(false);
  });
});

describe("private agents stay hidden on sibling routes (M9)", () => {
  async function privateAgent() {
    stubFetch();
    const t = await makeApp("Owner");
    const stranger = await addKey(t, "stranger-key", "Stranger");
    const { didHash } = await registerAgent(t.app, t.env, t.apiKey, { did: "did:aroha:hidden-m9", visibility: "private" });
    return { t, stranger, didHash };
  }

  it.each([
    ["credential", (h: string) => `/v1/credential/${h}`],
    ["revoked keys", (h: string) => `/v1/agents/${h}/revoked-keys`],
    ["analytics", (h: string) => `/v1/analytics/agents/${h}`],
  ])("%s: 404 for a stranger, 200 for the owner", async (_name, path) => {
    const { t, stranger, didHash } = await privateAgent();
    const anon = await t.app.request(path(didHash), {}, t.env);
    expect([401, 404]).toContain(anon.status);
    const other = await t.app.request(path(didHash), { headers: auth(stranger) }, t.env);
    expect(other.status).toBe(404);
    const owner = await t.app.request(path(didHash), { headers: auth(t.apiKey) }, t.env);
    expect(owner.status).toBe(200);
  });

  it("relay status: 404 for a stranger before the relay is consulted", async () => {
    const { t, stranger, didHash } = await privateAgent();
    const res = await t.app.request(`/v1/relay/${didHash}/status`, { headers: auth(stranger) }, t.env);
    expect(res.status).toBe(404);
  });

  it("marks the resolve response as viewer-dependent (L5)", async () => {
    const { t, didHash } = await privateAgent();
    const res = await t.app.request(`/v1/agents/${didHash}`, { headers: auth(t.apiKey) }, t.env);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Vary")).toContain("Authorization");
  });
});

describe("GET /v1/grants/check answers only parties to the grant (M9)", () => {
  it("requires auth, answers the owner, and 404s an unrelated caller", async () => {
    stubFetch();
    const t = await makeApp("Owner");
    const stranger = await addKey(t, "stranger-key", "Stranger");
    const { didHash } = await registerAgent(t.app, t.env, t.apiKey, { did: "did:aroha:grant-check", visibility: "private" });
    await t.app.request("/v1/grants", {
      method: "POST", headers: auth(t.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeDid: "did:aroha:bob" }),
    }, t.env);

    const q = `/v1/grants/check?resource=${didHash}&did=did:aroha:bob`;
    expect((await t.app.request(q, {}, t.env)).status).toBe(401);
    expect((await t.app.request(q, { headers: auth(stranger) }, t.env)).status).toBe(404);
    const owner = await t.app.request(q, { headers: auth(t.apiKey) }, t.env);
    expect(owner.status).toBe(200);
    expect(await owner.json()).toEqual({ granted: true });
  });
});

describe("request body ceiling (M7)", () => {
  it("413s a 65 KiB body to /v1/agents", async () => {
    const t = await makeApp();
    const res = await t.app.request("/v1/agents", {
      method: "POST", headers: auth(t.apiKey),
      body: JSON.stringify({ did: "did:aroha:big", pad: "x".repeat(65 * 1024) }),
    }, t.env);
    expect(res.status).toBe(413);
  });

  it("keeps the 256 KiB KEL allowance: a 100 KiB KEL body is not refused for size", async () => {
    const t = await makeApp();
    const res = await t.app.request("/v1/kel/did:aroha:Exyz", {
      method: "POST", headers: { "Content-Type": "application/json", "x-forwarded-for": "10.77.0.1" },
      body: JSON.stringify({ events: [], pad: "x".repeat(100 * 1024) }),
    }, t.env);
    expect(res.status).not.toBe(413);
    const huge = await t.app.request("/v1/kel/did:aroha:Exyz", {
      method: "POST", headers: { "Content-Type": "application/json", "x-forwarded-for": "10.77.0.2" },
      body: JSON.stringify({ events: [], pad: "x".repeat(300 * 1024) }),
    }, t.env);
    expect(huge.status).toBe(413);
  });
});

describe("grant expiry is capped whichever form is used (L7)", () => {
  it("clamps an absolute expiresAt to one year", async () => {
    stubFetch();
    const t = await makeApp("Owner");
    const { didHash } = await registerAgent(t.app, t.env, t.apiKey, { did: "did:aroha:grant-cap", visibility: "private" });
    const res = await t.app.request("/v1/grants", {
      method: "POST", headers: auth(t.apiKey),
      body: JSON.stringify({
        resourceDidHash: didHash, resourceType: "agent", granteeDid: "did:aroha:bob",
        expiresAt: Date.now() + 50 * 365 * 24 * 60 * 60 * 1000,
      }),
    }, t.env);
    expect(res.status).toBe(201);
    const { expiresAt } = await res.json() as { expiresAt: number };
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 366 * 24 * 60 * 60 * 1000);
  });
});

describe("rotate-key freshness (L6)", () => {
  it("refuses an issuedAt in the future", async () => {
    stubFetch();
    const t = await makeApp();
    const { didHash } = await registerAgent(t.app, t.env, t.apiKey, { did: "did:aroha:future-rotate" });
    const res = await t.app.request(`/v1/agents/${didHash}/rotate-key`, {
      method: "PUT", headers: auth(t.apiKey),
      body: JSON.stringify({
        newPublicKeyB64: btoa("n".repeat(32)), signature: btoa("s".repeat(64)),
        nonce: crypto.randomUUID(), issuedAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      }),
    }, t.env);
    expect(res.status).toBe(400);
  });
});
