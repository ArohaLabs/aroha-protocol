/**
 * Private agents: visibility levels and access grants.
 *
 * Covers the three visibility states across discovery, capability search, and
 * resolve-by-didHash, plus grant creation / scoping / revocation / expiry —
 * and the privacy-critical property that a private record is indistinguishable
 * from a non-existent one to an unauthorised caller.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent, manifestWith, stubManifestFetch } from "../test-utils/register.js";
import { sha256hex } from "../auth.js";
import type { SqliteD1 } from "../test-utils/sqlite-d1.js";

type TestApp = Awaited<ReturnType<typeof makeApp>>;
type App = TestApp["app"];
type Env = TestApp["env"];

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

// Capabilities for the next `register` call. The registry only indexes a
// manifest whose bytes hash to its CID, so `register` mints a real CIDv0
// for these and the stub serves it as a raw IPLD block.
let pendingCapabilities: string[] = [];
function stubFetch(capabilities: Array<{ id: string }> = []) {
  pendingCapabilities = capabilities.map((c) => c.id);
  stubManifestFetch();
}

/** Add a second org's API key to the same database. */
async function addKey(env: Env, raw: string, orgName: string) {
  const hash = await sha256hex(raw);
  await (env.DB as SqliteD1)
    .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
    .bind(hash, orgName, Date.now())
    .run();
  return { apiKey: raw, keyHash: hash };
}

/**
 * Register an agent and clear its 48 h discovery cooldown so list results are
 * about visibility, not the anti-squatting delay.
 */
async function register(
  app: App,
  env: Env,
  apiKey: string,
  did: string,
  visibility?: string,
) {
  const res = await postAgent(app, env, apiKey, {
      did, manifestCID: await manifestWith(pendingCapabilities), publicKeyB64: btoa("k".repeat(32)),
      ...(visibility ? { visibility } : {}),
    });
  const { didHash } = await res.json() as { didHash: string };
  await (env.DB as SqliteD1)
    .prepare(`UPDATE agent_records SET discovery_eligible_at = NULL WHERE did_hash = ?`)
    .bind(didHash).run();
  return didHash;
}

const auth = (k: string) => ({ Authorization: `Bearer ${k}` });

// ─── Visibility ──────────────────────────────────────────────────────────────

describe("visibility — discovery listing", () => {
  it("public agents are listed anonymously; unlisted and private are not", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    await register(app, env, apiKey, "did:aroha:pub", "public");
    await register(app, env, apiKey, "did:aroha:unl", "unlisted");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const body = await (await app.request("/v1/agents", {}, env)).json() as { did: string }[];
    expect(body.map((a) => a.did)).toEqual(["did:aroha:pub"]);
  });

  // An unrecognised key must not be an oracle. If a bad key produced 401 while
  // a good one produced a filtered list, an attacker could distinguish "this
  // key is wrong" from "this record is hidden" — and, worse, a caller whose key
  // was revoked would get a hard error instead of quietly falling back to the
  // public view. Optional auth means invalid credentials degrade, never reject.
  it("an unrecognised API key degrades to the anonymous view, not a 401", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    await register(app, env, apiKey, "did:aroha:pub", "public");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const res = await app.request("/v1/agents", { headers: auth("not-a-real-key") }, env);

    expect(res.status).toBe(200);
    const body = await res.json() as { did: string }[];
    expect(body.map((a) => a.did)).toEqual(["did:aroha:pub"]);
  });

  it("a malformed authorization header is treated as anonymous", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    await register(app, env, apiKey, "did:aroha:pub", "public");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const res = await app.request(
      "/v1/agents",
      { headers: { Authorization: "Basic zzzz" } },
      env,
    );

    expect(res.status).toBe(200);
    const body = await res.json() as { did: string }[];
    expect(body.map((a) => a.did)).toEqual(["did:aroha:pub"]);
  });

  it("the owner sees their own agents at every visibility level", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    await register(app, env, apiKey, "did:aroha:pub", "public");
    await register(app, env, apiKey, "did:aroha:unl", "unlisted");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const body = await (await app.request("/v1/agents", { headers: auth(apiKey) }, env)).json() as { did: string }[];
    expect(body.map((a) => a.did).sort()).toEqual(["did:aroha:priv", "did:aroha:pub", "did:aroha:unl"]);
  });

  it("another org does not see private agents in listings", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const other = await addKey(env, "other-key", "Other");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const body = await (await app.request("/v1/agents", { headers: auth(other.apiKey) }, env)).json() as unknown[];
    expect(body).toEqual([]);
  });

  it("private agents are excluded from capability search", async () => {
    stubFetch([{ id: "research" }]);
    const { app, apiKey, env } = await makeApp("Owner");
    const other = await addKey(env, "other-key", "Other");
    await register(app, env, apiKey, "did:aroha:priv", "private");

    const anon = await (await app.request("/v1/agents?capabilities=research", {}, env)).json() as unknown[];
    expect(anon).toEqual([]);

    const stranger = await (await app.request("/v1/agents?capabilities=research", { headers: auth(other.apiKey) }, env)).json() as unknown[];
    expect(stranger).toEqual([]);

    const owner = await (await app.request("/v1/agents?capabilities=research", { headers: auth(apiKey) }, env)).json() as unknown[];
    expect(owner).toHaveLength(1);
  });
});

describe("visibility — resolve by didHash", () => {
  it("unlisted agents remain resolvable by anyone who knows the identifier", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:unl", "unlisted");

    const res = await app.request(`/v1/agents/${didHash}`, {}, env);
    expect(res.status).toBe(200);
  });

  it("private agents return 404 to strangers — never 403, which would confirm existence", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const other = await addKey(env, "other-key", "Other");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    expect((await app.request(`/v1/agents/${didHash}`, {}, env)).status).toBe(404);
    expect((await app.request(`/v1/agents/${didHash}`, { headers: auth(other.apiKey) }, env)).status).toBe(404);
    expect((await app.request(`/v1/agents/${didHash}`, { headers: auth(apiKey) }, env)).status).toBe(200);
  });
});

describe("PATCH /v1/agents/:didHash/visibility", () => {
  it("the owner can change visibility, and it takes effect immediately", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:x", "public");

    expect(await (await app.request("/v1/agents", {}, env)).json()).toHaveLength(1);

    const res = await app.request(`/v1/agents/${didHash}/visibility`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ visibility: "private" }),
    }, env);
    expect(res.status).toBe(200);
    expect(await (await app.request("/v1/agents", {}, env)).json()).toEqual([]);
  });

  it("a non-owner cannot change visibility", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const other = await addKey(env, "other-key", "Other");
    const didHash = await register(app, env, apiKey, "did:aroha:x", "public");

    const res = await app.request(`/v1/agents/${didHash}/visibility`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...auth(other.apiKey) },
      body: JSON.stringify({ visibility: "private" }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("rejects an invalid visibility value", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:x");
    const res = await app.request(`/v1/agents/${didHash}/visibility`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ visibility: "secret" }),
    }, env);
    expect(res.status).toBe(422);
  });

  it("reviving a deactivated private agent does not silently make it public", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:x", "private");

    // Deactivate, then re-register — the only path that replaces the row.
    await app.request(`/v1/agents/${didHash}`, { method: "DELETE", headers: auth(apiKey) }, env);
    await register(app, env, apiKey, "did:aroha:x");   // no visibility given

    // Still private: anonymous discovery sees nothing, the owner still sees it.
    expect(await (await app.request("/v1/agents", {}, env)).json()).toEqual([]);
    expect(await (await app.request("/v1/agents", { headers: auth(apiKey) }, env)).json()).toHaveLength(1);
  });
});

// ─── Grants ──────────────────────────────────────────────────────────────────

describe("access grants", () => {
  it("a granted org can discover and resolve a private agent", async () => {
    stubFetch([{ id: "research" }]);
    const { app, apiKey, env } = await makeApp("Owner");
    const partner = await addKey(env, "partner-key", "Partner");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    // Before the grant: invisible.
    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toEqual([]);

    const grant = await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({
        resourceDidHash: didHash, resourceType: "agent",
        granteeApiKey: partner.apiKey, note: "Partner integration",
      }),
    }, env);
    expect(grant.status).toBe(201);

    // After the grant: listed, searchable, and resolvable.
    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toHaveLength(1);
    expect(await (await app.request("/v1/agents?capabilities=research", { headers: auth(partner.apiKey) }, env)).json()).toHaveLength(1);
    expect((await app.request(`/v1/agents/${didHash}`, { headers: auth(partner.apiKey) }, env)).status).toBe(200);

    // A third party still sees nothing.
    const stranger = await addKey(env, "stranger-key", "Stranger");
    expect(await (await app.request("/v1/agents", { headers: auth(stranger.apiKey) }, env)).json()).toEqual([]);
  });

  it("never echoes the grantee key hash back in responses", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const partner = await addKey(env, "partner-key", "Partner");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const res = await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeApiKey: partner.apiKey }),
    }, env);
    const body = await res.json() as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain(partner.keyHash);
    expect(body.granteeScoped).toBe(true);
  });

  it("revoking a grant removes access again", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const partner = await addKey(env, "partner-key", "Partner");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const created = await (await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeApiKey: partner.apiKey }),
    }, env)).json() as { id: number };

    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toHaveLength(1);

    const del = await app.request(`/v1/grants/${created.id}`, { method: "DELETE", headers: auth(apiKey) }, env);
    expect(del.status).toBe(200);

    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toEqual([]);
  });

  it("an expired grant confers no access", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const partner = await addKey(env, "partner-key", "Partner");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({
        resourceDidHash: didHash, resourceType: "agent",
        granteeApiKey: partner.apiKey, expiresAt: Date.now() + 50,
      }),
    }, env);

    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 80));
    expect(await (await app.request("/v1/agents", { headers: auth(partner.apiKey) }, env)).json()).toEqual([]);
  });

  it("rejects an expiry in the past", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");
    const res = await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({
        resourceDidHash: didHash, resourceType: "agent",
        granteeDid: "did:aroha:partner", expiresAt: Date.now() - 1000,
      }),
    }, env);
    expect(res.status).toBe(422);
  });

  it("a non-owner cannot grant access to someone else's agent", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const attacker = await addKey(env, "attacker-key", "Attacker");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const res = await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(attacker.apiKey) },
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeApiKey: attacker.apiKey }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("a non-owner cannot revoke someone else's grant", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const attacker = await addKey(env, "attacker-key", "Attacker");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const created = await (await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeDid: "did:aroha:p" }),
    }, env)).json() as { id: number };

    const res = await app.request(`/v1/grants/${created.id}`, { method: "DELETE", headers: auth(attacker.apiKey) }, env);
    expect(res.status).toBe(403);
  });

  it("re-granting the same pair replaces the previous grant rather than erroring", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp("Owner");
    const partner = await addKey(env, "partner-key", "Partner");
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const body = JSON.stringify({
      resourceDidHash: didHash, resourceType: "agent", granteeApiKey: partner.apiKey,
    });
    const headers = { "Content-Type": "application/json", ...auth(apiKey) };

    expect((await app.request("/v1/grants", { method: "POST", headers, body }, env)).status).toBe(201);
    expect((await app.request("/v1/grants", { method: "POST", headers, body }, env)).status).toBe(201);

    const list = await (await app.request(`/v1/grants?resource=${didHash}`, { headers: auth(apiKey) }, env)).json() as unknown[];
    expect(list).toHaveLength(1);   // one live grant, not two
  });

  it("GET /v1/grants/check reports DID-scoped grants for agent-side allow-lists", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const didHash = await register(app, env, apiKey, "did:aroha:priv", "private");

    const before = await (await app.request(`/v1/grants/check?resource=${didHash}&did=did:aroha:bob`, { headers: auth(apiKey) }, env)).json() as { granted: boolean };
    expect(before.granted).toBe(false);

    await app.request("/v1/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...auth(apiKey) },
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent", granteeDid: "did:aroha:bob" }),
    }, env);

    const after = await (await app.request(`/v1/grants/check?resource=${didHash}&did=did:aroha:bob`, { headers: auth(apiKey) }, env)).json() as { granted: boolean };
    expect(after.granted).toBe(true);
  });
});
