import { describe, it, expect, vi, afterEach } from "vitest";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent } from "../test-utils/register.js";

afterEach(() => { vi.unstubAllGlobals(); });

function stubFetch() {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
}

async function registerAgent(
  app: Awaited<ReturnType<typeof makeApp>>["app"],
  env: Awaited<ReturnType<typeof makeApp>>["env"],
  apiKey: string,
  did = "did:aroha:analytics-test",
) {
  stubFetch();
  const res = await postAgent(app, env, apiKey, { did, manifestCID: "QmAnalytics1", publicKeyB64: btoa("a".repeat(32)) });
  return await res.json() as { didHash: string };
}

// ─── GET /v1/analytics/agents/:didHash ────────────────────────────────────────

describe("GET /v1/analytics/agents/:didHash", () => {
  it("401 without a valid API key", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/analytics/agents/somehash", {
      headers: { Authorization: "Bearer badkey" },
    }, env);
    expect(res.status).toBe(401);
  });

  it("404 for unknown agent", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/analytics/agents/unknownhash", {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, env);
    expect(res.status).toBe(404);
  });

  it("returns zero discovery counts for a newly registered agent", async () => {
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:stats-zero");

    const res = await app.request(`/v1/analytics/agents/${didHash}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { total: number; last7d: number; last30d: number; did: string };
    expect(body.did).toBe("did:aroha:stats-zero");
    expect(body.total).toBe(0);
    expect(body.last7d).toBe(0);
    expect(body.last30d).toBe(0);
  });

  it("counts discovery events after GET /:didHash is called", async () => {
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:stats-counted");

    // Trigger discovery events via the public endpoint
    await app.request(`/v1/agents/${didHash}`, {}, env);
    await app.request(`/v1/agents/${didHash}`, {}, env);
    await app.request(`/v1/agents/${didHash}`, {}, env);

    const res = await app.request(`/v1/analytics/agents/${didHash}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { total: number; last7d: number; last30d: number };
    expect(body.total).toBe(3);
    expect(body.last7d).toBe(3);
    expect(body.last30d).toBe(3);
  });

  it("returns didHash and did in the response", async () => {
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:stats-fields");

    const res = await app.request(`/v1/analytics/agents/${didHash}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, env);
    const body = await res.json() as { didHash: string; did: string };
    expect(body.didHash).toBe(didHash);
    expect(body.did).toBe("did:aroha:stats-fields");
  });
});

// ─── GET /v1/analytics/summary ───────────────────────────────────────────────

describe("GET /v1/analytics/summary", () => {
  it("403 without admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/analytics/summary", {
      headers: { Authorization: "Bearer not-the-admin-secret" },
    }, env);
    expect(res.status).toBe(403);
  });

  it("returns platform summary with correct active agent count", async () => {
    const { app, apiKey, env } = await makeApp();
    await registerAgent(app, env, apiKey, "did:aroha:summary-a1");
    await registerAgent(app, env, apiKey, "did:aroha:summary-a2");

    const res = await app.request("/v1/analytics/summary", {
      headers: { Authorization: `Bearer ${env.ADMIN_SECRET}` },
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as {
      activeAgents: number;
      verifiedAgents: number;
      totalEvents7d: number;
      registrations7d: number;
    };
    expect(body.activeAgents).toBeGreaterThanOrEqual(2);
    // New agents below the 7000 reputation threshold → 0 verified
    expect(body.verifiedAgents).toBe(0);
    // Registration events should be counted
    expect(body.registrations7d).toBeGreaterThanOrEqual(2);
    expect(typeof body.totalEvents7d).toBe("number");
  });

  it("totalEvents7d increments when agents are discovered", async () => {
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:events-counted");

    const before = await (await app.request("/v1/analytics/summary", {
      headers: { Authorization: `Bearer ${env.ADMIN_SECRET}` },
    }, env)).json() as { totalEvents7d: number };

    // Trigger discovery events
    await app.request(`/v1/agents/${didHash}`, {}, env);
    await app.request(`/v1/agents/${didHash}`, {}, env);

    const after = await (await app.request("/v1/analytics/summary", {
      headers: { Authorization: `Bearer ${env.ADMIN_SECRET}` },
    }, env)).json() as { totalEvents7d: number };

    expect(after.totalEvents7d).toBeGreaterThanOrEqual(before.totalEvents7d + 2);
  });
});
