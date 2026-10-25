import { describe, it, expect, vi, afterEach } from "vitest";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent } from "../test-utils/register.js";

afterEach(() => { vi.unstubAllGlobals(); });

function adminHeaders() {
  return { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" };
}

// Register a test agent and return its didHash.
async function registerAgent(
  app: Awaited<ReturnType<typeof makeApp>>["app"],
  env: Awaited<ReturnType<typeof makeApp>>["env"],
  apiKey: string,
  did = "did:aroha:signal-agent",
) {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
  const res = await postAgent(app, env, apiKey, { did, manifestCID: "QmS", publicKeyB64: btoa("s".repeat(32)) });
  const { didHash } = await res.json() as { didHash: string };
  return didHash;
}

describe("POST /v1/signals", () => {
  it("updates reputation and returns compositeScore", async () => {
    const { app, apiKey, env } = await makeApp();
    const didHash = await registerAgent(app, env, apiKey);

    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ agentDID: didHash, source: "evals", successRate: 0.9, sampleSize: 20 }),
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; compositeScore: number };
    expect(body.ok).toBe(true);
    // compositeScore is on the 0–10000 reputation scale: α×(signal×10000) + (1−α)×current
    expect(body.compositeScore).toBeGreaterThan(0);
    expect(body.compositeScore).toBeLessThanOrEqual(10000);
    // A 90% signal with sampleSize=20 (α=0.3) from a starting 5000 should move up
    expect(body.compositeScore).toBeGreaterThan(5000);
  });

  it("accepts a full DID string (auto-hashes)", async () => {
    const { app, apiKey, env } = await makeApp();
    await registerAgent(app, env, apiKey, "did:aroha:signal-by-did");

    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ agentDID: "did:aroha:signal-by-did", successRate: 0.8 }),
    }, env);
    expect(res.status).toBe(200);
  });

  it("401 without admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-secret" },
      body: JSON.stringify({ agentDID: "did:aroha:x", successRate: 0.5 }),
    }, env);
    expect(res.status).toBe(401);
  });

  // An ordinary org API key used to be accepted (rate-limited), which let any
  // self-service key holder move any agent's reputation score.
  it("401 for an org API key — reputation signals are admin-only", async () => {
    const { app, apiKey, env } = await makeApp();
    const didHash = await registerAgent(app, env, apiKey, "did:aroha:signal-no-org-key");
    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ agentDID: didHash, successRate: 0.1 }),
    }, env);
    expect(res.status).toBe(401);
  });

  it("400 when successRate is out of range", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ agentDID: "did:aroha:x", successRate: 1.5 }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("400 when required fields missing", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ agentDID: "did:aroha:x" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("404 for an unregistered agent DID", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/signals", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ agentDID: "did:aroha:ghost", successRate: 0.7 }),
    }, env);
    expect(res.status).toBe(404);
  });
});
