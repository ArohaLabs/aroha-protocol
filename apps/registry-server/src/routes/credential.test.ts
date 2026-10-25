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
  did = "did:aroha:cred-test",
) {
  const res = await postAgent(app, env, apiKey, { did, manifestCID: "QmC", publicKeyB64: btoa("c".repeat(32)) });
  return await res.json() as { didHash: string };
}

// ─── GET /v1/credential/:didHash ─────────────────────────────────────────────

describe("GET /v1/credential/:didHash", () => {
  it("returns a JWT token and expiresAt for a registered agent", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey);

    const res = await app.request(`/v1/credential/${didHash}`, {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { token: string; expiresAt: number };
    expect(typeof body.token).toBe("string");
    expect(body.token.split(".")).toHaveLength(3); // header.payload.sig
    expect(body.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("credential payload contains agent did and reputationScore", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:cred-payload");

    const { token } = await (await app.request(`/v1/credential/${didHash}`, {}, env)).json() as { token: string };
    // Decode payload (middle part) without verifying — verify endpoint tests that
    const payloadB64 = token.split(".")[1];
    const padding = (4 - payloadB64.length % 4) % 4;
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding)));

    expect(payload.sub).toBe(didHash);
    expect(payload.iss).toBe("aroha-registry");
    expect(payload.agent.did).toBe("did:aroha:cred-payload");
    expect(typeof payload.agent.reputationScore).toBe("number");
    expect(typeof payload.agent.verified).toBe("boolean");
  });

  it("newly registered agent has verified: false in credential", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:cred-unverified");

    const { token } = await (await app.request(`/v1/credential/${didHash}`, {}, env)).json() as { token: string };
    const payloadB64 = token.split(".")[1];
    const padding = (4 - payloadB64.length % 4) % 4;
    const { agent } = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding)));

    // Default reputationScore=5000 < 7000 threshold, registered just now < 7 days
    expect(agent.verified).toBe(false);
  });

  it("404 for an unknown didHash", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/credential/0xdeadbeef", {}, env);
    expect(res.status).toBe(404);
  });
});

// ─── POST /v1/credential/verify ──────────────────────────────────────────────

describe("POST /v1/credential/verify", () => {
  it("verifies a valid token issued by the same registry and returns payload", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:verify-valid");

    const { token } = await (await app.request(`/v1/credential/${didHash}`, {}, env)).json() as { token: string };

    const res = await app.request("/v1/credential/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    }, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { valid: boolean; payload: { sub: string; agent: { did: string } } };
    expect(body.valid).toBe(true);
    expect(body.payload.sub).toBe(didHash);
    expect(body.payload.agent.did).toBe("did:aroha:verify-valid");
  });

  it("401 for a tampered token", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:tamper-test");

    const { token } = await (await app.request(`/v1/credential/${didHash}`, {}, env)).json() as { token: string };
    const parts = token.split(".");

    // Tamper with the FIRST signature character, not the last.
    //
    // An Ed25519 signature is 64 bytes = 512 bits, but base64url spreads it over
    // 86 chars = 516 bits, so the final character carries only 2 significant
    // bits and 4 bits of padding. Flipping it between chars that share their top
    // two bits (A/B/C/D all start 00) leaves the decoded signature byte-for-byte
    // identical — verification then correctly succeeds and the test fails for the
    // wrong reason, roughly 6% of runs. The first character has all 6 bits live.
    const sig = parts[2];
    const first = sig[0];
    const flipped = first === "A" ? "B" : "A";
    const badToken = `${parts[0]}.${parts[1]}.${flipped}${sig.slice(1)}`;

    // Prove the tamper actually changed the signature bytes, so this test can
    // never again silently degrade into asserting nothing.
    const decode = (s: string) =>
      Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    expect(decode(badToken.split(".")[2])).not.toEqual(decode(sig));

    const res = await app.request("/v1/credential/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: badToken }),
    }, env);
    expect(res.status).toBe(401);
  });

  it("401 for a token signed with a different secret", async () => {
    const { app, env } = await makeApp();
    const fakeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIweDEyMzQiLCJleHAiOjk5OTk5OTk5OTl9.invalidsignature";
    const res = await app.request("/v1/credential/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: fakeToken }),
    }, env);
    expect(res.status).toBe(401);
  });

  it("refuses to sign (503) when neither CREDENTIAL_SECRET nor a usable ADMIN_SECRET is set", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:cred-no-secret");
    const res = await app.request(`/v1/credential/${didHash}`, {}, { ...env, ADMIN_SECRET: "short" });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { token?: string }).token).toBeUndefined();
  });

  it("a token signed under one CREDENTIAL_SECRET does not verify under another", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const { didHash } = await registerAgent(app, env, apiKey, "did:aroha:cred-separate");
    const envA = { ...env, CREDENTIAL_SECRET: "a".repeat(40) };
    const envB = { ...env, CREDENTIAL_SECRET: "b".repeat(40) };
    const { token } = await (await app.request(`/v1/credential/${didHash}`, {}, envA)).json() as { token: string };
    const verify = (e: typeof env) => app.request("/v1/credential/verify", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }),
    }, e);
    expect((await verify(envA)).status).toBe(200);
    expect((await verify(envB)).status).toBe(401);
  });

  it("400 when token field is missing", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/credential/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }, env);
    expect(res.status).toBe(400);
  });
});
