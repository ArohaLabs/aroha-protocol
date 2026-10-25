import { describe, it, expect } from "vitest";
import { makeApp } from "../test-utils/make-app.js";

function authHeaders(apiKey: string) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` };
}

const SKILL_PAYLOAD = {
  did: "did:aroha:skill-test",
  name: "Web Search",
  description: "Real-time web search",
  skillType: "web-search",
  endpointUrl: "https://search.example.com",
};

describe("GET /v1/skills", () => {
  it("returns empty list initially", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/skills", {}, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);
  });

  it("filters by skillType", async () => {
    const { app, apiKey, env } = await makeApp();
    await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    await app.request("/v1/skills", {
      method: "POST", headers: authHeaders(apiKey),
      body: JSON.stringify({ ...SKILL_PAYLOAD, did: "did:aroha:rag-skill", name: "RAG Skill", skillType: "rag", endpointUrl: "https://rag.example.com" }),
    }, env);

    const res = await app.request("/v1/skills?type=rag", {}, env);
    const body = await res.json() as { skillType: string }[];
    expect(body).toHaveLength(1);
    expect(body[0].skillType).toBe("rag");
  });
});

describe("POST /v1/skills", () => {
  it("201 with valid payload", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    expect(res.status).toBe(201);
    const body = await res.json() as { didHash: string };
    expect(body.didHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("400 when did or name missing", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/skills", {
      method: "POST",
      headers: authHeaders(apiKey),
      body: JSON.stringify({ did: "did:aroha:no-name" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("400 for invalid skillType", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/skills", {
      method: "POST",
      headers: authHeaders(apiKey),
      body: JSON.stringify({ ...SKILL_PAYLOAD, did: "did:aroha:bad-type", skillType: "magic" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("409 on duplicate DID", async () => {
    const { app, apiKey, env } = await makeApp();
    await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    const res = await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    expect(res.status).toBe(409);
  });
});

describe("GET /v1/skills/:didHash", () => {
  it("404 for unknown DID", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/skills/did:aroha:no-such-skill", {}, env);
    expect(res.status).toBe(404);
  });

  it("resolves registered skill by DID string", async () => {
    const { app, apiKey, env } = await makeApp();
    const reg = await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };
    const res = await app.request(`/v1/skills/${didHash}`, {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { skillType: string };
    expect(body.skillType).toBe("web-search");
  });
});

describe("DELETE /v1/skills/:didHash/admin", () => {
  it("deactivates skill by orgName with admin secret", async () => {
    const { app, apiKey, env } = await makeApp("SkillOrg");
    const reg = await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/skills/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "SkillOrg" }),
    }, env);
    expect(res.status).toBe(200);
  });

  it("403 with wrong admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/skills/0x1234/admin", {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer bad-secret" },
      body: JSON.stringify({ orgName: "X" }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("404 when orgName does not own the skill", async () => {
    const { app, apiKey, env } = await makeApp("RealSkillOrg");
    const reg = await app.request("/v1/skills", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(SKILL_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/skills/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "WrongOrg" }),
    }, env);
    expect(res.status).toBe(404);
  });
});
