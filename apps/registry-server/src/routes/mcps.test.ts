import { describe, it, expect } from "vitest";
import { makeApp } from "../test-utils/make-app.js";

function authHeaders(apiKey: string) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` };
}

const MCP_PAYLOAD = {
  did: "did:aroha:mcp-test",
  name: "Test MCP",
  description: "A test MCP server",
  endpointUrl: "https://mcp.example.com/sse",
  toolIds: ["tool-search", "tool-fetch"],
};

describe("GET /v1/mcps", () => {
  it("returns empty list initially", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/mcps", {}, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);
  });

  it("returns registered MCP after POST", async () => {
    const { app, apiKey, env } = await makeApp();
    await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    const res = await app.request("/v1/mcps", {}, env);
    const body = await res.json() as { name: string }[];
    expect(body).toHaveLength(1);
    expect(body[0].name).toBe("Test MCP");
  });
});

describe("POST /v1/mcps", () => {
  it("201 with valid payload", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    expect(res.status).toBe(201);
    const body = await res.json() as { didHash: string };
    expect(body.didHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("400 when required fields missing", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/mcps", {
      method: "POST",
      headers: authHeaders(apiKey),
      body: JSON.stringify({ did: "did:aroha:mcp-missing" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("400 when endpointUrl is not http(s)", async () => {
    const { app, apiKey, env } = await makeApp();
    const res = await app.request("/v1/mcps", {
      method: "POST",
      headers: authHeaders(apiKey),
      body: JSON.stringify({ ...MCP_PAYLOAD, did: "did:aroha:mcp-bad-url", endpointUrl: "ws://bad" }),
    }, env);
    expect(res.status).toBe(400);
  });

  it("409 on duplicate DID", async () => {
    const { app, apiKey, env } = await makeApp();
    await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    const res = await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    expect(res.status).toBe(409);
  });

  it("401 without API key", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/mcps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(MCP_PAYLOAD),
    }, env);
    expect(res.status).toBe(401);
  });
});

describe("GET /v1/mcps/:didHash", () => {
  it("404 for unknown DID", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/mcps/did:aroha:no-such-mcp", {}, env);
    expect(res.status).toBe(404);
  });

  it("resolves registered MCP by DID string", async () => {
    const { app, apiKey, env } = await makeApp();
    const reg = await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };
    const res = await app.request(`/v1/mcps/${didHash}`, {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { did: string };
    expect(body.did).toBe(MCP_PAYLOAD.did);
  });
});

describe("DELETE /v1/mcps/:didHash/admin", () => {
  it("deactivates MCP by orgName with admin secret", async () => {
    const { app, apiKey, env } = await makeApp("McpOrg");
    const reg = await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/mcps/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "McpOrg" }),
    }, env);
    expect(res.status).toBe(200);
  });

  it("403 with wrong admin secret", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/v1/mcps/0x1234/admin", {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer bad-secret" },
      body: JSON.stringify({ orgName: "X" }),
    }, env);
    expect(res.status).toBe(403);
  });

  it("404 when orgName does not own the MCP", async () => {
    const { app, apiKey, env } = await makeApp("RealMcpOrg");
    const reg = await app.request("/v1/mcps", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(MCP_PAYLOAD) }, env);
    const { didHash } = await reg.json() as { didHash: string };

    const res = await app.request(`/v1/mcps/${didHash}/admin`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-admin-secret-0123456789abcdefghijklmn" },
      body: JSON.stringify({ orgName: "WrongOrg" }),
    }, env);
    expect(res.status).toBe(404);
  });
});
