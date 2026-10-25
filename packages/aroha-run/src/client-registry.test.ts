// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// registerMcp / resolveMcp / listMcps / registerSkill / resolveSkill / listSkills
//
// The Python SDK shipped register_mcp/register_skill for a long time without
// ever sending `did` — the registry's POST /v1/mcps and /v1/skills both 400
// without one (apps/registry-server/src/routes/{mcps,skills}.ts), so every
// call failed and nothing was ever registered. That bug survived because the
// tests asserted against a mock that accepted whatever shape was sent, rather
// than the shape the real route requires.
//
// These tests assert the exact request body against that route source, not
// just that a request was made — the same rigor applied to the Python fix.

import { describe, it, expect, afterEach, vi } from "vitest";
import { registerMcp, resolveMcp, listMcps, registerSkill, resolveSkill, listSkills } from "./client.js";

afterEach(() => { vi.unstubAllGlobals(); });

function stubFetch(handler: (url: string, init?: RequestInit) => Response) {
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return handler(url, init);
  });
}

describe("registerMcp", () => {
  it("sends a did — the registry 400s without one", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerMcp({ name: "search-mcp", endpointUrl: "https://mcp.example.com", apiKey: "key" });

    expect(typeof sentBody.did).toBe("string");
    expect((sentBody.did as string).length).toBeGreaterThan(0);
  });

  it("honours an explicit did instead of generating one", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerMcp({
      name: "search-mcp", endpointUrl: "https://mcp.example.com",
      did: "did:aroha:my-search-mcp", apiKey: "key",
    });

    expect(sentBody.did).toBe("did:aroha:my-search-mcp");
  });

  it("sends toolIds, not tools — the field insertMcp() actually reads", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerMcp({
      name: "search-mcp", endpointUrl: "https://mcp.example.com",
      tools: ["search", { name: "fetch" }], apiKey: "key",
    });

    expect(sentBody.toolIds).toEqual(["search", "fetch"]);
    expect(sentBody.tools).toBeUndefined();
  });

  it("posts to /v1/mcps with a bearer token", async () => {
    let sentUrl = "", sentAuth = "";
    stubFetch((url, init) => {
      sentUrl = url;
      sentAuth = (init!.headers as Record<string, string>).Authorization;
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerMcp({ name: "x", endpointUrl: "https://e.com", apiKey: "my-key" });

    expect(sentUrl).toBe("https://aroha-registry.aroha-labs.workers.dev/v1/mcps");
    expect(sentAuth).toBe("Bearer my-key");
  });

  it("throws with the response body on failure", async () => {
    stubFetch(() => new Response(JSON.stringify({ error: "DID already registered" }), { status: 409 }));

    await expect(
      registerMcp({ name: "x", endpointUrl: "https://e.com", apiKey: "key" }),
    ).rejects.toThrow(/409/);
  });
});

describe("resolveMcp / listMcps", () => {
  it("resolveMcp GETs /v1/mcps/:didOrHash and returns the parsed record", async () => {
    const record = { did: "did:aroha:x", didHash: "0xabc", name: "x", toolIds: ["search"] };
    let sentUrl = "";
    stubFetch((url) => { sentUrl = url; return new Response(JSON.stringify(record), { status: 200 }); });

    const result = await resolveMcp("0xabc");

    expect(sentUrl).toBe("https://aroha-registry.aroha-labs.workers.dev/v1/mcps/0xabc");
    expect(result.name).toBe("x");
  });

  it("listMcps parses a bare array — unlike listAgents, this endpoint has no wrapper object", async () => {
    const rows = [{ did: "did:aroha:a", didHash: "0x1" }, { did: "did:aroha:b", didHash: "0x2" }];
    stubFetch(() => new Response(JSON.stringify(rows), { status: 200 }));

    const result = await listMcps();

    expect(result).toHaveLength(2);
    expect(result[0].didHash).toBe("0x1");
  });

  it("listMcps sends limit and offset as query params", async () => {
    let sentUrl = "";
    stubFetch((url) => { sentUrl = url; return new Response("[]", { status: 200 }); });

    await listMcps({ limit: 5, offset: 10 });

    const params = new URL(sentUrl).searchParams;
    expect(params.get("limit")).toBe("5");
    expect(params.get("offset")).toBe("10");
  });
});

describe("registerSkill", () => {
  it("sends a did — the registry 400s without one", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerSkill({ name: "my-rag-skill", skillType: "rag", apiKey: "key" });

    expect(typeof sentBody.did).toBe("string");
    expect(sentBody.skillType).toBe("rag");
  });

  it("defaults skillType to custom, matching the server-side default", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerSkill({ name: "x", apiKey: "key" });

    expect(sentBody.skillType).toBe("custom");
  });

  it("omits endpointUrl entirely when not given, rather than sending an empty string", async () => {
    let sentBody: Record<string, unknown> = {};
    stubFetch((url, init) => {
      sentBody = JSON.parse(init!.body as string);
      return new Response(JSON.stringify({ didHash: "0xabc" }), { status: 201 });
    });

    await registerSkill({ name: "x", apiKey: "key" });

    expect("endpointUrl" in sentBody).toBe(false);
  });
});

describe("resolveSkill / listSkills", () => {
  it("resolveSkill GETs /v1/skills/:didOrHash", async () => {
    const record = { did: "did:aroha:x", didHash: "0xabc", skillType: "rag" };
    let sentUrl = "";
    stubFetch((url) => { sentUrl = url; return new Response(JSON.stringify(record), { status: 200 }); });

    const result = await resolveSkill("0xabc");

    expect(sentUrl).toBe("https://aroha-registry.aroha-labs.workers.dev/v1/skills/0xabc");
    expect(result.skillType).toBe("rag");
  });

  it("listSkills filters by type using the ?type= param the route reads", async () => {
    let sentUrl = "";
    stubFetch((url) => { sentUrl = url; return new Response("[]", { status: 200 }); });

    await listSkills({ skillType: "web-search" });

    expect(new URL(sentUrl).searchParams.get("type")).toBe("web-search");
  });
});
