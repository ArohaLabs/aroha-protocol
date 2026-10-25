// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Readable, Writable } from "stream";

// Mock @noble/curves/ed25519 before importing the bridge
vi.mock("@noble/curves/ed25519", () => ({
  ed25519: {
    utils: { randomPrivateKey: () => new Uint8Array(32).fill(1) },
    getPublicKey: () => new Uint8Array(32).fill(2),
  },
}));

vi.mock("@aroha-sdk/core", () => ({
  ArohaClient: class {
    async send() { return null; }
  },
  generateDid: () => "did:aroha:bridge-test",
}));

vi.mock("@aroha-sdk/mcp-bridge", () => ({
  arohaAgentToMcpTools: (_agent: unknown, _did: string, _key: Uint8Array, _client: unknown, _cid: string) => ({
    tools: [
      {
        name: "aroha_search_flights",
        description: "Search flights",
        inputSchema: { type: "object", properties: { from: { type: "string" }, to: { type: "string" } }, required: ["from", "to"] },
      },
    ],
    handleToolCall: async (name: string, args: Record<string, unknown>) => ({
      content: [{ type: "text" as const, text: JSON.stringify({ name, args, result: "mocked" }) }],
    }),
  }),
}));

vi.mock("@aroha-sdk/registry", () => ({}));

describe("Hermes MCP bridge — stdio protocol", () => {
  it("responds to tools/list with MCP tool definitions", async () => {
    const { createHermesMcpServer } = await import("./bridge.js");

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        id: "did:aroha:travel-agent",
        capabilities: [
          { id: "search-flights", description: "Search flights" },
        ],
      }),
    });

    const server = await createHermesMcpServer({
      endpoint: "http://localhost:3000",
      agentDID: "did:aroha:travel-agent",
      privateKey: new Uint8Array(32).fill(1),
      bridgeDID: "did:aroha:bridge-test",
    });

    expect(server.tools).toHaveLength(1);
    expect(server.tools[0].name).toBe("aroha_search_flights");
  });

  it("routes tools/call to the Aroha handleToolCall", async () => {
    const { createHermesMcpServer } = await import("./bridge.js");

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "did:aroha:travel-agent", capabilities: [{ id: "search-flights" }] }),
    });

    const server = await createHermesMcpServer({
      endpoint: "http://localhost:3000",
      agentDID: "did:aroha:travel-agent",
      privateKey: new Uint8Array(32).fill(1),
      bridgeDID: "did:aroha:bridge-test",
    });

    const result = await server.handleToolCall("aroha_search_flights", { from: "JFK", to: "LHR" });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain("aroha_search_flights");
  });

  it("serves JSON-RPC initialize handshake over stdio", async () => {
    const { createHermesMcpServer } = await import("./bridge.js");

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "did:aroha:travel-agent", capabilities: [] }),
    });

    const server = await createHermesMcpServer({
      endpoint: "http://localhost:3000",
      agentDID: "did:aroha:travel-agent",
      privateKey: new Uint8Array(32).fill(1),
      bridgeDID: "did:aroha:bridge-test",
    });

    const initMsg = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n";
    const input = Readable.from([initMsg]);
    const chunks: string[] = [];
    const output = new Writable({
      write(chunk, _enc, cb) { chunks.push(chunk.toString()); cb(); },
    });

    await server.serve(input, output);
    const parsed = JSON.parse(chunks.join("").trim());
    expect(parsed.result.serverInfo.name).toBe("aroha-hermes-bridge");
    expect(parsed.result.capabilities.tools).toBeDefined();
  });
});
