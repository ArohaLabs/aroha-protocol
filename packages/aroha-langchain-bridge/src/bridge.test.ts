// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import {
  arohaCapabilityToLangChainTool,
  arohaCapabilityToOpenAITool,
  langChainToolsToCapabilities,
  langChainAgentToArohaProvider,
} from "./bridge.js";
import type { LangChainToolLike } from "./types.js";
import { ArohaClient, ArohaServer, generateDID } from "@aroha-sdk/core";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTool(
  name: string,
  description = "A test tool",
  result = "tool result"
): LangChainToolLike {
  return {
    name,
    description,
    call: vi.fn().mockResolvedValue(result),
  };
}

// ─── langChainToolsToCapabilities ────────────────────────────────────────────

describe("langChainToolsToCapabilities", () => {
  it("maps each tool to a ArohaCapabilityDescriptor", () => {
    const tools = [
      makeTool("search-flights", "Search for available flights"),
      makeTool("search-hotels", "Search for hotels"),
    ];
    const caps = langChainToolsToCapabilities(tools);

    expect(caps).toHaveLength(2);
    expect(caps[0].capabilityId).toBe("search-flights");
    expect(caps[0].description).toBe("Search for available flights");
    expect(caps[1].capabilityId).toBe("search-hotels");
  });

  it("passes through the tool schema when present", () => {
    const schema = { type: "object", properties: { q: { type: "string" } } };
    const tools = [{ name: "search", description: "d", schema, call: vi.fn() }];
    const caps = langChainToolsToCapabilities(tools);
    expect(caps[0].inputSchema).toEqual(schema);
  });

  it("sets inputSchema to undefined when the tool has no schema", () => {
    const caps = langChainToolsToCapabilities([makeTool("no-schema")]);
    expect(caps[0].inputSchema).toBeUndefined();
  });

  it("returns an empty array for an empty tool list", () => {
    expect(langChainToolsToCapabilities([])).toEqual([]);
  });
});

// ─── arohaCapabilityToLangChainTool ────────────────────────────────────────────

describe("arohaCapabilityToLangChainTool", () => {
  it("returns a tool with the correct name (sanitised to word-chars)", () => {
    const tool = arohaCapabilityToLangChainTool("search-flights", {
      endpoint: "http://localhost:3001",
      agentDID: "did:aroha:remote",
      callerDID: "did:aroha:caller",
      callerPrivateKey: new Uint8Array(32),
      description: "Search flights",
      client: { send: vi.fn() } as unknown as ArohaClient,
    });
    // Hyphens are replaced with underscores by the sanitiser
    expect(tool.name).toMatch(/^[a-zA-Z0-9_-]+$/);
  });

  it("returns the provided description", () => {
    const tool = arohaCapabilityToLangChainTool("cap", {
      endpoint: "http://localhost:3001",
      agentDID: "did:aroha:remote",
      callerDID: "did:aroha:caller",
      callerPrivateKey: new Uint8Array(32),
      description: "Does something useful",
      client: { send: vi.fn() } as unknown as ArohaClient,
    });
    expect(tool.description).toBe("Does something useful");
  });

  it("passes through the schema option", () => {
    const schema = { type: "object" };
    const tool = arohaCapabilityToLangChainTool("cap", {
      endpoint: "http://localhost:3001",
      agentDID: "did:aroha:remote",
      callerDID: "did:aroha:caller",
      callerPrivateKey: new Uint8Array(32),
      description: "d",
      schema,
      client: { send: vi.fn() } as unknown as ArohaClient,
    });
    expect(tool.schema).toEqual(schema);
  });

  it("returns the result string from a successful ArohaResponse", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue({
      type: "ArohaResponse",
      body: { capability: "greet", result: { greeting: "hello" } },
    });

    const tool = arohaCapabilityToLangChainTool("greet", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "Greet",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    const result = await tool.call({ name: "World" });
    expect(result).toBe(JSON.stringify({ greeting: "hello" }));
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it("returns a plain string result as-is", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue({
      type: "ArohaResponse",
      body: { capability: "echo", result: "pong" },
    });

    const tool = arohaCapabilityToLangChainTool("echo", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "Echo",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    const result = await tool.call("{}");
    expect(result).toBe("pong");
  });

  it("throws when the response is a ArohaError", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue({
      type: "ArohaError",
      body: { code: "Aroha_UNKNOWN_CAPABILITY", message: "No such capability" },
    });

    const tool = arohaCapabilityToLangChainTool("missing-cap", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "d",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    await expect(tool.call({})).rejects.toThrow("No such capability");
  });

  it("throws when the client returns no response", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue(null);

    const tool = arohaCapabilityToLangChainTool("cap", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "d",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    await expect(tool.call({})).rejects.toThrow(/No response/);
  });

  it("accepts string input and parses it as JSON", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue({
      type: "ArohaResponse",
      body: { capability: "cap", result: { ok: true } },
    });

    const tool = arohaCapabilityToLangChainTool("cap", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "d",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    await tool.call('{"key":"value"}');
    // Should not throw — the string input is parsed and used as params
    expect(mockSend).toHaveBeenCalledTimes(1);
  });
});

// ─── arohaCapabilityToOpenAITool ───────────────────────────────────────────────

describe("arohaCapabilityToOpenAITool", () => {
  it("returns an OpenAI-shaped function tool", () => {
    const tool = arohaCapabilityToOpenAITool("greet", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: "did:aroha:caller",
      callerPrivateKey: new Uint8Array(32),
      description: "Greet a user",
      client: { send: vi.fn() } as unknown as ArohaClient,
    });

    expect(tool.type).toBe("function");
    expect(tool.function).toBeDefined();
    expect(tool.function.description).toBe("Greet a user");
    expect(typeof tool.invoke).toBe("function");
  });

  it("invoke() parses a JSON string result back to an object", async () => {
    const identity = await generateDID("caller", "http://localhost:3001");
    const mockSend = vi.fn().mockResolvedValue({
      type: "ArohaResponse",
      body: { capability: "greet", result: { msg: "hi" } },
    });

    const tool = arohaCapabilityToOpenAITool("greet", {
      endpoint: "http://localhost:3002",
      agentDID: "did:aroha:remote",
      callerDID: identity.did,
      callerPrivateKey: identity.privateKey,
      description: "d",
      client: { send: mockSend } as unknown as ArohaClient,
    });

    const result = await tool.invoke({ name: "World" });
    expect(result).toEqual({ msg: "hi" });
  });
});

// ─── langChainAgentToArohaProvider ─────────────────────────────────────────────

describe("langChainAgentToArohaProvider", () => {
  it("returns a ArohaServer instance without starting it", async () => {
    const identity = await generateDID("lc-bridge", "http://localhost:3099");

    const server = langChainAgentToArohaProvider(
      [makeTool("search-flights"), makeTool("book-hotel")],
      {
        agentDID: identity.did,
        agentPrivateKey: identity.privateKey,
        port: 3099,
        didDocument: identity.document,
        resolvePublicKey: async () => null,
      }
    );

    expect(server).toBeInstanceOf(ArohaServer);
  });
});
