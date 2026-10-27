// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { createServer } from "node:net";
import { describe, it, expect, vi, beforeAll } from "vitest";
import { mcpToolsToArohaCapabilities, arohaAgentToMcpTools, wrapMcp, type McpToolDefinition } from "./index.js";
import type { DiscoveredAgent } from "@aroha-sdk/registry";
import type { ArohaEnvelope, ArohaClient, DIDDocument, PublicKeyResolver } from "@aroha-sdk/core";
import { buildEnvelope, extractEndpoint, extractPublicKey } from "@aroha-sdk/core";
import { issueIntentMandate, attenuateToCart } from "@aroha-sdk/credentials";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function makeMcpTool(name: string, description = "A test tool"): McpToolDefinition {
  return {
    name,
    description,
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  };
}

function makeDiscoveredAgent(): DiscoveredAgent {
  return {
    record: {
      didHash: "0xtest-provider",
      ownerAddress: "0xOwner",
      manifestCID: "Qm123",
      publicKeyB64: Buffer.alloc(32).toString("base64url"),
      stakedWei: 1_000_000_000_000_000_000n,
      reputationScore: 8000,
      active: true,
      registeredAt: Date.now() - 86400_000,
      lastUpdatedAt: Date.now(),
    },
    manifest: {
      aroha: "1.0",
      did: "did:aroha:test-provider",
      name: "Test Provider",
      version: "1.0.0",
      endpoint: "https://provider.example.com/aroha",
      capabilities: [
        {
          id: "search-flights",
          version: "1.0.0",
          description: "Search for flights",
          inputSchema: { type: "object", properties: { origin: { type: "string" } } },
          outputSchema: { type: "object", properties: { flights: { type: "array" } } },
          async: false,
          maxResponseMs: 5000,
          requiredTrustLevel: 1,
          pricing: { model: "free" },
          sagaRole: "none",
        },
        {
          id: "book-flight",
          version: "1.0.0",
          description: "Book a flight",
          inputSchema: { type: "object", properties: { flightId: { type: "string" } } },
          outputSchema: { type: "object", properties: { booking: { type: "string" } } },
          async: false,
          maxResponseMs: 10000,
          requiredTrustLevel: 2,
          pricing: { model: "per-transaction", fee: "10.00" },
          sagaRole: "participant",
        },
      ],
      protocols: ["aroha/1.0"],
      createdAt: new Date().toISOString(),
      signature: "dummy-sig",
    },
    endpoint: "https://provider.example.com/aroha",
    publicKey: new Uint8Array(32),
  };
}

describe("mcpToolsToArohaCapabilities", () => {
  it("converts MCP tools to Aroha capability definitions", () => {
    const tools = [makeMcpTool("aroha_search_flights"), makeMcpTool("aroha_book_hotel")];
    const caps = mcpToolsToArohaCapabilities(tools);

    expect(caps).toHaveLength(2);
    expect(caps[0].id).toBe("search-flights");
    expect(caps[1].id).toBe("book-hotel");
  });

  it("sets correct default fields", () => {
    const caps = mcpToolsToArohaCapabilities([makeMcpTool("aroha_do_thing", "Does the thing")]);
    const cap = caps[0];
    expect(cap.version).toBe("1.0.0");
    expect(cap.async).toBe(false);
    expect(cap.requiredTrustLevel).toBe(1);
    expect(cap.pricing.model).toBe("free");
    expect(cap.sagaRole).toBe("none");
    expect(cap.description).toBe("Does the thing");
  });

  it("preserves the inputSchema", () => {
    const tool = makeMcpTool("aroha_test");
    const caps = mcpToolsToArohaCapabilities([tool]);
    expect(caps[0].inputSchema).toEqual(tool.inputSchema);
  });
});

describe("arohaAgentToMcpTools", () => {
  it("produces one MCP tool per capability", async () => {
    const priv = ed.utils.randomPrivateKey();
    const agent = makeDiscoveredAgent();
    const mockClient = { send: vi.fn(), stream: vi.fn(), fetchDIDDocument: vi.fn() } as unknown as ArohaClient;

    const { tools } = arohaAgentToMcpTools(
      agent,
      "did:aroha:orchestrator",
      priv,
      mockClient,
      "saga-test"
    );

    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe("aroha_search_flights");
    expect(tools[1].name).toBe("aroha_book_flight");
  });

  it("tool definitions include _aroha metadata", async () => {
    const priv = ed.utils.randomPrivateKey();
    const agent = makeDiscoveredAgent();
    const mockClient = { send: vi.fn(), stream: vi.fn(), fetchDIDDocument: vi.fn() } as unknown as ArohaClient;

    const { tools } = arohaAgentToMcpTools(
      agent,
      "did:aroha:orchestrator",
      priv,
      mockClient,
      "saga-test"
    );

    expect(tools[0]._aroha?.agentDID).toBe("did:aroha:test-provider");
    expect(tools[0]._aroha?.capabilityId).toBe("search-flights");
  });

  it("handleToolCall returns error for unknown tool", async () => {
    const priv = ed.utils.randomPrivateKey();
    const agent = makeDiscoveredAgent();
    const mockClient = { send: vi.fn(), stream: vi.fn(), fetchDIDDocument: vi.fn() } as unknown as ArohaClient;

    const { handleToolCall } = arohaAgentToMcpTools(
      agent,
      "did:aroha:orchestrator",
      priv,
      mockClient,
      "saga-test"
    );

    const result = await handleToolCall("aroha_nonexistent", {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Unknown tool/);
  });

  it("handleToolCall calls client.send and returns result", async () => {
    const priv = ed.utils.randomPrivateKey();
    const agent = makeDiscoveredAgent();

    const mockResponse: Partial<ArohaEnvelope> = {
      type: "ArohaResponse",
      body: { capability: "search-flights", result: { flights: ["AA100"] } } as ArohaEnvelope["body"],
    };

    const mockClient = {
      send: vi.fn().mockResolvedValue(mockResponse),
      stream: vi.fn(),
      fetchDIDDocument: vi.fn(),
    } as unknown as ArohaClient;

    const { handleToolCall } = arohaAgentToMcpTools(
      agent,
      "did:aroha:orchestrator",
      priv,
      mockClient,
      "saga-test"
    );

    const result = await handleToolCall("aroha_search_flights", { origin: "JFK" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("AA100");
    expect(mockClient.send).toHaveBeenCalled();
  });
});

// ─── wrapMcp() ─────────────────────────────────────────────────────────────────
//
// Three bugs, found and fixed together because they lived in the same ~150
// lines of the request handler:
//
//   1. The handler never called the tool's actual implementation — it
//      returned a placeholder `{ _note: "Handled by MCP tool: X" }` that
//      echoed the caller's params back, regardless of what the tool was
//      supposed to do.
//   2. The auto-generated identity used a PKCS8-DER key export where the
//      signer needed a raw 32-byte seed — every signed reply, success or
//      error, threw before bug 1's fix could even be tested.
//   3. No signature verification, replay protection, or expiry check ran on
//      inbound requests at all, despite the doc comment claiming otherwise;
//      no mandate enforcement existed despite the package's README claiming
//      it as the whole reason the package exists.
//
// Every test below posts a REAL request to the REAL running server, signed
// with a REAL keypair, and asserts on ACTUAL behaviour — not on a mock
// standing in for the transport.

/** A port the OS reports free right now (wrapMcp takes a fixed port and does not report the bound one). */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
  });
}

const CALLER_DID = "did:aroha:test-caller";
const GRANTOR_DID = "did:aroha:test-grantor";

let callerPriv: Uint8Array;
let callerPub: Uint8Array;
let grantorPriv: Uint8Array;
let grantorPub: Uint8Array;

beforeAll(async () => {
  callerPriv = ed.utils.randomPrivateKey();
  callerPub = await ed.getPublicKeyAsync(callerPriv);
  grantorPriv = ed.utils.randomPrivateKey();
  grantorPub = await ed.getPublicKeyAsync(grantorPriv);
});

/** Resolves exactly the two identities these tests know about — an unknown DID resolves to null, same as a real registry miss. */
function testResolver(): PublicKeyResolver {
  return async (did: string) => {
    if (did === CALLER_DID) return callerPub;
    if (did === GRANTOR_DID) return grantorPub;
    return null;
  };
}

async function postSigned(
  port: number,
  capability: string,
  params: Record<string, unknown>,
  opts: { from?: string; signingKey?: Uint8Array; credentialToken?: string } = {}
) {
  const envelope = await buildEnvelope(
    "ArohaRequest",
    opts.from ?? CALLER_DID,
    "did:aroha:test-agent",
    { capability, params, ...(opts.credentialToken ? { credentialToken: opts.credentialToken } : {}) },
    `test-correlation-${Math.random()}`,
    opts.signingKey ?? callerPriv
  );
  const res = await fetch(`http://localhost:${port}/aroha/v1`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope),
  });
  const body = await res.json() as ArohaEnvelope;
  return { status: res.status, body };
}

describe("wrapMcp", () => {
  it("start() throws if a tool has no matching handler", async () => {
    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "no-handlers-test",
      port: await freePort(),
      did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
      handlers: {}, // deliberately empty — "search" has no entry
    });
    await expect(agent.start()).rejects.toThrow(/no handler/i);
  });

  it("actually invokes the real handler and returns ITS result, not a placeholder", async () => {
    const port = await freePort();
    const handler = vi.fn(async (args: Record<string, unknown>) => ({
      content: [{ type: "text" as const, text: `real result for ${args.query}` }],
    }));

    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "real-handler-test",
      port,
      did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
      handlers: { aroha_search: handler },
    });
    const { stop } = await agent.start();

    try {
      const { status, body } = await postSigned(port, "search", { query: "flights" });

      expect(handler).toHaveBeenCalledWith({ query: "flights" });
      expect(status, JSON.stringify(body)).toBe(200);
      expect(body.type).toBe("ArohaResponse");

      const result = (body.body as unknown as { result: { content: Array<{ text: string }> } }).result;
      expect(result.content[0].text).toBe("real result for flights");

      // The specific regression this guards: the old placeholder shape.
      const serialized = JSON.stringify(body);
      expect(serialized).not.toContain("_note");
      expect(serialized).not.toContain("Handled by MCP tool");
    } finally {
      stop();
    }
  });

  it("routes multiple tools to their own distinct handlers, not to each other", async () => {
    const port = await freePort();
    const searchHandler = vi.fn(async () => ({ content: [{ type: "text" as const, text: "search-output" }] }));
    const bookHandler = vi.fn(async () => ({ content: [{ type: "text" as const, text: "book-output" }] }));

    const agent = await wrapMcp(
      [makeMcpTool("aroha_search"), makeMcpTool("aroha_book")],
      { name: "multi-tool-test", port, did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(), handlers: { aroha_search: searchHandler, aroha_book: bookHandler } }
    );
    const { stop } = await agent.start();

    try {
      const searchRes = await postSigned(port, "search", {});
      const bookRes = await postSigned(port, "book", {});

      expect(searchHandler).toHaveBeenCalledTimes(1);
      expect(bookHandler).toHaveBeenCalledTimes(1);

      const searchResult = (searchRes.body.body as unknown as { result: { content: Array<{ text: string }> } }).result;
      const bookResult = (bookRes.body.body as unknown as { result: { content: Array<{ text: string }> } }).result;
      expect(searchResult.content[0].text).toBe("search-output");
      expect(bookResult.content[0].text).toBe("book-output");
    } finally {
      stop();
    }
  });

  it("a handler reporting isError becomes an ArohaError response, not a 200", async () => {
    const port = await freePort();
    const failingHandler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: "tool-specific failure detail" }],
      isError: true,
    }));

    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "error-handler-test",
      port,
      did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
      handlers: { aroha_search: failingHandler },
    });
    const { stop } = await agent.start();

    try {
      const { status, body } = await postSigned(port, "search", {});
      expect(status).toBe(502);
      expect(body.type).toBe("ArohaError");
      expect((body.body as { message: string }).message).toContain("tool-specific failure detail");
    } finally {
      stop();
    }
  });

  it("still 404s for a capability with no matching tool at all (pre-existing behaviour, unchanged)", async () => {
    const port = await freePort();
    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "unknown-capability-test",
      port,
      did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
      handlers: { aroha_search: async () => ({ content: [{ type: "text", text: "x" }] }) },
    });
    const { stop } = await agent.start();

    try {
      const { status } = await postSigned(port, "nonexistent-capability", {});
      expect(status).toBe(404);
    } finally {
      stop();
    }
  });

  // ── Signature / replay / expiry — previously nonexistent ──────────────────

  describe("request authentication", () => {
    async function startAgent(port: number) {
      return wrapMcp([makeMcpTool("aroha_search")], {
        name: `auth-test-${port}`,
        port,
        did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
        handlers: { aroha_search: async () => ({ content: [{ type: "text", text: "ok" }] }) },
      }).then((a) => a.start().then((h) => ({ ...h, port })));
    }

    it("rejects a request from a sender resolvePublicKey doesn't know", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const { status } = await postSigned(port, "search", {}, { from: "did:aroha:nobody-registered" });
        expect(status).toBe(401);
      } finally { stop(); }
    });

    it("rejects a request signed by the wrong key while claiming a known DID", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        // Signs with grantorPriv but claims to be CALLER_DID — a forged sender.
        const { status, body } = await postSigned(port, "search", {}, { signingKey: grantorPriv });
        expect(status).toBe(401);
        expect(JSON.stringify(body)).not.toContain('"ok"'); // never reached the handler
      } finally { stop(); }
    });

    it("rejects a replayed request (same nonce twice)", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const envelope = await buildEnvelope(
          "ArohaRequest", CALLER_DID, "did:aroha:test-agent",
          { capability: "search", params: {} }, "replay-test", callerPriv
        );
        const send = () => fetch(`http://localhost:${port}/aroha/v1`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(envelope),
        });
        const first = await send();
        const second = await send();
        expect(first.status).toBe(200);
        expect(second.status).toBe(401);
      } finally { stop(); }
    });

    it("accepts a validly signed, unexpired, fresh-nonce request end to end", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const { status } = await postSigned(port, "search", {});
        expect(status).toBe(200);
      } finally { stop(); }
    });
  });

  // ── Mandate enforcement — previously nonexistent despite being the ────────
  // ── package's entire stated purpose ────────────────────────────────────────

  describe("requireMandate", () => {
    async function startAgent(port: number) {
      const agent = await wrapMcp([makeMcpTool("aroha_search")], {
        name: `mandate-test-${port}`,
        port,
        did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
        requireMandate: true,
        expectedRoot: GRANTOR_DID,
        handlers: { aroha_search: async () => ({ content: [{ type: "text", text: "ok" }] }) },
      });
      return agent.start();
    }

    it("rejects a request with no mandate at all", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const { status, body } = await postSigned(port, "search", {});
        expect(status).toBe(403);
        // The 403 mandate-rejection path returns a raw { error } object, not
        // an ArohaEnvelope — there's no tool result to wrap a reply around.
        expect((body as unknown as { error?: string }).error).toMatch(/mandate/i);
      } finally { stop(); }
    });

    it("accepts a valid mandate granting the caller", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const { token } = await issueIntentMandate(
          GRANTOR_DID, CALLER_DID, { spendLimitUsd: 500 }, grantorPriv
        );
        const { status } = await postSigned(port, "search", {}, { credentialToken: token });
        expect(status).toBe(200);
      } finally { stop(); }
    });

    it("accepts a delegated chain whose earlier grantor resolves only through the registry", async () => {
      // GRANTOR_DID is a namespaced DID, so the key of the chain's ROOT link
      // can only come from resolvePublicKey — this proves the bridge hands
      // its resolver to the chain walk, not just to the leaf signature.
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const root = await issueIntentMandate(
          GRANTOR_DID, CALLER_DID, { spendLimitUsd: 500 }, grantorPriv
        );
        const child = await attenuateToCart(
          root, CALLER_DID, { spendLimitUsd: 200 }, callerPriv
        );
        const { status } = await postSigned(port, "search", {}, { credentialToken: child.token });
        expect(status).toBe(200);
      } finally { stop(); }
    });

    it("rejects a mandate granted to a DIFFERENT agent than the caller", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const { token } = await issueIntentMandate(
          GRANTOR_DID, "did:aroha:someone-else", { spendLimitUsd: 500 }, grantorPriv
        );
        const { status } = await postSigned(port, "search", {}, { credentialToken: token });
        expect(status).toBe(403);
      } finally { stop(); }
    });

    it("rejects a mandate whose grantor doesn't resolve to a known key", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        const unknownGrantorKey = ed.utils.randomPrivateKey();
        const { token } = await issueIntentMandate(
          "did:aroha:unregistered-grantor", CALLER_DID, { spendLimitUsd: 500 }, unknownGrantorKey
        );
        const { status } = await postSigned(port, "search", {}, { credentialToken: token });
        expect(status).toBe(403);
      } finally { stop(); }
    });

    it("rejects a mandate signed by a key other than its claimed grantor", async () => {
      const port = await freePort();
      const { stop } = await startAgent(port);
      try {
        // Claims GRANTOR_DID (which resolves to grantorPub) but is actually
        // signed with the caller's key — a forged mandate.
        const { token } = await issueIntentMandate(
          GRANTOR_DID, CALLER_DID, { spendLimitUsd: 500 }, callerPriv
        );
        const { status } = await postSigned(port, "search", {}, { credentialToken: token });
        expect(status).toBe(403);
      } finally { stop(); }
    });

    it("does not require a mandate when requireMandate is unset (default false)", async () => {
      const port = await freePort();
      const agent = await wrapMcp([makeMcpTool("aroha_search")], {
        name: `no-mandate-required-${port}`,
        port,
        did: "did:aroha:test-agent",
        resolvePublicKey: testResolver(),
        handlers: { aroha_search: async () => ({ content: [{ type: "text", text: "ok" }] }) },
      });
      const { stop } = await agent.start();
      try {
        const { status } = await postSigned(port, "search", {});
        expect(status).toBe(200);
      } finally { stop(); }
    });
  });
});

describe("wrapMcp request hardening (M9)", () => {
  it("refuses a body over maxBodyBytes with 413 before verification", async () => {
    const port = await freePort();
    const resolver = vi.fn(testResolver());
    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "cap-test", port, did: "did:aroha:test-agent", maxBodyBytes: 512,
      resolvePublicKey: resolver,
      handlers: { aroha_search: async () => ({ content: [{ type: "text" as const, text: "x" }] }) },
    });
    const { stop } = await agent.start();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pad: "x".repeat(4096) }),
      }).catch(() => null);
      // The server answers 413 and closes; some stacks surface the reset instead.
      if (res) expect(res.status).toBe(413);
      expect(resolver).not.toHaveBeenCalled();
    } finally { stop(); }
  });

  it("passes proof.verificationMethod to resolvePublicKey", async () => {
    const port = await freePort();
    const calls: Array<[string, string | undefined]> = [];
    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "vm-test", port, did: "did:aroha:test-agent",
      resolvePublicKey: async (did, vm) => { calls.push([did, vm]); return did === CALLER_DID ? callerPub : null; },
      handlers: { aroha_search: async () => ({ content: [{ type: "text" as const, text: "ok" }] }) },
    });
    const { stop } = await agent.start();
    try {
      const { status } = await postSigned(port, "search", { query: "q" });
      expect(status).toBe(200);
      expect(calls[0][0]).toBe(CALLER_DID);
      expect(calls[0][1]).toMatch(new RegExp(`^${CALLER_DID}#`));
    } finally { stop(); }
  });
});

describe("wrapMcp DID document", () => {
  // The served document used to carry no verificationMethod, so core's
  // resolver (extractPublicKey) could not get the key the bridge signs with.
  it("publishes the bridge's own signing key in the form core's extractPublicKey reads", async () => {
    const port = await freePort();
    const bridgePriv = ed.utils.randomPrivateKey();
    const bridgePub = await ed.getPublicKeyAsync(bridgePriv);
    const agent = await wrapMcp([makeMcpTool("aroha_search")], {
      name: "doc-test", port, did: "did:aroha:test-agent", privateKey: bridgePriv,
      resolvePublicKey: testResolver(),
      handlers: { aroha_search: async () => ({ content: [{ type: "text" as const, text: "ok" }] }) },
    });
    const { stop } = await agent.start();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/.well-known/aroha-agent.json`);
      expect(res.status).toBe(200);
      const doc = await res.json() as DIDDocument & { did: string; endpoint: string; capabilities: unknown[] };

      expect(doc.id).toBe("did:aroha:test-agent");
      const key = extractPublicKey(doc);
      expect(key.length).toBe(32);
      expect(key).toEqual(bridgePub);
      expect(doc.authentication).toEqual([doc.verificationMethod[0].id]);
      expect(doc.assertionMethod).toEqual([doc.verificationMethod[0].id]);

      // The key id the bridge stamps on its signed replies resolves to the same key.
      const { status, body } = await postSigned(port, "search", { query: "q" });
      expect(status).toBe(200);
      expect(extractPublicKey(doc, body.proof?.verificationMethod)).toEqual(bridgePub);

      // Existing fields are kept.
      expect(doc.did).toBe("did:aroha:test-agent");
      expect(doc.endpoint).toBe(`http://localhost:${port}`);
      expect(doc.capabilities).toHaveLength(1);
      expect(doc.service).toContainEqual(
        { id: "did:aroha:test-agent#aroha", type: "ArohaAgent", serviceEndpoint: `http://localhost:${port}` }
      );

      // Core's extractEndpoint finds the ArohaEndpoint service entry.
      expect(extractEndpoint(doc)).toBe(`http://localhost:${port}`);
      expect(new Set(doc.service.map((s) => s.id)).size).toBe(doc.service.length);
    } finally { stop(); }
  });
});
