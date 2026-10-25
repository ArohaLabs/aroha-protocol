// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * - wrapMcp refuses to advertise a price it would never charge (priced tool,
 *   requireMandate off) unless allowUnchargedPricing is set.
 * - arohaAgentToMcpTools (outbound) can carry a mandate on each request and
 *   verifies the provider's response envelope when given a key resolver.
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, type ArohaClient, type ArohaEnvelope, type PublicKeyResolver } from "@aroha-sdk/core";
import type { DiscoveredAgent } from "@aroha-sdk/registry";
import { wrapMcp, arohaAgentToMcpTools, type McpToolDefinition } from "./index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const tool: McpToolDefinition = { name: "aroha_quote", description: "q", inputSchema: { type: "object", properties: {} } };
const handlers = { aroha_quote: async () => ({ content: [{ type: "text" as const, text: "quoted" }] }) };
const noKeys: PublicKeyResolver = async () => null;
let nextPort = 37981;

describe("wrapMcp: a price is never advertised without a way to charge it", () => {
  it("refuses to start with a priced tool and requireMandate off", async () => {
    const a = await wrapMcp([tool], { name: "p", port: nextPort++, resolvePublicKey: noKeys, handlers, price: 0.5 });
    await expect(a.start()).rejects.toThrow(/aroha_quote have a price but requireMandate is off/);
    const b = await wrapMcp([tool], { name: "p", port: nextPort++, resolvePublicKey: noKeys, handlers, capabilityPrices: { quote: 2 } });
    await expect(b.start()).rejects.toThrow(/allowUnchargedPricing/);
  });

  it("starts with allowUnchargedPricing: true, and with free tools as before", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const a = await wrapMcp([tool], {
      name: "p", port: nextPort++, resolvePublicKey: noKeys, handlers, price: 0.5, allowUnchargedPricing: true,
    });
    (await a.start()).stop();
    const b = await wrapMcp([tool], { name: "p", port: nextPort++, resolvePublicKey: noKeys, handlers });
    (await b.start()).stop();
  });
});

// ── Outbound ───────────────────────────────────────────────────────────────────

const ORCH = "did:aroha:orchestrator";
const PROVIDER = "did:aroha:provider";

let provPriv: Uint8Array, provPub: Uint8Array, otherPriv: Uint8Array, orchPriv: Uint8Array;
beforeAll(async () => {
  provPriv = ed.utils.randomPrivateKey();
  provPub = await ed.getPublicKeyAsync(provPriv);
  otherPriv = ed.utils.randomPrivateKey();
  orchPriv = ed.utils.randomPrivateKey();
});

function agent(): DiscoveredAgent {
  return {
    manifest: {
      did: PROVIDER,
      capabilities: [{
        id: "quote", version: "1.0.0", description: "q", inputSchema: {}, outputSchema: {}, async: false,
        maxResponseMs: 1000, requiredTrustLevel: 1, pricing: { model: "free" }, sagaRole: "none",
      }],
    },
    endpoint: "https://provider.example/aroha",
  } as unknown as DiscoveredAgent;
}

const resolver: PublicKeyResolver = async (did) => (did === PROVIDER ? provPub : null);

/** A client whose send() answers with a response built by `reply` from the request. */
function clientReplying(reply: (req: ArohaEnvelope) => Promise<ArohaEnvelope>) {
  const sent: ArohaEnvelope[] = [];
  const client = {
    send: vi.fn(async (_endpoint: string, env: ArohaEnvelope) => { sent.push(env); return reply(env); }),
  } as unknown as ArohaClient;
  return { client, sent };
}

const signedReply = (key: Uint8Array, from = PROVIDER) => (req: ArohaEnvelope) =>
  buildEnvelope("ArohaResponse", from, ORCH, { capability: "quote", result: { price: 3 } }, req.correlationId, key);

describe("arohaAgentToMcpTools: outbound mandate and response verification", () => {
  it("attaches a mandate token to each request (static or per call)", async () => {
    const { client, sent } = clientReplying(signedReply(provPriv));
    const { handleToolCall } = arohaAgentToMcpTools(agent(), ORCH, orchPriv, client, "corr-1", {
      mandateToken: (name) => (name === "aroha_quote" ? "tok-for-quote" : undefined),
      resolvePublicKey: resolver,
    });
    const r = await handleToolCall("aroha_quote", {});
    expect(r.isError).toBeUndefined();
    expect((sent[0].body as { credentialToken?: string }).credentialToken).toBe("tok-for-quote");

    const s = clientReplying(signedReply(provPriv));
    const t = arohaAgentToMcpTools(agent(), ORCH, orchPriv, s.client, "corr-2", { mandateToken: "static-tok" });
    await t.handleToolCall("aroha_quote", {});
    expect((s.sent[0].body as { credentialToken?: string }).credentialToken).toBe("static-tok");
  });

  it("accepts a response signed by the provider and rejects one signed by another key", async () => {
    const good = clientReplying(signedReply(provPriv));
    const ok = await arohaAgentToMcpTools(agent(), ORCH, orchPriv, good.client, "corr-3", { resolvePublicKey: resolver })
      .handleToolCall("aroha_quote", {});
    expect(ok.isError).toBeUndefined();
    expect(ok.content[0].text).toContain("3");

    const forged = clientReplying(signedReply(otherPriv));
    const bad = await arohaAgentToMcpTools(agent(), ORCH, orchPriv, forged.client, "corr-4", { resolvePublicKey: resolver })
      .handleToolCall("aroha_quote", {});
    expect(bad.isError).toBe(true);
    expect(bad.content[0].text).toMatch(/Response rejected/);
  });

  it("rejects an unsigned response, one from a different DID, and one for another correlationId", async () => {
    const unsigned = clientReplying(async (req) => ({
      ...(await signedReply(provPriv)(req)), proof: undefined,
    } as unknown as ArohaEnvelope));
    expect((await arohaAgentToMcpTools(agent(), ORCH, orchPriv, unsigned.client, "c5", { resolvePublicKey: resolver })
      .handleToolCall("aroha_quote", {})).isError).toBe(true);

    const impostor = clientReplying(signedReply(provPriv, "did:aroha:impostor"));
    const r = await arohaAgentToMcpTools(agent(), ORCH, orchPriv, impostor.client, "c6", { resolvePublicKey: resolver })
      .handleToolCall("aroha_quote", {});
    expect(r.content[0].text).toMatch(/not did:aroha:provider/);

    const elsewhere = clientReplying((req) =>
      buildEnvelope("ArohaResponse", PROVIDER, ORCH, { capability: "quote", result: {} }, "other-corr", provPriv));
    const e = await arohaAgentToMcpTools(agent(), ORCH, orchPriv, elsewhere.client, "c7", { resolvePublicKey: resolver })
      .handleToolCall("aroha_quote", {});
    expect(e.content[0].text).toMatch(/correlationId/);
  });

  it("rejects a replayed response envelope", async () => {
    let first: ArohaEnvelope | undefined;
    const replay = clientReplying(async (req) => (first ??= await signedReply(provPriv)(req)));
    const tools = arohaAgentToMcpTools(agent(), ORCH, orchPriv, replay.client, "c8", { resolvePublicKey: resolver });
    expect((await tools.handleToolCall("aroha_quote", {})).isError).toBeUndefined();
    expect((await tools.handleToolCall("aroha_quote", {})).isError).toBe(true);
  });

  it("verifyResponse without a resolver is a construction error; no resolver keeps the old behaviour", async () => {
    const { client } = clientReplying(signedReply(otherPriv));
    expect(() => arohaAgentToMcpTools(agent(), ORCH, orchPriv, client, "c9", { verifyResponse: true }))
      .toThrow(/needs resolvePublicKey/);
    const legacy = await arohaAgentToMcpTools(agent(), ORCH, orchPriv, client, "c10").handleToolCall("aroha_quote", {});
    expect(legacy.isError).toBeUndefined();
  });
});
