// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** M8/P4: createArohaLangChainTool signs with a real 32-byte seed and never addresses did:aroha:unknown. */

import { describe, it, expect, vi, afterEach } from "vitest";
import { ArohaClient, validateEnvelope, NonceRegistry, fromMultibase, isContentAddressedDid, type ArohaEnvelope } from "@aroha-sdk/core";
import { createArohaLangChainTool } from "./bridge.js";

afterEach(() => { vi.unstubAllGlobals(); });

function capturingClient(sent: ArohaEnvelope[]): ArohaClient {
  return {
    send: async (_endpoint: string, env: ArohaEnvelope) => {
      sent.push(env);
      return { type: "ArohaResponse", body: { capability: "x", result: { ok: true } } } as unknown as ArohaEnvelope;
    },
  } as unknown as ArohaClient;
}

describe("createArohaLangChainTool", () => {
  it("throws when the agent DID cannot be determined (no did:aroha:unknown fallback)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 404 })));
    await expect(createArohaLangChainTool("http://127.0.0.1:9", "x", "d")).rejects.toThrow(/agentDID/);
  });

  it("signs with a key a verifier derives from the caller DID", async () => {
    const sent: ArohaEnvelope[] = [];
    const tool = await createArohaLangChainTool("http://127.0.0.1:9", "x", "d", {
      agentDID: "did:aroha:vendor",
      client: capturingClient(sent),
    });
    await tool.call({ q: 1 });
    const env = sent[0];
    expect(env.to).toBe("did:aroha:vendor");
    expect(isContentAddressedDid(env.from)).toBe(true);
    const reg = new NonceRegistry();
    const r = await validateEnvelope(env, fromMultibase(env.from.slice("did:aroha:".length)), "did:aroha:vendor", reg);
    reg.destroy();
    expect(r.valid).toBe(true);
  });

  it("refuses http:// to a non-loopback endpoint", async () => {
    await expect(createArohaLangChainTool("http://agent.example.com", "x", "d", { agentDID: "did:aroha:v" })).rejects.toThrow(/http:\/\//);
  });
});
