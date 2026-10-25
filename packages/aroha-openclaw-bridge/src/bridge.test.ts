// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import {
  arohaCapabilityToOpenClawSkill,
  openClawSkillToArohaHandler,
  createArohaOpenClawPlugin,
  type OpenClawSkillContext,
  type OpenClawSkill,
} from "./bridge.js";
import { generateKeyPair, generateDid, verifyMessageSignature } from "@aroha-sdk/core";

vi.mock("@aroha-sdk/core", async (importOriginal) => {
  // Real buildEnvelope / signing; only the network client is stubbed.
  const actual = await importOriginal<typeof import("@aroha-sdk/core")>();
  return {
    ...actual,
    ArohaClient: class {
      async send(_endpoint: string, _env: unknown) {
        return {
          type: "ArohaResponse",
          body: { capability: "search-flights", result: { flights: ["AA100", "BA200"] } },
        };
      }
    },
    newCorrelationId: () => "test-cid-001",
  };
});

const mockContext: OpenClawSkillContext = {
  userId: "user123",
  channel: "telegram",
  reply: vi.fn(),
};

describe("arohaCapabilityToOpenClawSkill", () => {
  const skill = arohaCapabilityToOpenClawSkill("search-flights", {
    endpoint: "http://localhost:3000",
    agentDID: "did:aroha:travel-agent",
    callerDID: "did:aroha:openclaw-bridge",
    callerPrivateKey: new Uint8Array(32).fill(1),
    description: "Search available flights",
    parameters: {
      from: { type: "string", description: "Origin airport code" },
      to:   { type: "string", description: "Destination airport code" },
    },
  });

  it("has the correct name and description", () => {
    expect(skill.name).toBe("search-flights");
    expect(skill.description).toBe("Search available flights");
  });

  it("calls the Aroha agent and returns JSON result", async () => {
    const result = await skill.execute({ from: "JFK", to: "LHR" }, mockContext);
    const parsed = JSON.parse(result);
    expect(parsed.flights).toEqual(["AA100", "BA200"]);
  });
});

describe("openClawSkillToArohaHandler", () => {
  const skill: OpenClawSkill = {
    name: "weather",
    description: "Get weather for a city",
    async execute(params) {
      if (params.city === "Nowhere") throw new Error("unknown city");
      return JSON.stringify({ city: params.city, temp: "22°C" });
    },
  };

  const requestFor = (city: string) => ({
    "@context": [],
    id: "urn:uuid:abc",
    type: "ArohaRequest" as const,
    from: "did:aroha:caller",
    to: "did:aroha:openclaw",
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 300_000).toISOString(),
    nonce: "abc",
    correlationId: "cid-abc",
    body: { capability: "weather", params: { city } },
  });

  async function identity() {
    const { privateKey, publicKey } = await generateKeyPair();
    return { agentDID: generateDid(publicKey), agentPrivateKey: privateKey, publicKey };
  }

  it("routes ArohaRequest to the skill and replies with a signed ArohaResponse", async () => {
    const id = await identity();
    const handler = openClawSkillToArohaHandler(skill, id);

    let reply: Record<string, unknown> | null = null;
    await handler(requestFor("London"), (r) => { reply = r as unknown as Record<string, unknown>; }, vi.fn());

    expect(reply).not.toBeNull();
    const r = reply as unknown as Record<string, unknown> & { body: { result: { city: string } }; proof?: { verificationMethod: string } };
    expect(r.type).toBe("ArohaResponse");
    expect(r.from).toBe(id.agentDID);
    expect(r.to).toBe("did:aroha:caller");
    expect(r.correlationId).toBe("cid-abc");
    expect(r.body.result.city).toBe("London");
    expect(r.proof?.verificationMethod).toBe(`${id.agentDID}#key-1`);
    expect(await verifyMessageSignature(r, id.publicKey)).toBe(true);
  });

  it("signs ArohaError replies when the skill fails", async () => {
    const id = await identity();
    const handler = openClawSkillToArohaHandler(skill, id);

    let reply: Record<string, unknown> | null = null;
    await handler(requestFor("Nowhere"), (r) => { reply = r as unknown as Record<string, unknown>; }, vi.fn());

    const r = reply as unknown as Record<string, unknown> & { body: { message: string } };
    expect(r.type).toBe("ArohaError");
    expect(r.body.message).toContain("unknown city");
    expect(await verifyMessageSignature(r, id.publicKey)).toBe(true);
  });

  it("a reply does not verify against another key", async () => {
    const id = await identity();
    const other = await identity();
    const handler = openClawSkillToArohaHandler(skill, id);

    let reply: Record<string, unknown> | null = null;
    await handler(requestFor("London"), (r) => { reply = r as unknown as Record<string, unknown>; }, vi.fn());

    expect(await verifyMessageSignature(reply as unknown as Record<string, unknown>, other.publicKey)).toBe(false);
  });

  it("requires the serving identity", async () => {
    const id = await identity();
    expect(() =>
      openClawSkillToArohaHandler(skill, undefined as unknown as { agentDID: string; agentPrivateKey: Uint8Array })
    ).toThrow(/agentDID/);
    expect(() =>
      openClawSkillToArohaHandler(skill, { agentDID: "", agentPrivateKey: id.agentPrivateKey })
    ).toThrow(/agentDID/);
    expect(() =>
      openClawSkillToArohaHandler(skill, { agentDID: id.agentDID } as unknown as { agentDID: string; agentPrivateKey: Uint8Array })
    ).toThrow(/agentPrivateKey/);
    expect(() =>
      openClawSkillToArohaHandler(skill, { agentDID: id.agentDID, agentPrivateKey: new Uint8Array(16) })
    ).toThrow(/agentPrivateKey/);
  });
});

describe("createArohaOpenClawPlugin", () => {
  it("bundles multiple capabilities into a single plugin", () => {
    const sharedOpts = {
      endpoint: "http://localhost:3001",
      agentDID: "did:aroha:multi-agent",
      callerDID: "did:aroha:openclaw-plugin",
      callerPrivateKey: new Uint8Array(32).fill(1),
      description: "A capability",
    };

    const plugin = createArohaOpenClawPlugin("aroha-suite", [
      { capabilityId: "search-flights", ...sharedOpts },
      { capabilityId: "book-hotel",     ...sharedOpts },
    ]);

    expect(plugin.name).toBe("aroha-suite");
    expect(plugin.skills).toHaveLength(2);
    expect(plugin.skills[0].name).toBe("search-flights");
    expect(plugin.skills[1].name).toBe("book-hotel");
  });
});
