// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import {
  arohaCapabilityToComposioAction,
  registerArohaCapabilities,
  buildComposioActionHandler,
} from "./bridge.js";

vi.mock("@aroha-sdk/core", () => ({
  ArohaClient: class {
    async send() {
      return {
        type: "ArohaResponse",
        body: { capability: "search-flights", result: { flights: ["AA100", "UA200"] } },
      };
    }
  },
  buildEnvelope: async (_type: string, from: string, to: string, body: unknown, cid: string) => ({
    "@context": [],
    id: `urn:uuid:${cid}`,
    type: _type,
    from,
    to,
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 300_000).toISOString(),
    nonce: cid,
    correlationId: cid,
    body,
  }),
  newCorrelationId: () => "composio-cid-001",
}));

const BASE_OPTS = {
  endpoint: "http://localhost:3000",
  agentDID: "did:aroha:travel-agent",
  capabilityId: "search-flights",
  description: "Search for available flights",
  callerDID: "did:aroha:trustclaw-bridge",
  callerPrivateKey: new Uint8Array(32).fill(1),
  parameters: {
    from: { type: "string" as const, description: "Origin IATA code" },
    to:   { type: "string" as const, description: "Destination IATA code" },
  },
  required: ["from", "to"],
};

describe("arohaCapabilityToComposioAction", () => {
  it("generates a stable action name from DID + capability", () => {
    const action = arohaCapabilityToComposioAction(BASE_OPTS);
    expect(action.name).toBe("aroha_travel_agent_search_flights");
  });

  it("maps parameters to Composio parameter schema", () => {
    const action = arohaCapabilityToComposioAction(BASE_OPTS);
    expect(action.parameters.type).toBe("object");
    expect(action.parameters.properties.from.type).toBe("string");
    expect(action.parameters.required).toEqual(["from", "to"]);
  });

  it("execute() returns successful result from Aroha agent", async () => {
    const action = arohaCapabilityToComposioAction(BASE_OPTS);
    const result = await action.execute({ from: "JFK", to: "LHR" });
    expect(result.successful).toBe(true);
    expect((result.data as { flights: string[] }).flights).toEqual(["AA100", "UA200"]);
  });

  it("execute() returns error on ArohaError response", async () => {
    const errorClient = { send: async () => ({ type: "ArohaError", body: { message: "Agent unavailable" } }) };
    const action = arohaCapabilityToComposioAction({ ...BASE_OPTS, client: errorClient as never });
    const result = await action.execute({ from: "JFK", to: "LHR" });
    expect(result.successful).toBe(false);
    expect(result.error).toBe("Agent unavailable");
  });
});

describe("registerArohaCapabilities", () => {
  it("calls addCustomAction for each capability", async () => {
    const mockComposio = { addCustomAction: vi.fn().mockResolvedValue(undefined) };
    const actions = await registerArohaCapabilities(mockComposio, [BASE_OPTS]);
    expect(mockComposio.addCustomAction).toHaveBeenCalledTimes(1);
    expect(actions).toHaveLength(1);
  });

  it("falls back to createAction if addCustomAction not present", async () => {
    const mockComposio = { createAction: vi.fn().mockResolvedValue(undefined) };
    await registerArohaCapabilities(mockComposio, [BASE_OPTS]);
    expect(mockComposio.createAction).toHaveBeenCalledTimes(1);
  });

  it("throws if neither registration method is available", async () => {
    await expect(registerArohaCapabilities({}, [BASE_OPTS])).rejects.toThrow("addCustomAction");
  });
});

describe("buildComposioActionHandler", () => {
  it("returns a map keyed by action name", () => {
    const handler = buildComposioActionHandler([BASE_OPTS]);
    expect(handler.has("aroha_travel_agent_search_flights")).toBe(true);
  });

  it("executes the action via the map", async () => {
    const handler = buildComposioActionHandler([BASE_OPTS]);
    const execute = handler.get("aroha_travel_agent_search_flights")!;
    const result = await execute({ from: "JFK", to: "LHR" });
    expect(result.successful).toBe(true);
  });
});
