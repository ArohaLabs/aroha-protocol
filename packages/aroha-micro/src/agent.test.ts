// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from "vitest";
import { MicroAgent, createAgent } from "./agent.js";

// ─── Mocks ────────────────────────────────────────────────────────────────────

let capturedOnMessage: ((envelope: unknown, respond: (r: unknown) => void) => Promise<void>) | null = null;
let mockServerStart = vi.fn().mockResolvedValue(undefined);
let mockServerStop  = vi.fn().mockResolvedValue(undefined);

vi.mock("@aroha-sdk/core", () => ({
  generateDID: vi.fn().mockResolvedValue({
    did:        "did:aroha:test-agent",
    privateKey: new Uint8Array(32),
    publicKey:  new Uint8Array(32),
    document:   {},
  }),
  buildEnvelope: vi.fn().mockImplementation(async (type, from, to, body, correlationId) => ({
    type, from, to, body, correlationId,
    id: "env-" + Math.random(),
    created: new Date().toISOString(),
    expires: new Date().toISOString(),
    nonce: "n",
    proof: {},
  })),
  // A `function`, not an arrow: the code under test calls `new ArohaServer()`,
  // and Vitest 4+ constructs mocks with the implementation itself.
  ArohaServer: vi.fn().mockImplementation(function ({ onMessage }) {
    capturedOnMessage = onMessage;
    return { start: mockServerStart, stop: mockServerStop };
  }),
  ArohaErrorCode: {
    UnknownCapability: "UNKNOWN_CAPABILITY",
    InternalError:     "INTERNAL_ERROR",
    ReservationFailed: "RESERVATION_FAILED",
  },
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRequest(capability: string, params: Record<string, unknown> = {}) {
  return {
    type: "ArohaRequest",
    from: "did:aroha:caller",
    correlationId: "corr-123",
    body: { capability, params },
  };
}

function makeReserve(capability: string, params: Record<string, unknown> = {}) {
  return {
    type: "ArohaReserve",
    from: "did:aroha:caller",
    correlationId: "corr-456",
    body: { capability, params },
  };
}

async function dispatch(agent: MicroAgent, envelope: unknown) {
  const responses: unknown[] = [];
  await capturedOnMessage!(envelope, (r) => responses.push(r));
  return responses;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("createAgent", () => {
  it("returns a MicroAgent", () => {
    const agent = createAgent({ name: "test", port: 3001 });
    expect(agent).toBeInstanceOf(MicroAgent);
  });
});

describe("MicroAgent.on()", () => {
  it("registers a capability handler", async () => {
    const agent = createAgent({ name: "test", port: 3001 });
    const handler = vi.fn().mockResolvedValue({ ok: true });
    agent.on("my-cap", handler);
    await agent.start();

    const responses = await dispatch(agent, makeRequest("my-cap", { x: 1 }));
    expect(handler).toHaveBeenCalledWith({ x: 1 });
    expect(responses).toHaveLength(1);
  });

  it("is chainable", () => {
    const agent = createAgent({ name: "test", port: 3001 });
    const result = agent.on("a", vi.fn()).on("b", vi.fn());
    expect(result).toBe(agent);
  });
});

describe("MicroAgent.start()", () => {
  it("sets a DID after start", async () => {
    const agent = createAgent({ name: "test", port: 3002 });
    expect(agent.did).toBe("");
    await agent.start();
    expect(agent.did).toBe("did:aroha:test-agent");
  });

  it("exposes the correct endpoint", async () => {
    const agent = createAgent({ name: "test", port: 3003 });
    expect(agent.endpoint).toBe("http://localhost:3003");
  });

  it("T2/N8: devMode defaults to false; registry defaults to the managed one; endpoint is configurable", async () => {
    const { AROHA_MANAGED_REGISTRY_URL } = await import("@aroha-sdk/core/endpoints");
    const saved = { ep: process.env.AGENT_ENDPOINT, reg: process.env.AROHA_REGISTRY_URL };
    delete process.env.AGENT_ENDPOINT;
    delete process.env.AROHA_REGISTRY_URL;
    try {
      const prod = createAgent({ name: "p", port: 3011 }) as unknown as { opts: { devMode: boolean; registryUrl: string } };
      expect(prod.opts.devMode).toBe(false);
      expect(prod.opts.registryUrl).toBe(AROHA_MANAGED_REGISTRY_URL);
      const dev = createAgent({ name: "d", port: 3012, devMode: true }) as unknown as { opts: { registryUrl: string } };
      expect(dev.opts.registryUrl).toBe("http://localhost:3000");
      expect(createAgent({ name: "e", port: 3013, endpoint: "https://agent.example.com/" }).endpoint).toBe("https://agent.example.com");
      process.env.AGENT_ENDPOINT = "https://from-env.example.com";
      expect(createAgent({ name: "f", port: 3014 }).endpoint).toBe("https://from-env.example.com");
    } finally {
      if (saved.ep === undefined) delete process.env.AGENT_ENDPOINT; else process.env.AGENT_ENDPOINT = saved.ep;
      if (saved.reg === undefined) delete process.env.AROHA_REGISTRY_URL; else process.env.AROHA_REGISTRY_URL = saved.reg;
    }
  });
});

describe("dispatch — ArohaRequest", () => {
  beforeEach(() => { capturedOnMessage = null; });

  it("calls the registered handler and returns ArohaResponse", async () => {
    const agent = createAgent({ name: "test", port: 3004, devMode: false });
    agent.on("search", vi.fn().mockResolvedValue({ results: ["a", "b"] }));
    await agent.start();

    const responses = await dispatch(agent, makeRequest("search", { q: "hello" }));
    expect(responses).toHaveLength(1);
    const r = responses[0] as { type: string };
    expect(r.type).toBe("ArohaResponse");
  });

  it("returns ArohaError for unknown capability", async () => {
    const agent = createAgent({ name: "test", port: 3005 });
    await agent.start();

    const responses = await dispatch(agent, makeRequest("no-such-cap"));
    expect(responses).toHaveLength(1);
    const r = responses[0] as { type: string; body: { code: string } };
    expect(r.type).toBe("ArohaError");
    expect(r.body.code).toBe("UNKNOWN_CAPABILITY");
  });

  it("returns ArohaError when handler throws", async () => {
    const agent = createAgent({ name: "test", port: 3006 });
    agent.on("bad-cap", async () => { throw new Error("boom"); });
    await agent.start();

    const responses = await dispatch(agent, makeRequest("bad-cap"));
    const r = responses[0] as { type: string; body: { code: string } };
    expect(r.type).toBe("ArohaError");
    expect(r.body.code).toBe("INTERNAL_ERROR");
  });

  it("wraps non-object return values in { value: ... }", async () => {
    const agent = createAgent({ name: "test", port: 3007 });
    agent.on("echo", async () => "hello-string");
    await agent.start();

    const responses = await dispatch(agent, makeRequest("echo"));
    const r = responses[0] as { body: { result: { value: string } } };
    expect(r.body.result.value).toBe("hello-string");
  });
});

describe("dispatch — ArohaReserve (devMode)", () => {
  it("auto-commits in devMode — returns ArohaCommitAck", async () => {
    const agent = createAgent({ name: "test", port: 3008, devMode: true });
    agent.on("pay", vi.fn().mockResolvedValue({ ref: "TX-1" }));
    await agent.start();

    const responses = await dispatch(agent, makeReserve("pay", { amount: 100 }));
    const r = responses[0] as { type: string };
    expect(r.type).toBe("ArohaCommitAck");
  });

  it("returns ArohaError for ArohaReserve in production mode", async () => {
    const agent = createAgent({ name: "test", port: 3009, devMode: false });
    agent.on("pay", vi.fn());
    await agent.start();

    const responses = await dispatch(agent, makeReserve("pay"));
    const r = responses[0] as { type: string; body: { code: string } };
    expect(r.type).toBe("ArohaError");
    expect(r.body.code).toBe("RESERVATION_FAILED");
  });
});

describe("MicroAgent.stop()", () => {
  it("calls server stop", async () => {
    const agent = createAgent({ name: "test", port: 3010 });
    await agent.start();
    await agent.stop();
    expect(mockServerStop).toHaveBeenCalled();
  });
});
