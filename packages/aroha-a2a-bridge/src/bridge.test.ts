// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import {
  a2aToAroha,
  arohaToA2a,
  arohaStreamToA2aStatus,
  attachMandate,
  extractMandate,
  arohaMandateExtension,
  withArohaMandateExtension,
  cardSupportsArohaMandate,
  sendMessage,
  parseSendMessageResult,
  A2AJsonRpcError,
  AROHA_MANDATE_EXTENSION_URI,
  AROHA_MANDATE_METADATA_KEY,
  type A2AMessage,
  type A2AAgentCard,
} from "./index.js";
import type { ArohaEnvelope } from "@aroha-sdk/core";

function makeA2AMessage(overrides: Partial<A2AMessage> = {}): A2AMessage {
  return {
    messageId: "msg-001",
    taskId: "task-abc",
    contextId: "ctx-1",
    role: "ROLE_USER",
    parts: [{ data: { capability: "search-flights", params: { from: "JFK" } } }],
    ...overrides,
  };
}

function makeEnvelope(type: ArohaEnvelope["type"], body: Record<string, unknown> = {}): ArohaEnvelope {
  return {
    "@context": ["https://aroha-labs.com/contexts/v1"],
    id: "urn:uuid:test-id",
    type,
    from: "did:aroha:from",
    to: "did:aroha:to",
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 60_000).toISOString(),
    nonce: "test-nonce",
    correlationId: "saga-123",
    body: body as unknown as ArohaEnvelope["body"],
  };
}

function makeCard(): A2AAgentCard {
  return {
    name: "Flight Agent",
    description: "Books flights",
    supportedInterfaces: [{ url: "https://agent.example/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    version: "1.0.0",
    capabilities: { streaming: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [{ id: "book-flight", name: "Book flight", description: "Book a flight", tags: ["travel"] }],
  };
}

describe("a2aToAroha", () => {
  it("converts a ROLE_USER message to ArohaRequest", () => {
    const env = a2aToAroha(makeA2AMessage(), "did:aroha:from", "did:aroha:to");
    expect(env.type).toBe("ArohaRequest");
    expect(env.from).toBe("did:aroha:from");
    expect(env.to).toBe("did:aroha:to");
    expect(env.id).toBe("urn:a2a:msg-001");
    expect(env.correlationId).toBe("task-abc");
    expect(env.nonce).toBe("msg-001");
  });

  it("converts a ROLE_AGENT message to ArohaResponse", () => {
    const env = a2aToAroha(makeA2AMessage({ role: "ROLE_AGENT" }), "a", "b");
    expect(env.type).toBe("ArohaResponse");
  });

  it("falls back to contextId, then messageId, for correlationId", () => {
    expect(a2aToAroha(makeA2AMessage({ taskId: undefined }), "a", "b").correlationId).toBe("ctx-1");
    expect(
      a2aToAroha(makeA2AMessage({ taskId: undefined, contextId: undefined }), "a", "b").correlationId
    ).toBe("msg-001");
  });

  it("has no proof field (A2A messages are not Aroha-signed)", () => {
    expect(a2aToAroha(makeA2AMessage(), "a", "b").proof).toBeUndefined();
  });

  it("sets a future expiry", () => {
    const env = a2aToAroha(makeA2AMessage(), "a", "b");
    expect(new Date(env.expires) > new Date()).toBe(true);
  });

  it("extracts body from a text part containing JSON", () => {
    const env = a2aToAroha(
      makeA2AMessage({ parts: [{ text: JSON.stringify({ capability: "do-thing", params: {} }) }] }),
      "a",
      "b"
    );
    expect((env.body as unknown as Record<string, unknown>).capability).toBe("do-thing");
  });

  it("handles non-JSON text parts", () => {
    const env = a2aToAroha(makeA2AMessage({ parts: [{ text: "plain text" }] }), "a", "b");
    expect((env.body as unknown as Record<string, unknown>).text).toBe("plain text");
  });

  it("returns an empty body when there are no parts", () => {
    expect(a2aToAroha(makeA2AMessage({ parts: [] }), "a", "b").body).toEqual({});
  });

  it("copies a carried mandate into body.credentialToken", () => {
    const msg = attachMandate(makeA2AMessage(), "mandate-token-xyz");
    const env = a2aToAroha(msg, "a", "b");
    expect((env.body as unknown as Record<string, unknown>).credentialToken).toBe("mandate-token-xyz");
  });

  it("accepts pre-1.0 messages (role user/agent, typed parts)", () => {
    const env = a2aToAroha(
      {
        messageId: "old-1",
        taskId: "t",
        role: "user",
        parts: [{ type: "data", data: { capability: "legacy" } }],
      },
      "a",
      "b"
    );
    expect(env.type).toBe("ArohaRequest");
    expect((env.body as unknown as Record<string, unknown>).capability).toBe("legacy");
  });
});

describe("arohaToA2a", () => {
  it("uses ROLE_USER for ArohaRequest and ArohaReserve", () => {
    expect(arohaToA2a(makeEnvelope("ArohaRequest")).role).toBe("ROLE_USER");
    expect(arohaToA2a(makeEnvelope("ArohaReserve")).role).toBe("ROLE_USER");
  });

  it("uses ROLE_AGENT for responses", () => {
    expect(arohaToA2a(makeEnvelope("ArohaResponse")).role).toBe("ROLE_AGENT");
  });

  it("maps correlationId to taskId and contextId", () => {
    const msg = arohaToA2a(makeEnvelope("ArohaRequest"));
    expect(msg.taskId).toBe("saga-123");
    expect(msg.contextId).toBe("saga-123");
  });

  it("strips the urn:uuid: prefix from messageId", () => {
    expect(arohaToA2a(makeEnvelope("ArohaRequest")).messageId).toBe("test-id");
  });

  it("puts the envelope body in a 1.0 data part (no kind/type discriminator)", () => {
    const body = { capability: "x", result: {} };
    const part = arohaToA2a(makeEnvelope("ArohaResponse", body)).parts[0];
    expect(part.data).toEqual(body);
    expect(part.mediaType).toBe("application/json");
    expect(part).not.toHaveProperty("kind");
    expect(part).not.toHaveProperty("type");
  });

  it("records Aroha type and DIDs under namespaced metadata keys", () => {
    const msg = arohaToA2a(makeEnvelope("ArohaError"));
    expect(msg.metadata?.["aroha.type"]).toBe("ArohaError");
    expect(msg.metadata?.["aroha.from"]).toBe("did:aroha:from");
  });

  it("attaches a mandate when one is given", () => {
    const msg = arohaToA2a(makeEnvelope("ArohaRequest"), { mandateToken: "tok" });
    expect(extractMandate(msg)).toBe("tok");
    expect(msg.extensions).toContain(AROHA_MANDATE_EXTENSION_URI);
  });
});

describe("mandate metadata carriage", () => {
  it("attachMandate stores the token under aroha.mandate and lists the extension once", () => {
    const once = attachMandate(makeA2AMessage({ metadata: { other: 1 } }), "tok-1");
    const twice = attachMandate(once, "tok-2");
    expect(once.metadata?.[AROHA_MANDATE_METADATA_KEY]).toBe("tok-1");
    expect(once.metadata?.other).toBe(1);
    expect(twice.metadata?.[AROHA_MANDATE_METADATA_KEY]).toBe("tok-2");
    expect(twice.extensions?.filter((e) => e === AROHA_MANDATE_EXTENSION_URI)).toHaveLength(1);
  });

  it("attachMandate does not mutate its input", () => {
    const original = makeA2AMessage();
    attachMandate(original, "tok");
    expect(original.metadata).toBeUndefined();
    expect(original.extensions).toBeUndefined();
  });

  it("extractMandate returns undefined when absent or not a string", () => {
    expect(extractMandate(makeA2AMessage())).toBeUndefined();
    expect(extractMandate(makeA2AMessage({ metadata: { [AROHA_MANDATE_METADATA_KEY]: 42 } }))).toBeUndefined();
  });

  it("round-trips through JSON (as it would on the wire)", () => {
    const wire = JSON.parse(JSON.stringify(attachMandate(makeA2AMessage(), "tok"))) as A2AMessage;
    expect(extractMandate(wire)).toBe("tok");
  });
});

describe("agent card extension declaration", () => {
  it("declares the mandate extension in capabilities.extensions", () => {
    const card = withArohaMandateExtension(makeCard(), true);
    const ext = card.capabilities.extensions?.find((e) => e.uri === AROHA_MANDATE_EXTENSION_URI);
    expect(ext?.required).toBe(true);
    expect(ext?.params?.metadataKey).toBe(AROHA_MANDATE_METADATA_KEY);
    expect(cardSupportsArohaMandate(card)).toBe(true);
    expect(cardSupportsArohaMandate(makeCard())).toBe(false);
  });

  it("is idempotent and keeps other extensions", () => {
    const base = makeCard();
    base.capabilities.extensions = [{ uri: "https://example.com/ext/other" }];
    const card = withArohaMandateExtension(withArohaMandateExtension(base));
    expect(card.capabilities.extensions?.map((e) => e.uri)).toEqual([
      "https://example.com/ext/other",
      AROHA_MANDATE_EXTENSION_URI,
    ]);
  });

  it("arohaMandateExtension defaults to not required", () => {
    expect(arohaMandateExtension().required).toBe(false);
  });
});

describe("arohaStreamToA2aStatus", () => {
  function streamEnv(progressPct?: number): ArohaEnvelope {
    return makeEnvelope("ArohaStream", { capability: "x", progressPct, event: "progress" });
  }

  it("returns TASK_STATE_WORKING below 100%", () => {
    expect(arohaStreamToA2aStatus(streamEnv(50)).status.state).toBe("TASK_STATE_WORKING");
  });

  it("returns TASK_STATE_COMPLETED at 100%", () => {
    expect(arohaStreamToA2aStatus(streamEnv(100)).status.state).toBe("TASK_STATE_COMPLETED");
  });

  it("returns TASK_STATE_WORKING when progressPct is missing", () => {
    expect(arohaStreamToA2aStatus(streamEnv(undefined)).status.state).toBe("TASK_STATE_WORKING");
  });
});

describe("sendMessage (JSON-RPC client, injected fetch)", () => {
  function fakeFetch(responseBody: unknown, status = 200) {
    return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
      new Response(JSON.stringify(responseBody), { status, headers: { "Content-Type": "application/json" } })
    );
  }

  it("posts a SendMessage JSON-RPC request with the mandate in metadata", async () => {
    const reply: A2AMessage = { messageId: "r1", role: "ROLE_AGENT", parts: [{ text: "ok" }] };
    const f = fakeFetch({ jsonrpc: "2.0", id: "1", result: { message: reply } });

    const out = await sendMessage("https://agent.example/a2a", makeA2AMessage(), {
      mandateToken: "tok",
      fetch: f as unknown as typeof fetch,
      id: "1",
    });

    expect(out).toEqual({ kind: "message", message: reply });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://agent.example/a2a");
    const headers = init?.headers as Record<string, string>;
    expect(headers["A2A-Version"]).toBe("1.0");
    expect(headers["A2A-Extensions"]).toBe(AROHA_MANDATE_EXTENSION_URI);
    const sent = JSON.parse(init?.body as string);
    expect(sent.jsonrpc).toBe("2.0");
    expect(sent.method).toBe("SendMessage");
    expect(sent.id).toBe("1");
    expect(sent.params.message.metadata[AROHA_MANDATE_METADATA_KEY]).toBe("tok");
  });

  it("returns a Task result", async () => {
    const task = { id: "t1", status: { state: "TASK_STATE_SUBMITTED" } };
    const f = fakeFetch({ jsonrpc: "2.0", id: "1", result: { task } });
    const out = await sendMessage("u", makeA2AMessage(), { fetch: f as unknown as typeof fetch });
    expect(out).toEqual({ kind: "task", task });
  });

  it("throws A2AJsonRpcError on a JSON-RPC error", async () => {
    const f = fakeFetch({ jsonrpc: "2.0", id: "1", error: { code: -32602, message: "Invalid params" } });
    await expect(sendMessage("u", makeA2AMessage(), { fetch: f as unknown as typeof fetch })).rejects.toMatchObject({
      name: "A2AJsonRpcError",
      code: -32602,
    });
  });

  it("throws on a non-2xx HTTP status", async () => {
    const f = fakeFetch({}, 503);
    await expect(sendMessage("u", makeA2AMessage(), { fetch: f as unknown as typeof fetch })).rejects.toThrow(
      "HTTP 503"
    );
  });

  it("does not send A2A-Extensions when no extension is in use", async () => {
    const f = fakeFetch({ jsonrpc: "2.0", id: "1", result: { task: { id: "t", status: { state: "TASK_STATE_WORKING" } } } });
    await sendMessage("u", makeA2AMessage(), { fetch: f as unknown as typeof fetch });
    const headers = f.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers["A2A-Extensions"]).toBeUndefined();
  });
});

describe("parseSendMessageResult", () => {
  it("accepts a bare Message or Task defensively", () => {
    expect(parseSendMessageResult({ messageId: "m", role: "ROLE_AGENT", parts: [] }).kind).toBe("message");
    expect(parseSendMessageResult({ id: "t", status: { state: "TASK_STATE_WORKING" } }).kind).toBe("task");
  });

  it("rejects malformed results", () => {
    expect(() => parseSendMessageResult({ nope: true })).toThrow(A2AJsonRpcError);
    expect(() => parseSendMessageResult(null)).toThrow(A2AJsonRpcError);
  });
});
