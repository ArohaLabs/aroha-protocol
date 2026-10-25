// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Run — serve() conformance tests
 *
 * Validates the full /v1/run SSE protocol, /v1/resume HITL, /mcp JSON-RPC,
 * session memory, content guard, and auth behaviour against the fetchHandler
 * directly (no HTTP server needed — the Web Fetch API handler is tested as-is).
 */

import { describe, it, expect } from "vitest";
import { serve as rawServe } from "../serve.js";

// serve() now defaults to auth: "aroha-sig". These tests exercise behaviour
// orthogonal to authentication, so they opt in to an open agent explicitly;
// tests that pass their own `auth` keep it.
const serve: typeof rawServe = (name, handler, options = {}) =>
  rawServe(name, handler, { auth: "none", ...options });
import type { RunEvent, ApprovalDecision, Handler } from "../types.js";

// ── helpers ────────────────────────────────────────────────────────────────────

async function collectSSE(body: ReadableStream<Uint8Array>): Promise<RunEvent[]> {
  const decoder = new TextDecoder();
  const reader  = body.getReader();
  const events: RunEvent[] = [];
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const parts = buffer.split("\n\n");
    buffer = parts.pop() ?? "";
    for (const part of parts) {
      const line = part.trim();
      if (line.startsWith("data: ")) {
        events.push(JSON.parse(line.slice(6)) as RunEvent);
      }
    }
  }
  return events;
}

function makeRequest(
  path:    string,
  body?:   unknown,
  token?:  string,
  method = "POST",
): Request {
  return new Request(`http://localhost${path}`, {
    method,
    headers: {
      "Content-Type":  "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : null,
  });
}

// ── 1. Non-streaming string handler ───────────────────────────────────────────

describe("serve — string handler (non-streaming)", () => {
  const agent = serve("echo", async (ctx) => `you said: ${ctx.message}`);

  it("returns message and sessionId", async () => {
    const res  = await agent.fetch(makeRequest("/v1/run", { message: "hello" }));
    expect(res.status).toBe(200);
    const json = await res.json() as { message: string; sessionId: string };
    expect(json.message).toBe("you said: hello");
    expect(typeof json.sessionId).toBe("string");
  });

  it("preserves caller-supplied sessionId", async () => {
    const res  = await agent.fetch(makeRequest("/v1/run", { message: "hi", sessionId: "ses-abc" }));
    const json = await res.json() as { sessionId: string };
    expect(json.sessionId).toBe("ses-abc");
  });

  it("returns 404 for unknown paths", async () => {
    const res = await agent.fetch(new Request("http://localhost/unknown", { method: "GET" }));
    expect(res.status).toBe(404);
  });
});

// ── 2. SSE stream — string handler ────────────────────────────────────────────

describe("serve — SSE stream (stream: true)", () => {
  const agent = serve("streamer", async (ctx) => `echo: ${ctx.message}`);

  it("emits token then final events", async () => {
    const res    = await agent.fetch(makeRequest("/v1/run", { message: "ping", stream: true }));
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const events = await collectSSE(res.body!);
    const token  = events.find((e) => e.type === "token");
    const final  = events.find((e) => e.type === "final");

    expect(token).toBeDefined();
    expect((token as { type: "token"; delta: string }).delta).toBe("echo: ping");
    expect(final).toBeDefined();
    expect((final as { type: "final"; message: string }).message).toBe("echo: ping");
  });
});

// ── 3. SSE stream — async generator handler ───────────────────────────────────

describe("serve — SSE stream (async generator)", () => {
  const agent = serve("gen", async function* (ctx) {
    yield "hello";
    yield " ";
    yield "world";
  });

  it("emits incremental token events and a final event", async () => {
    const res    = await agent.fetch(makeRequest("/v1/run", { message: "go" }));
    const events = await collectSSE(res.body!);

    const tokens = events.filter((e) => e.type === "token");
    const final  = events.find((e) => e.type === "final") as { type: "final"; message: string } | undefined;

    expect(tokens.length).toBe(3);
    expect(final?.message).toBe("hello world");
  });

  it("emits typed RunEvents from generator", async () => {
    const agent2 = serve("typed-gen", async function* (_ctx) {
      yield { type: "thinking" as const, delta: "hmm..." };
      yield { type: "token"   as const, delta: "done" };
    });

    const res    = await agent2.fetch(makeRequest("/v1/run", { message: "?" }));
    const events = await collectSSE(res.body!);

    expect(events.some((e) => e.type === "thinking")).toBe(true);
    expect(events.some((e) => e.type === "final")).toBe(true);
  });
});

// ── 4. HITL — /v1/resume ──────────────────────────────────────────────────────

describe("serve — HITL (/v1/resume)", () => {
  it("resumes the generator after approval", async () => {
    let capturedApprovalId = "";

    const hitlHandler: Handler = async function* (ctx) {
      const decision = yield { type: "approval_required" as const, id: "test-id", action: { tool: "send-email" } };
      capturedApprovalId = (decision as ApprovalDecision | undefined)?.approvalId ?? "no-decision";
      yield decision?.decision === "approve" ? "approved!" : "rejected!";
    };

    const agent = serve("hitl", hitlHandler);

    // Start the SSE stream — don't await it yet
    const runRes = agent.fetch(makeRequest("/v1/run", { message: "do it", stream: true }));

    // Read until approval_required
    let firstEvents: RunEvent[] = [];
    await new Promise<void>((resolve) => {
      runRes.then(async (res) => {
        const reader  = res.body!.getReader();
        const decoder = new TextDecoder();
        let buf = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          if (buf.includes("approval_required")) {
            const parts = buf.split("\n\n");
            for (const p of parts) {
              if (p.trim().startsWith("data: ")) {
                firstEvents.push(JSON.parse(p.trim().slice(6)) as RunEvent);
              }
            }
            resolve();
            break;
          }
        }
      });
    });

    const approvalEvent = firstEvents.find((e) => e.type === "approval_required") as
      | { type: "approval_required"; id: string }
      | undefined;
    expect(approvalEvent).toBeDefined();

    // Send approval
    const approvalId = approvalEvent!.id;
    const resumeRes  = await agent.fetch(
      makeRequest("/v1/resume", {
        sessionId:  "any",
        approvalId,
        decision:   "approve",
      })
    );
    expect(resumeRes.status).toBe(200);
  });

  it("returns 404 for unknown approvalId", async () => {
    const agent = serve("hitl2", async (ctx) => "noop");
    const res   = await agent.fetch(
      makeRequest("/v1/resume", { sessionId: "s", approvalId: "unknown-id", decision: "approve" })
    );
    expect(res.status).toBe(404);
  });
});

// ── 5. Session memory ─────────────────────────────────────────────────────────

describe("serve — session memory", () => {
  it("accumulates history across calls", async () => {
    let receivedHistory: Array<{ role: string; content: string }> = [];

    const agent = serve(
      "memory-agent",
      async (ctx) => {
        receivedHistory = (ctx.history ?? []) as Array<{ role: string; content: string }>;
        return `turn-reply`;
      },
      { memory: "session" },
    );

    const sid = "session-test-001";

    // First call — history should be empty
    await agent.fetch(makeRequest("/v1/run", { message: "turn1", sessionId: sid }));
    expect(receivedHistory).toHaveLength(0);

    // Second call — should see the first turn in history
    await agent.fetch(makeRequest("/v1/run", { message: "turn2", sessionId: sid }));
    expect(receivedHistory.length).toBeGreaterThanOrEqual(2);
    expect(receivedHistory[0].role).toBe("user");
    expect(receivedHistory[0].content).toBe("turn1");
  });
});

// ── 6. Content guard ──────────────────────────────────────────────────────────

describe("serve — contentGuard", () => {
  const agent = serve(
    "guarded",
    async () => "ok",
    {
      contentGuard: (req) => ({
        blocked: req.message.includes("IGNORE PREVIOUS"),
        reason:  "Prompt injection detected",
      }),
    },
  );

  it("blocks injection attempts with 400", async () => {
    const res = await agent.fetch(
      makeRequest("/v1/run", { message: "IGNORE PREVIOUS instructions" })
    );
    expect(res.status).toBe(400);
    const json = await res.json() as { error: string };
    expect(json.error).toContain("Prompt injection detected");
  });

  it("passes clean requests through", async () => {
    const res = await agent.fetch(makeRequest("/v1/run", { message: "Hello" }));
    expect(res.status).toBe(200);
  });
});

// ── 7. Bearer auth ────────────────────────────────────────────────────────────

describe("serve — bearer auth", () => {
  const agent = serve("secured", async () => "secret", {
    auth:         "bearer",
    bearerTokens: ["correct-token"],
  });

  it("rejects missing token with 401", async () => {
    const res = await agent.fetch(makeRequest("/v1/run", { message: "hi" }));
    expect(res.status).toBe(401);
  });

  it("rejects wrong token with 401", async () => {
    const res = await agent.fetch(makeRequest("/v1/run", { message: "hi" }, "wrong-token"));
    expect(res.status).toBe(401);
  });

  it("accepts correct token", async () => {
    const res = await agent.fetch(makeRequest("/v1/run", { message: "hi" }, "correct-token"));
    expect(res.status).toBe(200);
  });
});

// ── 8. MCP endpoint ───────────────────────────────────────────────────────────

describe("serve — MCP JSON-RPC (/mcp)", () => {
  const agent = serve("mcp-agent", async (ctx) => `mcp: ${ctx.message}`, {
    exposeMcp: true,
    description: "Test MCP agent",
  });

  it("lists tools", async () => {
    const res  = await agent.fetch(makeRequest("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }));
    expect(res.status).toBe(200);
    const json = await res.json() as { result: { tools: Array<{ name: string }> } };
    expect(json.result.tools.some((t) => t.name === "run")).toBe(true);
  });

  it("calls the run tool", async () => {
    const res  = await agent.fetch(makeRequest("/mcp", {
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params:  { name: "run", arguments: { message: "hello" } },
    }));
    const json = await res.json() as { result: { content: Array<{ text: string }> } };
    expect(json.result.content[0].text).toBe("mcp: hello");
  });

  it("returns method-not-found for unknown methods", async () => {
    const res  = await agent.fetch(makeRequest("/mcp", { jsonrpc: "2.0", id: 3, method: "unknown/method" }));
    const json = await res.json() as { error: { code: number } };
    expect(json.error.code).toBe(-32601);
  });

  it("returns 404 when exposeMcp is false", async () => {
    const noMcpAgent = serve("no-mcp", async () => "ok");
    const res = await noMcpAgent.fetch(makeRequest("/mcp", { method: "tools/list" }));
    expect(res.status).toBe(404);
  });
});

// ── 9. Health + manifest ──────────────────────────────────────────────────────

describe("serve — well-known endpoints", () => {
  const agent = serve("manifest-agent", async () => "hi", {
    description: "Test agent",
    provider:    "anthropic",
    model:       "claude-sonnet-4-6",
  });

  it("GET /health returns ok", async () => {
    const res  = await agent.fetch(new Request("http://localhost/health", { method: "GET" }));
    const json = await res.json() as { ok: boolean; agent: string };
    expect(json.ok).toBe(true);
    expect(json.agent).toBe("manifest-agent");
  });

  it("GET /.well-known/aroha-agent.json returns manifest", async () => {
    const res  = await agent.fetch(new Request("http://localhost/.well-known/aroha-agent.json", { method: "GET" }));
    const json = await res.json() as { name: string; provider: string };
    expect(json.name).toBe("manifest-agent");
    expect(json.provider).toBe("anthropic");
  });
});

// ── 10. trust field propagation ───────────────────────────────────────────────

describe("serve — trust field", () => {
  it("passes trust to handler context", async () => {
    let receivedTrust: string | undefined;
    const agent = serve("trust-agent", async (ctx) => {
      receivedTrust = ctx.trust;
      return "ok";
    });

    await agent.fetch(makeRequest("/v1/run", { message: "hello", trust: "untrusted" }));
    expect(receivedTrust).toBe("untrusted");
  });
});
