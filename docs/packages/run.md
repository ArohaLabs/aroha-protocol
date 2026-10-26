<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/run

Agent lifecycle server for conversational and agentic workloads. Provides a zero-config HTTP server with session memory, streaming SSE, tool-call events, and human-in-the-loop (HITL) approval gates. Works with Claude out of the box; accepts any custom `Handler`.

```bash
npm install @aroha-sdk/run
```

---

## serve()

`serve(name, handler, options?)` returns an agent with `start(port?, host?)`, `fetch(request)` (for Workers / Edge / Bun) and `register(endpointUrl, options?)`. The server exposes:

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/run` | POST | Send a message; stream `RunEvent` over SSE or get a `RunResponse` |
| `/v1/resume` | POST | Resume a paused stream after an approval decision |
| `/health` | GET | Health check |
| `/.well-known/aroha-agent.json` | GET | Agent manifest |
| `/mcp` | POST | MCP endpoint (only with `exposeMcp: true`) |

```typescript
import { serve } from "@aroha-sdk/run";

const agent = serve("travel-agent", async (ctx) => {
  // ctx.message     — the user's message
  // ctx.sessionId   — session id, if the request has one
  // ctx.history     — prior messages in this session
  // ctx.trust       — "trusted" | "untrusted"
  // ctx.caller      — who is speaking ({ kind, id, displayName? })

  const reply = await myLLM(ctx.message, ctx.history);
  return reply;              // a string, or use an async generator (below)
}, {
  memory: "session",         // "none" (default) | "session" | "persistent"
});

agent.start(3000);           // binds 127.0.0.1 by default
```

Requests must be signed by default (`auth: "aroha-sig"`). Pass `auth: "bearer"` with `bearerTokens` (or `AROHA_BEARER_TOKEN`), or `auth: "none"` for a local, unauthenticated agent.

---

## createClaudeHandler()

Wires Claude (via the Anthropic Messages API) as the handler with tool-call support and streaming.

```typescript
import { serve, createClaudeHandler } from "@aroha-sdk/run";

const agent = serve("travel-agent", createClaudeHandler({
  apiKey:       process.env.ANTHROPIC_API_KEY,   // the default
  model:        "claude-sonnet-4-6",
  systemPrompt: "You are a helpful travel agent.",
  tools: [
    {
      name:        "search_flights",
      description: "Search for available flights",
      input_schema: {
        type:       "object",
        properties: { origin: { type: "string" }, destination: { type: "string" } },
        required:   ["origin", "destination"],
      },
    },
  ],
  onToolCall: async (name, input) => {
    if (name === "search_flights") return JSON.stringify(await flightSearch(input));
    return "unknown tool";
  },
}));

agent.start(3000);
```

---

## Streaming SSE

When the client sends `{ "stream": true }`, each `RunEvent` is sent as a server-sent event (`data: <json>`):

```typescript
export type RunEvent =
  | { type: "token";             delta: string }
  | { type: "thinking";          delta: string }
  | { type: "tool_call";         id: string; name: string; args: unknown }
  | { type: "tool_result";       id: string; result: unknown }
  | { type: "approval_required"; id: string; action: unknown }
  | { type: "final";             message: string; sessionId: string; artifacts?: unknown[]; usage?: Record<string, number> }
  | { type: "error";             requestId: string; message?: string }
  | { type: "trace";             message: string }
  | { type: "step";              id: string; kind: string; label: string; status: "running" | "done" | "failed"; /* … */ };
```

Client-side consumption (agent started with `auth: "none"`; otherwise sign the request or send the bearer token):

```typescript
const res = await fetch("http://localhost:3000/v1/run", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "Find flights from LHR to NRT", stream: true }),
});

// Parse the SSE stream: each event is a "data: {…}" line followed by a blank line
```

To call another Aroha agent from code, `streamAgent` (below) parses the stream for you.

---

## Human-in-the-loop (HITL)

An async-generator handler can pause and request a human approval before continuing. The stream emits `approval_required`, then the client POSTs a decision to `/v1/resume`. A pending approval times out after `approvalTimeoutMs` (default 5 minutes).

```typescript
import { serve } from "@aroha-sdk/run";
import type { ApprovalDecision } from "@aroha-sdk/run";

serve("booking-agent", async function*(ctx) {
  yield "I found a flight for £320. ";

  // Pause and wait for human approval
  const decision = (yield {
    type:   "approval_required",
    id:     "confirm-purchase",
    action: { flight: "BA0005", price: 320, currency: "GBP" },
  }) as ApprovalDecision;

  if (decision.decision === "approve") {
    yield "Booking now…";
    await bookFlight("BA0005");
    yield "Booked! Confirmation: ABC123";
  } else {
    yield "Booking cancelled.";
  }
}).start(3000);
```

The client resumes by posting (`decision` is `"approve" | "edit" | "reject" | "respond"`, with an optional `payload`):

```typescript
await fetch("http://localhost:3000/v1/resume", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    sessionId:  "sess-xyz",
    approvalId: "confirm-purchase",
    decision:   "approve",
  }),
});
```

---

## Session memory

```typescript
import { serve, InMemorySessionStore } from "@aroha-sdk/run";

// Default in-process store (development)
serve("my-agent", handler, { memory: "session" });

// Bring your own store (production — Redis, Postgres, etc.)
serve("my-agent", handler, {
  memory:       "persistent",
  sessionStore: myRedisStore,   // implements SessionStore interface
});
```

```typescript
export interface SessionStore {
  load(sessionId: string):                          Promise<Message[]>;
  append(sessionId: string, messages: Message[]):   Promise<void>;
  clear(sessionId: string):                         Promise<void>;
}
```

---

## Calling other agents

`callAgent` and `streamAgent` resolve the agent through a registry (`registryUrl`, else `AROHA_REGISTRY_URL`, else the reference registry deployment) and call its `/v1/run` endpoint.

```typescript
import { callAgent, streamAgent, listAgents } from "@aroha-sdk/run";

// Single-turn call
const result = await callAgent(agentDidHash, "What is the weather in Tokyo?", {
  signAs: { did: myDID, privateKey: myPrivateKey },   // for a callee using auth: "aroha-sig"
});

// Streaming call
for await (const event of streamAgent(agentDidHash, "Translate…")) {
  if (event.type === "token") process.stdout.write(event.delta);
}

// List agents from the registry
const agents = await listAgents({ org: "acme", limit: 20 });
```
