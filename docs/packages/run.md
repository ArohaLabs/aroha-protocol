<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/run

Agent lifecycle server for conversational and agentic workloads. Provides a zero-config HTTP server with session memory, streaming SSE, tool-call events, and human-in-the-loop (HITL) approval gates. Works with Claude out of the box; accepts any custom `Handler`.

```bash
npm install @aroha-sdk/run
```

---

## serve()

Starts an HTTP server exposing:

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/run` | POST | Send a message; stream `RunEvent` over SSE or get a `RunResponse` |
| `/v1/resume` | POST | Resume a paused stream after an approval decision |
| `/v1/health` | GET | Health check |

```typescript
import { serve } from "@aroha-sdk/run";

serve({
  port:    3000,
  memory:  "session",          // "none" | "session" | "persistent"
  handler: async (ctx) => {
    // ctx.message     — the user's message
    // ctx.sessionId   — auto-assigned UUID
    // ctx.history     — prior messages in this session
    // ctx.trust       — "trusted" | "untrusted"

    const reply = await myLLM(ctx.message, ctx.history);
    return reply;              // string or RunResponse
  },
});
```

---

## createClaudeHandler()

Wires Claude (via the Anthropic SDK) as the handler with tool-call support and streaming.

```typescript
import { serve, createClaudeHandler } from "@aroha-sdk/run";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

serve({
  port: 3000,
  handler: createClaudeHandler({
    client,
    model:  "claude-sonnet-4-6",
    system: "You are a helpful travel agent.",
    tools:  [
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
    toolHandler: async (name, args) => {
      if (name === "search_flights") return await flightSearch(args);
    },
  }),
});
```

---

## Streaming SSE

When the client sends `{ "stream": true }`, each `RunEvent` is emitted as a newline-delimited JSON line over SSE:

```typescript
export type RunEvent =
  | { type: "token";             delta: string }
  | { type: "thinking";          delta: string }
  | { type: "tool_call";         id: string; name: string; args: unknown }
  | { type: "tool_result";       id: string; result: unknown }
  | { type: "approval_required"; id: string; action: unknown }
  | { type: "final";             message: string; sessionId: string; artifacts?: unknown[]; usage?: Record<string, number> }
  | { type: "error";             requestId: string; message?: string };
```

Client-side consumption:

```typescript
const res = await fetch("http://localhost:3000/v1/run", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "Find flights from LHR to NRT", stream: true }),
});

for await (const line of res.body) {
  const event = JSON.parse(line);
  if (event.type === "token")   process.stdout.write(event.delta);
  if (event.type === "final")   console.log("\nDone:", event.sessionId);
}
```

---

## Human-in-the-loop (HITL)

Handlers can pause and request a human approval before continuing. The stream emits `approval_required`, then the client POSTs a decision to `/v1/resume`.

```typescript
import { serve } from "@aroha-sdk/run";
import type { ApprovalDecision } from "@aroha-sdk/run";

serve({
  port: 3000,
  handler: async function*(ctx) {
    yield "I found a flight for £320. ";

    // Pause and wait for human approval
    const decision: ApprovalDecision = yield {
      type:   "approval_required",
      id:     "confirm-purchase",
      action: { flight: "BA0005", price: 320, currency: "GBP" },
    };

    if (decision.decision === "approve") {
      yield "Booking now…";
      await bookFlight("BA0005");
      yield "Booked! Confirmation: ABC123";
    } else {
      yield "Booking cancelled.";
    }
  },
});
```

The client resumes by posting:

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
serve({ port: 3000, memory: "session", handler });

// Bring your own store (production — Redis, Postgres, etc.)
serve({
  port:        3000,
  sessionStore: myRedisStore,   // implements SessionStore interface
  handler,
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

```typescript
import { callAgent, streamAgent, listAgents } from "@aroha-sdk/run";

// Single-turn call
const result = await callAgent("http://agent.example.com", {
  message: "What is the weather in Tokyo?",
});

// Streaming call
for await (const event of streamAgent("http://agent.example.com", { message: "Translate…", stream: true })) {
  if (event.type === "token") process.stdout.write(event.delta);
}

// Discover agents from the registry
const agents = await listAgents({ capability: "weather" });
```
