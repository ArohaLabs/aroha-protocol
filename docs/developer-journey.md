<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Day 0 to Day 2: The Developer Experience

This guide follows a single capability — a currency converter — from a 60-second localhost hack to a production-grade, zero-trust deployment. Each day adds exactly one layer of complexity, and no previous code is ever thrown away.

---

## The Aroha Philosophy

Most agent frameworks start with the AI. Aroha starts with the *network*.

The core insight: an AI agent that can't prove its identity, can't negotiate terms, and can't settle atomically is just a chatbot with a job title. Aroha gives agents the primitives that humans already rely on — credentials, contracts, and payments — without requiring a central authority to issue or enforce any of them.

The protocol is deliberately layered:

| Layer | Concern | You touch it when... |
|---|---|---|
| **Layer 0** — Transport | HTTP, WebSocket | Never (handled by `ArohaServer`) |
| **Layer 1** — Identity | `did:aroha:` DIDs, Ed25519 keys | Day 2 (generating a key pair) |
| **Layer 2** — Capability | Discovery, negotiation | Day 1 (defining what your agent can do) |
| **Layer 3** — Messaging | Signed envelopes, saga flow | Day 2 (Reserve → Commit → Cancel) |
| **Layer 4** — Value | Settlement, credentials | Optional (commerce use cases) |

On Day 0 you operate entirely in Layer 2. The lower layers are there — you just don't see them yet.

---

## Day 0: The Hacker Experience

**Goal:** A working agent capability on localhost in under 60 seconds.

### The absolute minimum

Five lines. No config, no DID, no key:

```typescript
import { createAgent } from "@aroha-sdk/micro";

createAgent({ name: "greeter", port: 3001 })
  .on("greet", ({ name }) => ({ message: `Hello, ${name}!` }))
  .start();
```

```bash
# Verify it works
aroha doctor http://localhost:3001
```

Everything below adds one layer at a time. None of the handler code ever changes.

---

### Scaffold the project

```bash
npx create-aroha-agent my-converter
cd my-converter
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) — the `aroha dev` sandbox dashboard is running. Three agent cards appear: `orchestrator`, `worker-a`, and `worker-b`. They registered themselves automatically on startup.

### Your first capability

Replace `agents/worker-a/src/index.ts` with:

```typescript
import { createAgent } from "@aroha-sdk/micro";

createAgent({ name: "currency-converter", port: 3001 })
  .on("convert", async ({ body }) => {
    const { amount, from, to } = body as {
      amount: number;
      from: string;
      to: string;
    };

    // Hard-coded rate for the demo — swap for a real FX API on Day 1
    const rates: Record<string, number> = { USD: 1, EUR: 0.92, GBP: 0.79 };
    const result = (amount / rates[from]) * rates[to];

    return { converted: result, rate: rates[to] / rates[from] };
  })
  .start();
```

The agent registers with the sandbox automatically. Its card appears in the dashboard within a second.

### Test it

```bash
curl -X POST http://localhost:3001/aroha/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ArohaRequest",
    "from": "did:aroha:test",
    "to":   "did:aroha:currency-converter",
    "body": { "capability": "convert", "amount": 100, "from": "USD", "to": "EUR" }
  }'
```

```json
{ "converted": 92, "rate": 0.92 }
```

No key generation. No DID resolution. No envelope signing. `devMode: true` (the default) tells `ArohaServer` to skip all cryptographic validation and dispatch straight to your handler. This is intentional — the zero-trust machinery is always one line away.

### What `@aroha-sdk/micro` is doing for you

```
createAgent({ name, port, devMode: true })
    │
    ├── Creates a ArohaServer with devMode=true
    │       → skips signature/nonce/expiry validation
    │
    ├── Registers at http://localhost:3000/registry/register
    │       → appears in the aroha dev dashboard
    │
    └── Auto-commits ArohaReserve messages
            → saga flow works without any saga code
```

When you flip `devMode` to `false` on Day 2, every handler you wrote on Day 0 continues to work unchanged.

---

## Day 1: Bringing the Brain

**Goal:** Understand where the AI actually lives in the Aroha protocol.

Aroha is model-agnostic. Your handler function is a plain `async` function — the model is just another `await` inside it. The protocol doesn't care whether that `await` calls GPT-4o, Claude 3.5, or a fine-tuned open-source model on a local GPU.

### Pattern A — Direct SDK call (simplest)

```typescript
import { createAgent } from "@aroha-sdk/micro";
import Anthropic from "@anthropic-ai/sdk";

const claude = new Anthropic(); // reads ANTHROPIC_API_KEY from env

createAgent({ name: "currency-converter", port: 3001 })
  .on("convert", async ({ body }) => {
    const { amount, from, to } = body as Record<string, unknown>;

    const message = await claude.messages.create({
      model: "claude-opus-4-7",
      max_tokens: 256,
      messages: [
        {
          role: "user",
          content: `Convert ${amount} ${from} to ${to}. Reply with JSON only: { "converted": <number>, "explanation": "<string>" }`,
        },
      ],
    });

    const text =
      message.content[0].type === "text" ? message.content[0].text : "{}";
    return JSON.parse(text);
  })
  .start();
```

The handler is pure business logic. Zero Aroha ceremony.

### Pattern B — LangChain orchestrator (for complex multi-step agents)

Use `@aroha-sdk/langchain-bridge` when you need an LLM to *choose* which capabilities to call:

```typescript
import { createAgent } from "@aroha-sdk/micro";
import { ArohaClient } from "@aroha-sdk/core";
import { ChatAnthropic } from "@langchain/anthropic";
import { AgentExecutor, createOpenAIFunctionsAgent } from "langchain/agents";
import { langChainToolsToCapabilities } from "@aroha-sdk/langchain-bridge";

// Define tools as plain LangChain tools
const tools = [convertTool, lookupRateTool, formatCurrencyTool];

// Expose the orchestrator as a Aroha agent
createAgent({ name: "fx-orchestrator", port: 3000 })
  .on("fx-query", async ({ body }) => {
    const llm = new ChatAnthropic({ model: "claude-opus-4-7" });
    const agent = await createOpenAIFunctionsAgent({ llm, tools, prompt });
    const executor = new AgentExecutor({ agent, tools });
    const result = await executor.invoke({ input: body.query });
    return { answer: result.output };
  })
  .start();
```

The bridge translates LangChain tool schemas into Aroha capability descriptors so that remote agents can discover and call them over the wire, not just in-process.

### Where the model routing hint lives

When the `@aroha-sdk/orchestrator` routes a request, it can suggest a model tier in the envelope:

```json
{
  "routingHint": {
    "complexity": "standard",
    "suggestedModel": "claude-haiku-4-5"
  }
}
```

Your handler can read this hint and switch models accordingly — or ignore it. The transport layer never enforces it. This is how you build cost-aware routing without hardcoding model names in every agent.

---

## Day 2: Enterprise Production

**Goal:** Move from `devMode: true` on localhost to a decentralized, zero-trust network.

### Step 1 — Generate a real identity

```bash
aroha init --did did:aroha:currency-converter
```

This writes `aroha.config.json` with your DID and `keys/key-1.pem` (Ed25519 private key). Back up the key; lose it and your agent's cryptographic identity is gone.

### Step 2 — Flip devMode off

```typescript
// Before (Day 0)
createAgent({ name: "currency-converter", port: 3001 })

// After (Day 2) — one line change
createAgent({
  name: "currency-converter",
  port: 3001,
  devMode: false,           // ← the only change
  privateKeyPath: "./keys/key-1.pem",
  did: "did:aroha:currency-converter",
})
```

The full zero-trust pipeline re-engages:

1. Every inbound envelope must carry an Ed25519 signature
2. The `expires` field is checked against wall-clock time
3. The `nonce` is checked against a replay registry
4. The `to` field must match this agent's DID

Your handler code changes nothing.

### Step 3 — Add a policy guard

```typescript
import { ArohaPolicyEngine } from "@aroha-sdk/policy";

const policy = new ArohaPolicyEngine();
policy.addPolicy({
  did: "*",
  capability: "convert",
  rules: [
    { type: "requiredParamKeys", keys: ["amount", "from", "to"] },
    { type: "maxSpendPerCall", maxUsd: 0.10 },
    { type: "rateLimitPerMinute", limit: 60 },
  ],
});

createAgent({ ... })
  .on("convert", async ({ body, from }) => {
    const verdict = policy.evaluate(from, "convert", body);
    if (verdict !== "allow") {
      throw new Error("Aroha_POLICY_DENIED");
    }
    // ... handler logic
  })
  .start();
```

### Step 4 — Use the saga flow for atomic transactions

The three-phase saga prevents double-billing and partial failures:

```typescript
createAgent({ ... })
  // Phase 1: reserve capacity / funds
  .on("ArohaReserve", async ({ body, correlationId }) => {
    const token = await reserveInventory(body.amount, correlationId);
    return {
      type: "ArohaReserveAck",
      body: { reservationToken: token, expiresIn: 30 },
    };
  })

  // Phase 2: commit — deduct and fulfill
  .on("ArohaCommit", async ({ body }) => {
    const result = await commitReservation(body.reservationToken);
    return {
      type: "ArohaCommitAck",
      body: { reservationToken: body.reservationToken, result },
    };
  })

  // Phase 3: cancel — release the reservation
  .on("ArohaCancel", async ({ body }) => {
    await cancelReservation(body.reservationToken);
    return { type: "ArohaCancelAck", body: {} };
  })

  .start();
```

The `@aroha-sdk/orchestrator` drives this flow automatically when you declare a capability as `transactional: true` in your DID Document.

### Step 5 — Wire up distributed tracing

Every envelope carries an optional `traceparent` field (W3C Trace Context). Use `@aroha-sdk/telemetry` to propagate spans across agent hops:

```typescript
import { ArohaTracer } from "@aroha-sdk/telemetry";

const tracer = new ArohaTracer({ serviceName: "currency-converter" });

createAgent({ ... })
  .on("convert", async ({ body, traceparent }) => {
    const span = traceparent
      ? tracer.startChildSpan("convert", traceparent)
      : tracer.startSagaSpan("convert");

    try {
      const result = await doConversion(body);
      return result;
    } finally {
      span.end();
    }
  })
  .start();
```

Spans flow through every agent hop in the request graph, landing in your OpenTelemetry collector (Jaeger, Honeycomb, Datadog — your choice).

---

## The Production Checklist

Use this table as a pre-flight check before going live:

| Concern | Day 0 (dev) | Day 2 (production) |
|---|---|---|
| **Identity** | Anonymous (`devMode: true`) | `did:aroha:` + Ed25519 key pair |
| **Signature validation** | Skipped | Enforced on every inbound message |
| **Nonce replay protection** | Skipped | In-memory registry (swap for Redis at scale) |
| **Message expiry** | Skipped | Enforced (`expires` checked against wall clock) |
| **Policy enforcement** | None | `@aroha-sdk/policy` with per-capability rules |
| **Saga flow** | Auto-committed by `@aroha-sdk/micro` | Explicit Reserve → Commit → Cancel handlers |
| **TLS** | Plain HTTP (`localhost`) | TLS-terminating reverse proxy (nginx, Caddy) |
| **Key storage** | N/A | HSM or KMS — never commit private keys to git |
| **Distributed tracing** | None | `@aroha-sdk/telemetry` + OTel collector |
| **Registry** | `aroha dev` in-memory sandbox | Production Aroha Registry (or self-hosted) |
| **Rate limiting** | None | `rateLimitPerMinute` rule in `@aroha-sdk/policy` |
| **Secrets** | Hardcoded (fine for demos) | Environment variables / secret manager |

The protocol is designed so that flipping `devMode` from `true` to `false` is the only mandatory production change. Everything else on this list is defence-in-depth.
