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
| **Layer 2** — Registry | Capability manifests, discovery | Day 1 (defining what your agent can do) |
| **Layer 3** — Messaging | Signed envelopes, mandates | Day 2 (flipping `devMode` off) |
| Extensions | Sagas (Reserve → Commit → Cancel), settlement, commerce | Optional — see the [extensions document](spec/extensions.md) |

On Day 0 you operate entirely in Layer 2. The lower layers are there — you just don't see them yet.

---

## Day 0: The Hacker Experience

**Goal:** A working agent capability on localhost in under 60 seconds.

### The absolute minimum

Five lines. No config, no DID, no key. `devMode: true` is opt-in, for local development only (core refuses it unless `NODE_ENV=development`):

```typescript
import { createAgent } from "@aroha-sdk/micro";

createAgent({ name: "greeter", port: 3001, devMode: true })
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

createAgent({ name: "currency-converter", port: 3001, devMode: true })
  .on("convert", async (params) => {
    const { amount, from, to } = params as {
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
    "body": { "capability": "convert", "params": { "amount": 100, "from": "USD", "to": "EUR" } }
  }'
```

The reply is an `ArohaResponse` envelope; the handler's return value is in `body.result`:

```json
{ "type": "ArohaResponse", "body": { "capability": "convert", "result": { "converted": 92, "rate": 0.92 } }, ... }
```

No key generation. No DID resolution. No envelope signing. `devMode: true` tells `ArohaServer` to skip all cryptographic validation and dispatch straight to your handler. It is opt-in: `devMode` defaults to `false` in `@aroha-sdk/micro` (since 2.0.0), and core refuses to start with it unless `NODE_ENV=development`.

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

When you turn `devMode` off on Day 2, the handler functions you wrote on Day 0 keep the same shape (they receive the request `params`).

---

## Day 1: Bringing the Brain

**Goal:** Understand where the AI actually lives in the Aroha protocol.

Aroha is model-agnostic. Your handler function is a plain `async` function — the model is just another `await` inside it. The protocol doesn't care whether that `await` calls GPT-4o, Claude 3.5, or a fine-tuned open-source model on a local GPU.

### Pattern A — Direct SDK call (simplest)

```typescript
import { createAgent } from "@aroha-sdk/micro";
import Anthropic from "@anthropic-ai/sdk";

const claude = new Anthropic(); // reads ANTHROPIC_API_KEY from env

createAgent({ name: "currency-converter", port: 3001, devMode: true })
  .on("convert", async (params) => {
    const { amount, from, to } = params;

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
createAgent({ name: "fx-orchestrator", port: 3000, devMode: true })
  .on("fx-query", async ({ query }) => {
    const llm = new ChatAnthropic({ model: "claude-opus-4-7" });
    const agent = await createOpenAIFunctionsAgent({ llm, tools, prompt });
    const executor = new AgentExecutor({ agent, tools });
    const result = await executor.invoke({ input: query });
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

### Step 1 — Turn devMode off

`devMode` defaults to `false` in `@aroha-sdk/micro` (since 2.0.0), so turning it off means removing the option:

```typescript
// Day 0 — local development only
createAgent({ name: "currency-converter", port: 3001, devMode: true })

// Day 2 — devMode omitted (defaults to false)
createAgent({ name: "currency-converter", port: 3001 })
```

The full zero-trust pipeline re-engages:

1. Every inbound envelope must carry an Ed25519 signature
2. The `expires` field is checked against wall-clock time
3. The `nonce` is checked against a replay registry
4. The `to` field must match this agent's DID

`@aroha-sdk/micro` is limited outside devMode. It generates a new ephemeral DID and key on every `start()` (there is no option to load a persistent key), and its public-key resolver knows only the agent's own DID, so it rejects envelopes from other senders (`401 Unknown sender DID`). It also answers `ArohaReserve` with an error instead of auto-committing. For a production agent that accepts signed requests from peers, use `ArohaServer` from `@aroha-sdk/core` directly, as in the steps below.

### Step 2 — Use a real identity with `ArohaServer`

```typescript
import { ArohaServer, generateDID, buildEnvelope } from "@aroha-sdk/core";

const identity = await generateDID("currency-converter", "https://fx.example.com/aroha/v1");
// identity.did, identity.privateKey, identity.publicKey, identity.document
// Persist identity.privateKey in a secret manager or KMS. Lose it and the agent's
// cryptographic identity is gone.

const server = new ArohaServer({
  agentDID: identity.did,
  didDocument: identity.document,
  port: 3001,
  resolvePublicKey: async (senderDID) => lookUpPeerKey(senderDID), // your DID resolution
  onMessage: async (envelope, respond) => {
    if (envelope.type !== "ArohaRequest") return;
    const { capability, params = {} } = envelope.body as { capability: string; params?: Record<string, unknown> };
    const result = await convert(params); // the same handler logic as Day 0
    respond(await buildEnvelope("ArohaResponse", identity.did, envelope.from,
      { capability, result }, envelope.correlationId, identity.privateKey));
  },
});
await server.start();
```

### Step 3 — Add a policy guard

`@aroha-sdk/policy` registers one `CapabilityPolicy` per capability (`"*"` is the fallback) and mounts it as `ArohaServer` middleware. A denied request is rejected with `Aroha_FORBIDDEN` before `onMessage` runs:

```typescript
import { ArohaPolicyEngine, createPolicyMiddleware } from "@aroha-sdk/policy";

const policy = new ArohaPolicyEngine();
policy.addPolicy({
  capabilityId: "convert",
  requiredParamKeys: ["amount", "from", "to"],
  maxSpendPerCall: { amount: 10_000, currency: "USD", paramKey: "amount" },
  rateLimitPerMinute: 60,
});

const server = new ArohaServer({
  // ...options from Step 2
  middleware: [createPolicyMiddleware(policy)],
});
```

To check a request yourself, `await policy.evaluate(capability, params, senderDID)` returns `{ outcome: "allow" | "deny", violatedRule?, reason? }`.

### Step 4 — Use the saga flow for atomic transactions (optional extension)

Sagas are an optional extension, not part of the core protocol ([extensions document](spec/extensions.md)). The three-phase saga prevents double-billing and partial failures. `@aroha-sdk/micro`'s `.on()` registers capability handlers only, so handle the saga message types in the `ArohaServer` `onMessage` handler from Step 2:

```typescript
onMessage: async (envelope, respond) => {
  const reply = (type, body) => buildEnvelope(type, identity.did, envelope.from,
    body, envelope.correlationId, identity.privateKey).then(respond);
  const body = envelope.body as any;

  switch (envelope.type) {
    // Phase 1: reserve capacity / funds
    case "ArohaReserve": {
      const token = await reserveInventory(body.params?.amount, envelope.correlationId);
      const expiresAt = new Date(Date.now() + body.holdDurationMs).toISOString();
      return reply("ArohaReserveAck", { reservationToken: token, expiresAt });
    }
    // Phase 2: commit — deduct and fulfill
    case "ArohaCommit": {
      const result = await commitReservation(body.reservationToken);
      return reply("ArohaCommitAck", { reservationToken: body.reservationToken, result });
    }
    // Phase 3: cancel — release the reservation
    case "ArohaCancel": {
      await cancelReservation(body.reservationToken);
      return reply("ArohaCancelAck", { reservationToken: body.reservationToken });
    }
  }
},
```

The `@aroha-sdk/orchestrator` extension (published on npm; source not in this repository) drives this flow automatically when you declare a capability as `transactional: true` in your DID Document.

### Step 5 — Wire up distributed tracing

Every envelope carries an optional `traceparent` field (W3C Trace Context). Use `@aroha-sdk/telemetry` to propagate spans across agent hops:

```typescript
import { ArohaTracer, OtlpHttpExporter } from "@aroha-sdk/telemetry";

const exporter = new OtlpHttpExporter({ endpoint: "http://localhost:4318/v1/traces" });
const tracer = new ArohaTracer({ onSpanEnd: exporter.export });

// In the ArohaServer onMessage handler from Step 2:
onMessage: async (envelope, respond) => {
  const span = envelope.traceparent
    ? tracer.startChildSpan("convert", envelope.traceparent)
    : tracer.startSagaSpan("convert");

  try {
    // ... handle the request and respond(...)
  } finally {
    span.end();
  }
},
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
| **Policy enforcement** | None | `@aroha-sdk/policy` `CapabilityPolicy` per capability, via `createPolicyMiddleware` |
| **Saga flow** | Auto-committed by `@aroha-sdk/micro` | Explicit Reserve → Commit → Cancel handlers |
| **TLS** | Plain HTTP (`localhost`) | TLS-terminating reverse proxy (nginx, Caddy) |
| **Key storage** | N/A | HSM or KMS — never commit private keys to git |
| **Distributed tracing** | None | `@aroha-sdk/telemetry` + OTel collector |
| **Registry** | `aroha dev` in-memory sandbox | Production Aroha Registry (or self-hosted) |
| **Rate limiting** | None | `rateLimitPerMinute` field of a `@aroha-sdk/policy` `CapabilityPolicy` |
| **Secrets** | Hardcoded (fine for demos) | Environment variables / secret manager |

Turning `devMode` off (it defaults to `false`) is the mandatory production change. An agent that accepts requests from peers also needs a persistent identity and a `resolvePublicKey` that knows those peers (Steps 1–2). Everything else on this list is defence-in-depth.
