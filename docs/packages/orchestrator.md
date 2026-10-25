<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/orchestrator

> **Developed in `ArohaLabs/aroha-extensions`.** `@aroha-sdk/orchestrator` stays published on npm; its
> source moved out of the protocol repository on 2026-10-25.


Layer 4 — saga state machine, agent selection, and negotiation.

```bash
npm install @aroha-sdk/orchestrator
```

---

## SagaEngine

Executes atomic multi-agent transactions. All participants either commit or all roll back.

```typescript
import { SagaEngine } from "@aroha-sdk/orchestrator";
import { ArohaClient } from "@aroha-sdk/core";

const saga = new SagaEngine(
  arohaClient,          // ArohaClient instance
  orchestratorDID,     // string
  privateKey,          // Uint8Array
  persistLog?          // optional: async (log) => void — called after each phase
);

const result = await saga.execute([
  {
    agentDID: "did:aroha:flight-agent",
    agentEndpoint: "https://flight.example.com/aroha/v1",
    capability: "book-flight",
    params: { flightId: "FL123", passengers: 2 },
    holdDurationMs: 300_000,   // 5 minutes
  },
  {
    agentDID: "did:aroha:hotel-agent",
    agentEndpoint: "https://hotel.example.com/aroha/v1",
    capability: "book-hotel",
    params: { hotelId: "HTL456", nights: 3 },
    holdDurationMs: 300_000,
  },
]);

// result.success        boolean
// result.sagaId         string
// result.results        { [stepIndex]: commitResult }
// result.failures       { stepId, reason }[]
```

### Execution phases

```
Phase 1: RESERVE (parallel)
  For each participant: ArohaReserve → ArohaReserveAck (or ArohaError → abort)

Phase 1.5: AWAITING_APPROVAL (optional, if approvalGate is set)
  For each step where needsApproval(step) === true: pause and call approvalGate.requestApproval()
  "rejected" → trigger LIFO compensation immediately (no commit issued)
  "approved" → proceed

Phase 1.0 (read-only steps): ArohaRequest — result captured, no saga lock, skipped in commit
  Steps with readOnly: true are resolved here and never touched again.

Phase 2: COMMIT (sequential)
  For each participant (non-readOnly): ArohaCommit → ArohaCommitAck (or ArohaError → compensate)

Phase 3: COMPENSATE (LIFO, on failure)
  For each committed step in reverse: ArohaCancel → ArohaCancelAck
```

!!! important "ArohaCommit must be idempotent"
    If a commit times out and is retried, the provider must return the same result.
    Use the `reservationToken` as a database key and store the result on first commit.

---

## Human-in-the-Loop (HITL) Approval

Finance teams won't give AI agents an unlimited budget on day one. The `HumanApprovalGate` pauses the saga after all reserves succeed, waits for a human decision, and only then issues commits. A rejection triggers full LIFO compensation — no money moves, no bookings finalized.

```typescript
import { SagaEngine, WebhookApprovalGate } from "@aroha-sdk/orchestrator";

const approvalGate = new WebhookApprovalGate({
  // POST the approval request here (Slack, Teams, custom UI)
  webhookUrl: "https://your-app.com/hooks/aroha-approval",
  // Poll this endpoint until the human decides
  pollDecision: async (sagaId, stepId) => {
    const row = await db.query(
      "SELECT decision FROM approvals WHERE saga_id=$1 AND step_id=$2",
      [sagaId, stepId]
    );
    return row?.decision ?? null; // "approved" | "rejected" | null (still pending)
  },
  timeoutMs: 300_000,   // 5 minutes — reject on timeout
  secret: process.env.WEBHOOK_SECRET,  // optional HMAC signing
});

const saga = new SagaEngine(client, orchestratorDID, privateKey, {
  approvalGate,
  // Which steps need approval? Use a threshold function or per-step flag
  needsApproval: (step) => (step.estimatedCost ?? 0) > 500,
});

const result = await saga.execute([
  {
    agentDID: "did:aroha:flight-agent",
    capability: "book-flight",
    params: { flightId: "FL123" },
    holdDurationMs: 300_000,
    requiresApproval: true,
    estimatedCost: 2150,
    costCurrency: "USD",
  },
]);
```

### Available gate implementations

| Class | Description |
|-------|-------------|
| `WebhookApprovalGate` | POSTs a signed JSON payload to any webhook; polls for decision |
| `AlwaysApproveGate`   | Auto-approves every request — for development and tests |

Implement `HumanApprovalGate` directly to use Slack API, email, a mobile push notification, or any other channel.

---

## Read-only steps (fire-and-forget queries)

Not every step in a workflow needs a saga lock. Enrichment lookups, price quotes, and sentiment checks should complete instantly without holding reservations. Mark them `readOnly: true`:

```typescript
const result = await saga.execute([
  {
    agentDID: "did:aroha:twitter-scraper",
    capability: "get-btc-sentiment",
    params: { window: "24h" },
    holdDurationMs: 0,
    readOnly: true,          // ArohaRequest — no reserve token, no commit/cancel
  },
  {
    agentDID: "did:aroha:exchange-agent",
    capability: "place-order",
    params: { symbol: "BTC", side: "buy", qty: 0.5 },
    holdDurationMs: 10_000,  // normal saga step — reserve/commit/cancel
  },
]);

// result.results[0] = sentiment query result (from the readOnly step)
// result.results[1] = order placement result (from the saga step)
```

Read-only steps are executed in the same parallel fan-out as reserves. Their result is available in `result.results[stepIndex]` alongside committed steps.

---

## Async saga mode

High-throughput scenarios can't afford to wait for all commits before returning to the caller. Async mode returns an `AsyncSagaHandle` after all reservations succeed, runs commits in the background, and optionally POSTs the result to a webhook.

```typescript
const saga = new SagaEngine(client, orchestratorDID, privateKey, {
  executionMode: "async",
  webhookUrl: "https://your-app.com/hooks/saga-complete",  // optional
});

// Returns AFTER reserves succeed — commits happen in the background
const handle = await saga.executeAsync([
  { agentDID: "did:aroha:flight-agent", capability: "book-flight", ... },
  { agentDID: "did:aroha:hotel-agent",  capability: "book-hotel",  ... },
]);

console.log(`Saga ${handle.sagaId} reserved — committing in background`);

// If you need the full result later:
const result = await handle.wait();
```

When `webhookUrl` is set, the saga engine POSTs `{ sagaId, success, results, failures }` to that URL when the saga completes (success or failure). Use this for mobile push notifications, Slack alerts, or downstream pipeline triggers.

---

## AgentSelector

Fan-out `ArohaRequest` to multiple discovered agents, score responses, and return a winner.

```typescript
import { AgentSelector } from "@aroha-sdk/orchestrator";

const selector = new AgentSelector(
  arohaClient,
  orchestratorDID,
  privateKey
);

const selection = await selector.select(
  "search-flights",                  // capability
  { origin: "LHR", destination: "NRT" },  // params
  discoveredAgents,                  // DiscoveredAgent[] from ArohaDiscovery
  {
    scores: Map<string, number>,     // optional pre-computed preference scores
    timeoutMs: 10_000,
  }
);

// selection.winner.agent      DiscoveredAgent
// selection.winner.response   ArohaResponseBody
// selection.all               scored responses from all agents
```

The selector sends `ArohaRequest` to all eligible agents in parallel, waits for responses,
applies the score map, and returns the highest-scoring respondent.

---

## Negotiator

Multi-round price negotiation using `ArohaNegotiate` / `ArohaCounterOffer` / `ArohaAccept`.

```typescript
import { Negotiator } from "@aroha-sdk/orchestrator";

const negotiator = new Negotiator(arohaClient, orchestratorDID, privateKey);

const deal = await negotiator.negotiate(
  agentEndpoint,
  {
    capability: "book-flight",
    params: { flightId: "FL123" },
    maxRounds: 3,
    targetPrice: 180,      // USD
    maxPrice: 220,
    currency: "USD",
  }
);

// deal.agreed       boolean
// deal.finalPrice   number
// deal.terms        Record<string, unknown>
```

---

## Capability Schema Negotiation (CSN)

CSN lets a requestor discover a provider's capability by schema or intent, without knowing its exact name in advance. It is Aroha's superior alternative to ANP's meta-protocol: structural matching is deterministic and requires no LLM; LLM is only invoked for ambiguous cases (score 0.5–0.85); the result maps to an existing typed Aroha capability preserving all saga semantics.

See the [full CSN guide](../spec/csn.md) for message flow, scoring algorithm, and LLM adapter patterns.

### CapabilityRegistry (provider side)

Register capabilities so the `CSNHandler` can match inbound requests:

```typescript
import { CapabilityRegistry } from "@aroha-sdk/orchestrator";

const registry = new CapabilityRegistry();

registry.register({
  name:         "fx-convert",
  description:  "Convert between two currencies",
  inputSchema: {
    type: "object",
    properties: {
      amount: { type: "number" },
      from:   { type: "string" },
      to:     { type: "string" },
    },
    required: ["amount", "from", "to"],
  },
  outputSchema:   { type: "object", properties: { converted: { type: "number" } } },
  supportsSaga:   true,
  defaultPricing: { model: "per-call", amount: 0.001, currency: "USD" },
  defaultSLA:     { maxResponseMs: 500, p99Ms: 200 },
});
```

### CSNHandler (provider side)

Mount in your `ArohaServer` `onMessage` handler:

```typescript
import { CSNHandler } from "@aroha-sdk/orchestrator";

const csnHandler = new CSNHandler(registry, {
  agentDID:   "did:aroha:fx-agent",
  privateKey: agentPrivKey,
  // Optional — only called when structural score is 0.5–0.85
  llmMatcher: {
    match: async (intent, candidates) => {
      // Call any LLM — return the best capability name or null
      return callYourLLM(intent, candidates);
    },
  },
});

// In your ArohaServer onMessage:
server.onMessage = async (envelope, respond) => {
  if (envelope.type === "ArohaNegotiate" && envelope.body.csn) {
    const reply = await csnHandler.handle(envelope, envelope.from);
    respond(reply);
    return;
  }
  // ... other handlers
};
```

### CapabilityNegotiator (requestor side)

```typescript
import { CapabilityNegotiator } from "@aroha-sdk/orchestrator";

const negotiator = new CapabilityNegotiator(client, orchestratorDID, privateKey);

const result = await negotiator.discover(
  "https://fx.example.com/aroha/v1",
  "did:aroha-web:fx.example.com:agent",
  {
    capabilityIntent: "convert currency from USD to JPY",
    desiredSchema: {
      input: {
        type: "object",
        properties: {
          amount: { type: "number" },
          from:   { type: "string" },
          to:     { type: "string" },
        },
        required: ["amount", "from", "to"],
      },
    },
  }
);

// result.resolvedCapability === "fx-convert"
// result.matchMethod        === "schema"  (deterministic — no LLM)
// result.rounds             === 0         (cache hit on second call)

// Now use it in a saga step:
await saga.execute([{
  agentDID:       "did:aroha-web:fx.example.com:agent",
  agentEndpoint:  "https://fx.example.com/aroha/v1",
  capability:     result.resolvedCapability,   // ← from CSN
  params:         { amount: 100, from: "USD", to: "JPY" },
  holdDurationMs: 5_000,
}]);
```

### DiscoveryCache

CSN results are SHA-256 cached by `(agentDID, schemaHash)`. Repeat calls resolve in < 1 ms with zero network traffic.

```typescript
import { DiscoveryCache, type IDiscoveryStore } from "@aroha-sdk/orchestrator";

// Default: in-memory (process lifetime)
const cache = new DiscoveryCache();

// Production: plug in Redis or Postgres
class RedisDiscoveryStore implements IDiscoveryStore {
  async get(key: string) { return redis.get(key); }
  async set(key: string, entry: CacheEntry) { await redis.set(key, entry); }
  async delete(key: string) { await redis.del(key); }
  async keys(prefix?: string) { return redis.keys(`${prefix}*`); }
}

const persistentCache = new DiscoveryCache(new RedisDiscoveryStore());
const negotiator = new CapabilityNegotiator(client, orchestratorDID, key, persistentCache);
```

### Compatibility score thresholds

| Score | Meaning | Action |
|-------|---------|--------|
| ≥ 0.85 | Confident structural match | Accept — no LLM needed |
| 0.5–0.85 | Ambiguous | LLM fallback (if `llmMatcher` configured) |
| < 0.5 | Incompatible | Reject |

---

## SagaStep type

```typescript
interface SagaStep {
  agentDID: string;
  agentEndpoint: string;
  capability: string;
  params: Record<string, unknown>;
  holdDurationMs: number;
  // Human-in-the-loop fields (optional)
  requiresApproval?: boolean;   // flag this step for approval gate
  estimatedCost?: number;       // displayed in approval UI
  costCurrency?: string;        // ISO 4217, e.g. "USD"
}
```

## SagaState values

```typescript
type SagaState =
  | "PENDING"
  | "RESERVING"
  | "AWAITING_APPROVAL"    // paused — human decision pending
  | "COMMITTING"
  | "COMMITTED"
  | "COMPENSATING"
  | "COMPENSATED"
  | "FAILED";

type SagaStepState =
  | "PENDING"
  | "RESERVED"
  | "PENDING_APPROVAL"    // this specific step is awaiting human input
  | "COMMITTED"
  | "CANCELLED"
  | "FAILED";
```

---

## SagaResult type

```typescript
interface SagaResult {
  success: boolean;
  sagaId: string;
  results: Record<number, unknown>;   // stepIndex → ArohaCommitAck result
  failures: Array<{ stepId: number; reason: string }>;
}
```
