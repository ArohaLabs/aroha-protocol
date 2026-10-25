<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/resilience

Production-grade resilience primitives for Aroha orchestrators. Includes circuit breakers, bulkheads, retry policies, health checks, speculative execution, load shedding, rate limiting, and priority queuing — all designed to compose with the saga engine.

```bash
npm install @aroha-sdk/resilience
```

---

## CircuitBreaker

Per-agent-DID failure isolation using the classic CLOSED → OPEN → HALF_OPEN state machine.

```typescript
import { CircuitBreaker } from "@aroha-sdk/resilience";

const breaker = new CircuitBreaker({
  failureThreshold:  5,       // open after 5 failures within windowMs
  windowMs:          60_000,  // 1-minute sliding window
  recoveryTimeoutMs: 30_000,  // wait 30s before probing recovery
});

// Use via execute() — throws CircuitOpenError when OPEN
try {
  const result = await breaker.execute("did:aroha:payment-agent", () =>
    callPaymentAgent(envelope)
  );
} catch (err) {
  if (err instanceof CircuitOpenError) {
    // Fast-fail — don't wait for the agent to time out
  }
}

// Check state
breaker.stateOf("did:aroha:payment-agent"); // "CLOSED" | "OPEN" | "HALF_OPEN"
```

Use one `CircuitBreaker` instance (not one per call) so state persists across saga executions.

---

## Bulkhead

Caps concurrent calls to a single agent DID, preventing one slow agent from exhausting the thread pool.

```typescript
import { Bulkhead } from "@aroha-sdk/resilience";

const bulkhead = new Bulkhead({
  maxConcurrent: 10,   // max simultaneous in-flight calls
  maxQueue:      50,   // max queued calls before rejection
});

const result = await bulkhead.execute("did:aroha:search-agent", () =>
  callSearchAgent(envelope)
);
```

---

## RetryPolicy

Exponential back-off with jitter and a per-attempt filter.

```typescript
import { RetryPolicy } from "@aroha-sdk/resilience";

const retry = new RetryPolicy({
  maxAttempts:    3,
  initialDelayMs: 200,
  maxDelayMs:     5_000,
  backoffFactor:  2,
  jitter:         true,   // adds ±25% randomisation to avoid thundering herd
  retryOn:        (err) => err.code !== "UNKNOWN_CAPABILITY",
});

const result = await retry.execute(() => callAgent(envelope));
```

---

## HealthChecker

Periodically probes agent endpoints and maintains a live map of healthy DIDs.

```typescript
import { HealthChecker } from "@aroha-sdk/resilience";

const health = new HealthChecker({
  intervalMs: 30_000,
  timeoutMs:  5_000,
  agents: [
    { did: "did:aroha:travel-agent", endpoint: "http://travel.example.com" },
    { did: "did:aroha:payment-agent", endpoint: "http://pay.example.com" },
  ],
});

await health.start();

// In orchestrator agent selection
const candidates = allAgents.filter(a => health.isHealthy(a.did));
```

---

## Speculative execution

Sends the same request to multiple agents in parallel and returns the first successful response. Cancels the remaining in-flight calls.

```typescript
import { speculativeCall } from "@aroha-sdk/resilience";

const result = await speculativeCall([
  () => callAgent("did:aroha:provider-a", envelope),
  () => callAgent("did:aroha:provider-b", envelope),
  () => callAgent("did:aroha:provider-c", envelope),
], { timeoutMs: 5_000 });
// Returns whichever provider responded first
```

---

## LoadShedder

Rejects incoming requests when the server is overloaded, returning `503` before they reach the handler.

```typescript
import { LoadShedder } from "@aroha-sdk/resilience";

const shedder = new LoadShedder({
  maxQueueDepth:   100,
  cpuThresholdPct: 80,    // shed when CPU > 80%
});

// Mount as ArohaServer middleware
const server = new ArohaServer({
  middleware: [shedder.middleware()],
  // ...
});
```

---

## RateLimiter

Token-bucket rate limiter, keyed by sender DID.

```typescript
import { RateLimiter } from "@aroha-sdk/resilience";

const limiter = new RateLimiter({
  tokensPerSecond: 10,
  burstSize:       20,
});

// Returns false if the sender has exceeded their rate
if (!limiter.allow(envelope.from)) {
  return respond({ type: "ArohaError", body: { code: "RATE_LIMITED" } });
}
```

---

## PriorityBulkhead

Combines bulkhead concurrency control with a priority queue so high-priority sagas are never starved by low-priority background work.

```typescript
import { PriorityBulkhead } from "@aroha-sdk/resilience";

const pBulkhead = new PriorityBulkhead({
  maxConcurrent: 10,
  priorities:    ["critical", "standard", "background"],
});

await pBulkhead.execute(
  "did:aroha:search-agent",
  () => callSearchAgent(envelope),
  "critical",
);
```

---

## Composing primitives

The primitives are designed to be stacked — outer to inner: shed → rate limit → circuit break → bulkhead → retry → call.

```typescript
import { CircuitBreaker, Bulkhead, RetryPolicy } from "@aroha-sdk/resilience";

const breaker  = new CircuitBreaker({ failureThreshold: 5 });
const bulkhead = new Bulkhead({ maxConcurrent: 10 });
const retry    = new RetryPolicy({ maxAttempts: 3 });

async function resilientCall(agentDID: string, envelope: unknown) {
  return breaker.execute(agentDID, () =>
    bulkhead.execute(agentDID, () =>
      retry.execute(() => callAgent(agentDID, envelope))
    )
  );
}
```

See also: [`@aroha-sdk/chaos`](chaos.md) for fault injection to test these primitives.
