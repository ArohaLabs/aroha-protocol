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
import { CircuitBreaker, CircuitOpenError } from "@aroha-sdk/resilience";

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

Caps concurrent calls, preventing one slow agent from exhausting capacity. Use one `Bulkhead` per downstream agent; callers beyond `maxQueue` get `BulkheadRejectedError`.

```typescript
import { Bulkhead } from "@aroha-sdk/resilience";

const bulkhead = new Bulkhead({
  maxConcurrent: 10,   // max simultaneous in-flight calls
  maxQueue:      50,   // max queued calls before rejection
});

const result = await bulkhead.execute(() =>
  callSearchAgent(envelope)
);
```

---

## RetryPolicy

Exponential back-off with full jitter (`delay = random(0, min(capMs, baseMs * 2^attempt))`) and a retryable-error filter.

```typescript
import { RetryPolicy, CircuitOpenError } from "@aroha-sdk/resilience";

const retry = new RetryPolicy({
  maxAttempts: 3,       // including the first attempt
  baseMs:      200,     // default 100
  capMs:       5_000,   // default 10_000
  isRetryable: (err) => !(err instanceof CircuitOpenError),
  onRetry:     (attempt, delayMs, err) => console.warn(`retry ${attempt} in ${delayMs}ms`, err),
});

const result = await retry.execute(() => callAgent(envelope));
// or: await withRetry({ maxAttempts: 3 }, () => callAgent(envelope));
```

---

## HealthChecker

Preflight probes of agent endpoints. Each result is `ready`, `degraded`, `draining` or `unreachable`, and is cached for `cacheTtlMs`.

```typescript
import { HealthChecker } from "@aroha-sdk/resilience";

const health = new HealthChecker({
  timeoutMs:  3_000,   // per probe (default 3_000)
  cacheTtlMs: 5_000,   // reuse a result within this window (default 5_000)
});

const one = await health.check("did:aroha:travel-agent", "http://travel.example.com");

// In agent selection
const { healthy, excluded } = await health.filterHealthy([
  { agentDID: "did:aroha:travel-agent",  endpoint: "http://travel.example.com" },
  { agentDID: "did:aroha:payment-agent", endpoint: "http://pay.example.com" },
], { allowDegraded: true });
```

---

## Speculative execution

Sends the same request to multiple agents in parallel and returns the first successful response. The other in-flight calls are aborted through their `AbortSignal`.

```typescript
import { SpeculativeExecutor } from "@aroha-sdk/resilience";

const { result, winnerIndex, latencyMs } = await SpeculativeExecutor.race(
  ["did:aroha:provider-a", "did:aroha:provider-b", "did:aroha:provider-c"],
  (agentDID, signal) => callAgent(agentDID, envelope, { signal }),
  5_000,   // overall timeout in ms (default 10_000)
);
// result comes from whichever provider responded first
```

---

## LoadShedder

Rejects incoming requests when the server is overloaded, returning `429` (`AROHA_CAPACITY_EXCEEDED`, with a retry-after hint) before they reach the handler. It sheds on a token bucket (`ratePerSec`, `burst`) and on queue depth (`maxQueueDepth`).

```typescript
import { LoadShedder, createLoadShedMiddleware } from "@aroha-sdk/resilience";

const shedder = new LoadShedder({
  ratePerSec:    100,   // sustained rate (default 100)
  burst:         20,    // bucket depth (default 20)
  maxQueueDepth: 200,   // default 200
});

// Mount as ArohaServer middleware
const server = new ArohaServer({
  middleware: [createLoadShedMiddleware(shedder)],
  // ...
});
```

---

## PerDidRateLimiter

Token-bucket rate limiter, keyed by sender DID.

```typescript
import { PerDidRateLimiter, createRateLimitMiddleware } from "@aroha-sdk/resilience";

const limiter = new PerDidRateLimiter({
  ratePerSec: 10,       // per DID (default 10)
  burst:      20,       // default 20
  maxDids:    10_000,   // buckets kept before the least recently used is evicted
});

// As ArohaServer middleware: over-rate senders get 429 AROHA_RATE_LIMITED
const server = new ArohaServer({ middleware: [createRateLimitMiddleware(limiter)] /* ... */ });

// Or directly
const { allowed, retryAfterMs } = limiter.check(envelope.from);
```

---

## PriorityBulkhead

Combines bulkhead concurrency control with a priority queue so high-priority work runs before low-priority background work. A lower number means higher priority (default 5).

```typescript
import { PriorityBulkhead } from "@aroha-sdk/resilience";

const pBulkhead = new PriorityBulkhead({
  maxConcurrent: 10,
  maxQueue:      50,
});

await pBulkhead.execute(
  () => callSearchAgent(envelope),
  0,   // 0 = most important (e.g. commits); 10 = background
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
    bulkhead.execute(() =>
      retry.execute(() => callAgent(agentDID, envelope))
    )
  );
}
```

See also: [`@aroha-sdk/chaos`](chaos.md) for fault injection to test these primitives.
