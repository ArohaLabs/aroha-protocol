# @aroha-sdk/resilience

Circuit breakers, retries, bulkheads, rate limits and load shedding for Aroha agent chains —
mandate chains must survive transient failures.

## Install

```bash
npm install @aroha-sdk/resilience
```

## Quick example

```typescript
import { CircuitBreaker, RetryPolicy, Bulkhead, CircuitOpenError } from "@aroha-sdk/resilience";
import { ArohaClient } from "@aroha-sdk/core";

const client = new ArohaClient();
const breaker = new CircuitBreaker({ failureThreshold: 5, windowMs: 60_000, recoveryTimeoutMs: 30_000 });
const retry = new RetryPolicy({
  maxAttempts: 3,
  baseMs: 200,
  isRetryable: (err) => !(err instanceof CircuitOpenError), // don't hammer an open circuit
});
const bulkhead = new Bulkhead({ maxConcurrent: 10, maxQueue: 50 });

// Per-agent circuit (keyed by DID) → bounded concurrency → retries with jittered backoff.
// The per-attempt timeout is the transport's own (SendOptions.timeoutMs).
const reply = await retry.execute(() =>
  breaker.execute(flightAgentDID, () =>
    bulkhead.execute(() => client.send(flightAgentEndpoint, requestEnvelope, { timeoutMs: 5_000 })),
  ),
);
```

## Why this exists in the mandate chain

A mandate has a TTL. If a sub-agent call fails and retries exhaust the TTL, the mandate expires —
which is the correct behaviour. These primitives let mandate chains handle transient failures
without exceeding scope or TTL, and stop a failing provider from consuming the whole budget of
attempts.

## API

- `RetryPolicy({ maxAttempts?, baseMs?, capMs?, isRetryable?, onRetry? })` — `execute(fn)`; `withRetry(config, fn)` shorthand.
- `CircuitBreaker({ failureThreshold?, windowMs?, recoveryTimeoutMs? })` — `execute(agentDID, fn)`, `stateOf(agentDID)`; throws `CircuitOpenError` while open.
- `Bulkhead({ maxConcurrent?, maxQueue? })` / `PriorityBulkhead` — bounded concurrency; `BulkheadRejectedError` when full.
- `HealthChecker` — preflight probes (`ready` / `degraded` / `draining` / `unreachable`).
- `PerDidRateLimiter` + `createRateLimitMiddleware`, `LoadShedder` + `createLoadShedMiddleware` — server-side protection.
- Speculative (hedged) execution helpers.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
