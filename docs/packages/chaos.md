<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/chaos

Deterministic and probabilistic fault injection for Aroha agents. Use in test and staging environments to verify that LIFO compensation fires correctly, circuit breakers trip as expected, and retry policies converge within acceptable attempt counts.

```bash
npm install --save-dev @aroha-sdk/chaos
```

!!! warning "Not for production"
    `@aroha-sdk/chaos` is a testing and staging tool. Never install it as a production dependency.

---

## FaultInjector

Wraps calls to an agent and either passes them through or injects the first matching fault.

```typescript
import { FaultInjector } from "@aroha-sdk/chaos";

const injector = new FaultInjector({
  rules: [
    {
      agentDID:     "did:aroha:payment-agent",
      messageTypes: ["ArohaRequest"],
      fault:        "error",
      errorMessage: "Payment gateway unavailable",
      probability:  1.0,    // always inject
    },
  ],
});

// Run a call through the injector
const reply = await injector.execute("did:aroha:payment-agent", "ArohaRequest", () =>
  client.send(paymentEndpoint, requestEnvelope),
);
```

`injector.reset()` clears the attempt counters between test cases. Pass `randomSeed` to make `probability` draws reproducible.

---

## FaultRule

```typescript
interface FaultRule {
  /** DID of the target agent. Omit to apply to all agents. */
  agentDID?: string;

  /** Message types to intercept. Omit to apply to all. */
  messageTypes?: string[];

  fault: FaultType;

  /** Additional delay before injecting the fault. Default: 0 */
  delayMs?: number;

  /** For "slow" faults: extra latency in ms. */
  slowMs?: number;

  /** For "error" faults: the error message body. */
  errorMessage?: string;

  /**
   * Probability of injecting this fault (0.0–1.0).
   * 1.0 = deterministic. Default: 1.0
   */
  probability?: number;

  /**
   * Only inject on specific attempt numbers (1-indexed).
   * E.g. [1, 2] fails twice then passes — tests retry convergence.
   */
  onAttempts?: number[];
}
```

---

## Fault types

| Fault | What it does |
|---|---|
| `"timeout"` | Delays response beyond the saga's reserve timeout |
| `"error"` | Returns an `ArohaError` response |
| `"network-drop"` | Throws a network error (connection refused) |
| `"cancel-fail"` | Succeeds on reserve/commit, fails on `ArohaCancel` |
| `"corrupt-output"` | Returns a response with a malformed body |
| `"slow"` | Adds latency without timing out |

---

## ChaosSagaRunner

`ChaosSagaRunner` injects a failure at every step position of a saga in turn and checks that every earlier step was compensated (LIFO) and nothing else was. You supply the function that runs your saga with a given step forced to fail.

```typescript
import { ChaosSagaRunner, printChaosReport } from "@aroha-sdk/chaos";

const runner = new ChaosSagaRunner(async (steps, failAt) => {
  // Run your saga with step `failAt` forced to fail; report what happened.
  return runMySaga(steps, failAt); // → { success, failures, cancelledStepIds }
});

const report = await runner.sweepFailures([
  { agentDID: "did:aroha:flight-agent",  capability: "reserve-flight" },
  { agentDID: "did:aroha:hotel-agent",   capability: "reserve-hotel" },
  { agentDID: "did:aroha:payment-agent", capability: "charge" },
]);

printChaosReport(report);
expect(report.allPassed).toBe(true);
```

`runner.injectFailureAt(steps, index)` runs a single targeted failure and returns that `ChaosRun`.

---

## Test patterns

**Retry convergence:**

```typescript
const injector = new FaultInjector({
  rules: [{
    agentDID:   "did:aroha:weather-agent",
    fault:      "error",
    onAttempts: [1, 2],   // fail twice, succeed on attempt 3
  }],
});
// Verify @aroha-sdk/resilience RetryPolicy fires exactly twice
```

**Circuit breaker trip:**

```typescript
const injector = new FaultInjector({
  rules: [{ agentDID: "did:aroha:flaky-agent", fault: "error", probability: 1.0 }],
});
// Inject 5 failures — verify CircuitBreaker transitions CLOSED → OPEN
```

**Cancel failure handling:**

```typescript
const injector = new FaultInjector({
  rules: [{ agentDID: "did:aroha:payment-agent", fault: "cancel-fail" }],
});
// Verify CompensationDLQ captures the undeliverable cancel
```
