# @aroha-sdk/chaos

Fault-injection toolkit for Aroha agents — verify that saga compensation, retries and circuit
breakers behave correctly when agents fail.

## Install

```bash
npm install -D @aroha-sdk/chaos
```

## Quick example

```typescript
import { FaultInjector, ChaosSagaRunner, printChaosReport } from "@aroha-sdk/chaos";

// 1. Wrap individual calls with configurable faults
const injector = new FaultInjector({
  rules: [
    // Fail the first two reserve attempts on the hotel agent, then succeed (retry testing)
    { agentDID: "did:aroha:hotel-agent", messageTypes: ["ArohaReserve"], fault: "network-drop", onAttempts: [1, 2] },
    // 20% of calls to any agent are slowed by 2 s
    { fault: "slow", slowMs: 2_000, probability: 0.2 },
    // Cancels to the flight agent fail — exercises the compensation dead-letter queue
    { agentDID: "did:aroha:flight-agent", fault: "cancel-fail" },
  ],
});

const reply = await injector.execute("did:aroha:hotel-agent", "ArohaReserve", () =>
  client.send(hotelEndpoint, reserveEnvelope),
);

// 2. Sweep every single-step failure position of a saga and check LIFO compensation
const runner = new ChaosSagaRunner(async (steps, failAt) => {
  // Run your saga with step `failAt` forced to fail; report what happened.
  return runMySaga(steps, failAt); // → { success, failures, cancelledStepIds }
});

const report = await runner.sweepFailures([
  { capability: "book-flight", agentDID: "did:aroha:flight-agent" },
  { capability: "book-hotel", agentDID: "did:aroha:hotel-agent" },
  { capability: "charge-card", agentDID: "did:aroha:payments-agent" },
]);
printChaosReport(report);
// report.allPassed === true when every earlier step was compensated and nothing else was
```

## Why this exists in the mandate chain

Spending authority is only safe if a failed saga releases what it reserved. `@aroha-sdk/chaos`
injects failures at every step so you can confirm that compensation runs in the right order and
that no reservation is left behind.

## API

- `new FaultInjector({ rules, randomSeed? })` — `injector.execute(agentDID, messageType, fn)` runs `fn` or injects the first matching fault; `injector.reset()` clears attempt counters. With `randomSeed`, `probability` draws come from a seeded PRNG, so runs are reproducible (`reset()` rewinds it); without it, `Math.random` is used.
- `FaultRule` — `{ agentDID?, messageTypes?, fault, delayMs?, slowMs?, errorMessage?, probability?, onAttempts? }`.
- `FaultType` — `"timeout" | "error" | "network-drop" | "cancel-fail" | "corrupt-output" | "slow"`.
- `new ChaosSagaRunner(executorFn)` — `sweepFailures(steps)` and `injectFailureAt(steps, index)` return a `ChaosSagaReport` / `ChaosRun`.
- `printChaosReport(report)` — console summary.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
