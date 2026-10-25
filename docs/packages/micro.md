<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/micro

Lightweight scaffolding for single-capability Aroha agents. Skips the full `ArohaServer` setup — define your capabilities with `.on()`, call `.start()`, and the agent is live and registered.

```bash
npm install @aroha-sdk/micro
```

---

## createAgent()

```typescript
import { createAgent } from "@aroha-sdk/micro";

const agent = createAgent({
  name:    "weather-agent",
  port:    3001,
  devMode: true,   // auto-commits ArohaReserve (no manual settle needed in dev)
});

agent
  .on("get-weather", async ({ city }) => {
    const data = await fetchWeather(city);
    return { temperature: data.temp, condition: data.condition };
  })
  .on("get-forecast", async ({ city, days }) => {
    return await fetchForecast(city, days);
  });

await agent.start();
console.log(`Agent live at ${agent.endpoint} — DID: ${agent.did}`);
```

---

## MicroAgentOptions

```typescript
interface MicroAgentOptions {
  /** Human-readable agent name. Used in DID and registry manifest. */
  name:     string;
  /** Port to bind to. */
  port:     number;
  /**
   * Dev mode: ArohaReserve messages are auto-committed without a payment step.
   * Set to false (or omit) in production to require explicit settlement.
   * Default: false
   */
  devMode?: boolean;
}
```

---

## Capability handlers

```typescript
type CapabilityHandler = (params: Record<string, unknown>) => Promise<unknown>;
```

- Handlers receive the `params` from the inbound `ArohaRequest.body`.
- Return any JSON-serialisable value — it becomes the `result` in the `ArohaResponse`.
- Return a non-object (string, number, boolean) and micro wraps it as `{ value: <result> }`.
- Throw an `Error` and micro returns an `ArohaError` with `code: "INTERNAL_ERROR"`.
- Unknown capabilities return `ArohaError` with `code: "UNKNOWN_CAPABILITY"`.

---

## Lifecycle

```typescript
// After start(), agent.did is populated from the generated DID
await agent.start();

// agent.did      — e.g. "did:aroha:weather-agent"
// agent.endpoint — e.g. "http://localhost:3001"

// Graceful shutdown
await agent.stop();
```

---

## Chaining

`.on()` is chainable:

```typescript
createAgent({ name: "calc", port: 3002 })
  .on("add",      async ({ a, b }) => ({ result: a + b }))
  .on("subtract", async ({ a, b }) => ({ result: a - b }))
  .on("multiply", async ({ a, b }) => ({ result: a * b }))
  .start();
```

---

## When to use micro vs core

| Situation | Use |
|---|---|
| Single agent, ≤10 capabilities, rapid prototyping | `@aroha-sdk/micro` |
| Custom middleware, RBAC, streaming, enterprise features | `@aroha-sdk/core` + `ArohaServer` |
| Multi-agent orchestration | `@aroha-sdk/orchestrator` |

`@aroha-sdk/micro` wraps `@aroha-sdk/core` — you can always graduate a micro agent to a full `ArohaServer` by copying the capability handlers.
