<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/micro

Lightweight scaffolding for single-capability Aroha agents. Skips the full `ArohaServer` setup — define your capabilities with `.on()`, call `.start()`, and the agent is live. In dev mode it also registers itself with a local `aroha dev` sandbox if one is running.

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
  devMode: true,   // local development only: skips inbound verification, auto-commits ArohaReserve
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
  /** Human-readable agent name. Used in the DID and for console/registry display. */
  name:     string;
  /** Port to bind to. */
  port:     number;
  /**
   * Dev mode: skip inbound signature verification and auto-commit ArohaReserve
   * without a two-phase saga. The server refuses to start with it unless
   * NODE_ENV=development. Default: false
   */
  devMode?: boolean;
  /** Registry URL. Default: AROHA_REGISTRY_URL, else the reference registry; in dev mode http://localhost:3000. */
  registryUrl?: string;
  /** Public base URL of this agent. Default: AGENT_ENDPOINT, else http://localhost:{port}. */
  endpoint?: string;
  /** Interface to bind. Default "127.0.0.1"; pass "0.0.0.0" to accept other machines. */
  host?: string;
}
```

Outside dev mode, an `ArohaReserve` is answered with an `ArohaError` — implement sagas with `ArohaServer` directly.

---

## Capability handlers

```typescript
type CapabilityHandler = (params: Record<string, unknown>) => Promise<unknown> | unknown;
```

- Handlers receive the `params` from the inbound `ArohaRequest.body`.
- Return any JSON-serialisable value — it becomes the `result` in the `ArohaResponse`.
- Return a non-object (string, number, boolean) and micro wraps it as `{ value: <result> }`.
- Throw an `Error` and micro returns an `ArohaError` with `code: "Aroha_INTERNAL_ERROR"`.
- Unknown capabilities return `ArohaError` with `code: "Aroha_UNKNOWN_CAPABILITY"`.

---

## Lifecycle

```typescript
// After start(), agent.did is populated from the generated DID (a new ephemeral DID on each run)
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
