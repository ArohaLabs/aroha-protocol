# @aroha-sdk/micro

Minimal one-file framework for spinning up an Aroha agent — the fastest path from zero to a running agent.

**Status:** ![Stable](https://img.shields.io/badge/status-stable-brightgreen)

## Install

```bash
npm install @aroha-sdk/micro
```

## 5-line quick start

```typescript
import { createAgent } from "@aroha-sdk/micro";

createAgent({ name: "greeter", port: 3001 })
  .on("greet", ({ name }) => ({ message: `Hello, ${name}!` }))
  .start();
// → Agent listening on http://localhost:3001
```

That's a complete, running Aroha agent. No DID setup, no key generation, no configuration file: an ephemeral Ed25519 DID is generated on each start.

## Real-world example

```typescript
import { createAgent } from "@aroha-sdk/micro";
import { verifyMandateChain } from "@aroha-sdk/credentials";

createAgent({ name: "weather-agent", port: 3001 })
  .on("get-weather", async ({ city, mandateToken }) => {
    // Verify the mandate chain back to the human you accept authority from
    const { valid, chainVerified, reason } = await verifyMandateChain(
      mandateToken as string,
      undefined, // default resolver: content-addressed did:aroha:z… DIDs
      { expectedRoot: process.env.AROHA_MANDATE_ROOT_DID },
    );
    if (!valid || !chainVerified) return { error: reason, status: 403 };

    const weather = await fetchWeather(city as string);
    return { temp: weather.temp, description: weather.desc, city };
  })
  .start();
// Run: npx tsx agent.ts  →  http://localhost:3001/aroha/v1  Ready
```

## Dev mode

By default (`devMode: false`) every inbound message gets Ed25519 signature verification, nonce replay protection and expiry checks. For local development you can opt in to dev mode:

```typescript
createAgent({
  name: "weather-agent",
  port: 3001,
  devMode: true,            // local development only
})
  .on("get-weather", handler)
  .start();
```

Dev mode skips inbound signature verification, answers `ArohaReserve` with an immediate `ArohaCommitAck`, registers the agent with a local `aroha dev` sandbox if one is running, and prints a banner. The server refuses to start in dev mode unless `NODE_ENV=development`. Your handler code is the same in both modes.

Outside dev mode, the agent's public-key resolver knows only the agent's own (ephemeral) DID, so envelopes from any other sender are rejected as `Unknown sender DID`, and there is no option to supply a peer key resolver or a persistent key. To accept signed requests from other agents, use `ArohaServer` from `@aroha-sdk/core` with your own `resolvePublicKey`.

## API

- `createAgent(opts)` — create a `MicroAgent` instance.
  - `opts.name` — agent display name.
  - `opts.port` — port to listen on (required).
  - `opts.devMode` — skip inbound verification locally (default `false`).
  - `opts.registryUrl` — registry URL (default `AROHA_REGISTRY_URL`, else the reference registry; in dev mode `http://localhost:3000`).
  - `opts.endpoint` — public base URL of the agent (default `AGENT_ENDPOINT`, else `http://localhost:{port}`).
  - `opts.host` — interface to bind (default `127.0.0.1`).

- `.on(capability, handler)` — register a capability handler. Returns the agent for chaining.
  - `handler(params)` — receives the request's `params` and returns any JSON-serialisable value.

- `.start()` — start the HTTP server. Returns `Promise<void>`. `.stop()` shuts it down.

> `createMicroAgent` is also exported as an alias for `createAgent`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).