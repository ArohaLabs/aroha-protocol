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

That's a complete, running Aroha agent. No DID setup, no key generation, no configuration file.

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

## Production mode

By default, agents run in `devMode: true` (signatures skipped, zero setup). Flip one flag for production:

```typescript
createAgent({
  name: "weather-agent",
  port: 3001,
  devMode: false,           // ← the only change
  privateKeyPath: "./keys/key-1.pem",
  did: process.env.AROHA_AGENT_DID,
})
  .on("get-weather", handler)
  .start();
```

Your handler code is unchanged. `devMode: false` re-enables Ed25519 signature verification, nonce replay protection, and expiry checks.

## API

- `createAgent(opts)` — create a `MicroAgent` instance.
  - `opts.name` — agent display name.
  - `opts.port` — port to listen on (default `3001`).
  - `opts.devMode` — skip crypto validation locally (default `true`).
  - `opts.did` — agent DID (required when `devMode: false`).
  - `opts.privateKeyPath` — path to Ed25519 PEM key (required when `devMode: false`).

- `.on(capability, handler)` — register a capability handler. Returns the agent for chaining.
  - `handler(params)` — receives the request body and returns any JSON-serialisable value.

- `.start()` — start the HTTP server. Returns `Promise<void>`.

> `createMicroAgent` is also exported as an alias for `createAgent`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).