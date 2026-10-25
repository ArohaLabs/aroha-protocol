# @aroha-sdk/cache

Response caching for Aroha agents — avoid redundant calls when mandate-constrained budgets are tight.

## Install

```bash
npm install @aroha-sdk/cache
```

## Quick example

Client side — a drop-in `ArohaClient` that answers repeated `ArohaRequest`s from cache:

```typescript
import { CachingArohaClient, InMemorySemanticCache } from "@aroha-sdk/cache";
import { buildEnvelope } from "@aroha-sdk/core";

const client = new CachingArohaClient({
  cache: new InMemorySemanticCache(),
  ttl: { defaultTtlMs: 60_000, perCapability: { "get-forecast": 10 * 60_000 } },
});

const request = await buildEnvelope(
  "ArohaRequest", myDID, weatherAgentDID,
  { capability: "get-forecast", params: { city: "Auckland" } },
  correlationId, myPrivateKey,
);

// Identical (capability, params) requests within the TTL are served from cache.
// Only ArohaRequest is cached — saga protocol messages always go to the network.
const response = await client.send("https://weather-agent.example/aroha/v1", request);
const stats = await client.semanticCache.stats(); // { size, hitRate, totalHits, totalMisses }
```

Server side — wrap a message handler so cache hits are answered (and signed) without running it:

```typescript
import { withCaching, RedisSemanticCache } from "@aroha-sdk/cache";

const onMessage = withCaching(myHandler, {
  cache: new RedisSemanticCache({ url: "redis://localhost:6379" }), // requires ioredis
  ttl: { defaultTtlMs: 5 * 60_000 },
  agentDID,
  agentPrivateKey,
});
```

## Why this exists in the mandate chain

When an agent chain operates under a tight spending cap, redundant calls waste budget that could exceed the mandate limit. The cache layer intercepts identical requests and returns cached responses — preserving budget and reducing latency.

## API

- `new CachingArohaClient({ cache?, ttl? })` — an `ArohaClient` whose `send()` serves repeated `ArohaRequest`s from cache. `client.semanticCache` exposes the cache.
- `withCaching(handler, { cache, ttl?, agentDID, agentPrivateKey })` — wrap an `ArohaServer` message handler; cache hits are returned as signed `ArohaResponse` envelopes.
- `CacheTtlConfig` — `{ defaultTtlMs?, perCapability? }` (default TTL 5 minutes).
- `InMemorySemanticCache` / `RedisSemanticCache({ url?, keyPrefix? })` — cache backends implementing `ISemanticCache` (`get`, `set`, `invalidate(capabilityPrefix)`, `stats()`).
- `cacheKey(capability, params)` — the deterministic key both use.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
