<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/cache

**Semantic caching** — eliminate redundant LLM inference cycles by caching ArohaRequest → ArohaResponse pairs with content-addressed keys.

> If the Jira Agent asks the GitHub Agent for "Open PRs for Ticket-123" five times in a day, the second through fifth calls return instantly from cache with zero LLM inference.

---

## The problem it solves

Agent-to-agent networks amplify token costs. A single saga involving five agents, each making two inter-agent calls, incurs 10× the inference cost of a single agent. Repeated lookups — open issues, flight prices, product availability — spend tokens on questions that haven't changed since the last call.

`@aroha-sdk/cache` makes repeated ArohaRequest calls free after the first one.

---

## How it works

**Cache key**: SHA-256 of `capability + canonical JSON of params` (key-order independent). Identical requests from different agents, using different correlation IDs and envelope nonces, hash to the same cache key.

**Client-side** (`CachingArohaClient`): Intercepts `send()` calls before the network. Cache hit → return synthesized ArohaResponse immediately. Cache miss → send to network, store the response.

**Server-side** (`withCaching`): Wraps `onMessage` handler. Cache hit → build and sign a fresh ArohaResponse from cached data. Cache miss → call real handler, cache the response.

Only `ArohaRequest` messages are cached. Saga protocol messages (`ArohaReserve`, `ArohaCommit`, `ArohaCancel`) always pass through — they have side effects that must not be replayed from cache.

---

## Installation

```bash
npm install @aroha-sdk/cache
# For Redis backend:
npm install ioredis
```

---

## Client-side caching (orchestrator)

```typescript
import { CachingArohaClient, InMemorySemanticCache } from "@aroha-sdk/cache";

const client = new CachingArohaClient({
  cache: new InMemorySemanticCache(),
  ttl: {
    defaultTtlMs: 5 * 60 * 1000,   // 5 minutes default
    perCapability: {
      "search-flights": 60 * 1000,  // flights change fast — 1 minute
      "get-issue": 10 * 60 * 1000,  // Jira issues change slowly — 10 minutes
      "list-products": 30 * 60 * 1000,
    },
  },
});

// Drop-in replacement for ArohaClient in SagaEngine:
const saga = new SagaEngine(client, orchestratorDID, privateKey);
```

Cache statistics:

```typescript
const stats = await client.semanticCache.stats();
console.log(`Hit rate: ${(stats.hitRate * 100).toFixed(1)}%`);
console.log(`Cached entries: ${stats.size}`);
```

Invalidate after a write operation:

```typescript
// After creating a Jira issue, invalidate all cached list-issues responses
await client.semanticCache.invalidate("list-issues");
```

---

## Server-side caching (provider)

```typescript
import { withCaching, InMemorySemanticCache } from "@aroha-sdk/cache";

const cache = new InMemorySemanticCache();

const server = new ArohaServer({
  agentDID,
  onMessage: withCaching(myHandler, {
    cache,
    agentDID,
    agentPrivateKey: privateKey,
    ttl: {
      perCapability: {
        "search-products": 2 * 60 * 1000,
      },
    },
  }),
  // ...
});
```

---

## Redis backend (shared across processes)

```typescript
import { CachingArohaClient, RedisSemanticCache } from "@aroha-sdk/cache";

const client = new CachingArohaClient({
  cache: new RedisSemanticCache({
    url: "redis://your-redis-host:6379",
    keyPrefix: "aroha:cache:",
  }),
});
```

Multiple orchestrators hitting the same Redis cache means a warm cache from one agent benefits all agents in the cluster.

---

## Model routing + caching together

Combine with `@aroha-sdk/orchestrator` `ModelRouter` to route cache-misses to cheap models:

```typescript
import { createDefaultModelRouter } from "@aroha-sdk/orchestrator";
import { CachingArohaClient } from "@aroha-sdk/cache";

const router = createDefaultModelRouter();
// search-flights → trivial → Claude Haiku
// analyze-sentiment → complex → Claude Opus

const client = new CachingArohaClient({ ttl: { defaultTtlMs: 300_000 } });
// Cache hit: 0 tokens, 0 LLM calls
// Cache miss on "search-flights": routes to Haiku (~$0.00025/call)
// Cache miss on "analyze-sentiment": routes to Opus (expensive, but infrequent)
```

---

## Cache key examples

```typescript
import { cacheKey } from "@aroha-sdk/cache";

// These two requests produce the SAME cache key:
cacheKey("search-flights", { origin: "LHR", destination: "NRT", date: "2025-05-01" })
cacheKey("search-flights", { date: "2025-05-01", destination: "NRT", origin: "LHR" })
// → "a3f7c2..." (key-order independent)

// This produces a DIFFERENT key (different date):
cacheKey("search-flights", { origin: "LHR", destination: "NRT", date: "2025-05-02" })
// → "b8d4e1..."
```

---

## What is and isn't cached

| Message type | Cached? | Reason |
|--------------|---------|--------|
| `ArohaRequest` | **Yes** | Read-only queries — safe to replay |
| `ArohaResponse` | Stored | The result that gets cached |
| `ArohaReserve` | No | Allocates inventory — must not replay |
| `ArohaCommit` | No | Finalizes transaction — must not replay |
| `ArohaCancel` | No | Rolls back transaction — must not replay |
| `ArohaError` | No | Errors are not cached |
