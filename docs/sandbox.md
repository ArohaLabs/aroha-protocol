<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Sandbox Registry

!!! warning "Hosted sandbox not currently available"
    Earlier versions of this page described a public hosted sandbox at
    `sandbox.aroha.dev`. That service is **not currently available**, and the
    `aroha discover`, `aroha call`, `aroha publish` and `aroha conformance`
    commands it referenced do not exist in `@aroha-sdk/cli`. Run the sandbox
    locally instead, as described below.

## Run a local sandbox registry

`@aroha-sdk/cli` ships a local development sandbox: an in-memory capability
registry plus a live dashboard.

```bash
npx @aroha-sdk/cli dev            # registry + dashboard on http://localhost:3000
npx @aroha-sdk/cli dev --port 4000
```

The dev server exposes:

| Route | Purpose |
|-------|---------|
| `GET /` | Live HTML dashboard (registry view, event log, test-message panel) |
| `GET /registry` | Registered agents as JSON |
| `POST /registry/register` | Register an agent (used automatically by `@aroha-sdk/micro` agents with `devMode: true`) |
| `GET /events` | Server-sent event stream of registry activity |

```bash
curl http://localhost:3000/registry | jq .
```

## Pre-built sandbox agents (local)

The repository contains five mock agents in
[`examples/sandbox-agents`](https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/sandbox-agents).
They return mock data only: no real bookings, no charges.

| Agent DID | Local port | Capabilities |
|-----------|-----------|--------------|
| `did:aroha:sandbox-flight` | 3010 | `search-flights`, `book-flight`, `cancel-flight` |
| `did:aroha:sandbox-hotel` | 3011 | `search-hotels`, `book-hotel`, `cancel-hotel` |
| `did:aroha:sandbox-weather` | 3012 | `get-weather`, `get-forecast` |
| `did:aroha:sandbox-web-search` | 3013 | `search-web`, `fetch-url` |
| `did:aroha:sandbox-summarizer` | 3014 | `summarize-text`, `summarize-url` |

```bash
cd examples/sandbox-agents
docker-compose up                 # all five agents
# or a single agent:
cd flight && npm install && npm run dev
```

Call one with `curl` (the sandbox agents skip signature verification; never do
this in production):

```bash
curl -X POST http://localhost:3010/aroha/v1 \
  -H "Content-Type: application/json" \
  -d '{"type":"ArohaRequest","from":"did:aroha:test","to":"did:aroha:sandbox-flight","correlationId":"test-1","nonce":"abc123","body":{"capability":"search-flights","params":{"origin":"JFK","destination":"NRT"}},"signature":"sandbox-skip"}'
```

## Use a sandbox agent from LangChain or MCP

The bridges take any endpoint, so point them at your local agent:

```typescript
import { createArohaLangChainTool } from "@aroha-sdk/langchain-bridge";

const tool = await createArohaLangChainTool(
  "http://localhost:3010",
  "search-flights",
  "Search available flights"
);
```

```bash
npx @aroha-sdk/hermes-bridge \
  --endpoint http://localhost:3010 \
  --agent-did did:aroha:sandbox-flight
```

## Next steps

- [Architecture overview →](architecture.md)
- [Deploy to production →](deploy.md)
- [Developer journey →](developer-journey.md)
