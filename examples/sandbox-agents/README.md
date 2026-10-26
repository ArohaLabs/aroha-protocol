<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Sandbox Agents

Five pre-built Aroha agents for development and testing. Run them locally — a hosted sandbox at `sandbox.aroha.dev` was planned but is not currently available (see `docs/sandbox.md`).

| Agent | DID | Port | Capabilities |
|-------|-----|------|-------------|
| Flight | `did:aroha:sandbox-flight` | 3010 | `search-flights`, `book-flight`, `cancel-flight` |
| Hotel | `did:aroha:sandbox-hotel` | 3011 | `search-hotels`, `book-hotel`, `cancel-hotel` |
| Weather | `did:aroha:sandbox-weather` | 3012 | `get-weather`, `get-forecast` |
| Web Search | `did:aroha:sandbox-web-search` | 3013 | `search-web`, `fetch-url` |
| Summarizer | `did:aroha:sandbox-summarizer` | 3014 | `summarize-text`, `summarize-url` |

All agents return **mock data** by default — no real bookings, no external API calls.

## Run locally

```bash
# All agents via Docker Compose
docker-compose up

# Single agent
cd flight && npm install && npm run dev
```

## Test an agent

```bash
# Via curl (no auth — sandbox skips signature verification)
curl -X POST http://localhost:3010/aroha/v1 \
  -H "Content-Type: application/json" \
  -d '{"type":"ArohaRequest","from":"did:aroha:test","to":"did:aroha:sandbox-flight","correlationId":"test-1","issuedAt":"2026-07-01T00:00:00Z","nonce":"abc123","body":{"capability":"search-flights","params":{"origin":"JFK","destination":"NRT"}},"signature":"sandbox-skip"}'
```

## Enable real Claude summarization

The summarizer agent supports real Claude output when `ANTHROPIC_API_KEY` is set:

```bash
cd summarizer
ANTHROPIC_API_KEY=sk-ant-... npm run dev
```

## Deploy

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template/aroha-sandbox)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ArohaLabs/aroha-protocol)

Each agent can be deployed independently. Recommended: Fly.io or Railway for persistent Node.js servers.
