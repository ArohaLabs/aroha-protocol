<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Deploy an Aroha Agent on Render

This deploys the [quickstart agent](../quickstart/) (`@aroha-sdk/run`, Claude-backed) from this repository.

There is no one-click "Deploy to Render" button. Render's button reads `render.yaml` only from the root of a repository, and this repository's root has no Blueprint.

## Setup

1. Fork `ArohaLabs/aroha-protocol` on GitHub.
2. Copy `examples/render/render.yaml` to the root of your fork and commit it. Its `rootDir: examples/quickstart` keeps the service pointed at the quickstart.
3. In [Render](https://render.com), choose New → Blueprint and select your fork.
4. Set `ANTHROPIC_API_KEY` in the Render dashboard. The Blueprint also sets
   `HOST=0.0.0.0` (the agent binds loopback by default, which Render's proxy
   cannot reach) and generates `AROHA_BEARER_TOKEN`; off loopback the
   quickstart requires `Authorization: Bearer <token>` (or Aroha-signed
   requests if the token is unset).

Or skip the Blueprint and create a Web Service by hand:

| Setting | Value |
|---|---|
| Root directory | `examples/quickstart` |
| Build command | `npm install` |
| Start command | `npx --yes tsx agent.ts` |
| Health check path | `/health` |
| Environment | `ANTHROPIC_API_KEY`, `NODE_VERSION=22`, `HOST=0.0.0.0`, `AROHA_BEARER_TOKEN` |

## Why a persistent host

Inbound signed Aroha requests carry an expiry and a nonce. An always-on instance avoids cold-start delays that could push a request past its expiry. The `starter` plan in `render.yaml` stays on; the free plan sleeps.

## After deploy

```bash
curl https://<your-app>.onrender.com/health
curl https://<your-app>.onrender.com/.well-known/aroha-agent.json
```
