<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Deploy an Aroha Agent on Railway

This deploys the [quickstart agent](../quickstart/) (`@aroha-sdk/run`, Claude-backed) from this repository.

There is no published Railway template for Aroha yet, so there is no one-click button. Set the service up by hand:

1. Fork `ArohaLabs/aroha-protocol` on GitHub.
2. In [Railway](https://railway.com), choose New Project → Deploy from GitHub repo, and pick your fork.
3. In the service settings:
   - set **Root Directory** to `examples/quickstart`;
   - set **Config-as-code path** to `/examples/railway/railway.json`.
4. Set environment variables:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   HOST=0.0.0.0
   AROHA_BEARER_TOKEN=<long random secret>
   ```
   Railway sets `PORT` itself; the agent listens on it. `HOST=0.0.0.0` is
   required: the agent binds loopback by default, which Railway's proxy (and
   health check) cannot reach. Off loopback the quickstart requires request
   auth — `Authorization: Bearer $AROHA_BEARER_TOKEN`, or Aroha-signed requests
   if you leave the token unset.

`railway.json` runs `npm install`, starts the agent with `npx --yes tsx agent.ts`, health-checks `GET /health`, and restarts the service on failure.

## After deploy

```bash
curl https://<your-app>.up.railway.app/health
curl https://<your-app>.up.railway.app/.well-known/aroha-agent.json
```

To register the agent on the Aroha Hub, follow the `--register` instructions in [`examples/quickstart/agent.ts`](../quickstart/agent.ts).
