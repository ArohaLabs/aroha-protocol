<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Agent on Cloudflare Workers

Deploy a globally-distributed Aroha provider agent across Cloudflare's 300+ edge locations.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/cloudflare)

## What this deploys

A Aroha-compliant provider agent running at the edge:
- Serves DID Document at `/.well-known/aroha-agent.json`
- Accepts signed `ArohaRequest` envelopes at `/aroha/v1`
- Validates Ed25519 signatures using `@noble/ed25519` (pure JS, no Node.js required)
- Returns signed `ArohaResponse` envelopes from the nearest PoP

## Setup

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd aroha-protocol/examples/cloudflare
npm install
npx wrangler login

# Set secrets (nothing identity-related is committed in wrangler.toml)
npx wrangler secret put AROHA_PRIVATE_KEY        # base64 of the 32-byte Ed25519 seed
npx wrangler secret put AROHA_AGENT_DID          # did:aroha:my-cloudflare-agent
npx wrangler secret put ORCHESTRATOR_DID         # DID allowed to call this agent
npx wrangler secret put ORCHESTRATOR_PUBLIC_KEY  # base64 of its 32-byte public key

# Check without deploying (no Cloudflare account needed), then deploy
npm run check
npx wrangler deploy
```

For `wrangler dev`, put the same four values in a `.dev.vars` file (git-ignored — never commit it).

> The deploy button and `git clone` URL point at `github.com/ArohaLabs/aroha-protocol`.

The worker imports from `@aroha-sdk/core/messages`, not the package root: the root also exports the
Node transport (ws, undici, fs), which cannot run in a Worker. This example installs the
**published** `@aroha-sdk/core` from npm (CI type-checks it and runs `wrangler deploy --dry-run`
against that), so it reflects the latest release, not unreleased code in this repository.

## Environment variables / secrets

| Variable | Description |
|----------|-------------|
| `AROHA_PRIVATE_KEY` | Base64 of the 32-byte Ed25519 private key (seed) |
| `AROHA_AGENT_DID` | Your agent's DID |
| `ORCHESTRATOR_DID` | DID of the calling agent allowed to call this agent |
| `ORCHESTRATOR_PUBLIC_KEY` | Base64 of that caller's 32-byte public key |

### Generate keys

```bash
node -e "
const { generateKeyPairSync } = require('crypto');
const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
console.log('AROHA_PRIVATE_KEY=' + Buffer.from(jwk.d, 'base64url').toString('base64'));
console.log('public key (give to callers)=' + Buffer.from(jwk.x, 'base64url').toString('base64'));
"
```

## Add capabilities

Edit `aroha-worker.ts` — extend `handleCapability()`:

```typescript
async function handleCapability(capability: string, params: Record<string, unknown>) {
  switch (capability) {
    case "weather": {
      const res = await fetch(`https://api.weather.com/v1/current?city=${params.city}`);
      return res.json();
    }
    case "translate": {
      // Call any edge-compatible API
      return { translated: `[${params.text}] in ${params.lang}` };
    }
    default:
      return null;
  }
}
```

## Architecture

```
Calling agent  (anywhere on the internet)
      │  POST /aroha/v1  { ArohaRequest, proof: Ed25519Signature2020 }
      ▼
Cloudflare Worker  (nearest of 300+ PoPs)
      │
      ├── GET /.well-known/aroha-agent.json  → DID Document
      │
      └── POST /aroha/v1
              │
              ├── validateEnvelope()  — sig ✓, expiry ✓, nonce ✓
              ├── handleCapability()  — your business logic
              └── buildEnvelope("ArohaResponse")  — signed reply
```

## Production checklist

- [ ] **Replay protection.** The example's `NonceRegistry` lives at module scope, so it remembers
  nonces only within one isolate. Cloudflare runs many isolates and recycles them, so an envelope
  replayed to another isolate inside its validity window is accepted. Record nonces in a
  **Durable Object** (one strongly consistent owner per agent) before going to production.
  Cloudflare KV is not enough: it is eventually consistent, so two isolates can both miss a nonce.
- [ ] Use Durable Objects for stateful saga coordination (Reserve → Commit state)
- [ ] Add your agent to the [Aroha ecosystem registry](../../community/registry.json)
- [ ] Set a custom domain via `wrangler.toml` routes for a stable `AROHA_AGENT_DID`

## Why Cloudflare Workers?

| | Cloudflare Workers | AWS Lambda | Vercel Functions |
|---|---|---|---|
| Cold start | ~0 ms | 50–500 ms | ~50 ms |
| Global PoPs | 300+ | 33 regions | Edge network |
| Free tier | 100k req/day | 1M req/month | 100 GB-hours |
| `@noble/ed25519` | ✓ native | ✓ | ✓ |
| WebSockets | ✓ | ✗ | ✗ |
| Aroha fit | Excellent | Good | Good |
