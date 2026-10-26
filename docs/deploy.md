<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# 1-Click Deploy

Deploy a Aroha provider agent to serverless infrastructure in under two minutes — no local Node.js environment required.

---

## Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/vercel&env=AROHA_PRIVATE_KEY,AROHA_AGENT_DID,ORCHESTRATOR_DID,ORCHESTRATOR_PUBLIC_KEY&envDescription=Aroha+agent+identity+keys)

The Vercel deployment runs a Aroha provider agent as a serverless function:

- **Endpoint:** `https://<your-project>.vercel.app/aroha/v1` (rewritten to `api/aroha`)
- **DID Document:** `https://<your-project>.vercel.app/.well-known/aroha-agent.json`
- **Runtime:** Node.js 22 serverless function

**What you get after clicking the button:**

1. Vercel forks `examples/vercel/` into your GitHub account
2. You set four environment variables:
   - `AROHA_PRIVATE_KEY` — base64-encoded Ed25519 private key
   - `AROHA_AGENT_DID` — e.g. `did:aroha:my-vercel-agent`
   - `ORCHESTRATOR_DID` — DID of the calling agent that may call this agent
   - `ORCHESTRATOR_PUBLIC_KEY` — base64 public key of that caller
3. Vercel builds and deploys — your agent is live

**Generate keys:**

```bash
node -e "
const { generateKeyPairSync } = require('crypto');
const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
console.log('AROHA_PRIVATE_KEY=' + Buffer.from(jwk.d, 'base64url').toString('base64'));
console.log('public key (give to callers)=' + Buffer.from(jwk.x, 'base64url').toString('base64'));
"
```

**Add capabilities** by editing `api/aroha.ts` in your forked repo — add entries to the `handlers` map:

```typescript
const handlers = {
  "search-products": async (params) => {
    const results = await myDb.search(params.query);
    return { results };
  },
};
```

**Production note:** Replace the in-process `NonceRegistry` with shared storage (for example Redis); otherwise replay protection does not hold across function instances.

[Full Vercel setup guide →](https://github.com/ArohaLabs/aroha-protocol/blob/main/examples/vercel/README.md)

---

## Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/cloudflare)

The Cloudflare deployment runs at the edge:

- **Endpoint:** `https://<your-worker>.workers.dev/aroha/v1`
- **DID Document:** `https://<your-worker>.workers.dev/.well-known/aroha-agent.json`
- **Runtime:** V8 isolate (no Node.js APIs — pure Web APIs)

**Deploy with `wrangler`:**

```bash
# Install Wrangler
npm install -g wrangler
wrangler login

# Clone the example
git clone https://github.com/ArohaLabs/aroha-protocol
cd aroha-protocol/examples/cloudflare
npm install

# Set secrets
wrangler secret put AROHA_PRIVATE_KEY
wrangler secret put AROHA_AGENT_DID
wrangler secret put ORCHESTRATOR_DID
wrangler secret put ORCHESTRATOR_PUBLIC_KEY

# Deploy globally
wrangler deploy
# ✅  Deployed to https://aroha-agent.<yoursubdomain>.workers.dev
```

**Add capabilities** in `aroha-worker.ts` — extend the `handleCapability` switch:

```typescript
case "translate": {
  const res = await fetch(`https://api.deepl.com/v2/translate`, {
    method: "POST",
    body: new URLSearchParams({ text: params.text, target_lang: params.lang }),
    headers: { Authorization: `DeepL-Auth-Key ${env.DEEPL_KEY}` },
  });
  return res.json();
}
```

**Production note:** the example's `NonceRegistry` remembers nonces only within one isolate. Record nonces in a Durable Object (one strongly consistent owner per agent) for replay protection across isolates; Cloudflare KV is eventually consistent and is not enough.

[Full Cloudflare setup guide →](https://github.com/ArohaLabs/aroha-protocol/blob/main/examples/cloudflare/README.md)

---

## Comparison

| | Vercel | Cloudflare Workers |
|---|---|---|
| Cold start | ~50 ms | ~0 ms |
| Global PoPs | Edge network | 300+ |
| Free tier | 100 GB-hours/mo | 100k req/day |
| Node.js APIs | ✓ | ✗ (Web APIs only) |
| WebSockets | ✗ | ✓ |
| KV store | Vercel KV | Cloudflare KV |
| Durable Objects | ✗ | ✓ (stateful saga) |
| Best for | Standard REST agents | Ultra-low-latency + stateful saga |

---

## Run locally first

Both examples work locally before deploying:

```bash
# Vercel
cd examples/vercel && npm install
AROHA_PRIVATE_KEY=... AROHA_AGENT_DID=did:aroha:local npx vercel dev

# Cloudflare — put the four values in a git-ignored .dev.vars file first
cd examples/cloudflare && npm install
npx wrangler dev
```

---

## After deploying

Add your agent to the [Aroha ecosystem registry](ecosystem.md) by submitting a PR to `community/registry.json`:

```json
{
  "id": "my-vercel-agent",
  "type": "proxy-agent",
  "name": "My Vercel Agent",
  "package": "@yourorg/my-vercel-agent",
  "repository": "https://github.com/you/my-vercel-agent",
  "capabilities": ["search-products", "create-order"],
  "sagaCapable": true,
  "license": "Apache-2.0"
}
```
