<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Agent on Vercel

A self-contained Vercel project that runs an Aroha provider agent as a Serverless Function.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/vercel&env=AROHA_PRIVATE_KEY,AROHA_AGENT_DID,ORCHESTRATOR_DID,ORCHESTRATOR_PUBLIC_KEY&envDescription=Aroha+agent+identity+keys&envLink=https://github.com/ArohaLabs/aroha-protocol/blob/main/examples/vercel/README.md)

## What this deploys

- `api/aroha.ts`, reached through the rewrites in `vercel.json`:
  - `GET /.well-known/aroha-agent.json` serves the agent document
  - `POST /aroha/v1` accepts signed `ArohaRequest` envelopes
- Each request is checked for its Ed25519 signature, expiry, nonce replay and recipient.
- Responses are signed `ArohaResponse` or `ArohaError` envelopes.

## Run the typecheck locally

```bash
cd examples/vercel
npm install
npm run typecheck
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `AROHA_AGENT_DID` | Your agent's DID, e.g. `did:aroha:my-vercel-agent` |
| `AROHA_PRIVATE_KEY` | Base64 of the 32-byte Ed25519 private key (seed) |
| `ORCHESTRATOR_DID` | DID of the orchestrator allowed to call this agent |
| `ORCHESTRATOR_PUBLIC_KEY` | Base64 of that orchestrator's 32-byte Ed25519 public key |

### Generate a keypair

```bash
node -e "
const { generateKeyPairSync } = require('crypto');
const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
console.log('AROHA_PRIVATE_KEY=' + Buffer.from(jwk.d, 'base64url').toString('base64'));
console.log('public key (give to callers)=' + Buffer.from(jwk.x, 'base64url').toString('base64'));
"
```

## Add capabilities

Edit `api/aroha.ts` and add entries to the `handlers` map:

```typescript
const handlers = {
  "search-products": async (params) => {
    const results = await myDb.search(params.query);
    return { results };
  },
};
```

## Production checklist

- [ ] Replace the in-process `NonceRegistry` with shared storage (for example Redis). Otherwise replay protection does not hold across function instances.
- [ ] Keep `AROHA_PRIVATE_KEY` in Vercel environment secrets, never in source.
- [ ] Resolve caller keys from a registry (`@aroha-sdk/registry`) instead of a single `ORCHESTRATOR_*` pair.
