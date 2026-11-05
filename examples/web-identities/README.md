<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Mandates between web addresses

The [$500 flight example](../mandates/README.md), with each party named by a
web address that publishes its key instead of a `did:aroha` identifier. One
script, no accounts, and it runs offline: the three addresses are served by a
small server the script starts on `127.0.0.1`.

**Status: unreleased.** Web identities are on `main` and will ship in the next
SDK release. Until then, run the script from a checkout:

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd aroha-protocol
npm ci && npm run build
node examples/web-identities/quickstart.mjs
```

After the release, `npm install @aroha-sdk/core @aroha-sdk/credentials` in this
folder is enough.

```
person       → http://127.0.0.1:56066/people/kiri
assistant    → http://127.0.0.1:56066/agents/assistant
flight agent → http://127.0.0.1:56066/agents/flights
valid: true chainVerified: true limit: 300
widening to $600 → Cannot attenuate intent → payment: child spendLimitUsd (600) exceeds parent (500)
forged link  → valid: false
after the assistant changes its key → valid: false
```

The port changes on every run.

## What it shows

- **A name you already have.** Each party is an address that serves a small
  JSON document with its public key. It is the OAuth Client ID Metadata
  Document many agents already publish.
- **The same calls.** `issueIntentMandate` and `attenuateToPayment` take the
  address where a DID would go. The token format is the same.
- **A verifier opts in.** `createMandateKeyResolver({ web: … })` fetches each
  signer's key from its address. The same resolver still accepts `did:aroha`
  identifiers.
- **Narrowing still holds.** $600 out of a $500 grant is refused.
- **The address is the authority.** A link signed by a key the address does
  not publish is refused. When the assistant replaces its key, what it signed
  with the old one stops verifying.

## From this to production

| In the script | In production |
|---|---|
| `http://127.0.0.1:PORT/...` and `allowLoopbackHttp: true` | `https://` addresses on hosts you control; leave `allowLoopbackHttp` out |
| `maxCacheMs: 0` | The default: keys reused for up to five minutes |
| `isRevoked: null` | A revocation hook, for example `httpRevocationCheck` |
| No host list | `allowHost` naming the hosts you accept |

Rules, limits and what is not included: [Web identities](../../docs/integrations/web-identities.md).
