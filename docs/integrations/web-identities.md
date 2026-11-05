<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Web identities: mandates under an HTTPS address

**Status: unreleased.** This is in the repository's `main` branch and will ship in the next SDK release. It is implemented in the TypeScript and Python SDKs and the reference MCP server. It is not implemented in the Go or Java SDKs, and it has not been tested against any hosted assistant.

A mandate says what a key may do and within which limits. A *web identity* lets you name the owner of that key with an HTTPS address you already control, instead of a `did:aroha` identifier. The address serves a small JSON document that publishes the key. The specification is [§4.7](../spec/aroha-1.0.md#47-web-identities-optional).

The document is the OAuth Client ID Metadata Document that many agent platforms already ask an agent to publish. An agent that signs in somewhere with `https://agents.example.com/shopper` as its OAuth client id can sign and hold mandates under the same address. That OAuth draft does not mention mandates; using the document this way is Aroha's choice, and no OAuth flow runs.

To see it run, [`examples/web-identities`](https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/web-identities) is the $500 flight example between three web addresses. It needs no accounts and runs offline.

The mandate token format does not change. Only the way a verifier finds the signer's key does.

## Which name to use

| | Web identity | `did:aroha:z…` / `did:aroha:E…` |
|---|---|---|
| Looks like | `https://agents.example.com/shopper` | `did:aroha:z6Mk…` |
| What the verifier needs | An HTTPS request to that address | Nothing for z-form; the Key Event Log for E-form |
| What the verifier trusts | HTTPS to that host: its DNS, its certificate, whoever runs it | Only the identifier itself |
| Works offline | No | Yes (z-form) |
| Key replacement | Publish a new key; old mandates stop verifying | E-form rotation; old mandates stop verifying |
| Governed profile root | Not allowed | E-form person |
| Good for | Agents and services that already have a web address | Offline checks, no dependence on a web host, governed deployments |

Both kinds can appear in one chain. A person can issue from a DID to an assistant named by a web address, which then delegates to a tool named by either.

## Publish an identity

Build the document from your Ed25519 public key and serve it at the address.

```typescript
import { generateKeyPair } from "@aroha-sdk/core";
import { buildWebIdentityDocument } from "@aroha-sdk/credentials";

const identity = "https://agents.example.com/shopper";
const keys = await generateKeyPair();
const document = buildWebIdentityDocument({ identity, publicKey: keys.publicKey, name: "Shopper" });
// Serve JSON.stringify(document) at `identity`.
```

The document looks like this:

```json
{
  "client_id": "https://agents.example.com/shopper",
  "client_name": "Shopper",
  "jwks": {
    "keys": [
      { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", "use": "sig", "alg": "EdDSA" }
    ]
  }
}
```

Rules for serving it:

- Answer with HTTP 200 and JSON. A redirect is refused, so serve it at exactly the address you use as the identity.
- Keep it under 5 kilobytes.
- `client_id` must equal the address, character for character.
- Publish keys inline (`jwks`) or at another HTTPS address (`jwks_uri`), not both.
- Never include a client secret or a private key. A document that carries either is refused.

If the address is already your OAuth client id, add the `jwks` member to the document you have. Pass your existing OAuth members through the `extra` option of `buildWebIdentityDocument`.

The address itself has a strict form, so that one agent has exactly one name: `https`, a lower-case host name, an optional non-default port, and a path other than `/`. No query, fragment, user information, IP address, `localhost` or name under `.localhost`. `checkWebIdentity(address)` tells you why an address is refused.

## Issue and delegate

Nothing changes. Pass the address where you would pass a DID.

```typescript
import { issueIntentMandate, attenuateToCart } from "@aroha-sdk/credentials";

const HUMAN = "https://accounts.example.com/people/kiri";
const ASSISTANT = "https://agents.example.com/assistant";
const SHOP = "https://shop.example.net/agents/checkout";

const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 200, currency: "USD" }, humanPrivateKey);
const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 80, currency: "USD" }, assistantPrivateKey);
```

Narrowing, expiry, revocation hooks, spending ledgers and the HTTP presentation header all work as they do with DIDs.

## Verify

Resolving a web identity sends an HTTPS request to a host named in the token. A verifier has to opt in.

```typescript
import { createMandateKeyResolver, verifyMandateChain } from "@aroha-sdk/credentials";

const resolveKey = createMandateKeyResolver({
  web: {
    // Recommended: say which hosts this verifier will fetch.
    allowHost: (hostname) => hostname === "accounts.example.com" || hostname.endsWith(".example.com"),
    onFailure: (identity, reason) => console.warn(`web identity ${identity}: ${reason}`),
  },
});

const result = await verifyMandateChain(cart.token, resolveKey, {
  expectedRoot: "https://accounts.example.com/people/kiri", // whose authority you accept
  expectedGrantee: "https://shop.example.net/agents/checkout", // you
  isRevoked: null, // or your revocation hook
});
if (!result.valid) throw new Error(result.reason);
```

`createMandateKeyResolver({ web: true })` uses the defaults. The same resolver still handles `did:aroha` identifiers, so one verifier accepts both.

What the resolver does on each lookup:

- Refuses an address that is not in the accepted form, without making a request.
- Asks `allowHost` before each request, for the identity and for a `jwks_uri`.
- Resolves the host name and refuses the request if any of its addresses is internal: loopback, private, link-local and the other special-use ranges. This runs on Node.js and in Python. See [Internal addresses](#what-a-verifier-should-know) for its limits.
- Does not follow redirects, and accepts HTTP 200 only.
- Reads at most 5 kilobytes of the document and 16 kilobytes of a key set, and waits at most 5 seconds.
- Takes the first Ed25519 signing key in the key set.
- Reuses a key for at most 5 minutes, or less if the response's `Cache-Control` says so. Failures are never cached.
- Returns no key on any failure, so the mandate is rejected.

### Python

```python
from aroha.mandate import create_mandate_key_resolver, verify_mandate_chain
from aroha.web_identity import build_web_identity_document, create_web_identity_resolver

document = build_web_identity_document("https://agents.example.com/shopper", public_key, name="Shopper")

resolve_key = create_mandate_key_resolver(
    web=create_web_identity_resolver(allow_host=lambda hostname: hostname.endswith(".example.com")),
)
result = verify_mandate_chain(token, resolve_key, expected_root="https://accounts.example.com/people/kiri")
```

### Reference MCP server

`verify_mandate` accepts mandates signed by web identities when the operator turns them on:

| Environment | File | Default | Meaning |
|---|---|---|---|
| `AROHA_MCP_WEB_IDENTITIES=1` | `webIdentities.enabled` | off | Resolve web identities in `verify_mandate` |
| `AROHA_MCP_WEB_IDENTITY_HOSTS` | `webIdentities.allowedHosts` | any public host | Comma-separated host names that may be fetched |

The server fetches identity documents through the same address-vetting fetch it uses for agent endpoints. It refuses hosts that resolve to loopback, private or link-local addresses.

### Reference registry

The registry's revocation and redemption endpoints verify the mandate chain themselves. They accept chains that contain web identities when the operator sets:

| Variable | Default | Meaning |
|---|---|---|
| `WEB_IDENTITIES=1` | off | Resolve web identities in `POST /v1/mandates/:id/revoke` and `/redeem` |
| `WEB_IDENTITY_HOSTS` | any host | Comma-separated host names that may be fetched |

With that set, a web identity revokes what it granted the same way a DID does:

```typescript
import { httpRevocationCheck, revokeMandate, verifyMandateChain } from "@aroha-sdk/credentials";

// The grantor, or any grantor above it in the chain, withdraws the mandate.
await revokeMandate(registryUrl, cart.token, humanPrivateKey, { revokerDid: "https://accounts.example.com/people/kiri" });

// Every verifier that asks this registry then rejects the chain.
const result = await verifyMandateChain(payment.token, resolveKey, { isRevoked: httpRevocationCheck(registryUrl) });
```

Pass `revokerDid`. The client can work out the revoker by itself only for `did:aroha:z…` grantors.

It is off by default because `/revoke` accepts tokens from anyone, so a registry that resolves web identities can be asked to fetch public addresses. The public reference registry has not been redeployed with this build.

## Replacing a key

Publish the new key as the first entry in `jwks.keys`. Verifiers pick it up when their cached copy expires, within 5 minutes by default. Mandates signed with the earlier key then stop verifying, so issue them again. This is the same rule an E-form key rotation follows, and it is why mandates are short-lived.

Removing a key works the same way: it keeps verifying until each verifier's cached copy expires.

## What a verifier should know

- **A web identity is as strong as its web host.** Whoever controls the host, its DNS records or a certificate for it can publish a key. If you need a name that no third party can change, use a `did:aroha` identifier.
- **Pin the root.** Set `expectedRoot` or `trustedRoots`. Without it, any address that publishes a key can start a chain.
- **Internal addresses.** A hostile token could name a host that resolves to an address inside your network. The SDK refuses IP addresses and `localhost` outright. On Node.js and in Python it also resolves each host name first and refuses the request if any address is special-use. Three limits remain:
  - The check does not pin the connection. The request resolves the name again, so a resolver that changes its answer in between can still get through.
  - A Cloudflare Worker or a browser has no resolver to ask, so the check does not run there.
  - If you pass your own `fetch`, the check runs only when you also pass `lookup`.

  Where this matters, set `allowHost`, use a client that pins the connection (the reference MCP server's does), or run behind a network policy that blocks private ranges. A verifier that must reach identities on a private network sets `lookup: false` and an `allowHost` list.
- **Each new signer costs a request.** A chain of eight links signed by eight different addresses means up to sixteen requests on first sight. `allowHost` and the chain depth limit bound this.

## Not included

- **A JWT by default.** Naming a party by a web address does not change the token. For a token a stock JWT library can verify, issue the mandate in the [JWT form](mandate-jwt.md).
- **Governed roots.** The governed profile still requires a `did:aroha:E…` person as the root.
- **Revocation at the public reference registry.** Registry-backed revocation covers web identities only where the registry's operator has turned it on (see [Reference registry](#reference-registry)). The public reference deployment has not. Elsewhere, use your own `isRevoked` hook and short lifetimes.
- **Message envelopes and registry records.** Agents that exchange Aroha envelopes or register in a registry still need a DID.
- **Go and Java.** Not implemented.

## Common questions

**OAuth is the standard. Why not just use it?**

Use it. OAuth decides whether an application may reach an account, and a mandate does not replace that. A mandate adds what OAuth scopes do not carry:

- limits that travel with the work: which actions, how many, how much money, until when;
- a rule that each hand-off can only narrow those limits;
- a signature at every step, which the service doing the work checks itself.

An agent can sign in with OAuth and present a mandate in the same request.

**Is this the same as on-behalf-of?**

On-behalf-of, built on OAuth token exchange (RFC 8693), is the nearest OAuth feature. A service trades the user's token at the authorization server for a new token to call the next service. Inside one organisation that often covers the need. The differences:

| | On-behalf-of | Mandate chain |
|---|---|---|
| Who decides each hop | The authorization server, which must know both services | The party handing the work on |
| Across two organisations | Needs federation set up in advance | Needs no shared server |
| Narrowing | Up to the server's policy; the flow does not require it | Required; a verifier rejects a child that widens its parent |
| What a limit can say | A scope name | Counts, amounts, time windows, a running total across the chain |
| Evidence of the chain | Recorded by the server | Each link signed by the party that granted it |

**Will OAuth add this?**

Possibly. As of November 2026 there are IETF drafts on delegated and narrowing tokens for agents, and none is a standard. Web identities keep the names OAuth already uses, so a mandate can sit next to such a token without a second identifier scheme.

## Local development

`allowLoopbackHttp: true` (Python: `allow_loopback_http=True`) also accepts `http://localhost:PORT/path` and `http://127.0.0.1:PORT/path`. Such an identity proves nothing to anyone else. Do not set it in production.

## Conformance

Both SDKs are checked against [`web-identity-v1.json`](https://github.com/ArohaLabs/aroha-protocol/blob/main/packages/aroha-credentials/test-vectors/web-identity-v1.json): 48 addresses that are accepted or refused as identities, 8 loopback cases, 64 IP addresses judged internal or not, key-id vectors from RFC 8037, and 26 documents that must resolve to a given key or fail.
