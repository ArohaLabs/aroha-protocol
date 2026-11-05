<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Mandates as JWTs

**Status: unreleased.** This is in the repository and will ship in the next SDK release. It is implemented in the TypeScript and Python SDKs, the reference MCP server and the registry server. It is not implemented in the Go or Java SDKs, and it has not been tested against any hosted assistant.

A mandate can be issued as a JSON Web Token. It is the same mandate, with the same limits and the same chain rules, written so that a service with an ordinary JWT library can read it and verify its signature. The specification is [§6.10](../spec/aroha-1.0.md#610-mandate-token-jwt-form-optional).

Use it when the service that receives a mandate already handles OAuth access tokens: it has a JWT library, it fetches each issuer's keys from a URL, and it reads `iss`, `sub` and `exp`. Together with [web identities](web-identities.md), a mandate then looks like the tokens that service already accepts.

The native token stays the default. Nothing changes for code that does not ask for the JWT form.

## What a mandate JWT looks like

Each link of a chain is one JWT, signed by the party that granted it.

```json
{ "alg": "EdDSA", "typ": "aroha-mandate+jwt", "kid": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" }
```

```json
{
  "iss": "https://agents.example.com/assistant",
  "sub": "https://shop.example.net/agents/checkout",
  "jti": "22222222-2222-4222-8222-222222222222",
  "iat": 1767225600,
  "exp": 1767229200,
  "authorization_details": [
    {
      "type": "https://aroha-labs.com/mandates/spending",
      "mandateTier": "cart",
      "constraints": { "spendLimitUsd": 300, "merchantCategory": "4511" },
      "parentMandateId": "11111111-1111-4111-8111-111111111111"
    }
  ]
}
```

| Claim | Mandate field |
|---|---|
| `iss` | `grantor`: who granted this link |
| `sub` | `grantee`: who may use it |
| `jti` | `mandateId` |
| `iat`, `exp` | `issuedAt`, `expiresAt`, in whole seconds |
| `authorization_details[0]` | Everything else: the tier, the limits, the parent's id. `type` says spending or task |

`authorization_details` is the member OAuth Rich Authorization Requests (RFC 9396) uses to say what a token is good for.

A chain is its link JWTs joined by `~`, root first:

```
<intent JWT>~<cart JWT>~<payment JWT>
```

A root mandate is a single, plain JWT. A task mandate is one JWT per link, carried as a list the way native task mandates are.

## Issue

Ask for the JWT form when you issue the root. Every mandate attenuated from it is a JWT too.

```typescript
import { issueIntentMandate, attenuateToCart } from "@aroha-sdk/credentials";

const intent = await issueIntentMandate(
  "https://accounts.example.com/people/kiri", "https://agents.example.com/assistant",
  { spendLimitUsd: 500, merchantCategory: "4511" }, humanPrivateKey, 3_600_000,
  { format: "jwt" },
);
// intent.token is one JWT.

const cart = await attenuateToCart(intent, "https://shop.example.net/agents/checkout",
  { spendLimitUsd: 300, merchantCategory: "4511" }, assistantPrivateKey);
// cart.token is "<intent JWT>~<cart JWT>".
```

Task mandates take the same option: `issueTaskMandate(…, { format: "jwt" })`.

Times in a JWT are whole seconds, so a JWT mandate can expire up to one second sooner than the lifetime you asked for.

## Verify

The same call verifies both forms. It tells them apart by itself.

```typescript
import { createMandateKeyResolver, verifyMandateChain } from "@aroha-sdk/credentials";

const result = await verifyMandateChain(cart.token, createMandateKeyResolver({ web: true }), {
  expectedRoot: "https://accounts.example.com/people/kiri",
  expectedGrantee: "https://shop.example.net/agents/checkout",
  isRevoked: null, // or your revocation hook
});
```

Everything that takes a token accepts the JWT form: `verifyMandate`, `enforceSpendingConstraints`, `verifyTaskMandate`, `verifyTaskMandateChain`, the HTTP presentation header, the MCP presentation, `revokeMandate`, `httpRedemptionStore`, the reference MCP server's `verify_mandate` and the registry's revoke and redeem endpoints.

### Python

```python
from aroha.mandate import SpendingConstraints, attenuate_to_cart, issue_intent_mandate, verify_mandate_chain

intent = issue_intent_mandate(human, assistant, SpendingConstraints(spend_limit_usd=500), human_key, format="jwt")
cart = attenuate_to_cart(intent, shop, SpendingConstraints(spend_limit_usd=300), assistant_key)
result = verify_mandate_chain(cart.token, expected_root=human, expected_grantee=shop)
```

## With a stock JWT library

A general JWT library verifies one link. This is `jose`, using the key set a [web identity](web-identities.md) publishes:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

const link = token.split("~").at(-1)!; // the leaf
const { payload } = await jwtVerify(link, createRemoteJWKSet(new URL(jwksUri)), {
  issuer: "https://agents.example.com/assistant",
  typ: "aroha-mandate+jwt",
  algorithms: ["EdDSA"],
});
const limit = payload.authorization_details[0].constraints.spendLimitUsd;
```

That tells you the link is genuine: the named party signed it and its `exp` has not passed.

**It does not tell you the mandate is valid.** A JWT library does not know that:

- a child must narrow its parent. A cart for $5,000 under a $500 intent is a perfectly well-signed JWT;
- the links have to join into a chain, each granted by the party the one above it named;
- the chain has to start at a root you trust;
- any link may have been revoked;
- `validFrom` and `validUntil` also limit when a mandate is valid. A JWT library does not read them;
- `kid` does not choose the key. A mandate verifier uses the identity's first eligible key, so a link signed with a second key in the set is refused.

Those are the mandate rules, and `verifyMandateChain` applies them to both forms. Use a JWT library to read a mandate or to pre-check a link. Use `verifyMandateChain` before you act on one.

## What is strict, and why

- **`typ` is required.** A mandate JWT has `typ: aroha-mandate+jwt`, so an access token or an identity token signed by the same key is never read as a mandate. A consumer that accepts other JWTs must check `typ` too, or it could read a mandate as one of those.
- **Only six claims, and no unknown members.** `iss`, `sub`, `jti`, `iat`, `exp`, `authorization_details`. A JWT with any other claim, or an unknown member in `authorization_details` or its constraints, is refused. A member that one consumer enforces and the mandate verifier ignores would let the two disagree about the same token.
- **`sub` is the agent, not the user.** It is the party the mandate was granted to. OAuth access tokens usually put the user there, so do not read it that way here.
- **`~` is not SD-JWT.** The first link is the root, the widest authority. Do not split a token and read the first part. The leaf is the last link.
- **A JWT expires at `exp`,** as RFC 7519 says, not one instant later.
- **Portable values.** Nesting stops at 32 levels, numbers stay within 2^53 − 1, text must be well-formed Unicode with no byte order mark, member names may not repeat, and `validFrom` and `validUntil` take exactly one date form, so every SDK reads a token the same way.
- **Only `alg`, `typ` and `kid` in the header.** A key carried in the token (`jwk`, `jku`, `x5c`) is refused. The key always comes from the grantor's identity, never from the token.
- **`alg` is `EdDSA`** (or `Ed25519`, its newer name). Nothing else, including `none`.
- **One form per chain.** A mandate is issued in one form and its children keep it. The signature covers different bytes in each form, so a token cannot be converted.

## Not included

- **An audience.** A mandate is not bound to one service by a claim. The holder proves possession for each request with the [presentation](../spec/aroha-1.0.md#69-mandate-presentation) header, which names the service.
- **Key binding in the token** (`cnf`, DPoP). The holder is the `sub`, and its key is resolved from its identity.
- **A token status list.** Revocation is the `isRevoked` hook and the registry, as for native tokens.
- **Issuing by an OAuth authorization server.** Mandates are signed by the party that grants them. Mapping a mandate onto a token an authorization server issues, for example through token exchange, is not defined here.
- **Go and Java.** Not implemented.
- **The reference MCP server's issuing tools** still issue native tokens. `verify_mandate` accepts both forms.

## Conformance

Both SDKs are checked against [`mandate-jwt-v1.json`](https://github.com/ArohaLabs/aroha-protocol/blob/main/packages/aroha-credentials/test-vectors/mandate-jwt-v1.json): 7 links that must decode to a given body, and 64 tokens of which 54 must be refused. The Python SDK also reproduces each JWT byte for byte. The TypeScript tests verify mandates with `jose`, and verify a JWT that `jose` signed.
