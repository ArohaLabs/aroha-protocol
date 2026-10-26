<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# `@aroha-sdk/credentials`

The `@aroha-sdk/credentials` package provides Role-Based Access Control (RBAC) and human credential issuance. It is an optional extension that plugs into the protocol kernel (`@aroha-sdk/core`) via middleware and HTTP route handlers.

```bash
npm install @aroha-sdk/credentials
```

---

## Why RBAC?

By default, an agent running `ArohaServer` accepts validly signed messages from any DID. For enterprise, B2B, or personal deployments, you need access control. `@aroha-sdk/credentials` implements the standard Aroha permission model:

### Roles

| Role | Type | Can do |
|------|------|--------|
| `human:admin` | Human | Everything |
| `human:user` | Human | query, reserve, commit, cancel, negotiate, mandate |
| `human:readonly` | Human | query only |
| `agent:orchestrator` | Agent DID | query, reserve, commit, cancel, delegate, negotiate, mandate |
| `agent:provider` | Agent DID | receives only |
| `agent:observer` | Agent DID | query only |

---

## RBAC Middleware

Mount `createRbacMiddleware` onto `ArohaServer` to automatically reject unauthorised requests before they reach your handler.

```typescript
import { ArohaServer } from "@aroha-sdk/core";
import { createRbacMiddleware } from "@aroha-sdk/credentials";

const server = new ArohaServer({
  // ... core config ...
  
  middleware: [
    createRbacMiddleware({
      resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
      resolveIssuerPublicKey: async (did) => knownPublicKeys.get(did) ?? null,
    })
  ]
});
```

---

## Human Credentials

Users authenticate to their Personal Agent out-of-band and receive a signed `HumanCredential`. This credential is mathematically linked to the user's identity and carries their roles.

### Issue a Credential

```typescript
import { issueHumanCredential, ArohaRole, serializeCredential } from "@aroha-sdk/credentials";

// Issuer side (usually a Personal Agent)
const credential = await issueHumanCredential(
  "user-alice",                          // userId
  [ArohaRole.HumanUser],                  // roles
  "did:aroha:personal-agent",             // issuerDID
  issuerPrivateKey,                      // private key used to sign
  3_600_000,                             // ttlMs (default 1 hour)
  "alice@example.com"                    // email (optional)
);

// Carry as inline token (no registry needed)
const token = serializeCredential(credential);  // base64url string
// Put in message body: { credentialToken: token }
```

### Verify a Credential

```typescript
import { verifyHumanCredential } from "@aroha-sdk/credentials";

// Receiving agent: verify manually (unless using middleware)
const result = await verifyHumanCredential(token, issuerPublicKey);

if (result.valid) {
  const roles = result.credential!.roles;
  console.log("Roles approved:", roles);
}
```

---

## CredentialRegistry

To support revocable credentials (passed by reference rather than inline tokens), you can host a `CredentialRegistry`. It exposes standard endpoints for querying and managing credentials.

```typescript
import { CredentialRegistry, credentialRegistryRoutes } from "@aroha-sdk/credentials";
import { ArohaServer } from "@aroha-sdk/core";

// Initialize the registry
const registry = new CredentialRegistry();

// Register a newly issued credential (issuer side)
await registry.register(credential, issuerPublicKey);

// Server integration to expose the HTTP API
const server = new ArohaServer({
  // ... core config ...
  httpRoutes: [
    ...credentialRegistryRoutes(registry, {
      // Required: without it, register and revoke answer 401
      resolveIssuerPublicKey: async (did) => issuerKeys.get(did) ?? null,
    })
  ]
});
```

### Registry Endpoints

When `credentialRegistryRoutes` is mounted, the following endpoints are available:

- `POST /aroha/credentials`                 — Register (verifies signature)
- `GET /aroha/credentials/:id`              — Resolve by ID
- `GET /aroha/credentials?userId=...`       — List user's credentials
- `DELETE /aroha/credentials/:id`           — Revoke (requires `X-Revoke-Proof` header)

If a message arrives with `credentialId` instead of `credentialToken`, the `createRbacMiddleware` will automatically attempt to fetch and verify the credential from the registry.

---

## Spending Mandates

`ArohaSpendingMandate` lets users grant agents the authority to spend on their behalf — without ever exposing raw payment credentials. Mandate constraints are **monotonically narrowing**: each delegation hop can only tighten limits, never widen them.

### Delegation chain

```
User (intent)
  └── Personal Agent (cart) — narrows to specific purchase
        └── Provider Agent (payment) — narrows to single transaction
```

### Issue an Intent Mandate

```typescript
import { issueIntentMandate } from "@aroha-sdk/credentials";

// User grants their Personal Agent a broad spending intent
const mandate = await issueIntentMandate(
  "did:aroha:personal-agent-alice",   // grantorDID (user's identity)
  "did:aroha:personal-agent",         // granteeDID
  {
    spendLimitUsd:               500,
    requireHumanApprovalAboveUsd: 100,
    allowedMerchants:            null,   // any
    currency:                    "USD",
  },
  userPrivateKey,
  3_600_000              // ttlMs: 1 hour
);
// mandate.token — base64url signed payload, carry in ArohaSpendingMandate messages
```

### Attenuate to Cart

When the Personal Agent has identified a specific purchase, it narrows the mandate:

```typescript
import { attenuateToCart } from "@aroha-sdk/credentials";

const cartMandate = await attenuateToCart(
  mandate,                            // parent intent mandate
  "did:aroha:shopping-orchestrator",   // granteeDID
  {
    spendLimitUsd:    79.99,
    allowedMerchants: ["did:aroha:bookshop-agent"],
    currency:         "USD",
  },
  personalAgentPrivKey
);
```

### Attenuate to Payment

Final hop — provider receives the narrowest mandate:

```typescript
import { attenuateToPayment } from "@aroha-sdk/credentials";

const paymentMandate = await attenuateToPayment(
  cartMandate,
  "did:aroha:bookshop-agent",
  {
    spendLimitUsd: 79.99,
    currency:      "USD",
    validUntil:    new Date(Date.now() + 60_000).toISOString(),
  },
  orchestratorPrivKey
);
```

### Verify a Mandate

```typescript
import { verifyMandate } from "@aroha-sdk/credentials";

const result = await verifyMandate(
  paymentMandate.token,
  granterPublicKey,
  "did:aroha:bookshop-agent",   // expectedGrantee
);

if (result.valid) {
  const { spendLimitUsd, allowedMerchants } = result.mandate.constraints;
  // Proceed with transaction ≤ spendLimitUsd
}
```

`verifyMandate` checks a single link. To accept a mandate from another party, use `verifyMandateChain`, which walks every link back to a root you trust (see the [package README](https://github.com/ArohaLabs/aroha-protocol/tree/main/packages/aroha-credentials#readme)).

### Constraint narrowing rules

| Constraint | Rule |
|------------|------|
| `spendLimitUsd` | Child ≤ parent |
| `sessionLimitUsd` | Child ≤ parent (if set) |
| `allowedMerchants` | Child ⊆ parent (or parent is `null` = any) |
| `requireHumanApprovalAboveUsd` | Child ≤ parent (lower threshold = tighter) |
| `validUntil` | Child ≤ parent |

Passing a wider constraint throws an `Error` before signing.
