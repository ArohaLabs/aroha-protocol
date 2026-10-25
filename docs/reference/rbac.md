<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# RBAC & Human Credentials

Aroha has a built-in role system enforced at the transport layer **before your application code runs**.

---

## Roles

| Role | Type | Permitted actions |
|------|------|------------------|
| `human:admin` | Human | All — query, reserve, commit, cancel, delegate, negotiate, admin |
| `human:user` | Human | query, reserve, commit, cancel, negotiate |
| `human:readonly` | Human | query only |
| `agent:orchestrator` | Agent DID | query, reserve, commit, cancel, delegate, negotiate |
| `agent:provider` | Agent DID | receive only (no RBAC restriction — accepts any inbound) |
| `agent:observer` | Agent DID | query only |

---

## Action → message type mapping

| Action | Message types |
|--------|--------------|
| `query` | `ArohaRequest`, `ArohaStream` |
| `reserve` | `ArohaReserve` |
| `commit` | `ArohaCommit` |
| `cancel` | `ArohaCancel` |
| `negotiate` | `ArohaNegotiate`, `ArohaCounterOffer`, `ArohaAccept` |
| `delegate` | `ArohaDelegate` |

---

## Configuring RBAC in ArohaServer

```typescript
import { ArohaServer } from "@aroha-sdk/core";
import { createRbacMiddleware, ArohaRole } from "@aroha-sdk/credentials";

const server = new ArohaServer({
  // ... core config
  middleware: [
    createRbacMiddleware({
      // Override the default permission matrix (optional)
      permissions: {
        [ArohaRole.HumanUser]: ["query", "reserve", "commit", "cancel"],
        [ArohaRole.AgentOrchestrator]: ["query", "reserve", "commit", "cancel", "delegate"],
        // Omitted roles get empty permissions
      },

      // Resolve roles for agent DIDs
      resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],

      // Resolve issuer public key for credential verification
      resolveIssuerPublicKey: async (issuerDID) => knownPublicKeys.get(issuerDID) ?? null,
    })
  ],
});
```

If `permissions` is omitted, the default matrix is used (table above).

---

## Human Credentials

Users authenticate out-of-band (password, OAuth, passkey) and receive a signed
`HumanCredential` from their Personal Agent.

### Issue a credential

```typescript
import { issueHumanCredential, ArohaRole } from "@aroha-sdk/credentials";

const credential = await issueHumanCredential(
  "alice",                              // userId
  [ArohaRole.HumanUser],                 // roles
  "did:aroha:personal-agent-alice",      // issuerDID (this agent's DID)
  personalAgentPrivateKey,              // Uint8Array
  {
    email: "alice@example.com",
    ttlMs: 3_600_000,                   // 1 hour
  }
);
```

### Carry the credential in a message

=== "Inline token (first call)"

    ```typescript
    import { serializeCredential } from "@aroha-sdk/credentials";

    const token = serializeCredential(credential);  // base64url string

    const envelope = await buildEnvelope("ArohaRequest", fromDID, toDID, {
      capability: "search-flights",
      params: { origin: "LHR", destination: "NRT" },
      credentialToken: token,            // inline
    }, correlationId, privateKey);
    ```

=== "Registry ID (repeated calls)"

    ```typescript
    import { CredentialRegistry } from "@aroha-sdk/credentials";

    const registry = new CredentialRegistry();
    await registry.register(credential, issuerPublicKey);

    const envelope = await buildEnvelope("ArohaRequest", fromDID, toDID, {
      capability: "book-flight",
      params: { flightId: "FL123" },
      credentialId: credential.credentialId,  // reference
    }, correlationId, privateKey);
    ```

### Verify a credential (receiving agent)

`ArohaServer` verifies credentials automatically when `createRbacMiddleware` is configured.
To verify manually:

```typescript
import { verifyHumanCredential, serializeCredential } from "@aroha-sdk/credentials";

// Inline token
const result = await verifyHumanCredential(
  credentialToken,         // base64url string from message body
  issuerPublicKey          // Uint8Array — the issuer's Ed25519 public key
);
if (result.valid) {
  const roles = result.credential!.roles;  // string[]
}

// From registry
const cred = await credentialRegistry.resolve(credentialId);
const serialized = serializeCredential(cred);
const result2 = await verifyHumanCredential(serialized, issuerPublicKey);
```

---

## Credential Registry HTTP API

Agents that host a `CredentialRegistry` expose these endpoints at the same host as `/aroha/v1`:

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| `POST` | `/aroha/credentials` | Register credential | Verifies Ed25519 signature |
| `GET` | `/aroha/credentials/:id` | Resolve by ID | Public |
| `GET` | `/aroha/credentials?userId=<id>` | List by user | Public |
| `DELETE` | `/aroha/credentials/:id` | Revoke | `X-Revoke-Proof` header (issuer signature) |

Enable by passing `credentialRegistry` to `ArohaServer`:

```typescript
import { CredentialRegistry } from "@aroha-sdk/core";

const server = new ArohaServer({
  // ...
  credentialRegistry: new CredentialRegistry(),
});
```

### Revocation

```typescript
// Revoke via HTTP (from the issuer agent)
await fetch(`https://agent.example.com/aroha/credentials/${credentialId}`, {
  method: "DELETE",
  headers: {
    "X-Revoke-Proof": revokeProofBase64url,  // Ed25519 sig over { action:"revoke", credentialId }
  },
});
```

After revocation, any message bearing that `credentialId` is rejected with `401 Aroha_UNAUTHORIZED`.

---

## Best practices

| Concern | Recommendation |
|---------|---------------|
| TTL | `human:user` ≤ 1 hour; `human:admin` ≤ 24 hours |
| Repeated calls | Use `credentialId` (registry) — shorter payloads, instant revocation |
| Single calls | Use `credentialToken` (inline) — no registry dependency |
| Issuer key | Same Ed25519 key as the agent's message signing key |
| `human:admin` | Issue sparingly; never for automated flows |
