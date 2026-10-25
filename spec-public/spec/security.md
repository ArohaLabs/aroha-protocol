<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Security Model

Aroha is designed for zero-trust agent communication. Every claim is cryptographically verifiable.

---

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Message impersonation | Ed25519 signature on every envelope |
| Replay attacks | Per-message nonce (random 32-byte hex) + `expires` TTL |
| Message tampering | Signature covers canonical body (sorted keys, `proof` omitted) |
| Wrong recipient | `to` DID validated by `ArohaServer` before `onMessage` |
| MITM / eavesdropping | TLS 1.3+ on all connections |
| Privilege escalation | RBAC enforced at transport layer, before application code |
| Credential forgery | Credentials signed by issuer's Ed25519 key |
| Stale credentials | `expiresAt` enforced; registry-based credentials can be revoked |
| Registry manipulation | Manifest signature verified against the agent's registered public key; for z-form and E-form DIDs the key comes from the DID / Key Event Log, so a registry cannot substitute one |
| Partial saga / dirty state | Saga LIFO compensation guarantees no partial commits |

---

## Message signing

Every envelope is signed using Ed25519 (RFC 8037):

```
signing input = UTF-8(JSON.stringify(sortedCanonical(message)))

where sortedCanonical:
  - omit the "proof" field
  - sort all keys lexicographically (recursively)
  - no whitespace

proofValue = base64url(Ed25519Sign(signingInput, privateKey))
```

Verification:

```typescript
const isValid = await ed.verifyAsync(
  fromBase64url(envelope.proof.proofValue),
  new TextEncoder().encode(JSON.stringify(sortKeys(bodyWithoutProof))),
  publicKey
);
```

---

## Nonce / replay protection

`validateEnvelope` (used by `ArohaServer`) checks, in this order — normative rules in [Aroha 1.0 §6.3](aroha-1.0.md#63-validation-rules):

1. `to` is this agent's DID.
2. Stateless time checks: `created` and `expires` parse; `expires` is not in the past; `created` is not more than the allowed skew in the future (default 30 s); `expires - created` is at most the maximum lifetime (default 5 minutes). A nonce is present.
3. **Signature** — the proof's `verificationMethod` must belong to `from`, and the Ed25519 signature must verify.
4. **Only then the nonce store:** the key `<from>:<nonce>` is checked and recorded, retained until `expires` plus any clock tolerance. A repeat is rejected as a replay.

Why the signature comes before the nonce: if the nonce were recorded first, any unauthenticated client could fill the store, or send a forged envelope carrying a legitimate sender's nonce so that the real message is later rejected as a replay. Why nonces are keyed per sender: one sender's nonce can never collide with (and consume) another sender's.

The default nonce store is in-memory, so it protects one process. Several instances serving the same DID need a shared, durable store; raising the maximum lifetime without one widens the replay window.

Nonces are 32 bytes of cryptographically random hex (`crypto.getRandomValues`).

---

## RBAC enforcement

If the `@aroha-sdk/credentials` extension is used, RBAC is enforced **before** `onMessage` is called via `createRbacMiddleware`. The server rejects unauthorized messages with a `ArohaError { code: Aroha_FORBIDDEN }` before any application code runs.

Role resolution order:

1. If `body.credentialId` present → resolve from `CredentialRegistry` → verify signature → extract roles
2. If `body.credentialToken` present → verify inline credential signature → extract roles
3. Else → resolve from `rbacPolicy` options → use agent roles

See the [RBAC reference](https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/reference/rbac.md) for the full permission matrix.

---

## Trust levels

| Level | How to achieve | Operations permitted |
|-------|---------------|---------------------|
| 0 | None | Read manifests, query registry |
| 1 | Registered with a Layer 2 registry (a minimum stake only where an optional blockchain registry requires one) | Search, negotiate |
| 2 | VC (`CorporateIdentityCredential`) from trust anchor | Reserve (low-value) |
| 3 | Reputation ≥ 8000/10000 | Reserve + commit (high-value) |
| 4 | Explicit `CapabilityAuthorizationCredential` | Full access, payments |

Trust level 4 is required for payment flows. The `WalletService` issues the
`CapabilityAuthorizationCredential` after user confirmation.

---

## Credential security

Human credentials (`HumanCredential`) are signed by the issuing agent's Ed25519 key:

```json
{
  "credentialId": "<uuid>",
  "userId": "alice",
  "roles": ["human:user"],
  "issuedAt": "...",
  "expiresAt": "...",
  "issuerDID": "did:aroha:personal-agent",
  "signature": "<base64url-Ed25519>"
}
```

Signing input:
```
UTF-8(JSON.stringify(sortedKeys({ ...credential, signature: "" })))
```

**Revocation:** Registry-based credentials (`credentialId`) can be revoked immediately.
The registry rejects any message carrying a revoked ID with `401 Aroha_UNAUTHORIZED`.
Inline tokens (`credentialToken`) cannot be revoked before `expiresAt`.

**TTL recommendation:** Issue credentials with short TTLs (≤ 1 hour for `human:user`,
≤ 24 hours for `human:admin`). Use the registry for long-lived sessions.

---

## Manifest security

Capability manifests are signed by the agent's Ed25519 key (and, with the optional blockchain
registry, published to IPFS). `ArohaDiscovery` verifies the signature against the agent's
registered public key before returning any result. A manifest with an invalid signature is silently excluded.

This ensures that:
- The endpoint in the manifest is controlled by the key owner
- The capabilities list has not been tampered with
- No MITM can substitute a different endpoint

---

## Production checklist

- [ ] TLS 1.3 on all endpoints (`/.well-known/`, `/aroha/v1`, WebSocket)
- [ ] mTLS between known peer agents (provider ↔ orchestrator)
- [ ] Private key stored in HSM or secrets manager — never in env vars or source code
- [ ] DID Document served from HTTPS (not HTTP)
- [ ] Credential TTLs ≤ 1 hour for `human:user`
- [ ] Registry-based credentials (`credentialId`) for all production sessions — enables revocation
- [ ] `ArohaServer` behind a rate limiter (replay nonce store is in-memory by default)
- [ ] Monitor for `Aroha_UNAUTHORIZED` spikes — may indicate a compromised credential
