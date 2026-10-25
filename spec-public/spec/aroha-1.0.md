<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol
## Specification Version 1.0

**Status:** Draft — not yet submitted to any standards body. No W3C Community Group has been proposed; `did:aroha` is not registered in the W3C DID Method Registry.  
**Date:** 2026-07-27  
**Authors:** Aroha Working Group  
**HTML version:** [aroha-1.0.html](aroha-1.0.html) (W3C ReSpec format)  
**DID Method Spec:** [did-aroha-method-1.0.html](did-aroha-method-1.0.html)

---

### Revision history

| Date | Change |
|------|--------|
| 2026-10-25 | Scope: the core specification now covers Layers 0–3 (Transport, Identity, Registry, Messaging). §7 (orchestration, sagas) and §8 (preference context) moved unchanged to the [extensions document](extensions.md); §7 and §8 keep their numbers as pointers. §11 conformance items 4 and 5 now apply to implementations that adopt those extensions. |
| 2026-10-19 | New §6.9 Mandate Presentation: the holder proof that keeps a mandate from being a bearer token, with the MCP binding (`_meta["aroha/mandate"]`, previously defined only by the reference code) and a new plain-HTTP binding (`Aroha-Mandate` header) with vectors in `packages/aroha-credentials/test-vectors/http-presentation-v1.json`. §6.5: a body that carries `mandateType` is a task mandate and is refused as a spending mandate. |
| 2026-10-15 | New §12 Conversation and Memory Profile: signed rooms and membership epochs, person invitations with per-event signed consent records, turn signatures, the person-DID signing rule and speaker-kind resolution, the memory record, signed action receipts v1/v2 (outcome, denied receipts, `presentedHash`), and `ArohaDisclosure` (optional envelope field, §6.1). New §6.6 task-mandate token v2 (with `onBehalfOf` and `roomId`), §6.7 signed revocation status, §6.8 governed verifier profile — previously defined only by the reference code. Schemas in `spec-public/schemas/`, vectors in `spec-public/vectors/conversation-v1.json`. |
| 2026-10-08 | Registry: the HTTP registry (§5.1a) is the normative baseline; on-chain registration, staking and slashing are scoped to the optional blockchain registry (§5.1b). §6.3 envelope validation: maximum lifetime, `created` skew, signature-before-nonce ordering, per-sender nonce keys. §6.4 lists all 19 message types. New §6.5 normative spending-mandate token format (v2). §9 key rotation is KEL rotation for E-form DIDs. Appendix A lists all 28 error codes; Appendix B states SDK status. |
| 2026-10-07 | Identity: rotatable, self-certifying `did:aroha:E…` identifiers with Key Event Logs (pre-rotation, person controllers, controller recovery and revocation, stale-log and duplicity handling) — see the DID method specification. §4.1 lists the three `did:aroha` forms; the `z` form is marked legacy (non-rotatable) and the named form registry-trusted. §9 adds the person-root rule for delegation chains. |
| 2026-07-27 | Private resources: §3.5 `aroha-sig` caller authentication (signed material, headers, and the verifier ordering rules); §5.4 registry visibility levels and access grants, including the requirement to filter inside the query and to make an unauthorised viewer indistinguishable from a non-existent record; §5.1a grant and visibility endpoints. |
| 2026-04-28 | Kernel hardening: `auth/` directory removed from `@aroha-sdk/core` (dead duplicate of `@aroha-sdk/credentials`); `WalletService` relocated to `@aroha-sdk/settlement/payments`; Ed25519→X25519 key conversion corrected to use `edwardsToMontgomeryPub/Priv`; full Vitest suite added (100+ tests across all 10 packages). |
| 2026-04-21 | `@aroha-sdk/commerce` extension complete (B2B, B2C, C2B); `@aroha-sdk/credentials` extracted from kernel; `IArohaRegistry` pluggable backend spec finalized. |
| 2026-04-14 | Initial draft prepared in W3C CG format (not submitted). |

---

## Abstract

Aroha (Aroha Protocol) is an open, decentralized protocol for agent-to-agent communication, discovery, and atomic multi-agent transactions. It defines how AI agents from different organizations discover each other, establish identity and trust, exchange messages securely, and coordinate complex multi-step tasks that either fully succeed or fully roll back. Multi-step coordination (sagas) and preference context are defined as extensions in a companion [extensions document](extensions.md).

Aroha is language-agnostic and framework-agnostic. It defines a protocol specification (this document), not an implementation. Any agent that correctly implements these rules can interoperate with any other Aroha agent.

---

## 1. Design Principles

1. **Decentralized** — No central authority controls agent discovery or registration.
2. **Self-sovereign identity** — Every agent owns its cryptographic identity. No registry or other third party can revoke it; only the identity itself or, for an E-form agent, the person named as its controller can rotate, recover or revoke it ([DID Method → Forms](did-method.md#forms)).
3. **Composable** — Complex tasks are assembled from atomic, single-purpose agents.
4. **Atomic** — Multi-agent transactions either fully succeed or fully roll back (saga pattern, defined in the [extensions document](extensions.md)).
5. **Open standards** — Built on W3C DIDs, JSON-LD, Ed25519, EVM smart contracts.
6. **Protocol-application separation** — The protocol defines envelopes and handshakes. Applications decide what to do with messages.

---

## 2. Protocol Layers

| Layer | Name | Responsibility |
|-------|------|---------------|
| 0 | Transport | HTTPS + WebSocket, TLS 1.3+ |
| 1 | Identity | W3C DIDs, Ed25519 |
| 2 | Registry | Pluggable registry (managed HTTP, self-hosted, or optional blockchain) + IPFS manifests |
| 3 | Messaging | Signed JSON-LD envelopes, 19 message types |

Extensions (pluggable outside the core protocol):
- **Orchestration:** saga state machine, reserve/commit/cancel ([extensions document](extensions.md) §1; formerly Layer 4)
- **Preference Context:** user constraints, consent tokens ([extensions document](extensions.md) §2; formerly Layer 5)
- **Credentials:** RBAC, Human Credentials, Credential Registry
- **Settlement:** Null, ApiKey, Quota, Escrow — plus `WalletService` for invisible Web3
- **Commerce:** B2B Agreements, B2C Consent, C2B Feedback, `CommerceAuditLog`

!!! important "Kernel boundary"
    The core protocol kernel (`@aroha-sdk/core`) MUST NOT import any extension package.
    `@aroha-sdk/core` exports: transport, identity, crypto primitives, and signed messaging only.
    Settlement, credentials, and commerce are injected via the `middleware` / `settlement` constructor parameters — never statically coupled to the kernel.

---

## 3. Layer 0 — Transport

### 3.1 Well-Known Endpoint

Every Aroha agent MUST serve:

```
GET https://<domain>/.well-known/aroha-agent.json
Content-Type: application/json
→ Response: DID Document (see Layer 1)
```

### 3.2 Message Endpoint

All Aroha messages MUST be sent via:

```
POST https://<domain>/aroha/v1
Content-Type: application/json
Body: ArohaEnvelope (see Layer 3)
```

### 3.3 Streaming

Async capabilities MUST use WebSocket at:

```
wss://<domain>/aroha/stream?cid=<correlationId>
```

Frames are ArohaStream envelopes (JSON).

### 3.4 Security

- All connections MUST use TLS 1.3 or higher.
- Provider agents SHOULD use mTLS.
- HTTP (non-TLS) MUST NOT be used in production.

*(Note: Credential Registry endpoints, previously defined in Layer 0, are now part of the `@aroha-sdk/credentials` extension. See the [`@aroha-sdk/credentials` documentation](https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/packages/credentials.md).)*

### 3.5 Caller Authentication (`aroha-sig`)

A bearer token proves only that the caller holds a secret; every holder of that token is indistinguishable. An agent that must restrict *which agents* may invoke it therefore needs caller **identity**, not a shared secret.

Agents MAY require the `aroha-sig` scheme. A signed request carries the caller's DID and an Ed25519 signature that the callee verifies against the public key published for that DID (§4.2).

**Signed material.** The caller signs the newline-joined concatenation, in exactly this order:

```
METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA-256(body, hex)
```

Binding the method and path prevents a captured signature being replayed against a different endpoint; binding a hash of the body prevents alteration of its content.

**Headers.**

| Header | Value |
|--------|-------|
| `X-Aroha-Did` | Caller's DID, e.g. `did:aroha:planner` |
| `X-Aroha-Timestamp` | ISO-8601 instant |
| `X-Aroha-Nonce` | Unique per request |
| `X-Aroha-Signature` | `base64url` Ed25519 signature over the signed material |

**Verifier requirements.** A conformant verifier MUST:

1. Reject a request whose `X-Aroha-Timestamp` differs from local time by more than the permitted skew (RECOMMENDED default: 5 minutes).
2. Reject a request whose `X-Aroha-Did` is absent from the callee's allow-list, **before** resolving any key. Checking membership first means an unauthorised DID cannot use response timing to probe which identities are known.
3. Resolve the caller's public key from the DID and verify the signature.
4. Reject a replayed `X-Aroha-Nonce`. The nonce MUST be consumed **last** — only once the request is otherwise fully valid. Consuming it earlier would let an attacker burn a legitimate caller's nonce with an invalid request.

An agent requiring `aroha-sig` MUST fail closed: a request with a missing, malformed, or unverifiable signature is rejected, never downgraded to anonymous access.

---

## 4. Layer 1 — Identity

### 4.1 Agent DID

Every agent MUST have a DID:

```
did:aroha:<unique-id>
```

Where `<unique-id>` is globally unique and chosen by the operator.

Three forms of `<unique-id>` exist, told apart by syntax
([DID Method → Forms](did-method.md#forms)):

- **E-form** `did:aroha:E<base58btc(sha256(inception))>` — self-certifying
  and rotatable; the current key is derived from the identifier's Key Event
  Log. A person is an E-form identity of kind `person`; an agent MAY name a
  person as its controller, who can recover or revoke it. New identities
  SHOULD use this form.
- **z-form** `did:aroha:z<base58btc(publicKey)>` — legacy. Self-certifying
  but not rotatable.
- **Named form** — human-readable and registry-trusted.

### 4.2 DID Document Format

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:aroha:<unique-id>",
  "verificationMethod": [{
    "id": "did:aroha:<unique-id>#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:aroha:<unique-id>",
    "publicKeyMultibase": "z<base58btc-encoded-32-bytes>"
  }],
  "authentication": ["did:aroha:<unique-id>#key-1"],
  "service": [{
    "id": "did:aroha:<unique-id>#aroha",
    "type": "ArohaEndpoint",
    "serviceEndpoint": "https://<domain>/aroha/v1"
  }]
}
```

**Requirements:**
- MUST contain at least one `Ed25519VerificationKey2020` verification method.
- MUST contain a `ArohaEndpoint` service entry.
- The public key MUST be registered with the agent's Layer 2 registry (§5.1) before the agent can be discovered.

The HTTP registry (§5.1a) is the normative baseline for registration and key resolution. The blockchain registry (§5.1b) is OPTIONAL; where it is used, "registered" means registered on-chain. For z-form and E-form DIDs the verifying key comes from the DID itself (and, for E-form, its Key Event Log), so a registry record can never substitute a different key for them. The registry smart contracts in Appendix B are not wired into DID resolution in the reference implementation.

### 4.3 Verifiable Credentials

Agents MAY carry W3C Verifiable Credentials (VCs) to prove claims:

| VC Type | Purpose | Required at Trust Level |
|---------|---------|------------------------|
| `CorporateIdentityCredential` | Proves corporate operator | 2 |
| `ComplianceCertificationCredential` | Proves regulatory compliance | 2 |
| `CapabilityAuthorizationCredential` | Authorizes specific capabilities | 3 |

VCs MUST be signed by a recognized trust anchor's Ed25519 key.

### 4.4 Trust Levels

| Level | Requirements | Permitted Operations |
|-------|-------------|---------------------|
| 0 | None | Read manifests, query registry |
| 1 | Registered with a Layer 2 registry (plus a stake only where an optional blockchain registry requires one, §5.1b) | Search, negotiate |
| 2 | VC from trust anchor | Reserve (low-value) |
| 3 | Reputation ≥ 8000 | Reserve + commit (high-value) |
| 4 | Explicit user authorization | Full access + payments |

### 4.5 Human Credentials (Extension)

See the `@aroha-sdk/credentials` extension for details on how human users authenticate to their Personal Agent out-of-band and receive a signed `HumanCredential`.

### 4.6 Role-Based Access Control (Extension)

See the `@aroha-sdk/credentials` extension for details on the standard role system that governs which principals may invoke which message types.

---

## 5. Layer 2 — Registry

### 5.1 Registry Interface

Any conformant registry implementation MUST satisfy the following logical interface (shown in TypeScript; equivalent interfaces exist in all SDK languages):

```typescript
interface IArohaRegistry {
  register(did: string, manifestCID: string, publicKey: Uint8Array,
           options?: RegisterOptions): Promise<void>;
  deactivate(did: string): Promise<void>;
  updateManifest(did: string, newCID: string): Promise<void>;
  resolveByDID(did: string): Promise<AgentRecord | null>;
  queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]>;
}
```

Three conformant implementations are defined by this specification:

| Implementation | Backend | Use case |
|---------------|---------|----------|
| **Managed HTTP Registry** | REST API (SaaS or self-hosted) | Enterprise default. No blockchain required. Subscription-based. |
| **Self-hosted HTTP Registry** | REST API (operator-run) | Regulated industries (healthcare, finance, government) that cannot use external services. |
| **Blockchain Registry** | EVM smart contract (optional) | Trustless, permissionless deployments. Useful for open ecosystems with no trusted operator. |

Implementations are **interchangeable** at the SDK level. Application code depends only on `IArohaRegistry`, not on any specific backend.

### 5.1a Managed and Self-Hosted HTTP Registry

An HTTP registry MUST expose the following REST endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/agents` | Register an agent. Body: `{ did, manifestCID, publicKeyB64 }` |
| `DELETE` | `/v1/agents/:didHash` | Deactivate an agent |
| `PUT` | `/v1/agents/:didHash/manifest` | Update capability manifest CID |
| `GET` | `/v1/agents/:didHash` | Resolve agent record by DID |
| `GET` | `/v1/agents?capabilities=a,b` | Query agents by capability ID list |

A registry supporting visibility and access grants (§5.4) MUST additionally expose:

| Method | Path | Purpose |
|--------|------|---------|
| `PATCH` | `/v1/agents/:didHash/visibility` | Set `public` \| `unlisted` \| `private` |
| `POST` | `/v1/grants` | Grant a party access to a resource |
| `GET` | `/v1/grants?resource=:didHash` | List live grants on a resource |
| `DELETE` | `/v1/grants/:id` | Revoke a grant |

All four are restricted to the owner of the resource.

Authentication is via `Authorization: Bearer <api-key>` header. Endpoints that read records MUST accept the header as OPTIONAL, since visibility filtering (§5.4.3) requires serving anonymous callers the public view rather than rejecting them. Sybil resistance is enforced by the registry operator through subscription tiers, org verification, or rate limiting — not by cryptocurrency staking.

### 5.1b Blockchain Registry (Optional)

For trustless deployments, the following Solidity interface defines a conformant on-chain registry:

```solidity
interface IArohaRegistry {
  function register(bytes32 didHash, string calldata manifestCID, bytes calldata publicKey) external payable;
  function deactivate(bytes32 didHash) external;
  function updateManifest(bytes32 didHash, string calldata newCID) external;
  function updatePublicKey(bytes32 didHash, bytes calldata newPublicKey, bytes calldata rotationProof) external;
  function resolveByDID(bytes32 didHash) external view returns (AgentRecord memory);
  function queryByCapability(bytes32[] calldata capabilityHashes) external view returns (AgentRecord[] memory);
}
```

- `updatePublicKey` enables key rotation while preserving the DID and on-chain reputation. The `rotationProof` is an Ed25519 signature by the current private key over `SHA-256("aroha-key-rotation:" || didHash || newPublicKey)`.
- `didHash` = `keccak256(didString)`; `capabilityHash` = `keccak256(capabilityId)`
- Staking (`payable`) is OPTIONAL. Registry operators MAY require a minimum stake for Sybil resistance; they MAY also set minimum stake to zero.

### 5.2 Capability Manifest

The manifest MUST be signed by the agent. With the optional blockchain registry (§5.1b), the manifest MUST be published to IPFS and its CID stored on-chain. An HTTP registry (§5.1a) MAY store the signed manifest directly or reference it by CID.

```json
{
  "aroha": "1.0",
  "did": "did:aroha:<id>",
  "name": "<string>",
  "version": "<semver>",
  "endpoint": "https://<domain>/aroha/v1",
  "capabilities": [ /* CapabilityDefinition[] */ ],
  "protocols": ["aroha/1.0"],
  "signature": "<base64url-Ed25519-signature-over-manifest-body>"
}
```

The `endpoint` field is the authoritative Aroha message URL for this agent. Discovering agents MUST use the `endpoint` value from the verified manifest as the target for all Aroha messages. This field MUST be present and MUST be an HTTPS URL (or `wss://` for streaming-only agents). Because the manifest is Ed25519-signed by the agent operator and verified against the agent's registered public key (§4.2), the endpoint value is trusted without a separate DID Document resolution step.

**Capability Definition:**

```json
{
  "id": "<string>",
  "version": "<semver>",
  "inputSchema": { /* JSON Schema */ },
  "outputSchema": { /* JSON Schema */ },
  "async": false,
  "maxResponseMs": 5000,
  "requiredTrustLevel": 1,
  "pricing": { "model": "free" | "per-transaction" | "subscription" },
  "sagaRole": "none" | "participant",
  "reserveCapabilityId": "<id>",
  "cancelCapabilityId": "<id>"
}
```

**Requirements:**
- The manifest `signature` MUST be verified against the agent's registered public key (§4.2) before use.
- Any manifest with an invalid signature MUST be rejected.

### 5.3 Reputation

Reputation scores (0–10000) are maintained by the `ArohaReputation` oracle contract:

```
newScore = floor(oldScore × 0.85 + signal × 0.15)

signal values:
  SUCCESS      = 10000
  COMPENSATED  =  3000
  FAILURE      =  1000
  DISPUTE_LOST =     0
```

Default score for new agents: **5000** (neutral).

### 5.4 Visibility and Access Grants

Not every agent, MCP server, or skill is meant to be public. A registry MUST support restricting **discovery** of a record, and this is distinct from restricting **invocation** of the agent it describes.

#### 5.4.1 Visibility levels

Every agent, MCP, and skill record has a `visibility` field:

| Level | Appears in capability queries | Resolvable by `didHash` |
|-------|-------------------------------|-------------------------|
| `public` | Yes | Yes |
| `unlisted` | No | Yes |
| `private` | Only for the owner and holders of a live grant | Only for the owner and holders of a live grant |

`public` is the default, so an implementation adding visibility does not change the behaviour of existing records.

`unlisted` is *obscurity*, not access control: anyone who learns the `didHash` can resolve the record. It is appropriate for records that are simply not worth listing, and MUST NOT be relied on to protect anything.

#### 5.4.2 Access grants

An **access grant** records that the owner of a resource has granted a named party access to it. A grant identifies its grantee in one of two ways, because discovery and invocation authenticate differently:

| Grantee form | Used at | Rationale |
|--------------|---------|-----------|
| Registry credential | Discovery time | Registry callers authenticate with an API key, not a DID |
| Agent DID | Invocation time | The calling agent proves its DID via `aroha-sig` (§3.5) |

A grant MAY carry an expiry and MAY be limited to a subset of the resource's capability identifiers; an absent capability list means the whole resource. Revocation MUST be a soft delete so the audit trail survives, and MUST take effect immediately for subsequent requests.

A registry MUST enforce that at most one live grant exists per (resource, grantee) pair, while still permitting a grantee to be re-granted access after revocation.

#### 5.4.3 Filtering requirements

A conformant registry MUST apply visibility filtering **inside the query that retrieves records**, not by post-filtering results. Post-filtering leaks existence through result counts, pagination boundaries, and timing.

A viewer is entitled to a record when any of the following holds:

1. the record is `public` (for capability queries), or `public`/`unlisted` (for direct resolution);
2. the viewer owns the record; or
3. the viewer holds a grant on the record that is neither revoked nor expired.

Requests presenting no credential MUST be treated as an anonymous viewer that satisfies only condition 1. An anonymous viewer MUST NOT be distinguishable, in status code or timing, from an authenticated viewer who simply lacks access — both MUST receive the same "not found" response. Returning `403` for a private record confirms that it exists.

Credentials presented for discovery MUST NOT be used to probe: an invalid or unrecognised credential MUST degrade to the anonymous view rather than producing an authentication error, so that the presence of a record cannot be inferred from the difference.

#### 5.4.4 Separation of discovery and invocation

Visibility and grants govern the **registry** only. Marking a record `private` conceals it from discovery; it does not prevent invocation by a party that already knows the endpoint.

An agent that must restrict who may invoke it MUST enforce that itself, by requiring `aroha-sig` (§3.5) and checking the caller's DID against its own allow-list. Implementations MUST NOT present registry visibility as an invocation control.

---

## 6. Layer 3 — Messaging

### 6.1 Message Envelope

All Aroha messages MUST use this envelope:

```json
{
  "@context": ["https://aroha-labs.com/contexts/v1",
               "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "urn:uuid:<uuid-v4>",
  "type": "<ArohaMessageType>",
  "from": "did:aroha:<sender>",
  "to":   "did:aroha:<recipient>",
  "created": "<ISO8601>",
  "expires":  "<ISO8601>",
  "nonce": "<random-hex-32>",
  "correlationId": "<string>",
  "body": { },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO8601>",
    "verificationMethod": "did:aroha:<sender>#key-1",
    "proofPurpose": "authentication",
    "proofValue": "<base64url-Ed25519-signature>"
  }
}
```

An envelope MAY also carry an optional `disclosure` member (an `ArohaDisclosure`, see the Conversation and Memory Profile). Like every other member except `proof`, it is covered by the signature.

### 6.2 Signature Rule

`proof.proofValue` MUST be the Ed25519 signature over:

```
canonicalJSON = JSON.stringify(messageWithoutProof, keysLexicographicallySorted)
```

### 6.3 Validation Rules

A receiving agent MUST reject any message where:

1. Signature verification fails against the sender's public key, resolved for the `from` DID (§4.1–§4.2): derived from the DID for z-form, from the Key Event Log for E-form, from the registry for named DIDs
2. `expires` timestamp is in the past
3. `nonce` has been seen before (replay attack prevention)
4. `to` does not match the receiving agent's DID
5. `created` or `expires` is missing or cannot be parsed
6. `created` is more than the allowed clock skew in the future (default 30 seconds)
7. `expires - created` exceeds the maximum envelope lifetime (default 5 minutes)
8. the proof's `verificationMethod` names a DID other than `from`

**Ordering.** A receiver MUST perform the stateless checks (recipient, timestamps, lifetime, nonce present) and the signature check **before** it consults or writes the nonce store. Only an envelope whose signature verifies may record its nonce; otherwise an unauthenticated client could fill the store, or consume a legitimate sender's nonce in advance so that the real message is later rejected as a replay.

**Nonce scope.** Nonces MUST be tracked per sender: the replay key is the pair (`from`, `nonce`), so one sender's nonce can never collide with another's. A recorded nonce MUST be retained at least until `expires` plus any expiry clock tolerance the receiver applies.

A receiver that raises the maximum lifetime SHOULD use a nonce store that survives restarts and is shared by every instance that accepts messages for the same DID, because an envelope's replay window is its whole lifetime.

### 6.4 Message Types

| Type | Sender | Body Fields |
|------|--------|-------------|
| `ArohaRequest` | Orchestrator | `capability`, `params`, `preferenceContext?`, `credentialId?`, `credentialToken?` |
| `ArohaResponse` | Provider | `capability`, `result` |
| `ArohaStream` | Provider | `capability`, `progressPct`, `event`, `data?` |
| `ArohaNegotiate` | Orchestrator | `capability`, `proposedTerms` |
| `ArohaCounterOffer` | Provider | `capability`, `revisedTerms` |
| `ArohaAccept` | Orchestrator | `capability`, `acceptedTerms` |
| `ArohaReserve` | Orchestrator | `capability`, `params`, `holdDurationMs`, `preferenceContext?`, `credentialId?`, `credentialToken?` |
| `ArohaReserveAck` | Provider | `reservationToken`, `expiresAt` |
| `ArohaCommit` | Orchestrator | `reservationToken` |
| `ArohaCommitAck` | Provider | `reservationToken`, `result` |
| `ArohaCancel` | Orchestrator | `reservationToken`, `reason` |
| `ArohaCancelAck` | Provider | `reservationToken` |
| `ArohaDelegate` | Orchestrator | `targetDID`, `capability`, `params`, `credentialId?`, `credentialToken?` |
| `ArohaError` | Either | `code`, `message`, `retryable` |
| `ArohaSatisfactionSignal` | Orchestrator → its own preference store (never to a provider) | `sagaId`, `agentDID`, `outcome`, `dimensions` |
| `ArohaSpendingMandate` | Grantor → grantee | `mandateTier`, `constraints`, `grantee`, `grantor`, `issuedAt`, `expiresAt`, `parentMandateId`, `mandateId` (wire token format: §6.5) |
| `ArohaTaskMandate` | Grantor → grantee | `mandateType`, `mandateTier`, `allowed`, `blocked?`, `taskConstraints`, `spendingConstraints?`, `invariants?`, `grantee`, `grantor`, `issuedAt`, … |
| `ArohaDispute` | Either transacting party → arbiter | `sagaId`, `reservationToken`, `raisedBy`, `reason`, `disputedEvidence?` |
| `ArohaDisputeResolution` | Arbiter → both parties | `sagaId`, `reservationToken`, `resolution` (`release` \| `refund` \| `split`), `splitAmountWei?`, `reason`, `arbiterSignature` |

The first 15 types are shared by every reference SDK; the last four are implemented in the TypeScript reference only (Appendix B).

`credentialId` and `credentialToken` are mutually exclusive; `credentialId` takes precedence when both are present. They are required only when the receiving agent enforces an RBAC policy (see §4.6). Agent-to-agent messages where the sender's DID already carries a known role do not need to include them.

### 6.5 Spending Mandate Token Format (v2)

A spending mandate is a signed, narrowing grant of spending authority from a grantor to a grantee. Mandates form a chain: a human (or organisation) issues a root `intent` mandate, and each delegate may issue a narrower `cart` or `payment` mandate to the next agent. This section defines the wire format that every implementation MUST produce and accept; the conformance vectors are in `packages/aroha-credentials/test-vectors/mandate-v2.json` in the reference repository.

**Mandate body.** Each link's body has the fields `mandateTier` (`intent` | `cart` | `payment`), `constraints`, `grantee`, `grantor`, `issuedAt`, `expiresAt`, `parentMandateId` (null for a root) and `mandateId`. `issuedAt` is REQUIRED. A body that carries `mandateType` is a task mandate and MUST be rejected as a spending mandate.

**Signature.** A v2 link signature is the Ed25519 signature, by the link's grantor, over the UTF-8 bytes of the RFC 8785 (JCS) canonicalisation of the object `{"mandate": <body>, "v": 2}`, encoded as base64url without padding.

**Token.** A token is base64url(JSON) of `{ "v": 2, "mandate": <leaf body>, "signature": <leaf signature>, "chain": [ … ] }`. `chain` lists every ancestor link, root first, excluding the leaf; each entry is `{ "v": 1 | 2, "mandate": <body>, "signature": <sig> }`. A root mandate carries an empty `chain`. A token without `v` is a legacy v1 token, which never carries a chain; a token with a `chain` but no `v: 2` MUST be rejected as malformed.

**Chain verification.** Before acting on a token to move money, a verifier MUST check every link, root first, and MUST reject the token if any check fails:

1. Each link's signature verifies against the public key of that link's `grantor`. The key for an ancestor link MUST be resolved from the grantor's DID (derived from a z-form DID, from the Key Event Log for an E-form DID, or from a trusted registry for a named DID) — never taken from the token. A key the caller supplies for the leaf grantor applies to the leaf link only, by position; if the leaf grantor's DID is self-certifying, the supplied key MUST equal the key derived from that DID.
2. The root has `parentMandateId` null and tier `intent`; if the verifier expects a particular root, the root's `grantor` equals it.
3. Each child's `grantor` equals its parent's `grantee`, its `parentMandateId` equals its parent's `mandateId`, its tier is not broader than its parent's (`intent` → `cart` → `payment`), and its `expiresAt` is not later than its parent's.
4. Each child's constraints narrow its parent's: `spendLimitUsd` is not greater; and every optional limit the parent sets (`sessionLimitUsd`, `requireHumanApprovalAboveUsd`, `allowedMerchants`, `merchantCategory`, `validFrom`, `validUntil`, `currency`) is also set by the child, to an equal or narrower value. A child that omits a limit its parent sets is a widening and MUST be rejected.
5. Every link is within its time window (`issuedAt`, `expiresAt`, `validFrom`, `validUntil`) and, when a revocation source is configured, not revoked.
6. If the verifier expects a particular grantee (normally itself), the leaf's `grantee` equals it.

Issuers MAY fill an omitted optional limit from the parent when they attenuate (so that honest callers produce valid children); verifiers MUST NOT.

**Acting-for side.** A mandate body MAY carry `actingFor` (`payer` | `payee`), declaring which side of a payment the chain acts for. When a parent sets it, a verifier MUST reject a child whose `actingFor` is absent or different. The field is part of the signed body only when present.

A legacy v1 token proves only that its immediate grantor signed it. A verifier MUST NOT treat a v1 token that is not itself a root as authority traceable to a human.

**Revocation and redemption (optional registry extensions).** A registry MAY expose `GET /v1/mandates/:id/revoked` so verifiers can check every link's `mandateId` for revocation, and MAY offer payment-mandate redemption tracking so the cumulative amount redeemed against a payment mandate never exceeds `min(spendLimitUsd, sessionLimitUsd)`. Both are extensions to the HTTP registry of §5.1a. A verifier that uses a revocation source MUST treat an unreachable source as a failure. Without redemption tracking, a payment mandate is a bearer authorisation that could be presented more than once. A registry that records revocations or redemption totals MUST key them by the pair (grantor, mandateId), where grantor is the mandate's own grantor, because a mandateId is chosen by whoever mints the mandate and does not by itself identify one.

The reference registry implements these extensions as follows (non-normative):

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/mandates/:mandateId/revoke` | none (rate limited); signed | Body `{ token, revokedAt, revoker, signature }`. `token`'s leaf is `:mandateId` and verifies; `revoker` is the grantor of the leaf or of any ancestor; `signature` is Ed25519 by the revoker over JCS `{ mandateId, purpose: "aroha.mandate.revoke/v1", revokedAt }`. Revocations are permanent and first-wins. |
| `GET` | `/v1/mandates/:mandateId/revoked?grantor=<DID>` | public | `{ mandateId, grantor, revoked, revokedAt? }` |
| `POST` | `/v1/mandates/:mandateId/redeem` | API key | Body `{ token, amountMicros, merchant, redemptionId? }`. The registry verifies the chain itself, requires a payment mandate and an allowed merchant, derives the limit from the verified leaf, and adds atomically: `200 { accepted: true, … }` or `409 { accepted: false, redeemedMicros, limitMicros }`. |
| `GET` | `/v1/mandates/:mandateId/redemptions?grantor=<DID>` | API key | `{ mandateId, grantor, redeemedMicros }` (integer micro-USD) |

The `@aroha-sdk/credentials` clients are `revokeMandate`, `httpRevocationCheck` and `httpRedemptionStore`.

### 6.6 Task Mandate Token Format (v2)

A task mandate (`ArohaTaskMandate`, §6.4) grants non-monetary authority: which capabilities a grantee may invoke and under which task constraints. It narrows along a chain the same way as a spending mandate.

**Signature.** A v2 task-mandate signature is the Ed25519 signature, by the mandate's grantor, over the UTF-8 bytes of the JCS canonicalisation of `{"mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2}`, encoded as base64url without padding. The purpose tag keeps a task-mandate signature from verifying as any other Aroha object.

**Token.** A token is base64url(JSON) of `{ "v": 2, "mandate": <body>, "signature": <sig> }`. A token without `v` is a legacy v1 token, signed over the key-sorted JSON of the body. A verifier MUST reject any other value of `v`.

**Body.** `mandateType` (`task` | `hybrid`), `mandateTier` (`intent` | `cart` | `execution`), `allowed` (capability ids), `blocked?`, `taskConstraints`, `spendingConstraints?` (REQUIRED when `mandateType` is `hybrid`), `invariants?`, `grantee`, `grantor`, `issuedAt`, `expiresAt`, `parentMandateId`, `mandateId`. `taskConstraints` has the optional members `actionLimits`, `computeLimit`, `dataAccess`, `outputHandling`, `reversibleOnly`, `humanGates`, `checkpointIntervalMs`, `requireSandbox`, `maxDelegationDepth`, `onBehalfOf` and `roomId`.

**Narrowing.** A verifier of a task-mandate chain MUST reject a child that is not equal to or narrower than its parent. For every constraint the parent sets, the child MUST set it too, to an equal or narrower value; a child that omits a constraint its parent sets is a widening. In particular: `allowed` is a subset of the parent's; `blocked` is a superset; each `actionLimits` and `computeLimit` value is not greater; `dataAccess` grants no right the parent lacks; `reversibleOnly` and `requireSandbox` stay true once set; `humanGates` keeps every gate on a capability the child still allows; `onBehalfOf` and `roomId`, when the parent sets them, are kept with the same value; `expiresAt` is not later than the parent's.

**Enforcement.** Before executing a capability under a task mandate, a receiver MUST check the request against the mandate: the capability is allowed and not blocked; `reversibleOnly` refuses an irreversible capability; a capability in `humanGates` runs only after a human approval; action, compute and data-access limits hold. When `taskConstraints.roomId` is set, the receiver MUST refuse a request that does not come from that room, and when `taskConstraints.onBehalfOf` is set, it MUST refuse a request made for any other member, including a request that names no room or member. The receiver takes the room and member from its own records, never from the request body.

The vector `taskMandateV2` in `spec-public/vectors/conversation-v1.json` covers a guest grant with `onBehalfOf` and `roomId`.

### 6.7 Signed Revocation Status

A registry that answers the revocation query of §6.5 SHOULD sign every answer. A signed answer carries `statusSignature`, `statusKeyId` and `checkedAt` beside `mandateId`, `grantor`, `revoked` and, when revoked, `revokedAt`.

**Signature.** `statusSignature` is the Ed25519 signature by a registry key over the UTF-8 bytes of the JCS canonicalisation of `{ "purpose": "aroha.revocation-status/v1", "mandateId", "grantor", "revoked", "revokedAt"?, "checkedAt" }`, base64url without padding; `revokedAt` is present only when `revoked` is true.

**Keys.** The registry publishes its keys at `/.well-known/aroha-registry-keys.json`. A key's `keyId` is the first 16 hex characters of the SHA-256 of its 32-byte public key. A key marked `retired` MUST NOT be accepted for revocation status.

**Verification.** A verifier configured with registry keys MUST reject an answer that is unsigned, signed by an unknown or retired key, names a different mandate or grantor, or whose `checkedAt` is older than its freshness limit (60 seconds in the reference) or in the future beyond its clock-skew allowance. Such an answer MUST be treated as a failure, never as "not revoked", even when the verifier is otherwise configured to tolerate an unreachable registry.

### 6.8 Governed Verifier Profile

The governed verifier profile is the set of mandate checks a production payment or action gate SHOULD apply. A verifier claiming the governed profile MUST:

1. require that the chain root is a person: a `did:aroha:E…` identity whose Key Event Log verifies, is not revoked and has `kind` `person`;
2. resolve every E-form grantor's key from its current Key Event Log, and fail when an identity or its controller is revoked or its log cannot be obtained;
3. consult a revocation source for every link and treat an unreachable source as a failure;
4. require a chain that verifies back to a root before honouring a spend (a bare leaf is not enough);
5. pin the root to an expected grantor, an expected person or a non-empty list of trusted roots, because anyone can incept a person identity.

A verifier that cannot meet one of these prerequisites MUST NOT report a verification as governed. In the reference implementation, `governedVerification()` in `@aroha-sdk/credentials` builds these options and refuses to build them when a prerequisite is missing.

### 6.9 Mandate Presentation

A mandate token is a bearer credential: anyone holding a copy can present it. A receiver MUST NOT act on a mandate token that arrives without a holder proof. A holder proof is an Ed25519 signature by the holder (the leaf grantee of the token) that binds the token to one receiver, one request and one use. This section defines two bindings, one for MCP tool calls and one for plain HTTP requests. Both share these rules:

1. The verifier MUST resolve the holder's public key from the holder DID (as for a grantor in §6.5), never from the presentation.
2. The verifier MUST reject a presentation whose holder is not the leaf grantee of the token, either directly or by verifying the token with the holder as the expected grantee.
3. The verifier MUST reject a presentation whose `expires` has passed, or whose `expires` lies more than 5 minutes plus a clock-skew allowance (30 seconds in the reference) in the future.
4. The verifier MUST remember each accepted nonce until its presentation expires and MUST reject a nonce it has already accepted from the same holder. It MUST consume the nonce last, only after every other check has passed, so that a request that fails cannot use up a legitimate holder's nonce.
5. A presentation proves possession only. The verifier MUST then verify the token itself (§6.5 or §6.6) with the holder as the expected grantee before acting on it.

#### 6.9.1 MCP Binding

An MCP `tools/call` request carries its presentation in the request `_meta` under the key `aroha/mandate`, as the object `{ "token", "holder", "nonce", "expires", "proof" }`. `proof` is the holder's Ed25519 signature, base64url without padding, over the UTF-8 bytes of the JCS canonicalisation of `{ "purpose": "aroha.mcp-mandate-presentation/v1", "audience", "tool", "argsSha256", "mandateId", "holder", "nonce", "expires" }`, where `audience` is the receiving agent's DID, `tool` the tool name, `argsSha256` the lower-case hex SHA-256 of the UTF-8 JCS canonicalisation of the call arguments (`{}` when there are none), and `mandateId` the token's leaf `mandateId`. The reference implementation is `presentMandate()` and `verifyPresentation()` in `@aroha-sdk/mcp-bridge`.

#### 6.9.2 HTTP Binding

A plain HTTP request carries its presentation in the `Aroha-Mandate` request header. The header value is the base64url encoding, without padding, of the UTF-8 bytes of the JCS canonicalisation of an object with exactly the members `token`, `holder`, `nonce`, `expires` and `proof`, each a non-empty string. A verifier MUST reject a value that does not decode to such an object, including one with any other member. A verifier MAY refuse a value longer than 32 768 characters.

- `nonce` is 16 to 128 characters from the base64url alphabet (`A–Z a–z 0–9 - _`). It MUST be unpredictable; 16 random bytes are RECOMMENDED.
- `expires` is a UTC instant in exactly the form `YYYY-MM-DDTHH:mm:ss.sssZ`; a verifier MUST reject any other form.
- `proof` is the holder's Ed25519 signature, base64url without padding, over the UTF-8 bytes of the JCS canonicalisation of the signed object below.

```
{ "purpose":    "aroha.http-mandate-presentation/v1",
  "audience":   <the receiving server's identifier>,
  "method":     <request method, ASCII upper-case>,
  "target":     <request target, see below>,
  "bodySha256": <lower-case hex SHA-256 of the exact body bytes>,
  "mandateId":  <the token's leaf mandateId>,
  "holder", "nonce", "expires" }
```

**Audience.** The audience is the identifier the server is configured with (its DID or its origin, such as `https://api.example.com`). A verifier MUST use its own configured value, never one taken from the request.

**Method.** The method is an HTTP method token, upper-cased in ASCII only.

**Target.** The target is the path and query of the request exactly as sent on the wire (the origin-form request target): for an absolute `http` or `https` URL, everything after the authority; for an origin-form URL, the URL itself. The fragment is dropped, an empty path is `/`, and a query is kept with its leading `?`. Percent-escapes are kept exactly as sent and are never decoded or re-encoded. A client MUST refuse to sign, and a verifier MUST refuse to verify, a target that contains a character outside the RFC 3986 unreserved and reserved sets and `%`, a `%` not followed by two hex digits, a `.` or `..` path segment in any percent-encoded spelling, or user information in the authority, because an HTTP client or proxy can rewrite such a target in transit.

**Body.** The body hash covers the exact bytes of the request body as sent. An empty or absent body hashes as SHA-256 of the empty string. A client MUST sign the bytes it sends, and a verifier MUST hash the bytes it received before any parsing; a body that is parsed and re-serialised will not verify.

**Verification.** A verifier MUST compute the method, target and body hash from the request it received, never from the presentation, and MUST apply the shared rules above. A server SHOULD answer a missing or invalid presentation with status 401 and a valid presentation of a mandate that does not authorise the request with status 403.

**Spending.** A presentation authorises a request, not an amount. A server whose request spends money under the presented mandate checks the amount against the constraints of every link of the verified chain and keeps a running total for every link, keyed by the pair (grantor, mandateId) and capped at `min(spendLimitUsd, sessionLimitUsd)` as for redemption (§6.5), so that sibling mandates cannot together spend more than their common parent.

**Enrollment (informative).** A server that pins each request to the root DID of one of its customer accounts needs a binding from account to DID. One way to establish it, used by the reference implementation, is: the server issues a fresh, single-use, expiring challenge bound to the account the customer is signed in to; the customer's device signs, with the DID's key, the JCS canonicalisation of `{ "purpose": "aroha.enrollment/v1", "audience", "accountId", "did", "challenge" }` (Ed25519, base64url without padding); the server spends the challenge whatever the outcome, checks that it was issued to the signed-in account and has not expired, resolves the key from the DID as for a holder, verifies the signature, and records the binding, replacing any earlier one. This note adds no requirement. The reference implementation is `issueEnrollmentChallenge()`, `completeEnrollment()`, `enrolledDid()` and `signEnrollment()` in `@aroha-sdk/credentials` and the same names in snake case in the Python SDK's `aroha.enrollment`; the vectors are in `packages/aroha-credentials/test-vectors/enrollment-v1.json`.

The reference implementation is `presentMandateHttp()`, `verifyHttpPresentation()`, `verifyHttpMandateRequest()` and `verifyHttpSpendRequest()` in `@aroha-sdk/credentials`, and `present_mandate_http()`, `verify_http_presentation()`, `verify_http_mandate_request()` and `verify_http_spend_request()` in the Python SDK's `aroha.http_mandate`. The conformance vectors are in `packages/aroha-credentials/test-vectors/http-presentation-v1.json` and `packages/aroha-credentials/test-vectors/http-spend-v1.json` in the reference repository.

---

## 7. Orchestration (moved)

Orchestration primitives (sagas: reserve, commit, cancel, idempotency, compensation order and hold duration), formerly Layer 4, are specified in §1 of the [extensions document](extensions.md). The rules are unchanged.

---

## 8. Preference Context (moved)

Preference context (format, provider obligations and satisfaction signals), formerly Layer 5, is specified in §2 of the [extensions document](extensions.md). The rules are unchanged.

---

## 9. Security Requirements

| Requirement | Specification |
|------------|---------------|
| Transport | TLS 1.3+ required. mTLS recommended for providers. |
| Message integrity | Ed25519 signature on every message. |
| Replay prevention | Envelope lifetime capped (default 5 minutes), `created` checked against clock skew, signature verified before the nonce store is touched, nonces keyed per sender and retained until `expires` (§6.3). |
| Encryption | DIDComm v2 JWE for sensitive body fields. |
| Key storage | Private keys MUST be stored in HSM or secure enclave. |
| Key rotation | E-form DIDs rotate by appending a rotation event to their Key Event Log, using the pre-committed next key ([DID Method](did-method.md)); z-form DIDs cannot rotate (migrate to E-form); named DIDs rotate through their registry. With the optional blockchain registry, `updatePublicKey` (§5.1b) also applies. |
| Sybil resistance | HTTP registries (§5.1a): operator controls (org verification, subscription tiers, rate limits). Optional blockchain registry (§5.1b) only: a minimum stake MAY be required. |
| Bad actor penalties | Optional blockchain registry (§5.1b) only: stake slashing via a dispute contract. Otherwise, registry de-listing and reputation (§5.3). |
| Access control | RBAC enforced at transport layer before application dispatch (§4.6). |
| Caller identity | Agents restricting who may invoke them MUST verify `aroha-sig` (§3.5) and fail closed on a missing or unverifiable signature. |
| Discovery privacy | Registries MUST filter by visibility inside the retrieval query, and MUST NOT distinguish "no access" from "does not exist" (§5.4.3). |
| Human credential integrity | Ed25519 signature over canonical credential body; expiry checked on every use. |
| Credential revocation | Revoked credentials (`DELETE /aroha/credentials/:id`) MUST be rejected on the next use by any verifier that consults the credential registry. A verifier that works offline cannot observe a revocation before the credential expires. |
| Mandate revocation | Implementations MUST check a revocation source when one is configured, for every mandate in a delegation chain, and MUST reject a chain containing a revoked mandate. When no revocation source is configured, a mandate remains valid until it expires. (The reference mandate-chain verifier accepts an `isRevoked` hook for this.) |
| Identity revocation (E-form) | A verifier holding a Key Event Log source MUST reject a delegation chain in which any E-form grantor or grantee, or its controller, is revoked, and MUST verify each E-form grantor's signature against its current key ([DID Method → Delegation roots](did-method.md#delegation-roots)). |
| Delegation root | A verifier MAY require the root grantor of a delegation chain to be a person (an unrevoked E-form identity of kind `person`). |
| Key Event Log freshness | Verifiers SHOULD retain the longest verified KEL per identifier, MUST NOT accept a shorter one as current, and MUST treat two different events at one sequence number as duplicity. |

---

## 10. Interoperability

Aroha agents SHOULD advertise protocol compatibility in their manifest:

```json
{
  "protocols": ["aroha/1.0", "mcp/2024-11", "a2a/1.0"]
}
```

| External Protocol | Integration Method |
|------------------|-------------------|
| MCP (Model Context Protocol) | Wrap capabilities as MCP tools; bridge handles translation |
| A2A (Agent2Agent, Linux Foundation) | Map A2A message fields to Aroha envelope fields |
| OpenAPI / REST | Convert spec to capability manifest via adapter |
| LangChain | `ArohaCapabilityTool` extends `BaseTool` (Python) |
| CrewAI | `ArohaCrewTool` extends `CrewBaseTool` (Python) |
| AutoGen | `aroha_tools_for_autogen()` returns `FunctionTool` list (Python) |
| Spring AI / LangChain4j / LangChainGo | Coming soon, with the Java and Go SDKs |

---

## 11. Conformance

An implementation is conformant if it:

1. Exposes a valid DID Document at `/.well-known/aroha-agent.json`
2. Accepts messages at `/aroha/v1` using the defined envelope format
3. Rejects messages that fail signature, expiry, nonce, or recipient checks
4. If it adopts the orchestration extension (`sagaRole: "participant"`), meets that extension's conformance requirements ([extensions document](extensions.md) §3)
5. If it adopts the preference context extension, does not store or share `preferenceContext` beyond the current request ([extensions document](extensions.md) §2.2)
6. Publishes a signed capability manifest that includes a valid `endpoint` field when registering in any registry (to IPFS when the registry is the optional blockchain registry, §5.2)
7. Executes extensions appropriately: if RBAC is configured (via `@aroha-sdk/credentials`), resolves agent roles and verifies `HumanCredential` before dispatching any action message; returns `401` or `403` on failure.

---

## 12. Conversation and Memory Profile

This profile defines how a shared conversation (a room with more than one person, and possibly more than one agent) carries authority and attribution as signed data, so that an implementation can enforce who may read, write, approve and remember outside the model. It adds no message type: its objects are stored by the runtime and carried inside existing bodies (for example a `capability: "invite"` request). The JSON Schemas are in `spec-public/schemas/` and the conformance vectors in `spec-public/vectors/conversation-v1.json`.

All signatures in this section are Ed25519 over the UTF-8 bytes of an RFC 8785 (JCS) canonical form, encoded as base64url without padding. Each signed object carries a `purpose` tag inside the signed bytes, so a signature made for one kind of object never verifies as another.

A signature proves possession of a key that the signer's Key Event Log names. When a runtime holds a person's key and signs on their behalf, the signature does not prove that the person was present.

### 12.1 Room

A room is a signed record held by its host:

```json
{
  "v": 1, "purpose": "aroha.room/v1",
  "roomId": "<string>", "threadId": "<string>", "ownerDid": "did:aroha:E…",
  "epoch": 2,
  "members": [{ "did": "<DID>", "kind": "person | agent", "principalId?": "<string>",
                "displayName": "<string>", "role": "host | guest | own | invited | delegated",
                "joinedEpoch": 0, "leftEpoch?": 3, "consentRef?": "<recordId>" }],
  "historyVisibility": "joined | shared", "invocation": "explicit | implicit",
  "memoryPolicy": { "personalRead": false, "personalWrite": false,
                    "roomMemory": "off | consented", "agentRead?": "none | members" },
  "disclosure": { "…": "ArohaDisclosure, §12.7" },
  "updatedAt": "<ISO8601>", "signature": "<base64url>"
}
```

**Signature.** `signature` is made by the current key of `ownerDid` over JCS of the record with `signature` removed. `ownerDid` MUST resolve, through its Key Event Log, to an identity of kind `person`; a verifier MUST reject a room signed by any other key.

**Rules.** Exactly one member has role `host`, and that member is `ownerDid` with kind `person`. Member DIDs are unique. `joinedEpoch` is not greater than `epoch`; `leftEpoch`, when present, is greater than `joinedEpoch` and not greater than `epoch`. A person with role `guest` MUST have a `consentRef`. A verifier MUST reject a record that has a field this section does not define.

**Epochs.** The host MUST increment `epoch` and re-sign the record on every membership change. A member is a member at epoch `e` when `joinedEpoch ≤ e < leftEpoch` (or `leftEpoch` is absent). Turns and facts from a member are bounded by that interval.

**Defaults.** A host SHOULD create rooms with `historyVisibility: "joined"` (a late guest sees nothing before their join), `invocation: "explicit"` (the agent answers only turns whose `addressedTo` includes it) and a `memoryPolicy` with every member off.

### 12.2 Person Identities in Conversations

A person DID (an E-form DID whose Key Event Log inception has `kind: "person"`) MAY sign chat turns, consent records and approvals. A person DID MUST NOT be the `from` of an `ArohaRequest` carrying a capability request it did not author; an agent that acts on a person's words sends the request under its own DID and carries the person's authority as a mandate or a signed approval.

**Speaker kind.** A verifier MUST resolve the kind of a signer (`person` or `agent`) from the signer's verified Key Event Log, and MUST NOT take it from the signed object or from the message that carries it. A DID whose kind cannot be resolved that way (a z-form or named DID, an unavailable or invalid log) MUST be treated as `agent`, because the lesser authority is the safe default. A receiver resolves a person's log from the registry's KEL endpoint or from a log the person supplied, verified as in the DID method specification.

### 12.3 Person Invitation and Consent Record

A person invitation is a `capability: "invite"` request whose invitee is a person DID. It MUST NOT be accepted automatically: it stays pending until the invitee accepts with their own person key, and the acceptance carries a consent record shaped after ISO/IEC TS 27560:

```json
{
  "v": 1, "purpose": "aroha.consent/v1",
  "recordId": "<string>", "subjectDid": "<person DID>", "roomId": "<string>",
  "purposes": ["transcript_retention", "agent_use_of_messages", "memory_write", "provider_processing"],
  "withdrawalRoute": "<URL or instruction>",
  "events": [{ "event": "given | withdrawn", "purposes": ["…"], "at": "<ISO8601>",
               "actorDid": "<DID>", "epoch": 1, "sig": "<base64url>" }]
}
```

**Event signatures.** Each event is signed by its own `actorDid`. The signature covers JCS of `{ "purpose": "aroha.consent-event/v1", "recordId", "subjectDid", "roomId", "purposes", "withdrawalRoute", "index", "prevHash", "entry" }`, where `index` is the event's position, `entry` is the event without `sig`, and `prevHash` is the lowercase hex SHA-256 of JCS of the previous event including its `sig` (null for the first event). Because every event is bound to its actor, its position and its predecessor, nobody who appends an event can alter, insert or remove an earlier one.

**Rules.** A verifier MUST check every event's signature against the current key of that event's `actorDid`, and every actor MUST resolve to a person. The first event MUST be `given`. A `given` event MUST be signed by `subjectDid`. Any current room member MAY record a `withdrawn` event for any purpose. When any event's actor is not the subject, the verifier MUST have the room record and MUST reject the consent record unless that actor was a room member at the event's `epoch`; a member who has left cannot withdraw on someone's behalf. Event purposes are a subset of the record's `purposes`; `at` and `epoch` do not decrease.

**Effect.** The purposes in force are those given and not later withdrawn, replayed in order. When `agent_use_of_messages` is not in force for a member, that member's turns MUST be shown to people only and MUST NOT be passed to an agent. When `memory_write` is not in force, nothing that member says may be written to room memory.

### 12.4 Turn Signature

A turn is one message in a room. An authored turn is:

```json
{ "threadId": "<string>", "roomId": "<string>", "epoch": 2, "at": "<ISO8601>",
  "contentHash": "<sha256 hex>", "addressedTo": ["<DID>"],
  "authorDid": "<DID>", "content": "<text>", "authorSignature": "<base64url>" }
```

`contentHash` is the lowercase hex SHA-256 of the UTF-8 bytes of `content`. `authorSignature` is made by the author's current key over JCS of `{ "purpose": "aroha.turn/v1", "threadId", "roomId", "epoch", "at", "contentHash", "addressedTo" }`.

A verifier MUST reject a turn whose `contentHash` does not match its content, whose signature does not verify, or (when it holds the room record) whose author was not a member at the turn's `epoch`. The runtime sets a turn's author from the authenticated caller, never from the request body. A turn from a guest is untrusted input for gating purposes: an action it leads to requires an approval bound to the host, or to the member who holds the relevant mandate, never to the guest.

### 12.5 Memory Record

A memory record (`MemoryFact`) has the fields `v` (1), `factId`, `text`, `speakerDid`, `speakerKind` (`person` | `agent`), `subjectDid` (`self`, `room`, or a member's DID, person or agent), `scope` (`private` or `room:<roomId>`), `audience` (`host` | `persons` | `members`), `epoch`, `origin` (the hash of the signed turn or envelope the fact came from), `derivedFrom` (the `factId`s it was derived from), `status` (`fact` | `claim`), `consentRef?` and `createdAt`.

`speakerKind` MUST be resolved as in §12.2 at write time. A fact whose speaker is an agent MUST be stored with `status: "claim"` and MAY become a `fact` only through an approval bound to the person it concerns. In a room whose `memoryPolicy.personalWrite` is false, nothing said in the room may be written to a personal scope. Recall MUST return a fact only when its `scope` is the asker's private scope or a room the asker is a member of at the current epoch. A fact derived from others MUST carry the strongest taint among its `derivedFrom` set. When a member leaves, withdraws consent or is deleted, facts with that member as `speakerDid` or `subjectDid` in room scope, and facts derived from them, MUST be deleted.

This profile defines the record and these rules; it does not define storage or retrieval structure.

### 12.6 Signed Action Receipts

An action receipt is a statement, signed by the acting agent's key, of what it did (or refused to do) and under which approval and mandate. The signature covers JCS of the receipt with `signature` removed. It proves the agent made these claims; it does not prove they are true.

**v1** (`"v": 1`, `"purpose": "aroha.action-receipt/v1"`): `agentDid`, `action`, `argsSha256` (lowercase hex SHA-256 of JCS of the action's arguments), `at`, `tainted`, `provenance?`, `approval?` (`approverDid`, `approvedAt`, `approvalId`), `mandateId?`, `mandateGrantor?`, `correlationId?`, `signature`.

**v2** (`"v": 2`, `"purpose": "aroha.action-receipt/v2"`): every v1 field, plus `requesterDid?` (who asked), `principalDid?` (whose authority it ran under), `executorDid?` (who executed or refused it), `presentedHash?`, `traceparent?` (W3C Trace Context), `outcome` (`executed` | `denied`), `denialReason?`, `roomId?`, `onBehalfOf?`; `approval` gains `presentedHash?` and `approverSignature?`.

A verifier MUST accept both versions, and MUST reject a receipt that carries a field its version does not define, a `denied` receipt without a `denialReason`, or an `executed` receipt with one. An implementation SHOULD issue a receipt for a refused action as well as for an executed one.

**Presented hash.** `presentedHash` is the lowercase hex SHA-256 of JCS of exactly what was shown to the approver. A `UserApproval` that carries `presentedHash` MUST have its `userSignature` made over JCS of `{ "invariants", "presentedHash", "purpose": "aroha.user-approval/v2" }`; one without it is a legacy approval signed over the key-sorted invariants. A party holding the presented content checks a verified receipt by recomputing the hash; a verifier MUST treat a mismatch with any `presentedHash` in the receipt as a failure.

### 12.7 ArohaDisclosure

An `ArohaDisclosure` states that a message comes from an AI agent and names the principal it acts for:

```json
{ "v": 1, "agentDid": "<DID>", "principalDid": "<DID>",
  "principalKind": "person | organization", "purpose": "<text, at most 512 characters>",
  "hop": 0, "aiGenerated": true }
```

`hop` is 0 for the agent its principal addressed directly and increases by one per delegation. An envelope MAY carry a disclosure in its optional `disclosure` field; it is then covered by the envelope signature (§6.2). A receiver MUST reject an envelope whose disclosure is malformed or whose `agentDid` differs from `from`. A room carries its agent's disclosure (§12.1), and an implementation SHOULD show it to every member on joining. A disclosure is a statement by the agent; that the principal authorised the agent is shown by a mandate chain rooted in that principal, not by the disclosure.

---

## Appendix A — Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `Aroha_INVALID_SIGNATURE` | 401 | Ed25519 signature verification failed |
| `Aroha_EXPIRED_MESSAGE` | 401 | Message `expires` is in the past |
| `Aroha_REPLAY_DETECTED` | 401 | Nonce has been seen before |
| `Aroha_UNAUTHORIZED` | 401 | Credential missing, malformed, expired, or from unknown issuer |
| `Aroha_FORBIDDEN` | 403 | Principal is authenticated but lacks the required action permission |
| `Aroha_UNKNOWN_CAPABILITY` | 400 | Capability ID not recognized |
| `Aroha_TRUST_LEVEL_INSUFFICIENT` | 403 | Sender's trust level too low |
| `Aroha_RESERVATION_FAILED` | 409 | Could not reserve the resource |
| `Aroha_RESERVATION_EXPIRED` | 410 | Reservation hold window passed |
| `Aroha_COMMIT_FAILED` | 409 | Could not commit the reservation |
| `Aroha_CANCEL_FAILED` | 409 | Could not cancel (non-reversible) |
| `Aroha_INVALID_TOKEN` | 404 | Unknown reservation token |
| `Aroha_NO_INVENTORY` | 409 | Resource not available |
| `Aroha_CAPACITY_EXCEEDED` | 503 | Agent capacity limit reached; retry later |
| `Aroha_SERVICE_UNAVAILABLE` | 503 | Agent temporarily unavailable |
| `Aroha_INTERNAL_ERROR` | 500 | Unspecified internal error |
| `Aroha_INVALID_PARAMS` | 400 | Request parameters failed schema validation |
| `CSN_NO_STRUCTURAL_MATCH` | 404 | No capability matched the request's structure (CSN extension; note: no `Aroha_` prefix) |
| `Aroha_ACTION_LIMIT_EXCEEDED` | 403 | Invocation count exceeds the task mandate's `actionLimits` |
| `Aroha_COMPUTE_LIMIT_EXCEEDED` | 403 | Compute budget (tokens, requests, time) exhausted |
| `Aroha_REVERSIBILITY_VIOLATION` | 403 | Capability is irreversible but the mandate requires reversible actions only |
| `Aroha_HUMAN_GATE_REQUIRED` | 403 | Capability requires human approval before execution |
| `Aroha_DATA_ACCESS_VIOLATION` | 403 | Access to a data resource beyond the mandate's scope |
| `Aroha_SANDBOX_REQUIRED` | 403 | Code execution attempted outside a declared sandbox |
| `Aroha_DELEGATION_DEPTH_EXCEEDED` | 403 | Delegation chain deeper than allowed |
| `Aroha_CAPABILITY_NOT_PERMITTED` | 403 | Capability not in the mandate's allowed list |
| `Aroha_SETTLEMENT_RAIL_MISMATCH` | 409 | Requester's and provider's settlement rails have nothing in common |
| `Aroha_COMMIT_DISPUTED` | 409 | Commit result disputed in the challenge window, or resolved against the provider |

The `code` string in the `ArohaError` body is normative; the HTTP status is a recommendation for HTTP transports. The first 17 codes are shared by every reference SDK; the remaining 11 are implemented in the TypeScript reference only, and a receiver MUST treat an unknown code as a generic, non-retryable error unless `retryable` says otherwise.

---

## Appendix B — Reference Implementations

Reference SDKs implement the protocol in four languages. Their use is optional — any software that correctly implements the rules in this document is a conformant Aroha implementation.

### TypeScript SDK (`@aroha-sdk/*`)

Organized to mirror the protocol layers exactly:

```
@aroha-sdk/core          → Layers 0–3 (transport, identity, crypto, messaging)
  @aroha-sdk/core/identity  — DID generation (z-form, E-form, named), Key Event
                              Logs (inception, rotation, recovery, revocation),
                              z→E migration linkage, W3C VP issuance
  @aroha-sdk/core/crypto    — Ed25519 sign/verify, RFC 8785 JCS, DIDComm v2 JWE
  @aroha-sdk/core/messages  — Envelope build/validate (§6.3 rules), nonce
                              registry, the 19 message types, error codes
  @aroha-sdk/core/transport — HTTPS + WebSocket server and client
  (the package root re-exports all of these; the subpaths let runtimes without
   Node APIs, such as edge workers, import identity/crypto/messages alone)

@aroha-sdk/credentials   → Spending mandates (v2 tokens, §6.5: issue, attenuate,
                           verifyMandateChain, redemption), task mandates, RBAC,
                           Human Credentials, auth middleware
@aroha-sdk/delegation    → Multi-hop delegated serving: attenuated task-mandate
                           chains verified against trust anchors at every hop
@aroha-sdk/settlement    → Extension: ApiKey, Quota, Escrow Settlement
@aroha-sdk/commerce      → Extension: B2B, B2C, C2B Commerce Agreements
@aroha-sdk/registry      → Layer 2 (HTTP client, discovery; subpaths
                           /contract, /ipfs, /discover, /server, /sar,
                           /personal-name)
@aroha-sdk/orchestrator  → Extension: orchestration (saga engine, agent selector, negotiator)
@aroha-sdk/preferences   → Extension: preference context (profile, filter, scorer, satisfaction)
@aroha-sdk/mcp-bridge    → MCP interoperability adapter
@aroha-sdk/a2a-bridge    → A2A interoperability adapter
```

The v2 mandate token format (§6.5), the envelope validation rules of §6.3 and E-form DID / Key Event Log verification are implemented in TypeScript, Python, Go and Java, each tested against the shared vectors in `packages/aroha-credentials/test-vectors/mandate-v2.json`.

### Python SDK (`aroha` on PyPI)

```
aroha.identity       → DID generation, Ed25519 keys, multibase encoding
aroha.crypto         → Sign/verify/canonicalize, AES-256-GCM encryption
aroha.messages       → Envelope build/validate, nonce registry
aroha.transport      → FastAPI server, httpx client
aroha.orchestrator   → SagaEngine, AgentSelector
aroha.bridges.langchain_bridge  → ArohaCapabilityTool (LangChain BaseTool)
aroha.bridges.crewai_bridge     → ArohaCrewTool (CrewAI BaseTool)
aroha.bridges.autogen_bridge    → aroha_tools_for_autogen() (AutoGen FunctionTool)
```

Install extras: `pip install aroha[langchain]`, `[crewai]`, `[autogen]`

### Go and Java SDKs — partial

Partial Go and Java implementations exist in the reference repository
(`sdks/go`, `sdks/java`). They cover the envelope, signature validation,
v2 mandate chains, E-form DID verification and sagas, but not the full
protocol surface. Neither is published as a stable artifact yet.

**Status of the non-TypeScript SDKs:** Python, Go and Java implement v2 mandate tokens (issue, attenuate, chain verification), the §6.3 envelope rules and E-form DID / Key Event Log verification. Their `did:aroha-web` support still follows the earlier schema, and they do not implement the four TypeScript-only message types or the 11 TypeScript-only error codes; see each SDK's README.

Nothing in this specification depends on either. The normative requirements are
language agnostic, so an implementer in any language can conform today by
following the protocol directly — the conformance matrix, not any particular
codebase, is the definition of correctness.

### Smart Contracts (Solidity 0.8+, Polygon PoS)

```
contracts/ArohaRegistry.sol    → Agent registration, capability indexing, staking, key rotation
contracts/ArohaEscrow.sol      → Payment escrow for saga transactions
contracts/ArohaReputation.sol  → Outcome recording, reputation oracle (EMA scoring)
```

---

## Appendix C — Post-Quantum Cryptography Migration

> **This appendix is non-normative and describes future work.** No reference implementation supports post-quantum keys today. RFC 2119 keywords in this appendix describe intended future requirements, not requirements of Aroha 1.0 conformance.

This appendix defines how implementations transition from Ed25519 to post-quantum (PQ) signature schemes without a protocol flag-day or breaking change.

### C.1 Motivation

Ed25519 (128-bit classical security) is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. NIST has standardized three post-quantum signature schemes:

| Algorithm | NIST Standard | Public key | Signature | Notes |
|-----------|--------------|-----------|-----------|-------|
| ML-DSA-44 (Dilithium2) | FIPS 204 | 1,312 bytes | 2,420 bytes | Recommended for most Aroha deployments |
| SLH-DSA-128s (SPHINCS+) | FIPS 205 | 32 bytes | 7,856 bytes | Conservative / hash-based; largest signatures |
| FN-DSA-512 (Falcon-512) | FIPS 206 | 897 bytes | ~666 bytes | Compact signatures; complex implementation |

All three are supported as primary or additional keys in `did:aroha` DID Documents.

### C.2 Cryptographic Isolation

The entire signing surface in the Aroha TypeScript SDK is isolated to two files:

- `packages/aroha-core/src/crypto/signing.ts` — exports `sign(message, privateKey)`, `verify(message, sig, publicKey)`, `canonicalize(obj)`. Replace the `@noble/ed25519` import here.
- `packages/aroha-core/src/identity/did.ts` — generates keypairs; update to produce PQ keys and the correct multibase prefix.

All callers — `buildEnvelope`, `validateEnvelope`, or `issueHumanCredential`/`verifyHumanCredential` (if using `@aroha-sdk/credentials`) — are unaffected.

### C.3 DID Document Changes

Add a second `verificationMethod` entry for the PQ key. The existing Ed25519 entry remains valid during the hybrid period:

```json
{
  "verificationMethod": [
    {
      "id": "did:aroha:example#key-1",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6Mk..."
    },
    {
      "id": "did:aroha:example#key-pq",
      "type": "Mldsa44VerificationKey2025",
      "publicKeyMultibase": "u<base64url-1312-bytes>"
    }
  ],
  "authentication": [
    "did:aroha:example#key-1",
    "did:aroha:example#key-pq"
  ]
}
```

Supported `type` strings:

| Algorithm | `verificationMethod.type` | Multibase prefix |
|-----------|--------------------------|-----------------|
| ML-DSA-44 | `Mldsa44VerificationKey2025` | `u` (base64url) |
| SLH-DSA-128s | `SlhDsa128sVerificationKey2025` | `u` (base64url) |
| FN-DSA-512 | `FnDsa512VerificationKey2025` | `u` (base64url) |

The `proof.verificationMethod` field in each message envelope specifies which key was used. Receivers MUST support any key type listed in the sender's DID Document.

### C.4 On-Chain Registry

The `ArohaRegistry` contract stores `bytes calldata publicKey` without type annotation. For PQ keys, pass the full serialized public key bytes (e.g., 1,312 bytes for ML-DSA-44). The contract does not need modification.

Key rotation follows the same `updatePublicKey` flow — sign the rotation message with the current key (whether Ed25519 or PQ) and provide the new PQ public key.

### C.5 Migration Procedure (No Flag Day)

The hybrid period allows Aroha agents to accept both Ed25519 and PQ signatures simultaneously:

**Step 1 — Add PQ key (non-breaking):**
Generate a PQ key pair. Add it to the DID Document alongside the existing Ed25519 key. Push the updated well-known document. Begin signing new outbound messages with the PQ key.

**Step 2 — Hybrid acceptance (grace period — 90 days recommended):**
All agents MUST accept messages signed with either key during this period. The `proof.verificationMethod` field identifies which key was used.

**Step 3 — Drop Ed25519 key (after grace period):**
Remove the Ed25519 entry from the DID Document. Rotate on-chain via `updatePublicKey` to replace the 32-byte Ed25519 public key with the PQ public key. Sign the rotation proof with the Ed25519 key one final time.

**Step 4 — PQ-only (target state):**
All agents sign and verify using PQ keys only.

### C.6 Conformance

Implementations SHOULD add PQ key support before quantum computers capable of breaking 128-bit elliptic curve keys become publicly available. Aroha Working Group estimates this as a 10–15 year horizon from the date of this specification.

A Aroha agent that supports only Ed25519 remains conformant with Aroha 1.0. Support for at least one NIST-standardized PQ scheme will be REQUIRED in Aroha 2.0.

