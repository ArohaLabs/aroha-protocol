<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Message Types

Aroha defines exactly 19 message types: 15 shared by every reference SDK, plus `ArohaSpendingMandate`, `ArohaTaskMandate`, `ArohaDispute` and `ArohaDisputeResolution`, which only the TypeScript reference implements. Applications may not invent new top-level types —
extension is done through the `body` field only.

---

## Envelope structure

Every message uses the same outer envelope:

```json
{
  "@context": [
    "https://aroha-labs.com/contexts/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:<uuid-v4>",
  "type": "<MessageType>",
  "from": "did:aroha:<sender>",
  "to": "did:aroha:<recipient>",
  "created": "<ISO8601>",
  "expires": "<ISO8601>",
  "nonce": "<random-hex-32>",
  "correlationId": "<string>",
  "body": { },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO8601>",
    "verificationMethod": "did:aroha:<sender>#key-1",
    "proofPurpose": "authentication",
    "proofValue": "<base64url-Ed25519>"
  }
}
```

`expires` defaults to `created + 300s`. Nonces are checked in a rolling 5-minute window.

---

## Query / search

### ArohaRequest

Orchestrator → Provider. Invoke a read-only capability.

```typescript
// body
{
  capability: string;               // e.g. "search-flights"
  params: Record<string, unknown>;  // capability-specific input
  credentialId?: string;            // human auth (registry-based)
  credentialToken?: string;         // human auth (inline)
  preferenceContext?: {             // optional user constraints
    budget?: { max: number; currency: string };
    quality?: { minRating?: number };
    constraints?: string[];
    consentToken?: string;
  };
}
```

### ArohaResponse

Provider → Orchestrator. Result of a `ArohaRequest`.

```typescript
// body
{
  capability: string;
  result: Record<string, unknown>;
}
```

### ArohaStream

Provider → Orchestrator (WebSocket). Streaming progress update.

```typescript
// body
{
  capability: string;
  progressPct: number;          // 0–100
  event: string;                // e.g. "searching", "found", "complete"
  data?: Record<string, unknown>;
  final?: boolean;              // true on last event
}
```

---

## Negotiation

### ArohaNegotiate

Orchestrator → Provider. Open price negotiation.

```typescript
// body
{
  capability: string;
  params: Record<string, unknown>;
  offerPrice: number;
  currency: string;
  maxRounds?: number;
  credentialId?: string;
  credentialToken?: string;
}
```

### ArohaCounterOffer

Provider → Orchestrator. Counter-propose a price.

```typescript
// body
{
  capability: string;
  counterPrice: number;
  currency: string;
  terms?: Record<string, unknown>;
}
```

### ArohaAccept

Orchestrator → Provider. Accept the current offer.

```typescript
// body
{
  capability: string;
  agreedPrice: number;
  currency: string;
}
```

---

## Saga (atomic transactions)

### ArohaReserve

Orchestrator → Provider. Hold inventory for `holdDurationMs` milliseconds.

```typescript
// body
{
  capability: string;
  params: Record<string, unknown>;
  holdDurationMs: number;         // e.g. 300_000 (5 minutes)
  credentialId?: string;
  credentialToken?: string;
  preferenceContext?: PreferenceContext;
}
```

### ArohaReserveAck

Provider → Orchestrator. Reservation confirmed.

```typescript
// body
{
  reservationToken: string;       // opaque ID — pass back in ArohaCommit/ArohaCancel
  expiresAt: string;              // ISO8601 — when the hold expires
}
```

### ArohaCommit

Orchestrator → Provider. Finalize the reservation. **Must be idempotent.**

```typescript
// body
{
  reservationToken: string;
}
```

### ArohaCommitAck

Provider → Orchestrator. Commitment confirmed.

```typescript
// body
{
  reservationToken: string;
  result: Record<string, unknown>;  // e.g. { pnr: "PNR123", status: "confirmed" }
}
```

### ArohaCancel

Orchestrator → Provider. Compensating transaction — cancel and roll back.

```typescript
// body
{
  reservationToken: string;
  reason: string;                   // e.g. "orchestrator-abort" | "downstream-failure"
}
```

### ArohaCancelAck

Provider → Orchestrator. Cancellation confirmed.

```typescript
// body
{
  reservationToken: string;
}
```

---

## Delegation

### ArohaDelegate

Orchestrator A → Orchestrator B. Forward a request to a sub-orchestrator.

```typescript
// body
{
  delegatedEnvelope: ArohaEnvelope;   // the original request
  delegationProof: string;            // base64url — proof of delegation authority
}
```

---

## Errors

### ArohaError

Provider → Orchestrator. Typed error response.

```typescript
// body
{
  code: ArohaErrorCode;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}
```

See [Aroha 1.0 Appendix A](aroha-1.0.md#appendix-a--error-codes) for all 28 `ArohaErrorCode` values.

---

## Post-saga feedback

### ArohaSatisfactionSignal

Orchestrator → its own preference store. Post-saga satisfaction feedback for preference and reputation learning. It is **private**: an orchestrator MUST NOT send it to provider agents ([Extensions §2.3](extensions.md#23-satisfaction-signals)).

```typescript
// body
{
  sagaId: string;
  outcome: "satisfied" | "neutral" | "dissatisfied";
  dimensions?: {
    price?: "satisfied" | "neutral" | "dissatisfied";
    quality?: "satisfied" | "neutral" | "dissatisfied";
    speed?: "satisfied" | "neutral" | "dissatisfied";
  };
  comment?: string;
}
```

---

## Message type summary

| Type | Direction | Saga? | Description |
|------|-----------|-------|-------------|
| `ArohaRequest` | → Provider | | Invoke capability |
| `ArohaResponse` | ← Provider | | Capability result |
| `ArohaStream` | ← Provider | | Async progress (WebSocket) |
| `ArohaNegotiate` | → Provider | | Open negotiation |
| `ArohaCounterOffer` | ← Provider | | Counter-propose price |
| `ArohaAccept` | → Provider | | Accept offer |
| `ArohaReserve` | → Provider | ✓ | Hold inventory |
| `ArohaReserveAck` | ← Provider | ✓ | Reservation token |
| `ArohaCommit` | → Provider | ✓ | Finalize (idempotent) |
| `ArohaCommitAck` | ← Provider | ✓ | Confirmation + result |
| `ArohaCancel` | → Provider | ✓ | Compensate / roll back |
| `ArohaCancelAck` | ← Provider | ✓ | Cancellation confirmed |
| `ArohaDelegate` | → Orchestrator | | Forward to sub-orchestrator |
| `ArohaError` | ← Provider | | Typed error |
| `ArohaSatisfactionSignal` | → self (own preference store; never to a provider) | | Post-saga feedback |
| `ArohaSpendingMandate` | Grantor → grantee | | Spending authority token (TypeScript reference only) |
| `ArohaTaskMandate` | Grantor → grantee | | Task authority token (TypeScript reference only) |
| `ArohaDispute` | Party → arbiter | ✓ | Contest a commit result (TypeScript reference only) |
| `ArohaDisputeResolution` | Arbiter → parties | ✓ | Binding release / refund / split (TypeScript reference only) |

---

## Spending Mandate

### ArohaSpendingMandate

Carries an `Intent`, `Cart`, or `Payment` mandate token in a Aroha envelope. The mandate authorises the recipient to act within the constraints without exposing raw payment credentials. The normative wire format (v2 token, signature, chain verification) is [Aroha 1.0 §6.5](aroha-1.0.md#65-spending-mandate-token-format-v2); see also the [`@aroha-sdk/credentials` documentation](https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/packages/credentials.md#spending-mandates).

```typescript
// body
{
  mandateTier:    "intent" | "cart" | "payment";
  constraints: {
    spendLimitUsd:               number;
    sessionLimitUsd?:            number;
    currency?:                   string;   // ISO 4217, default "USD"
    merchantCategory?:           string | null;
    requireHumanApprovalAboveUsd?: number;
    allowedMerchants?:           string[] | null;
    validFrom?:                  string;  // ISO8601
    validUntil?:                 string;  // ISO8601
  };
  grantee:        string;   // DID receiving the mandate
  grantor:        string;   // DID issuing the mandate
  issuedAt:       string;   // ISO8601 — REQUIRED in v2
  expiresAt:      string;   // ISO8601
  parentMandateId: string | null;
  mandateId:      string;
}
```

A child mandate cannot widen any constraint of its parent. In the TypeScript reference, `attenuateToCart` / `attenuateToPayment` throw an `Error` (message `Cannot attenuate <parent> → <child>: …`) before signing, and `verifyMandateChain` re-checks every link, because the attenuation-time check is advisory — the attenuating agent could skip it. A child that omits a limit its parent sets is a widening ([Aroha 1.0 §6.5](aroha-1.0.md#65-spending-mandate-token-format-v2)).

---

## CSN Extensions

### ArohaNegotiate — CSN extension

The `csn` field extends `ArohaNegotiate` with intent-based capability discovery. Omit it for traditional price/SLA-only negotiation. See [Capability Schema Negotiation →](csn.md)

```typescript
// body.csn (optional)
{
  capabilityIntent?:          string;   // natural-language description of the need
  desiredSchema?: {
    input:  Record<string, unknown>;   // JSON Schema for the capability's input
    output?: Record<string, unknown>;  // JSON Schema for the expected output
  };
  schemaHash?:                string;   // SHA-256 hex of canonical desiredSchema
  requestCapabilityManifest?: boolean;  // request provider's full signed manifest
}
```

### ArohaAccept — CSN extension

```typescript
// body.csn (present when CSN resolved the capability)
{
  resolvedCapability?: string;         // actual registered capability name
  agreedSchema?: {
    input:  Record<string, unknown>;
    output?: Record<string, unknown>;
  };
  schemaHash?:          string;        // echo of requestor's schemaHash
  capabilityManifest?:  SignedCapabilityManifest;
  matchMethod?:         "schema" | "intent" | "cache";
  compatibilityScore?:  number;        // 0–1; ≥0.85 = confident, 0.5–0.85 = ambiguous
}
```

### Match method values

| Value | Meaning |
|-------|---------|
| `"schema"` | Deterministic structural match (no LLM needed) |
| `"intent"` | LLM-assisted match (score was 0.5–0.85) |
| `"cache"` | Recovered from SHA-256 discovery cache (zero-latency) |
