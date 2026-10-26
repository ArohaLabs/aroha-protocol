<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Error Codes

All Aroha errors are returned as a `ArohaError` envelope:

```typescript
// body
{
  code: ArohaErrorCode;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}
```

---

## ArohaErrorCode values

These are the canonical wire values. Every SDK uses the same strings — a `ArohaError` from a Go agent is parsed identically by a Python consumer.

### Authentication & Authorization

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_UNAUTHORIZED` | 401 | false | No credential or credential verification failed |
| `Aroha_FORBIDDEN` | 403 | false | Credential valid but role lacks permission for this action |
| `Aroha_INVALID_SIGNATURE` | 400 | false | Ed25519 proof verification failed |
| `Aroha_REPLAY_DETECTED` | 400 | false | Nonce already seen in the rolling 5-minute window |

### Message validation

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_EXPIRED_MESSAGE` | 400 | false | `envelope.expires` is in the past |
| `Aroha_TRUST_LEVEL_INSUFFICIENT` | 403 | false | Sender's trust level does not meet requirement |
| `Aroha_UNKNOWN_CAPABILITY` | 400 | false | Capability ID not recognised by this agent |
| `Aroha_INVALID_PARAMS` | 400 | false | Required body field missing or wrong type |

### Saga

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_RESERVATION_FAILED` | 409 | true | Reserve attempt failed (provider-side error) |
| `Aroha_RESERVATION_EXPIRED` | 409 | false | Hold duration elapsed before commit |
| `Aroha_COMMIT_FAILED` | 500 | true | Commit could not be applied; idempotent retry safe |
| `Aroha_CANCEL_FAILED` | 500 | true | Compensation failed; manual intervention may be needed |
| `Aroha_INVALID_TOKEN` | 400 | false | `reservationToken` unknown or already cancelled |

### Availability

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_NO_INVENTORY` | 409 | true | Capability temporarily unavailable (no seats, rooms, etc.) |
| `Aroha_CAPACITY_EXCEEDED` | 429 | true | Provider is at capacity; retry later |
| `Aroha_SERVICE_UNAVAILABLE` | 503 | true | Provider dependency is down |

### Internal

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_INTERNAL_ERROR` | 500 | true | Unexpected internal error |

### CSN extension

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `CSN_NO_STRUCTURAL_MATCH` | 404 | — | No structural capability schema match found (note: no `Aroha_` prefix) |

### Task mandates

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_ACTION_LIMIT_EXCEEDED` | 403 | — | Action invocation count exceeds the mandate's `actionLimits` |
| `Aroha_COMPUTE_LIMIT_EXCEEDED` | 403 | — | Compute resource (tokens/requests/time) budget exhausted |
| `Aroha_REVERSIBILITY_VIOLATION` | 403 | — | Capability is irreversible but the mandate requires `reversibleOnly` |
| `Aroha_HUMAN_GATE_REQUIRED` | 403 | — | Capability requires human approval (`humanGates`) before execution |
| `Aroha_DATA_ACCESS_VIOLATION` | 403 | — | Agent attempted to access a data resource beyond its scope |
| `Aroha_SANDBOX_REQUIRED` | 403 | — | Code execution attempted outside a declared sandbox |
| `Aroha_DELEGATION_DEPTH_EXCEEDED` | 403 | — | Delegation chain depth exceeds `maxDelegationDepth` |
| `Aroha_CAPABILITY_NOT_PERMITTED` | 403 | — | Capability not in the mandate's allowed list |

### Settlement

| Code | HTTP equivalent | `retryable` | Description |
|------|----------------|-------------|-------------|
| `Aroha_SETTLEMENT_RAIL_MISMATCH` | 409 | — | Requestor's and provider's settlement rails share no common value |
| `Aroha_COMMIT_DISPUTED` | 409 | — | Buyer disputed the commit result during the challenge window, or the arbiter resolved against the provider |

For the codes marked —, the code does not fix a `retryable` value; read it from the `ArohaError` body. The HTTP statuses for these codes are the ones recommended in the specification's error-code appendix ([Appendix A](../spec/aroha-1.0.md#appendix-a--error-codes)).

---

## Sending errors in TypeScript

```typescript
import { buildEnvelope, ArohaErrorCode } from "@aroha-sdk/core";

// In your message handler:
return buildEnvelope("ArohaError", agentDID, envelope.from, {
  code: ArohaErrorCode.NoInventory,
  message: "No seats available for this flight",
  retryable: true,
  details: { nextAvailableDate: "2026-06-05" },
}, envelope.correlationId, privateKey);
```

---

## Error handling in orchestrators

```typescript
const reply = await arohaClient.send(endpoint, requestEnvelope);

if (reply.type === "ArohaError") {
  const { code, message, retryable } = reply.body as ArohaErrorBody;

  if (retryable) {
    // Retry with exponential backoff
    await sleep(1000 * attempt);
    continue;
  }

  if (code === "Aroha_NO_INVENTORY") {
    // Try next provider
    continue;
  }

  throw new Error(`Provider error: ${code} — ${message}`);
}
```

---

## Saga error handling

When a provider returns `ArohaError` during the **Reserve** phase, the `SagaEngine`
automatically aborts and does not send any commits.

When a provider returns `ArohaError` during the **Commit** phase, the `SagaEngine`
triggers LIFO compensation (`ArohaCancel`) for all previously committed steps.

`ArohaCancel` handlers MUST always succeed — if a cancel fails, the `SagaEngine`
logs the failure and continues compensating the remaining steps. Providers should
never return `ArohaError` in response to `ArohaCancel`.
