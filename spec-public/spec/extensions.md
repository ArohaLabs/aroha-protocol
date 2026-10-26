<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol Extensions
## Orchestration and Preference Context, Version 1.0

**Status:** Draft. Companion to the [Aroha Protocol Specification 1.0](aroha-1.0.md).  
**Date:** 2026-10-25

---

## About this document

Until 2026-10-25 these two sections were Layer 4 (§7) and Layer 5 (§8) of the
core specification. They moved here unchanged so the core specification covers
only Transport, Identity, Registry and Messaging. Their rules apply to any
implementation that adopts the extension; an implementation that does not
adopt it is still a conformant Aroha implementation.

The message types these extensions use (`ArohaReserve`, `ArohaCommit`,
`ArohaCancel`, their acknowledgements, and `ArohaSatisfactionSignal`) stay
defined in core §6.4, and their envelopes follow core §6.

The reference implementations are `@aroha-sdk/orchestrator` (sagas) and
`@aroha-sdk/preferences` (preference context), published on npm. The
orchestrator's source is not in this repository.

---

## 1. Orchestration (sagas)

### 1.1 Saga Requirements

Any agent with `sagaRole: "participant"` MUST implement:
- `ArohaReserve` / `ArohaReserveAck`
- `ArohaCommit` / `ArohaCommitAck`
- `ArohaCancel` / `ArohaCancelAck`

### 1.2 Saga State Machine

```
IDLE
  └─[ArohaReserve]──► RESERVED
                        ├─[ArohaCommit]──► COMMITTED
                        ├─[ArohaCancel]──► CANCELLED
                        └─[timeout]─────► AUTO_CANCELLED
```

### 1.3 Idempotency

`ArohaCommit` MUST be idempotent. Sending the same `reservationToken` twice MUST return identical `ArohaCommitAck`.

### 1.4 Compensation Order

When a saga compensates (rolls back), `ArohaCancel` MUST be sent in reverse order of `ArohaCommit` (LIFO).

### 1.5 Hold Duration

A `ArohaReserve` MUST hold the resource for at least `holdDurationMs` milliseconds. If no `ArohaCommit` or `ArohaCancel` is received within that window, the provider MAY auto-cancel.

---

## 2. Preference Context

### 2.1 Preference Context Format

An orchestrator MAY attach to any `ArohaRequest` or `ArohaReserve`:

```json
{
  "preferenceContext": {
    "budget": { "max": 600, "currency": "USD" },
    "quality": { "minRating": 4.0 },
    "accessibility": { "wheelchairAccess": false },
    "constraints": ["direct-flights-only"],
    "consentToken": "<W3C-VC-signed-by-user-agent>"
  }
}
```

### 2.2 Provider Obligations

- Provider agents MUST NOT store, log, or share `preferenceContext` beyond fulfilling the current request.
- Extended access is ONLY permitted if `consentToken` explicitly grants it.
- Provider agents MUST ignore unknown fields in `preferenceContext` (forward compatibility).

### 2.3 Satisfaction Signals

`ArohaSatisfactionSignal` messages are PRIVATE. They MUST be sent only from the orchestrator to itself (or its local preference store). They MUST NOT be sent to provider agents.

The privacy considerations for preference data are in the core specification's
Privacy Considerations section.

---

## 3. Conformance

These requirements apply in addition to core §11.

A provider agent that adopts these extensions is conformant if it:

1. Implements all three saga message pairs (§1.1) for each capability where `sagaRole` is `"participant"`.
2. Does not store, log, or forward `preferenceContext` beyond the current request unless a valid `consentToken` authorizes it (§2.2).

An orchestrator agent that adopts these extensions is conformant if it:

1. Implements the saga state machine (§1.2) when sending `ArohaReserve` messages.
2. Sends compensation (`ArohaCancel`) in LIFO order on saga failure (§1.4).
3. Sends `ArohaSatisfactionSignal` messages only to itself or its local preference store, never to provider agents (§2.3).
