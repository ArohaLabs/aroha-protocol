<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/audit

Tamper-evident, append-only audit log for Aroha saga and envelope events. Every entry is SHA-256 hash-chained and linked to the previous entry, making silent modification detectable without a blockchain.

```bash
npm install @aroha-sdk/audit
```

---

## AuditLog

```typescript
import { AuditLog } from "@aroha-sdk/audit";

const log = new AuditLog();

// Append events as saga milestones occur
await log.append({
  type:     "saga_started",
  sagaId:   "saga-abc123",
  actorDID: "did:aroha:orchestrator",
  detail:   { capability: "book-flight", params: { origin: "LHR", destination: "NRT" } },
});

await log.append({
  type:     "settlement_processed",
  sagaId:   "saga-abc123",
  actorDID: "did:aroha:travel-agent",
  detail:   { amount: 0.05, currency: "USD", receiptId: "rcpt-xyz" },
});

await log.append({
  type:     "saga_committed",
  sagaId:   "saga-abc123",
  actorDID: "did:aroha:orchestrator",
  detail:   { stepCount: 2, durationMs: 1240 },
});
```

Each entry receives:

| Field | Description |
|---|---|
| `seq` | Monotonically increasing sequence number |
| `timestamp` | ISO 8601 timestamp at append time |
| `hash` | SHA-256 of the entry's JSON serialisation (`hash` field excluded) |
| `previousHash` | Hash of the previous entry — empty string for the first entry |

---

## Supported event types

```typescript
type AuditEventType =
  | "saga_started"        // Saga engine began coordinating
  | "saga_committed"      // All steps committed successfully
  | "saga_compensated"    // LIFO compensation chain ran successfully
  | "saga_failed"         // Saga failed and compensation could not complete
  | "envelope_received"   // An inbound Aroha envelope passed verification
  | "envelope_rejected"   // Envelope failed signature / nonce / expiry check
  | "settlement_processed"// A payment was charged or refunded
  | "credential_issued"   // A verifiable credential was issued
  | "credential_revoked"  // A verifiable credential was revoked
  | "key_rotated"         // DID key rotation occurred
  | "key_revoked"         // DID key was revoked
  | "consult_answered" | "consult_refused" | "consult_failed"   // cross-agent consults
  | "admin_consults_toggled"                                     // operator kill switch
  | "invite_sent" | "invite_accepted" | "invite_declined" | "invite_withdrawn"
  | "action_pending" | "action_executed" | "action_refused" | "action_failed" | "action_cancelled"
  | "log_rotated";        // rotation seam: names the archive's final hash
```

---

## Reading and verifying

```typescript
// Read all entries
const entries = log.entries();

// Verify the entire chain
const isValid = log.verify();
// Returns false if any entry's hash doesn't match its content,
// or if any previousHash doesn't match the prior entry's hash.

// Export as newline-delimited JSON (NDJSON) for log shipping
const ndjson = log.toJSONLines();
// One JSON object per line — compatible with Datadog, Elasticsearch, etc.
```

---

## Integration with ArohaServer

Mount `AuditLog` directly on your `onMessage` handler — no middleware required.

```typescript
import { ArohaServer } from "@aroha-sdk/core";
import { AuditLog }    from "@aroha-sdk/audit";

const audit = new AuditLog();

const server = new ArohaServer({
  agentDID: myDID,
  didDocument: identity.document,
  port: 3001,
  onMessage: async (envelope, respond) => {
    await audit.append({
      type:     "envelope_received",
      actorDID: envelope.from,
      detail:   { type: envelope.type, correlationId: envelope.correlationId },
    });

    const result = await handleCapability(envelope.body);
    respond(result);
  },
});
```

---

## Compliance notes

- **Self-assessed; not auditor-reviewed.** No auditor or compliance assessor has evaluated this package. The points below describe what the hash chain can contribute as evidence; they are not certifications.
- The hash chain can support a **GDPR** record of processing activities (Art. 30); it does not by itself satisfy the requirement.
- It can be used as **SOC 2** evidence that log entries were not deleted or reordered after the fact (self-assessed; whether it is sufficient is for your auditor to decide).
- For long-term storage, periodically snapshot `log.toJSONLines()` to an append-only store (S3 Object Lock, Cloudflare R2, WORM drives).
- `@aroha-sdk/audit` deliberately has no network or filesystem I/O — it is an in-process log. Persistence and shipping are the application's responsibility: pass `onAppend` to write each entry to a durable sink and `initial` to resume the chain after a restart (`new AuditLog({ initial, onAppend })`). `log.persistence()` reports how many entries the sink failed to store.
