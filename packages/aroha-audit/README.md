# @aroha-sdk/audit

Append-only, hash-chained audit log for Aroha agent chains — a tamper-evident record of what was
authorised and what was done under that authority.

## Install

```bash
npm install @aroha-sdk/audit
```

## Quick example

```typescript
import { AuditLog, type AuditEntry } from "@aroha-sdk/audit";
import { appendFileSync } from "node:fs";

// The package never touches the filesystem itself (it also runs on Workers):
// you supply the durable sink, and the entries to resume from on restart.
const log = new AuditLog({
  initial: [] as AuditEntry[],
  onAppend: (entry) => appendFileSync("./audit.jsonl", JSON.stringify(entry) + "\n"),
});

// Record a credential issued under a mandate
await log.append({
  type: "credential_issued",
  actorDID: "did:aroha:orchestrator",
  detail: { grantee: "did:aroha:flight-agent", spendLimitUsd: 300 },
});

// Record the action taken under it
await log.append({
  type: "action_executed",
  actorDID: "did:aroha:flight-agent",
  sagaId: "saga-123",
  detail: { action: "book-flight", amountUsd: 299 },
});

// Check the chain has not been altered
const intact: boolean = log.verify(); // true

// Durable copy falling behind? Non-zero failures means storage lost entries.
const { failures } = log.persistence();

// Export as JSON Lines (e.g. for SIEM ingestion)
const jsonLines = log.toJSONLines();
```

## Why this exists in the mandate chain

Cryptographic mandate bounds prevent over-scope at runtime. The audit log records, after the
fact, that those bounds were respected — every credential issued and every action taken —
in a hash chain where an edited or deleted entry breaks `verify()`. Supports compliance
evidence, debugging, and reputation scoring.

## API

- `new AuditLog({ initial?, onAppend? })` — create a log, optionally resuming from persisted entries.
  - `log.append({ type, actorDID, detail, sagaId? })` — append a hash-chained entry; returns the `AuditEntry`.
  - `log.verify()` — `true` when every hash recomputes and links to its predecessor (a leading
    `log_rotated` marker is treated as a rotation seam).
  - `log.entries()` — the entries, read-only.
  - `log.persistence()` — `{ failures, lastError? }` for the `onAppend` sink.
  - `log.toJSONLines()` — the log as JSON Lines.
- `AuditEventType` — the event vocabulary (`saga_*`, `envelope_*`, `credential_*`, `key_*`,
  `consult_*`, `invite_*`, `action_*`, `log_rotated`, …).

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
