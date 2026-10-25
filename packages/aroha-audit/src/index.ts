// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

export type AuditEventType =
  | "saga_started" | "saga_committed" | "saga_compensated" | "saga_failed"
  | "envelope_received" | "envelope_rejected" | "settlement_processed"
  | "credential_issued" | "credential_revoked" | "key_rotated" | "key_revoked"
  // Cross-agent consults (design spec §7). Recorded on EVERY outcome — a
  // consult refused for looping matters as much to an operator as one that
  // was answered.
  | "consult_answered" | "consult_refused" | "consult_failed"
  // Operator actions (design spec §8). Flipping a kill switch is itself an
  // auditable act — otherwise the trail shows a gap in traffic with nothing
  // explaining it.
  | "admin_consults_toggled"
  // Cross-firm invitations — the permission that precedes a consult. Kept
  // distinct from the consult events rather than folded into them: a consult
  // records that something was asked, an invitation records that someone
  // agreed it could be. "Who was granted access, when, and did they accept?"
  // is a question a firm has to answer without replaying every question its
  // agents ever asked, and only these three entries can answer it.
  | "invite_sent" | "invite_accepted" | "invite_declined" | "invite_withdrawn"
  // Action requests (design spec §5) — the write path. action_executed
  // carries the idempotency key so the trail shows what was performed. It is
  // no longer what makes a replay detectable: that moved to a store the log
  // does not own, which is what allows the log to be rotated at all.
  | "action_pending" | "action_executed" | "action_refused" | "action_failed"
  | "action_cancelled"
  // Rotation, recorded IN the chain rather than as a silent gap. Cutting old
  // entries out would leave the first surviving entry naming a hash that is
  // gone, and a verifier would read routine maintenance as tampering. This
  // entry names the archive and its final hash, so continuity across the cut
  // is checkable instead of assumed.
  | "log_rotated";

export interface AuditEntry {
  seq: number;
  type: AuditEventType;
  sagaId?: string;
  actorDID: string;
  detail: Record<string, unknown>;
  timestamp: string;
  hash: string;
  previousHash: string;
}

type AppendInput = Omit<AuditEntry, "seq" | "timestamp" | "hash" | "previousHash">;

export interface AuditLogOptions {
  /**
   * Entries restored from durable storage. The hash chain resumes from the
   * last one, so tamper-evidence survives a restart — without this the log
   * is only tamper-evident within a single process lifetime, which is not
   * tamper-evident at all.
   */
  initial?: AuditEntry[];
  /**
   * Called with each newly appended entry, for durable persistence.
   *
   * Deliberately injected rather than implemented here: this package is also
   * usable in environments with no filesystem (Cloudflare Workers), so it
   * must not import node:fs. The runtime supplies a JSONL-file sink; a
   * Worker could supply a D1 or KV write, or none at all.
   *
   * A throwing sink does not take down the operation being audited — but it
   * is NOT silently ignored either. See `persistence()`.
   */
  onAppend?: (entry: AuditEntry) => void | Promise<void>;
}

/**
 * How the durable copy is faring. A failed write leaves the entry in the
 * in-memory chain but absent from storage, so the two views DRIFT: on the
 * next restart the log restores from storage without it, and because each
 * view is internally consistent, `verify()` passes on both. A dropped write
 * would then be indistinguishable from a deleted record — precisely the
 * thing a tamper-evident log exists to rule out.
 *
 * Swallowing that silently would make the audit trail claim more than it
 * can back. Counting it instead keeps the operation alive (an audit write
 * failing must not fail the consult it records) while leaving the gap
 * visible to an operator, which is the honest version of this trade.
 */
export interface AuditPersistenceStatus {
  /** Entries appended to the chain that the sink failed to persist. */
  failures: number;
  /** Message from the most recent persistence failure, if any. */
  lastError?: string;
}

export class AuditLog {
  private readonly _entries: AuditEntry[];
  private readonly onAppend?: (entry: AuditEntry) => void | Promise<void>;
  private _persistFailures = 0;
  private _lastPersistError?: string;

  constructor(opts: AuditLogOptions = {}) {
    this._entries = [...(opts.initial ?? [])];
    this.onAppend = opts.onAppend;
  }

  /**
   * Whether the durable copy is keeping up. Non-zero `failures` means the
   * in-memory chain contains entries that storage does not — see
   * AuditPersistenceStatus for why that matters and must not be silent.
   */
  persistence(): AuditPersistenceStatus {
    return this._lastPersistError === undefined
      ? { failures: this._persistFailures }
      : { failures: this._persistFailures, lastError: this._lastPersistError };
  }

  async append(input: AppendInput): Promise<AuditEntry> {
    const seq = this._entries.length;
    const previousHash = seq > 0 ? this._entries[seq - 1].hash : "";
    const timestamp = new Date().toISOString();

    const content = { seq, ...input, timestamp, previousHash };
    const hash = bytesToHex(sha256(JSON.stringify(content)));

    const entry: AuditEntry = { ...content, hash };
    this._entries.push(entry);

    if (this.onAppend) {
      try {
        await this.onAppend(entry);
      } catch (err) {
        // Not rethrown — losing the audited operation because the audit
        // write failed would be a worse outcome than a gap in the log. But
        // NOT silent either: the gap is counted, because from here on the
        // in-memory chain and the durable copy have diverged, and nothing
        // downstream can detect that from the entries alone (see
        // AuditPersistenceStatus).
        this._persistFailures++;
        this._lastPersistError = err instanceof Error ? err.message : String(err);
      }
    }
    return entry;
  }

  entries(): readonly AuditEntry[] {
    return this._entries;
  }

  /**
   * Is this chain internally consistent?
   *
   * Every entry's hash must recompute from its own content, and every entry
   * must name its predecessor's hash.
   *
   * ── The one exception: a rotation seam ─────────────────────────────────
   *
   * A rotated log begins with a `log_rotated` marker whose `hash` field
   * carries the ARCHIVE's final hash, not a hash of itself. That is what
   * lets the surviving entries keep the predecessor they were written with:
   * inserting a normally-hashed anchor would require rewriting every kept
   * entry's previousHash, which would change their hashes and destroy the
   * chain this is meant to protect.
   *
   * So the marker is a seam, not a record, and is checked as one. Recomputing
   * its hash would fail by construction — which it did, firing the tamper
   * warning on every rotated log until this was written.
   *
   * This deliberately proves less on its own: a forged marker could claim any
   * hash. `verifyRotationSeam` in the runtime is what closes that, by reading
   * the archive named in the marker and confirming its final hash and entry
   * count. Two checks, and rotation needs both.
   */
  verify(): boolean {
    for (let i = 0; i < this._entries.length; i++) {
      const entry = this._entries[i];

      if (i === 0 && entry.type === "log_rotated") {
        // The seam. Its hash belongs to the archive, so there is nothing
        // here to recompute — only continuity into the next entry to check.
        const next = this._entries[1];
        if (next && next.previousHash !== entry.hash) return false;
        continue;
      }

      const { hash, ...content } = entry;
      const recomputed = bytesToHex(sha256(JSON.stringify(content)));
      if (recomputed !== hash) return false;
      // The entry after a seam names the archive's last hash, which the seam
      // also carries — so the same comparison holds across the cut.
      if (i > 0 && entry.previousHash !== this._entries[i - 1].hash) return false;
    }
    return true;
  }

  toJSONLines(): string {
    return this._entries.map(e => JSON.stringify(e)).join("\n");
  }
}
