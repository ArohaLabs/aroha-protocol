// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Data retention — run by the Worker's scheduled() handler (wrangler.toml
 * [triggers] crons, hourly).
 *
 * Several tables only ever grew. Single-use rows (challenges, connect
 * tokens and proofs, rotation nonces) were consumed but never deleted once
 * expired; expired SAR records were filtered out of every query yet kept
 * forever; and the telemetry-like tables accumulated without bound, which
 * is both a cost and a privacy question (they hold key hashes and DIDs
 * linked to timestamps). The only pruning was a fire-and-forget call on
 * the rotate-key path, so on a quiet registry nothing was ever removed.
 *
 * Every window lives in RETENTION below, with the reason for its length,
 * so changing one is a reviewed edit to one table rather than a hunt
 * through route files.
 */

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/**
 * Rows older than `keepMs` (by `column`, Unix ms) are deleted. `expiry`
 * rows store their own expiry instant, so keepMs is a grace period after it.
 */
export interface RetentionRule {
  table: string;
  /** SQL expression yielding the row's reference instant in Unix ms. Never user input. */
  column: string;
  keepMs: number;
  why: string;
}

export const RETENTION: readonly RetentionRule[] = [
  // ── Single-use, self-expiring: delete shortly after expiry ────────────────
  // A one-hour grace keeps an expired row around long enough to answer a
  // late duplicate as "expired" in logs rather than "never existed".
  { table: "registration_challenges", column: "expires_at", keepMs: HOUR,
    why: "single-use registration nonce; useless once expired" },
  { table: "relay_connect_tokens", column: "expires_at", keepMs: HOUR,
    why: "single-use WebSocket token; 60 s TTL" },
  { table: "relay_connect_proofs", column: "expires_at", keepMs: HOUR,
    why: "replay record; a proof past its expiry already fails the freshness check" },
  { table: "rotation_nonces", column: "expires_at", keepMs: HOUR,
    why: "replay record; issuedAt is bounded to ±5 min, so an expired nonce cannot be replayed" },
  { table: "sar_records", column: "(issued_at + ttl)", keepMs: DAY,
    why: "an expired Signed Agent Record is never served; the publisher re-publishes" },

  // ── Accumulating records: keep a bounded history ──────────────────────────
  { table: "signal_rate_limits", column: "window_start", keepMs: 2 * DAY,
    why: "counts per 24 h window; nothing reads a window older than the current one" },
  { table: "analytics_events", column: "created_at", keepMs: 90 * DAY,
    why: "discovery statistics are reported over 7/30-day ranges; 90 days covers them with margin" },
  { table: "routing_signals", column: "created_at", keepMs: 90 * DAY,
    why: "routing priors should reflect recent model quality; old signals describe models that changed" },
  // Longer than the telemetry tables: attestations are reputation evidence,
  // and dropping them early would move scores. A year keeps a full history
  // of current behaviour without holding caller DIDs indefinitely.
  { table: "caller_attestations", column: "submitted_at", keepMs: 365 * DAY,
    why: "reputation evidence; a year of history, not forever" },
  // A SET a receiver has not collected (poll) or accepted (push) within 30
  // days is past any useful revocation latency; the revocation itself stays
  // queryable at its own endpoint. Delivered rows go on the same clock.
  { table: "ssf_outbox", column: "created_at", keepMs: 30 * DAY,
    why: "Shared Signals delivery queue; a 30-day-old revocation event is history, not a signal" },
  // NOT listed, deliberately: audit_anchors (migration 018). An anchor is the
  // off-machine witness a runtime's audit log is checked against, possibly
  // years later; pruning it would reopen the undetectable-truncation gap it
  // exists to close. Anchors are permanent.
];

/** Delete every row outside its retention window. Returns rows removed per table. */
export async function pruneExpired(db: D1Database, now: number = Date.now()): Promise<Record<string, number>> {
  const removed: Record<string, number> = {};
  for (const rule of RETENTION) {
    // table / column come from the constant table above, never from a request.
    // One table failing (e.g. a migration not yet applied) must not stop the
    // others from being pruned; it is logged and reported as -1.
    try {
      const result = await db
        .prepare(`DELETE FROM ${rule.table} WHERE ${rule.column} < ?`)
        .bind(now - rule.keepMs)
        .run();
      removed[rule.table] = result.meta.changes ?? 0;
    } catch (err) {
      console.error(`[retention] pruning ${rule.table} failed:`, err);
      removed[rule.table] = -1;
    }
  }
  return removed;
}
