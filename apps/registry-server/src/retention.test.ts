// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { openDb } from "./test-utils/sqlite-d1.js";
import { FULL_SCHEMA } from "./test-utils/make-app.js";
import { pruneExpired, RETENTION } from "./retention.js";

const DAY = 24 * 60 * 60 * 1000;

describe("pruneExpired", () => {
  it("names only tables that exist in schema.sql", () => {
    const { db } = openDb(FULL_SCHEMA);
    const tables = new Set(
      (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((r) => r.name),
    );
    expect(RETENTION.map((r) => r.table).filter((t) => !tables.has(t))).toEqual([]);
  });

  it("deletes expired and out-of-window rows and keeps current ones", async () => {
    const { db, adapter } = openDb(FULL_SCHEMA);
    const now = 1_000 * DAY;
    const old = now - 400 * DAY;
    const recent = now - 60_000;

    const ins = (sql: string, ...v: unknown[]) => db.prepare(sql).run(...(v as never[]));
    // single-use rows: one long expired, one still live
    ins(`INSERT INTO registration_challenges (nonce, did, key_hash, expires_at) VALUES ('n-old','d','k',?)`, old);
    ins(`INSERT INTO registration_challenges (nonce, did, key_hash, expires_at) VALUES ('n-new','d','k',?)`, now + 60_000);
    ins(`INSERT INTO relay_connect_tokens (token, did_hash, expires_at) VALUES ('t-old','h',?)`, old);
    ins(`INSERT INTO relay_connect_proofs (signature_hash, did_hash, expires_at) VALUES ('p-old','h',?)`, old);
    ins(`INSERT INTO relay_connect_proofs (signature_hash, did_hash, expires_at) VALUES ('p-new','h',?)`, now + 60_000);
    ins(`INSERT INTO sar_records (did, capabilities, transports, settlement_rails, terms, issued_at, ttl, signature, stored_at)
         VALUES ('did:old','[]','[]','[]','{}',?,1000,'s',?)`, old, old);
    ins(`INSERT INTO sar_records (did, capabilities, transports, settlement_rails, terms, issued_at, ttl, signature, stored_at)
         VALUES ('did:new','[]','[]','[]','{}',?,?,'s',?)`, recent, DAY, recent);
    // accumulating rows
    ins(`INSERT INTO analytics_events (event_type, did_hash, created_at) VALUES ('e', 'h', ?)`, old);
    ins(`INSERT INTO analytics_events (event_type, did_hash, created_at) VALUES ('e', 'h', ?)`, recent);
    ins(`INSERT INTO signal_rate_limits (key_hash, did_hash, window_start, count) VALUES ('k','h',?,1)`, old);
    ins(`INSERT INTO caller_attestations (saga_id, agent_did_hash, caller_did, success, domain, caller_weight, submitted_at)
         VALUES ('s-old','h','c',1,'general',1,?)`, old);
    ins(`INSERT INTO caller_attestations (saga_id, agent_did_hash, caller_did, success, domain, caller_weight, submitted_at)
         VALUES ('s-new','h','c',1,'general',1,?)`, now - 100 * DAY);

    const removed = await pruneExpired(adapter as unknown as D1Database, now);

    const count = (t: string) => (db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as { n: number }).n;
    expect(count("registration_challenges")).toBe(1);
    expect(count("relay_connect_tokens")).toBe(0);
    expect(count("relay_connect_proofs")).toBe(1);
    expect(count("sar_records")).toBe(1);
    expect(count("analytics_events")).toBe(1);
    expect(count("signal_rate_limits")).toBe(0);
    // 100-day-old attestation is inside the one-year window.
    expect(count("caller_attestations")).toBe(1);
    expect(removed.registration_challenges).toBe(1);
    expect(Object.values(removed).every((n) => n >= 0)).toBe(true);
  });

  it("keeps going when one table is missing", async () => {
    const { adapter, db } = openDb(FULL_SCHEMA);
    db.exec("DROP TABLE relay_connect_proofs");
    const removed = await pruneExpired(adapter as unknown as D1Database, Date.now());
    expect(removed.relay_connect_proofs).toBe(-1);
    expect(removed.caller_attestations).toBe(0);
  });
});
