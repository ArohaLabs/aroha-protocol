// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Migration 019 adds the Shared Signals stream and outbox tables and the
// operator-recorded audit columns. Existing agents must survive with no
// audit recorded, and the outbox must refuse a duplicate (stream, jti).

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { openDb } from "./test-utils/sqlite-d1.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATION_019 = readFileSync(join(ROOT, "migrations", "019_ssf_and_agent_audit.sql"), "utf8");

const PRE_019 = `
  CREATE TABLE agent_records (
    did_hash TEXT PRIMARY KEY,
    did      TEXT NOT NULL UNIQUE,
    active   INTEGER NOT NULL DEFAULT 1
  );
`;

describe("migration 019", () => {
  it("keeps existing agents with no audit recorded", () => {
    const { db } = openDb(PRE_019);
    db.prepare(`INSERT INTO agent_records (did_hash, did) VALUES ('0x1', 'did:aroha:a')`).run();
    db.exec(MIGRATION_019);
    expect(db.prepare(`SELECT did, audited_at, audit_reference FROM agent_records`).all())
      .toEqual([{ did: "did:aroha:a", audited_at: null, audit_reference: null }]);
  });

  it("creates ssf_streams (status checked) and ssf_outbox keyed by (stream_id, jti)", () => {
    const { db } = openDb(PRE_019);
    db.exec(MIGRATION_019);
    const stream = db.prepare(
      `INSERT INTO ssf_streams (stream_id, owner_key_hash, iss, aud, delivery_method, endpoint_url, status, created_at, updated_at)
       VALUES (?, 'k', 'i', 'a', 'urn:ietf:rfc:8936', 'u', ?, 1, 1)`,
    );
    stream.run("s1", "enabled");
    expect(() => stream.run("s2", "bogus")).toThrow();
    const out = db.prepare(
      `INSERT INTO ssf_outbox (stream_id, jti, event_type, set_jwt, created_at, next_attempt_at) VALUES ('s1', ?, 't', 'jwt', 1, 1)`,
    );
    out.run("j1");
    expect(() => out.run("j1")).toThrow();
    expect(db.prepare(`SELECT attempts, delivered_at, failed_at FROM ssf_outbox`).get())
      .toEqual({ attempts: 0, delivered_at: null, failed_at: null });
  });
});
