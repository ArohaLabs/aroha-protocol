// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Migration 018 adds audit_anchors and marks pre-existing spending budgets as
// unverified ('caller'). Existing rows must survive with that marking, and
// the anchor table must refuse a second row at the same chain position.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { openDb } from "./test-utils/sqlite-d1.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATION_018 = readFileSync(join(ROOT, "migrations", "018_audit_anchors_and_verified_budgets.sql"), "utf8");

/** spending_budgets exactly as migration 004 / schema.sql had it before 018. */
const PRE_018 = `
  CREATE TABLE spending_budgets (
    mandate_id      TEXT PRIMARY KEY,
    limit_usd       REAL NOT NULL CHECK (limit_usd > 0),
    allocated_usd   REAL NOT NULL DEFAULT 0 CHECK (allocated_usd >= 0),
    owner_key_hash  TEXT NOT NULL DEFAULT '',
    expires_at      INTEGER,
    created_at      INTEGER NOT NULL
  );
`;

describe("migration 018", () => {
  it("keeps existing budgets, marked as caller-supplied (unverified)", () => {
    const { db } = openDb(PRE_018);
    db.prepare(`INSERT INTO spending_budgets (mandate_id, limit_usd, owner_key_hash, created_at) VALUES ('m1', 100, 'k', 1)`).run();
    db.exec(MIGRATION_018);
    expect(db.prepare(`SELECT mandate_id, limit_usd, limit_source, chain_keys FROM spending_budgets`).all())
      .toEqual([{ mandate_id: "m1", limit_usd: 100, limit_source: "caller", chain_keys: null }]);
  });

  it("creates audit_anchors with (install_did, seq) and (install_did, log_index) unique", () => {
    const { db } = openDb(PRE_018);
    db.exec(MIGRATION_018);
    const ins = db.prepare(
      `INSERT INTO audit_anchors (install_did, seq, hash, signed_at, anchored_at, log_index, prev_anchor_hash, witness_signature, witness_key_id, install_signature)
       VALUES (?, ?, 'h', 's', 'a', ?, '', 'w', 'k', 'i')`,
    );
    ins.run("did:aroha:z1", 1, 0);
    expect(() => ins.run("did:aroha:z1", 1, 1)).toThrow();
    expect(() => ins.run("did:aroha:z1", 2, 0)).toThrow();
    ins.run("did:aroha:z2", 1, 0);
  });
});
