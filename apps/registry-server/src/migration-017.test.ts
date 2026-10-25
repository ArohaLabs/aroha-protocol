// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Migration 017 rebuilds mandate_redemptions to key it by
// (mandate_id, redemption_id) and adds relay_connect_proofs. A rebuild is
// the riskiest kind of migration, so: existing rows survive it, the new key
// behaves as intended, and replaying the file changes nothing.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { openDb } from "./test-utils/sqlite-d1.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATION_017 = readFileSync(join(ROOT, "migrations", "017_relay_proofs_and_redemption_scope.sql"), "utf8");

/** The two tables exactly as migration 016 created them. */
const PRE_017 = `
  CREATE TABLE mandate_redemptions (
    redemption_id TEXT    PRIMARY KEY,
    mandate_id    TEXT    NOT NULL,
    amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
    merchant      TEXT    NOT NULL,
    redeemed_at   INTEGER NOT NULL,
    actor         TEXT    NOT NULL DEFAULT ''
  );
  CREATE INDEX idx_mandate_redemptions_mandate ON mandate_redemptions (mandate_id);
`;

describe("migration 017", () => {
  it("keeps existing redemptions, scopes ids per mandate, and is safe to replay", () => {
    const { db } = openDb(PRE_017);
    db.prepare(`INSERT INTO mandate_redemptions VALUES ('r1', 'g#m1', 5, 'shop', 1, 'a')`).run();

    db.exec(MIGRATION_017);
    db.exec(MIGRATION_017);

    expect(db.prepare(`SELECT redemption_id, mandate_id FROM mandate_redemptions`).all())
      .toEqual([{ redemption_id: "r1", mandate_id: "g#m1" }]);
    // Same id, different mandate: now allowed.
    db.prepare(`INSERT INTO mandate_redemptions VALUES ('r1', 'g#m2', 5, 'shop', 2, 'a')`).run();
    // Same id, same mandate: still refused.
    expect(() => db.prepare(`INSERT INTO mandate_redemptions VALUES ('r1', 'g#m1', 5, 'shop', 3, 'a')`).run()).toThrow();

    expect(db.prepare(`SELECT name FROM sqlite_master WHERE name = 'relay_connect_proofs'`).get())
      .toEqual({ name: "relay_connect_proofs" });
  });
});
