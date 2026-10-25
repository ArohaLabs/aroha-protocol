// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Migration 015 run against a database in the state production is in BEFORE
// it: agent_records without controller_did / deactivated_reason, and E-DID
// agents whose KELs (and their controllers' KELs) are already in kel_logs.
// schema-drift.test.ts proves schema.sql and the migration agree on columns;
// this proves the migration's BACKFILL does what its comments say — a
// person revoked before the migration ran must not leave their agents live
// until somebody happens to post a log.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { incept, revokeKelSelf, generateKeyPair, generateDid, type KelEvent } from "@aroha-sdk/core";
import { openDb } from "./test-utils/sqlite-d1.js";
import { hashDID } from "./routes/agents.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Line endings normalised: a Windows checkout (core.autocrlf) has CRLF, and
// the stripping patterns below are written against "\n".
const SCHEMA_SQL = readFileSync(join(ROOT, "schema.sql"), "utf8").replace(/\r\n/g, "\n");
const MIGRATION_015 = readFileSync(join(ROOT, "migrations", "015_agent_controller.sql"), "utf8");

/** schema.sql as it was before migration 015 — the two columns and their index removed. */
function preMigrationSchema(): string {
  const out = SCHEMA_SQL
    // Later migrations' agent_records columns (019) follow 015's in the
    // table body; a pre-015 database had none of them either.
    .replace(/,\n\s*-- ── migration 015[\s\S]*?deactivated_reason TEXT[\s\S]*?\n\);/, "\n);")
    .replace(/^CREATE INDEX IF NOT EXISTS idx_agent_controller .*$/m, "");
  // Guard the guard: if schema.sql's layout changes, fail here rather than
  // "migrating" a database that already had the columns.
  if (out.includes("controller_did") || out.includes("deactivated_reason")) {
    throw new Error("could not strip migration 015's columns from schema.sql — update preMigrationSchema()");
  }
  return out;
}

describe("migration 015 (agent controller)", () => {
  it("backfills controller_did from stored KELs and takes down agents of an already-revoked person", async () => {
    const { db } = openDb(preMigrationSchema());
    const insertKel = db.prepare(
      `INSERT INTO kel_logs (did, events_json, sequence, last_digest, updated_at) VALUES (?, ?, ?, ?, 0)`,
    );
    const putKel = (did: string, events: KelEvent[]) => insertKel.run(did, JSON.stringify(events), events.length - 1, "x");
    const insertAgent = db.prepare(
      `INSERT INTO agent_records (did_hash, did, owner_key_hash, manifest_cid, public_key_b64, registered_at, last_updated_at)
       VALUES (?, ?, 'owner', 'QmAbc', ?, 0, 0)`,
    );

    const revokedPerson = await incept({ kind: "person" });
    const livePerson = await incept({ kind: "person" });
    const orphan = await incept({ kind: "agent", controller: revokedPerson.did });
    const kept = await incept({ kind: "agent", controller: livePerson.did });
    const free = await incept({ kind: "agent" });
    const z = await generateKeyPair();
    const zDid = generateDid(z.publicKey);

    putKel(revokedPerson.did, await revokeKelSelf(revokedPerson));
    putKel(livePerson.did, livePerson.kel);
    for (const id of [orphan, kept, free]) {
      putKel(id.did, id.kel);
      insertAgent.run(hashDID(id.did), id.did, `key-of-${id.did}`);
    }
    insertAgent.run(hashDID(zDid), zDid, "z-key");

    db.exec(MIGRATION_015);

    const row = (did: string) =>
      db.prepare(`SELECT controller_did, active, deactivated_reason FROM agent_records WHERE did = ?`).get(did) as {
        controller_did: string | null; active: number; deactivated_reason: string | null;
      };
    expect(row(orphan.did)).toEqual({ controller_did: revokedPerson.did, active: 0, deactivated_reason: "controller-revoked" });
    expect(row(kept.did)).toEqual({ controller_did: livePerson.did, active: 1, deactivated_reason: null });
    expect(row(free.did)).toEqual({ controller_did: null, active: 1, deactivated_reason: null });
    expect(row(zDid)).toEqual({ controller_did: null, active: 1, deactivated_reason: null });

    const archived = db.prepare(`SELECT did_hash, public_key_b64 FROM revoked_keys`).all();
    expect(archived).toEqual([{ did_hash: hashDID(orphan.did), public_key_b64: `key-of-${orphan.did}` }]);

    // Replaying the backfill after a partial apply — archive done, the
    // agent re-activated as if the deactivating UPDATE never ran — must not
    // archive the same key a second time.
    db.prepare(`UPDATE agent_records SET active = 1, deactivated_reason = NULL WHERE did = ?`).run(orphan.did);
    db.exec(MIGRATION_015.replace(/^ALTER TABLE .*$/gm, ""));
    expect(db.prepare(`SELECT COUNT(*) AS n FROM revoked_keys`).get()).toEqual({ n: 1 });
    expect(row(orphan.did).active).toBe(0);
  });
});
