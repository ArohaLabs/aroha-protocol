// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Guards against the failure that took the registry down: schema.sql, the
// migrations, and the code's expectations drifting apart with nothing to notice.
//
// The concrete incident: migrations 001 and 002 added columns to agent_records
// and api_keys, but nobody added them to schema.sql, and production never ran
// the files. The suite stayed green because the test helper carried its OWN
// hand-written schema that happened to include them. Three copies, no single
// source, no comparison between them.
//
// These tests make each of those copies answer to schema.sql.

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { REQUIRED_SCHEMA, findSchemaGaps } from "./schema-manifest.js";
import { openDb } from "./test-utils/sqlite-d1.js";
import { makeApp } from "./test-utils/make-app.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_SQL = readFileSync(join(ROOT, "schema.sql"), "utf8");
const MIGRATIONS_DIR = join(ROOT, "migrations");

/** Parse `CREATE TABLE` blocks in a .sql file into table -> column names. */
function parseTables(sql: string): Map<string, Set<string>> {
  const tables = new Map<string, Set<string>>();
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(([\s\S]*?)\n\s*\);/gi;

  for (const m of sql.matchAll(re)) {
    const [, name, body] = m;
    const cols = new Set<string>();

    for (const rawLine of body.split("\n")) {
      // Strip comments and trailing commas before looking at the first token.
      const line = rawLine.replace(/--.*$/, "").trim().replace(/,$/, "");
      if (!line) continue;
      const first = line.split(/[\s(]/)[0].toUpperCase();
      // Table-level constraints are not columns.
      if (["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"].includes(first)) continue;
      const colName = line.split(/\s/)[0];
      if (/^\w+$/.test(colName)) cols.add(colName);
    }
    tables.set(name, cols);
  }
  return tables;
}

const schemaTables = parseTables(SCHEMA_SQL);
const schemaIndexes = new Set(
  [...SCHEMA_SQL.matchAll(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi)].map((m) => m[1]),
);

const migrationFiles = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();

/**
 * schema.sql with agent_records.discovery_eligible_at removed — reproducing the
 * exact production state during the outage.
 *
 * The index over that column has to go too, or SQLite rejects the whole script
 * and we'd be testing "invalid SQL" rather than "missing column".
 */
function withoutDiscoveryColumn(): string {
  return SCHEMA_SQL
    .replace(/^\s*discovery_eligible_at INTEGER,$/m, "")
    .replace(/^CREATE INDEX IF NOT EXISTS idx_agent_discovery_eligible.*$/m, "");
}

describe("schema.sql is the single source of truth", () => {
  it("parses into the tables we expect (parser sanity)", () => {
    // If the parser silently matched nothing, every assertion below would
    // vacuously pass — so prove it actually found the schema first.
    expect(schemaTables.size).toBeGreaterThanOrEqual(15);
    expect(schemaTables.get("agent_records")?.has("did_hash")).toBe(true);
  });

  it("contains every table and column the running code requires", () => {
    const missing: string[] = [];
    for (const [table, required] of Object.entries(REQUIRED_SCHEMA)) {
      const cols = schemaTables.get(table);
      if (!cols) {
        missing.push(`table ${table}`);
        continue;
      }
      for (const c of required) if (!cols.has(c)) missing.push(`${table}.${c}`);
    }
    expect(missing, `schema.sql is missing: ${missing.join(", ")}`).toEqual([]);
  });

  // The actual bug: a migration adds a column, schema.sql never learns about
  // it, and every freshly bootstrapped database is silently broken.
  it.each(migrationFiles)("folds every column added by %s", (file) => {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    const added = [...sql.matchAll(/ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)/gi)];

    const missing = added
      .filter(([, table, col]) => !schemaTables.get(table)?.has(col))
      .map(([, table, col]) => `${table}.${col}`);

    expect(
      missing,
      `${file} adds columns absent from schema.sql: ${missing.join(", ")}. ` +
        `A database bootstrapped from schema.sql would be missing them.`,
    ).toEqual([]);
  });

  it.each(migrationFiles)("folds every table created by %s", (file) => {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    // A table a migration builds and then renames (SQLite's only way to
    // change a primary key — see 017) is scaffolding, not a table.
    const renamedAway = new Set(
      [...sql.matchAll(/ALTER\s+TABLE\s+(\w+)\s+RENAME\s+TO\s+\w+/gi)].map((m) => m[1]),
    );
    const created = [...sql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi)]
      .map((m) => m[1])
      .filter((t) => !renamedAway.has(t))
      .filter((t) => !schemaTables.has(t));

    expect(created, `${file} creates tables absent from schema.sql`).toEqual([]);
  });

  // Same bug, one level down: idx_agent_visibility lived in migration 003
  // only, so every database bootstrapped from schema.sql lacked it and
  // nothing noticed — the column check above cannot see indexes.
  it.each(migrationFiles)("folds every index created by %s", (file) => {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    const missing = [...sql.matchAll(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi)]
      .map((m) => m[1])
      .filter((idx) => !schemaIndexes.has(idx));

    expect(missing, `${file} creates indexes absent from schema.sql: ${missing.join(", ")}`).toEqual([]);
  });

  it("a database built from schema.sql has every index schema.sql declares", () => {
    const { db } = openDb(SCHEMA_SQL);
    const live = new Set(
      (db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'").all() as Array<{ name: string }>)
        .map((r) => r.name),
    );
    expect([...schemaIndexes].filter((i) => !live.has(i))).toEqual([]);
  });
});

describe("schema verification", () => {
  it("reports no gaps for a database built from schema.sql", async () => {
    const { adapter } = openDb(SCHEMA_SQL);
    const gaps = await findSchemaGaps(adapter as never);
    expect(gaps).toEqual([]);
  });

  it("names the exact missing column rather than failing opaquely", async () => {
    // Rebuild agent_records without discovery_eligible_at — the precise state
    // production was in during the outage.
    const crippled = withoutDiscoveryColumn();
    const { adapter } = openDb(crippled);

    const gaps = await findSchemaGaps(adapter as never);
    expect(gaps).toContainEqual({
      table: "agent_records",
      missingColumns: ["discovery_eligible_at"],
    });
  });

  it("reports a missing table as missing", async () => {
    const withoutGrants = SCHEMA_SQL.replace(
      /CREATE TABLE IF NOT EXISTS access_grants[\s\S]*?\n\);/,
      "",
    ).replace(/CREATE (?:UNIQUE )?INDEX IF NOT EXISTS idx_grant\w*[\s\S]*?;/g, "");

    const { adapter } = openDb(withoutGrants);
    const gaps = await findSchemaGaps(adapter as never);
    expect(gaps).toContainEqual({ table: "access_grants", missing: true });
  });
});

describe("GET /health", () => {
  it("reports schema ok on a correct database", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/health", {}, env as never);

    expect(res.status).toBe(200);
    const body = await res.json() as { status: string; schema: string };
    expect(body.status).toBe("ok");
    expect(body.schema).toBe("ok");
  });

  // The old /health answered 200 throughout the outage because its single
  // count query never touched the missing columns. This is that regression.
  it("returns 503 with the gap named when a required column is absent", async () => {
    const crippled = withoutDiscoveryColumn();
    const { adapter } = openDb(crippled);
    const env = {
      DB: adapter as unknown as D1Database,
      ADMIN_SECRET: "test-admin-secret-0123456789abcdefghijklmn",
      IPFS_GATEWAY: "http://localhost:5001/ipfs",
    };
    const { app } = await makeApp();

    const res = await app.request(
      "/health",
      { headers: { Authorization: `Bearer ${env.ADMIN_SECRET}` } },
      env as never,
    );

    expect(res.status).toBe(503);
    const body = await res.json() as { status: string; schema: string; gaps: unknown[] };
    expect(body.status).toBe("degraded");
    expect(body.schema).toBe("drift");
    expect(body.gaps).toContainEqual({
      table: "agent_records",
      missingColumns: ["discovery_eligible_at"],
    });
  });

  // Table and column names are operator detail: an anonymous caller learns
  // that the schema drifted, never what is missing.
  it("withholds the named gaps from an anonymous caller", async () => {
    const { adapter } = openDb(withoutDiscoveryColumn());
    const env = { DB: adapter as unknown as D1Database, ADMIN_SECRET: "x".repeat(40), IPFS_GATEWAY: "" };
    const { app } = await makeApp();

    const res = await app.request("/health", {}, env as never);
    expect(res.status).toBe(503);
    const body = await res.json() as Record<string, unknown>;
    expect(body.schema).toBe("drift");
    expect(body.gaps).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain("discovery_eligible_at");
  });

  it("never returns the database error text", async () => {
    const failing = {
      prepare() { throw new Error("D1_ERROR: no such table: agent_records SQLITE_ERROR"); },
    };
    const env = { DB: failing, ADMIN_SECRET: "x".repeat(40), IPFS_GATEWAY: "" };
    const { app } = await makeApp();

    const res = await app.request("/health", {}, env as never);
    expect(res.status).toBe(503);
    const body = await res.json() as Record<string, unknown>;
    expect(body.db).toBe("unavailable");
    expect(JSON.stringify(body)).not.toContain("SQLITE");
  });
});
