#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Apply pending D1 migrations, or report drift without changing anything.
//
//   node scripts/migrate.mjs --check            # local DB,  exit 1 if pending
//   node scripts/migrate.mjs --check --remote   # production, exit 1 if pending
//   node scripts/migrate.mjs --remote           # apply pending to production
//
// Model
// -----
// schema.sql is the COMPLETE current schema — a database bootstrapped from it
// already contains every migration's effect. migrations/NNN_*.sql exist only to
// bring FORWARD databases created before a given change.
//
// schema_migrations records which files this database has seen. On a database
// that has the table but no rows and no user tables, we bootstrap from
// schema.sql and stamp every migration as applied (they are already included).
// On an existing database we replay only unrecorded files, in filename order.
//
// Why: production ran two migrations behind for weeks with no signal, then went
// down the moment a deploy read the new columns. `--check` in CI turns that
// silent state into a failed build.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATIONS_DIR = join(ROOT, "migrations");
const DB_NAME = "aroha-registry";

const args = process.argv.slice(2);
const REMOTE = args.includes("--remote");
const CHECK_ONLY = args.includes("--check");
const TARGET = REMOTE ? "--remote" : "--local";

// Run wrangler's JS entry point under the current node binary rather than the
// `npx` shim. Two Windows problems disappear at once: `shell: true` would let
// cmd re-split SQL statements on their spaces, and Node 24 refuses to spawn
// .cmd files without a shell at all. Invoking the .js directly needs neither.
const WRANGLER = resolveWrangler();

function resolveWrangler() {
  const candidates = [
    join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js"),
    join(ROOT, "..", "..", "node_modules", "wrangler", "bin", "wrangler.js"),
  ];
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    console.error("wrangler not found — run npm install first");
    process.exit(2);
  }
  return found;
}

function d1(extraArgs) {
  return execFileSync(
    process.execPath,
    [WRANGLER, "d1", "execute", DB_NAME, TARGET, "--json", ...extraArgs],
    { cwd: ROOT, encoding: "utf8" },
  );
}

/** wrangler prefixes JSON with human-readable banner lines; find the payload. */
function parseD1(out) {
  const start = out.indexOf("[");
  if (start === -1) throw new Error(`Unexpected wrangler output:\n${out}`);
  return JSON.parse(out.slice(start));
}

function query(sql) {
  return parseD1(d1(["--command", sql]))[0].results;
}

function runFile(path) {
  d1(["--file", path]);
}

const migrationFiles = readdirSync(MIGRATIONS_DIR)
  .filter((f) => f.endsWith(".sql"))
  .sort(); // NNN_ prefix makes lexical order the correct apply order

// ── Determine what this database already has ────────────────────────────────

let applied;
try {
  applied = new Set(query("SELECT filename FROM schema_migrations").map((r) => r.filename));
} catch {
  // No schema_migrations table: either a brand-new database, or one created
  // before migration tracking existed. Distinguish by looking for user tables.
  const tables = query(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
  ).map((r) => r.name);

  if (tables.length === 0) {
    console.log("empty database — bootstrapping from schema.sql");
    if (CHECK_ONLY) {
      console.log(`PENDING: full bootstrap + ${migrationFiles.length} migration(s)`);
      process.exit(1);
    }
    runFile(join(ROOT, "schema.sql"));
    // schema.sql already contains every migration's effect, so record them all
    // rather than replaying ALTERs that would fail on existing columns.
    stamp(migrationFiles);
    console.log(`bootstrapped and stamped ${migrationFiles.length} migration(s) ✓`);
    process.exit(0);
  }

  // Pre-existing database with no tracking. Create the table and treat every
  // migration as unapplied; each file is then verified below before replay.
  console.log("existing database without migration tracking — adding schema_migrations");
  if (!CHECK_ONLY) {
    query(
      "CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
    );
  }
  applied = new Set();
}

function stamp(files) {
  if (files.length === 0) return;
  const now = Date.now();
  const values = files.map((f) => `('${f.replace(/'/g, "''")}', ${now})`).join(", ");
  query(`INSERT OR IGNORE INTO schema_migrations (filename, applied_at) VALUES ${values}`);
}

// ── Decide which files still need to run ────────────────────────────────────
//
// A migration may be recorded as pending yet already present in the database —
// that is precisely the state prod was in before this script existed (columns
// added by hand, or a schema.sql bootstrap that predated tracking). Replaying
// an ADD COLUMN in that state fails, so probe first and stamp what is already
// there instead of erroring.

const pending = migrationFiles.filter((f) => !applied.has(f));

if (pending.length === 0) {
  console.log(`up to date — ${migrationFiles.length} migration(s) applied ✓`);
  process.exit(0);
}

/** Columns a migration adds, as [table, column] pairs. */
function addedColumns(sql) {
  const re = /ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)/gi;
  return [...sql.matchAll(re)].map((m) => [m[1], m[2]]);
}

const alreadyPresent = [];
const trulyPending = [];
const partial = [];

const columnCache = new Map();
function columnsOf(table) {
  if (!columnCache.has(table)) {
    columnCache.set(table, new Set(query(`SELECT name FROM pragma_table_info('${table}')`).map((r) => r.name)));
  }
  return columnCache.get(table);
}

for (const file of pending) {
  const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
  const cols = addedColumns(sql);
  // A migration with no ADD COLUMN (pure CREATE TABLE IF NOT EXISTS) is
  // idempotent, so it is always safe to run.
  if (cols.length === 0) {
    trulyPending.push(file);
    continue;
  }
  // Probe EVERY column the file adds, not just the first. Probing one used
  // to classify a half-applied file (first ALTER landed, a later one did
  // not) as "already applied": it was stamped and its remaining columns
  // never added. A file is either wholly present, wholly absent, or a state
  // this script must not guess about.
  const present = cols.filter(([table, column]) => columnsOf(table).has(column));
  if (present.length === cols.length) alreadyPresent.push(file);
  else if (present.length === 0) trulyPending.push(file);
  else {
    partial.push({
      file,
      present: present.map(([t, c]) => `${t}.${c}`),
      missing: cols.filter((tc) => !present.includes(tc)).map(([t, c]) => `${t}.${c}`),
    });
  }
}

if (partial.length > 0) {
  for (const p of partial) {
    console.error(`PARTIALLY APPLIED: ${p.file}`);
    console.error(`  present: ${p.present.join(", ")}`);
    console.error(`  missing: ${p.missing.join(", ")}`);
  }
  console.error(
    "\nThese files cannot be replayed (their ADD COLUMNs would fail on the columns already\n" +
      "present) and must not be stamped (columns are missing). Reconcile by hand: add the\n" +
      "missing columns (and any backfill the file performs), then INSERT the filename into\n" +
      "schema_migrations. Nothing has been changed.",
  );
  process.exit(2);
}

if (CHECK_ONLY) {
  for (const f of alreadyPresent) console.log(`UNTRACKED (already applied): ${f}`);
  for (const f of trulyPending) console.log(`PENDING: ${f}`);
  console.log(
    trulyPending.length > 0
      ? `\n${trulyPending.length} migration(s) not applied to ${REMOTE ? "production" : "local"}.`
      : `\nSchema is current; ${alreadyPresent.length} file(s) need stamping only.`,
  );
  process.exit(1);
}

// Stamp what is already present first, then stamp each applied file the
// moment it succeeds. Stamping all of `pending` after the loop meant a
// failure on file N left files 1..N-1 applied but unrecorded, and the next
// run replayed their ADD COLUMNs into "duplicate column" errors.
stamp(alreadyPresent);
for (const file of trulyPending) {
  console.log(`applying ${file}`);
  runFile(join(MIGRATIONS_DIR, file));
  stamp([file]);
}

console.log(
  `applied ${trulyPending.length}, stamped ${alreadyPresent.length} already-present ✓`,
);
