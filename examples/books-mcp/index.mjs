// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// A read-only SQL window onto the practice's books, spoken over MCP stdio.
//
// WHY A TOOL AND NOT MORE DOCUMENTS
//
// Retrieval answers "what did we say about the Hendricks fee?" and cannot
// answer "what did we actually bill them?" — the second is a sum over 43 rows,
// and a language model asked to add them up from prose will produce a number
// that looks right. The books are queried; the notes are retrieved; a budget
// needs both, and neither half can stand in for the other.
//
// READ ONLY, ENFORCED HERE
//
// The database is opened read-only AND every statement is checked before it
// runs. Either alone would be weaker than it looks: the open flag is the real
// protection, and the statement check is what lets the agent be told WHY, in
// words it can act on, instead of receiving a driver error. An agent that can
// rewrite the ledger it is reporting on is not a reporting tool.

import { DatabaseSync } from "node:sqlite";
import { createInterface } from "node:readline";

const DB_PATH = process.env.BOOKS_DB;
if (!DB_PATH) {
  process.stderr.write("BOOKS_DB is not set — nothing to read.\n");
  process.exit(1);
}

const db = new DatabaseSync(DB_PATH, { readOnly: true });

/** Rows returned to a model, capped. A budget question needs aggregates, not
 *  a data dump, and an unbounded SELECT would fill the context with rows the
 *  answer never uses. */
const MAX_ROWS = 200;

/**
 * One statement, and it must be a SELECT.
 *
 * Rejects anything with a second statement (a trailing semicolon and more),
 * any write verb, and any PRAGMA or ATTACH — the last two are how a read-only
 * handle gets talked into touching another file.
 */
function refuse(sql) {
  const trimmed = sql.trim().replace(/;\s*$/, "");
  if (!trimmed) return "The query was empty.";
  if (trimmed.includes(";")) {
    return "Send one statement at a time — this looked like several.";
  }
  if (!/^(select|with)\b/i.test(trimmed)) {
    return "Only SELECT is available here. The books are read-only: "
      + "nothing in this tool can change them.";
  }
  const banned = /\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum)\b/i;
  const m = banned.exec(trimmed);
  if (m) {
    return `"${m[0].toUpperCase()}" is not available — the books are read-only. `
      + "Ask for the figures with SELECT and report them.";
  }
  return null;
}

/**
 * The schema, read from the database rather than written here.
 *
 * A hardcoded description is a second copy of the truth: point this server at
 * a different firm's books - which is exactly what a second firm is - and the
 * hardcoded version describes tables that are not there, so the model writes
 * queries against columns that do not exist and blames itself for the errors.
 * sqlite_master cannot drift from what the file actually contains.
 *
 * Column NOTES still have to be written by a person, because "paid_on IS NULL
 * means outstanding" is not recoverable from a type. They are keyed by
 * "table.column" and simply skipped where none was written.
 */
const COLUMN_NOTES = {
  "invoices.paid_on": "NULL means the invoice is still outstanding.",
  "payroll.monthly_cost": "The TOTAL for that headcount, not per person.",
  "payroll.effective": "The 'YYYY-MM' the rate began; a role appears twice when its cost changed mid-year, so take the latest per role.",
  "expenses.month": "'YYYY-MM'.",
  "clients.fee_basis": "'retainer' | 'hourly' | 'fixed'.",
  "engagements.status": "'planning' | 'fieldwork' | 'review' | 'signed'.",
  "timesheets.hours": "Hours charged to the engagement by that grade.",
  "timesheets.grade": "Staff grade, which sets the charge-out rate.",
  "rates.charge_out": "Hourly rate billed for that grade.",
  "findings.severity": "'low' | 'medium' | 'high'.",
  "findings.cleared_on": "NULL means the finding is still open.",
};

function describeSchema() {
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all()
    .map((r) => r.name);

  const parts = ["Tables (SQLite). Amounts are GBP; dates are ISO strings, so SQLite date functions work.", ""];
  for (const t of tables) {
    const cols = db.prepare(`PRAGMA table_info(${t})`).all();
    const n = db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
    parts.push(`${t}(${cols.map((c) => c.name).join(", ")})  -- ${n} rows`);
    for (const c of cols) {
      const note = COLUMN_NOTES[`${t}.${c.name}`];
      if (note) parts.push(`    ${c.name}: ${note}`);
    }
  }
  return parts.join("\n");
}

const SCHEMA = describeSchema();

const TOOLS = [
  {
    name: "books_schema",
    description:
      "The tables available in the practice's books, with what each column means. "
      + "Call this before writing a query if you are unsure of a column name.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "books_query",
    description:
      "Run one read-only SELECT against the practice's books and get the rows back. "
      + "Use this for anything countable — totals billed, what is outstanding, "
      + "expenses by category, headcount cost. Do NOT add figures up yourself when "
      + "SQL can do it: write the SUM into the query. "
      + "Returns at most " + MAX_ROWS + " rows, so aggregate rather than listing.",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "A single SELECT statement." },
      },
      required: ["sql"],
    },
  },
];

function runQuery(sql) {
  const problem = refuse(String(sql ?? ""));
  if (problem) return { isError: true, text: problem };
  try {
    const rows = db.prepare(String(sql).trim().replace(/;\s*$/, "")).all();
    if (rows.length === 0) {
      return { isError: false, text: "No rows matched that query." };
    }
    const shown = rows.slice(0, MAX_ROWS);
    const header = Object.keys(shown[0]);
    const lines = [
      header.join(" | "),
      header.map(() => "---").join(" | "),
      ...shown.map((r) => header.map((h) => fmt(r[h])).join(" | ")),
    ];
    if (rows.length > MAX_ROWS) {
      lines.push(`(${rows.length} rows matched; ${MAX_ROWS} shown. Aggregate in SQL to see them all.)`);
    }
    return { isError: false, text: lines.join("\n") };
  } catch (err) {
    // The message names the column or syntax at fault, which is what lets a
    // model correct itself instead of guessing again.
    return { isError: true, text: `That query did not run: ${err.message}` };
  }
}

function fmt(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "number") {
    return Number.isInteger(v) ? String(v) : v.toFixed(2);
  }
  return String(v);
}

// ── MCP over stdio ─────────────────────────────────────────────────────────

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function reply(id, result) {
  if (id === undefined || id === null) return;   // a notification wants no answer
  send({ jsonrpc: "2.0", id, result });
}

createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;   // not addressed to us in any form we can answer
  }
  const { id, method, params } = msg;

  if (method === "initialize") {
    reply(id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "books", version: "1.0.0" },
    });
    return;
  }
  if (method === "tools/list") {
    reply(id, { tools: TOOLS });
    return;
  }
  if (method === "tools/call") {
    const name = params?.name;
    if (name === "books_schema") {
      reply(id, { content: [{ type: "text", text: SCHEMA }], isError: false });
      return;
    }
    if (name === "books_query") {
      const out = runQuery(params?.arguments?.sql);
      reply(id, { content: [{ type: "text", text: out.text }], isError: out.isError });
      return;
    }
    reply(id, {
      content: [{ type: "text", text: `No tool named "${name}" here.` }],
      isError: true,
    });
    return;
  }
  if (id !== undefined && id !== null) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: `unknown method: ${method}` } });
  }
});
