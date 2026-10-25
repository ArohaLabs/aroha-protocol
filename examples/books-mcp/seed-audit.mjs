// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The books of an AUDIT practice — a different firm, not a copy of the first.
//
// Different tables on purpose. The point of two firms is that they hold
// genuinely different things: firm1 bills retainers and builds a budget,
// firm2 runs engagements and worries about recovery — hours charged against
// the fee that was quoted. A second copy of the same schema would demonstrate
// nothing that one firm does not already show, and the schema is introspected
// from the file now, so the tool describes whichever of the two it is given.
//
// Run: node seed-audit.mjs [path/to/audit.db]

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const out = resolve(process.argv[2] ?? "audit.db");
mkdirSync(dirname(out), { recursive: true });
const db = new DatabaseSync(out);

db.exec(`
  DROP TABLE IF EXISTS clients;
  DROP TABLE IF EXISTS engagements;
  DROP TABLE IF EXISTS timesheets;
  DROP TABLE IF EXISTS rates;
  DROP TABLE IF EXISTS findings;

  CREATE TABLE clients (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    sector   TEXT NOT NULL,
    year_end TEXT NOT NULL,        -- 'MM-DD'
    listed   INTEGER NOT NULL      -- 1 = public interest entity
  );

  CREATE TABLE engagements (
    id          INTEGER PRIMARY KEY,
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    fy          TEXT NOT NULL,     -- 'FY2025'
    quoted_fee  REAL NOT NULL,     -- what the client agreed to pay
    status      TEXT NOT NULL,     -- planning | fieldwork | review | signed
    partner     TEXT NOT NULL,
    signed_on   TEXT               -- NULL until the opinion is signed
  );

  CREATE TABLE timesheets (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    grade         TEXT NOT NULL,
    hours         REAL NOT NULL,
    week_ending   TEXT NOT NULL
  );

  CREATE TABLE rates (
    id         INTEGER PRIMARY KEY,
    grade      TEXT NOT NULL,
    charge_out REAL NOT NULL,      -- billed per hour
    cost_rate  REAL NOT NULL       -- what the hour costs the firm
  );

  CREATE TABLE findings (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    raised_on     TEXT NOT NULL,
    severity      TEXT NOT NULL,   -- low | medium | high
    summary       TEXT NOT NULL,
    cleared_on    TEXT             -- NULL means still open
  );
`);

const clients = [
  [1, "Thorne Aggregates plc",   "Construction materials", "03-31", 1],
  [2, "Marlow Care Homes Ltd",   "Healthcare",             "12-31", 0],
  [3, "Kestrel Foods Ltd",       "Food manufacturing",     "06-30", 0],
  [4, "Ardenhall Housing Trust", "Social housing",         "03-31", 1],
  [5, "Loxley Components Ltd",   "Engineering",            "09-30", 0],
];
const ic = db.prepare("INSERT INTO clients VALUES (?,?,?,?,?)");
for (const c of clients) ic.run(...c);

const engagements = [
  [1, 1, "FY2025", 84000, "signed",    "H. Vance",   "2025-08-14"],
  [2, 2, "FY2025", 21500, "signed",    "D. Okafor",  "2025-05-02"],
  [3, 3, "FY2025", 33000, "review",    "H. Vance",   null],
  [4, 4, "FY2025", 58000, "fieldwork", "D. Okafor",  null],
  [5, 5, "FY2025", 26500, "planning",  "H. Vance",   null],
  [6, 1, "FY2024", 78000, "signed",    "H. Vance",   "2024-08-09"],
  [7, 2, "FY2024", 20000, "signed",    "D. Okafor",  "2024-04-26"],
];
const ie = db.prepare("INSERT INTO engagements VALUES (?,?,?,?,?,?,?)");
for (const e of engagements) ie.run(...e);

const ir = db.prepare("INSERT INTO rates VALUES (?,?,?,?)");
[
  [1, "Partner",   240, 96],
  [2, "Manager",   145, 62],
  [3, "Senior",     95, 41],
  [4, "Assistant",  62, 28],
].forEach((r) => ir.run(...r));

// Hours. Thorne and Ardenhall over-run badly; the reason is only in the notes.
const hours = {
  1: { Partner: 42,  Manager: 168, Senior: 340, Assistant: 410 },   // Thorne FY25
  2: { Partner: 12,  Manager: 44,  Senior: 96,  Assistant: 120 },   // Marlow FY25
  3: { Partner: 18,  Manager: 70,  Senior: 150, Assistant: 190 },   // Kestrel FY25
  4: { Partner: 33,  Manager: 130, Senior: 268, Assistant: 300 },   // Ardenhall FY25
  5: { Partner: 6,   Manager: 18,  Senior: 30,  Assistant: 24 },    // Loxley, planning only
  6: { Partner: 38,  Manager: 150, Senior: 300, Assistant: 360 },   // Thorne FY24
  7: { Partner: 11,  Manager: 40,  Senior: 90,  Assistant: 110 },   // Marlow FY24
};
const it = db.prepare("INSERT INTO timesheets VALUES (?,?,?,?,?)");
let tid = 1;
for (const [eid, byGrade] of Object.entries(hours)) {
  let week = 1;
  for (const [grade, total] of Object.entries(byGrade)) {
    // Spread each grade's hours over four weeks so the table looks like a
    // timesheet rather than a summary, and weekly questions are answerable.
    for (let w = 0; w < 4; w++) {
      const h = w === 3 ? total - Math.floor(total / 4) * 3 : Math.floor(total / 4);
      it.run(tid++, Number(eid), grade, h,
        `2025-0${(week % 9) + 1}-${String(7 * (w + 1)).padStart(2, "0")}`);
    }
    week++;
  }
}

const findings = [
  [1, 1, "2025-06-12", "high",   "Revenue cut-off: 14 deliveries recorded in the wrong period", "2025-07-30"],
  [2, 1, "2025-06-20", "medium", "Stock count attendance incomplete at the Redditch depot", "2025-07-14"],
  [3, 1, "2025-07-02", "low",    "Fixed asset register not reconciled monthly", null],
  [4, 4, "2025-09-05", "high",   "Housing grant income recognised before conditions met", null],
  [5, 4, "2025-09-18", "medium", "Related party disclosures incomplete for two board members", null],
  [6, 3, "2025-08-22", "low",    "Bank reconciliations signed by preparer only", "2025-09-09"],
  [7, 2, "2025-03-11", "medium", "Payroll starters and leavers not independently reviewed", "2025-04-01"],
];
const iff = db.prepare("INSERT INTO findings VALUES (?,?,?,?,?,?)");
for (const f of findings) iff.run(...f);

const counts = ["clients", "engagements", "timesheets", "rates", "findings"]
  .map((t) => `${t}=${db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n}`);
console.log(`wrote ${out}\n  ${counts.join("  ")}`);
db.close();
