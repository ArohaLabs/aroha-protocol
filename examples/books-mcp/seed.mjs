// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Build the practice's books: a small SQLite file a budget can be derived from.
//
// Deliberately mundane and internally consistent. Every figure a demo question
// asks for is derivable from these tables and from nothing else, so an answer
// that does not query them is an answer that was invented — which is the
// property the whole SQL-plus-documents pairing exists to demonstrate.
//
// Run: node seed.mjs [path/to/books.db]

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const out = resolve(process.argv[2] ?? "books.db");
mkdirSync(dirname(out), { recursive: true });

const db = new DatabaseSync(out);

db.exec(`
  DROP TABLE IF EXISTS clients;
  DROP TABLE IF EXISTS invoices;
  DROP TABLE IF EXISTS expenses;
  DROP TABLE IF EXISTS payroll;
  DROP TABLE IF EXISTS budget_prior;

  CREATE TABLE clients (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    sector       TEXT NOT NULL,
    client_since TEXT NOT NULL,   -- ISO date
    fee_basis    TEXT NOT NULL,   -- 'retainer' | 'hourly' | 'fixed'
    partner      TEXT NOT NULL
  );

  CREATE TABLE invoices (
    id         INTEGER PRIMARY KEY,
    client_id  INTEGER NOT NULL REFERENCES clients(id),
    issued_on  TEXT NOT NULL,
    due_on     TEXT NOT NULL,
    amount     REAL NOT NULL,     -- GBP
    paid_on    TEXT,              -- NULL means outstanding
    service    TEXT NOT NULL
  );

  CREATE TABLE expenses (
    id       INTEGER PRIMARY KEY,
    month    TEXT NOT NULL,       -- 'YYYY-MM'
    category TEXT NOT NULL,
    amount   REAL NOT NULL,
    note     TEXT
  );

  CREATE TABLE payroll (
    id           INTEGER PRIMARY KEY,
    role         TEXT NOT NULL,
    headcount    INTEGER NOT NULL,
    monthly_cost REAL NOT NULL,   -- total for that headcount
    effective    TEXT NOT NULL    -- 'YYYY-MM' this rate took effect
  );

  CREATE TABLE budget_prior (
    id       INTEGER PRIMARY KEY,
    fy       TEXT NOT NULL,       -- 'FY2025'
    line     TEXT NOT NULL,
    amount   REAL NOT NULL
  );
`);

const clients = [
  [1, "Hendricks Manufacturing", "Manufacturing", "2019-04-01", "retainer", "R. Shah"],
  [2, "Calloway & Sons",         "Construction",  "2021-09-15", "retainer", "R. Shah"],
  [3, "Brightleaf Cafés",        "Hospitality",   "2022-01-10", "fixed",    "M. Osei"],
  [4, "Pemberton Dental",        "Healthcare",    "2020-06-01", "retainer", "M. Osei"],
  [5, "Northgate Logistics",     "Transport",     "2023-03-20", "hourly",   "R. Shah"],
  [6, "Aveline Interiors",       "Retail",        "2024-11-05", "fixed",    "M. Osei"],
];
const insClient = db.prepare("INSERT INTO clients VALUES (?,?,?,?,?,?)");
for (const c of clients) insClient.run(...c);

// Twelve months of 2025. Retainers bill monthly; fixed and hourly are lumpier.
const monthly = {
  1: 4200,   // Hendricks — the biggest retainer
  2: 2600,   // Calloway
  4: 1900,   // Pemberton
};
const insInv = db.prepare("INSERT INTO invoices VALUES (?,?,?,?,?,?,?)");
let invId = 1;
for (let m = 1; m <= 12; m++) {
  const mm = String(m).padStart(2, "0");
  for (const [cid, amount] of Object.entries(monthly)) {
    const issued = `2025-${mm}-01`;
    const due = `2025-${mm}-28`;
    // The last two months of Hendricks and Calloway are unpaid — this is what
    // makes "who is behind, and what does it do to cash" a real question.
    const unpaid = m >= 11 && (cid === "1" || cid === "2");
    insInv.run(invId++, Number(cid), issued, due,
      amount, unpaid ? null : `2025-${mm}-24`, "Monthly retainer");
  }
}
// Fixed-fee and hourly work, irregular through the year.
const adhoc = [
  [3, "2025-02-14", "2025-03-14", 3800, "2025-03-11", "Year-end accounts"],
  [3, "2025-08-02", "2025-08-30", 1450, "2025-08-27", "VAT review"],
  [5, "2025-04-09", "2025-05-09", 6200, "2025-05-06", "Systems migration advisory"],
  [5, "2025-10-01", "2025-10-31", 4100, null,          "Q3 management accounts"],
  [6, "2025-05-20", "2025-06-20", 2750, "2025-06-18", "Onboarding and setup"],
  [6, "2025-09-12", "2025-10-12", 1980, "2025-10-09", "Half-year accounts"],
  [4, "2025-07-01", "2025-07-31", 2400, "2025-07-29", "Payroll health check"],
];
for (const [cid, issued, due, amount, paid, service] of adhoc) {
  insInv.run(invId++, cid, issued, due, amount, paid, service);
}

const insExp = db.prepare("INSERT INTO expenses VALUES (?,?,?,?,?)");
let expId = 1;
const recurring = [
  ["Office rent", 1850, "Riverside Chambers, 2nd floor"],
  ["Software subscriptions", 640, "Practice management, tax filing, e-signature"],
  ["Insurance", 310, "Professional indemnity"],
  ["Utilities", 220, null],
];
for (let m = 1; m <= 12; m++) {
  const month = `2025-${String(m).padStart(2, "0")}`;
  for (const [category, amount, note] of recurring) {
    // The software bill steps up mid-year; a budget that misses this
    // under-states next year, and the reason is only in the notes.
    const bumped = category === "Software subscriptions" && m >= 7 ? amount + 185 : amount;
    insExp.run(expId++, month, category, bumped, note);
  }
}
const oneOff = [
  ["2025-03", "Professional development", 1200, "Two staff, tax update courses"],
  ["2025-06", "Marketing", 2400, "Website rebuild"],
  ["2025-09", "Equipment", 3150, "Four replacement laptops"],
  ["2025-11", "Professional development", 890, "Audit methodology refresher"],
];
for (const [month, category, amount, note] of oneOff) {
  insExp.run(expId++, month, category, amount, note);
}

const insPay = db.prepare("INSERT INTO payroll VALUES (?,?,?,?,?)");
[
  [1, "Partner",         2, 14000, "2025-01"],
  [2, "Senior associate", 2, 8200, "2025-01"],
  [3, "Associate",        3, 8700, "2025-01"],
  [4, "Administrator",    1, 2400, "2025-01"],
  [5, "Senior associate", 2, 8700, "2025-07"],  // mid-year pay review
].forEach((r) => insPay.run(...r));

const insPrior = db.prepare("INSERT INTO budget_prior VALUES (?,?,?,?)");
[
  ["FY2025", "Fee income",               128000],
  ["FY2025", "Salaries and wages",       399600],
  ["FY2025", "Office rent",               22200],
  ["FY2025", "Software subscriptions",     8790],
  ["FY2025", "Insurance",                  3720],
  ["FY2025", "Utilities",                  2640],
  ["FY2025", "Professional development",   3000],
  ["FY2025", "Marketing",                  2000],
  ["FY2025", "Equipment",                  2500],
].forEach((r, i) => insPrior.run(i + 1, ...r));

const counts = ["clients", "invoices", "expenses", "payroll", "budget_prior"]
  .map((t) => `${t}=${db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n}`);
console.log(`wrote ${out}\n  ${counts.join("  ")}`);
db.close();
