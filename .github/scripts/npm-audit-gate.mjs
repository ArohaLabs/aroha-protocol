#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// CI dependency audit: `npm audit --audit-level=high --omit=dev` over the root
// lockfile, with an allowlist for findings the project has knowingly accepted.
//
//   AUDIT_MODE=block   (target) any high/critical advisory not allowlisted, or
//                      allowlisted past its expiry, fails the job
//   AUDIT_MODE=report  (current) the same findings are printed as warnings and
//                      the job passes
//
// Allowlist: .github/audit-allowlist.json — an array of
//   { "id": "GHSA-xxxx-xxxx-xxxx", "package": "name", "reason": "...",
//     "owner": "handle", "expires": "YYYY-MM-DD" }
// Every entry needs all five fields; an expired entry no longer suppresses.

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

const MODE = process.env.AUDIT_MODE === "block" ? "block" : "report";
const ALLOWLIST = ".github/audit-allowlist.json";
const today = new Date().toISOString().slice(0, 10);

let raw;
try {
  raw = execFileSync("npm", ["audit", "--audit-level=high", "--omit=dev", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: process.platform === "win32",
  });
} catch (e) {
  // npm audit exits non-zero when it finds anything at or above the level.
  raw = e.stdout;
  if (!raw) {
    console.error("ERROR: npm audit produced no output:", e.message);
    process.exit(1);
  }
}

let report;
try {
  report = JSON.parse(raw);
} catch {
  console.error("ERROR: could not parse npm audit JSON output");
  process.exit(1);
}
if (report.error) {
  console.error("ERROR: npm audit failed:", JSON.stringify(report.error));
  process.exit(1);
}

let allow = [];
if (existsSync(ALLOWLIST)) {
  const parsed = JSON.parse(readFileSync(ALLOWLIST, "utf8"));
  allow = Array.isArray(parsed) ? parsed : parsed.entries ?? [];
  for (const a of allow) {
    for (const f of ["id", "package", "reason", "owner", "expires"]) {
      if (!a[f]) {
        console.error(`ERROR: ${ALLOWLIST} entry ${JSON.stringify(a)} is missing "${f}"`);
        process.exit(1);
      }
    }
  }
}

// Collect direct advisories (objects in `via`) at high/critical severity.
const findings = new Map();
for (const [pkg, v] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of v.via ?? []) {
    if (typeof via !== "object") continue;
    if (!["high", "critical"].includes(via.severity)) continue;
    const id = (via.url ?? "").split("/").pop() || String(via.source);
    findings.set(`${pkg} ${id}`, { pkg, id, severity: via.severity, title: via.title, url: via.url });
  }
}

const open = [];
for (const f of findings.values()) {
  const a = allow.find((x) => x.id === f.id && x.package === f.pkg);
  if (a && a.expires >= today) {
    console.log(`allowlisted until ${a.expires} (${a.owner}): ${f.severity} ${f.pkg} ${f.id} — ${a.reason}`);
    continue;
  }
  open.push({ ...f, expired: Boolean(a) });
}

const counts = report.metadata?.vulnerabilities ?? {};
console.log(`npm audit (production deps): ${JSON.stringify(counts)}`);
if (open.length === 0) {
  console.log("OK: no un-allowlisted high/critical advisories");
  process.exit(0);
}

const level = MODE === "block" ? "error" : "warning";
for (const f of open) {
  console.log(
    `::${level}::${f.severity} ${f.pkg} ${f.id}${f.expired ? " (allowlist entry EXPIRED)" : ""} — ${f.title} ${f.url ?? ""}`,
  );
}
console.log(`${open.length} high/critical advisory finding(s) not allowlisted. Mode: ${MODE}.`);
process.exit(MODE === "block" ? 1 : 0);
