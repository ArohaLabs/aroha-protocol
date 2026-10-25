#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Release gate: the release tag must appear in CHANGELOG.md under a DATED
// release heading, e.g.
//
//   ## [2.0.0] — 2026-10-20
//   ...
//   - @aroha-sdk/core@2.0.0
//
// A tag that is only mentioned under "## [Unreleased]" (or any heading without
// a YYYY-MM-DD date) fails: cutting a release means moving its entry out of
// Unreleased and dating it first.
//
// Usage: node .github/scripts/check-changelog-tag.mjs <tag> [CHANGELOG.md]
// Exit 0 = found under a dated heading, 1 = not found / only undated, 2 = usage.

import { readFileSync, existsSync } from "node:fs";

const [tag, file = "CHANGELOG.md"] = process.argv.slice(2);
if (!tag) {
  console.error("usage: check-changelog-tag.mjs <tag> [CHANGELOG.md]");
  process.exit(2);
}
if (!existsSync(file)) {
  console.error(`ERROR: ${file} is missing — every release requires a changelog entry`);
  process.exit(1);
}

// A release heading is dated when it carries a YYYY-MM-DD date and is not
// the Unreleased section: "## [2.0.0] — 2026-10-20" or "## 2026-10-20".
const DATED = { test: (h) => /\b\d{4}-\d{2}-\d{2}\b/.test(h) && !/unreleased/i.test(h) };
// The tag must not be followed by a character that would make it a different
// tag (so "@aroha-sdk/core@1.3.0" does not match "@aroha-sdk/core@1.3.01").
const esc = tag.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
const mention = new RegExp(`(^|[^A-Za-z0-9@/._-])${esc}(?![A-Za-z0-9]|[._-][A-Za-z0-9])`);

let heading = null;
const undated = [];
for (const [i, line] of readFileSync(file, "utf8").split(/\r?\n/).entries()) {
  if (line.startsWith("## ")) {
    heading = line;
    continue;
  }
  if (!mention.test(line)) continue;
  if (heading && DATED.test(heading)) {
    console.log(`OK: ${tag} is listed under "${heading}" (line ${i + 1})`);
    process.exit(0);
  }
  undated.push(`line ${i + 1} under "${heading ?? "(no heading)"}"`);
}

if (undated.length) {
  console.error(`ERROR: ${tag} is mentioned only under an undated heading (${undated.join("; ")}).`);
  console.error('Move the entry from "## [Unreleased]" to a dated heading such as "## [x.y.z] — YYYY-MM-DD" before tagging.');
} else {
  console.error(`ERROR: ${file} does not mention ${tag}.`);
  console.error(`Add a line "- ${tag}" under the dated release heading.`);
}
process.exit(1);
