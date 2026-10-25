#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Regenerates the wordlist.ts data module in every package that needs the
// personal-agent-naming wordlist (design spec §7.10), from the single
// canonical source at scripts/wordlists/bip39-english.txt.
//
// Why generated in more than one place instead of imported from one: the
// Cloudflare Worker in apps/registry-server never imports @aroha-sdk/registry
// (see the header comment in apps/registry-server/src/sar-verify.ts) — its
// barrel export pulls in `ethers`, which is Node-only and breaks the Workers
// build. Every package that needs the wordlist gets its own generated copy
// instead. Hand-duplicating a 2048-line file risks silent divergence, so
// this script is the single source of truth, and each generated file embeds
// the sha256 of the canonical .txt so a test in every consuming package can
// assert its copy is byte-identical to the source, not just "close enough."
//
// Run: node scripts/generate-wordlist.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

const sourcePath = join(repoRoot, "scripts/wordlists/bip39-english.txt");
const raw = readFileSync(sourcePath, "utf8");
const words = raw.trim().split(/\r?\n/);

if (words.length !== 2048) {
  throw new Error(`expected 2048 words, got ${words.length}`);
}
if (new Set(words).size !== words.length) {
  throw new Error("duplicate word detected in source wordlist");
}
for (const w of words) {
  if (!/^[a-z]+$/.test(w)) throw new Error(`non-lowercase-ascii word: ${JSON.stringify(w)}`);
}

const sha256 = createHash("sha256").update(raw).digest("hex");

const banner = `// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED FILE — do not hand-edit. Regenerate with
// \`node scripts/generate-wordlist.mjs\` from the canonical source at
// scripts/wordlists/bip39-english.txt (the standard BIP-39 English wordlist,
// https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
//
// Used for design spec §7.10 personal-agent-name derivation: 2048 words
// (11 bits/word, indexable 0-2047), curated by the BIP-39 authors against
// prefix collisions and includes only common, unambiguous English words —
// which happens to double as exactly the "no brand-forming fragments"
// property §7.10's vanity-grinding Layer 1 needs. Reused rather than
// hand-curated for this project specifically because a wrong or duplicated
// entry here would silently corrupt the derivation's entropy guarantee.
//
// SHA-256 of the canonical source .txt this was generated from (each
// consumer's test suite asserts this file's export still hashes to this
// same value, so any hand-edit or generation bug is caught, not silently
// shipped):
//   ${sha256}

export const WORDLIST_SHA256 = ${JSON.stringify(sha256)};

export const WORDLIST: readonly string[] = ${JSON.stringify(words, null, 2)};
`;

const targets = [
  join(repoRoot, "packages/aroha-registry/src/wordlist.ts"),
  join(repoRoot, "apps/registry-server/src/wordlist.ts"),
];

for (const target of targets) {
  writeFileSync(target, banner);
  console.log(`wrote ${target}`);
}
