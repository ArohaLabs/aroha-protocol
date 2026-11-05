#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Make what a manual test of web identities needs (spec §4.7), for example
// the hosted-assistant runbook in docs/integrations/remote-mcp-connector.md:
//
//   identity.json     the document to serve at the address
//   private-key.txt   the signing key (base64url). Test material only.
//   mandates.json     a spending mandate and a task mandate signed by that
//                     address, a forged one, and what verify_mandate should say
//
// Usage (from a built checkout: npm ci && npm run build):
//   node scripts/web-identity-fixture.mjs https://you.example.com/agents/tester [--grantee <id>] [--hours 24] [--out web-identity-fixture]
//
// Nothing is sent anywhere. Serve identity.json at the address yourself
// (HTTP 200, application/json, no redirect), then give the tokens to the
// verifier you are testing.

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateKeyPair } from "@aroha-sdk/core";
import { buildWebIdentityDocument, checkWebIdentity, issueIntentMandate, issueTaskMandate } from "@aroha-sdk/credentials";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args.splice(i, 2)[1] : fallback;
};
const grantee = flag("grantee", "https://agents.example.com/assistant");
const hours = Number(flag("hours", "24"));
const out = resolve(flag("out", "web-identity-fixture"));
const identity = args[0];

if (!identity) {
  console.error("Usage: node scripts/web-identity-fixture.mjs <https address> [--grantee <id>] [--hours 24] [--out dir]");
  process.exit(2);
}
const why = checkWebIdentity(identity);
if (why) {
  console.error(`${why}: ${identity}`);
  process.exit(2);
}
if (!Number.isFinite(hours) || hours <= 0 || hours > 24 * 30) {
  console.error("--hours must be between 0 and 720");
  process.exit(2);
}

const keys = await generateKeyPair();
const stranger = await generateKeyPair();
const ttlMs = hours * 3_600_000;
const document = buildWebIdentityDocument({ identity, publicKey: keys.publicKey, name: "Aroha web identity test fixture" });
const spending = await issueIntentMandate(identity, grantee, { spendLimitUsd: 25, currency: "USD" }, keys.privateKey, ttlMs);
const task = await issueTaskMandate(identity, grantee, ["inbox.read", "inbox.archive"], { actionLimits: { "inbox.archive": 20 } }, keys.privateKey, ttlMs);
const forged = await issueIntentMandate(identity, grantee, { spendLimitUsd: 5000, currency: "USD" }, stranger.privateKey, ttlMs);

mkdirSync(out, { recursive: true });
writeFileSync(join(out, "identity.json"), JSON.stringify(document, null, 2) + "\n");
writeFileSync(join(out, "private-key.txt"), Buffer.from(keys.privateKey).toString("base64url") + "\n", { mode: 0o600 });
writeFileSync(
  join(out, "mandates.json"),
  JSON.stringify(
    {
      identity,
      grantee,
      expires: spending.mandate.expiresAt,
      cases: [
        { name: "spending mandate signed by the address", token: spending.token, expectedGrantee: grantee, expect: { valid: true, kind: "spending", rootGrantor: identity } },
        { name: "task mandate signed by the address", token: task.token, expectedGrantee: grantee, expect: { valid: true, kind: "task" } },
        { name: "wrong expected grantee", token: spending.token, expectedGrantee: "https://agents.example.com/someone-else", expect: { valid: false } },
        { name: "signed by a key the address does not publish", token: forged.token, expectedGrantee: grantee, expect: { valid: false } },
      ],
    },
    null,
    2,
  ) + "\n",
);

console.log(`Wrote ${out}`);
console.log(`1. Serve ${join(out, "identity.json")} at ${identity} (HTTP 200, application/json, no redirect).`);
console.log("2. Give each token in mandates.json to the verifier under test and compare its answer with `expect`.");
console.log(`3. The mandates expire at ${spending.mandate.expiresAt}. Delete ${join(out, "private-key.txt")} when you are done.`);
