// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// THE CUSTOMER'S SIDE. Runs on the customer's device (in a real product: your
// app or wallet on their phone or laptop). It does three things, and the
// customer's private key never leaves this file's process:
//
//   1. init       create the customer's key and DID (once)
//   2. enroll     prove to the invoice service that this DID is theirs
//   3. authorise  sign a spending mandate for ONE agent: a limit and an expiry
//
//   node customer.mjs init
//   node customer.mjs enroll <serviceUrl> <accountApiKey> [audience]
//   node customer.mjs authorise <agentDid> <limitUsd> <hours>   → prints the token to give the agent

import { issueIntentMandate, signEnrollment } from "@aroha-sdk/credentials";
import { loadOrCreateKey } from "./lib/keystore.mjs";
import { pathToFileURL } from "node:url";

/**
 * Enroll: tell the service "customer <customerId> is did:aroha:z…".
 *
 * Two things are proved together, and the service needs both:
 *   - the ACCOUNT: the customer's existing login with the service (here an
 *     API key; in a product, their signed-in session). This is what stops
 *     anyone from enrolling a DID for someone else's account.
 *   - the KEY: a signature with the DID's private key over a fresh,
 *     single-use challenge from the service. This is what stops anyone from
 *     enrolling a DID whose key they do not hold.
 */
export async function enroll({ serviceUrl, audience, accountApiKey, key }) {
  const auth = { authorization: `Bearer ${accountApiKey}` };
  const c = await fetch(`${serviceUrl}/enroll/challenge`, { method: "POST", headers: auth });
  if (!c.ok) throw new Error(`challenge refused: ${c.status} ${await c.text()}`);
  // The service says which account the login belongs to; the proof names it,
  // the challenge and this service (audience), signed with the DID's own key.
  const { challenge, accountId } = await c.json();
  const proof = await signEnrollment({ accountId, did: key.did, challenge, audience: audience ?? serviceUrl, privateKey: key.privateKey });
  const r = await fetch(`${serviceUrl}/enroll`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ did: key.did, challenge, proof }),
  });
  if (!r.ok) throw new Error(`enrollment refused: ${r.status} ${await r.text()}`);
  return r.json();
}

/**
 * Authorise ONE agent to spend up to `limitUsd` for `hours`. The agent asked
 * for this by showing its DID (agent.mjs); the customer decides the limit
 * and expiry here, on their own device, and hands back only the token.
 */
export async function authorise({ key, agentDid, limitUsd, hours }) {
  const grant = await issueIntentMandate(key.did, agentDid, { spendLimitUsd: limitUsd, currency: "USD" }, key.privateKey, hours * 3_600_000);
  return grant.token;
}

// ── CLI ──────────────────────────────────────────────────────────────────────

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const keyPath = process.env.CUSTOMER_KEY ?? ".keys/customer.json";
  const [cmd, ...args] = process.argv.slice(2);
  const key = await loadOrCreateKey(keyPath);
  if (cmd === "init") {
    console.log(key.did);
  } else if (cmd === "enroll") {
    const [serviceUrl, accountApiKey, audience] = args;
    console.log(await enroll({ serviceUrl, accountApiKey, audience, key }));
  } else if (cmd === "authorise") {
    const [agentDid, limitUsd, hours] = args;
    console.log(await authorise({ key, agentDid, limitUsd: Number(limitUsd), hours: Number(hours) }));
  } else {
    console.error("usage: node customer.mjs init | enroll <serviceUrl> <accountApiKey> [audience] | authorise <agentDid> <limitUsd> <hours>");
    process.exitCode = 2;
  }
}
