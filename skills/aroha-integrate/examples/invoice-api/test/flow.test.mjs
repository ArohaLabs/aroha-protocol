// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// The whole flow, end to end over real HTTP: a customer enrolls, authorises an
// agent, the agent invoices — and everything outside the authorisation is
// refused. Each party's key is created in its own temp file; only DIDs and
// tokens pass between them, as they would between devices.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { issueIntentMandate, signEnrollment } from "@aroha-sdk/credentials";
import { loadOrCreateKey } from "../lib/keystore.mjs";
import { enroll, authorise } from "../customer.mjs";
import { sendInvoice } from "../agent.mjs";
import { createInvoiceService, listen } from "../server.mjs";

let dir, svc, server, url, acme, globex, agent, otherAgent, failNextSend = false;
let clock = Date.now();   // the service's clock — tests move it instead of sleeping

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "invoice-api-"));
  acme = await loadOrCreateKey(join(dir, "acme.json"));         // Acme's device
  globex = await loadOrCreateKey(join(dir, "globex.json"));     // Globex's device
  agent = await loadOrCreateKey(join(dir, "agent.json"));       // the agent's host
  otherAgent = await loadOrCreateKey(join(dir, "other.json"));  // someone else's agent
  svc = createInvoiceService({
    accounts: { acme: "acme-login", globex: "globex-login" },
    audience: "https://invoices.example.com",
    sendInvoice: async () => (failNextSend ? ((failNextSend = false), { ok: false }) : { ok: true }),
    now: () => clock,
  });
  server = await listen(svc);
  url = server.url;
});
after(async () => { await server.close(); rmSync(dir, { recursive: true, force: true }); });

const AUD = "https://invoices.example.com";
const post = (path, body, headers = {}) =>
  fetch(url + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

// ── Enrollment ───────────────────────────────────────────────────────────────

test("enrollment: a customer proves both their account and their key", async () => {
  assert.deepEqual(await enroll({ serviceUrl: url, audience: AUD, accountApiKey: "acme-login", key: acme }), { customerId: "acme", did: acme.did });
  await enroll({ serviceUrl: url, audience: AUD, accountApiKey: "globex-login", key: globex });
  assert.equal(await svc.enrolledDidOf("acme"), acme.did);
});

test("enrollment: refused without a login, for someone else's account, or without the key", async () => {
  assert.equal((await post("/enroll/challenge", {})).status, 401);
  const acmeLogin = { authorization: "Bearer acme-login" };
  const globexLogin = { authorization: "Bearer globex-login" };
  // A challenge issued to Acme's login cannot be completed under Globex's.
  const forAcme = await (await post("/enroll/challenge", {}, acmeLogin)).json();
  const crossProof = await signEnrollment({ accountId: "acme", did: globex.did, challenge: forAcme.challenge, audience: AUD, privateKey: globex.privateKey });
  const cross = await post("/enroll", { did: globex.did, challenge: forAcme.challenge, proof: crossProof }, globexLogin);
  assert.equal((await cross.json()).error, "CHALLENGE_ACCOUNT_MISMATCH");
  // The right login, but a proof made with a key that is not the DID's.
  const c1 = await (await post("/enroll/challenge", {}, acmeLogin)).json();
  // Signed correctly — but by another key (for its own DID), then submitted for Acme's DID.
  const notTheKey = await signEnrollment({ accountId: "acme", did: otherAgent.did, challenge: c1.challenge, audience: AUD, privateKey: otherAgent.privateKey });
  const wrongKey = await post("/enroll", { did: acme.did, challenge: c1.challenge, proof: notTheKey }, acmeLogin);
  assert.equal((await wrongKey.json()).error, "BAD_PROOF");
  // That challenge is spent even though the attempt failed.
  const again = await signEnrollment({ accountId: "acme", did: acme.did, challenge: c1.challenge, audience: AUD, privateKey: acme.privateKey });
  assert.equal((await (await post("/enroll", { did: acme.did, challenge: c1.challenge, proof: again }, acmeLogin)).json()).error, "CHALLENGE_UNKNOWN");
  // A proof made for another service does not enroll here.
  const c2 = await (await post("/enroll/challenge", {}, acmeLogin)).json();
  const elsewhere = await signEnrollment({ accountId: "acme", did: acme.did, challenge: c2.challenge, audience: "https://other.example.com", privateKey: acme.privateKey });
  assert.equal((await (await post("/enroll", { did: acme.did, challenge: c2.challenge, proof: elsewhere }, acmeLogin)).json()).error, "BAD_PROOF");
  assert.equal(await svc.enrolledDidOf("acme"), acme.did);
});

// ── Invoicing ────────────────────────────────────────────────────────────────

test("an authorised agent invoices within the limit, as a running total", async () => {
  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 500, hours: 1 });
  const first = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 300 });
  assert.equal(first.status, 200);
  const second = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 200 });
  assert.equal(second.status, 200);
  const over = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 0.01 });
  assert.equal(over.status, 403);
  assert.equal(over.body.error, "OVER_LIMIT");
});

test("a single invoice over the limit is refused", async () => {
  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 500, hours: 1 });
  const r = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 500.01 });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "OVER_LIMIT");
});

test("another agent cannot use the token, and another customer's token does not work for Acme", async () => {
  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 500, hours: 1 });
  // The client library refuses to present someone else's token; a hostile
  // agent would not use it, so present the token under the other agent's key
  // with the test helper instead.
  const { presentMandateHttpUnchecked } = await import("@aroha-sdk/credentials/testing");
  const body = JSON.stringify({ customerId: "acme", amountUsd: 10 });
  const forged = await presentMandateHttpUnchecked({
    token, holderDid: otherAgent.did, holderPrivateKey: otherAgent.privateKey,
    audience: AUD, method: "POST", url: url + "/tools/send_invoice", body,
  });
  const stolen = await fetch(url + "/tools/send_invoice", { method: "POST", headers: { ...forged, "content-type": "application/json" }, body });
  assert.equal(stolen.status, 401);
  // Globex authorised the agent — but for Globex. Pinned to Acme's DID, it fails.
  const globexToken = await authorise({ key: globex, agentDid: agent.did, limitUsd: 500, hours: 1 });
  const cross = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token: globexToken, customerId: "acme", amountUsd: 10 });
  assert.equal(cross.status, 403);
  // A mandate the agent signed itself, claiming to be a customer, also fails.
  const selfMade = (await issueIntentMandate(agent.did, agent.did, { spendLimitUsd: 1000 }, agent.privateKey, 3_600_000)).token;
  assert.equal((await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token: selfMade, customerId: "acme", amountUsd: 10 })).status, 403);
});

test("expired, tampered or missing authorisations are refused", async () => {
  // Expiry on the service's clock: an authorisation for one hour, and the
  // service two hours later. The agent's presentation is fresh; the mandate is not.
  const hourLong = await authorise({ key: acme, agentDid: agent.did, limitUsd: 500, hours: 1 });
  clock = Date.now() + 2 * 3_600_000;
  const late = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token: hourLong, customerId: "acme", amountUsd: 10, presentAt: clock });
  clock = Date.now();
  assert.equal(late.status, 403);
  assert.match(late.body.reason, /expired/i);

  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 5, hours: 1 });
  const decoded = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  decoded.mandate.constraints.spendLimitUsd = 5000;              // raise the limit after signing
  const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64url");
  assert.equal((await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token: tampered, customerId: "acme", amountUsd: 10 })).status, 403);

  const none = await post("/tools/send_invoice", { customerId: "acme", amountUsd: 10 });
  assert.equal(none.status, 401);
});

test("an authorisation in another currency is refused", async () => {
  // The service charges in USD; a customer's EUR authorisation must not be read as dollars.
  const eur = (await issueIntentMandate(acme.did, agent.did, { spendLimitUsd: 500, currency: "EUR" }, acme.privateKey, 3_600_000)).token;
  const r = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token: eur, customerId: "acme", amountUsd: 10 });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "CURRENCY_MISMATCH");
});

test("a send that fails gives the money back", async () => {
  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 100, hours: 1 });
  failNextSend = true;
  assert.equal((await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 100 })).status, 502);
  // The full $100 is still available.
  assert.equal((await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "acme", amountUsd: 100 })).status, 200);
});

test("an unknown customer is refused before any check", async () => {
  const token = await authorise({ key: acme, agentDid: agent.did, limitUsd: 5, hours: 1 });
  const r = await sendInvoice({ serviceUrl: url, audience: AUD, key: agent, token, customerId: "nobody", amountUsd: 1 });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "ROOT_NOT_PINNED");   // the library refuses an empty pin; no 500
});
