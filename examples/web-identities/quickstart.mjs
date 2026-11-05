// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The $500 flight example with every party named by a web address instead of
// a did:aroha identifier. A person grants an assistant $500 for airline
// purchases, the assistant passes $300 of it to a flight agent, and the
// flight agent checks the whole chain, fetching each signer's key from the
// address that names it.
//
// It runs offline: the three addresses are served by a small server this
// script starts on 127.0.0.1. In production they are https addresses on hosts
// you control, and `allowLoopbackHttp` is not set.
//
//   node quickstart.mjs

import { createServer } from "node:http";
import { generateKeyPair } from "@aroha-sdk/core";
import * as credentials from "@aroha-sdk/credentials";

const { issueIntentMandate, attenuateToPayment, verifyMandateChain, createMandateKeyResolver, buildWebIdentityDocument } = credentials;
if (typeof buildWebIdentityDocument !== "function") {
  console.error("This example needs web identities, which are not in the installed @aroha-sdk/credentials yet.");
  console.error("Run it from a checkout: npm ci && npm run build at the repository root, then node examples/web-identities/quickstart.mjs");
  process.exit(1);
}

// ── Three parties, each with a key and a web address ─────────────────────────
const human = await generateKeyPair();
const assistant = await generateKeyPair();
const flightAgent = await generateKeyPair();

/** What each address serves: path → the JSON document that publishes the key. */
const documents = new Map();
const server = createServer((req, res) => {
  const document = documents.get(req.url);
  if (!document) return res.writeHead(404).end();
  res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(document));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

/** Publish a key at an address, as an agent's own web host would. */
function publish(path, publicKey, name) {
  const identity = `${origin}${path}`;
  documents.set(path, buildWebIdentityDocument({ identity, publicKey, name, allowLoopbackHttp: true }));
  return identity;
}
const HUMAN = publish("/people/kiri", human.publicKey, "Kiri");
const ASSISTANT = publish("/agents/assistant", assistant.publicKey, "Assistant");
const FLIGHT_AGENT = publish("/agents/flights", flightAgent.publicKey, "Flight agent");
console.log("person       →", HUMAN);
console.log("assistant    →", ASSISTANT);
console.log("flight agent →", FLIGHT_AGENT);

// ── Grant and delegate: the same calls as with DIDs ──────────────────────────
const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 500, merchantCategory: "4511" }, human.privateKey, 3_600_000);
const payment = await attenuateToPayment(intent, FLIGHT_AGENT, { spendLimitUsd: 300, merchantCategory: "4511" }, assistant.privateKey);

// ── Verify: one resolver for did:aroha identifiers and web addresses ─────────
// `web` is off unless a verifier asks for it, because it means fetching from a
// host named in the token. maxCacheMs: 0 so the key change below shows at once.
const resolveKey = createMandateKeyResolver({ web: { allowLoopbackHttp: true, maxCacheMs: 0 } });
const check = (token) => verifyMandateChain(token, resolveKey, { expectedRoot: HUMAN, expectedGrantee: FLIGHT_AGENT, isRevoked: null });

const result = await check(payment.token);
console.log("valid:", result.valid, "chainVerified:", result.chainVerified, "limit:", result.mandate?.constraints.spendLimitUsd);

// Widening is refused when the assistant tries it…
try {
  await attenuateToPayment(intent, FLIGHT_AGENT, { spendLimitUsd: 600, merchantCategory: "4511" }, assistant.privateKey);
} catch (err) {
  console.log("widening to $600 →", err.message);
}

// …and a link signed by a key the address does not publish is refused.
const stranger = await generateKeyPair();
const forged = await attenuateToPayment(intent, FLIGHT_AGENT, { spendLimitUsd: 300, merchantCategory: "4511" }, stranger.privateKey);
console.log("forged link  → valid:", (await check(forged.token)).valid);

// ── The same grant as JWTs ────────────────────────────────────────────────────
// For a service that already verifies OAuth access tokens: ask for the JWT form
// at the root, and every link is a JWT a stock JWT library can read. The chain
// is the link JWTs joined by "~". The same verifier checks it.
const jwtIntent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 500, merchantCategory: "4511" }, human.privateKey, 3_600_000, { format: "jwt" });
const jwtPayment = await attenuateToPayment(jwtIntent, FLIGHT_AGENT, { spendLimitUsd: 300, merchantCategory: "4511" }, assistant.privateKey);
const links = jwtPayment.token.split("~");
const leafClaims = JSON.parse(Buffer.from(links.at(-1).split(".")[1], "base64url").toString("utf8"));
console.log(
  "as JWTs      → valid:", (await check(jwtPayment.token)).valid,
  "links:", links.length,
  "leaf iss is the assistant:", leafClaims.iss === ASSISTANT,
  "limit:", leafClaims.authorization_details[0].constraints.spendLimitUsd,
);

// When the assistant replaces its key, what it signed with the old one stops verifying.
publish("/agents/assistant", (await generateKeyPair()).publicKey, "Assistant");
console.log("after the assistant changes its key → valid:", (await check(payment.token)).valid);

server.close();
