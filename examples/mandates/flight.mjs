// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The README's flight example: a person grants an assistant $500 for airline
// purchases for an hour, the assistant passes $300 of it to a flight agent,
// and the flight agent checks the whole chain before acting. Spending mandates.
//
//   npm install && node flight.mjs

import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, attenuateToPayment, verifyMandateChain } from "@aroha-sdk/credentials";

const human = await generateKeyPair();
const assistant = await generateKeyPair();
const flightAgent = await generateKeyPair();
const humanDID = generateDid(human.publicKey);
const assistantDID = generateDid(assistant.publicKey);
const flightAgentDID = generateDid(flightAgent.publicKey);

// The human grants the assistant $500 for airline purchases (MCC 4511), for one hour.
const intent = await issueIntentMandate(
  humanDID, assistantDID,
  { spendLimitUsd: 500, merchantCategory: "4511" },
  human.privateKey, 3_600_000,
);

// The assistant passes $300 of that to the flight agent. The child token
// embeds the signed chain back to the human.
const payment = await attenuateToPayment(
  intent, flightAgentDID,
  { spendLimitUsd: 300, merchantCategory: "4511" },
  assistant.privateKey,
);

// The flight agent verifies every link back to the human before acting.
// In production, pass an `isRevoked` hook as well; the library warns if you do not.
const result = await verifyMandateChain(payment.token, undefined, {
  expectedRoot: humanDID,
  expectedGrantee: flightAgentDID,
});
console.log("valid:", result.valid, "chainVerified:", result.chainVerified, "limit:", result.mandate?.constraints.spendLimitUsd);

// Widening is refused at issue time, and would fail verification if forged.
try {
  await attenuateToPayment(intent, flightAgentDID, { spendLimitUsd: 600, merchantCategory: "4511" }, assistant.privateKey);
} catch (err) {
  console.log("widening to $600 →", err.message);
}
