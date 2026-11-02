// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// An inbox assistant that may read mail and propose what to archive, and may
// never delete, no matter what it is told. Non-monetary task mandates.
//
//   npm install && node inbox.mjs

import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import {
  issueTaskMandate,
  attenuateTaskMandate,
  enforceTaskConstraints,
} from "@aroha-sdk/credentials";
import { verifyTaskMandateChain, staticResolver } from "@aroha-sdk/delegation";

// Three identities: me, my inbox assistant, and a summariser it may call.
const me = await generateKeyPair();
const assistant = await generateKeyPair();
const summariser = await generateKeyPair();
const meDID = generateDid(me.publicKey);
const assistantDID = generateDid(assistant.publicKey);
const summariserDID = generateDid(summariser.publicKey);

// 1. I sign a mandate: read my mail and propose what to archive, for one hour.
//    Deleting is explicitly blocked.
const mandate = await issueTaskMandate(
  meDID, assistantDID,
  ["read-email", "propose-archive"],
  { dataAccess: { mailbox: "read" }, maxDelegationDepth: 1 },
  me.privateKey,
  60 * 60 * 1000,
  { blocked: ["delete-email"] },
);

// 2. The mail tool checks every call against the mandate before doing anything.
//    It does not trust the assistant; it trusts my signature.
async function mailTool(capability) {
  try {
    await enforceTaskConstraints(mandate.token, me.publicKey, {
      expectedGrantee: assistantDID,
      requestedCapability: capability,
      capabilityReversibility: "full",
      dataAccess: { mailbox: "read" },
    });
    return "allowed";
  } catch (err) {
    return `refused (${err.code}): ${err.message}`;
  }
}
console.log("read-email      →", await mailTool("read-email"));
console.log("propose-archive →", await mailTool("propose-archive"));
console.log("delete-email    →", await mailTool("delete-email"));

// 3. The assistant hands the summarising to a sub-agent, with read only.
//    The sub-agent verifies the whole chain back to me.
const child = await attenuateTaskMandate(
  mandate, summariserDID,
  ["read-email"],
  { dataAccess: { mailbox: "read" }, maxDelegationDepth: 0 },
  assistant.privateKey,
);
const chain = await verifyTaskMandateChain([mandate.token, child.token], me.publicKey, {
  expectedGrantee: summariserDID,
  resolvePublicKey: staticResolver({ [assistantDID]: assistant.publicKey }),
});
console.log("sub-agent chain →", chain.valid ? `valid, may: ${chain.mandate.allowed}` : chain.reason);

// 4. The assistant tries to give the sub-agent delete. Scope can only narrow.
try {
  await attenuateTaskMandate(
    mandate, summariserDID,
    ["read-email", "delete-email"],
    { dataAccess: { mailbox: "read" }, maxDelegationDepth: 0 },
    assistant.privateKey,
  );
} catch (err) {
  console.log("widening        →", err.message);
}
