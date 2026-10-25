// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates spec-public/vectors/conversation-v1.json — the Conversation
 * and Memory Profile vectors (room, consent, turn, receipts v1/v2,
 * disclosure-bearing envelope, task mandate v2 with onBehalfOf/roomId).
 *
 *   npx tsx packages/aroha-core/scripts/gen-conversation-vectors.ts
 *
 * Everything is fixed (RFC 8032 §7.1 test keys, hard-coded ids and
 * timestamps) and Ed25519 is deterministic, so regenerating MUST produce an
 * identical file. If it does not, a canonical form changed — a protocol
 * break, not a refresh. The keys are public test keys: never use them for
 * anything real.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "../src/crypto/jcs.js";
import { canonicalizeMessage } from "../src/crypto/signing.js";
import { generateDid } from "../src/identity/did.js";
import { incept } from "../src/identity/kel.js";
import { buildDisclosure } from "../src/messages/disclosure.js";
import {
  signRoom, createConsent, appendConsentEvent, consentEventSigningBytes, signTurn, conversationSigningBytes, turnSigningBytes,
  type RoomRecord, type ConsentRecord,
} from "../src/conversation/index.js";
import {
  signActionReceipt, signActionReceiptV1, actionReceiptSigningBytes, hashReceiptArgs, hashPresentedContent,
} from "../src/receipts/index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const OUT = resolve(ROOT, "spec-public", "vectors", "conversation-v1.json");

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const text = (b: Uint8Array) => new TextDecoder().decode(b);

// RFC 8032 §7.1: TEST 1, TEST 2, TEST 3, TEST 1024 and TEST SHA(abc) secret keys.
const SEEDS = {
  hostCurrent: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  hostNext: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
  guestCurrent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  guestNext: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
  agent: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;

async function main() {
  const host = await incept({
    kind: "person", privateKey: fromHex(SEEDS.hostCurrent), nextPrivateKey: fromHex(SEEDS.hostNext),
    now: new Date("2026-10-01T09:00:00.000Z"),
  });
  const guest = await incept({
    kind: "person", privateKey: fromHex(SEEDS.guestCurrent), nextPrivateKey: fromHex(SEEDS.guestNext),
    now: new Date("2026-10-01T09:05:00.000Z"),
  });
  const agentPriv = fromHex(SEEDS.agent);
  const agentPub = await ed.getPublicKeyAsync(agentPriv);
  const agentDid = generateDid(agentPub);

  const ROOM_ID = "room-01J9ZK3Q7V";
  const THREAD_ID = "thread-01J9ZK3Q7V";

  // ── Disclosure ──────────────────────────────────────────────────────────────
  const disclosure = buildDisclosure({
    agentDid, principalDid: host.did, principalKind: "person",
    purpose: "Personal assistant for the host; answers in this room when addressed", hop: 0,
  });

  // ── Room ────────────────────────────────────────────────────────────────────
  const room = await signRoom({
    roomId: ROOM_ID, threadId: THREAD_ID, ownerDid: host.did, epoch: 2,
    members: [
      { did: host.did, kind: "person", displayName: "Ana", role: "host", joinedEpoch: 0 },
      { did: agentDid, kind: "agent", displayName: "Ana's assistant", role: "own", joinedEpoch: 0 },
      { did: guest.did, kind: "person", displayName: "Ben", role: "guest", joinedEpoch: 1, consentRef: "consent-01J9ZK4A" },
    ],
    historyVisibility: "joined", invocation: "explicit",
    memoryPolicy: { personalRead: false, personalWrite: false, roomMemory: "consented", agentRead: "none" },
    disclosure, updatedAt: "2026-10-15T10:00:00.000Z",
  }, host.privateKey);
  const roomAgentSigned: RoomRecord = { ...room, signature: Buffer.from(await ed.signAsync(conversationSigningBytes(room as unknown as Record<string, unknown>), agentPriv)).toString("base64url") };

  // ── Consent ─────────────────────────────────────────────────────────────────
  const consentGiven = await createConsent({
    recordId: "consent-01J9ZK4A", subjectDid: guest.did, roomId: ROOM_ID,
    purposes: ["transcript_retention", "agent_use_of_messages", "memory_write"],
    withdrawalRoute: "Room settings > Privacy > Withdraw consent",
    given: { purposes: ["transcript_retention", "agent_use_of_messages", "memory_write"], at: "2026-10-15T10:00:00.000Z", epoch: 1 },
  }, guest.privateKey);
  // The host (a room member at epoch 2) withdraws memory_write for the guest.
  const consentWithdrawn = await appendConsentEvent(consentGiven, {
    event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 2, actorDid: host.did,
  }, host.privateKey);
  // Forgery attempt: the host rewrites the guest's earlier "given" event to add
  // a purpose, then appends its own (validly signed) withdrawal on top.
  const forgedBase: ConsentRecord = JSON.parse(JSON.stringify(consentGiven));
  forgedBase.purposes = ["transcript_retention", "agent_use_of_messages", "memory_write", "provider_processing"];
  forgedBase.events[0].purposes = [...forgedBase.purposes];
  const forgedGiven = await appendConsentEvent(forgedBase, {
    event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 2, actorDid: host.did,
  }, host.privateKey);
  // A withdrawal by the host claiming an epoch the room record does not reach.
  const withdrawnBeyondRoom = await appendConsentEvent(consentGiven, {
    event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 5, actorDid: host.did,
  }, host.privateKey);

  // ── Turn ────────────────────────────────────────────────────────────────────
  const turn = await signTurn({
    threadId: THREAD_ID, roomId: ROOM_ID, epoch: 2, at: "2026-10-15T10:05:00.000Z",
    addressedTo: [agentDid], authorDid: guest.did,
    content: "Could you suggest three restaurants near the station for Friday?",
  }, guest.privateKey);

  // ── Receipts ────────────────────────────────────────────────────────────────
  const args = { to: "ben@example.com", subject: "Friday dinner", body: "Three options attached." };
  const presented = { action: "send-email", to: "ben@example.com", subject: "Friday dinner", preview: "Three options attached." };
  const presentedHash = hashPresentedContent(presented);
  const receiptV1 = await signActionReceiptV1({
    agentDid, action: "send-email", argsSha256: hashReceiptArgs(args), at: "2026-10-15T10:10:00.000Z",
    tainted: false, provenance: ["user"], correlationId: "corr-01",
  }, agentPriv);
  const receiptV2 = await signActionReceipt({
    agentDid, action: "send-email", argsSha256: hashReceiptArgs(args), at: "2026-10-15T10:10:00.000Z",
    tainted: true, provenance: ["user", "peer"],
    approval: { approverDid: host.did, approvedAt: "2026-10-15T10:09:30.000Z", approvalId: "approval-01", presentedHash },
    requesterDid: guest.did, principalDid: host.did, executorDid: agentDid, presentedHash,
    traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    roomId: ROOM_ID, onBehalfOf: guest.did, mandateId: "task-01J9ZK5B", mandateGrantor: host.did, correlationId: "corr-02",
  }, agentPriv);
  const receiptDenied = await signActionReceipt({
    agentDid, action: "pay", argsSha256: hashReceiptArgs({ amountMinor: 4500, currency: "EUR" }), at: "2026-10-15T10:12:00.000Z",
    tainted: true, provenance: ["peer"], requesterDid: guest.did, principalDid: host.did, executorDid: agentDid,
    roomId: ROOM_ID, outcome: "denied", denialReason: "guest-origin request for a host-only capability",
  }, agentPriv);

  // ── Disclosure-bearing envelope ─────────────────────────────────────────────
  const envelopeUnsigned = {
    "@context": ["https://aroha-labs.com/contexts/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    id: "urn:uuid:0b6f1e9a-5d6c-4d55-8a0f-3f1b2c4d5e6f",
    type: "ArohaRequest",
    from: agentDid,
    to: "did:aroha:zHyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
    created: "2026-10-15T10:06:00.000Z",
    expires: "2026-10-15T10:11:00.000Z",
    nonce: "a3f1c2d4e5b6978877665544332211000ffeeddccbbaa99887766554433221100",
    correlationId: "corr-03",
    body: { capability: "search", params: { query: "restaurants near the station" } },
    disclosure,
  };
  const envelopeSigningPayload = canonicalizeMessage(envelopeUnsigned);
  const envelope = {
    ...envelopeUnsigned,
    proof: {
      type: "Ed25519Signature2020", created: "2026-10-15T10:06:00.000Z",
      verificationMethod: `${agentDid}#key-1`, proofPurpose: "authentication",
      proofValue: Buffer.from(await ed.signAsync(new TextEncoder().encode(envelopeSigningPayload), agentPriv)).toString("base64url"),
    },
  };

  // ── Task mandate v2 with onBehalfOf / roomId (a guest grant) ────────────────
  const taskMandate = {
    mandateType: "task", mandateTier: "intent", allowed: ["search", "draft-email"],
    taskConstraints: { onBehalfOf: guest.did, roomId: ROOM_ID, reversibleOnly: true, humanGates: ["draft-email"] },
    grantee: agentDid, grantor: host.did,
    issuedAt: "2026-10-15T10:00:00.000Z", expiresAt: "2026-10-15T22:00:00.000Z",
    parentMandateId: null, mandateId: "task-01J9ZK5B",
  };
  const taskPayload = canonicalizeJcs({ mandate: taskMandate, purpose: "aroha.task-mandate/v2", v: 2 });
  const taskSig = Buffer.from(await ed.signAsync(new TextEncoder().encode(taskPayload), host.privateKey)).toString("base64url");
  const taskToken = Buffer.from(JSON.stringify({ v: 2, mandate: taskMandate, signature: taskSig })).toString("base64url");

  const out = {
    description:
      "Aroha Conversation and Memory Profile vectors (spec aroha-1.0 §12). Every signature is Ed25519 over the UTF-8 bytes of the stated signing payload, base64url without padding. JCS is RFC 8785. Person keys resolve from the Key Event Logs under `kels` (verify the inception, then use keys[0]; the inception's `kind` is the speaker kind); the agent key resolves from its content-addressed did:aroha:z… DID. Keys are RFC 8032 §7.1 test keys — never use them for anything real.",
    generatedBy: "packages/aroha-core/scripts/gen-conversation-vectors.ts",
    keys: {
      host: { privateKeyHex: SEEDS.hostCurrent, nextPrivateKeyHex: SEEDS.hostNext, publicKeyHex: hex(host.publicKey), did: host.did, kind: "person" },
      guest: { privateKeyHex: SEEDS.guestCurrent, nextPrivateKeyHex: SEEDS.guestNext, publicKeyHex: hex(guest.publicKey), did: guest.did, kind: "person" },
      agent: { privateKeyHex: SEEDS.agent, publicKeyHex: hex(agentPub), did: agentDid, kind: "agent" },
    },
    kels: { [host.did]: host.kel, [guest.did]: guest.kel },
    disclosure: { value: disclosure, valid: true },
    room: {
      value: room,
      expectedSigningPayload: text(conversationSigningBytes(room as unknown as Record<string, unknown>)),
      valid: true,
      invalid: [
        { name: "tampered-member-role", value: { ...room, members: room.members.map((m) => m.did === guest.did ? { ...m, role: "host" } : m) }, reason: "shape or signature" },
        { name: "tampered-epoch", value: { ...room, epoch: 3 }, reason: "signature" },
        { name: "signed-by-agent-key", value: roomAgentSigned, reason: "signature (owner key is the host person's)" },
      ],
    },
    consent: {
      given: {
        value: consentGiven, effectivePurposes: ["agent_use_of_messages", "memory_write", "transcript_retention"], valid: true,
        expectedEventSigningPayloads: consentGiven.events.map((_e, i) => text(consentEventSigningBytes(consentGiven, i))),
      },
      withdrawn: {
        value: consentWithdrawn, effectivePurposes: ["agent_use_of_messages", "transcript_retention"], valid: true, requiresRoom: true,
        expectedEventSigningPayloads: consentWithdrawn.events.map((_e, i) => text(consentEventSigningBytes(consentWithdrawn, i))),
      },
      invalid: [
        { name: "forged-earlier-given-event", value: forgedGiven, reason: "events[0] signature (the subject never signed the altered terms)" },
        { name: "purpose-added-after-signing", value: { ...consentGiven, purposes: [...consentGiven.purposes, "provider_processing"] }, reason: "signature" },
        { name: "given-by-non-subject", value: { ...consentGiven, events: [{ ...consentGiven.events[0], actorDid: host.did }] }, reason: "shape (only the subject can give consent)" },
        { name: "withdrawal-at-epoch-beyond-room", value: withdrawnBeyondRoom, reason: "actor not a room member at the event's epoch" },
        { name: "event-removed", value: { ...consentWithdrawn, events: [consentWithdrawn.events[1]] }, reason: "first event must be given" },
      ],
    },
    turn: {
      value: turn,
      expectedContentHash: turn.contentHash,
      expectedSigningPayload: text(turnSigningBytes(turn)),
      expectedSpeakerKind: "person",
      valid: true,
      invalid: [
        { name: "content-edited", value: { ...turn, content: turn.content.replace("three", "five") }, reason: "contentHash" },
        { name: "readdressed", value: { ...turn, addressedTo: [host.did] }, reason: "signature" },
        { name: "epoch-before-join", value: { ...turn, epoch: 0 }, reason: "signature (and not a member at epoch 0)" },
      ],
    },
    receipts: {
      v1: { value: receiptV1, expectedSigningPayload: text(actionReceiptSigningBytes(receiptV1)), valid: true },
      v2Executed: {
        value: receiptV2, expectedSigningPayload: text(actionReceiptSigningBytes(receiptV2)), valid: true,
        presentedContent: presented, expectedPresentedHash: presentedHash,
        mismatchedPresentedContent: { ...presented, to: "someone-else@example.com" },
      },
      v2Denied: { value: receiptDenied, expectedSigningPayload: text(actionReceiptSigningBytes(receiptDenied)), valid: true },
      invalid: [
        { name: "v2-denied-without-reason", value: dropKey(receiptDenied, "denialReason"), reason: "shape" },
        { name: "v1-with-v2-field", value: { ...receiptV1, outcome: "executed" }, reason: "shape (unknown field for v1)" },
        { name: "v2-outcome-flipped", value: { ...receiptDenied, outcome: "executed", denialReason: undefined }, reason: "shape / signature" },
        { name: "v2-unknown-field", value: { ...receiptV2, extra: true }, reason: "shape" },
      ],
    },
    envelopeWithDisclosure: { value: envelope, expectedSigningPayload: envelopeSigningPayload, valid: true },
    taskMandateV2: {
      mandate: taskMandate, expectedSigningPayload: taskPayload, signature: taskSig, token: taskToken,
      requests: [
        { request: { requestedCapability: "search", capabilityReversibility: "full", roomId: ROOM_ID, onBehalfOf: guest.did }, allowed: true },
        { request: { requestedCapability: "search", capabilityReversibility: "full", roomId: "room-other", onBehalfOf: guest.did }, allowed: false, code: "CONTEXT_MISMATCH" },
        { request: { requestedCapability: "search", capabilityReversibility: "full", roomId: ROOM_ID, onBehalfOf: host.did }, allowed: false, code: "CONTEXT_MISMATCH" },
        { request: { requestedCapability: "search", capabilityReversibility: "full" }, allowed: false, code: "CONTEXT_MISMATCH" },
      ],
    },
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(out, (_k, v) => (v === undefined ? undefined : v), 2) + "\n");
  console.log(`wrote ${OUT}`);
}

function dropKey<T extends object>(o: T, k: keyof T): Omit<T, typeof k> {
  const copy = { ...o };
  delete copy[k];
  return copy;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
