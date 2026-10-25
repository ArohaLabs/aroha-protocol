// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/task-mandate-v2-cases.json.
 *
 *   npx tsx scripts/gen-task-test-vectors.ts
 *
 * Cross-SDK contract for v2 TASK mandates (issueTaskMandate /
 * verifyTaskMandate / checkTaskNarrowing / checkTaskConstraints). An
 * implementation passes when it reproduces every expectedSigningPayload and
 * expectedSignature byte for byte, reaches the same verdict (and reason) on
 * every token, the same narrowing reason on every pair, and the same
 * violation code on every action. Keys are the RFC 8032 §7.1 test keys, ids
 * and timestamps are fixed and Ed25519 is deterministic, so regenerating must
 * produce an identical file; if it does not, the canonical form changed.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaTaskMandateBody } from "@aroha-sdk/core";
import {
  checkTaskConstraints,
  checkTaskNarrowing,
  taskMandateSigningPayloadV2,
  verifyTaskMandate,
  type TaskActionRequest,
} from "../src/mandate.js";
import { canonicalizeJcs } from "../src/jcs.js";

// Same as the (private) sortKeys in src/mandate.ts: the v1 signing rule.
function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.fromEntries(
      Object.keys(obj as Record<string, unknown>).sort().map((k) => [k, sortKeys((obj as Record<string, unknown>)[k])])
    );
  }
  return obj;
}

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (s: string) => Buffer.from(s).toString("base64url");

const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  vendor: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }

  const ROOM = "room-7f3a";
  const GUEST = "did:aroha:guest-bob";

  const root: ArohaTaskMandateBody = {
    mandateType: "task",
    mandateTier: "intent",
    allowed: ["web-search", "draft-email", "send-email", "read-calendar"],
    blocked: ["delete-files"],
    taskConstraints: {
      actionLimits: { "send-email": 3, "web-search": 20 },
      computeLimit: { llmTokens: 50000, webRequests: 40, executionTimeMs: 600000 },
      dataAccess: { calendar: "read", email: "read-write", "files:/drafts": "write" },
      outputHandling: "user-only",
      reversibleOnly: false,
      humanGates: ["send-email"],
      checkpointIntervalMs: 30000,
      requireSandbox: true,
      maxDelegationDepth: 2,
      onBehalfOf: GUEST,
      roomId: ROOM,
    },
    grantee: keys.agent.did,
    grantor: keys.human.did,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z",
    parentMandateId: null,
    mandateId: "00000000-0000-4000-8000-0000000000a1",
  };
  const child: ArohaTaskMandateBody = {
    mandateType: "task",
    mandateTier: "cart",
    allowed: ["web-search", "send-email"],
    blocked: ["delete-files"],
    taskConstraints: {
      actionLimits: { "send-email": 1, "web-search": 5.5 },
      computeLimit: { llmTokens: 1000, webRequests: 10, executionTimeMs: 60000 },
      dataAccess: { email: "read" },
      outputHandling: "internal-only",
      humanGates: ["send-email"],
      checkpointIntervalMs: 10000,
      requireSandbox: true,
      onBehalfOf: GUEST,
      roomId: ROOM,
    },
    grantee: keys.vendor.did,
    grantor: keys.agent.did,
    issuedAt: "2026-01-01T00:00:01.000Z",
    expiresAt: "2098-01-01T00:00:00.000Z",
    parentMandateId: root.mandateId,
    mandateId: "00000000-0000-4000-8000-0000000000a2",
  };
  const hybrid: ArohaTaskMandateBody = {
    mandateType: "hybrid",
    mandateTier: "intent",
    allowed: ["book-flight"],
    taskConstraints: { reversibleOnly: true },
    spendingConstraints: { spendLimitUsd: 420.07, currency: "USD", allowedMerchants: ["did:aroha:airline"] },
    invariants: { payee: ["did:aroha:airline"], parameters: { destination: "JFK", seats: 1, refundable: true } },
    grantee: keys.agent.did,
    grantor: keys.human.did,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:00:00.000Z",
    parentMandateId: null,
    mandateId: "00000000-0000-4000-8000-0000000000b1",
  };
  // Correctly signed, but widens its parent: must be refused by a verifier
  // that re-runs checkTaskNarrowing on the link.
  const widened: ArohaTaskMandateBody = {
    ...child,
    taskConstraints: { ...child.taskConstraints, actionLimits: { "send-email": 9, "web-search": 5 }, roomId: undefined },
    mandateId: "00000000-0000-4000-8000-0000000000a3",
  };
  // EMPTY IS NOT ABSENT. An empty dataAccess map grants no data at all and
  // an empty payee list pays nobody; only a MISSING field means "no limit".
  // A port that tests these by truthiness fails open (it did once, in
  // Python), so the vectors pin both.
  const denyData: ArohaTaskMandateBody = {
    ...root,
    taskConstraints: { ...root.taskConstraints, dataAccess: {} },
    mandateId: "00000000-0000-4000-8000-0000000000a4",
  };
  const noPayees: ArohaTaskMandateBody = {
    ...hybrid,
    invariants: { payee: [], parameters: { destination: "JFK", seats: 1, refundable: true } },
    mandateId: "00000000-0000-4000-8000-0000000000b2",
  };
  const clean = (m: ArohaTaskMandateBody) => JSON.parse(JSON.stringify(m)) as ArohaTaskMandateBody;

  async function signV2(signer: KeyName, mandate: ArohaTaskMandateBody) {
    const payload = taskMandateSigningPayloadV2(mandate);
    const sig = await ed.signAsync(new TextEncoder().encode(payload), keys[signer].priv);
    return { payload, signature: Buffer.from(sig).toString("base64url") };
  }

  const mandates = [];
  const signed: Record<string, { mandate: ArohaTaskMandateBody; signature: string; signer: KeyName }> = {};
  for (const [name, signer, m] of [
    ["task-root", "human", root],
    ["task-child", "agent", child],
    ["hybrid-root", "human", hybrid],
    ["task-child-widened", "agent", widened],
    ["task-root-deny-data", "human", denyData],
    ["hybrid-root-no-payees", "human", noPayees],
  ] as const) {
    const mandate = clean(m);
    const { payload, signature } = await signV2(signer, mandate);
    signed[name] = { mandate, signature, signer };
    mandates.push({ name, signer, mandate, expectedSigningPayload: payload, expectedSignature: signature });
  }

  const tokenOf = (o: Record<string, unknown>) => b64u(JSON.stringify(o));
  const v2 = (n: string) => ({ v: 2, mandate: signed[n].mandate, signature: signed[n].signature });

  // A v1 (legacy) token: no "v", signature over sortKeys/JSON.stringify.
  const v1Sig = Buffer.from(await ed.signAsync(
    new TextEncoder().encode(JSON.stringify(sortKeys(signed["task-root"].mandate as unknown as Record<string, unknown>))),
    keys.human.priv,
  )).toString("base64url");
  // The same body signed WITHOUT the purpose tag (a spending-style v2
  // payload): a task verifier must not accept it.
  const noPurposeSig = Buffer.from(await ed.signAsync(
    new TextEncoder().encode(canonicalizeJcs({ mandate: signed["task-root"].mandate, v: 2 })),
    keys.human.priv,
  )).toString("base64url");
  const tampered = { ...v2("task-root"), mandate: { ...signed["task-root"].mandate, allowed: [...root.allowed, "delete-files"] } };

  const tokenCases: { name: string; token: string; signer: KeyName; verifyAt: string; expectedGrantee?: string }[] = [
    { name: "valid-root", token: tokenOf(v2("task-root")), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "valid-child", token: tokenOf(v2("task-child")), signer: "agent", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "valid-hybrid", token: tokenOf(v2("hybrid-root")), signer: "human", verifyAt: "2026-06-01T00:00:00.000Z" },
    { name: "valid-legacy-v1", token: tokenOf({ mandate: signed["task-root"].mandate, signature: v1Sig }), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "tampered-allowed-list", token: tokenOf(tampered), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "wrong-signer-key", token: tokenOf(v2("task-root")), signer: "agent", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "no-purpose-tag", token: tokenOf({ v: 2, mandate: signed["task-root"].mandate, signature: noPurposeSig }), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "v1-signature-claimed-as-v2", token: tokenOf({ v: 2, mandate: signed["task-root"].mandate, signature: v1Sig }), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "expired", token: tokenOf(v2("hybrid-root")), signer: "human", verifyAt: "2027-01-01T00:00:00.001Z" },
    { name: "issued-in-future", token: tokenOf(v2("task-root")), signer: "human", verifyAt: "2025-12-31T23:59:00.000Z" },
    { name: "grantee-mismatch", token: tokenOf(v2("task-root")), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z", expectedGrantee: keys.vendor.did },
    { name: "unsupported-version", token: tokenOf({ ...v2("task-root"), v: 3 }), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
    { name: "bad-shape-onBehalfOf", token: tokenOf({ ...v2("task-root"), mandate: { ...signed["task-root"].mandate, taskConstraints: { onBehalfOf: "" } } }), signer: "human", verifyAt: "2027-01-01T00:00:00.000Z" },
  ];
  const tokens = [];
  for (const c of tokenCases) {
    const r = await verifyTaskMandate(c.token, keys[c.signer].pub, c.expectedGrantee, { now: Date.parse(c.verifyAt) });
    tokens.push({ ...c, expected: { valid: r.valid, reason: r.reason ?? null } });
  }

  const narrowingPairs: [string, ArohaTaskMandateBody, Partial<ArohaTaskMandateBody>][] = [
    ["child-narrows-root", signed["task-root"].mandate, signed["task-child"].mandate],
    ["widened-child", signed["task-root"].mandate, signed["task-child-widened"].mandate],
    ["drops-room", signed["task-root"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, roomId: undefined } }],
    ["changes-onBehalfOf", signed["task-root"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, onBehalfOf: "did:aroha:mallory" } }],
    ["adds-capability", signed["task-root"].mandate, { ...signed["task-child"].mandate, allowed: ["web-search", "delete-files"] }],
    ["drops-blocked", signed["task-root"].mandate, { ...signed["task-child"].mandate, blocked: [] }],
    ["write-only-to-read", signed["task-root"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, dataAccess: { "files:/drafts": "read" } } }],
    ["omits-compute-field", signed["task-root"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, computeLimit: { llmTokens: 1 } } }],
    ["outlives-parent", signed["task-root"].mandate, { ...signed["task-child"].mandate, expiresAt: "2099-01-01T00:00:00.001Z" }],
    ["hybrid-spend-widened", signed["hybrid-root"].mandate, { ...signed["hybrid-root"].mandate, spendingConstraints: { spendLimitUsd: 500, allowedMerchants: ["did:aroha:airline"] } }],
    ["hybrid-invariant-param-changed", signed["hybrid-root"].mandate, { ...signed["hybrid-root"].mandate, invariants: { payee: ["did:aroha:airline"], parameters: { destination: "JFK", seats: 1, refundable: "true" } } }],
    ["hybrid-same", signed["hybrid-root"].mandate, signed["hybrid-root"].mandate],
    ["empty-dataAccess-dropped", signed["task-root-deny-data"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, dataAccess: undefined } }],
    ["empty-dataAccess-kept", signed["task-root-deny-data"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, dataAccess: {} } }],
    ["empty-dataAccess-widened", signed["task-root-deny-data"].mandate, { ...signed["task-child"].mandate, taskConstraints: { ...signed["task-child"].mandate.taskConstraints, dataAccess: { email: "read" } } }],
    ["empty-payee-dropped", signed["hybrid-root-no-payees"].mandate, { ...signed["hybrid-root-no-payees"].mandate, invariants: { parameters: { destination: "JFK", seats: 1, refundable: true } } }],
    ["empty-payee-widened", signed["hybrid-root-no-payees"].mandate, { ...signed["hybrid-root-no-payees"].mandate, invariants: { payee: ["did:aroha:airline"], parameters: { destination: "JFK", seats: 1, refundable: true } } }],
  ];
  const narrowing = narrowingPairs.map(([name, parent, c]) => {
    const childBody = JSON.parse(JSON.stringify(c));
    return { name, parent, child: childBody, expectedReason: checkTaskNarrowing(parent, childBody) };
  });

  const room = { roomId: ROOM, onBehalfOf: GUEST };
  const actionCases: [string, string, TaskActionRequest][] = [
    ["allowed-search", "task-root", { requestedCapability: "web-search", ...room, capabilityReversibility: "full" }],
    ["no-room", "task-root", { requestedCapability: "web-search", onBehalfOf: GUEST }],
    ["other-room", "task-root", { requestedCapability: "web-search", roomId: "room-other", onBehalfOf: GUEST }],
    ["other-member", "task-root", { requestedCapability: "web-search", roomId: ROOM, onBehalfOf: "did:aroha:mallory" }],
    ["not-allowed", "task-root", { requestedCapability: "post-social", ...room }],
    ["blocked", "task-root", { ...room, requestedCapability: "delete-files" }],
    ["gate-unapproved", "task-root", { requestedCapability: "send-email", ...room }],
    ["gate-approved", "task-root", { requestedCapability: "send-email", ...room, humanApproved: true, currentActionCounts: { "send-email": 2 } }],
    ["over-action-limit", "task-root", { requestedCapability: "send-email", ...room, humanApproved: true, currentActionCounts: { "send-email": 3 } }],
    ["over-llm-tokens", "task-root", { requestedCapability: "web-search", ...room, currentCompute: { llmTokens: 50000 } }],
    ["over-wall-clock", "task-root", { requestedCapability: "web-search", ...room, currentCompute: { llmTokens: 1, webRequests: 1, wallClockMs: 600000 } }],
    ["data-read-ok", "task-root", { requestedCapability: "read-calendar", ...room, dataAccess: { calendar: "read", email: "read-write" } }],
    ["data-write-on-read", "task-root", { requestedCapability: "read-calendar", ...room, dataAccess: { calendar: "write" } }],
    ["data-read-on-write-only", "task-root", { requestedCapability: "read-calendar", ...room, dataAccess: { "files:/drafts": "read" } }],
    ["data-unlisted-resource", "task-root", { requestedCapability: "read-calendar", ...room, dataAccess: { "customer-db": "read" } }],
    ["empty-dataAccess-denies-read", "task-root-deny-data", { requestedCapability: "read-calendar", ...room, dataAccess: { calendar: "read" } }],
    ["empty-dataAccess-no-data-requested", "task-root-deny-data", { requestedCapability: "read-calendar", ...room }],
    ["reversible-only-default-irreversible", "hybrid-root", { requestedCapability: "book-flight" }],
    ["reversible-only-semi", "hybrid-root", { requestedCapability: "book-flight", capabilityReversibility: "semi" }],
  ];
  const actions = actionCases.map(([name, mandateName, request]) => {
    const v = checkTaskConstraints(signed[mandateName].mandate, request);
    return { name, mandate: mandateName, request, expected: v ? { code: v.code, message: v.message } : null };
  });

  const out = {
    description:
      "Aroha task-mandate v2 conformance vectors. A v2 signature is Ed25519(privateKey, UTF-8(JCS({\"mandate\": <body>, " +
      "\"purpose\": \"aroha.task-mandate/v2\", \"v\": 2}))), base64url without padding; a token is " +
      "base64url(JSON({v: 2, mandate, signature})). v1 tokens omit v and sign sortKeys/JSON.stringify of the body. " +
      "tokens[].expected is verifyTaskMandate(token, keys[signer].publicKey, expectedGrantee, {now: verifyAt}); " +
      "narrowing[].expectedReason is checkTaskNarrowing(parent, child); actions[].expected is checkTaskConstraints(mandates[mandate], request) " +
      "(null = permitted). Keys are the RFC 8032 §7.1 test keys — never use them for anything real.",
    generatedBy: "packages/aroha-credentials/scripts/gen-task-test-vectors.ts",
    keys: Object.fromEntries(
      (Object.keys(keys) as KeyName[]).map((n) => [n, { privateKeyHex: hex(keys[n].priv), publicKeyHex: hex(keys[n].pub), did: keys[n].did }])
    ),
    mandates,
    tokens,
    narrowing,
    actions,
  };

  const target = fileURLToPath(new URL("../test-vectors/task-mandate-v2-cases.json", import.meta.url));
  writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${target}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
