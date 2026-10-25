// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/task-mandate-v2.json.
 *
 *   npx tsx scripts/gen-task-mandate-vectors.ts
 *
 * The cross-SDK contract for task mandates (issueTaskMandate /
 * verifyTaskMandate / checkTaskNarrowing / checkTaskConstraints). A Python,
 * Go or Java implementation passes when it reproduces every
 * `expectedSigningPayload` and `expectedSignature` byte for byte and reaches
 * the same verdict — and the same reason or violation code — on every token,
 * narrowing pair and request below.
 *
 * Every verdict here is computed by the TypeScript reference functions, not
 * written by hand. Keys are the RFC 8032 §7.1 test keys, ids and timestamps
 * are fixed, and Ed25519 is deterministic, so regenerating must produce an
 * identical file. If it does not, the canonical form or a rule changed —
 * which is a protocol break, not a refresh.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaTaskMandateBody } from "@aroha-sdk/core";
import { canonicalizeJcs } from "../src/jcs.js";
import {
  checkTaskConstraints,
  checkTaskNarrowing,
  taskMandateSigningPayloadV2,
  verifyTaskMandate,
  type TaskActionRequest,
  type TaskNarrowingChild,
} from "../src/mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

// RFC 8032 §7.1 TEST 1, 2 and 3 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  provider: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

const ISSUED = "2026-10-01T09:00:00.000Z";
const EXPIRES = "2026-10-01T21:00:00.000Z";
const CHILD_EXPIRES = "2026-10-01T15:00:00.000Z";
const VERIFY_AT = Date.parse("2026-10-01T10:00:00.000Z");
const AFTER_EXPIRY = Date.parse("2026-10-01T21:00:00.001Z");
const BEFORE_ISSUE = Date.parse("2026-10-01T08:59:00.000Z"); // 60 s early: beyond the 30 s tolerance
const ROOM = "room-01JA0TASK";

const sortKeys = (o: unknown): unknown =>
  Array.isArray(o)
    ? o.map(sortKeys)
    : o !== null && typeof o === "object"
      ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys((o as Record<string, unknown>)[k])]))
      : o;

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }
  const { human, agent, provider } = keys;

  // ── Mandate bodies ─────────────────────────────────────────────────────────
  const root: ArohaTaskMandateBody = {
    mandateType: "task",
    mandateTier: "intent",
    allowed: ["search", "draft-email", "send-email", "read-calendar", "export-data"],
    blocked: ["export-data"],
    taskConstraints: {
      actionLimits: { "send-email": 3, search: 50 },
      computeLimit: { llmTokens: 100000, webRequests: 200, executionTimeMs: 600000 },
      dataAccess: { calendar: "read", email: "read-write", drafts: "write" },
      outputHandling: "user-only",
      humanGates: ["send-email"],
      checkpointIntervalMs: 60000,
      requireSandbox: true,
      maxDelegationDepth: 2,
    },
    grantee: agent.did,
    grantor: human.did,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    parentMandateId: null,
    mandateId: "task-root-0001",
  };
  const child: ArohaTaskMandateBody = {
    mandateType: "task",
    mandateTier: "cart",
    allowed: ["search", "send-email"],
    blocked: ["export-data"],
    taskConstraints: {
      actionLimits: { "send-email": 1, search: 10 },
      computeLimit: { llmTokens: 5000, webRequests: 20, executionTimeMs: 60000 },
      dataAccess: { email: "write" },
      outputHandling: "internal-only",
      humanGates: ["send-email"],
      checkpointIntervalMs: 30000,
      requireSandbox: true,
      maxDelegationDepth: 1,
    },
    grantee: provider.did,
    grantor: agent.did,
    issuedAt: ISSUED,
    expiresAt: CHILD_EXPIRES,
    parentMandateId: "task-root-0001",
    mandateId: "task-child-0002",
  };
  const guest: ArohaTaskMandateBody = {
    mandateType: "task",
    mandateTier: "intent",
    allowed: ["search", "draft-email"],
    taskConstraints: { onBehalfOf: provider.did, roomId: ROOM, reversibleOnly: true, humanGates: ["draft-email"] },
    grantee: agent.did,
    grantor: human.did,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    parentMandateId: null,
    mandateId: "task-guest-0003",
  };
  const hybrid: ArohaTaskMandateBody = {
    mandateType: "hybrid",
    mandateTier: "intent",
    allowed: ["book-flight"],
    taskConstraints: { actionLimits: { "book-flight": 1 } },
    spendingConstraints: { spendLimitUsd: 500, currency: "USD", allowedMerchants: ["did:aroha:airline-a"] },
    invariants: { payee: ["did:aroha:airline-a"], parameters: { destination: "JFK", passengers: 1 }, maxAmount: { amount: 450, currency: "USD" } },
    grantee: agent.did,
    grantor: human.did,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    parentMandateId: null,
    mandateId: "task-hybrid-0004",
  };
  const bodies = { root, child, guest, hybrid } as const;
  type BodyName = keyof typeof bodies;
  const signerOf: Record<BodyName, KeyName> = { root: "human", child: "agent", guest: "human", hybrid: "human" };

  const signV2 = async (m: ArohaTaskMandateBody, k: KeyName) =>
    b64u(await ed.signAsync(new TextEncoder().encode(taskMandateSigningPayloadV2(m)), keys[k].priv));
  const tokenOf = (o: Record<string, unknown>) => b64u(JSON.stringify(o));

  const mandates = [];
  const tokenByName: Record<string, string> = {};
  for (const name of Object.keys(bodies) as BodyName[]) {
    const m = bodies[name];
    const signature = await signV2(m, signerOf[name]);
    const token = tokenOf({ v: 2, mandate: m, signature });
    tokenByName[name] = token;
    mandates.push({
      name,
      signer: signerOf[name],
      mandate: m,
      expectedSigningPayload: taskMandateSigningPayloadV2(m),
      expectedSignature: signature,
      token,
    });
  }

  // ── Tokens and verdicts ────────────────────────────────────────────────────
  const rootSig = await signV2(root, "human");
  const legacySig = b64u(await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(root))), human.priv));
  const spendingStyleSig = b64u(await ed.signAsync(new TextEncoder().encode(canonicalizeJcs({ mandate: root, v: 2 })), human.priv));

  const tokenCases: { name: string; token: string; signer: KeyName; at: number; expectedGrantee?: string }[] = [
    { name: "root-valid", token: tokenByName.root, signer: "human", at: VERIFY_AT },
    { name: "child-valid", token: tokenByName.child, signer: "agent", at: VERIFY_AT },
    { name: "guest-valid", token: tokenByName.guest, signer: "human", at: VERIFY_AT },
    { name: "hybrid-valid", token: tokenByName.hybrid, signer: "human", at: VERIFY_AT },
    { name: "root-expected-grantee", token: tokenByName.root, signer: "human", at: VERIFY_AT, expectedGrantee: agent.did },
    { name: "legacy-v1", token: tokenOf({ mandate: root, signature: legacySig }), signer: "human", at: VERIFY_AT },
    {
      name: "tampered-allowed-widened",
      token: tokenOf({ v: 2, mandate: { ...root, allowed: [...root.allowed, "delete-account"] }, signature: rootSig }),
      signer: "human", at: VERIFY_AT,
    },
    {
      name: "tampered-action-limit-raised",
      token: tokenOf({ v: 2, mandate: { ...root, taskConstraints: { ...root.taskConstraints, actionLimits: { "send-email": 300, search: 50 } } }, signature: rootSig }),
      signer: "human", at: VERIFY_AT,
    },
    {
      name: "tampered-expiry-extended",
      token: tokenOf({ v: 2, mandate: { ...root, expiresAt: "2027-10-01T21:00:00.000Z" }, signature: rootSig }),
      signer: "human", at: VERIFY_AT,
    },
    { name: "wrong-key", token: tokenByName.root, signer: "agent", at: VERIFY_AT },
    { name: "expired", token: tokenByName.root, signer: "human", at: AFTER_EXPIRY },
    { name: "issued-in-future", token: tokenByName.root, signer: "human", at: BEFORE_ISSUE },
    { name: "grantee-mismatch", token: tokenByName.root, signer: "human", at: VERIFY_AT, expectedGrantee: provider.did },
    { name: "v2-signature-under-v1-marker", token: tokenOf({ mandate: root, signature: rootSig }), signer: "human", at: VERIFY_AT },
    { name: "v1-signature-under-v2-marker", token: tokenOf({ v: 2, mandate: root, signature: legacySig }), signer: "human", at: VERIFY_AT },
    { name: "spending-payload-replayed", token: tokenOf({ v: 2, mandate: root, signature: spendingStyleSig }), signer: "human", at: VERIFY_AT },
    { name: "unsupported-version", token: tokenOf({ v: 3, mandate: root, signature: rootSig }), signer: "human", at: VERIFY_AT },
    { name: "signature-missing", token: tokenOf({ v: 2, mandate: root }), signer: "human", at: VERIFY_AT },
    { name: "token-is-null", token: b64u("null"), signer: "human", at: VERIFY_AT },
    { name: "mandate-type-invalid", token: tokenOf({ v: 2, mandate: { ...root, mandateType: "spend" }, signature: rootSig }), signer: "human", at: VERIFY_AT },
    {
      name: "action-limit-not-a-number",
      token: tokenOf({ v: 2, mandate: { ...root, taskConstraints: { ...root.taskConstraints, actionLimits: { "send-email": "3" } } }, signature: rootSig }),
      signer: "human", at: VERIFY_AT,
    },
    {
      name: "data-access-level-invalid",
      token: tokenOf({ v: 2, mandate: { ...root, taskConstraints: { ...root.taskConstraints, dataAccess: { email: "admin" } } }, signature: rootSig }),
      signer: "human", at: VERIFY_AT,
    },
    { name: "hybrid-without-spending", token: tokenOf({ v: 2, mandate: { ...hybrid, spendingConstraints: undefined }, signature: rootSig }), signer: "human", at: VERIFY_AT },
  ];
  const tokens = [];
  for (const c of tokenCases) {
    const r = await verifyTaskMandate(c.token, keys[c.signer].pub, c.expectedGrantee, { now: c.at });
    tokens.push({
      name: c.name,
      token: c.token,
      signer: c.signer,
      now: new Date(c.at).toISOString(),
      ...(c.expectedGrantee ? { expectedGrantee: c.expectedGrantee } : {}),
      valid: r.valid,
      ...(r.valid ? {} : { reason: r.reason }),
    });
  }

  // ── Narrowing (the per-link rule a chain verifier applies) ─────────────────
  const tc = child.taskConstraints;
  const narrowingCases: { name: string; parent: BodyName; child: TaskNarrowingChild }[] = [
    { name: "child-narrows-root", parent: "root", child },
    { name: "equal-is-allowed", parent: "root", child: { ...root } },
    { name: "allowed-widened", parent: "root", child: { ...child, allowed: [...child.allowed, "post-social"] } },
    { name: "blocked-dropped", parent: "root", child: { ...child, blocked: [] } },
    { name: "action-limit-omitted", parent: "root", child: { ...child, taskConstraints: { ...tc, actionLimits: { search: 10 } } } },
    { name: "action-limit-raised", parent: "root", child: { ...child, taskConstraints: { ...tc, actionLimits: { "send-email": 4, search: 10 } } } },
    {
      name: "action-limit-for-dropped-capability-may-be-omitted", parent: "root",
      child: { ...child, allowed: ["search"], taskConstraints: { ...tc, actionLimits: { search: 10 } } },
    },
    { name: "compute-limit-omitted", parent: "root", child: { ...child, taskConstraints: { ...tc, computeLimit: undefined } } },
    { name: "compute-limit-raised", parent: "root", child: { ...child, taskConstraints: { ...tc, computeLimit: { ...tc.computeLimit, webRequests: 201 } } } },
    { name: "data-access-omitted", parent: "root", child: { ...child, taskConstraints: { ...tc, dataAccess: undefined } } },
    { name: "data-access-read-to-read-write", parent: "root", child: { ...child, taskConstraints: { ...tc, dataAccess: { calendar: "read-write" } } } },
    { name: "data-access-write-only-to-read", parent: "root", child: { ...child, taskConstraints: { ...tc, dataAccess: { drafts: "read" } } } },
    { name: "data-access-new-resource", parent: "root", child: { ...child, taskConstraints: { ...tc, dataAccess: { contacts: "read" } } } },
    { name: "human-gate-dropped", parent: "root", child: { ...child, taskConstraints: { ...tc, humanGates: [] } } },
    { name: "sandbox-dropped", parent: "root", child: { ...child, taskConstraints: { ...tc, requireSandbox: false } } },
    { name: "output-handling-widened", parent: "root", child: { ...child, taskConstraints: { ...tc, outputHandling: "shareable" } } },
    { name: "output-handling-omitted", parent: "root", child: { ...child, taskConstraints: { ...tc, outputHandling: undefined } } },
    { name: "checkpoint-interval-longer", parent: "root", child: { ...child, taskConstraints: { ...tc, checkpointIntervalMs: 120000 } } },
    { name: "expiry-beyond-parent", parent: "root", child: { ...child, expiresAt: "2026-10-02T00:00:00.000Z" } },
    {
      name: "guest-child-keeps-binding", parent: "guest",
      child: { allowed: ["search"], taskConstraints: { onBehalfOf: provider.did, roomId: ROOM, reversibleOnly: true }, expiresAt: EXPIRES },
    },
    {
      name: "guest-room-dropped", parent: "guest",
      child: { allowed: ["search"], taskConstraints: { onBehalfOf: provider.did, reversibleOnly: true } },
    },
    {
      name: "guest-on-behalf-of-changed", parent: "guest",
      child: { allowed: ["search"], taskConstraints: { onBehalfOf: human.did, roomId: ROOM, reversibleOnly: true } },
    },
    {
      name: "guest-reversible-only-dropped", parent: "guest",
      child: { allowed: ["search"], taskConstraints: { onBehalfOf: provider.did, roomId: ROOM } },
    },
    {
      name: "hybrid-narrows", parent: "hybrid",
      child: {
        allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } },
        spendingConstraints: { spendLimitUsd: 450, currency: "USD", allowedMerchants: ["did:aroha:airline-a"] },
        invariants: { payee: ["did:aroha:airline-a"], parameters: { destination: "JFK", passengers: 1 }, maxAmount: { amount: 400, currency: "USD" } },
      },
    },
    {
      name: "hybrid-spend-widened", parent: "hybrid",
      child: {
        allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } },
        spendingConstraints: { spendLimitUsd: 900, currency: "USD", allowedMerchants: ["did:aroha:airline-a"] },
        invariants: hybrid.invariants,
      },
    },
    {
      name: "hybrid-spending-dropped", parent: "hybrid",
      child: { allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } }, invariants: hybrid.invariants },
    },
    {
      name: "hybrid-invariants-dropped", parent: "hybrid",
      child: { allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } }, spendingConstraints: hybrid.spendingConstraints },
    },
    {
      name: "hybrid-parameter-changed", parent: "hybrid",
      child: {
        allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } }, spendingConstraints: hybrid.spendingConstraints,
        invariants: { ...hybrid.invariants, parameters: { destination: "LGA", passengers: 1 } },
      },
    },
    {
      name: "hybrid-max-amount-raised", parent: "hybrid",
      child: {
        allowed: ["book-flight"], taskConstraints: { actionLimits: { "book-flight": 1 } }, spendingConstraints: hybrid.spendingConstraints,
        invariants: { ...hybrid.invariants, maxAmount: { amount: 451, currency: "USD" } },
      },
    },
  ];
  const narrowing = narrowingCases.map((c) => {
    const reason = checkTaskNarrowing(bodies[c.parent], c.child);
    return { name: c.name, parent: c.parent, child: JSON.parse(JSON.stringify(c.child)), valid: reason === null, ...(reason ? { reason } : {}) };
  });

  // ── Requests against a verified mandate ────────────────────────────────────
  const requestCases: { name: string; mandate: BodyName; request: TaskActionRequest }[] = [
    { name: "search-within-limits", mandate: "child", request: { requestedCapability: "search", currentActionCounts: { search: 9 }, currentCompute: { llmTokens: 4999 } } },
    { name: "action-limit-reached", mandate: "child", request: { requestedCapability: "search", currentActionCounts: { search: 10 } } },
    { name: "send-email-needs-human", mandate: "child", request: { requestedCapability: "send-email" } },
    { name: "send-email-approved", mandate: "child", request: { requestedCapability: "send-email", humanApproved: true, dataAccess: { email: "write" } } },
    { name: "send-email-over-limit", mandate: "child", request: { requestedCapability: "send-email", humanApproved: true, currentActionCounts: { "send-email": 1 } } },
    { name: "capability-not-allowed", mandate: "child", request: { requestedCapability: "draft-email" } },
    { name: "capability-blocked", mandate: "root", request: { requestedCapability: "export-data" } },
    { name: "llm-budget-exhausted", mandate: "child", request: { requestedCapability: "search", currentCompute: { llmTokens: 5000 } } },
    { name: "web-budget-exhausted", mandate: "child", request: { requestedCapability: "search", currentCompute: { webRequests: 20 } } },
    { name: "time-budget-exhausted", mandate: "child", request: { requestedCapability: "search", currentCompute: { wallClockMs: 60000 } } },
    { name: "data-read-on-write-only-grant", mandate: "child", request: { requestedCapability: "search", dataAccess: { email: "read" } } },
    { name: "data-on-unlisted-resource", mandate: "child", request: { requestedCapability: "search", dataAccess: { calendar: "read" } } },
    { name: "data-read-granted", mandate: "root", request: { requestedCapability: "read-calendar", dataAccess: { calendar: "read" } } },
    {
      name: "guest-request-in-room", mandate: "guest",
      request: { requestedCapability: "search", capabilityReversibility: "full", roomId: ROOM, onBehalfOf: provider.did },
    },
    {
      name: "guest-request-other-room", mandate: "guest",
      request: { requestedCapability: "search", capabilityReversibility: "full", roomId: "room-other", onBehalfOf: provider.did },
    },
    { name: "guest-request-no-room", mandate: "guest", request: { requestedCapability: "search", capabilityReversibility: "full", onBehalfOf: provider.did } },
    {
      name: "guest-request-other-member", mandate: "guest",
      request: { requestedCapability: "search", capabilityReversibility: "full", roomId: ROOM, onBehalfOf: human.did },
    },
    {
      name: "guest-undeclared-reversibility", mandate: "guest",
      request: { requestedCapability: "search", roomId: ROOM, onBehalfOf: provider.did },
    },
    {
      name: "guest-semi-reversible-gated", mandate: "guest",
      request: { requestedCapability: "draft-email", capabilityReversibility: "semi", roomId: ROOM, onBehalfOf: provider.did },
    },
    { name: "hybrid-book-flight", mandate: "hybrid", request: { requestedCapability: "book-flight" } },
    { name: "hybrid-book-flight-twice", mandate: "hybrid", request: { requestedCapability: "book-flight", currentActionCounts: { "book-flight": 1 } } },
  ];
  const requests = requestCases.map((c) => {
    const v = checkTaskConstraints(bodies[c.mandate], c.request);
    return { name: c.name, mandate: c.mandate, request: c.request, allowed: v === null, ...(v ? { code: v.code, reason: v.message } : {}) };
  });

  const out = {
    description:
      "Aroha task-mandate v2 conformance vectors. Canonicalisation is RFC 8785 (JCS). A v2 task-mandate signature is " +
      "Ed25519(privateKey, UTF-8(JCS({\"mandate\": <body>, \"purpose\": \"aroha.task-mandate/v2\", \"v\": 2}))), base64url " +
      "without padding; a legacy v1 signature covers JSON.stringify(sortKeys(body)). Tokens are base64url(JSON({v: 2, mandate, " +
      "signature})) and carry one link. Every verdict, reason and code below was computed by the TypeScript reference " +
      "(verifyTaskMandate with options.now, checkTaskNarrowing, checkTaskConstraints). Public keys resolve from " +
      "content-addressed DIDs (did:aroha:z<base58btc(pubkey)>). Keys are the RFC 8032 section 7.1 test keys - never use them " +
      "for anything real.",
    generatedBy: "packages/aroha-credentials/scripts/gen-task-mandate-vectors.ts",
    keys: Object.fromEntries(
      (Object.keys(keys) as KeyName[]).map((k) => [k, { privateKeyHex: KEY_SEEDS[k], publicKeyHex: hex(keys[k].pub), did: keys[k].did }]),
    ),
    clockToleranceMs: 30000,
    mandates,
    tokens,
    narrowing,
    requests,
  };
  const path = fileURLToPath(new URL("../test-vectors/task-mandate-v2.json", import.meta.url));
  writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${path}: ${mandates.length} mandates, ${tokens.length} tokens, ${narrowing.length} narrowing, ${requests.length} requests`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
