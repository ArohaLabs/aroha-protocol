// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Task-mandate interop between the Java SDK and the TypeScript reference
 * (@aroha-sdk/credentials). Needs a BUILT packages/aroha-credentials (dist/),
 * found at $AROHA_CREDENTIALS_DIR or ../../../packages/aroha-credentials.
 *
 *   node task-mandate-interop.mjs gen  > ../src/test/resources/task-mandate-ts-vectors.json
 *       TypeScript issues and attenuates task mandates, builds tampered /
 *       widened / over-limit cases, and records its own verdicts (reason
 *       strings and violation codes) for TaskMandateTsInteropTest to match.
 *
 *   node task-mandate-interop.mjs verify <java-tokens.json>
 *       TypeScript verifies tokens the Java SDK issued (written by
 *       JavaTokensVerifiedByTypeScriptTest) and prints its verdicts as JSON.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const credDir = process.env.AROHA_CREDENTIALS_DIR ?? resolve(here, "../../../packages/aroha-credentials");
const C = await import(pathToFileURL(join(credDir, "dist", "index.js")).href);

/** @noble/ed25519 as the credentials package resolves it (workspace-hoisted). */
async function loadEd() {
  for (let d = credDir; ; d = dirname(d)) {
    const f = join(d, "node_modules", "@noble", "ed25519", "index.js");
    if (existsSync(f)) return import(pathToFileURL(f).href);
    if (dirname(d) === d) throw new Error("@noble/ed25519 not found above " + credDir);
  }
}
const ed = await loadEd();
const pubOf = (seedBytes) => ed.getPublicKeyAsync(seedBytes);

const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const seed = (b) => new Uint8Array(32).fill(b);
const b64urlJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const decode = (t) => JSON.parse(Buffer.from(t, "base64url").toString("utf8"));

/** checkTaskConstraints as data: null, or { code, message }. */
function verdict(mandate, request) {
  const v = C.checkTaskConstraints(mandate, request);
  return v === null ? null : { code: v.code, message: v.message };
}

async function verifyAt(token, pub, grantee, now) {
  const r = await C.verifyTaskMandate(token, pub, grantee, { now });
  return r.valid ? { valid: true } : { valid: false, reason: r.reason };
}

// ─── gen ──────────────────────────────────────────────────────────────────────

async function gen() {
  // Deterministic keys (seed bytes); DIDs are opaque to task-mandate checks.
  const keys = { user: seed(1), agentA: seed(2), agentB: seed(3) };
  const USER = "did:aroha:user-alice";
  const GUEST = "did:aroha:guest-ben";
  const A = "did:aroha:agent-a";
  const B = "did:aroha:agent-b";

  const rootConstraints = {
    actionLimits: { "send-email": 3, "draft-email": 10 },
    computeLimit: { llmTokens: 10000, webRequests: 50, executionTimeMs: 600000, cpuSeconds: 1.5 },
    dataAccess: { calendar: "read", email: "read-write", drafts: "write" },
    outputHandling: "user-only",
    humanGates: ["send-email"],
    checkpointIntervalMs: 60000,
    maxDelegationDepth: 2,
    onBehalfOf: GUEST,
    roomId: "room-01J9ZK3Q7V",
  };
  const rootAllowed = ["search", "draft-email", "send-email", "read-calendar", "résumé-review"];
  const root = await C.issueTaskMandate(USER, A, rootAllowed, rootConstraints, keys.user, 3_600_000, {
    blocked: ["delete-email"],
  });

  const child = await C.attenuateTaskMandate(
    root, B, ["search", "send-email"],
    {
      actionLimits: { "send-email": 1 },
      computeLimit: { llmTokens: 5000, webRequests: 10, executionTimeMs: 300000, cpuSeconds: 1 },
      dataAccess: { email: "read" },
      outputHandling: "internal-only",
      humanGates: ["send-email"],
      checkpointIntervalMs: 30000,
    },
    keys.agentA, 1_800_000,
  );

  const hybrid = await C.issueTaskMandate(USER, A, ["book-flight", "search"], { reversibleOnly: true }, keys.user, 3_600_000, {
    blocked: ["search"],
    spendingConstraints: { spendLimitUsd: 500, sessionLimitUsd: 200, currency: "USD", merchantCategory: "travel" },
    invariants: {
      payee: ["did:aroha:airline"],
      maxAmount: { amount: 450, currency: "USD" },
      parameters: { destination: "JFK", seats: 2, refundable: true },
      expiry: new Date(Date.now() + 1_800_000).toISOString(),
    },
  });

  const now = (m) => Date.parse(m.mandate.issuedAt) + 1000;
  const tokens = {};
  for (const [name, m, key, grantee] of [["root", root, keys.user, A], ["child", child, keys.agentA, B], ["hybrid", hybrid, keys.user, A]]) {
    tokens[name] = {
      token: m.token,
      mandate: m.mandate,
      signature: m.signature,
      signingPayload: C.taskMandateSigningPayloadV2(m.mandate),
      grantorSeed: hex(key),
      grantee,
      verifyAt: now(m),
      expected: await verifyAt(m.token, await pubOf(key), grantee, now(m)),
    };
  }

  // ── rejected tokens: tampered body, tampered signature, wrong key, expired, bad version
  const raw = decode(root.token);
  const tamperedBody = b64urlJson({ ...raw, mandate: { ...raw.mandate, allowed: [...raw.mandate.allowed, "delete-email"] } });
  const tamperedLimit = b64urlJson({
    ...raw,
    mandate: { ...raw.mandate, taskConstraints: { ...raw.mandate.taskConstraints, actionLimits: { "send-email": 300, "draft-email": 10 } } },
  });
  const sig = Buffer.from(raw.signature, "base64url");
  sig[0] ^= 1;
  const tamperedSig = b64urlJson({ ...raw, signature: sig.toString("base64url") });
  const asV1 = b64urlJson({ mandate: raw.mandate, signature: raw.signature });
  const badVersion = b64urlJson({ ...raw, v: 3 });
  const t0 = now(root);
  const rejected = [];
  const reject = async (name, token, seedHex, grantee, at) => {
    const pub = await pubOf(unhex(seedHex));
    rejected.push({ name, token, grantorSeed: seedHex, grantee, verifyAt: at, expected: await verifyAt(token, pub, grantee, at) });
  };
  await reject("tampered-allowed", tamperedBody, hex(keys.user), A, t0);
  await reject("tampered-action-limit", tamperedLimit, hex(keys.user), A, t0);
  await reject("tampered-signature", tamperedSig, hex(keys.user), A, t0);
  await reject("v2-signature-presented-as-v1", asV1, hex(keys.user), A, t0);
  await reject("unsupported-version", badVersion, hex(keys.user), A, t0);
  await reject("wrong-grantor-key", root.token, hex(keys.agentA), A, t0);
  await reject("wrong-grantee", root.token, hex(keys.user), B, t0);
  await reject("expired", root.token, hex(keys.user), A, Date.parse(root.mandate.expiresAt) + 1);
  await reject("issued-in-the-future", root.token, hex(keys.user), A, Date.parse(root.mandate.issuedAt) - 60_000);

  // ── widened children: correctly signed by agent A, but wider than root.
  // TypeScript's attenuateTaskMandate refuses all of these; issueTaskMandate
  // signs them anyway, which is what a dishonest delegating agent would do.
  const rc = root.mandate.taskConstraints;
  const childBase = {
    actionLimits: { "send-email": 1 },
    computeLimit: { llmTokens: 5000, webRequests: 10, executionTimeMs: 300000, cpuSeconds: 1 },
    dataAccess: { email: "read" },
    outputHandling: "internal-only",
    humanGates: ["send-email"],
    checkpointIntervalMs: 30000,
    onBehalfOf: rc.onBehalfOf,
    roomId: rc.roomId,
  };
  const widen = [
    ["extra-capability", ["search", "send-email", "delete-email"], childBase, {}],
    ["action-limit-raised", ["search", "send-email"], { ...childBase, actionLimits: { "send-email": 5 } }, {}],
    ["action-limit-omitted", ["search", "send-email"], { ...childBase, actionLimits: {} }, {}],
    ["compute-limit-omitted", ["search", "send-email"], { ...childBase, computeLimit: undefined }, {}],
    ["cpu-seconds-raised", ["search", "send-email"], { ...childBase, computeLimit: { ...childBase.computeLimit, cpuSeconds: 2.5 } }, {}],
    ["data-access-read-to-read-write", ["search", "send-email"], { ...childBase, dataAccess: { calendar: "read-write" } }, {}],
    ["data-access-write-only-to-read", ["search", "send-email"], { ...childBase, dataAccess: { drafts: "read" } }, {}],
    ["data-access-omitted", ["search", "send-email"], { ...childBase, dataAccess: undefined }, {}],
    ["room-dropped", ["search", "send-email"], { ...childBase, roomId: undefined }, {}],
    ["on-behalf-of-changed", ["search", "send-email"], { ...childBase, onBehalfOf: USER }, {}],
    ["human-gate-dropped", ["search", "send-email"], { ...childBase, humanGates: [] }, {}],
    ["output-handling-widened", ["search", "send-email"], { ...childBase, outputHandling: "shareable" }, {}],
    ["checkpoint-interval-longer", ["search", "send-email"], { ...childBase, checkpointIntervalMs: 120000 }, {}],
    ["blocked-dropped", ["search", "send-email"], childBase, { noBlocked: true }],
    ["expiry-beyond-parent", ["search", "send-email"], childBase, { expiresAtMs: Date.parse(root.mandate.expiresAt) + 60_000 }],
  ];
  const widened = [];
  for (const [name, allowed, tc, opt] of widen) {
    const c = await C.issueTaskMandate(A, B, allowed, JSON.parse(JSON.stringify(tc)), keys.agentA, 600_000, {
      blocked: opt.noBlocked ? undefined : ["delete-email"],
      parentMandateId: root.mandate.mandateId,
      tier: "cart",
      expiresAtMs: opt.expiresAtMs,
    });
    widened.push({ name, token: c.token, reason: C.checkTaskNarrowing(root.mandate, c.mandate) });
  }
  // Hybrid: spending and invariants narrowing.
  const hc = hybrid.mandate;
  const hWiden = [
    ["spend-limit-raised", { ...hc.spendingConstraints, spendLimitUsd: 600 }, hc.invariants],
    ["invariant-parameter-changed", hc.spendingConstraints, { ...hc.invariants, parameters: { ...hc.invariants.parameters, destination: "LAX" } }],
    ["invariant-payee-added", hc.spendingConstraints, { ...hc.invariants, payee: ["did:aroha:airline", "did:aroha:mallory"] }],
    ["invariants-dropped", hc.spendingConstraints, undefined],
    ["reversible-only-dropped", hc.spendingConstraints, hc.invariants, {}],
  ];
  for (const [name, sc, inv, tcOverride] of hWiden) {
    const c = await C.issueTaskMandate(A, B, ["book-flight"], tcOverride ?? { reversibleOnly: true }, keys.agentA, 600_000, {
      blocked: ["search"], spendingConstraints: sc, invariants: inv, parentMandateId: hc.mandateId, tier: "cart",
    });
    widened.push({ name: `hybrid-${name}`, parent: "hybrid", token: c.token, reason: C.checkTaskNarrowing(hc, c.mandate) });
  }
  // The honest child narrows: TS says null.
  widened.push({ name: "honest-child", token: child.token, reason: C.checkTaskNarrowing(root.mandate, child.mandate) });

  // ── requests against the verified root / hybrid / child
  const inRoom = { roomId: rc.roomId, onBehalfOf: rc.onBehalfOf };
  const reqs = [
    ["root", "search-in-room", { requestedCapability: "search", ...inRoom }],
    ["root", "unicode-capability", { requestedCapability: "résumé-review", ...inRoom }],
    ["root", "other-room", { requestedCapability: "search", roomId: "room-other", onBehalfOf: rc.onBehalfOf }],
    ["root", "no-room", { requestedCapability: "search" }],
    ["root", "other-member", { requestedCapability: "search", roomId: rc.roomId, onBehalfOf: USER }],
    ["root", "not-allowed", { requestedCapability: "book-flight", ...inRoom }],
    ["root", "blocked", { requestedCapability: "delete-email", ...inRoom }],
    ["root", "human-gate-unapproved", { requestedCapability: "send-email", ...inRoom }],
    ["root", "human-gate-approved", { requestedCapability: "send-email", humanApproved: true, ...inRoom }],
    ["root", "action-limit-reached", { requestedCapability: "send-email", humanApproved: true, currentActionCounts: { "send-email": 3 }, ...inRoom }],
    ["root", "action-limit-below", { requestedCapability: "send-email", humanApproved: true, currentActionCounts: { "send-email": 2 }, ...inRoom }],
    ["root", "llm-tokens-exhausted", { requestedCapability: "search", currentCompute: { llmTokens: 10000 }, ...inRoom }],
    ["root", "web-requests-exhausted", { requestedCapability: "search", currentCompute: { llmTokens: 1, webRequests: 50 }, ...inRoom }],
    ["root", "wall-clock-exhausted", { requestedCapability: "search", currentCompute: { wallClockMs: 600000 }, ...inRoom }],
    ["root", "compute-within", { requestedCapability: "search", currentCompute: { llmTokens: 9999, webRequests: 49, wallClockMs: 1 }, ...inRoom }],
    ["root", "data-read-email", { requestedCapability: "draft-email", dataAccess: { email: "read" }, ...inRoom }],
    ["root", "data-write-calendar", { requestedCapability: "read-calendar", dataAccess: { calendar: "write" }, ...inRoom }],
    ["root", "data-read-write-only", { requestedCapability: "draft-email", dataAccess: { drafts: "read" }, ...inRoom }],
    ["root", "data-write-write-only", { requestedCapability: "draft-email", dataAccess: { drafts: "write" }, ...inRoom }],
    ["root", "data-unknown-resource", { requestedCapability: "draft-email", dataAccess: { contacts: "read" }, ...inRoom }],
    ["hybrid", "irreversible-default", { requestedCapability: "book-flight" }],
    ["hybrid", "irreversible-declared", { requestedCapability: "book-flight", capabilityReversibility: "irreversible" }],
    ["hybrid", "blocked-overrides-allowed", { requestedCapability: "search", capabilityReversibility: "full" }],
    ["hybrid", "semi-reversible", { requestedCapability: "book-flight", capabilityReversibility: "semi" }],
    ["child", "child-limit-reached", { requestedCapability: "send-email", humanApproved: true, currentActionCounts: { "send-email": 1 }, ...inRoom }],
    ["child", "child-dropped-capability", { requestedCapability: "draft-email", ...inRoom }],
  ];
  const mandates = { root: root.mandate, hybrid: hybrid.mandate, child: child.mandate };
  const requests = reqs.map(([on, name, request]) => ({ on, name, request, expected: verdict(mandates[on], request) }));

  process.stdout.write(JSON.stringify({
    comment: "Generated by sdks/java/scripts/task-mandate-interop.mjs gen from @aroha-sdk/credentials (TypeScript). Do not edit.",
    generatedAt: new Date().toISOString(),
    keysAreSeeds: "grantorSeed is the 32-byte Ed25519 seed, hex",
    tokens, rejected, widened, requests,
  }, null, 2) + "\n");
}

// ─── verify ───────────────────────────────────────────────────────────────────

async function verify(file) {
  const J = JSON.parse(readFileSync(file, "utf8"));
  const out = { tokens: {}, rejected: [], widened: [], requests: [], attenuation: [] };
  for (const [name, t] of Object.entries(J.tokens)) {
    const r = await C.verifyTaskMandate(t.token, unhex(t.grantorPublicKey), t.grantee, { now: t.verifyAt });
    out.tokens[name] = {
      valid: r.valid,
      reason: r.reason ?? null,
      signingPayload: r.valid ? C.taskMandateSigningPayloadV2(r.mandate) : null,
    };
  }
  for (const t of J.rejected) {
    const r = await C.verifyTaskMandate(t.token, unhex(t.grantorPublicKey), t.grantee, { now: t.verifyAt });
    out.rejected.push({ name: t.name, valid: r.valid, reason: r.reason ?? null });
  }
  for (const w of J.widened) {
    out.widened.push({ name: w.name, reason: C.checkTaskNarrowing(decode(w.parentToken).mandate, decode(w.token).mandate) });
  }
  for (const q of J.requests) {
    const m = decode(J.tokens[q.on].token).mandate;
    out.requests.push({ name: q.name, verdict: verdict(m, q.request) });
  }
  // TypeScript attenuating a Java-issued parent, and its child verifying.
  for (const a of J.attenuation ?? []) {
    const parent = { ...decode(J.tokens[a.parent].token), token: J.tokens[a.parent].token, v: 2 };
    try {
      const c = await C.attenuateTaskMandate(parent, a.grantee, a.allowed, a.taskConstraints, unhex(a.grantorSeed), 600_000);
      const r = await C.verifyTaskMandate(c.token, unhex(a.grantorPublicKey), a.grantee);
      out.attenuation.push({ name: a.name, ok: true, token: c.token, valid: r.valid, reason: r.reason ?? null });
    } catch (e) {
      out.attenuation.push({ name: a.name, ok: false, error: String(e.message) });
    }
  }
  process.stdout.write(JSON.stringify(out));
}

const [mode, arg] = process.argv.slice(2);
if (mode === "gen") await gen();
else if (mode === "verify") await verify(arg);
else {
  console.error("usage: node task-mandate-interop.mjs gen | verify <file>");
  process.exit(2);
}
