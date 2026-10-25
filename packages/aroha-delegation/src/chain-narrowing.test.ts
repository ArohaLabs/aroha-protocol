// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifier-side task-mandate narrowing (H1). Each widening child below is
 * FORGED with issueTaskMandate — i.e. signed by the delegating agent without
 * running the issuer-side check — because that is exactly what a dishonest
 * intermediate would do. The chain verifier must refuse every one, and
 * accept an honest narrowing produced by attenuateTaskMandate.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import type { TaskConstraints, SpendingConstraints, MandateInvariants } from "@aroha-sdk/core";
import { issueTaskMandate, attenuateTaskMandate, type SignedTaskMandate } from "@aroha-sdk/credentials";
import {
  verifyTaskMandateChain, parseTaskMandateToken, staticResolver, TaskMandateTokenError,
  checkRootTrust, assertRootTrustConfigured,
} from "./chain.js";

const A = { did: "did:aroha:test:root" };
const B = { did: "did:aroha:test:orchestrator" };
const C = { did: "did:aroha:test:worker" };

let aKey: Uint8Array, bKey: Uint8Array, aPub: Uint8Array, bPub: Uint8Array;
let root: SignedTaskMandate;

const ROOT_ALLOWED = ["research", "web-search", "send-email"];
const ROOT_TC: TaskConstraints = {
  actionLimits: { "web-search": 10, "send-email": 2 },
  computeLimit: { llmTokens: 10_000, webRequests: 50 },
  dataAccess: { calendar: "read", drafts: "write" },
  reversibleOnly: true,
  requireSandbox: true,
  humanGates: ["send-email"],
  outputHandling: "user-only",
};
const ROOT_SPEND: SpendingConstraints = { spendLimitUsd: 50, sessionLimitUsd: 20 };
const ROOT_INV: MandateInvariants = { payee: ["did:aroha:test:airline"], maxAmount: { amount: 40, currency: "USD" } };

beforeAll(async () => {
  aKey = ed.utils.randomPrivateKey();
  bKey = ed.utils.randomPrivateKey();
  aPub = await ed.getPublicKeyAsync(aKey);
  bPub = await ed.getPublicKeyAsync(bKey);
  root = await issueTaskMandate(A.did, B.did, ROOT_ALLOWED, ROOT_TC, aKey, 3_600_000, {
    blocked: ["delete-account"],
    spendingConstraints: ROOT_SPEND,
    invariants: ROOT_INV,
  });
});

/** An honest child: every parent constraint restated, some narrowed. */
function honest(): { allowed: string[]; tc: TaskConstraints; blocked: string[]; spend: SpendingConstraints; inv: MandateInvariants } {
  return {
    allowed: ["research", "web-search", "send-email"],
    tc: {
      actionLimits: { "web-search": 5, "send-email": 1 },
      computeLimit: { llmTokens: 5_000, webRequests: 50 },
      dataAccess: { calendar: "read" },
      reversibleOnly: true,
      requireSandbox: true,
      humanGates: ["send-email"],
      outputHandling: "internal-only",
    },
    blocked: ["delete-account"],
    spend: { spendLimitUsd: 25, sessionLimitUsd: 10 },
    inv: { payee: ["did:aroha:test:airline"], maxAmount: { amount: 30, currency: "USD" } },
  };
}

async function forge(mutate: (c: ReturnType<typeof honest>) => void, expiresAtMs?: number) {
  const c = honest();
  mutate(c);
  return issueTaskMandate(B.did, C.did, c.allowed, c.tc, bKey, 60_000, {
    parentMandateId: root.mandate.mandateId,
    blocked: c.blocked,
    spendingConstraints: c.spend,
    invariants: c.inv,
    expiresAtMs,
  });
}

async function verify(child: SignedTaskMandate) {
  return verifyTaskMandateChain([root.token, child.token], aPub, {
    expectedGrantee: C.did,
    resolvePublicKey: staticResolver({ [B.did]: bPub }),
  });
}

describe("verifyTaskMandateChain — omission is widening", () => {
  it("accepts an honest child built by attenuateTaskMandate", async () => {
    const h = honest();
    const child = await attenuateTaskMandate(root, C.did, h.allowed, h.tc, bKey, 60_000, {
      spendingConstraints: h.spend,
      invariants: h.inv,
    });
    const r = await verify(child);
    expect(r.reason).toBeUndefined();
    expect(r.valid).toBe(true);
    // Blocked list was inherited even though the caller did not pass it.
    expect(r.mandate?.blocked).toContain("delete-account");
  });

  it("accepts an honest forged-style child that restates every constraint", async () => {
    expect((await verify(await forge(() => {}))).valid).toBe(true);
  });

  it("accepts a child that drops the limit for a capability it no longer allows", async () => {
    const child = await forge((c) => {
      c.allowed = ["research", "web-search"];
      delete c.tc.actionLimits!["send-email"];
      c.tc.humanGates = [];
    });
    expect((await verify(child)).valid).toBe(true);
  });

  const widenings: Array<[string, (c: ReturnType<typeof honest>) => void, RegExp]> = [
    ["omits actionLimits", (c) => { delete c.tc.actionLimits; }, /actionLimits/],
    ["raises an action limit", (c) => { c.tc.actionLimits!["web-search"] = 11; }, /actionLimits/],
    ["omits computeLimit", (c) => { delete c.tc.computeLimit; }, /computeLimit/],
    ["omits one compute dimension", (c) => { delete c.tc.computeLimit!.webRequests; }, /webRequests/],
    ["raises llmTokens", (c) => { c.tc.computeLimit!.llmTokens = 10_001; }, /llmTokens/],
    ["omits dataAccess", (c) => { delete c.tc.dataAccess; }, /dataAccess/],
    ["widens read to read-write", (c) => { c.tc.dataAccess = { calendar: "read-write" }; }, /dataAccess/],
    ["turns write-only into read-write", (c) => { c.tc.dataAccess = { drafts: "read-write" }; }, /dataAccess/],
    ["adds a resource the parent never granted", (c) => { c.tc.dataAccess = { email: "read" }; }, /dataAccess/],
    ["omits reversibleOnly", (c) => { delete c.tc.reversibleOnly; }, /reversibleOnly/],
    ["sets reversibleOnly false", (c) => { c.tc.reversibleOnly = false; }, /reversibleOnly/],
    ["omits requireSandbox", (c) => { delete c.tc.requireSandbox; }, /requireSandbox/],
    ["drops a human gate", (c) => { c.tc.humanGates = []; }, /human gate/],
    ["omits humanGates", (c) => { delete c.tc.humanGates; }, /human gate/],
    ["widens outputHandling", (c) => { c.tc.outputHandling = "shareable"; }, /outputHandling/],
    ["omits spendingConstraints", (c) => { (c as { spend?: SpendingConstraints }).spend = undefined; }, /spendingConstraints/],
    ["raises the spend limit", (c) => { c.spend.spendLimitUsd = 51; }, /spendLimitUsd/],
    ["omits the session limit", (c) => { delete c.spend.sessionLimitUsd; }, /sessionLimitUsd/],
    ["omits invariants", (c) => { (c as { inv?: MandateInvariants }).inv = undefined; }, /invariants/],
    ["adds a payee", (c) => { c.inv.payee = ["did:aroha:test:airline", "did:aroha:test:other"]; }, /payee/],
    ["raises maxAmount", (c) => { c.inv.maxAmount = { amount: 41, currency: "USD" }; }, /maxAmount/],
    ["drops an inherited blocked capability", (c) => { c.blocked = []; }, /blocked capability/],
    ["adds a capability", (c) => { c.allowed = [...c.allowed, "pay"]; }, /not in parent's allowed list/],
  ];

  for (const [name, mutate, reason] of widenings) {
    it(`refuses a child that ${name}`, async () => {
      const r = await verify(await forge(mutate));
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/Scope widened at link 1/);
      expect(r.reason).toMatch(reason);
    });
  }

  it("refuses a child whose expiry outlives the parent", async () => {
    const child = await forge(() => {}, Date.parse(root.mandate.expiresAt) + 60_000);
    const r = await verify(child);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expiry/);
  });

  it("the issuer runs the same rule: attenuateTaskMandate refuses an omitted constraint", async () => {
    const h = honest();
    delete h.tc.humanGates;
    await expect(
      attenuateTaskMandate(root, C.did, h.allowed, h.tc, bKey, 60_000, { spendingConstraints: h.spend, invariants: h.inv })
    ).rejects.toThrow(/human gate/);
  });
});

describe("parseTaskMandateToken — shape check (M4)", () => {
  it("throws TaskMandateTokenError on garbage and on an unparseable expiry", () => {
    expect(() => parseTaskMandateToken("not-a-token")).toThrow(TaskMandateTokenError);
    const body = { ...root.mandate, expiresAt: "never" };
    const tok = Buffer.from(JSON.stringify({ mandate: body, signature: root.signature })).toString("base64url");
    expect(() => parseTaskMandateToken(tok)).toThrow(/expiresAt/);
  });

  it("verifyTaskMandateChain reports a NaN expiry as malformed instead of 'not expired'", async () => {
    const body = { ...root.mandate, expiresAt: "garbage" };
    const tok = Buffer.from(JSON.stringify({ mandate: body, signature: root.signature })).toString("base64url");
    const r = await verifyTaskMandateChain([tok], aPub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expiresAt/);
  });
});

describe("root-of-trust pinning (M6)", () => {
  it("assertRootTrustConfigured refuses a server with no anchor unless allowUnpinnedRoot", () => {
    expect(() => assertRootTrustConfigured({}, "test")).toThrow(/trustAnchors or resolveRootKey/);
    expect(() => assertRootTrustConfigured({ trustAnchors: {} }, "test")).toThrow();
    expect(() => assertRootTrustConfigured({ allowUnpinnedRoot: true }, "test")).not.toThrow();
    expect(() => assertRootTrustConfigured({ resolveRootKey: async () => null }, "test")).not.toThrow();
  });

  it("checkRootTrust matches anchors and resolver keys, and refuses unknown roots", async () => {
    const aB64 = Buffer.from(aPub).toString("base64");
    expect(await checkRootTrust(A.did, aB64, { trustAnchors: { [A.did]: aPub } })).toBeNull();
    expect(await checkRootTrust(A.did, aB64, { trustAnchors: { [A.did]: bPub } })).toMatch(/does not match/);
    expect(await checkRootTrust(A.did, aB64, { resolveRootKey: async () => aPub })).toBeNull();
    expect(await checkRootTrust(A.did, aB64, { resolveRootKey: async () => null })).toMatch(/Untrusted/);
    expect(await checkRootTrust(A.did, aB64, {})).toMatch(/Untrusted/);
    expect(await checkRootTrust(A.did, aB64, { allowUnpinnedRoot: true })).toBeNull();
  });
});
