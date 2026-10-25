// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { toMultibase, fromMultibase } from "../identity/did.js";
import { canonicalizeJcs } from "../crypto/jcs.js";
import {
  ACTION_RECEIPT_PURPOSE_V2, actionReceiptHash, hashReceiptArgs, receiptMatches, requireApprovalIfTainted,
  signActionReceipt, verifyActionReceipt, type ArohaActionReceipt,
} from "./index.js";

async function agent() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey, did: `did:aroha:${toMultibase(publicKey)}` };
}

/** A downstream verifier with nothing but the DID: content-addressed resolution. */
const resolveZ = (did: string) => fromMultibase(did.slice("did:aroha:".length));

describe("signed action receipts", () => {
  it("signs over JCS with the purpose inside the signed body", async () => {
    const a = await agent();
    const r = await signActionReceipt(
      { agentDid: a.did, action: "send-email", argsSha256: hashReceiptArgs({ to: "x@example.com" }), tainted: false },
      a.privateKey,
    );
    expect(r.v).toBe(2);
    expect(r.purpose).toBe(ACTION_RECEIPT_PURPOSE_V2);
    const { signature, ...body } = r;
    const ok = await ed.verifyAsync(
      Buffer.from(signature, "base64url"), new TextEncoder().encode(canonicalizeJcs(body)), a.publicKey,
    );
    expect(ok).toBe(true);
    expect((await verifyActionReceipt(r, resolveZ)).ok).toBe(true);
  });

  it("argument digests do not depend on key order", () => {
    expect(hashReceiptArgs({ a: 1, b: "two" })).toBe(hashReceiptArgs({ b: "two", a: 1 }));
    expect(hashReceiptArgs({ a: 1 })).not.toBe(hashReceiptArgs({ a: 2 }));
  });

  it("a downstream verifier rejects a tainted action with no approval", async () => {
    const a = await agent();
    const r = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({ amount: 10 }),
      tainted: true, provenance: ["retrieval"],
    }, a.privateKey);
    const verified = await verifyActionReceipt(r, resolveZ);
    expect(verified.ok).toBe(true);
    expect(requireApprovalIfTainted(r)).toMatch(/untrusted input/);
  });

  it("an approved tainted action passes the policy", async () => {
    const a = await agent();
    const r = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({ amount: 10 }), tainted: true,
      approval: { approverDid: "did:aroha:zPerson", approvedAt: new Date().toISOString(), approvalId: "ap-1" },
      mandateId: "urn:uuid:m-1", mandateGrantor: "did:aroha:zGrantor", correlationId: "c-1",
    }, a.privateKey);
    expect((await verifyActionReceipt(r, resolveZ)).ok).toBe(true);
    expect(requireApprovalIfTainted(r)).toBeNull();
    // An untainted action needs no approval.
    expect(requireApprovalIfTainted({ ...r, tainted: false, approval: undefined })).toBeNull();
  });

  it("a tampered receipt fails verification", async () => {
    const a = await agent();
    const r = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({ amount: 10 }), tainted: true,
    }, a.privateKey);
    // Flipping the taint flag to dodge the policy breaks the signature.
    expect((await verifyActionReceipt({ ...r, tainted: false }, resolveZ)).ok).toBe(false);
    // So does grafting an approval on afterwards.
    const grafted = { ...r, approval: { approverDid: "did:aroha:zX", approvedAt: r.at, approvalId: "forged" } };
    expect((await verifyActionReceipt(grafted, resolveZ)).ok).toBe(false);
    // And re-attributing it to another agent.
    const other = await agent();
    expect((await verifyActionReceipt({ ...r, agentDid: other.did }, resolveZ)).ok).toBe(false);
    // Unknown fields are refused rather than silently ignored.
    expect((await verifyActionReceipt({ ...r, extra: 1 }, resolveZ)).ok).toBe(false);
    expect((await verifyActionReceipt({ ...r, purpose: "other" }, resolveZ)).ok).toBe(false);
  });

  it("refuses a receipt whose agent key cannot be resolved", async () => {
    const a = await agent();
    const r = await signActionReceipt({ agentDid: a.did, action: "x", argsSha256: hashReceiptArgs({}), tainted: false }, a.privateKey);
    const v = await verifyActionReceipt(r, () => null);
    expect(v.ok).toBe(false);
  });

  it("receiptMatches binds the receipt to one action and its arguments", async () => {
    const a = await agent();
    const r: ArohaActionReceipt = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({ amount: 10, to: "acct" }), tainted: false,
    }, a.privateKey);
    expect(receiptMatches(r, { agentDid: a.did, action: "pay", args: { to: "acct", amount: 10 } })).toBeNull();
    expect(receiptMatches(r, { agentDid: a.did, action: "pay", args: { to: "other", amount: 10 } })).toMatch(/arguments/);
    expect(receiptMatches(r, { agentDid: a.did, action: "refund", args: { to: "acct", amount: 10 } })).toMatch(/refund/);
    expect(receiptMatches(r, { agentDid: "did:aroha:zOther", action: "pay", args: { to: "acct", amount: 10 } })).toMatch(/not/);
  });

  it("the receipt hash is stable and changes with any field", async () => {
    const a = await agent();
    const r = await signActionReceipt({ agentDid: a.did, action: "x", argsSha256: hashReceiptArgs({}), tainted: false }, a.privateKey);
    expect(actionReceiptHash(r)).toMatch(/^[0-9a-f]{64}$/);
    expect(actionReceiptHash({ ...r })).toBe(actionReceiptHash(r));
    expect(actionReceiptHash({ ...r, tainted: true })).not.toBe(actionReceiptHash(r));
  });
});
