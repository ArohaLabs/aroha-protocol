// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { toMultibase, fromMultibase } from "../identity/did.js";
import {
  ACTION_RECEIPT_PURPOSE, ACTION_RECEIPT_PURPOSE_V2, hashPresentedContent, hashReceiptArgs, parseActionReceipt,
  signActionReceipt, signActionReceiptV1, verifyActionReceipt, verifyPresentedHash,
} from "./index.js";

async function agent() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey, did: `did:aroha:${toMultibase(publicKey)}` };
}
const resolveZ = (did: string) => fromMultibase(did.slice("did:aroha:".length));

const presented = { title: "Pay Acme Ltd", amount: "12.00 EUR", payee: "Acme Ltd", note: "Invoice 42" };

describe("action receipt v2", () => {
  it("carries the four identities, presentedHash, traceparent and room binding", async () => {
    const a = await agent();
    const ph = hashPresentedContent(presented);
    const r = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({ amount: 12 }), tainted: true,
      requesterDid: "did:aroha:Eguest", principalDid: "did:aroha:Ehost", executorDid: a.did,
      approval: { approverDid: "did:aroha:Ehost", approvedAt: "2026-10-15T10:00:00.000Z", approvalId: "ap-1", presentedHash: ph, approverSignature: "c2ln" },
      presentedHash: ph,
      traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      roomId: "room-1", onBehalfOf: "did:aroha:Eguest",
    }, a.privateKey);
    expect(r.v).toBe(2);
    expect(r.purpose).toBe(ACTION_RECEIPT_PURPOSE_V2);
    expect(r.outcome).toBe("executed");
    expect((await verifyActionReceipt(r, resolveZ)).ok).toBe(true);
    expect(verifyPresentedHash(r, presented)).toBeNull();
  });

  it("verification fails when the presented content differs from the approved hash", async () => {
    const a = await agent();
    const ph = hashPresentedContent(presented);
    const r = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({}), tainted: false, presentedHash: ph,
    }, a.privateKey);
    expect(verifyPresentedHash(r, { ...presented, payee: "Other Ltd" })).toMatch(/differs/);
    // key order of what was shown does not matter (JCS)
    expect(verifyPresentedHash(r, { note: "Invoice 42", payee: "Acme Ltd", amount: "12.00 EUR", title: "Pay Acme Ltd" })).toBeNull();
    const none = await signActionReceipt({ agentDid: a.did, action: "x", argsSha256: hashReceiptArgs({}), tainted: false }, a.privateKey);
    expect(verifyPresentedHash(none, presented)).toMatch(/no presentedHash/);
  });

  it("a denied receipt requires a denialReason and verifies", async () => {
    const a = await agent();
    await expect(signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({}), tainted: true, outcome: "denied",
    }, a.privateKey)).rejects.toThrow(/denialReason/);
    await expect(signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({}), tainted: true, denialReason: "x",
    }, a.privateKey)).rejects.toThrow(/executed/);
    const d = await signActionReceipt({
      agentDid: a.did, action: "pay", argsSha256: hashReceiptArgs({}), tainted: true,
      outcome: "denied", denialReason: "guest-origin request for a host-only capability",
    }, a.privateKey);
    expect((await verifyActionReceipt(d, resolveZ)).ok).toBe(true);
    // Removing the reason from a signed denied receipt makes it malformed.
    const { denialReason: _r, ...stripped } = d;
    expect(parseActionReceipt(stripped)).toBeNull();
    // Flipping the outcome breaks the signature (and the shape rule).
    expect((await verifyActionReceipt({ ...d, outcome: "executed" }, resolveZ)).ok).toBe(false);
  });

  it("v1 receipts still verify, and each version refuses the other's fields", async () => {
    const a = await agent();
    const v1 = await signActionReceiptV1({ agentDid: a.did, action: "x", argsSha256: hashReceiptArgs({}), tainted: false }, a.privateKey);
    expect(v1.v).toBe(1);
    expect(v1.purpose).toBe(ACTION_RECEIPT_PURPOSE);
    expect((await verifyActionReceipt(v1, resolveZ)).ok).toBe(true);
    expect(parseActionReceipt({ ...v1, outcome: "executed" })).toBeNull();
    expect(parseActionReceipt({ ...v1, approval: { approverDid: "d", approvedAt: "t", approvalId: "i", presentedHash: "0".repeat(64) } })).toBeNull();
    const v2 = await signActionReceipt({ agentDid: a.did, action: "x", argsSha256: hashReceiptArgs({}), tainted: false }, a.privateKey);
    expect(parseActionReceipt({ ...v2, surprise: 1 })).toBeNull();
    // A v2 body relabelled as v1 is refused (purpose and v must agree).
    expect(parseActionReceipt({ ...v2, v: 1 })).toBeNull();
    expect(parseActionReceipt({ ...v2, presentedHash: "not-hex" })).toBeNull();
  });
});
