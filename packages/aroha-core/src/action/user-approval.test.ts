// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { canonicalizeJcs } from "../crypto/jcs.js";
import { hashPresentedContent } from "../receipts/index.js";
import {
  USER_APPROVAL_PURPOSE_V2, signUserApprovalPayload, userApprovalSigningBytes, verifyUserApprovalSignature,
} from "./user-approval.js";

const invariants = { parameters: { to: "a@example.com", subject: "Hi" }, payee: ["did:aroha:zP"] };

describe("UserApproval signing bytes", () => {
  it("legacy form (no presentedHash) is key-sorted JSON of the invariants, unchanged", () => {
    const bytes = new TextDecoder().decode(userApprovalSigningBytes({ invariants }));
    expect(bytes).toBe('{"parameters":{"subject":"Hi","to":"a@example.com"},"payee":["did:aroha:zP"]}');
  });

  it("presentedHash form is JCS with a purpose tag", () => {
    const presentedHash = hashPresentedContent({ shown: "Send 'Hi' to a@example.com" });
    const bytes = new TextDecoder().decode(userApprovalSigningBytes({ invariants, presentedHash }));
    expect(bytes).toBe(canonicalizeJcs({ invariants, presentedHash, purpose: USER_APPROVAL_PURPOSE_V2 }));
    expect(() => userApprovalSigningBytes({ invariants, presentedHash: "xyz" })).toThrow(/SHA-256/);
  });

  it("the person's signature covers presentedHash", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const presentedHash = hashPresentedContent({ shown: "A" });
    const userSignature = await signUserApprovalPayload({ invariants, presentedHash }, priv);
    expect(await verifyUserApprovalSignature({ invariants, presentedHash, userSignature }, pub)).toBe(true);
    // A different presented content, or dropping the hash, fails.
    expect(await verifyUserApprovalSignature({ invariants, presentedHash: hashPresentedContent({ shown: "B" }), userSignature }, pub)).toBe(false);
    expect(await verifyUserApprovalSignature({ invariants, userSignature }, pub)).toBe(false);
    // Legacy signatures still verify under the legacy rule.
    const legacy = await signUserApprovalPayload({ invariants }, priv);
    expect(await verifyUserApprovalSignature({ invariants, userSignature: legacy }, pub)).toBe(true);
  });
});
