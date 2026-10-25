// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * L17: a spending mandate whose expiresAt precedes its issuedAt is refused,
 * even when both instants individually pass the time-window checks. The
 * body is signed properly (signV2-style) so the refusal cannot be the
 * signature check.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody } from "@aroha-sdk/core";
import { verifyMandate, mandateSigningPayloadV2 } from "./mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

describe("spending mandate time ordering", () => {
  it("refuses expiresAt < issuedAt", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const did = generateDid(pub);
    const now = Date.now();
    const mandate: ArohaSpendingMandateBody = {
      mandateTier: "intent",
      constraints: { spendLimitUsd: 10 },
      grantee: "did:aroha:grantee",
      grantor: did,
      // issuedAt within clock tolerance, expiresAt in the future but before it.
      issuedAt: new Date(now + 20_000).toISOString(),
      expiresAt: new Date(now + 10_000).toISOString(),
      parentMandateId: null,
      mandateId: "m-1",
    };
    const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(mandate)), priv);
    const token = Buffer.from(
      JSON.stringify({ v: 2, mandate, signature: Buffer.from(sig).toString("base64url"), chain: [] })
    ).toString("base64url");
    const r = await verifyMandate(token, pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expires before it was issued/);
  });
});
