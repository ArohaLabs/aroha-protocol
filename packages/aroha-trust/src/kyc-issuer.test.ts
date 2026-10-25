// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { issueCertificate, verifyCertificate } from "./kyc-issuer.js";
import { generateCredentialSecret } from "./nullifier.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function issuerKeypair() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub };
}

describe("issueCertificate / verifyCertificate", () => {
  it("verifies a certificate signed by the correct issuer key", async () => {
    const issuer = await issuerKeypair();
    const cred = generateCredentialSecret();
    const cert = await issueCertificate(cred.commitment, "did:aroha:kyc:test-issuer", issuer.priv);

    expect(await verifyCertificate(cert, issuer.pub)).toEqual({ ok: true });
  });

  it("rejects a certificate signed by a different key", async () => {
    const issuer = await issuerKeypair();
    const impostor = await issuerKeypair();
    const cred = generateCredentialSecret();
    const cert = await issueCertificate(cred.commitment, "did:aroha:kyc:test-issuer", impostor.priv);

    const result = await verifyCertificate(cert, issuer.pub);
    expect(result.ok).toBe(false);
  });

  it("rejects an expired certificate even with a valid signature", async () => {
    const issuer = await issuerKeypair();
    const cred = generateCredentialSecret();
    const cert = await issueCertificate(cred.commitment, "did:aroha:kyc:test-issuer", issuer.priv, -1000);

    const result = await verifyCertificate(cert, issuer.pub);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/expired/);
  });

  it("rejects a certificate whose commitment field was swapped after signing", async () => {
    const issuer = await issuerKeypair();
    const credA = generateCredentialSecret();
    const credB = generateCredentialSecret();
    const cert = await issueCertificate(credA.commitment, "did:aroha:kyc:test-issuer", issuer.priv);

    // Attacker rewrites the certificate to point at a different commitment,
    // hoping the signature check is loose enough not to notice.
    const tampered = { ...cert, commitment: Buffer.from(credB.commitment).toString("base64url") };
    const result = await verifyCertificate(tampered, issuer.pub);
    expect(result.ok).toBe(false);
  });

  it("rejects a certificate whose issuerDID was swapped after signing", async () => {
    const issuer = await issuerKeypair();
    const cred = generateCredentialSecret();
    const cert = await issueCertificate(cred.commitment, "did:aroha:kyc:real-issuer", issuer.priv);

    const tampered = { ...cert, issuerDID: "did:aroha:kyc:different-issuer" };
    expect((await verifyCertificate(tampered, issuer.pub)).ok).toBe(false);
  });

  it("handles a malformed signature without throwing", async () => {
    const issuer = await issuerKeypair();
    const cred = generateCredentialSecret();
    const cert = await issueCertificate(cred.commitment, "did:aroha:kyc:test", issuer.priv);
    const garbled = { ...cert, signature: "not-valid-base64url!!!" };

    await expect(verifyCertificate(garbled, issuer.pub)).resolves.toMatchObject({ ok: false });
  });
});
