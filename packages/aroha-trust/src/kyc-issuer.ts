// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// A KYC issuer certifies that a specific credential commitment (see
// nullifier.ts) belongs to a real, unique human or entity it has verified
// through its own off-chain process. This module only covers the signature
// over that certification — domain-ownership proof (the actual trust
// bootstrap, mirroring the existing org-signing `.well-known` flow in
// apps/registry-server/src/routes/keys.ts) lives in the registry, since it
// needs network access this package deliberately doesn't have.
//
// Deliberately NOT reusing HumanCredential (@aroha-sdk/credentials): that
// credential is self-issued by a Personal Agent about its own session — an
// attacker controlling their own agent can mint arbitrarily many, so it
// carries no uniqueness guarantee. A KycCertificate is signed by a
// separately-trusted ISSUER key, proven via domain ownership the same way an
// org-signed agent registration is — the trust anchor is external to the
// party being certified, which is the entire point.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

export interface KycCertificate {
  /** The credential commitment (P, from nullifier.ts) being certified. */
  commitment: string; // base64url
  /** DID of the issuer, e.g. "did:aroha:kyc:onfido". */
  issuerDID: string;
  issuedAt: string;   // ISO8601
  expiresAt: string;  // ISO8601
  signature: string;  // base64url, over the canonical string below
}

function canonical(cert: Omit<KycCertificate, "signature">): string {
  // Field order fixed explicitly — do not derive from Object.keys, which is
  // insertion-order-dependent and would make this silently non-canonical.
  return JSON.stringify({
    commitment: cert.commitment,
    issuerDID:  cert.issuerDID,
    issuedAt:   cert.issuedAt,
    expiresAt:  cert.expiresAt,
  });
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Issuer-side: certify a credential commitment as belonging to a verified-unique holder. */
export async function issueCertificate(
  commitment: Uint8Array,
  issuerDID: string,
  issuerPrivateKey: Uint8Array,
  ttlMs = 365 * 24 * 60 * 60 * 1000, // KYC status is long-lived by default; issuers may reissue sooner
): Promise<KycCertificate> {
  const now = new Date();
  const unsigned = {
    commitment: b64url(commitment),
    issuerDID,
    issuedAt:  now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
  };
  const sig = await ed.signAsync(new TextEncoder().encode(canonical(unsigned)), issuerPrivateKey);
  return { ...unsigned, signature: b64url(sig) };
}

export interface CertVerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a certificate against a known issuer public key. Does NOT establish
 * that the public key belongs to a *trusted* issuer — that's a registry-side
 * lookup against issuers who completed domain-ownership proof. This only
 * checks "this specific key signed this specific certificate correctly."
 */
export async function verifyCertificate(
  cert: KycCertificate,
  issuerPublicKey: Uint8Array,
  now = new Date(),
): Promise<CertVerifyResult> {
  if (new Date(cert.expiresAt).getTime() <= now.getTime()) {
    return { ok: false, reason: "certificate expired" };
  }
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromB64url(cert.signature);
  } catch {
    return { ok: false, reason: "malformed signature encoding" };
  }
  const { signature: _sig, ...unsigned } = cert;
  const message = new TextEncoder().encode(canonical(unsigned));

  let valid: boolean;
  try {
    valid = await ed.verifyAsync(sigBytes, message, issuerPublicKey);
  } catch {
    return { ok: false, reason: "signature verification failed" };
  }
  if (!valid) return { ok: false, reason: "invalid signature" };
  return { ok: true };
}
