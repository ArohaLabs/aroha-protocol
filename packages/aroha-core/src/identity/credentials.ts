// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Verifiable Credentials (VCs)
 *
 * Based on W3C Verifiable Credentials Data Model 2.0.
 * VCs allow agents to prove claims about themselves (corporate identity,
 * compliance certifications, capability authorization) without revealing
 * more than necessary (selective disclosure via ZKP proofs).
 *
 * Issuance flow:
 *   Trust Anchor (e.g. Expedia Corp) issues a VC to its agent.
 *   The VC is signed with the issuer's private key.
 *   The agent presents the VC during negotiation.
 *   The counterpart verifies the VC signature.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── Types ────────────────────────────────────────────────────────────────────

export type TrustLevel = 0 | 1 | 2 | 3 | 4;

export const TRUST_LEVEL_DESCRIPTIONS: Record<TrustLevel, string> = {
  0: "Public — read capability manifests only",
  1: "Registered — on-chain registration + stake",
  2: "Verified — VC from recognized trust anchor",
  3: "Reputable — reputation score >= 0.8",
  4: "User-trusted — explicit user authorization",
};

export interface CredentialSubject {
  id: string; // DID of the subject (the agent being described)
  [key: string]: unknown;
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string; // DID of the issuer (e.g. did:aroha:expedia-corp)
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: CredentialSubject;
  proof?: VCProof;
}

export interface VCProof {
  type: "Ed25519Signature2020";
  created: string;
  verificationMethod: string; // issuer DID + key fragment
  proofPurpose: "assertionMethod";
  proofValue: string; // base64url-encoded signature
}

// ─── Standard Aroha credential types ──────────────────────────────────────────

/** Issued by a company to vouch that an agent is operated by them. */
export interface CorporateIdentityCredential extends VerifiableCredential {
  credentialSubject: {
    id: string;
    companyName: string;
    companyDomain: string;
    registeredCountry: string;
  };
}

/** Issued by a compliance body (e.g. PCI-DSS, HIPAA auditor). */
export interface ComplianceCertificationCredential extends VerifiableCredential {
  credentialSubject: {
    id: string;
    standard: string; // "PCI-DSS-L1" | "HIPAA" | "SOC2-T2" | ...
    certifiedUntil: string;
    scope: string;
  };
}

/** Issued by a platform operator to authorize an agent to act. */
export interface CapabilityAuthorizationCredential extends VerifiableCredential {
  credentialSubject: {
    id: string;
    authorizedCapabilities: string[];
    maxTransactionValue?: { amount: number; currency: string };
  };
}

// ─── Issue / Verify ───────────────────────────────────────────────────────────

/**
 * Issue a Verifiable Credential.
 * The issuer signs the credential's canonical JSON with their Ed25519 key.
 */
export async function issueCredential(
  credential: Omit<VerifiableCredential, "proof" | "id">,
  issuerPrivateKey: Uint8Array,
  issuerKeyId: string
): Promise<VerifiableCredential> {
  const id = `urn:uuid:${crypto.randomUUID()}`;
  const unsigned: VerifiableCredential = { ...credential, id };

  const payload = JSON.stringify(canonicalize(unsigned));
  const payloadBytes = new TextEncoder().encode(payload);

  const signature = await ed.signAsync(payloadBytes, issuerPrivateKey);
  const proofValue = Buffer.from(signature).toString("base64url");

  const proof: VCProof = {
    type: "Ed25519Signature2020",
    created: new Date().toISOString(),
    verificationMethod: issuerKeyId,
    proofPurpose: "assertionMethod",
    proofValue,
  };

  return { ...unsigned, proof };
}

/**
 * Verify a Verifiable Credential's signature.
 * Returns true if the signature is valid.
 */
export async function verifyCredential(
  credential: VerifiableCredential,
  issuerPublicKey: Uint8Array
): Promise<boolean> {
  if (!credential.proof) return false;

  const { proof, ...unsigned } = credential;
  const payload = JSON.stringify(canonicalize(unsigned as VerifiableCredential));
  const payloadBytes = new TextEncoder().encode(payload);

  const signature = Buffer.from(proof.proofValue, "base64url");
  return ed.verifyAsync(signature, payloadBytes, issuerPublicKey);
}

/**
 * Check if a credential is expired. An expirationDate that is present but
 * unparseable counts as expired: NaN compares false with everything, so the
 * old `new Date(x) < new Date()` read a garbage date as "never expires".
 */
export function isCredentialExpired(credential: VerifiableCredential): boolean {
  if (credential.expirationDate === undefined || credential.expirationDate === null) return false;
  const t = Date.parse(credential.expirationDate);
  return Number.isNaN(t) || t < Date.now();
}

// ─── Deterministic JSON (canonical form for signing) ──────────────────────────

function canonicalize(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(canonicalize);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj as object)
      .sort()
      .reduce(
        (acc, key) => {
          (acc as Record<string, unknown>)[key] = canonicalize(
            (obj as Record<string, unknown>)[key]
          );
          return acc;
        },
        {} as Record<string, unknown>
      );
  }
  return obj;
}
