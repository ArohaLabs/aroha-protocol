// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Chaum-Pedersen DLEQ proofs, applied as a Sybil-resistance nullifier scheme.
//
// ── What this is, precisely ─────────────────────────────────────────────────
//
// A KYC issuer verifies a real, unique human/entity through its own off-chain
// process and hands them a secret scalar `s`, alongside a public commitment
// `P = s·G` that the issuer signs (see kyc-issuer.ts). That's the only new
// thing the issuer does — everything after this point is public-key math the
// caller runs themselves, with no further issuer involvement.
//
// To prove "I am a verified, not-yet-used caller" for some scope (e.g. the
// registry's "verified-caller" pool), the holder of `s`:
//   1. Derives a scope point H = hashToScalar(scope)·G — public, deterministic,
//      the same for everyone proving against that scope.
//   2. Computes a nullifier N = s·H.
//   3. Proves, in zero knowledge, that the SAME secret s satisfies both
//      P = s·G and N = s·H — a discrete-log-equality (DLEQ) proof, the
//      Chaum-Pedersen protocol, made non-interactive via Fiat-Shamir.
//
// The verifier learns: "the party who submitted this proof knows the secret
// behind P, and N is that secret's correctly-derived nullifier for this
// scope" — without ever learning s. Reusing the proof, or deriving N from a
// different s, both fail verification.
//
// ── What this is NOT ────────────────────────────────────────────────────────
//
// This is not a general-purpose zk-SNARK, and it does not provide anonymity
// SET privacy the way Semaphore does. P is revealed as part of every proof —
// the registry (or anyone) can see that the same P produced two different
// submissions, i.e. P functions as a stable pseudonym. What stays hidden is
// the secret s and, by extension, any PII the KYC issuer holds (name, DOB,
// document data) — that data never leaves the issuer. If unlinkability of P
// itself becomes a requirement, the upgrade path is wrapping this same DLEQ
// relation in an anonymity-set SNARK (Semaphore-style) — a materially bigger
// build, deliberately deferred rather than half-built here.
//
// The Sybil-resistance property this delivers: registering as a "verified
// caller" requires an issuer to certify uniqueness once per P, and a given P
// can produce at most one live nullifier per scope (the registry rejects a
// repeat). Getting N distinct verified-caller slots requires N distinct
// issuer-certified credentials — the actual cost the attacker must pay.

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToNumberBE, numberToBytesBE, concatBytes, randomBytes } from "@noble/curves/abstract/utils.js";

const G = ed25519.Point.BASE;
const ORDER = ed25519.CURVE.n; // curve order — all scalar arithmetic is mod this
const SCALAR_BYTES = 32;

// ─── Scalar helpers ─────────────────────────────────────────────────────────

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/** Hash arbitrary bytes down to a scalar mod the curve order. Not constant-time; fine for public values. */
function hashToScalar(...parts: Uint8Array[]): bigint {
  const h = sha256(concatBytes(...parts));
  return mod(bytesToNumberBE(h), ORDER);
}

function scalarToBytes(s: bigint): Uint8Array {
  return numberToBytesBE(mod(s, ORDER), SCALAR_BYTES);
}

/** A fresh random scalar — used for the Schnorr commitment nonce, never reused across proofs. */
function randomScalar(): bigint {
  return mod(bytesToNumberBE(randomBytes(32)), ORDER);
}

// ─── Public API ─────────────────────────────────────────────────────────────

export interface CredentialSecret {
  /** 32-byte scalar. Never sent to the registry — only P (below) and proofs derived from it are. */
  secret: Uint8Array;
  /** P = secret·G — the public commitment the issuer signs and the registry stores. */
  commitment: Uint8Array;
}

export interface NullifierProof {
  /** The credential's public commitment (P). Functions as a stable pseudonym — see module doc. */
  commitment: Uint8Array;
  /** The scope this proof was generated for (e.g. "verified-caller"). */
  scope: string;
  /** N = secret·H(scope) — deterministic per (secret, scope); the registry's dedup key. */
  nullifier: Uint8Array;
  /** Chaum-Pedersen proof transcript. */
  r1: Uint8Array;
  r2: Uint8Array;
  z: Uint8Array;
}

/** Issuer-side: generate a fresh credential secret and its public commitment. */
export function generateCredentialSecret(): CredentialSecret {
  const s = randomScalar();
  const P = G.multiply(s);
  return { secret: scalarToBytes(s), commitment: P.toBytes() };
}

/** The public, scope-specific generator point H every prover and verifier derives independently. */
export function scopePoint(scope: string): Uint8Array {
  const h = hashToScalar(new TextEncoder().encode("aroha-trust/scope-point"), new TextEncoder().encode(scope));
  return G.multiply(h).toBytes();
}

/**
 * Holder-side: prove "I know the secret behind `commitment`, and this
 * nullifier is that secret's correct derivation for `scope`" — without
 * revealing the secret.
 */
export function proveUniqueness(secretBytes: Uint8Array, scope: string): NullifierProof {
  const s = mod(bytesToNumberBE(secretBytes), ORDER);
  const P = G.multiply(s);
  const H = ed25519.Point.fromBytes(scopePoint(scope));
  const N = H.multiply(s);

  const k = randomScalar();
  const R1 = G.multiply(k);
  const R2 = H.multiply(k);

  const c = hashToScalar(
    G.toBytes(), H.toBytes(), P.toBytes(), N.toBytes(), R1.toBytes(), R2.toBytes(),
  );
  const z = mod(k + c * s, ORDER);

  return {
    commitment: P.toBytes(),
    scope,
    nullifier: N.toBytes(),
    r1: R1.toBytes(),
    r2: R2.toBytes(),
    z: scalarToBytes(z),
  };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verifier-side: check the proof without ever seeing the secret.
 *
 * Verifies z·G == R1 + c·P and z·H == R2 + c·N for the same challenge c —
 * the standard Chaum-Pedersen check. Both equations must hold under the
 * SAME z for the proof to establish that one secret satisfies both
 * relations; checking either alone proves nothing about the other.
 */
export function verifyUniquenessProof(proof: NullifierProof): VerifyResult {
  // Every curve operation below can throw on adversarial input — a zero or
  // out-of-range scalar, a point not on the curve, a small-order point used
  // to try to bypass the equality check. Any of those must fail closed as an
  // invalid proof, not crash the caller, so the whole computation — not just
  // the initial parsing — lives in one try block.
  try {
    const P = ed25519.Point.fromBytes(proof.commitment);
    const H = ed25519.Point.fromBytes(scopePoint(proof.scope));
    const N = ed25519.Point.fromBytes(proof.nullifier);
    const R1 = ed25519.Point.fromBytes(proof.r1);
    const R2 = ed25519.Point.fromBytes(proof.r2);
    const z = mod(bytesToNumberBE(proof.z), ORDER);
    if (z === 0n) return { ok: false, reason: "malformed proof — zero response scalar" };

    const c = hashToScalar(G.toBytes(), H.toBytes(), P.toBytes(), N.toBytes(), R1.toBytes(), R2.toBytes());

    const lhs1 = G.multiply(z);
    const rhs1 = R1.add(P.multiply(c));
    if (!lhs1.equals(rhs1)) return { ok: false, reason: "proof does not establish knowledge of the commitment's secret" };

    const lhs2 = H.multiply(z);
    const rhs2 = R2.add(N.multiply(c));
    if (!lhs2.equals(rhs2)) return { ok: false, reason: "nullifier is not correctly derived from the same secret" };

    return { ok: true };
  } catch {
    return { ok: false, reason: "malformed proof — invalid curve point or scalar encoding" };
  }
}
