// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * BBS Sign and Verify (draft-irtf-cfrg-bbs-signatures §3.4, §3.6).
 *
 * A BBS signature is a single short pair (A, e) over an arbitrary number of
 * messages — which is what makes selective disclosure possible later: the
 * holder can prove they possess a valid signature over ALL the messages
 * while revealing only some of them. Nothing here does that yet; this is the
 * signing half, and it is built first because a proof over a signature this
 * implementation got wrong would be worthless.
 */

import {
  bls, Fr, P1, BP2, OCTET_SCALAR_LENGTH, OCTET_POINT_LENGTH, OCTET_POINT_G2_LENGTH,
  H2S_DST, createGenerators, calculateDomain, hashToScalar, messagesToScalars,
  serialize, i2osp, os2ip, type G1Point, type G2Point,
} from "./ciphersuite.js";
import { concatBytes } from "@noble/hashes/utils";

export interface Signature {
  A: G1Point;
  e: bigint;
}

/** Secret key from key material, per the draft's KeyGen. */
export function skToPk(sk: bigint): Uint8Array {
  if (sk === 0n) throw new Error("BBS: secret key must not be zero");
  return BP2.multiply(sk).toRawBytes(true);
}

/**
 * Scalar multiplication that tolerates a zero scalar.
 *
 * noble refuses `multiply(0n)` — correct for key operations, where a zero
 * scalar is always a bug. Here a message can legitimately hash to zero (with
 * negligible probability), and the right answer is the identity, not a crash
 * that would only ever be seen in production.
 */
function mul(point: G1Point, scalar: bigint): G1Point {
  const s = Fr.create(scalar);
  return s === 0n ? bls.G1.ProjectivePoint.ZERO : point.multiply(s);
}

/**
 * B = P1 + Q_1·domain + Σ H_i·msg_i — the commitment both signing and
 * verification recompute independently. Shared so the two can never drift.
 */
function computeB(domain: bigint, msgScalars: bigint[], generators: G1Point[]): G1Point {
  const [q1, ...hPoints] = generators;
  let b = P1.add(mul(q1, domain));
  for (let i = 0; i < msgScalars.length; i++) b = b.add(mul(hPoints[i], msgScalars[i]));
  return b;
}

export interface SignOptions {
  /**
   * Bound into the signature but never revealed as a message. Use it for
   * context that must not be swappable — a credential type, an issuance
   * epoch — since a signature is only valid against the exact header it was
   * made with.
   */
  header?: Uint8Array;
}

/** Sign raw message octets. Messages are mapped to scalars by the ciphersuite. */
export function sign(
  sk: bigint,
  pk: Uint8Array,
  messages: Uint8Array[],
  options: SignOptions = {},
): Uint8Array {
  const header = options.header ?? new Uint8Array(0);
  const msgScalars = messagesToScalars(messages);
  const generators = createGenerators(msgScalars.length + 1);
  const [q1, ...hPoints] = generators;

  const domain = calculateDomain(pk, q1, hPoints, header);
  const e = hashToScalar(
    serialize([{ scalar: sk }, ...msgScalars.map((m) => ({ scalar: m })), { scalar: domain }]),
    H2S_DST,
  );

  const b = computeB(domain, msgScalars, generators);
  // A = B/(SK + e). The inverse is taken in Fr, so a secret key that happened
  // to equal -e would divide by zero — the draft treats that as an abort
  // rather than a value to work around.
  const denominator = Fr.add(Fr.create(sk), e);
  if (denominator === 0n) throw new Error("BBS: sk + e is zero; cannot sign");
  const a = b.multiply(Fr.inv(denominator));

  return signatureToOctets({ A: a, e });
}

export function signatureToOctets(sig: Signature): Uint8Array {
  return concatBytes(sig.A.toRawBytes(true), i2osp(sig.e, OCTET_SCALAR_LENGTH));
}

/** Parse a signature, rejecting anything malformed rather than guessing. */
export function octetsToSignature(octets: Uint8Array): Signature {
  if (octets.length !== OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH) {
    throw new Error(`BBS: signature must be ${OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH} octets`);
  }
  const A = bls.G1.ProjectivePoint.fromHex(octets.slice(0, OCTET_POINT_LENGTH));
  // Rejecting the identity is not pedantry: A = identity would make the
  // pairing check pass for a signature that commits to nothing.
  if (A.equals(bls.G1.ProjectivePoint.ZERO)) throw new Error("BBS: signature point is the identity");
  A.assertValidity();

  const e = os2ip(octets.slice(OCTET_POINT_LENGTH));
  if (e === 0n || e >= Fr.ORDER) throw new Error("BBS: signature scalar out of range");
  return { A, e };
}

function octetsToPubkey(pk: Uint8Array): G2Point {
  if (pk.length !== OCTET_POINT_G2_LENGTH) {
    throw new Error(`BBS: public key must be ${OCTET_POINT_G2_LENGTH} octets`);
  }
  const w = bls.G2.ProjectivePoint.fromHex(pk);
  if (w.equals(bls.G2.ProjectivePoint.ZERO)) throw new Error("BBS: public key is the identity");
  w.assertValidity();
  return w;
}

/**
 * Verify a signature over the full message set.
 *
 * Returns false for every rejection, including a malformed signature or key.
 * A verifier that threw on bad input and returned false on a bad signature
 * would make "invalid" and "crashed" two different call sites for the same
 * security answer, which is how a try/catch ends up swallowing a real
 * verification failure.
 */
export function verify(
  pk: Uint8Array,
  signature: Uint8Array,
  messages: Uint8Array[],
  options: SignOptions = {},
): boolean {
  try {
    const header = options.header ?? new Uint8Array(0);
    const { A, e } = octetsToSignature(signature);
    const w = octetsToPubkey(pk);

    const msgScalars = messagesToScalars(messages);
    const generators = createGenerators(msgScalars.length + 1);
    const [q1, ...hPoints] = generators;

    const domain = calculateDomain(pk, q1, hPoints, header);
    const b = computeB(domain, msgScalars, generators);

    // e(A, W + BP2·e) · e(B, -BP2) == 1, which holds exactly when
    // A = B/(sk + e) for the sk behind W.
    const result = bls.pairingBatch([
      { g1: A, g2: w.add(BP2.multiply(e)) },
      { g1: b, g2: BP2.negate() },
    ]);
    return bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
  } catch {
    return false;
  }
}
