// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * BBS ProofGen and ProofVerify (draft-irtf-cfrg-bbs-signatures §3.6.3–§3.7).
 *
 * This is the half that does selective disclosure. Given a signature over
 * messages 0..L-1, the holder produces a proof that reveals a chosen subset
 * and says nothing about the rest — not their values, and not (to a verifier
 * who sees two proofs) whether the two came from the same signature, because
 * Abar/Bbar/D are re-randomised every time.
 *
 * What it proves: "an issuer whose public key is PK signed a message set in
 * which position 3 is 'over_18=true'". What it does not prove: anything
 * about who is presenting it. Binding a proof to a holder is a separate
 * problem, and pretending otherwise is how a presentation becomes a bearer
 * token — see the README.
 */

import {
  bls, Fr, P1, BP2, OCTET_SCALAR_LENGTH, OCTET_POINT_LENGTH,
  H2S_DST, createGenerators, calculateDomain, hashToScalar, messagesToScalars,
  serialize, i2osp, os2ip, expandMessageXmd, type G1Point,
} from "./ciphersuite.js";
import { octetsToSignature, type SignOptions } from "./sign.js";
import { concatBytes } from "@noble/hashes/utils";
import { randomBytes } from "@noble/hashes/utils";

const EXPAND_LEN = 48;

export interface Proof {
  Abar: G1Point;
  Bbar: G1Point;
  D: G1Point;
  eHat: bigint;
  r1Hat: bigint;
  r3Hat: bigint;
  /** One per UNDISCLOSED message, in ascending index order. */
  commitments: bigint[];
  challenge: bigint;
}

/**
 * Where the proof's blinding scalars come from.
 *
 * Injectable for exactly one reason: the reference fixtures publish the
 * scalars they used, and reproducing a published proof byte for byte is the
 * only way to show this implementation agrees with the standard rather than
 * merely with itself.
 *
 * SUPPLYING THIS IN PRODUCTION DESTROYS THE PROOF'S ZERO-KNOWLEDGE. The
 * blinding is what hides the undisclosed messages and unlinks two
 * presentations; predictable scalars reveal both. It is a separate named
 * option rather than a positional argument so it cannot be passed by
 * accident.
 */
export type RandomScalars = (count: number) => bigint[];

const defaultRandomScalars: RandomScalars = (count) =>
  Array.from({ length: count }, () => os2ip(randomBytes(EXPAND_LEN)) % Fr.ORDER);

function mul(point: G1Point, scalar: bigint): G1Point {
  const s = Fr.create(scalar);
  return s === 0n ? bls.G1.ProjectivePoint.ZERO : point.multiply(s);
}

/** Σ points[i]·scalars[i]. */
function msm(points: G1Point[], scalars: bigint[]): G1Point {
  let acc = bls.G1.ProjectivePoint.ZERO;
  for (let i = 0; i < points.length; i++) acc = acc.add(mul(points[i], scalars[i]));
  return acc;
}

/**
 * The five points plus domain that both prover and verifier arrive at
 * independently — the prover by construction, the verifier by recomputation.
 * The proof is valid exactly when the two agree, which is what makes the
 * challenge a Fiat-Shamir binding rather than a value the prover chose.
 */
interface InitResult {
  Abar: G1Point; Bbar: G1Point; D: G1Point; T1: G1Point; T2: G1Point; domain: bigint;
}

function proofChallenge(
  init: InitResult,
  disclosedIndexes: number[],
  disclosedScalars: bigint[],
  ph: Uint8Array,
): bigint {
  const cArr: Parameters<typeof serialize>[0] = [{ uint: disclosedIndexes.length }];
  for (let i = 0; i < disclosedIndexes.length; i++) {
    // Index AND value, so a proof cannot be replayed with the same revealed
    // value claimed at a different position.
    cArr.push({ uint: disclosedIndexes[i] }, { scalar: disclosedScalars[i] });
  }
  cArr.push(init.Abar, init.Bbar, init.D, init.T1, init.T2, { scalar: init.domain });

  const cOcts = concatBytes(serialize(cArr), i2osp(ph.length, 8), ph);
  return hashToScalar(cOcts, H2S_DST);
}

export interface ProveOptions extends SignOptions {
  /**
   * Presentation header — bound into the challenge, never revealed as a
   * message. This is where a verifier's nonce goes; without one, a proof a
   * verifier has seen once can be replayed to them forever.
   */
  presentationHeader?: Uint8Array;
}

/**
 * Produce a proof revealing only `disclosedIndexes` of the signed messages.
 *
 * Takes the full message set because the prover holds it: the undisclosed
 * messages are needed to build the proof even though the verifier never
 * learns them.
 */
export function prove(
  pk: Uint8Array,
  signature: Uint8Array,
  messages: Uint8Array[],
  disclosedIndexes: number[],
  options: ProveOptions = {},
): Uint8Array {
  // The old public option. Refused loudly rather than ignored, so code that
  // relied on it notices: fixed blinding scalars make every proof linkable
  // and can reveal the undisclosed messages.
  if ((options as { unsafeRandomScalars?: unknown }).unsafeRandomScalars !== undefined) {
    throw new Error("prove(): unsafeRandomScalars is no longer accepted (it destroys zero-knowledge)");
  }
  return proveInternal(pk, signature, messages, disclosedIndexes, options, defaultRandomScalars);
}

/**
 * TEST-ONLY: prove() with caller-supplied blinding scalars, for byte-exact
 * spec test vectors. Not re-exported from the package entry point (the
 * package exposes only "."), so it is unreachable for consumers. WHY it
 * moved off ProveOptions: a public option is one autocomplete away from
 * production code, and supplying it destroys zero-knowledge.
 * @internal
 */
export function proveWithFixedScalarsForTesting(
  pk: Uint8Array,
  signature: Uint8Array,
  messages: Uint8Array[],
  disclosedIndexes: number[],
  options: ProveOptions,
  scalars: RandomScalars,
): Uint8Array {
  return proveInternal(pk, signature, messages, disclosedIndexes, options, scalars);
}

function proveInternal(
  pk: Uint8Array,
  signature: Uint8Array,
  messages: Uint8Array[],
  disclosedIndexes: number[],
  options: ProveOptions,
  getRandom: RandomScalars,
): Uint8Array {
  const header = options.header ?? new Uint8Array(0);
  const ph = options.presentationHeader ?? new Uint8Array(0);

  const { A, e } = octetsToSignature(signature);
  const L = messages.length;

  const disclosed = [...new Set(disclosedIndexes)].sort((a, b) => a - b);
  for (const i of disclosed) {
    if (!Number.isInteger(i) || i < 0 || i >= L) throw new Error(`BBS: disclosed index ${i} out of range`);
  }
  const undisclosed = Array.from({ length: L }, (_, i) => i).filter((i) => !disclosed.includes(i));
  const U = undisclosed.length;

  const msgScalars = messagesToScalars(messages);
  const generators = createGenerators(L + 1);
  const [q1, ...hPoints] = generators;

  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTilde] = getRandom(5 + U);
  if (mTilde.length !== U) throw new Error("BBS: random scalar source returned the wrong count");

  const domain = calculateDomain(pk, q1, hPoints, header);
  const B = P1.add(mul(q1, domain)).add(msm(hPoints, msgScalars));

  // Re-randomisation: D, Abar and Bbar are fresh every time, which is why
  // two proofs from one signature cannot be linked to each other.
  const D = mul(B, r2);
  const Abar = mul(A, Fr.mul(r1, r2));
  const Bbar = mul(D, r1).subtract(mul(Abar, e));

  const T1 = mul(Abar, eTilde).add(mul(D, r1Tilde));
  const T2 = mul(D, r3Tilde).add(msm(undisclosed.map((j) => hPoints[j]), mTilde));

  const init: InitResult = { Abar, Bbar, D, T1, T2, domain };
  const challenge = proofChallenge(init, disclosed, disclosed.map((i) => msgScalars[i]), ph);

  const r3 = Fr.inv(r2);
  const eHat = Fr.add(eTilde, Fr.mul(e, challenge));
  const r1Hat = Fr.sub(r1Tilde, Fr.mul(r1, challenge));
  const r3Hat = Fr.sub(r3Tilde, Fr.mul(r3, challenge));
  const commitments = undisclosed.map((j, k) => Fr.add(mTilde[k], Fr.mul(msgScalars[j], challenge)));

  return proofToOctets({ Abar, Bbar, D, eHat, r1Hat, r3Hat, commitments, challenge });
}

export function proofToOctets(proof: Proof): Uint8Array {
  return serialize([
    proof.Abar, proof.Bbar, proof.D,
    { scalar: proof.eHat }, { scalar: proof.r1Hat }, { scalar: proof.r3Hat },
    ...proof.commitments.map((c) => ({ scalar: c })),
    { scalar: proof.challenge },
  ]);
}

export function octetsToProof(octets: Uint8Array): Proof {
  const fixed = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH;
  if (octets.length < fixed || (octets.length - fixed) % OCTET_SCALAR_LENGTH !== 0) {
    throw new Error("BBS: proof is not a valid length");
  }

  let offset = 0;
  const point = (): G1Point => {
    const p = bls.G1.ProjectivePoint.fromHex(octets.slice(offset, offset + OCTET_POINT_LENGTH));
    offset += OCTET_POINT_LENGTH;
    // The identity would make the pairing check pass vacuously.
    if (p.equals(bls.G1.ProjectivePoint.ZERO)) throw new Error("BBS: proof contains the identity point");
    p.assertValidity();
    return p;
  };
  const scalar = (): bigint => {
    const s = os2ip(octets.slice(offset, offset + OCTET_SCALAR_LENGTH));
    offset += OCTET_SCALAR_LENGTH;
    if (s === 0n || s >= Fr.ORDER) throw new Error("BBS: proof scalar out of range");
    return s;
  };

  const Abar = point(), Bbar = point(), D = point();
  const eHat = scalar(), r1Hat = scalar(), r3Hat = scalar();
  const commitmentCount = (octets.length - fixed) / OCTET_SCALAR_LENGTH;
  const commitments = Array.from({ length: commitmentCount }, scalar);
  const challenge = scalar();

  return { Abar, Bbar, D, eHat, r1Hat, r3Hat, commitments, challenge };
}

/**
 * Verify a proof against the messages the holder chose to reveal.
 *
 * `disclosedIndexes` must be the positions those messages occupied in the
 * ORIGINAL signed set — the verifier has to know which attribute it is being
 * shown, or "over_18=true" at position 3 and a different flag at position 7
 * become interchangeable.
 *
 * Returns false for every rejection, matching verify()'s contract.
 */
export function verifyProof(
  pk: Uint8Array,
  proofOctets: Uint8Array,
  disclosedMessages: Uint8Array[],
  disclosedIndexes: number[],
  options: ProveOptions = {},
): boolean {
  try {
    const header = options.header ?? new Uint8Array(0);
    const ph = options.presentationHeader ?? new Uint8Array(0);

    const proof = octetsToProof(proofOctets);
    const w = bls.G2.ProjectivePoint.fromHex(pk);
    w.assertValidity();
    if (w.equals(bls.G2.ProjectivePoint.ZERO)) return false;

    const U = proof.commitments.length;
    const R = disclosedIndexes.length;
    const L = R + U;
    if (disclosedMessages.length !== R) return false;

    const disclosed = [...disclosedIndexes];
    for (const i of disclosed) {
      if (!Number.isInteger(i) || i < 0 || i >= L) return false;
    }
    if (new Set(disclosed).size !== R) return false; // a repeated index is malformed
    const undisclosed = Array.from({ length: L }, (_, i) => i).filter((i) => !disclosed.includes(i));

    const generators = createGenerators(L + 1);
    const [q1, ...hPoints] = generators;
    const domain = calculateDomain(pk, q1, hPoints, header);
    const disclosedScalars = messagesToScalars(disclosedMessages);

    // Recompute T1 and T2 from the proof's responses. They match the
    // prover's only if the responses really were built from a valid
    // signature over the claimed messages.
    const T1 = mul(proof.Bbar, proof.challenge)
      .add(mul(proof.Abar, proof.eHat))
      .add(mul(proof.D, proof.r1Hat));
    const Bv = P1.add(mul(q1, domain)).add(msm(disclosed.map((i) => hPoints[i]), disclosedScalars));
    const T2 = mul(Bv, proof.challenge)
      .add(mul(proof.D, proof.r3Hat))
      .add(msm(undisclosed.map((j) => hPoints[j]), proof.commitments));

    const init: InitResult = { Abar: proof.Abar, Bbar: proof.Bbar, D: proof.D, T1, T2, domain };
    const expected = proofChallenge(init, disclosed, disclosedScalars, ph);
    if (expected !== proof.challenge) return false;

    // And that the re-randomised pair still sits under the issuer's key.
    const pairing = bls.pairingBatch([
      { g1: proof.Abar, g2: w },
      { g1: proof.Bbar, g2: BP2.negate() },
    ]);
    return bls.fields.Fp12.eql(pairing, bls.fields.Fp12.ONE);
  } catch {
    return false;
  }
}

export { expandMessageXmd };
