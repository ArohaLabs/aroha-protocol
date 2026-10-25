// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * BLS12-381-SHA-256 ciphersuite primitives for BBS signatures
 * (draft-irtf-cfrg-bbs-signatures).
 *
 * Every constant and every algorithm here is defined by the draft, not chosen
 * by us. Where this file looks arbitrary — the exact DST suffixes, the
 * hardcoded P1, expanding to 48 octets rather than 32 — it is transcribing a
 * specification, and the vector tests are what prove the transcription is
 * faithful. Changing any string in this file changes the wire format and
 * breaks interoperability with every other implementation.
 */

import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";

export type G1Point = InstanceType<typeof bls.G1.ProjectivePoint>;
export type G2Point = InstanceType<typeof bls.G2.ProjectivePoint>;

export const Fr = bls.fields.Fr;
export const R = Fr.ORDER;

/** Compressed point lengths, fixed by the curve. */
export const OCTET_POINT_LENGTH = 48;
export const OCTET_POINT_G2_LENGTH = 96;
export const OCTET_SCALAR_LENGTH = 32;

/**
 * The interface identifier, which prefixes every domain separation tag.
 *
 * "H2G_HM2S_" names the interface's two choices — generators by hash-to-curve,
 * messages to scalars by hash — and is part of the string, not a comment
 * about it.
 */
export const API_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

const te = new TextEncoder();
export const utf8 = (s: string): Uint8Array => te.encode(s);

/**
 * P1, a fixed generator that is deliberately NOT the curve's standard base
 * point: it is a nothing-up-my-sleeve point from the draft, so that no party
 * knows its discrete log relative to the message generators.
 */
export const P1_HEX =
  "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

export const P1: G1Point = bls.G1.ProjectivePoint.fromHex(P1_HEX);
/** The G2 base point, written BP2 in the draft. */
export const BP2: G2Point = bls.G2.ProjectivePoint.BASE;

/**
 * How many octets hash_to_scalar expands to before reducing mod r.
 *
 * 48, not 32: reducing 32 octets mod r would leave a small but real bias
 * toward low scalars, because 2^256 is not a multiple of r. The extra 128
 * bits make the bias negligible. This is the draft's value and the reason
 * for it.
 */
const EXPAND_LEN = 48;

/** RFC 9380 expand_message_xmd with SHA-256. */
export function expandMessageXmd(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  const b_in_bytes = 32;
  const r_in_bytes = 64;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (ell > 255 || lenInBytes > 65535 || dst.length > 255) {
    throw new Error("expand_message_xmd: parameters out of range");
  }
  const dstPrime = concatBytes(dst, i2osp(dst.length, 1));
  const zPad = new Uint8Array(r_in_bytes);
  const b0 = sha256(concatBytes(zPad, msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstPrime));

  const bs: Uint8Array[] = [sha256(concatBytes(b0, i2osp(1, 1), dstPrime))];
  for (let i = 2; i <= ell; i++) {
    bs.push(sha256(concatBytes(strxor(b0, bs[i - 2]), i2osp(i, 1), dstPrime)));
  }
  return concatBytes(...bs).slice(0, lenInBytes);
}

function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** Big-endian integer to fixed-width octets. */
export function i2osp(value: number | bigint, length: number): Uint8Array {
  let v = BigInt(value);
  if (v < 0n) throw new Error("i2osp: negative");
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("i2osp: value does not fit");
  return out;
}

/** Octets to big-endian integer. */
export function os2ip(octets: Uint8Array): bigint {
  let v = 0n;
  for (const byte of octets) v = (v << 8n) | BigInt(byte);
  return v;
}

/**
 * hash_to_scalar — expand, then reduce mod r.
 *
 * The draft's version never returns zero for any realistic input; it is not
 * rejection-sampled, so this does not loop.
 */
export function hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
  return os2ip(expandMessageXmd(msg, dst, EXPAND_LEN)) % R;
}

/** DSTs, each the interface id plus the draft's suffix for that operation. */
export const H2S_DST = utf8(`${API_ID}H2S_`);
export const MAP_MSG_DST = utf8(`${API_ID}MAP_MSG_TO_SCALAR_AS_HASH_`);
const SEED_DST = utf8(`${API_ID}SIG_GENERATOR_SEED_`);
const GENERATOR_DST = utf8(`${API_ID}SIG_GENERATOR_DST_`);
const GENERATOR_SEED = utf8(`${API_ID}MESSAGE_GENERATOR_SEED`);

/**
 * Deterministic generators: Q_1 followed by one per message slot.
 *
 * Chained rather than indexed independently — each seed is the expansion of
 * the previous one — so the whole sequence is reproducible by any verifier
 * from the ciphersuite alone. Nobody transmits generators, and nobody has to
 * be trusted to have picked them honestly.
 */
export function createGenerators(count: number): G1Point[] {
  const out: G1Point[] = [];
  let v = expandMessageXmd(GENERATOR_SEED, SEED_DST, EXPAND_LEN);
  for (let i = 1; i <= count; i++) {
    v = expandMessageXmd(concatBytes(v, i2osp(i, 8)), SEED_DST, EXPAND_LEN);
    out.push(hashToG1(v, GENERATOR_DST));
  }
  return out;
}

export function hashToG1(msg: Uint8Array, dst: Uint8Array): G1Point {
  const p = bls.G1.hashToCurve(msg, { DST: dst });
  return bls.G1.ProjectivePoint.fromAffine(p.toAffine());
}

/** Map raw message octets to scalars — the messages BBS actually signs. */
export function messagesToScalars(messages: Uint8Array[]): bigint[] {
  return messages.map((m) => hashToScalar(m, MAP_MSG_DST));
}

/**
 * The draft's `serialize`: a heterogeneous array flattened to octets.
 *
 * Points compress, scalars take 32 octets, plain integers take 8. Lengths are
 * fixed per type rather than delimited, so a reader who knows the schema can
 * parse it and nothing else can be confused for something it isn't.
 */
export type SerializableItem = G1Point | G2Point | { scalar: bigint } | { uint: number | bigint } | Uint8Array;

export function serialize(items: SerializableItem[]): Uint8Array {
  const parts = items.map((item) => {
    if (item instanceof Uint8Array) return item;
    if ("scalar" in item) return i2osp(item.scalar, OCTET_SCALAR_LENGTH);
    if ("uint" in item) return i2osp(item.uint, 8);
    return item.toRawBytes(true);
  });
  return concatBytes(...parts);
}

/**
 * calculate_domain — binds a signature to the public key, the exact generator
 * set, and the header.
 *
 * Without this a signature over the same messages would verify under a
 * different generator count or a different header, which is how message
 * re-binding attacks work.
 */
export function calculateDomain(
  pk: Uint8Array,
  q1: G1Point,
  hPoints: G1Point[],
  header: Uint8Array,
): bigint {
  const domOcts = concatBytes(
    serialize([{ uint: hPoints.length }, q1, ...hPoints]),
    utf8(API_ID),
  );
  const domInput = concatBytes(pk, domOcts, i2osp(header.length, 8), header);
  return hashToScalar(domInput, H2S_DST);
}

export { bls };
