// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export { sign, verify, skToPk, octetsToSignature, signatureToOctets } from "./sign.js";
export type { Signature, SignOptions } from "./sign.js";
export { prove, verifyProof, octetsToProof, proofToOctets } from "./proof.js";
export type { Proof, ProveOptions, RandomScalars } from "./proof.js";
export {
  API_ID, P1_HEX, OCTET_SCALAR_LENGTH, OCTET_POINT_LENGTH, OCTET_POINT_G2_LENGTH,
  createGenerators, messagesToScalars, hashToScalar, expandMessageXmd, i2osp, os2ip, utf8,
} from "./ciphersuite.js";
export type { G1Point, G2Point } from "./ciphersuite.js";
