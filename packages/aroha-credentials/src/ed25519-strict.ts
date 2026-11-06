// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * One Ed25519 verification rule for every mandate signature.
 *
 * WHY. The library's default follows ZIP 215, which accepts encodings RFC 8032
 * does not, and it multiplies by the cofactor. OpenSSL, which the Python SDK
 * uses, does neither. On an ordinary key the two agree. On a small-order key
 * they do not, and with the identity point as the key a signature verifies
 * for EVERY message, so anyone could sign as that identity. Verification here
 * is RFC 8032 strict, and small-order keys are refused outright, in both SDKs.
 *
 * Imports only @noble/*, so it is safe in the Worker entry.
 */

import * as ed from "@noble/ed25519";

/** Small-order points and their non-canonical spellings, as lower-case hex. */
const WEAK_KEYS = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

/** True when `publicKey` is a small-order point, which no real key is. */
export function isWeakEd25519Key(publicKey: Uint8Array): boolean {
  return WEAK_KEYS.has(Buffer.from(publicKey).toString("hex"));
}

/** RFC 8032 strict verification. Refuses a small-order key. May throw on malformed input. */
export async function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  if (isWeakEd25519Key(publicKey)) return false;
  return ed.verifyAsync(signature, message, publicKey, { zip215: false });
}
