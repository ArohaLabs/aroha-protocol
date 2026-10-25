// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The one base64 decoder for keys and signatures arriving over HTTP.
 *
 * Two encodings reach this registry for the same field: @aroha-sdk/registry's
 * ArohaHttpRegistry sends `publicKeyB64` as unpadded base64url (and the
 * OpenAPI contract has always said base64url), while Studio, the CLI and
 * most tests send standard padded base64. Routes used to decode with a bare
 * `atob`, which throws on `-` / `_` — so an agent registered through the SDK
 * stored a key that rotate-key, relay connect and caller-signature checks
 * then could not read.
 *
 * base64url (RFC 4648 §5, unpadded) is the canonical, documented encoding;
 * standard base64 (§4, padded or not) is accepted everywhere too. The stored
 * string is kept as submitted, so a response echoes the encoding the key
 * was registered with — every server-side reader goes through this decoder.
 */

const B64_ANY = /^[A-Za-z0-9+/_-]*={0,2}$/;

/** Decode standard base64 or base64url, padded or not. null on anything malformed. */
export function decodeB64(input: unknown): Uint8Array | null {
  if (typeof input !== "string" || !B64_ANY.test(input)) return null;
  // Mixing the two alphabets in one string is not something either encoder
  // produces; refusing it keeps one byte string from having two spellings
  // that a naive string comparison would treat as different keys.
  if (/[+/]/.test(input) && /[-_]/.test(input)) return null;
  const unpadded = input.replace(/=+$/, "");
  if (unpadded.length % 4 === 1) return null;
  const std = unpadded.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

/** A raw Ed25519 public key: decodes AND is exactly 32 bytes. */
export function decodeEd25519PublicKey(input: unknown): Uint8Array | null {
  const bytes = decodeB64(input);
  return bytes && bytes.length === 32 ? bytes : null;
}

/** Constant-shape byte comparison (keys are public; this is about correctness, not timing). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
