// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 3 Signing
 *
 * Implements the signing rule from the spec:
 *   "The proof.proofValue MUST be the Ed25519 signature over the canonical
 *    JSON of the message with the proof field omitted, keys sorted
 *    lexicographically."
 *
 * This module is pure protocol infrastructure. It knows nothing about
 * what the message body contains or what the agent does with it.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MessageProof {
  type: "Ed25519Signature2020";
  created: string;
  verificationMethod: string; // did:aroha:<id>#key-1
  proofPurpose: "authentication";
  proofValue: string; // base64url-encoded Ed25519 signature
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign a Aroha message.
 * Returns a proof object to embed in the message envelope.
 *
 * @param message           Full message object (proof field will be excluded before signing)
 * @param privateKey        Ed25519 private key (32 bytes)
 * @param verificationMethodId  e.g. "did:aroha:my-agent#key-1"
 */
export async function signMessage(
  message: Record<string, unknown>,
  privateKey: Uint8Array,
  verificationMethodId: string
): Promise<MessageProof> {
  const canonical = canonicalizeMessage(message);
  const bytes = new TextEncoder().encode(canonical);
  const signature = await ed.signAsync(bytes, privateKey);

  return {
    type: "Ed25519Signature2020",
    created: new Date().toISOString(),
    verificationMethod: verificationMethodId,
    proofPurpose: "authentication",
    proofValue: Buffer.from(signature).toString("base64url"),
  };
}

/**
 * Verify a Aroha message signature.
 *
 * @param message    Full message object including the proof field
 * @param publicKey  Ed25519 public key (32 bytes) of the claimed sender
 * @returns          true if signature is valid, false otherwise
 */
export async function verifyMessageSignature(
  message: Record<string, unknown>,
  publicKey: Uint8Array
): Promise<boolean> {
  const proof = message.proof as MessageProof | undefined;
  if (!proof?.proofValue) return false;

  const canonical = canonicalizeMessage(message); // excludes proof
  const bytes = new TextEncoder().encode(canonical);

  try {
    const signature = Buffer.from(proof.proofValue, "base64url");
    return await ed.verifyAsync(signature, bytes, publicKey);
  } catch {
    return false;
  }
}

// ─── Low-level signing ────────────────────────────────────────────────────────
//
// signMessage()/verifyMessageSignature() always wrap the result in a full
// MessageProof (DID-document-shaped proof object) — the right choice for
// message envelopes, wrong for anything else that just needs "prove I hold
// this DID's key over this payload." A caller with a flat, one-off payload
// (e.g. proving control of a DID to an external API — no envelope, no proof
// block) previously had no supported way to get a bare signature without
// either reconstructing the wrapper and stripping it back out, or bypassing
// this package entirely and pulling in a second Ed25519 library just to get
// one step below what signMessage() offers. These two functions are that
// step: canonicalize + sign, canonicalize + verify, nothing else attached.

/** Hex-encoded 64-byte Ed25519 signature. */
export type HexSignature = string;

/**
 * Sign an arbitrary flat (or nested) payload's canonical JSON — no proof
 * wrapper, no envelope shape assumed. Use this when you need to prove
 * control of a DID's key over a caller-defined payload that isn't itself
 * a Aroha message envelope (e.g. an out-of-band API request).
 *
 * `canonicalizeMessage`'s "exclude proof" step is a no-op here as long as
 * `payload` has no top-level `proof` field, which holds for the flat
 * payloads this is meant for.
 */
export async function signCanonical(
  payload: Record<string, unknown>,
  privateKey: Uint8Array
): Promise<HexSignature> {
  const bytes = new TextEncoder().encode(canonicalizeMessage(payload));
  const signature = await ed.signAsync(bytes, privateKey);
  return Buffer.from(signature).toString("hex");
}

/**
 * Verify a signature produced by `signCanonical` against the same payload
 * and a claimed signer's public key.
 */
export async function verifyCanonicalSignature(
  payload: Record<string, unknown>,
  signatureHex: HexSignature,
  publicKey: Uint8Array
): Promise<boolean> {
  const bytes = new TextEncoder().encode(canonicalizeMessage(payload));
  try {
    const signature = Buffer.from(signatureHex, "hex");
    if (signature.length !== 64) return false;
    return await ed.verifyAsync(signature, bytes, publicKey);
  } catch {
    return false;
  }
}

// ─── Canonicalization ─────────────────────────────────────────────────────────

/**
 * Produce the canonical JSON string of a message for signing/verification.
 *
 * Per spec: exclude the "proof" field, sort all keys lexicographically
 * at every level of nesting.
 */
export function canonicalizeMessage(message: Record<string, unknown>): string {
  const { proof: _excluded, ...rest } = message;
  return JSON.stringify(sortKeysDeep(rest));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
