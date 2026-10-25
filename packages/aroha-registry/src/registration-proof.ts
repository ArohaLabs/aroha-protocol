// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Proof of key possession for POST /v1/agents.
 *
 * The registry (apps/registry-server, and this package's http-server) refuses
 * to register any DID except a rotatable did:aroha:E… unless the registrant
 * proves it holds the private key for the publicKeyB64 it submits:
 *
 *   1. POST /v1/agents/challenge { did }            → { nonce, expiresAt }
 *   2. sign UTF-8( JSON.stringify({ action: "prove-ownership", did, nonce }) )
 *      — key order exactly as written; it is the server's canonical string
 *   3. POST /v1/agents { did, manifestCID, publicKeyB64 (base64url),
 *                        challengeNonce, challengeSignature (base64url), … }
 *
 * WHY: without it an API key alone could bind any key to any DID — someone
 * else's DID, or a key the registrant does not hold. The message is distinct
 * from every other signed Aroha payload ("prove-ownership"), so a signature
 * over it cannot be replayed as anything else.
 */

import * as ed from "@noble/ed25519";
import { isContentAddressedDid, fromMultibase, isInceptionDid } from "@aroha-sdk/core/identity";

/** Either the raw 32-byte Ed25519 seed, or a callback that signs (for HSM/KMS-held keys). */
export type RegistrationSigner =
  | { privateKey: Uint8Array }
  | { sign: (message: Uint8Array) => Promise<Uint8Array> | Uint8Array };

/** The exact bytes the registry verifies the challenge signature over. */
export function registrationChallengeMessage(did: string, nonce: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did, nonce }));
}

/** True when registering `did` needs a challenge proof (every DID except did:aroha:E…). */
export function registrationNeedsProof(did: string): boolean {
  return !isInceptionDid(did);
}

/** Sign a registration challenge. Throws unless the result is a 64-byte Ed25519 signature. */
export async function signRegistrationChallenge(
  signer: RegistrationSigner,
  did: string,
  nonce: string
): Promise<Uint8Array> {
  const message = registrationChallengeMessage(did, nonce);
  const sig = "privateKey" in signer
    ? await ed.signAsync(message, signer.privateKey)
    : await signer.sign(message);
  if (!(sig instanceof Uint8Array) || sig.length !== 64) {
    throw new Error("Registration signer must return a 64-byte Ed25519 signature");
  }
  return sig;
}

/**
 * Client-side sanity checks the server would also make, run first so the
 * caller gets a precise error instead of a 400/403 after a round trip:
 *   - a did:aroha:z… must be registered with exactly the key it encodes;
 *   - a privateKey signer must actually hold `publicKey`.
 */
export async function assertRegistrationKey(
  did: string,
  publicKey: Uint8Array,
  signer?: RegistrationSigner
): Promise<void> {
  if (publicKey.length !== 32) throw new Error("publicKey must be a 32-byte Ed25519 public key");
  if (isContentAddressedDid(did)) {
    const encoded = fromMultibase(did.slice("did:aroha:".length));
    if (!bytesEqual(encoded, publicKey)) {
      throw new Error(`${did} is content-addressed and can only be registered with the key it encodes`);
    }
  }
  if (signer && "privateKey" in signer) {
    const derived = await ed.getPublicKeyAsync(signer.privateKey);
    if (!bytesEqual(derived, publicKey)) {
      throw new Error("Registration signer's private key does not match the publicKey being registered");
    }
  }
}

/** Verify a challenge signature (used by this package's http-server). */
export async function verifyRegistrationChallenge(
  did: string,
  nonce: string,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, registrationChallengeMessage(did, nonce), publicKey);
  } catch {
    return false;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
