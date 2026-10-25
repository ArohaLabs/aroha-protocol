// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 3 Encryption
 *
 * Implements the spec rule:
 *   "For sensitive body fields, senders SHOULD encrypt using DIDComm v2 JWE
 *    with the recipient's public key."
 *
 * Uses X25519 ECDH for key agreement + AES-256-GCM for content encryption.
 * This is a protocol-level primitive. It does not know what is being encrypted
 * or why — that is the application's concern.
 */

import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";
import { randomBytes, concatBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EncryptedBody {
  /** Algorithm identifier */
  alg: "ECDH-ES+A256GCM";
  /** Base64url-encoded ephemeral X25519 public key */
  epk: string;
  /** Base64url-encoded IV (12 bytes for AES-GCM) */
  iv: string;
  /** Base64url-encoded ciphertext */
  ciphertext: string;
  /** Base64url-encoded AES-GCM authentication tag (16 bytes) */
  tag: string;
}

// ─── Encrypt ──────────────────────────────────────────────────────────────────

/**
 * Encrypt a message body for a specific recipient.
 *
 * @param plaintext        The body object to encrypt (will be JSON-serialized)
 * @param recipientPubKey  Recipient's Ed25519 public key (32 bytes).
 *                         We convert it to X25519 for ECDH.
 */
export async function encryptBody(
  plaintext: Record<string, unknown>,
  recipientPubKey: Uint8Array
): Promise<EncryptedBody> {
  // Convert Ed25519 pubkey to X25519 for key exchange
  const recipientX25519 = ed25519PubKeyToX25519(recipientPubKey);

  // Generate ephemeral X25519 keypair
  const ephemeralPriv = x25519.utils.randomPrivateKey();
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv);

  // ECDH shared secret
  const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientX25519);

  // Derive AES-256-GCM key from shared secret via SHA-256
  const aesKey = sha256(sharedSecret);

  // Encrypt with AES-256-GCM
  const iv = randomBytes(12);
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext));
  const { ciphertext, tag } = await aesGcmEncrypt(aesKey, iv, plaintextBytes);

  return {
    alg: "ECDH-ES+A256GCM",
    epk: Buffer.from(ephemeralPub).toString("base64url"),
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(ciphertext).toString("base64url"),
    tag: Buffer.from(tag).toString("base64url"),
  };
}

// ─── Decrypt ──────────────────────────────────────────────────────────────────

/**
 * Decrypt an encrypted message body.
 *
 * @param encrypted     The EncryptedBody from the message
 * @param privateKey    Recipient's Ed25519 private key (32 bytes)
 */
export async function decryptBody(
  encrypted: EncryptedBody,
  privateKey: Uint8Array
): Promise<Record<string, unknown>> {
  // Convert Ed25519 private key to X25519
  const x25519Priv = ed25519PrivKeyToX25519(privateKey);

  const ephemeralPub = Buffer.from(encrypted.epk, "base64url");
  const sharedSecret = x25519.getSharedSecret(x25519Priv, ephemeralPub);
  const aesKey = sha256(sharedSecret);

  const iv = Buffer.from(encrypted.iv, "base64url");
  const ciphertext = Buffer.from(encrypted.ciphertext, "base64url");
  const tag = Buffer.from(encrypted.tag, "base64url");

  const plaintext = await aesGcmDecrypt(aesKey, iv, ciphertext, tag);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ─── Key Conversion ───────────────────────────────────────────────────────────
// Ed25519 keys can be converted to X25519 (Curve25519) via the birational map
// between the two curve models. @noble/curves implements the correct conversion.

function ed25519PubKeyToX25519(edPub: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPub(edPub);
}

function ed25519PrivKeyToX25519(edPriv: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPriv(edPriv);
}

// ─── AES-256-GCM (Web Crypto API) ────────────────────────────────────────────

async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    cryptoKey,
    plaintext
  );

  const buf = new Uint8Array(encrypted);
  const ciphertext = buf.slice(0, buf.length - 16);
  const tag = buf.slice(buf.length - 16);
  return { ciphertext, tag };
}

async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const combined = concatBytes(ciphertext, tag);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    cryptoKey,
    combined
  );

  return new Uint8Array(decrypted);
}
