// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * At-rest protection for SSF push credentials.
 *
 * WHY. A push stream may carry an `authorization_header` — the receiver's own
 * bearer credential, which the registry presents on every push. Stored as
 * plain text, one database export or backup hands out every subscriber's
 * receiver credential. It cannot be hashed (it has to be replayed), so it is
 * sealed with AES-256-GCM instead.
 *
 * KEY. Derived with HKDF-SHA-256 from REGISTRY_SIGNING_KEY under its own
 * label, so the encryption key is never the signing key and one secret does
 * not have to be provisioned twice. The stream id is bound in as additional
 * data, so a sealed value copied onto another stream's row does not open.
 *
 * ROTATION. Each sealed value records a fingerprint of the key that sealed
 * it. After a rotation, values sealed under the old seed still open while it
 * is set as REGISTRY_SIGNING_KEY_PREVIOUS, and are re-sealed under the new
 * key the next time they are read (see `openPushCredential`'s `resealed`).
 *
 * FORMAT. `enc:v1:<fingerprint>:<iv b64url>:<ciphertext b64url>`. A value
 * without the prefix is a row written before this module existed and is
 * returned as-is, so those streams keep delivering until re-sealed.
 */

import { b64urlToBytes, bytesToB64url, parseSigningSeed, type RegistryKeyEnv } from "./registry-signing.js";

const PREFIX = "enc:v1:";
const HKDF_SALT = new TextEncoder().encode("aroha-registry/ssf");
const ENC_INFO = new TextEncoder().encode("aroha.ssf-push-credential/v1");
const FP_INFO = new TextEncoder().encode("aroha.ssf-push-credential/v1/fingerprint");

interface SealingKey {
  key: CryptoKey;
  fingerprint: string;
}

async function deriveFromSeed(seed: Uint8Array): Promise<SealingKey> {
  const ikm = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveKey", "deriveBits"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: ENC_INFO },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  // A separate HKDF output identifies the key without exposing anything
  // that helps recover it.
  const fp = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: FP_INFO }, ikm, 64),
  );
  return { key, fingerprint: [...fp].map((b) => b.toString(16).padStart(2, "0")).join("") };
}

async function sealingKeys(env: RegistryKeyEnv): Promise<{ current: SealingKey | null; previous: SealingKey | null }> {
  const cur = parseSigningSeed(env.REGISTRY_SIGNING_KEY);
  const prev = parseSigningSeed(env.REGISTRY_SIGNING_KEY_PREVIOUS);
  return {
    current: cur ? await deriveFromSeed(cur) : null,
    previous: prev ? await deriveFromSeed(prev) : null,
  };
}

function aad(streamId: string): Uint8Array {
  return new TextEncoder().encode(`aroha-ssf-stream:${streamId}`);
}

/**
 * Seal a receiver credential for storage. Throws when REGISTRY_SIGNING_KEY is
 * unset — the caller (stream creation) already refuses with 503 in that case,
 * so a credential is never stored unprotected.
 */
export async function sealPushCredential(env: RegistryKeyEnv, streamId: string, plaintext: string): Promise<string> {
  const { current } = await sealingKeys(env);
  if (!current) throw new Error("REGISTRY_SIGNING_KEY is not configured; refusing to store a push credential");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad(streamId) },
      current.key,
      new TextEncoder().encode(plaintext),
    ),
  );
  return `${PREFIX}${current.fingerprint}:${bytesToB64url(iv)}:${bytesToB64url(ct)}`;
}

export interface OpenedCredential {
  /** The receiver credential, or null when it cannot be opened. */
  value: string | null;
  /** A re-sealed value under the current key when the stored one used an older key or was legacy plaintext. */
  resealed?: string;
}

/**
 * Open a stored credential. Legacy plaintext is returned and offered for
 * re-sealing; a value sealed under the previous key opens and is re-sealed;
 * a value whose key is no longer configured, or that fails authentication,
 * opens to null and the push goes out without it (the receiver then refuses,
 * which the stream status records) rather than with a guessed credential.
 */
export async function openPushCredential(env: RegistryKeyEnv, streamId: string, stored: string | null): Promise<OpenedCredential> {
  if (stored === null || stored === "") return { value: null };
  const keys = await sealingKeys(env);
  if (!stored.startsWith(PREFIX)) {
    const resealed = keys.current ? await sealPushCredential(env, streamId, stored) : undefined;
    return { value: stored, ...(resealed ? { resealed } : {}) };
  }
  const parts = stored.slice(PREFIX.length).split(":");
  if (parts.length !== 3) return { value: null };
  const [fingerprint, ivB64, ctB64] = parts;
  const iv = b64urlToBytes(ivB64);
  const ct = b64urlToBytes(ctB64);
  if (!iv || !ct) return { value: null };
  const key =
    keys.current?.fingerprint === fingerprint ? keys.current : keys.previous?.fingerprint === fingerprint ? keys.previous : null;
  if (!key) return { value: null };
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad(streamId) }, key.key, ct);
    const value = new TextDecoder().decode(pt);
    if (key === keys.current) return { value };
    return { value, resealed: await sealPushCredential(env, streamId, value) };
  } catch {
    return { value: null };
  }
}
