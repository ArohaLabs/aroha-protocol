// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The registry's own signing key — the one place REGISTRY_SIGNING_KEY is read.
 *
 * WHY THE REGISTRY SIGNS. Several answers this Worker gives are evidence
 * other parties rely on later, away from this connection (Shared Signals
 * SETs and agent monitoring summaries are signed for the same reason as the
 * two below):
 *
 *   • audit anchors (routes/audit-anchors.ts) — a runtime's signed audit head,
 *     witnessed and timestamped by a party other than the runtime, so a later
 *     rewrite of that runtime's log is detectable against the witness record;
 *   • revocation status (GET /v1/mandates/:id/revoked) — the answer that
 *     decides whether a payment mandate is still honoured.
 *
 * Unsigned, both are only as trustworthy as the transport that carried them
 * and whatever cache or proxy sat in between. Signed with a key published at
 * /.well-known/aroha-registry-keys.json, a verifier that pins that key can
 * check them offline and after the fact.
 *
 * KEY FORMAT. A 32-byte Ed25519 seed, as 64 hex characters or 43 base64url
 * characters (padding tolerated). Anything else is a configuration error.
 *
 * FAIL CLOSED. An unset or malformed REGISTRY_SIGNING_KEY never falls back to
 * a derived or built-in key: the routes that need it answer 503 with the fixed
 * message below, so a misconfigured deployment is visible to its operator
 * instead of quietly serving unsigned (or attacker-predictable) answers.
 *
 * ROTATION. Set the new seed as REGISTRY_SIGNING_KEY and the old one as
 * REGISTRY_SIGNING_KEY_PREVIOUS. Only the current key signs; the previous one
 * is still published (marked `retired: true`) so signatures made before the
 * rotation — audit anchors are permanent — keep verifying. Revocation-status
 * signatures are short-lived (verifiers check freshness), so verifiers should
 * accept only non-retired keys for those.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex } from "@noble/hashes/utils";
import { canonicalizeJcs } from "@aroha-sdk/credentials/mandates";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** Fixed body for a deployment with no usable signing key — no detail about why. */
export const REGISTRY_SIGNING_UNCONFIGURED_MESSAGE = "Registry signing is not configured on this deployment";

/**
 * What the one registry key signs. "ssf-set": Shared Signals Security Event
 * Tokens (ssf.ts, also published as a JWKS at /.well-known/jwks.json);
 * "agent-monitoring": GET /v1/agents/:didHash/monitoring summaries.
 */
export type RegistryKeyPurpose = "audit-anchor" | "revocation-status" | "ssf-set" | "agent-monitoring";
export const REGISTRY_KEY_PURPOSES: readonly RegistryKeyPurpose[] = [
  "audit-anchor", "revocation-status", "ssf-set", "agent-monitoring",
];

export interface RegistrySigningKey {
  keyId: string;
  publicKey: Uint8Array;
  seed: Uint8Array;
}

/** Published entry in /.well-known/aroha-registry-keys.json. */
export interface PublishedRegistryKey {
  keyId: string;
  publicKeyB64: string;
  purpose: RegistryKeyPurpose[];
  retired?: true;
}

export function bytesToB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToBytes(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

/** A 32-byte seed from 64 hex chars or base64url; null for anything else. */
export function parseSigningSeed(raw: string | undefined | null): Uint8Array | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    return Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
  }
  const bytes = b64urlToBytes(s);
  return bytes && bytes.length === 32 ? bytes : null;
}

/** First 16 hex characters of SHA-256(publicKey) — stable, short, and not secret. */
export function registryKeyId(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey)).slice(0, 16);
}

// Deriving a public key is cheap but not free; cache per seed string so each
// request does not repeat it. Keyed by the secret's value, so a rotation
// (new value) is picked up without a redeploy of code.
const keyCache = new Map<string, RegistrySigningKey>();

function keyFrom(raw: string | undefined): RegistrySigningKey | null {
  if (typeof raw !== "string") return null;
  const cached = keyCache.get(raw);
  if (cached) return cached;
  const seed = parseSigningSeed(raw);
  if (!seed) return null;
  const publicKey = ed.getPublicKey(seed);
  const key = { keyId: registryKeyId(publicKey), publicKey, seed };
  if (keyCache.size > 8) keyCache.clear();
  keyCache.set(raw, key);
  return key;
}

export interface RegistryKeyEnv {
  REGISTRY_SIGNING_KEY?: string;
  REGISTRY_SIGNING_KEY_PREVIOUS?: string;
}

/** The current signing key, or null when unset/malformed (callers answer 503). */
export function currentSigningKey(env: RegistryKeyEnv): RegistrySigningKey | null {
  const key = keyFrom(env.REGISTRY_SIGNING_KEY);
  if (!key && env.REGISTRY_SIGNING_KEY !== undefined) {
    console.error("[registry-signing] REGISTRY_SIGNING_KEY is not a 32-byte Ed25519 seed (hex or base64url) — signed routes are refusing every request");
  }
  return key;
}

/**
 * The key document. Null when there is no usable current key — publishing
 * only a retired key would invite verifiers to pin something no longer used.
 * A malformed PREVIOUS key is left out (and logged) rather than blocking the
 * current one: old signatures then stop verifying, which the operator sees,
 * but new ones keep flowing.
 */
export function publishedKeys(env: RegistryKeyEnv): PublishedRegistryKey[] | null {
  const current = currentSigningKey(env);
  if (!current) return null;
  const keys: PublishedRegistryKey[] = [
    { keyId: current.keyId, publicKeyB64: bytesToB64url(current.publicKey), purpose: [...REGISTRY_KEY_PURPOSES] },
  ];
  if (env.REGISTRY_SIGNING_KEY_PREVIOUS !== undefined && env.REGISTRY_SIGNING_KEY_PREVIOUS !== "") {
    const previous = keyFrom(env.REGISTRY_SIGNING_KEY_PREVIOUS);
    if (!previous) {
      console.error("[registry-signing] REGISTRY_SIGNING_KEY_PREVIOUS is malformed — not published");
    } else if (previous.keyId !== current.keyId) {
      keys.push({
        keyId: previous.keyId,
        publicKeyB64: bytesToB64url(previous.publicKey),
        purpose: [...REGISTRY_KEY_PURPOSES],
        retired: true,
      });
    }
  }
  return keys;
}

/** base64url Ed25519 signature over RFC 8785 JCS of `value`. */
export function signJcs(value: unknown, key: RegistrySigningKey): string {
  return bytesToB64url(ed.sign(new TextEncoder().encode(canonicalizeJcs(value)), key.seed));
}

/** SHA-256 hex of RFC 8785 JCS of `value`. */
export function jcsSha256Hex(value: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalizeJcs(value))));
}

/**
 * Compact JWS (RFC 7515) with alg EdDSA (RFC 8037) under the registry key.
 * Used for Shared Signals SETs; `header` adds to { alg, kid }.
 */
export function signCompactJws(header: Record<string, unknown>, payload: unknown, key: RegistrySigningKey): string {
  const enc = new TextEncoder();
  const h = bytesToB64url(enc.encode(JSON.stringify({ alg: "EdDSA", kid: key.keyId, ...header })));
  const p = bytesToB64url(enc.encode(JSON.stringify(payload)));
  const sig = ed.sign(enc.encode(`${h}.${p}`), key.seed);
  return `${h}.${p}.${bytesToB64url(sig)}`;
}

/** The published keys as a JWK Set (RFC 7517 / RFC 8037 OKP keys); null when unconfigured. */
export function publishedJwks(env: RegistryKeyEnv): { keys: Array<Record<string, string>> } | null {
  const keys = publishedKeys(env);
  if (!keys) return null;
  return {
    keys: keys.map((k) => ({ kty: "OKP", crv: "Ed25519", x: k.publicKeyB64, kid: k.keyId, use: "sig", alg: "EdDSA" })),
  };
}
