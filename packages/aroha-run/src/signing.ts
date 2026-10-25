// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Request signing for `auth: "aroha-sig"` — proving *which agent* is calling.
 *
 * Bearer tokens are a shared secret: everyone who holds one is indistinguishable.
 * For private agents you need caller *identity*, so a signed request carries the
 * caller's DID and an Ed25519 signature the callee verifies against that DID's
 * registered public key.
 *
 * Signed material (newline-joined, order fixed):
 *
 *     METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA-256(body, hex)
 *
 * Headers:
 *     X-Aroha-Did         did:aroha:caller
 *     X-Aroha-Timestamp   ISO-8601
 *     X-Aroha-Nonce       unique per request
 *     X-Aroha-Signature   base64url(Ed25519 signature)
 *
 * Binding the method, path, and a hash of the body means a captured signature
 * cannot be replayed against a different endpoint or with altered content; the
 * timestamp bounds the replay window.
 *
 * Zero dependencies: Ed25519 comes from WebCrypto, available in Node 22+,
 * Cloudflare Workers, Deno, and Bun.
 */

import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";

export const SIG_HEADERS = {
  did: "x-aroha-did",
  timestamp: "x-aroha-timestamp",
  nonce: "x-aroha-nonce",
  signature: "x-aroha-signature",
} as const;

/** Default tolerance for clock skew between caller and callee. */
export const DEFAULT_MAX_SKEW_MS = 5 * 60 * 1000;

/**
 * Copy into a freshly-allocated ArrayBuffer.
 * A Uint8Array may be backed by a SharedArrayBuffer, which WebCrypto's
 * BufferSource type rejects; this normalises it at every crypto boundary.
 */
function buf(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

function pkcs8FromSeed(privateKey: Uint8Array): Uint8Array {
  return privateKey.length === 32
    ? new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20, ...privateKey,
      ])
    : privateKey;
}

/** Ed25519-sign raw bytes with a 32-byte seed (or PKCS#8 key). */
export async function signBytes(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("pkcs8", buf(pkcs8FromSeed(privateKey)), { name: "Ed25519" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, buf(message)));
}

/** The raw 32-byte Ed25519 public key for a 32-byte seed (or PKCS#8 key). */
export async function publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("pkcs8", buf(pkcs8FromSeed(privateKey)), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (typeof jwk.x !== "string") throw new Error("could not derive the Ed25519 public key");
  return fromBase64Url(jwk.x);
}

/** base64url without padding. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return toBase64Url(bytes);
}

/** Decode a base64 (standard or url) Ed25519 key into raw bytes. */
export function decodeKey(key: string | Uint8Array): Uint8Array {
  if (typeof key !== "string") return key;
  return fromBase64Url(key);
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buf(new TextEncoder().encode(input)));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Build the exact string that gets signed. Callers and verifiers must agree byte-for-byte. */
export async function canonicalString(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): Promise<string> {
  return [method.toUpperCase(), path, timestamp, nonce, await sha256Hex(body)].join("\n");
}

/**
 * Sign a request as `did`. Returns headers to merge into your fetch call.
 *
 * @param privateKey Raw 32-byte Ed25519 seed, or a PKCS#8 key.
 */
export async function signRequest(opts: {
  did: string;
  privateKey: Uint8Array;
  method: string;
  path: string;
  body?: string;
  timestamp?: string;
  nonce?: string;
}): Promise<Record<string, string>> {
  const timestamp = opts.timestamp ?? new Date().toISOString();
  const nonce = opts.nonce ?? crypto.randomUUID();
  const canonical = await canonicalString(opts.method, opts.path, timestamp, nonce, opts.body ?? "");

  // A raw 32-byte seed must be wrapped in a minimal PKCS#8 envelope for WebCrypto.
  const pkcs8 =
    opts.privateKey.length === 32
      ? new Uint8Array([
          0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
          0x04, 0x22, 0x04, 0x20, ...opts.privateKey,
        ])
      : opts.privateKey;

  const key = await crypto.subtle.importKey("pkcs8", buf(pkcs8), { name: "Ed25519" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, buf(new TextEncoder().encode(canonical)));

  return {
    [SIG_HEADERS.did]: opts.did,
    [SIG_HEADERS.timestamp]: timestamp,
    [SIG_HEADERS.nonce]: nonce,
    [SIG_HEADERS.signature]: toBase64Url(new Uint8Array(sig)),
  };
}

export interface VerifyResult {
  ok: boolean;
  /** The verified caller DID — only trustworthy when ok is true. */
  did?: string;
  reason?: string;
}

/**
 * Verify a signed request. Fails closed on every ambiguity: missing headers,
 * stale timestamp, unknown DID, unresolvable key, or bad signature.
 *
 * @param resolvePublicKey Maps a caller DID to its raw Ed25519 public key.
 *   Return null for unknown DIDs — the request is then rejected.
 */
export async function verifySignedRequest(opts: {
  headers: Headers | Record<string, string | undefined>;
  method: string;
  path: string;
  body?: string;
  resolvePublicKey: (did: string) => Promise<Uint8Array | null> | Uint8Array | null;
  allowedCallers?: string[];
  maxSkewMs?: number;
  /** Optional replay guard — return false if this (did, nonce) was already used. */
  consumeNonce?: (did: string, nonce: string) => Promise<boolean> | boolean;
}): Promise<VerifyResult> {
  const get = (name: string): string | undefined =>
    opts.headers instanceof Headers
      ? (opts.headers.get(name) ?? undefined)
      : (opts.headers[name] ?? opts.headers[name.toLowerCase()] ?? undefined);

  const did = get(SIG_HEADERS.did);
  const timestamp = get(SIG_HEADERS.timestamp);
  const nonce = get(SIG_HEADERS.nonce);
  const signature = get(SIG_HEADERS.signature);

  if (!did || !timestamp || !nonce || !signature) {
    return { ok: false, reason: "Missing signature headers" };
  }

  // Allow-list first: never spend verification work on a caller we'd reject,
  // and never reveal whether an unknown DID has a resolvable key.
  if (opts.allowedCallers && !opts.allowedCallers.includes(did)) {
    return { ok: false, reason: "Caller not permitted" };
  }

  const ts = Date.parse(timestamp);
  if (Number.isNaN(ts)) return { ok: false, reason: "Malformed timestamp" };
  const skew = Math.abs(Date.now() - ts);
  if (skew > (opts.maxSkewMs ?? DEFAULT_MAX_SKEW_MS)) {
    return { ok: false, reason: "Timestamp outside the accepted window" };
  }

  let publicKey: Uint8Array | null;
  try {
    publicKey = await opts.resolvePublicKey(did);
  } catch {
    return { ok: false, reason: "Could not resolve caller key" };
  }
  if (!publicKey || publicKey.length !== 32) {
    return { ok: false, reason: "Unknown caller key" };
  }

  const canonical = await canonicalString(opts.method, opts.path, timestamp, nonce, opts.body ?? "");
  let valid = false;
  try {
    const key = await crypto.subtle.importKey("raw", buf(publicKey), { name: "Ed25519" }, false, ["verify"]);
    valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      buf(fromBase64Url(signature)),
      buf(new TextEncoder().encode(canonical)),
    );
  } catch {
    return { ok: false, reason: "Signature verification error" };
  }
  if (!valid) return { ok: false, reason: "Invalid signature" };

  // Replay guard runs last: only burn a nonce for an otherwise-valid request.
  if (opts.consumeNonce && !(await opts.consumeNonce(did, nonce))) {
    return { ok: false, reason: "Replayed nonce" };
  }

  return { ok: true, did };
}

/**
 * In-memory replay guard, suitable for a single long-lived process.
 * Multi-instance deployments should back this with a shared store.
 */
export function createNonceGuard(windowMs = DEFAULT_MAX_SKEW_MS) {
  const seen = new Map<string, number>();
  return (did: string, nonce: string): boolean => {
    const now = Date.now();
    for (const [k, t] of seen) if (now - t > windowMs) seen.delete(k);
    const key = `${did}:${nonce}`;
    if (seen.has(key)) return false;
    seen.set(key, now);
    return true;
  };
}

/**
 * Resolve caller public keys from the Aroha registry, with a small
 * TTL-bounded cache.
 *
 * Both hit and miss entries expire. Without a TTL, a DID that resolves to
 * `null` the first time it's looked up (e.g. because the caller registered
 * itself moments after this resolver's first request for it) stays
 * permanently unresolvable for the lifetime of the process — every
 * subsequent request from that caller fails signature verification with no
 * way to recover short of a restart. Misses get a shorter TTL than hits
 * (registration completing is the more likely near-term change); hits still
 * expire so key rotation eventually propagates rather than never.
 */
export function registryKeyResolver(
  registryOverride?: string,
): (did: string) => Promise<Uint8Array | null> {
  const registryUrl = resolveRegistryUrl(registryOverride);
  const HIT_TTL_MS = 5 * 60_000;
  const MISS_TTL_MS = 30_000;
  const cache = new Map<string, { value: Uint8Array | null; expiresAt: number }>();

  return async (did: string) => {
    const cached = cache.get(did);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    try {
      const res = await fetch(`${registryUrl}/v1/agents/${encodeURIComponent(did)}`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        cache.set(did, { value: null, expiresAt: Date.now() + MISS_TTL_MS });
        return null;
      }
      const record = (await res.json()) as { publicKeyB64?: string };
      const key = record.publicKeyB64 ? decodeKey(record.publicKeyB64) : null;
      cache.set(did, { value: key, expiresAt: Date.now() + (key ? HIT_TTL_MS : MISS_TTL_MS) });
      return key;
    } catch {
      return null;   // not cached — a transient failure shouldn't poison the cache
    }
  };
}
