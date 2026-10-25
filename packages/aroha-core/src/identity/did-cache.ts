// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DID Resolution Cache
 *
 * Wraps any PublicKeyResolver with an in-memory cache.
 *
 * Cache strategy by DID method:
 *   did:aroha:z...   Content-addressed (isContentAddressedDid) — permanent:
 *                    the public key IS the DID (base58 of key bytes).
 *   did:aroha:E...   Inception-based (kel.ts) — TTL-based (defaultTtlMs).
 *                    The DID is self-certifying but its key ROTATES (and can
 *                    be recovered or revoked), so it must never be cached
 *                    forever the way the z-form can. Long-lived verifiers
 *                    should prefer a KelStore over this cache for E-DIDs.
 *   did:aroha:<name> Named — TTL-based (defaultTtlMs). The key comes from a
 *                    registry and can rotate/be revoked, so caching it
 *                    forever (the old behaviour for every did:aroha:) would
 *                    keep trusting a revoked key indefinitely.
 *   did:aroha-web:   TTL-based — keys rotate with a 24-hour cooldown per spec.
 *                    Default TTL: 23h to stay just inside the rotation window.
 *   Other methods:   TTL-based with configurable default.
 *
 * At 1000 messages/second resolving 20 known agents, this eliminates
 * ~50,000 redundant base58 decodes and ~1,000 DNS+HTTPS fetches per second.
 */

import { isContentAddressedDid, fromMultibase } from "./did.js";

export interface DidCacheConfig {
  /** TTL for did:aroha-web: entries in ms. Default: 82_800_000 (23 hours) */
  webDidTtlMs?: number;
  /** TTL for unknown DID methods. Default: 300_000 (5 minutes) */
  defaultTtlMs?: number;
  /** Maximum number of entries before LRU eviction. Default: 1000 */
  maxSize?: number;
  /**
   * TTL for a DEFINITIVE not-found (the resolver threw DidNotFoundError).
   * Default: 60_000. A plain `null` from the resolver is never cached — it
   * cannot be told apart from a transient failure.
   */
  notFoundTtlMs?: number;
}

/**
 * Throw from a resolver to say "this DID definitively has no key" (e.g. a
 * registry 404), as opposed to returning null, which the cache treats as a
 * possibly-transient miss and does not remember.
 */
export class DidNotFoundError extends Error {
  readonly code = "DID_NOT_FOUND";
  constructor(did: string) {
    super(`DID not found: ${did}`);
    this.name = "DidNotFoundError";
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Resolve a sender's public key.
 *
 * `verificationMethodId` is the `proof.verificationMethod` named by the
 * envelope being verified (e.g. `did:aroha:x#device-2`). Resolvers backed
 * by a DID Document should pass it to `extractPublicKey(doc, id)` so DIDs
 * with several (device) keys verify against the key that actually signed.
 * Optional — single-key resolvers can ignore it.
 */
export type PublicKeyResolver = (
  senderDID: string,
  verificationMethodId?: string
) => Promise<Uint8Array | null>;

interface CacheEntry {
  key: Uint8Array | null;
  expiresAt: number; // Infinity for permanent entries
  lastUsed: number;
}

export class DidResolutionCache {
  private readonly webDidTtlMs: number;
  private readonly defaultTtlMs: number;
  private readonly maxSize: number;
  private readonly notFoundTtlMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(config: DidCacheConfig = {}) {
    this.webDidTtlMs   = config.webDidTtlMs   ?? 82_800_000; // 23h
    this.defaultTtlMs  = config.defaultTtlMs  ?? 300_000;    // 5m
    this.maxSize       = config.maxSize       ?? 1_000;
    this.notFoundTtlMs = config.notFoundTtlMs ?? 60_000;
  }

  /**
   * Wrap a resolver function with cache semantics.
   * The returned resolver is a drop-in replacement.
   */
  wrap(resolver: PublicKeyResolver): PublicKeyResolver {
    return async (did: string, verificationMethodId?: string): Promise<Uint8Array | null> => {
      // Cache per (DID, verification method) so a multi-key DID does not
      // answer every key id with whichever key was resolved first.
      const cacheKey = verificationMethodId ? `${did}\u0000${verificationMethodId}` : did;
      const cached = this.getByKey(cacheKey);
      if (cached !== undefined) return cached;

      // did:aroha:z… commits to its key: derive it locally. WHY: the cache
      // stores z-DID keys forever, so a resolver that returned a DIFFERENT
      // key (a compromised registry, a bug) would have been trusted
      // permanently. The DID's own primary key needs no resolver at all; a
      // resolver answer for another verification method is passed through
      // but cached only if it matches the derived key.
      const derived = isContentAddressedDid(did) ? fromMultibase(did.slice("did:aroha:".length)) : null;
      if (derived && !verificationMethodId) {
        this.setByKey(cacheKey, did, derived);
        return derived;
      }

      let key: Uint8Array | null;
      try {
        key = await resolver(did, verificationMethodId);
      } catch (err) {
        if (err instanceof DidNotFoundError) {
          this.setByKey(cacheKey, did, null, this.notFoundTtlMs);
          return null;
        }
        throw err; // transient failure: not cached
      }
      // A null may be a timeout or a 5xx dressed as "no key". Caching it
      // would lock the DID out for the whole TTL, so it is not remembered.
      if (key === null) return null;
      if (derived && !bytesEqual(key, derived)) return key;
      this.setByKey(cacheKey, did, key);
      return key;
    };
  }

  /** Manually populate the cache (e.g. from known agent registry). */
  set(did: string, key: Uint8Array | null): void {
    this.setByKey(did, did, key);
  }

  private setByKey(cacheKey: string, did: string, key: Uint8Array | null, ttlOverride?: number): void {
    if (this.cache.size >= this.maxSize && !this.cache.has(cacheKey)) this.evictLru();

    const ttl = ttlOverride ?? (key === null ? this.notFoundTtlMs : this.ttlFor(did));
    this.cache.set(cacheKey, {
      key,
      expiresAt: ttl === Infinity ? Infinity : Date.now() + ttl,
      lastUsed: Date.now(),
    });
  }

  /** Returns undefined on cache miss or expiry. */
  get(did: string): Uint8Array | null | undefined {
    return this.getByKey(did);
  }

  private getByKey(cacheKey: string): Uint8Array | null | undefined {
    const entry = this.cache.get(cacheKey);
    if (!entry) return undefined;
    if (entry.expiresAt !== Infinity && Date.now() > entry.expiresAt) {
      this.cache.delete(cacheKey);
      return undefined;
    }
    entry.lastUsed = Date.now();
    return entry.key;
  }

  /** Invalidate a specific DID (e.g. after a key rotation event). */
  invalidate(did: string): void {
    for (const k of [...this.cache.keys()]) {
      if (k === did || k.startsWith(`${did}\u0000`)) this.cache.delete(k);
    }
  }

  get size(): number {
    return this.cache.size;
  }

  private ttlFor(did: string): number {
    if (isContentAddressedDid(did)) {
      return Infinity; // key is encoded in the DID itself — never rotates
    }
    if (did.startsWith("did:aroha-web:")) {
      return this.webDidTtlMs;
    }
    return this.defaultTtlMs;
  }

  private evictLru(): void {
    let oldest: [string, CacheEntry] | null = null;
    for (const entry of this.cache.entries()) {
      if (!oldest || entry[1].lastUsed < oldest[1].lastUsed) {
        oldest = entry;
      }
    }
    if (oldest) this.cache.delete(oldest[0]);
  }
}
