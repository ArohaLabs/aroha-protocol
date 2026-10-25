// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Nonce Registry
 *
 * Implements the spec rule:
 *   "A receiving agent MUST reject any message where nonce has been seen before
 *    (replay attack)"
 *
 * Nonces are stored with a TTL equal to the message's expires window.
 * After a nonce expires it is automatically evicted to bound memory usage.
 *
 * This is protocol infrastructure. It has no knowledge of message contents.
 */

// ─── NonceStore interface ─────────────────────────────────────────────────────

/**
 * Pluggable nonce deduplication backend.
 *
 * Default: MapNonceStore (in-process, forgotten on restart). Recommended:
 *   - single instance → `FileNonceStore` (./file-nonce-store.ts, exported
 *     from the package root) so a restart does not reopen the replay window
 *     for envelopes that have not yet expired;
 *   - multiple instances → a shared store (e.g. Redis `SET NX PXAT`).
 *
 * Keys passed by `validateEnvelope` are sender-scoped (`<fromDID>:<nonce>`)
 * and are only recorded AFTER the envelope's signature verified, so
 * unauthenticated traffic cannot fill the store or pre-burn a nonce.
 */
export interface NonceStore {
  /**
   * Record a nonce and return true if it is fresh (first seen).
   * Returns false if the nonce was already recorded (replay).
   * expiryMs is the absolute expiry timestamp in milliseconds.
   */
  setIfAbsent(nonce: string, expiryMs: number): Promise<boolean>;
  evictExpired(): Promise<void>;
}

// ─── Default in-process store ─────────────────────────────────────────────────

export interface MapNonceStoreOptions {
  /** Entry cap. Default 100 000. */
  maxEntries?: number;
}

export class MapNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(options: MapNonceStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 100_000;
  }

  async setIfAbsent(nonce: string, expiryMs: number): Promise<boolean> {
    return this.setIfAbsentSync(nonce, expiryMs);
  }

  /**
   * Synchronous form, used by NonceRegistry.check(). Same semantics.
   *
   * Bounded: past maxEntries, expired entries are dropped first, then the
   * entry that expires SOONEST. WHY that one: it is the nonce whose replay
   * window is closest to closing on its own, so forgetting it reopens the
   * least. The cap exists because the map was unbounded — every accepted
   * envelope's nonce is held until expiry, so sustained signed traffic (or
   * a signer flooding it) grew memory without limit. A deployment that must
   * never forget a live nonce should size maxEntries for its peak rate ×
   * max envelope TTL, or use a persistent/shared NonceStore.
   */
  setIfAbsentSync(nonce: string, expiryMs: number): boolean {
    // A NaN expiry would never be evicted (NaN < now is false) — refuse it.
    if (!Number.isFinite(expiryMs)) return false;
    if (this.seen.has(nonce)) return false;
    if (this.seen.size >= this.maxEntries) {
      this.evictExpiredSync();
      if (this.seen.size >= this.maxEntries) this.evictSoonestExpiring();
    }
    this.seen.set(nonce, expiryMs);
    return true;
  }

  private evictExpiredSync(): void {
    const now = Date.now();
    for (const [nonce, expiryMs] of this.seen) {
      if (expiryMs < now) this.seen.delete(nonce);
    }
  }

  private evictSoonestExpiring(): void {
    let victim: string | undefined;
    let soonest = Infinity;
    for (const [nonce, expiryMs] of this.seen) {
      if (expiryMs < soonest) { soonest = expiryMs; victim = nonce; }
    }
    if (victim !== undefined) this.seen.delete(victim);
  }

  async evictExpired(): Promise<void> {
    this.evictExpiredSync();
  }

  get size(): number { return this.seen.size; }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

export class NonceRegistry {
  private readonly store: NonceStore;
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs = 60_000, store?: NonceStore) {
    this.store = store ?? new MapNonceStore();
    this.cleanupTimer = setInterval(() => {
      this.store.evictExpired().catch(() => {});
    }, cleanupIntervalMs);
    // Allow the process to exit even if this registry is still alive.
    if (typeof this.cleanupTimer.unref === "function") this.cleanupTimer.unref();
  }

  /**
   * Synchronous check against the SAME store checkAsync uses.
   *
   * @deprecated Use checkAsync. Throws when a custom (non-MapNonceStore)
   * store is configured. WHY: check() used to keep its own private map, so a
   * caller mixing check() and checkAsync() — or one that configured a shared
   * Redis store and then called check() — had two disjoint replay caches and
   * a nonce seen by one was fresh to the other.
   *
   * @param nonce     The nonce string from the message envelope
   * @param expiresAt ISO8601 expiry time from the message's "expires" field
   * @returns         true if the nonce is fresh (first time seen), false if replay
   */
  check(nonce: string, expiresAt: string): boolean {
    if (!(this.store instanceof MapNonceStore)) {
      throw new Error("NonceRegistry.check() cannot use a custom NonceStore synchronously; use checkAsync()");
    }
    return this.store.setIfAbsentSync(nonce, Date.parse(expiresAt));
  }

  /**
   * Async check — works with any NonceStore, including custom backends.
   *
   * @param nonce     The nonce string from the message envelope
   * @param expiresAt ISO8601 expiry time from the message's "expires" field
   * @returns         true if the nonce is fresh (first time seen), false if replay
   */
  async checkAsync(nonce: string, expiresAt: string): Promise<boolean> {
    const expiryMs = Date.parse(expiresAt);
    // Unparseable expiry: refuse rather than store an entry that never expires.
    if (Number.isNaN(expiryMs)) return false;
    return this.store.setIfAbsent(nonce, expiryMs);
  }

  /** Number of nonces currently tracked (default store only; 0 for a custom store). */
  get size(): number {
    return this.store instanceof MapNonceStore ? this.store.size : 0;
  }

  /** Stop the background cleanup timer. Call when the owning server shuts down. */
  destroy(): void {
    clearInterval(this.cleanupTimer);
  }

}
