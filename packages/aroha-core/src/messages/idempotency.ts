// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Idempotency Store — server-side deduplication for ArohaRequest.
 *
 * ArohaCommit is already spec-idempotent. But ArohaRequest (capability
 * invocations) are not — a retried "book-flight" request could create a
 * duplicate booking. The idempotency store fixes this.
 *
 * Protocol contract:
 *   Sender includes idempotencyKey: string in ArohaRequestBody.
 *   Receiver checks the store before processing. If the key exists and
 *   the cached response is still valid, the cached response is returned
 *   immediately — no work is done twice.
 *
 * Key design: senderDID:idempotencyKey — scoped per sender so different
 * orchestrators cannot accidentally share idempotency keys.
 *
 * Reference: Stripe API idempotency (https://stripe.com/docs/idempotency)
 */

import { type ArohaEnvelope } from "./envelope.js";

// ─── Interface ────────────────────────────────────────────────────────────────

export interface IIdempotencyStore {
  /**
   * Retrieve a cached response for this key.
   * Returns null if not found or expired.
   */
  get(senderDID: string, idempotencyKey: string): Promise<ArohaEnvelope | null>;

  /**
   * Store a response for this key with a TTL.
   * TTL default: 86_400_000 ms (24 hours) — matches typical saga window.
   */
  set(
    senderDID: string,
    idempotencyKey: string,
    response: ArohaEnvelope,
    ttlMs?: number
  ): Promise<void>;
}

// ─── In-memory implementation ─────────────────────────────────────────────────

interface StoredEntry {
  response: ArohaEnvelope;
  expiresAt: number;
}

export class InMemoryIdempotencyStore implements IIdempotencyStore {
  private readonly defaultTtlMs: number;
  private readonly store = new Map<string, StoredEntry>();
  private readonly cleanupIntervalMs: number;
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(config: { defaultTtlMs?: number; cleanupIntervalMs?: number } = {}) {
    this.defaultTtlMs       = config.defaultTtlMs       ?? 86_400_000; // 24h
    this.cleanupIntervalMs  = config.cleanupIntervalMs  ?? 300_000;    // 5m

    // Periodically evict expired entries to prevent unbounded memory growth
    this.cleanupTimer = setInterval(() => this.evictExpired(), this.cleanupIntervalMs);
    // Don't prevent process exit if only cleanup timer is pending
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  async get(senderDID: string, idempotencyKey: string): Promise<ArohaEnvelope | null> {
    const key = storeKey(senderDID, idempotencyKey);
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.response;
  }

  async set(
    senderDID: string,
    idempotencyKey: string,
    response: ArohaEnvelope,
    ttlMs = this.defaultTtlMs
  ): Promise<void> {
    this.store.set(storeKey(senderDID, idempotencyKey), {
      response,
      expiresAt: Date.now() + ttlMs,
    });
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) this.store.delete(key);
    }
  }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/**
 * Composite key for (sender, idempotencyKey).
 *
 * WHY a NUL separator and not ":": DIDs are colon-delimited
 * (`did:aroha:alice`), so `${sender}:${key}` made sender "did:aroha:a" with
 * key "b:c" and sender "did:aroha:a:b" with key "c" the SAME entry — one
 * sender could be served another sender's cached response (and its result
 * data) just by choosing an idempotency key. NUL cannot appear in a DID or in
 * a JSON-borne string key that anyone would legitimately send, and the store
 * is in-process, so nothing outside ever parses this string.
 */
function storeKey(senderDID: string, idempotencyKey: string): string {
  return `${senderDID}\u0000${idempotencyKey}`;
}

/**
 * Check the idempotency store and return a cached response if one exists.
 * Returns null if the request should proceed normally.
 *
 * Usage in an agent's message handler:
 *   const cached = await checkIdempotency(store, envelope);
 *   if (cached) { respond(cached); return; }
 *   // ... process normally ...
 *   const response = buildResponse(...);
 *   await storeIdempotency(store, envelope, response);
 *   respond(response);
 */
export async function checkIdempotency(
  store: IIdempotencyStore,
  envelope: ArohaEnvelope
): Promise<ArohaEnvelope | null> {
  const body = envelope.body as { idempotencyKey?: string };
  if (!body.idempotencyKey) return null;
  return store.get(envelope.from, body.idempotencyKey);
}

export async function storeIdempotency(
  store: IIdempotencyStore,
  requestEnvelope: ArohaEnvelope,
  responseEnvelope: ArohaEnvelope,
  ttlMs?: number
): Promise<void> {
  const body = requestEnvelope.body as { idempotencyKey?: string };
  if (!body.idempotencyKey) return;
  await store.set(requestEnvelope.from, body.idempotencyKey, responseEnvelope, ttlMs);
}
