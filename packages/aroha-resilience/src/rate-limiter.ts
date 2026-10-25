// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Token Bucket Rate Limiter — per-sender-DID fairness enforcement.
 *
 * Prevents a single orchestrator DID from saturating an agent's capacity.
 * Each DID gets an independent token bucket. Excessive callers receive
 * error code "AROHA_RATE_LIMITED" with a Retry-After header value.
 *
 * Complements the LoadShedder (global) — this enforces per-caller fairness.
 *
 * Wire as ArohaServer middleware:
 *   const limiter = new PerDidRateLimiter({ ratePerSec: 10, burst: 5 });
 *   new ArohaServer({ middleware: [createRateLimitMiddleware(limiter)] });
 */

export interface RateLimiterConfig {
  /** Requests allowed per second per DID. Default: 10 */
  ratePerSec?: number;
  /** Burst capacity per DID. Default: 20 */
  burst?: number;
  /**
   * Maximum number of distinct DID buckets to track.
   * Oldest-used DIDs are evicted when this is exceeded.
   * Default: 10_000
   */
  maxDids?: number;
}

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export class PerDidRateLimiter {
  private readonly ratePerSec: number;
  private readonly burst: number;
  private readonly maxDids: number;
  private readonly buckets = new Map<string, Bucket>();

  constructor(config: RateLimiterConfig = {}) {
    this.ratePerSec = config.ratePerSec ?? 10;
    this.burst      = config.burst      ?? 20;
    this.maxDids    = config.maxDids    ?? 10_000;
  }

  check(senderDID: string): { allowed: boolean; retryAfterMs?: number } {
    let bucket = this.buckets.get(senderDID);
    if (!bucket) {
      if (this.buckets.size >= this.maxDids) this.evictOldest();
      bucket = { tokens: this.burst, lastRefill: Date.now() };
      this.buckets.set(senderDID, bucket);
    }

    this.refillBucket(bucket);

    if (bucket.tokens < 1) {
      const retryAfterMs = Math.ceil((1 - bucket.tokens) / this.ratePerSec * 1000);
      return { allowed: false, retryAfterMs };
    }

    bucket.tokens -= 1;
    return { allowed: true };
  }

  private refillBucket(bucket: Bucket): void {
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(this.burst, bucket.tokens + elapsed * this.ratePerSec);
    bucket.lastRefill = now;
  }

  private evictOldest(): void {
    const oldest = this.buckets.keys().next().value;
    if (oldest) this.buckets.delete(oldest);
  }
}

/**
 * Create an ArohaServer middleware that rate-limits by sender DID.
 * The envelope's `from` field is used as the rate-limit key.
 */
export function createRateLimitMiddleware(limiter: PerDidRateLimiter) {
  return async (
    envelope: { from?: string },
    reject: (status: number, code: string, reason: string) => void
  ): Promise<void> => {
    const senderDID = envelope.from ?? "unknown";
    const result = limiter.check(senderDID);
    if (!result.allowed) {
      reject(
        429,
        "AROHA_RATE_LIMITED",
        `Rate limit exceeded for ${senderDID}. Retry after ${result.retryAfterMs ?? 1000}ms.`
      );
    }
  };
}
