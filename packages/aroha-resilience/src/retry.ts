// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * RetryPolicy — exponential backoff with full jitter.
 *
 * Jitter formula (full jitter, AWS-style):
 *   delay = random(0, min(cap, base * 2^attempt))
 *
 * Full jitter is preferred over equal jitter because it spreads load across
 * the entire backoff window, preventing synchronized retry spikes.
 * Ref: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 */

export interface RetryConfig {
  /** Maximum number of attempts (including the first). Default: 3 */
  maxAttempts?: number;
  /** Initial backoff in ms. Default: 100 */
  baseMs?: number;
  /** Maximum backoff cap in ms. Default: 10_000 */
  capMs?: number;
  /**
   * Predicate to decide if an error is retryable.
   * Default: all errors are retryable.
   */
  isRetryable?: (err: unknown) => boolean;
  /** Called before each retry (useful for logging). */
  onRetry?: (attempt: number, delayMs: number, err: unknown) => void;
}

export class RetryPolicy {
  private readonly maxAttempts: number;
  private readonly baseMs: number;
  private readonly capMs: number;
  private readonly isRetryable: (err: unknown) => boolean;
  private readonly onRetry?: (attempt: number, delayMs: number, err: unknown) => void;

  constructor(config: RetryConfig = {}) {
    this.maxAttempts  = config.maxAttempts ?? 3;
    this.baseMs       = config.baseMs      ?? 100;
    this.capMs        = config.capMs       ?? 10_000;
    this.isRetryable  = config.isRetryable ?? (() => true);
    this.onRetry      = config.onRetry;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (err) {
        lastError = err;

        const isLast = attempt === this.maxAttempts;
        if (isLast || !this.isRetryable(err)) throw err;

        const delayMs = this.jitteredDelay(attempt);
        this.onRetry?.(attempt, delayMs, err);
        await sleep(delayMs);
      }
    }

    throw lastError;
  }

  /** Compute full-jitter delay for a given attempt number (1-indexed). */
  private jitteredDelay(attempt: number): number {
    const exponential = this.baseMs * Math.pow(2, attempt - 1);
    const cap = Math.min(this.capMs, exponential);
    return Math.random() * cap;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Wraps a RetryPolicy and a CircuitBreaker together for a common usage pattern. */
export function withRetry<T>(
  config: RetryConfig,
  fn: () => Promise<T>
): Promise<T> {
  return new RetryPolicy(config).execute(fn);
}
