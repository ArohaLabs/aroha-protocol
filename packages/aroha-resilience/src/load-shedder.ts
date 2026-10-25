// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Adaptive Load Shedder
 *
 * Actively rejects requests at the ingress when the system is overloaded.
 * This is distinct from the Bulkhead (which queues): load shedding returns
 * an immediate 429 so the orchestrator's circuit breaker trips and reroutes.
 *
 * Two independent shedding signals:
 *   1. Token bucket — refills at `ratePerSec` tokens/second, bursts up to `burst`
 *   2. Queue depth — shed if pending requests exceed `maxQueueDepth` regardless of tokens
 *
 * Wire as ArohaServer middleware:
 *   import { LoadShedder, createLoadShedMiddleware } from "@aroha-sdk/resilience";
 *   const shedder = new LoadShedder({ ratePerSec: 100, burst: 20 });
 *   server = new ArohaServer({ middleware: [createLoadShedMiddleware(shedder)] });
 */

export interface LoadShedderConfig {
  /**
   * Sustained request rate allowed per second.
   * Tokens refill at this rate continuously.
   * Default: 100
   */
  ratePerSec?: number;
  /**
   * Maximum burst of requests above the sustained rate.
   * Token bucket depth. Default: 20
   */
  burst?: number;
  /**
   * Shed all requests when pending queue exceeds this depth,
   * regardless of available tokens. Default: 200
   */
  maxQueueDepth?: number;
}

export interface ShedDecision {
  shed: boolean;
  /** Only set when shed=true. Time in ms before the client should retry. */
  retryAfterMs?: number;
}

export class LoadShedder {
  private readonly ratePerSec: number;
  private readonly burst: number;
  private readonly maxQueueDepth: number;

  private tokens: number;
  private lastRefill: number;
  private queueDepth = 0;

  constructor(config: LoadShedderConfig = {}) {
    this.ratePerSec    = config.ratePerSec    ?? 100;
    this.burst         = config.burst         ?? 20;
    this.maxQueueDepth = config.maxQueueDepth ?? 200;

    this.tokens     = this.burst;
    this.lastRefill = Date.now();
  }

  check(): ShedDecision {
    this.refill();

    // Queue depth signal — hard shed regardless of token availability
    if (this.queueDepth >= this.maxQueueDepth) {
      return { shed: true, retryAfterMs: Math.ceil(1000 / this.ratePerSec) };
    }

    if (this.tokens < 1) {
      // Time until the next token is available
      const retryAfterMs = Math.ceil((1 - this.tokens) / this.ratePerSec * 1000);
      return { shed: true, retryAfterMs };
    }

    this.tokens -= 1;
    return { shed: false };
  }

  /** Call when a request enters the processing queue. */
  enqueue(): void {
    this.queueDepth++;
  }

  /** Call when a request leaves the processing queue (success or error). */
  dequeue(): void {
    this.queueDepth = Math.max(0, this.queueDepth - 1);
  }

  get stats(): { tokens: number; queueDepth: number } {
    return { tokens: Math.floor(this.tokens), queueDepth: this.queueDepth };
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.burst, this.tokens + elapsed * this.ratePerSec);
    this.lastRefill = now;
  }
}

/**
 * Create an ArohaServer middleware that sheds load when the system is overloaded.
 * Rejected requests receive error code "AROHA_CAPACITY_EXCEEDED" and a Retry-After hint.
 */
export function createLoadShedMiddleware(shedder: LoadShedder) {
  return async (
    _envelope: unknown,
    reject: (status: number, code: string, reason: string) => void
  ): Promise<void> => {
    const decision = shedder.check();
    if (decision.shed) {
      reject(
        429,
        "AROHA_CAPACITY_EXCEEDED",
        `Server overloaded. Retry after ${decision.retryAfterMs ?? 1000}ms.`
      );
    }
  };
}
