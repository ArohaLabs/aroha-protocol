// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Bulkhead — bounded concurrency per agent class.
 *
 * Prevents one overloaded agent type from exhausting the shared connection
 * pool and starving all other agents. Like watertight compartments in a ship.
 *
 * Usage:
 *   const bulkhead = new Bulkhead({ maxConcurrent: 10, maxQueue: 20 });
 *   const result = await bulkhead.execute(() => callAgent(endpoint, envelope));
 */

export interface BulkheadConfig {
  /** Maximum number of concurrent operations allowed. Default: 10 */
  maxConcurrent?: number;
  /**
   * Maximum number of operations waiting in the queue.
   * Excess callers get BulkheadRejectedError immediately.
   * Default: 50
   */
  maxQueue?: number;
}

export class Bulkhead {
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;
  private running = 0;
  private readonly queue: Array<() => void> = [];

  constructor(config: BulkheadConfig = {}) {
    this.maxConcurrent = config.maxConcurrent ?? 10;
    this.maxQueue      = config.maxQueue      ?? 50;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.running >= this.maxConcurrent) {
      if (this.queue.length >= this.maxQueue) {
        throw new BulkheadRejectedError(this.maxConcurrent, this.maxQueue);
      }
      // Queue the execution slot — resolved when a running op completes
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }

    this.running++;
    try {
      return await fn();
    } finally {
      this.running--;
      const next = this.queue.shift();
      if (next) next();
    }
  }

  get stats(): { running: number; queued: number } {
    return { running: this.running, queued: this.queue.length };
  }
}

export class BulkheadRejectedError extends Error {
  constructor(maxConcurrent: number, maxQueue: number) {
    super(
      `Bulkhead full: ${maxConcurrent} concurrent + ${maxQueue} queued operations in flight. ` +
      `Request rejected to protect downstream capacity.`
    );
    this.name = "BulkheadRejectedError";
  }
}
