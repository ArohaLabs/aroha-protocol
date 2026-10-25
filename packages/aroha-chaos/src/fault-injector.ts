// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * FaultInjector — deterministic or probabilistic fault injection for Aroha agents.
 *
 * Use in tests and staging environments to verify that:
 *   1. LIFO compensation fires correctly when a mid-saga step fails
 *   2. Circuit breakers trip after repeated failures
 *   3. Retry policies converge within expected attempt counts
 *   4. The CompensationDLQ catches cancel delivery failures
 *
 * The injector wraps an agent endpoint handler. The real agent processes
 * normally; the injector intercepts and either passes through or injects
 * the configured fault.
 */

export type FaultType =
  | "timeout"        // Delays response beyond the saga's reserve timeout
  | "error"          // Returns an ArohaError response
  | "network-drop"   // Throws a network error (connection refused)
  | "cancel-fail"    // Succeeds on reserve/commit but fails on ArohaCancel
  | "corrupt-output" // Returns a response with a malformed body
  | "slow"           // Adds latency without timing out;

export interface FaultRule {
  /** The agent DID this rule applies to. Omit to apply to all agents. */
  agentDID?: string;
  /** Which message types to inject faults on. Omit to apply to all. */
  messageTypes?: string[];
  fault: FaultType;
  /** Additional delay in ms before injecting the fault. Default: 0 */
  delayMs?: number;
  /** Slow fault: adds this many ms to response time. */
  slowMs?: number;
  /** Error fault: the error message to return. */
  errorMessage?: string;
  /**
   * Probability of injecting this fault (0.0–1.0).
   * 1.0 = always inject (deterministic). Default: 1.0
   */
  probability?: number;
  /**
   * Only inject on attempt numbers in this set (1-indexed).
   * Useful for "fail twice then succeed" retry testing.
   */
  onAttempts?: number[];
}

export interface FaultInjectorConfig {
  rules: FaultRule[];
  /**
   * Seed for reproducible probabilistic fault injection. When set, every
   * `probability` draw comes from a seeded PRNG (mulberry32), so the same
   * seed, rules and call sequence inject the same faults on every run.
   * The seed is truncated to an unsigned 32-bit integer. Omit to use
   * Math.random (non-reproducible).
   */
  randomSeed?: number;
}

export class FaultInjector {
  private readonly rules: FaultRule[];
  private readonly callCounts = new Map<string, number>(); // key: "agentDID:messageType"
  private readonly seed: number | undefined;
  private random: () => number;

  constructor(config: FaultInjectorConfig) {
    this.rules = config.rules;
    if (config.randomSeed !== undefined) {
      if (!Number.isFinite(config.randomSeed)) {
        throw new Error("FaultInjector: randomSeed must be a finite number");
      }
      this.seed = config.randomSeed >>> 0;
      this.random = mulberry32(this.seed);
    } else {
      this.seed = undefined;
      this.random = Math.random;
    }
  }

  /**
   * Wrap an async operation with fault injection.
   *
   * @param agentDID     Target agent DID
   * @param messageType  Aroha message type (e.g. "ArohaReserve", "ArohaCommit", "ArohaCancel")
   * @param fn           The real operation to execute (if not faulted)
   */
  async execute<T>(
    agentDID: string,
    messageType: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const key = `${agentDID}:${messageType}`;
    const attempt = (this.callCounts.get(key) ?? 0) + 1;
    this.callCounts.set(key, attempt);

    const rule = this.matchRule(agentDID, messageType, attempt);
    if (!rule) return fn();

    if (rule.delayMs) {
      await sleep(rule.delayMs);
    }

    switch (rule.fault) {
      case "timeout":
        // Never resolves — simulates the agent going dark
        await new Promise<never>(() => {});
        throw new Error("unreachable");

      case "network-drop":
        throw new Error(`ECONNREFUSED: Connection refused to ${agentDID}`);

      case "error":
        throw new Error(rule.errorMessage ?? `Injected ArohaError for ${agentDID}`);

      case "slow":
        await sleep(rule.slowMs ?? 2_000);
        return fn();

      case "cancel-fail":
        if (messageType === "ArohaCancel") {
          throw new Error(`Injected cancel failure for ${agentDID}`);
        }
        return fn();

      case "corrupt-output": {
        const result = await fn();
        // Corrupt the output by replacing it with an invalid object
        return { _corrupted: true, _original: result } as unknown as T;
      }
    }
  }

  /**
   * Reset call counts (useful between test cases). With a `randomSeed`, the
   * PRNG is also rewound to the seed, so the next run repeats the same draws.
   */
  reset(): void {
    this.callCounts.clear();
    if (this.seed !== undefined) this.random = mulberry32(this.seed);
  }

  private matchRule(agentDID: string, messageType: string, attempt: number): FaultRule | null {
    for (const rule of this.rules) {
      // DID filter
      if (rule.agentDID && rule.agentDID !== agentDID) continue;
      // Message type filter
      if (rule.messageTypes && !rule.messageTypes.includes(messageType)) continue;
      // Attempt filter
      if (rule.onAttempts && !rule.onAttempts.includes(attempt)) continue;
      // Probability
      const p = rule.probability ?? 1.0;
      if (this.random() > p) continue;

      return rule;
    }
    return null;
  }
}

/**
 * mulberry32 — a small, fast 32-bit seeded PRNG returning floats in [0, 1).
 * Not cryptographically secure; used only to make fault injection reproducible.
 */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
