// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Circuit Breaker — per-agent-DID failure isolation.
 *
 * State machine:
 *   CLOSED   → normal operation, counts failures
 *   OPEN     → fails fast without calling the agent
 *   HALF_OPEN → allows one probe call to test recovery
 *
 * Use one CircuitBreakerRegistry (not one CircuitBreaker) per orchestrator
 * so that breaker state persists across saga executions.
 */

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerConfig {
  /** Number of consecutive failures before the circuit opens. Default: 5 */
  failureThreshold?: number;
  /** Failures within this window count toward the threshold (ms). Default: 60_000 */
  windowMs?: number;
  /** How long the circuit stays OPEN before testing recovery (ms). Default: 30_000 */
  recoveryTimeoutMs?: number;
}

interface BreakerState {
  state: CircuitState;
  failures: number[];    // timestamps of recent failures
  openedAt?: number;
  halfOpenProbeInFlight: boolean;
}

export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly windowMs: number;
  private readonly recoveryTimeoutMs: number;
  private readonly states = new Map<string, BreakerState>();

  constructor(config: CircuitBreakerConfig = {}) {
    this.failureThreshold    = config.failureThreshold    ?? 5;
    this.windowMs            = config.windowMs            ?? 60_000;
    this.recoveryTimeoutMs   = config.recoveryTimeoutMs   ?? 30_000;
  }

  /** Returns the current circuit state for an agent. */
  stateOf(agentDID: string): CircuitState {
    return this.getOrCreate(agentDID).state;
  }

  /**
   * Execute fn through the circuit breaker.
   * Throws CircuitOpenError immediately if the circuit is OPEN.
   * Records success/failure and transitions state accordingly.
   */
  async execute<T>(agentDID: string, fn: () => Promise<T>): Promise<T> {
    const breaker = this.getOrCreate(agentDID);
    this.maybeTransitionToHalfOpen(breaker);

    if (breaker.state === "OPEN") {
      throw new CircuitOpenError(agentDID, this.recoveryTimeoutMs);
    }

    if (breaker.state === "HALF_OPEN") {
      if (breaker.halfOpenProbeInFlight) {
        // Only one probe at a time — reject concurrent half-open calls
        throw new CircuitOpenError(agentDID, this.recoveryTimeoutMs);
      }
      breaker.halfOpenProbeInFlight = true;
    }

    try {
      const result = await fn();
      this.onSuccess(agentDID, breaker);
      return result;
    } catch (err) {
      this.onFailure(agentDID, breaker);
      throw err;
    }
  }

  /** Manually reset a circuit (e.g. after operator intervention). */
  reset(agentDID: string): void {
    this.states.delete(agentDID);
  }

  /** Snapshot of all breaker states (for dashboards / metrics). */
  snapshot(): Record<string, { state: CircuitState; recentFailures: number }> {
    const now = Date.now();
    const out: Record<string, { state: CircuitState; recentFailures: number }> = {};
    for (const [did, b] of this.states) {
      out[did] = {
        state: b.state,
        recentFailures: b.failures.filter((t) => now - t < this.windowMs).length,
      };
    }
    return out;
  }

  private getOrCreate(agentDID: string): BreakerState {
    if (!this.states.has(agentDID)) {
      this.states.set(agentDID, {
        state: "CLOSED",
        failures: [],
        halfOpenProbeInFlight: false,
      });
    }
    return this.states.get(agentDID)!;
  }

  private maybeTransitionToHalfOpen(breaker: BreakerState): void {
    if (
      breaker.state === "OPEN" &&
      breaker.openedAt !== undefined &&
      Date.now() - breaker.openedAt >= this.recoveryTimeoutMs
    ) {
      breaker.state = "HALF_OPEN";
      breaker.halfOpenProbeInFlight = false;
    }
  }

  private onSuccess(agentDID: string, breaker: BreakerState): void {
    breaker.state = "CLOSED";
    breaker.failures = [];
    breaker.halfOpenProbeInFlight = false;
  }

  private onFailure(agentDID: string, breaker: BreakerState): void {
    const now = Date.now();
    breaker.failures.push(now);
    // Evict failures outside the rolling window
    breaker.failures = breaker.failures.filter((t) => now - t < this.windowMs);
    breaker.halfOpenProbeInFlight = false;

    if (breaker.failures.length >= this.failureThreshold) {
      breaker.state = "OPEN";
      breaker.openedAt = now;
    }
  }
}

export class CircuitOpenError extends Error {
  constructor(agentDID: string, recoveryTimeoutMs: number) {
    super(
      `Circuit OPEN for agent ${agentDID}. ` +
      `Will probe again after ${recoveryTimeoutMs / 1000}s recovery timeout.`
    );
    this.name = "CircuitOpenError";
  }
}
