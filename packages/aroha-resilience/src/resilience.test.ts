// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CircuitBreaker, CircuitOpenError } from "./circuit-breaker.js";
import { Bulkhead, BulkheadRejectedError } from "./bulkhead.js";
import { RetryPolicy } from "./retry.js";
import { SpeculativeExecutor } from "./speculative.js";

// ─── CircuitBreaker ───────────────────────────────────────────────────────────

describe("CircuitBreaker", () => {
  it("starts CLOSED and passes calls through", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    const result = await cb.execute("did:aroha:agent1", async () => "ok");
    expect(result).toBe("ok");
    expect(cb.stateOf("did:aroha:agent1")).toBe("CLOSED");
  });

  it("opens after failure threshold is reached", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, windowMs: 60_000 });
    const failFn = async () => { throw new Error("fail"); };

    for (let i = 0; i < 3; i++) {
      await cb.execute("did:aroha:agent1", failFn).catch(() => {});
    }

    expect(cb.stateOf("did:aroha:agent1")).toBe("OPEN");
  });

  it("throws CircuitOpenError when OPEN", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 });
    await cb.execute("did:aroha:agent1", async () => { throw new Error("fail"); }).catch(() => {});

    await expect(
      cb.execute("did:aroha:agent1", async () => "should not run")
    ).rejects.toThrow(CircuitOpenError);
  });

  it("transitions to HALF_OPEN after recovery timeout", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1, recoveryTimeoutMs: 0 });
    await cb.execute("did:aroha:agent1", async () => { throw new Error("fail"); }).catch(() => {});

    expect(cb.stateOf("did:aroha:agent1")).toBe("OPEN");
    // recoveryTimeoutMs=0 means immediately transitionable
    await new Promise((r) => setTimeout(r, 1));

    // Poke state — maybeTransitionToHalfOpen triggers on next execute
    await cb.execute("did:aroha:agent1", async () => "probe").catch(() => {});
    expect(cb.stateOf("did:aroha:agent1")).toBe("CLOSED");
  });

  it("reset() clears breaker state", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 });
    await cb.execute("did:aroha:agent1", async () => { throw new Error("fail"); }).catch(() => {});
    expect(cb.stateOf("did:aroha:agent1")).toBe("OPEN");

    cb.reset("did:aroha:agent1");
    expect(cb.stateOf("did:aroha:agent1")).toBe("CLOSED");
  });

  it("tracks per-DID state independently", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 });
    await cb.execute("did:aroha:agent1", async () => { throw new Error(); }).catch(() => {});

    expect(cb.stateOf("did:aroha:agent1")).toBe("OPEN");
    expect(cb.stateOf("did:aroha:agent2")).toBe("CLOSED");
  });
});

// ─── Bulkhead ────────────────────────────────────────────────────────────────

describe("Bulkhead", () => {
  it("allows up to maxConcurrent operations", async () => {
    const bh = new Bulkhead({ maxConcurrent: 3, maxQueue: 0 });
    let running = 0;
    let maxObserved = 0;

    const task = () => bh.execute(async () => {
      running++;
      maxObserved = Math.max(maxObserved, running);
      await new Promise((r) => setTimeout(r, 10));
      running--;
    });

    await Promise.all([task(), task(), task()]);
    expect(maxObserved).toBeLessThanOrEqual(3);
  });

  it("rejects when queue is full", async () => {
    const bh = new Bulkhead({ maxConcurrent: 1, maxQueue: 0 });
    const blocker = bh.execute(() => new Promise((r) => setTimeout(r, 50)));

    await expect(
      bh.execute(async () => "should reject")
    ).rejects.toThrow(BulkheadRejectedError);

    await blocker;
  });

  it("queues operations up to maxQueue", async () => {
    const bh = new Bulkhead({ maxConcurrent: 1, maxQueue: 2 });
    const results: number[] = [];

    const makeTask = (n: number) =>
      bh.execute(async () => {
        await new Promise((r) => setTimeout(r, 5));
        results.push(n);
      });

    await Promise.all([makeTask(1), makeTask(2), makeTask(3)]);
    expect(results).toHaveLength(3);
  });
});

// ─── RetryPolicy ─────────────────────────────────────────────────────────────

describe("RetryPolicy", () => {
  it("returns result on first success", async () => {
    const policy = new RetryPolicy({ maxAttempts: 3, baseMs: 0 });
    const result = await policy.execute(async () => "success");
    expect(result).toBe("success");
  });

  it("retries on failure and succeeds eventually", async () => {
    const policy = new RetryPolicy({ maxAttempts: 3, baseMs: 0 });
    let calls = 0;
    const result = await policy.execute(async () => {
      calls++;
      if (calls < 3) throw new Error("transient");
      return "ok";
    });
    expect(result).toBe("ok");
    expect(calls).toBe(3);
  });

  it("throws after maxAttempts exhausted", async () => {
    const policy = new RetryPolicy({ maxAttempts: 2, baseMs: 0 });
    let calls = 0;
    await expect(
      policy.execute(async () => { calls++; throw new Error("persistent"); })
    ).rejects.toThrow("persistent");
    expect(calls).toBe(2);
  });

  it("respects isRetryable predicate", async () => {
    const policy = new RetryPolicy({
      maxAttempts: 5,
      baseMs: 0,
      isRetryable: (err) => (err as Error).message !== "fatal",
    });
    let calls = 0;
    await expect(
      policy.execute(async () => { calls++; throw new Error("fatal"); })
    ).rejects.toThrow("fatal");
    expect(calls).toBe(1); // no retries for non-retryable errors
  });

  it("calls onRetry callback before each retry", async () => {
    const onRetry = vi.fn();
    const policy = new RetryPolicy({ maxAttempts: 3, baseMs: 0, onRetry });
    let calls = 0;
    await policy.execute(async () => {
      if (++calls < 3) throw new Error("retry me");
      return "done";
    });
    expect(onRetry).toHaveBeenCalledTimes(2);
  });
});

// ─── SpeculativeExecutor ──────────────────────────────────────────────────────

describe("SpeculativeExecutor", () => {
  it("returns first successful result", async () => {
    const { result, winnerIndex } = await SpeculativeExecutor.race(
      ["slow", "fast", "slower"],
      async (candidate, _signal) => {
        const delay = candidate === "fast" ? 5 : 50;
        await new Promise((r) => setTimeout(r, delay));
        return candidate;
      }
    );
    expect(result).toBe("fast");
    expect(winnerIndex).toBe(1);
  });

  it("falls back to another candidate if one fails", async () => {
    const { result } = await SpeculativeExecutor.race(
      ["fail", "succeed"],
      async (candidate) => {
        if (candidate === "fail") throw new Error("nope");
        await new Promise((r) => setTimeout(r, 5));
        return "ok";
      }
    );
    expect(result).toBe("ok");
  });

  it("throws if all candidates fail", async () => {
    await expect(
      SpeculativeExecutor.race(
        ["a", "b"],
        async () => { throw new Error("all fail"); }
      )
    ).rejects.toThrow();
  });

  it("throws on empty candidates", async () => {
    await expect(
      SpeculativeExecutor.race([], async () => "x")
    ).rejects.toThrow("no candidates");
  });
});
