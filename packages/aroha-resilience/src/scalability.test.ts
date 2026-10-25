// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { LoadShedder, createLoadShedMiddleware } from "./load-shedder.js";
import { PerDidRateLimiter } from "./rate-limiter.js";
import { PriorityBulkhead, PriorityBulkheadRejectedError } from "./priority-bulkhead.js";

// ─── LoadShedder ──────────────────────────────────────────────────────────────

describe("LoadShedder", () => {
  it("allows requests within token budget", () => {
    const shedder = new LoadShedder({ ratePerSec: 100, burst: 10 });
    const result = shedder.check();
    expect(result.shed).toBe(false);
  });

  it("sheds when token bucket is exhausted", () => {
    const shedder = new LoadShedder({ ratePerSec: 1, burst: 2 });
    shedder.check(); // consume 1
    shedder.check(); // consume 2
    const result = shedder.check(); // exhausted
    expect(result.shed).toBe(true);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it("sheds when queue depth exceeds threshold", () => {
    const shedder = new LoadShedder({ ratePerSec: 1000, burst: 1000, maxQueueDepth: 2 });
    shedder.enqueue();
    shedder.enqueue();
    // At depth=2 (>= maxQueueDepth=2), shed
    const result = shedder.check();
    expect(result.shed).toBe(true);
    shedder.dequeue();
    shedder.dequeue();
  });

  it("allows after dequeue brings depth below threshold", () => {
    const shedder = new LoadShedder({ ratePerSec: 1000, burst: 1000, maxQueueDepth: 2 });
    shedder.enqueue();
    shedder.enqueue();
    shedder.dequeue(); // back to 1
    const result = shedder.check();
    expect(result.shed).toBe(false);
    shedder.dequeue();
  });

  it("middleware calls reject when shedding", async () => {
    const shedder = new LoadShedder({ ratePerSec: 1, burst: 0 });
    const middleware = createLoadShedMiddleware(shedder);
    const reject = vi.fn();
    await middleware({}, reject);
    expect(reject).toHaveBeenCalledWith(429, "AROHA_CAPACITY_EXCEEDED", expect.any(String));
  });

  it("middleware does not call reject when not shedding", async () => {
    const shedder = new LoadShedder({ ratePerSec: 100, burst: 100 });
    const middleware = createLoadShedMiddleware(shedder);
    const reject = vi.fn();
    await middleware({}, reject);
    expect(reject).not.toHaveBeenCalled();
  });
});

// ─── PerDidRateLimiter ────────────────────────────────────────────────────────

describe("PerDidRateLimiter", () => {
  it("allows requests within rate", () => {
    const limiter = new PerDidRateLimiter({ ratePerSec: 10, burst: 5 });
    const result = limiter.check("did:aroha:alice");
    expect(result.allowed).toBe(true);
  });

  it("rate limits a single DID after burst exhausted", () => {
    const limiter = new PerDidRateLimiter({ ratePerSec: 1, burst: 2 });
    limiter.check("did:aroha:alice"); // 1
    limiter.check("did:aroha:alice"); // 2
    const result = limiter.check("did:aroha:alice"); // exhausted
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it("does not rate limit different DIDs together", () => {
    const limiter = new PerDidRateLimiter({ ratePerSec: 1, burst: 1 });
    limiter.check("did:aroha:alice"); // exhausts alice
    const result = limiter.check("did:aroha:bob"); // bob still has budget
    expect(result.allowed).toBe(true);
  });

  it("evicts oldest DID when maxDids exceeded", () => {
    const limiter = new PerDidRateLimiter({ ratePerSec: 10, burst: 10, maxDids: 2 });
    limiter.check("did:aroha:a");
    limiter.check("did:aroha:b");
    limiter.check("did:aroha:c"); // triggers eviction of 'a'
    // Should not throw
    const result = limiter.check("did:aroha:c");
    expect(result.allowed).toBe(true);
  });
});

// ─── PriorityBulkhead ─────────────────────────────────────────────────────────

describe("PriorityBulkhead", () => {
  it("executes tasks within concurrency limit", async () => {
    const bh = new PriorityBulkhead({ maxConcurrent: 2 });
    const results: number[] = [];
    await Promise.all([
      bh.execute(async () => { results.push(1); }, 5),
      bh.execute(async () => { results.push(2); }, 5),
    ]);
    expect(results).toHaveLength(2);
  });

  it("rejects when at max capacity and queue full", async () => {
    const bh = new PriorityBulkhead({ maxConcurrent: 1, maxQueue: 1 });
    const blocker = bh.execute(() => new Promise((r) => setTimeout(r, 50)));
    bh.execute(async () => {}, 5); // fills queue
    await expect(
      bh.execute(async () => {}, 5)
    ).rejects.toThrow(PriorityBulkheadRejectedError);
    await blocker;
  });

  it("executes higher-priority tasks before lower-priority when queue contested", async () => {
    const bh = new PriorityBulkhead({ maxConcurrent: 1 });
    const order: number[] = [];

    // Block the slot with a long-running task
    const blocker = bh.execute(() => new Promise((r) => setTimeout(r, 30)));

    // Queue low priority first, then high priority
    const low  = bh.execute(async () => { order.push(10); }, 10);
    const high = bh.execute(async () => { order.push(1);  }, 1);

    await blocker;
    await Promise.all([low, high]);

    // High priority (1) should run before low priority (10)
    expect(order[0]).toBe(1);
    expect(order[1]).toBe(10);
  });

  it("reports stats correctly", async () => {
    const bh = new PriorityBulkhead({ maxConcurrent: 2 });
    expect(bh.stats).toEqual({ running: 0, queued: 0 });

    const p1 = bh.execute(() => new Promise((r) => setTimeout(r, 20)));
    const p2 = bh.execute(() => new Promise((r) => setTimeout(r, 20)));
    bh.execute(() => new Promise((r) => setTimeout(r, 20))).catch(() => {});

    expect(bh.stats.running).toBe(2);
    await Promise.all([p1, p2]);
  });
});
