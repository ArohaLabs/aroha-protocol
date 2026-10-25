// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { FaultInjector } from "./fault-injector.js";
import { ChaosSagaRunner } from "./chaos-saga.js";

// ─── FaultInjector ────────────────────────────────────────────────────────────

describe("FaultInjector", () => {
  it("passes through when no rule matches", async () => {
    const injector = new FaultInjector({ rules: [] });
    const result = await injector.execute("did:aroha:agent1", "ArohaReserve", async () => "real");
    expect(result).toBe("real");
  });

  it("throws network-drop fault", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "network-drop", agentDID: "did:aroha:agent1" }],
    });
    await expect(
      injector.execute("did:aroha:agent1", "ArohaReserve", async () => "unreachable")
    ).rejects.toThrow("ECONNREFUSED");
  });

  it("throws error fault with custom message", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "error", errorMessage: "injected failure" }],
    });
    await expect(
      injector.execute("did:aroha:agent1", "ArohaReserve", async () => "x")
    ).rejects.toThrow("injected failure");
  });

  it("injects cancel-fail only on ArohaCancel", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "cancel-fail" }],
    });

    // Reserve should pass through
    const reserveResult = await injector.execute("did:aroha:agent1", "ArohaReserve", async () => "reserved");
    expect(reserveResult).toBe("reserved");

    // Cancel should fail
    await expect(
      injector.execute("did:aroha:agent1", "ArohaCancel", async () => "acked")
    ).rejects.toThrow("cancel failure");
  });

  it("respects onAttempts filter", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "error", onAttempts: [1, 2] }],
    });

    // Attempts 1 and 2 fail
    await expect(injector.execute("a:b", "ArohaReserve", async () => "x")).rejects.toThrow();
    await expect(injector.execute("a:b", "ArohaReserve", async () => "x")).rejects.toThrow();
    // Attempt 3 passes
    const result = await injector.execute("a:b", "ArohaReserve", async () => "ok");
    expect(result).toBe("ok");
  });

  it("applies DID filter correctly", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "error", agentDID: "did:aroha:target" }],
    });

    // Target DID fails
    await expect(
      injector.execute("did:aroha:target", "ArohaReserve", async () => "x")
    ).rejects.toThrow();

    // Other DID passes
    const result = await injector.execute("did:aroha:other", "ArohaReserve", async () => "ok");
    expect(result).toBe("ok");
  });

  it("corrupts output", async () => {
    const injector = new FaultInjector({
      rules: [{ fault: "corrupt-output" }],
    });
    const result = await injector.execute("a", "ArohaCommit", async () => ({ price: 100 }));
    expect((result as unknown as { _corrupted: boolean })._corrupted).toBe(true);
  });
});

describe("FaultInjector randomSeed", () => {
  async function pattern(injector: FaultInjector, n = 64): Promise<boolean[]> {
    const out: boolean[] = [];
    for (let i = 0; i < n; i++) {
      try {
        await injector.execute("did:aroha:a", "ArohaReserve", async () => "ok");
        out.push(false);
      } catch {
        out.push(true);
      }
    }
    return out;
  }
  const rules = [{ fault: "error" as const, probability: 0.5 }];

  it("same seed injects the same faults on every run", async () => {
    const a = await pattern(new FaultInjector({ rules, randomSeed: 42 }));
    const b = await pattern(new FaultInjector({ rules, randomSeed: 42 }));
    expect(a).toEqual(b);
    // Probabilistic, not degenerate: some calls faulted, some passed.
    expect(a.some(Boolean)).toBe(true);
    expect(a.some((x) => !x)).toBe(true);
  });

  it("different seeds give different fault sequences", async () => {
    const a = await pattern(new FaultInjector({ rules, randomSeed: 1 }));
    const b = await pattern(new FaultInjector({ rules, randomSeed: 2 }));
    expect(a).not.toEqual(b);
  });

  it("reset() rewinds the seeded sequence", async () => {
    const injector = new FaultInjector({ rules, randomSeed: 7 });
    const first = await pattern(injector);
    injector.reset();
    const second = await pattern(injector);
    expect(second).toEqual(first);
  });

  it("does not use Math.random when seeded, and does when unseeded", async () => {
    const spy = vi.spyOn(Math, "random");
    try {
      await pattern(new FaultInjector({ rules, randomSeed: 3 }), 8);
      expect(spy).not.toHaveBeenCalled();
      await pattern(new FaultInjector({ rules }), 8);
      expect(spy).toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects a non-finite seed", () => {
    expect(() => new FaultInjector({ rules, randomSeed: Number.NaN })).toThrow(/randomSeed/);
  });
});

// ─── ChaosSagaRunner ─────────────────────────────────────────────────────────

describe("ChaosSagaRunner", () => {
  const makeSteps = (n: number) =>
    Array.from({ length: n }, (_, i) => ({
      capability: `step-${i}`,
      agentDID: `did:aroha:agent${i}`,
    }));

  it("reports all passed when executor correctly compensates", async () => {
    const runner = new ChaosSagaRunner(async (steps, failAt) => {
      const cancelledStepIds = Array.from({ length: failAt }, (_, i) => i);
      return { success: false, failures: [{ stepId: failAt, reason: "injected" }], cancelledStepIds };
    });

    const report = await runner.sweepFailures(makeSteps(4));
    expect(report.allPassed).toBe(true);
    expect(report.totalRuns).toBe(4);
  });

  it("detects missing compensations", async () => {
    const runner = new ChaosSagaRunner(async (_steps, _failAt) => {
      // Bug: never cancels anything
      return { success: false, failures: [{ stepId: 2, reason: "injected" }], cancelledStepIds: [] };
    });

    const report = await runner.sweepFailures(makeSteps(3));
    expect(report.allPassed).toBe(false);
    // Run where failAt=0 passes (no compensations needed), runs 1 and 2 fail
    expect(report.failedRuns).toBeGreaterThan(0);
  });

  it("detects unexpected cancellations", async () => {
    const runner = new ChaosSagaRunner(async (_steps, failAt) => {
      // Bug: always cancels all steps including the failing one
      const cancelledStepIds = Array.from({ length: failAt + 1 }, (_, i) => i);
      return { success: false, failures: [{ stepId: failAt, reason: "injected" }], cancelledStepIds };
    });

    const report = await runner.sweepFailures(makeSteps(3));
    // failAt=0: expects no cancellations, gets [0] — FAIL
    const firstRun = report.runs[0];
    expect(firstRun.passed).toBe(false);
    expect(firstRun.notes.some((n) => n.includes("Unexpected"))).toBe(true);
  });
});
