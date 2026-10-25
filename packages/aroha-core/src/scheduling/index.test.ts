// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, afterEach } from "vitest";
import { LocalScheduler, SchedulerError } from "./index.js";

afterEach(() => { vi.useRealTimers(); });

describe("LocalScheduler", () => {
  it("runs an interval task on its own, without an explicit trigger", async () => {
    vi.useFakeTimers();
    const scheduler = new LocalScheduler();
    let runs = 0;
    scheduler.schedule({ id: "tick", trigger: { type: "interval", everyMs: 1000 }, run: () => { runs++; } });

    await vi.advanceTimersByTimeAsync(3500);
    scheduler.stopAll();

    expect(runs).toBe(3);
  });

  it("a manual task never runs on its own", async () => {
    vi.useFakeTimers();
    const scheduler = new LocalScheduler();
    let runs = 0;
    scheduler.schedule({ id: "manual", trigger: { type: "manual" }, run: () => { runs++; } });

    await vi.advanceTimersByTimeAsync(10_000);
    expect(runs).toBe(0);

    await scheduler.trigger("manual");
    expect(runs).toBe(1);
    scheduler.stopAll();
  });

  it("a cron task is registered but not natively run — external scheduling required", async () => {
    vi.useFakeTimers();
    const scheduler = new LocalScheduler();
    let runs = 0;
    scheduler.schedule({ id: "nightly", trigger: { type: "cron", expression: "0 0 * * *" }, run: () => { runs++; } });

    await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
    expect(runs).toBe(0);
    scheduler.stopAll();
  });

  it("stop() halts an interval task", async () => {
    vi.useFakeTimers();
    const scheduler = new LocalScheduler();
    let runs = 0;
    scheduler.schedule({ id: "tick", trigger: { type: "interval", everyMs: 100 }, run: () => { runs++; } });

    await vi.advanceTimersByTimeAsync(250);
    scheduler.stop("tick");
    const runsAtStop = runs;
    await vi.advanceTimersByTimeAsync(1000);

    expect(runs).toBe(runsAtStop);
  });

  it("onError is called instead of the scheduler crashing", async () => {
    const scheduler = new LocalScheduler();
    const errors: unknown[] = [];
    scheduler.schedule({
      id: "flaky", trigger: { type: "manual" },
      run: () => { throw new Error("boom"); },
      onError: (e) => errors.push(e),
    });

    await scheduler.trigger("flaky");
    expect(errors).toHaveLength(1);
    expect((errors[0] as Error).message).toBe("boom");
  });

  it("rejects scheduling the same id twice", () => {
    const scheduler = new LocalScheduler();
    scheduler.schedule({ id: "x", trigger: { type: "manual" }, run: () => {} });
    expect(() => scheduler.schedule({ id: "x", trigger: { type: "manual" }, run: () => {} })).toThrow(SchedulerError);
  });

  it("throws triggering an unscheduled task", async () => {
    const scheduler = new LocalScheduler();
    await expect(scheduler.trigger("nope")).rejects.toThrow(SchedulerError);
  });
});
