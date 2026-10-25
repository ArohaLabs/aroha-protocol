// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** L6/L7: integer micro-USD accounting in the redemption store and the spending ledger. */

import { describe, it, expect } from "vitest";
import { InMemoryRedemptionStore } from "./redemption.js";
import { MapSpendingLedger } from "./spending-ledger.js";

const rec = { redemptionId: "r", mandateId: "m", amountUsd: 1, merchant: "did:x", redeemedAt: new Date().toISOString() };

describe("InMemoryRedemptionStore", () => {
  it("refuses a zero, fractional or unsafe amountMicros", async () => {
    const s = new InMemoryRedemptionStore();
    await expect(s.tryRedeem("g#m", 0, 100, rec)).rejects.toThrow(RangeError);
    await expect(s.tryRedeem("g#m", 0.5, 100, rec)).rejects.toThrow(RangeError);
    await expect(s.tryRedeem("g#m", 2 ** 60, 2 ** 61, rec)).rejects.toThrow(RangeError);
    await expect(s.tryRedeem("g#m", 1, NaN, rec)).rejects.toThrow(RangeError);
    expect((await s.tryRedeem("g#m", 1, 100, rec)).accepted).toBe(true);
  });
});

describe("MapSpendingLedger", () => {
  it("does not drift with decimal dollars: ten 0.1 allocations exactly fill a 1.0 budget", async () => {
    const l = new MapSpendingLedger();
    await l.init("p", 1.0);
    for (let i = 0; i < 10; i++) await l.allocate("p", 0.1);
    expect((await l.status("p"))!.remainingUsd).toBe(0);
    await expect(l.allocate("p", 0.000001)).rejects.toThrow();
  });

  it("refuses negative, NaN and infinite amounts", async () => {
    const l = new MapSpendingLedger();
    await l.init("p", 10);
    await expect(l.allocate("p", -5)).rejects.toThrow(RangeError);
    await expect(l.allocate("p", NaN)).rejects.toThrow(RangeError);
    await expect(l.allocate("p", Infinity)).rejects.toThrow(RangeError);
    await expect(l.init("q", -1)).rejects.toThrow(RangeError);
    expect((await l.status("p"))!.remainingUsd).toBe(10);
  });
});
