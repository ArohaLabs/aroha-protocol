import { describe, it, expect } from "vitest";
import { D1SpendingLedger } from "./spending-ledger-d1.js";
import { BudgetExhaustedError } from "./spending-ledger.js";
import { openSpendingDb } from "./test-utils/sqlite-d1.js";

function makeLedger() {
  return new D1SpendingLedger(openSpendingDb());
}

describe("D1SpendingLedger — basic operations", () => {
  it("init registers a budget and status reflects it", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100);
    const s = await ledger.status("m1");
    expect(s).not.toBeNull();
    expect(s!.limitUsd).toBe(100);
    expect(s!.allocatedUsd).toBe(0);
    expect(s!.remainingUsd).toBe(100);
  });

  it("init is idempotent — second call with different limit is a no-op", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100);
    await ledger.init("m1", 999); // INSERT OR IGNORE
    const s = await ledger.status("m1");
    expect(s!.limitUsd).toBe(100);
  });

  it("status returns null for unknown mandateId", async () => {
    const ledger = makeLedger();
    expect(await ledger.status("no-such-mandate")).toBeNull();
  });
});

describe("D1SpendingLedger — allocate atomicity (no double-decrement)", () => {
  it("sequential allocations deduct correctly without double-counting", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100);

    const r1 = await ledger.allocate("m1", 60);
    expect(r1.remainingUsd).toBe(40);

    const r2 = await ledger.allocate("m1", 40);
    expect(r2.remainingUsd).toBe(0);
  });

  it("allocate throws BudgetExhaustedError when balance is insufficient", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100);
    await ledger.allocate("m1", 80);

    await expect(ledger.allocate("m1", 30)).rejects.toBeInstanceOf(BudgetExhaustedError);
  });

  it("allocation record is created on success (release works)", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100);
    const { allocationId } = await ledger.allocate("m1", 60);

    const { remainingUsd } = await ledger.release("m1", allocationId);
    expect(remainingUsd).toBe(100); // full balance restored
  });
});

describe("D1SpendingLedger — budget expiry (expires_at CTE guard)", () => {
  it("allocate is rejected when budget is expired", async () => {
    const ledger = makeLedger();
    const pastMs = Date.now() - 10_000;
    await ledger.init("m1", 100, pastMs);

    // The CTE WHERE clause: AND (expires_at IS NULL OR expires_at > ?)
    // pastMs < now → guard fails → meta.changes === 0 → BudgetExhaustedError
    await expect(ledger.allocate("m1", 1)).rejects.toBeInstanceOf(BudgetExhaustedError);
  });

  it("allocate succeeds when budget has not yet expired", async () => {
    const ledger = makeLedger();
    const futureMs = Date.now() + 60_000;
    await ledger.init("m1", 100, futureMs);

    const r = await ledger.allocate("m1", 50);
    expect(r.remainingUsd).toBe(50);
  });

  it("expired budget does not modify allocated_usd (atomic guard prevents partial write)", async () => {
    const ledger = makeLedger();
    const pastMs = Date.now() - 1;
    await ledger.init("m1", 100, pastMs);

    try {
      await ledger.allocate("m1", 50);
    } catch {
      // expected BudgetExhaustedError
    }

    // budget should be untouched — CTE UPDATE was not executed
    const s = await ledger.status("m1");
    expect(s!.allocatedUsd).toBe(0);
  });

  it("budget without expiry (null) never expires", async () => {
    const ledger = makeLedger();
    await ledger.init("m1", 100); // no expiresAt → stored as NULL

    const r = await ledger.allocate("m1", 50);
    expect(r.remainingUsd).toBe(50);
  });
});

describe("D1SpendingLedger — concurrency invariants", () => {
  it("concurrent allocations never exceed the budget limit", async () => {
    const ledger = makeLedger();
    await ledger.init("m-concurrent", 50);

    // Fire 10 concurrent $10 allocations against a $50 pool — only 5 can succeed.
    // Node.js is single-threaded but Promise.allSettled still exercises the
    // conditional UPDATE guard because each Promise resolves before the next one
    // has a chance to read a stale balance.
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => ledger.allocate("m-concurrent", 10)),
    );

    const succeeded = results.filter((r) => r.status === "fulfilled");
    const failed = results.filter((r) => r.status === "rejected");

    expect(succeeded).toHaveLength(5);
    expect(failed).toHaveLength(5);
    for (const r of failed) {
      expect((r as PromiseRejectedResult).reason).toBeInstanceOf(BudgetExhaustedError);
    }

    // Guard: total allocated must equal exactly the limit, no double-counting.
    const s = await ledger.status("m-concurrent");
    expect(s!.allocatedUsd).toBe(50);
    expect(s!.remainingUsd).toBe(0);
  });

  it("two concurrent allocations at the exact limit: exactly one succeeds", async () => {
    const ledger = makeLedger();
    await ledger.init("m-exact-limit", 100);

    const [r1, r2] = await Promise.allSettled([
      ledger.allocate("m-exact-limit", 100),
      ledger.allocate("m-exact-limit", 100),
    ]);

    const succeeded = [r1, r2].filter((r) => r.status === "fulfilled");
    const failed = [r1, r2].filter((r) => r.status === "rejected");
    expect(succeeded).toHaveLength(1);
    expect(failed).toHaveLength(1);
    expect((failed[0] as PromiseRejectedResult).reason).toBeInstanceOf(BudgetExhaustedError);
  });

  it("concurrent releases atomically restore the full pool", async () => {
    const ledger = makeLedger();
    await ledger.init("m-concurrent-release", 30);

    const allocs = await Promise.all([
      ledger.allocate("m-concurrent-release", 10),
      ledger.allocate("m-concurrent-release", 10),
      ledger.allocate("m-concurrent-release", 10),
    ]);
    expect((await ledger.status("m-concurrent-release"))!.remainingUsd).toBe(0);

    // Release all three concurrently — total should return to 30
    await Promise.all(
      allocs.map(({ allocationId }) => ledger.release("m-concurrent-release", allocationId)),
    );

    const s = await ledger.status("m-concurrent-release");
    expect(s!.allocatedUsd).toBe(0);
    expect(s!.remainingUsd).toBe(30);
  });
});

describe("D1SpendingLedger — opportunistic GC", () => {
  it("status() prunes expired budgets as a side-effect", async () => {
    const ledger = makeLedger();
    const past = Date.now() - 1_000;

    await ledger.init("expired-1", 100, past);
    await ledger.init("alive-1", 100);

    // Trigger GC by querying a different mandate
    await ledger.status("alive-1");

    // GC in our adapter is synchronous (Promise.resolve wraps sync call), so it's
    // already complete. expired-1 should be gone.
    const gone = await ledger.status("expired-1");
    expect(gone).toBeNull();
  });
});
