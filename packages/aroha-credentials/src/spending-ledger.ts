// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * SpendingLedger — cumulative budget enforcement for mandate chains.
 *
 * The mandate chain (assertNarrowing) guarantees each individual child
 * mandate cannot claim more than its parent's stated limit. But without a
 * shared counter it is possible to issue N children each claiming the full
 * parent limit, effectively multiplying the budget.
 *
 * The SpendingLedger closes that gap: every call to attenuateToCart /
 * attenuateToPayment atomically deducts the child's spendLimitUsd from the
 * parent's remaining balance. Over-allocation throws BudgetExhaustedError
 * before the child mandate token is ever signed.
 *
 * Analogy: the mandate is a payment channel. The ledger is the channel state.
 * Cryptographic narrowing proves the chain is valid; the ledger proves the
 * capacity was actually available when the child was issued.
 *
 * Lifecycle:
 *   issueIntentMandate  → ledger.init(mandateId, limit)
 *   attenuateToCart     → ledger.allocate(parentId, amount)  ← throws if exhausted
 *   attenuateToPayment  → ledger.allocate(parentId, amount)  ← throws if exhausted
 *   saga compensation   → ledger.release(parentId, allocationId)
 *
 * Two implementations are provided:
 *   MapSpendingLedger  — in-process Map, suitable for single-process deployments
 *                        and tests. Allocation is atomic within the JS event loop
 *                        (no await between check and deduct).
 *
 *   ISpendingLedger    — interface for plug-in backends (D1, Redis, Postgres).
 *                        Implement this for multi-process / edge deployments where
 *                        the ledger must survive process restarts.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BudgetStatus {
  mandateId: string;
  limitUsd: number;
  allocatedUsd: number;
  remainingUsd: number;
  allocationCount: number;
}

export interface AllocationResult {
  allocationId: string;
  remainingUsd: number;
}

// ─── Error ────────────────────────────────────────────────────────────────────

export class BudgetExhaustedError extends Error {
  readonly code = "BUDGET_EXHAUSTED" as const;

  constructor(
    public readonly mandateId: string,
    public readonly requestedUsd: number,
    public readonly remainingUsd: number
  ) {
    super(
      `Budget exhausted for mandate ${mandateId}: ` +
      `requested $${requestedUsd.toFixed(2)}, ` +
      `only $${remainingUsd.toFixed(2)} remaining`
    );
    this.name = "BudgetExhaustedError";
  }
}

// ─── Interface ────────────────────────────────────────────────────────────────

export interface ISpendingLedger {
  /**
   * Register a new mandate's budget. Idempotent — safe to call twice with
   * the same mandateId (subsequent calls are no-ops).
   *
   * @param expiresAt  Unix ms timestamp at which the budget expires (= mandate's
   *                   own expiresAt). allocate() rejects after this time.
   *                   Omit or pass undefined for no expiry.
   */
  init(mandateId: string, limitUsd: number, expiresAt?: number): Promise<void>;

  /**
   * Atomically allocate amountUsd from the parent mandate's remaining budget.
   *
   * Throws BudgetExhaustedError if `allocated + amountUsd > limit`.
   * Returns the allocationId — store it alongside the child mandate so you
   * can call release() during saga compensation.
   */
  allocate(parentMandateId: string, amountUsd: number): Promise<AllocationResult>;

  /**
   * Return a previously allocated amount to the parent's available budget.
   * Called during saga compensation or when a mandate expires unused.
   * Safe to call with an unknown allocationId (no-op).
   */
  release(parentMandateId: string, allocationId: string): Promise<{ remainingUsd: number }>;

  /** Current state of a mandate's budget. Returns null if not registered. */
  status(mandateId: string): Promise<BudgetStatus | null>;
}

// ─── In-process implementation ────────────────────────────────────────────────

// Amounts are held as integer micro-USD. Adding and subtracting decimal
// dollars as floats drifts (0.1 + 0.2 !== 0.3), and a ledger that drifts can
// hand out a fraction of a cent more than the parent's limit, or refuse the
// last allocation that should exactly fit.
const MICROS_PER_USD = 1_000_000;
const toMicros = (usd: number): number => Math.round(usd * MICROS_PER_USD);
const toUsd = (micros: number): number => micros / MICROS_PER_USD;

function assertAmount(name: string, usd: number): void {
  if (typeof usd !== "number" || !Number.isFinite(usd) || usd < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number of USD (got ${String(usd)})`);
  }
  if (!Number.isSafeInteger(toMicros(usd))) {
    throw new RangeError(`${name} is too large to account for exactly (got ${String(usd)})`);
  }
}

interface BudgetEntry {
  /** Integer micro-USD. */
  limitMicros: number;
  /** Integer micro-USD. */
  allocatedMicros: number;
  expiresAt?: number;  // Unix ms; undefined = never expires
  /** allocationId → reserved amount, integer micro-USD */
  allocations: Map<string, number>;
}

/**
 * In-process spending ledger backed by a plain Map.
 *
 * Allocation is atomic within the JS single-threaded model: there is no
 * `await` between the remaining-balance check and the deduction, so no other
 * microtask can interleave and over-allocate.
 *
 * Use this for:
 *   - Single-process agents and orchestrators
 *   - Tests and local development
 *   - Ephemeral saga sessions that don't need cross-process consistency
 *
 * For multi-process or edge deployments, implement ISpendingLedger against
 * Cloudflare D1, Redis, or Postgres with row-level locking on the budget row.
 */
export class MapSpendingLedger implements ISpendingLedger {
  private readonly budgets = new Map<string, BudgetEntry>();

  async init(mandateId: string, limitUsd: number, expiresAt?: number): Promise<void> {
    assertAmount("limitUsd", limitUsd);
    if (!this.budgets.has(mandateId)) {
      this.budgets.set(mandateId, {
        limitMicros: toMicros(limitUsd),
        allocatedMicros: 0,
        expiresAt,
        allocations: new Map(),
      });
    }
  }

  async allocate(parentMandateId: string, amountUsd: number): Promise<AllocationResult> {
    // A negative allocation would ADD budget back; NaN would compare false
    // against `remaining` and slip through.
    assertAmount("amountUsd", amountUsd);
    const budget = this.budgets.get(parentMandateId);
    if (!budget) {
      throw new Error(
        `No budget registered for mandate ${parentMandateId}. ` +
        `Pass { ledger } to issueIntentMandate() so the root budget is initialised ` +
        `before any children are issued.`
      );
    }

    if (budget.expiresAt !== undefined && Date.now() > budget.expiresAt) {
      throw new BudgetExhaustedError(parentMandateId, amountUsd, 0);
    }

    // Atomic check + deduct — no await between these two lines.
    const amountMicros = toMicros(amountUsd);
    const remaining = budget.limitMicros - budget.allocatedMicros;
    if (amountMicros > remaining) {
      throw new BudgetExhaustedError(parentMandateId, amountUsd, toUsd(remaining));
    }
    budget.allocatedMicros += amountMicros;
    const allocationId = crypto.randomUUID();
    budget.allocations.set(allocationId, amountMicros);

    return { allocationId, remainingUsd: toUsd(budget.limitMicros - budget.allocatedMicros) };
  }

  async release(parentMandateId: string, allocationId: string): Promise<{ remainingUsd: number }> {
    const budget = this.budgets.get(parentMandateId);
    if (!budget) return { remainingUsd: 0 };

    const amount = budget.allocations.get(allocationId);
    if (amount === undefined) {
      return { remainingUsd: toUsd(budget.limitMicros - budget.allocatedMicros) };
    }

    budget.allocatedMicros = Math.max(0, budget.allocatedMicros - amount);
    budget.allocations.delete(allocationId);
    return { remainingUsd: toUsd(budget.limitMicros - budget.allocatedMicros) };
  }

  async status(mandateId: string): Promise<BudgetStatus | null> {
    const budget = this.budgets.get(mandateId);
    if (!budget) return null;
    return {
      mandateId,
      limitUsd: toUsd(budget.limitMicros),
      allocatedUsd: toUsd(budget.allocatedMicros),
      remainingUsd: toUsd(budget.limitMicros - budget.allocatedMicros),
      allocationCount: budget.allocations.size,
    };
  }
}
