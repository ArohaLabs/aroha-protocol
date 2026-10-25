// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Payment-mandate redemption tracking.
 *
 * Why this exists: a payment mandate is an authorisation for "up to $X". A
 * signature proves who granted it, but says nothing about how often it has
 * already been used — verifyMandateChain() will happily accept the same $50
 * token at ten merchants, or ten times at one. The SpendingLedger caps what a
 * parent HANDS OUT; this caps what a payment mandate actually SPENDS.
 *
 * Semantics — cumulative, not single-use: a payment mandate may be redeemed
 * in several parts (a split shipment, a deposit then a balance) as long as
 * the running total never exceeds its limit. The limit is
 * min(spendLimitUsd, sessionLimitUsd) — a payment mandate is one session, so
 * the tighter of the two applies. Single-use is the special case of
 * redeeming the full amount once.
 *
 * Scope: the guarantee holds across everything that shares one
 * RedemptionStore. InMemoryRedemptionStore is per-process — it stops one
 * verifier from honouring a token twice, nothing more. Payees that share
 * mandates across processes or organisations need a shared, durable store:
 *   - D1RedemptionStore (redemption-d1.ts) — your own D1/SQLite database,
 *     check-and-add in one batch;
 *   - httpRedemptionStore (mandate-registry-client.ts) — the Aroha registry's
 *     POST /v1/mandates/:mandateId/redeem, which re-verifies the token and
 *     derives the limit itself, so payees in different organisations share
 *     one cap without trusting each other's limit arithmetic.
 *
 * Amounts are tracked in integer micro-dollars (USD × 1e6) so that repeated
 * additions of decimal amounts like 0.1 cannot drift past the limit.
 */

import type { ArohaSpendingMandateBody } from "@aroha-sdk/core";
import {
  SpendingConstraintViolation,
  checkSpendMerchant,
  mandateCumulativeLimitUsd,
} from "./mandate.js";

/**
 * The key a RedemptionStore keeps a mandate's running total under:
 * `<grantor>#<mandateId>`.
 *
 * Not the bare mandateId. The id is chosen by whoever mints the mandate, so
 * a stranger can mint a valid mandate of their own that reuses yours and, in
 * a store shared between payees, spend down your cap. The grantor is fixed
 * by the signature. A DID cannot contain `#`, so the key splits back into
 * its two parts at the first one.
 */
export function mandateRedemptionKey(mandate: { grantor: string; mandateId: string }): string {
  return `${mandate.grantor}#${mandate.mandateId}`;
}

/** Inverse of mandateRedemptionKey; null for a key that is not one. */
export function parseMandateRedemptionKey(key: string): { grantor: string; mandateId: string } | null {
  const i = key.indexOf("#");
  if (i <= 0 || i === key.length - 1) return null;
  return { grantor: key.slice(0, i), mandateId: key.slice(i + 1) };
}

export interface RedemptionRecord {
  redemptionId: string;
  mandateId: string;
  amountUsd: number;
  merchant: string;
  redeemedAt: string;
  /**
   * The mandate token being redeemed. Optional for local stores; REQUIRED by
   * httpRedemptionStore, because the registry will not take a payee's word
   * for the limit — it re-verifies the token and derives the limit from it.
   * Pass it via redeemPaymentMandate(..., { token }).
   */
  token?: string;
}

export interface RedeemPaymentMandateOptions {
  /** Override "now" (Unix ms). */
  now?: number;
  /** The verified token — forwarded to the store (see RedemptionRecord.token). */
  token?: string;
}

export interface RedemptionStore {
  /**
   * ATOMICALLY: if (already redeemed for mandateId) + amountMicros ≤ limitMicros,
   * record the redemption and return accepted: true; otherwise change
   * nothing and return accepted: false. Totals are in integer micro-USD.
   * Implementations backed by a shared database must do the read and the
   * write in one transaction, or two payees can both pass the check.
   */
  tryRedeem(
    mandateId: string,
    amountMicros: number,
    limitMicros: number,
    record: RedemptionRecord
  ): Promise<{ accepted: boolean; redeemedMicros: number }>;

  /** Total redeemed so far for mandateId, in integer micro-USD (0 if none). */
  redeemedMicros(mandateId: string): Promise<number>;
}

/** Process-local RedemptionStore. Atomic because the check-and-add has no await in it. */
export class InMemoryRedemptionStore implements RedemptionStore {
  private readonly totals = new Map<string, number>();
  private readonly records = new Map<string, RedemptionRecord[]>();

  async tryRedeem(
    mandateId: string,
    amountMicros: number,
    limitMicros: number,
    record: RedemptionRecord
  ): Promise<{ accepted: boolean; redeemedMicros: number }> {
    // Integer micro-USD only. A fractional or unsafe value would make the
    // running total drift (or round a real spend to zero) — refuse it here,
    // where the arithmetic happens, not only in redeemPaymentMandate.
    if (!Number.isSafeInteger(amountMicros) || amountMicros < 1) {
      throw new RangeError(`amountMicros must be a safe integer ≥ 1 (got ${String(amountMicros)})`);
    }
    if (!Number.isSafeInteger(limitMicros) || limitMicros < 0) {
      throw new RangeError(`limitMicros must be a safe non-negative integer (got ${String(limitMicros)})`);
    }
    const current = this.totals.get(mandateId) ?? 0;
    if (current + amountMicros > limitMicros) {
      return { accepted: false, redeemedMicros: current };
    }
    const next = current + amountMicros;
    this.totals.set(mandateId, next);
    const list = this.records.get(mandateId) ?? [];
    list.push(record);
    this.records.set(mandateId, list);
    return { accepted: true, redeemedMicros: next };
  }

  async redeemedMicros(mandateId: string): Promise<number> {
    return this.totals.get(mandateId) ?? 0;
  }

  /** Redemption history for a mandate (for audit / tests). */
  history(mandateId: string): RedemptionRecord[] {
    return [...(this.records.get(mandateId) ?? [])];
  }
}

export interface RedemptionReceipt {
  redemptionId: string;
  mandateId: string;
  amountUsd: number;
  merchant: string;
  /** Running total redeemed against this mandate, including this redemption. */
  redeemedTotalUsd: number;
  /** What is left before the mandate's cumulative limit is reached. */
  remainingUsd: number;
}

const MICROS_PER_USD = 1_000_000;

function toMicros(usd: number): number {
  return Math.round(usd * MICROS_PER_USD);
}

/**
 * Record a spend against a payment mandate, enforcing its cumulative limit.
 *
 * Call this at settlement, AFTER verifyMandateChain() has accepted the token
 * — pass the verified `result.mandate`, not a body decoded by hand. It
 * re-checks the cheap per-redemption rules (tier, expiry, amount, merchant)
 * so a stale or mismatched call fails closed, then atomically adds the
 * amount to the mandate's running total.
 *
 * Throws SpendingConstraintViolation:
 *   - MANDATE_INVALID            not a payment mandate, or expired
 *   - INVALID_AMOUNT             amount not finite and > 0, or merchant empty
 *   - MERCHANT_NOT_ALLOWED       merchant outside constraints.allowedMerchants
 *   - REDEMPTION_LIMIT_EXCEEDED  running total would exceed the limit
 */
export async function redeemPaymentMandate(
  store: RedemptionStore,
  mandate: ArohaSpendingMandateBody,
  amountUsd: number,
  merchant: string,
  nowOrOptions: number | RedeemPaymentMandateOptions = Date.now()
): Promise<RedemptionReceipt> {
  const opts: RedeemPaymentMandateOptions =
    typeof nowOrOptions === "number" ? { now: nowOrOptions } : nowOrOptions;
  const now = opts.now ?? Date.now();
  if (mandate.mandateTier !== "payment") {
    throw new SpendingConstraintViolation(
      `Only payment mandates can be redeemed (got ${mandate.mandateTier})`,
      "MANDATE_INVALID"
    );
  }
  const expiresAtMs = Date.parse(mandate.expiresAt);
  if (Number.isNaN(expiresAtMs) || expiresAtMs < now) {
    throw new SpendingConstraintViolation("Payment mandate expired or has an invalid expiry", "MANDATE_INVALID");
  }
  if (typeof amountUsd !== "number" || !Number.isFinite(amountUsd) || amountUsd <= 0) {
    throw new SpendingConstraintViolation(
      `Redemption amount ${String(amountUsd)} must be a finite number greater than 0`,
      "INVALID_AMOUNT"
    );
  }
  if (typeof merchant !== "string" || merchant.length === 0) {
    throw new SpendingConstraintViolation("Redemption requires a merchant DID", "INVALID_AMOUNT");
  }

  const { constraints } = mandate;
  const merchantProblem = checkSpendMerchant(constraints, merchant);
  if (merchantProblem) throw new SpendingConstraintViolation(merchantProblem, "MERCHANT_NOT_ALLOWED");

  const limitUsd = mandateCumulativeLimitUsd(constraints);
  const limitMicros = toMicros(limitUsd);
  const amountMicros = toMicros(amountUsd);
  // A positive amount below half a micro-dollar rounds to 0 micros — a
  // "redemption" that adds nothing to the running total, repeatable forever.
  if (amountMicros < 1) {
    throw new SpendingConstraintViolation(
      `Redemption amount ${String(amountUsd)} is below the smallest unit (1 micro-USD)`,
      "INVALID_AMOUNT"
    );
  }

  const record: RedemptionRecord = {
    redemptionId: crypto.randomUUID(),
    mandateId: mandate.mandateId,
    amountUsd,
    merchant,
    redeemedAt: new Date(now).toISOString(),
    ...(opts.token !== undefined ? { token: opts.token } : {}),
  };

  const result = await store.tryRedeem(mandateRedemptionKey(mandate), amountMicros, limitMicros, record);
  if (!result.accepted) {
    throw new SpendingConstraintViolation(
      `Redeeming $${amountUsd} would exceed mandate ${mandate.mandateId}'s limit of $${limitUsd} ` +
        `($${result.redeemedMicros / MICROS_PER_USD} already redeemed)`,
      "REDEMPTION_LIMIT_EXCEEDED"
    );
  }

  return {
    redemptionId: record.redemptionId,
    mandateId: mandate.mandateId,
    amountUsd,
    merchant,
    redeemedTotalUsd: result.redeemedMicros / MICROS_PER_USD,
    remainingUsd: (limitMicros - result.redeemedMicros) / MICROS_PER_USD,
  };
}
