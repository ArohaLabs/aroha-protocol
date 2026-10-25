// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * verifyHttpSpendRequest — the one call a REST endpoint that spends money
 * under a mandate needs.
 *
 * WHY. verifyHttpMandateRequest proves who is asking and that a human's
 * mandate chain authorises them, but it never sees the amount. Everything
 * after that was left to the server, and two parts of it are easy to get
 * wrong: keeping a running total (without one, a $500 mandate pays any number
 * of $500 invoices), and keeping it for EVERY link of a delegated chain under
 * the right key (two sibling carts under one $500 intent can each claim the
 * full $500; a total keyed by the bare mandateId can be spent down by anyone
 * who mints a mandate reusing the id). This function does all of it:
 *
 *   1. verifyHttpMandateRequest — holder proof for this exact request, chain
 *      back to a pinned root, revocation, validity windows. Unchanged.
 *   2. The leaf must be a spending mandate (a task mandate is refused).
 *   3. The amount and every constraint of EVERY link are checked
 *      (checkSpendAgainstConstraints: currency, allowedMerchants,
 *      merchantCategory, requireHumanApprovalAboveUsd, and the amount against
 *      min(spendLimitUsd, sessionLimitUsd)). A constraint whose input the
 *      server did not supply refuses.
 *   4. The amount is charged against a running total for every link, keyed
 *      by mandateRedemptionKey (grantor#mandateId). All links or none: if one
 *      link would be exceeded, the links already charged are released.
 *
 * The nonce is consumed in step 1, before the spend checks: a request refused
 * for its amount has used its presentation, and the client signs a new one.
 */

import type { ArohaSpendingMandateBody } from "@aroha-sdk/core";
import {
  verifyHttpMandateRequest,
  type HttpPresentationFailureCode,
  type VerifyHttpMandateRequestOptions,
} from "./http-mandate.js";
import {
  checkSpendAgainstConstraints,
  checkSpendAmount,
  mandateCumulativeLimitUsd,
  type SpendConstraintCode,
} from "./mandate.js";
import { mandateRedemptionKey } from "./redemption.js";
import { BudgetExhaustedError, type ISpendingLedger } from "./spending-ledger.js";

export interface VerifyHttpSpendRequestOptions extends VerifyHttpMandateRequestOptions {
  /**
   * What this request spends, in `currency` units (the name says USD because
   * the mandate's limits are named that way; the limits are in the mandate's
   * own currency). Must be a finite number greater than 0. Take it from the
   * request you are about to act on — after the holder proof has bound the
   * body — never from a separate, unsigned source.
   */
  amountUsd: number;
  /** ISO 4217 code of `amountUsd`. Default "USD". Must equal every link's currency (default "USD"). */
  currency?: string;
  /** The payee's DID. Required when any link restricts `allowedMerchants`. */
  merchant?: string;
  /** The payee's merchant category. Required when any link sets `merchantCategory`. */
  merchantCategory?: string;
  /**
   * True only when a human approved THIS spend out of band (your approval
   * flow, not a flag the client sends). Required when the amount is above
   * any link's `requireHumanApprovalAboveUsd`.
   */
  humanApproved?: boolean;
  /**
   * Where running totals live. REQUIRED. Each link's total is kept under
   * mandateRedemptionKey(link) with the limit min(spendLimitUsd, sessionLimitUsd).
   *
   * MapSpendingLedger is in-memory: per process, and empty again after a
   * restart (everything already spent can be spent again). Use it for one
   * process and for tests. A server with more than one process, or one that
   * restarts, needs a shared durable ledger — D1SpendingLedger, or your own
   * ISpendingLedger whose allocate() is atomic.
   *
   * Use a ledger dedicated to request spending. The ledger passed to
   * issueIntentMandate / attenuateToCart counts what a parent HANDS OUT to
   * children, not what is spent; sharing one instance mixes the two.
   */
  ledger: ISpendingLedger;
}

export type HttpSpendFailureCode =
  | HttpPresentationFailureCode
  | "MANDATE_INVALID"
  | "ROOT_NOT_PINNED"
  | "NOT_A_SPENDING_MANDATE"
  | "INVALID_AMOUNT"
  | SpendConstraintCode
  | "LEDGER_UNAVAILABLE";

/** The money a successful call has taken from every link's running total. */
export interface HttpSpendCharge {
  amountUsd: number;
  /** One entry per link, root first: the ledger key and the allocation made under it. */
  allocations: { key: string; allocationId: string }[];
  /**
   * Give the money back to every link — call this when the side effect the
   * request paid for fails. Safe to call more than once. Throws if the ledger
   * could not release an allocation (the others are still released; calling
   * again retries only what is left).
   */
  release(): Promise<void>;
}

export type HttpSpendRequestResult =
  | {
      ok: true;
      holder: string;
      token: string;
      /** The verified leaf mandate. */
      mandate: ArohaSpendingMandateBody;
      /** The verified chain, root first, including the leaf. Every link was charged. */
      chain: ArohaSpendingMandateBody[];
      rootGrantor: string;
      /** False when the server passed `isRevoked: null` (revocation was not checked). */
      revocationChecked: boolean;
      charge: HttpSpendCharge;
    }
  | {
      ok: false;
      code: HttpSpendFailureCode;
      reason: string;
      /**
       * Suggested HTTP status: 401 bad or missing presentation, 403 the mandate
       * does not authorise this spend, 400 the server's own amount is invalid,
       * 503 the ledger could not be reached.
       */
      status: 400 | 401 | 403 | 503;
    };

const refuse = (
  code: HttpSpendFailureCode,
  reason: string,
  status: 400 | 401 | 403 | 503,
): HttpSpendRequestResult => ({ ok: false, code, reason, status });

/**
 * Verify a spending request and charge it, or refuse it. See the module
 * comment for every step. Throws TypeError for a server misconfiguration
 * (no ledger, no root pin option at all, no isRevoked) rather than running a
 * weaker check. A pin option that is supplied but empty (an account with no
 * enrolled DID) is a refusal, ROOT_NOT_PINNED (403), not a throw. `now` governs
 * presentation, nonce and mandate expiry alike.
 *
 *   const r = await verifyHttpSpendRequest(req.headers["aroha-mandate"], {
 *     audience, method: req.method, url: req.url, body: rawBody, nonces,
 *     expectedRoot: HUMAN_DID, isRevoked: null, ledger, amountUsd: invoice.amountUsd,
 *   });
 *   if (!r.ok) return res.status(r.status).json({ code: r.code });
 *   try { await sendInvoice(invoice); } catch (e) { await r.charge.release(); throw e; }
 */
export async function verifyHttpSpendRequest(
  headerValue: string | readonly string[] | null | undefined,
  options: VerifyHttpSpendRequestOptions,
): Promise<HttpSpendRequestResult> {
  const ledger = options?.ledger;
  if (!ledger || typeof ledger.init !== "function" || typeof ledger.allocate !== "function" || typeof ledger.release !== "function") {
    throw new TypeError("verifyHttpSpendRequest: a ledger is required (MapSpendingLedger for one process, a shared ISpendingLedger otherwise)");
  }
  for (const k of ["currency", "merchant", "merchantCategory"] as const) {
    if (options[k] !== undefined && (typeof options[k] !== "string" || options[k]!.length === 0)) {
      throw new TypeError(`verifyHttpSpendRequest: ${k} must be a non-empty string when given`);
    }
  }
  if (options.humanApproved !== undefined && typeof options.humanApproved !== "boolean") {
    throw new TypeError("verifyHttpSpendRequest: humanApproved must be a boolean when given");
  }

  // The amount is the server's own input: refuse it before touching the
  // presentation, so a bad amount does not consume the client's nonce.
  const amountProblem = checkSpendAmount(options.amountUsd);
  if (amountProblem) return refuse("INVALID_AMOUNT", amountProblem, 400);

  const { amountUsd, currency, merchant, merchantCategory, humanApproved, ledger: _ledger, ...mandateOptions } = options;
  const verified = await verifyHttpMandateRequest(headerValue, mandateOptions);
  if (!verified.ok) {
    if (verified.code === "MANDATE_INVALID" && presentedTaskMandate(headerValue)) {
      return refuse("NOT_A_SPENDING_MANDATE", "The presented mandate is a task mandate; this endpoint spends money", 403);
    }
    return refuse(verified.code, verified.reason, verified.status);
  }

  // Every link, root first. Narrowing makes a child at least as tight as its
  // parent, but checking each link costs nothing and does not rely on it.
  for (const link of verified.chain) {
    const problem = checkSpendAgainstConstraints(link.constraints, { amountUsd, currency, merchant, merchantCategory, humanApproved });
    if (problem) return refuse(problem.code, `${link.mandateTier} ${link.mandateId}: ${problem.reason}`, 403);
  }

  const charged: { key: string; allocationId: string }[] = [];
  const rollBack = async (): Promise<boolean> => {
    let clean = true;
    for (const a of charged.splice(0).reverse()) {
      try {
        await ledger.release(a.key, a.allocationId);
      } catch {
        clean = false;
      }
    }
    return clean;
  };
  for (const link of verified.chain) {
    const key = mandateRedemptionKey(link);
    try {
      // Idempotent: the first call for a key registers its limit, later ones
      // are no-ops. The limit is the one the grantor signed, and the key
      // includes the grantor, so nobody else can register it first.
      await ledger.init(key, mandateCumulativeLimitUsd(link.constraints));
      const { allocationId } = await ledger.allocate(key, amountUsd);
      charged.push({ key, allocationId });
    } catch (e) {
      const clean = await rollBack();
      const tail = clean ? "" : " (and releasing the links already charged failed; their totals stay reduced)";
      if (e instanceof BudgetExhaustedError) {
        return refuse(
          "OVER_LIMIT",
          `${link.mandateTier} ${link.mandateId}: $${amountUsd} would take the running total past the limit ` +
            `($${e.remainingUsd} left)${tail}`,
          403,
        );
      }
      return refuse("LEDGER_UNAVAILABLE", `Spending ledger unavailable${tail}`, 503);
    }
  }

  const allocations = charged.map((a) => ({ ...a }));
  const outstanding = [...allocations];
  const charge: HttpSpendCharge = {
    amountUsd,
    allocations,
    async release() {
      let first: unknown;
      for (const a of [...outstanding].reverse()) {
        try {
          await ledger.release(a.key, a.allocationId);
          outstanding.splice(outstanding.indexOf(a), 1);
        } catch (e) {
          first ??= e;
        }
      }
      if (first !== undefined) throw first;
    },
  };
  return {
    ok: true, holder: verified.holder, token: verified.token, mandate: verified.mandate, chain: verified.chain,
    rootGrantor: verified.rootGrantor, revocationChecked: verified.revocationChecked, charge,
  };
}

/** True when the header carries a task mandate (only consulted after the holder proof verified). */
function presentedTaskMandate(headerValue: unknown): boolean {
  if (typeof headerValue !== "string") return false;
  try {
    const p = JSON.parse(Buffer.from(headerValue, "base64url").toString("utf8")) as { token?: unknown };
    if (typeof p?.token !== "string") return false;
    const t = JSON.parse(Buffer.from(p.token, "base64url").toString("utf8")) as { mandate?: { mandateType?: unknown } };
    return t?.mandate !== null && typeof t?.mandate === "object" && t.mandate.mandateType !== undefined;
  } catch {
    return false;
  }
}
