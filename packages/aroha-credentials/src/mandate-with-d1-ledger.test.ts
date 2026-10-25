/**
 * Integration tests: mandate chain (intent → cart → payment) wired to D1SpendingLedger.
 *
 * These tests exercise the cross-package boundary between mandate.ts and
 * spending-ledger-d1.ts — the path the rating flagged as untested.
 * MapSpendingLedger tests live in mandate.test.ts; these specifically verify
 * the D1 persistence path with real SQL via the node:sqlite adapter.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  releaseAllocation,
} from "./mandate.js";
import { D1SpendingLedger } from "./spending-ledger-d1.js";
import { BudgetExhaustedError } from "./spending-ledger.js";
import { openSpendingDb } from "./test-utils/sqlite-d1.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// Deterministic test key pairs — key identity is not verified in unit tests
// (no DID resolution), so any consistent 32-byte seed works.
const USER_KEY = new Uint8Array(32).fill(0x01);   // user → agent (intent grantor)
const AGENT_KEY = new Uint8Array(32).fill(0x02);  // agent → cart-agent (cart grantor)

function makeStack() {
  return new D1SpendingLedger(openSpendingDb());
}

// ─── intent → cart ────────────────────────────────────────────────────────────

describe("D1SpendingLedger via mandate chain — intent → cart", () => {
  it("attenuateToCart deducts from the intent budget and returns allocationId", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );

    const cart = await attenuateToCart(
      intent, "did:aroha:cart-agent",
      { spendLimitUsd: 30 }, USER_KEY, 3_600_000, { ledger },
    );

    expect(cart.allocationId).toBeDefined();

    const status = await ledger.status(intent.mandate.mandateId);
    expect(status!.allocatedUsd).toBe(30);
    expect(status!.remainingUsd).toBe(70);
  });

  it("two children totalling the limit both succeed; a third is rejected", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );

    await attenuateToCart(intent, "did:aroha:cart-1", { spendLimitUsd: 60 }, USER_KEY, 3_600_000, { ledger });
    await attenuateToCart(intent, "did:aroha:cart-2", { spendLimitUsd: 40 }, USER_KEY, 3_600_000, { ledger });

    await expect(
      attenuateToCart(intent, "did:aroha:cart-3", { spendLimitUsd: 1 }, USER_KEY, 3_600_000, { ledger }),
    ).rejects.toThrow(BudgetExhaustedError);
  });

  it("releasing a cart allocation restores the parent budget", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );

    const cart = await attenuateToCart(
      intent, "did:aroha:cart-agent",
      { spendLimitUsd: 60 }, USER_KEY, 3_600_000, { ledger },
    );

    await releaseAllocation(intent.mandate.mandateId, cart.allocationId!, ledger);

    const status = await ledger.status(intent.mandate.mandateId);
    expect(status!.remainingUsd).toBe(100);
    expect(status!.allocatedUsd).toBe(0);
  });

  it("allocate throws BudgetExhaustedError when the intent budget is expired", async () => {
    const ledger = makeStack();
    // ttlMs of -60 000 ms places expiresAt one minute in the past.
    // ledger.init() records that past timestamp; allocate() rejects because
    // the expires_at CTE guard (expires_at IS NULL OR expires_at > now) fails.
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, -60_000, { ledger },
    );

    await expect(
      attenuateToCart(intent, "did:aroha:cart-agent", { spendLimitUsd: 10 }, USER_KEY, 3_600_000, { ledger }),
    ).rejects.toThrow(BudgetExhaustedError);
  });
});

// ─── cart → payment ───────────────────────────────────────────────────────────

describe("D1SpendingLedger via mandate chain — cart → payment", () => {
  it("attenuateToPayment deducts from the cart budget", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );

    const cart = await attenuateToCart(
      intent, "did:aroha:cart-agent",
      { spendLimitUsd: 50 }, USER_KEY, 3_600_000, { ledger },
    );

    const payment = await attenuateToPayment(
      cart, "did:aroha:merchant",
      { spendLimitUsd: 20 }, AGENT_KEY, 3_600_000, { ledger },
    );

    expect(payment.allocationId).toBeDefined();

    const cartStatus = await ledger.status(cart.mandate.mandateId);
    expect(cartStatus!.allocatedUsd).toBe(20);
    expect(cartStatus!.remainingUsd).toBe(30);
  });

  it("multiple payments from one cart are bounded by the cart limit", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );
    const cart = await attenuateToCart(
      intent, "did:aroha:cart-agent",
      { spendLimitUsd: 30 }, USER_KEY, 3_600_000, { ledger },
    );

    await attenuateToPayment(cart, "did:aroha:m1", { spendLimitUsd: 20 }, AGENT_KEY, 3_600_000, { ledger });
    await attenuateToPayment(cart, "did:aroha:m2", { spendLimitUsd: 10 }, AGENT_KEY, 3_600_000, { ledger });

    // Cart is now fully allocated — next payment throws
    await expect(
      attenuateToPayment(cart, "did:aroha:m3", { spendLimitUsd: 1 }, AGENT_KEY, 3_600_000, { ledger }),
    ).rejects.toThrow(BudgetExhaustedError);
  });

  it("releasing a payment allocation restores the cart budget", async () => {
    const ledger = makeStack();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, USER_KEY, 3_600_000, { ledger },
    );
    const cart = await attenuateToCart(
      intent, "did:aroha:cart-agent",
      { spendLimitUsd: 50 }, USER_KEY, 3_600_000, { ledger },
    );
    const payment = await attenuateToPayment(
      cart, "did:aroha:merchant",
      { spendLimitUsd: 20 }, AGENT_KEY, 3_600_000, { ledger },
    );

    await releaseAllocation(cart.mandate.mandateId, payment.allocationId!, ledger);

    const cartStatus = await ledger.status(cart.mandate.mandateId);
    expect(cartStatus!.remainingUsd).toBe(50);
  });
});
