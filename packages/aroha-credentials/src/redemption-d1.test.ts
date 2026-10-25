// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * D1RedemptionStore — the durable RedemptionStore. The property under test
 * is the cumulative cap holding across separate store INSTANCES on one
 * database (two payee processes), which InMemoryRedemptionStore cannot give.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import { D1RedemptionStore } from "./redemption-d1.js";
import { redeemPaymentMandate, type RedemptionRecord } from "./redemption.js";
import { issueIntentMandate, attenuateToCart, attenuateToPayment, SpendingConstraintViolation } from "./mandate.js";
import { openRedemptionDb } from "./test-utils/sqlite-d1.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const rec = (id: string, merchant = "did:aroha:shop"): RedemptionRecord => ({
  redemptionId: id, mandateId: "m1", amountUsd: 0, merchant, redeemedAt: new Date().toISOString(),
});

describe("D1RedemptionStore", () => {
  it("accumulates up to the limit and refuses beyond it, without recording the refused one", async () => {
    const store = new D1RedemptionStore(openRedemptionDb());
    expect(await store.tryRedeem("m1", 30_000_000, 50_000_000, rec("r1"))).toEqual({ accepted: true, redeemedMicros: 30_000_000 });
    expect(await store.tryRedeem("m1", 20_000_000, 50_000_000, rec("r2"))).toEqual({ accepted: true, redeemedMicros: 50_000_000 });
    expect(await store.tryRedeem("m1", 1, 50_000_000, rec("r3"))).toEqual({ accepted: false, redeemedMicros: 50_000_000 });
    expect((await store.history("m1")).map((h) => h.redemptionId)).toEqual(["r1", "r2"]);
  });

  it("two store instances on one database share the cap (two payee processes)", async () => {
    const db = openRedemptionDb();
    const a = new D1RedemptionStore(db, { actor: "payee-a" });
    const b = new D1RedemptionStore(db, { actor: "payee-b" });
    expect((await a.tryRedeem("m1", 40_000_000, 50_000_000, rec("r1"))).accepted).toBe(true);
    expect((await b.tryRedeem("m1", 40_000_000, 50_000_000, rec("r2"))).accepted).toBe(false);
    expect(await b.redeemedMicros("m1")).toBe(40_000_000);
    expect((await a.history("m1"))[0].actor).toBe("payee-a");
  });

  it("a later caller cannot raise the recorded limit; a tighter one is honoured", async () => {
    const store = new D1RedemptionStore(openRedemptionDb());
    await store.tryRedeem("m1", 10_000_000, 20_000_000, rec("r1"));
    expect((await store.tryRedeem("m1", 15_000_000, 1_000_000_000, rec("r2"))).accepted).toBe(false);
    expect((await store.tryRedeem("m1", 5_000_000, 12_000_000, rec("r3"))).accepted).toBe(false);
    expect((await store.tryRedeem("m1", 2_000_000, 12_000_000, rec("r4"))).accepted).toBe(true);
  });

  it("rejects non-integer, zero and negative amounts", async () => {
    const store = new D1RedemptionStore(openRedemptionDb());
    await expect(store.tryRedeem("m1", 0.5, 10, rec("r1"))).rejects.toThrow(RangeError);
    await expect(store.tryRedeem("m1", 0, 10, rec("r1"))).rejects.toThrow(RangeError);
    await expect(store.tryRedeem("m1", -1, 10, rec("r1"))).rejects.toThrow(RangeError);
    await expect(store.tryRedeem("m1", 1, Number.NaN, rec("r1"))).rejects.toThrow(RangeError);
  });

  it("unknown mandate has redeemed 0", async () => {
    expect(await new D1RedemptionStore(openRedemptionDb()).redeemedMicros("nope")).toBe(0);
  });

  it("works end-to-end under redeemPaymentMandate", async () => {
    const keys = await Promise.all([0, 1, 2, 3].map(async () => {
      const priv = ed.utils.randomPrivateKey();
      return { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
    }));
    const [human, agent, provider, processor] = keys;
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv);
    const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 60 }, agent.priv);
    const payment = await attenuateToPayment(cart, processor.did, { spendLimitUsd: 50 }, provider.priv);

    const db = openRedemptionDb();
    const r1 = await redeemPaymentMandate(new D1RedemptionStore(db), payment.mandate, 30, "did:aroha:shop");
    expect(r1.remainingUsd).toBe(20);
    await expect(redeemPaymentMandate(new D1RedemptionStore(db), payment.mandate, 30, "did:aroha:shop2"))
      .rejects.toBeInstanceOf(SpendingConstraintViolation);
  });
});
