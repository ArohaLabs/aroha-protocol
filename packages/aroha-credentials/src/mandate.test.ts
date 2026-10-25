// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandate,
  releaseAllocation,
  issueTaskMandate,
  attenuateTaskMandate,
  verifyTaskMandate,
  signInvariants,
  verifySignedInvariants,
  verifyInvariants,
  type SignedMandate,
} from "./mandate.js";
import { MapSpendingLedger, BudgetExhaustedError } from "./spending-ledger.js";
import { generateDid, type SpendingConstraints, type TaskConstraints, type MandateInvariants } from "@aroha-sdk/core";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeKey() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub };
}

/** A keypair plus the content-addressed DID that commits to it. */
async function makeDidKey() {
  const k = await makeKey();
  return { ...k, did: generateDid(k.pub) };
}

const BASE: SpendingConstraints = {
  spendLimitUsd: 500,
  sessionLimitUsd: 200,
  requireHumanApprovalAboveUsd: 100,
  allowedMerchants: ["merchant-a", "merchant-b", "merchant-c"],
};

// ─── issueIntentMandate ───────────────────────────────────────────────────────

describe("issueIntentMandate", () => {
  it("issues a mandate with correct fields", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:grantor", "did:aroha:grantee", BASE, k.priv);
    expect(m.mandate.mandateTier).toBe("intent");
    expect(m.mandate.grantor).toBe("did:aroha:grantor");
    expect(m.mandate.grantee).toBe("did:aroha:grantee");
    expect(m.mandate.parentMandateId).toBeNull();
    expect(m.mandate.mandateId).toBeTruthy();
    expect(new Date(m.mandate.expiresAt) > new Date()).toBe(true);
    expect(m.token).toBeTruthy();
    expect(m.signature).toBeTruthy();
  });

  it("respects custom ttlMs", async () => {
    const k = await makeKey();
    const before = Date.now();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv, 10_000);
    const expMs = new Date(m.mandate.expiresAt).getTime();
    expect(expMs - before).toBeGreaterThan(9_000);
    expect(expMs - before).toBeLessThan(11_000);
  });
});

// ─── verifyMandate ────────────────────────────────────────────────────────────

describe("verifyMandate", () => {
  it("accepts a valid token", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv);
    const r = await verifyMandate(m.token, k.pub);
    expect(r.valid).toBe(true);
    expect(r.mandate?.mandateId).toBe(m.mandate.mandateId);
  });

  it("rejects a token signed by a different key", async () => {
    const k = await makeKey();
    const other = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv);
    const r = await verifyMandate(m.token, other.pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/signature/i);
  });

  it("rejects an expired mandate", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv, -1);
    const r = await verifyMandate(m.token, k.pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expired/i);
  });

  it("rejects grantee mismatch", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv);
    const r = await verifyMandate(m.token, k.pub, "did:aroha:someone-else");
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/grantee/i);
  });

  it("rejects malformed token", async () => {
    const k = await makeKey();
    const r = await verifyMandate("not!!valid!!base64url", k.pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/malformed/i);
  });

  it("accepts token when issuedAt is after key_rotated_at", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv);
    const issuedAtMs = new Date(m.mandate.issuedAt).getTime();
    // Rotation happened before the mandate was issued — token should be valid
    const r = await verifyMandate(m.token, k.pub, undefined, { keyRotatedAt: issuedAtMs - 1_000 });
    expect(r.valid).toBe(true);
  });

  it("rejects token when issuedAt precedes key_rotated_at (signed with revoked key)", async () => {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:g", "did:aroha:e", BASE, k.priv);
    const issuedAtMs = new Date(m.mandate.issuedAt).getTime();
    // Rotation happened after the mandate was issued — token was signed with the old key
    const r = await verifyMandate(m.token, k.pub, undefined, { keyRotatedAt: issuedAtMs + 1_000 });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/rotated/i);
  });
});

// ─── attenuateToCart — narrowing enforcement ──────────────────────────────────

describe("attenuateToCart narrowing", () => {
  async function intent(): Promise<[SignedMandate, Uint8Array, Uint8Array]> {
    const k = await makeKey();
    const m = await issueIntentMandate("did:aroha:user", "did:aroha:agent", BASE, k.priv);
    return [m, k.priv, k.pub];
  }

  it("allows valid narrowing", async () => {
    const [parent, agentKey] = await intent();
    const narrow: SpendingConstraints = {
      spendLimitUsd: 100,
      sessionLimitUsd: 50,
      requireHumanApprovalAboveUsd: 50,
      allowedMerchants: ["merchant-a"],
    };
    await expect(
      attenuateToCart(parent, "did:aroha:provider", narrow, agentKey)
    ).resolves.toBeDefined();
  });

  it("rejects spendLimitUsd widening", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 1000 }, agentKey)
    ).rejects.toThrow(/spendLimit/i);
  });

  it("rejects sessionLimitUsd widening", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, sessionLimitUsd: 999 }, agentKey)
    ).rejects.toThrow(/sessionLimit/i);
  });

  it("rejects requireHumanApprovalAboveUsd widening", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, requireHumanApprovalAboveUsd: 999 }, agentKey)
    ).rejects.toThrow(/approval threshold/i);
  });

  it("rejects allowedMerchants with unlisted merchant", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        allowedMerchants: ["merchant-a", "merchant-unknown"],
      }, agentKey)
    ).rejects.toThrow(/allowedMerchants/i);
  });

  it("rejects empty allowedMerchants when parent restricts", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        allowedMerchants: [],
      }, agentKey)
    ).rejects.toThrow(/allowedMerchants/i);
  });

  it("rejects missing allowedMerchants when parent restricts", async () => {
    const [parent, agentKey] = await intent();
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100 }, agentKey)
    ).rejects.toThrow(/allowedMerchants/i);
  });
});

// ─── attenuateToPayment — narrowing enforcement ───────────────────────────────

describe("attenuateToPayment narrowing", () => {
  it("rejects spendLimitUsd widening from cart", async () => {
    const intentKey = await makeKey();
    const cartKey = await makeKey();
    const intent = await issueIntentMandate("did:aroha:user", "did:aroha:agent", BASE, intentKey.priv);
    const cart = await attenuateToCart(intent, "did:aroha:provider", {
      spendLimitUsd: 100, allowedMerchants: ["merchant-a"],
    }, intentKey.priv);
    await expect(
      attenuateToPayment(cart, "did:aroha:processor", { spendLimitUsd: 999 }, cartKey.priv)
    ).rejects.toThrow(/spendLimit/i);
  });
});

// ─── Full chain: intent → cart → payment ─────────────────────────────────────

describe("full delegation chain", () => {
  // CHANGED for the chain-verification fix: this test used to sign all three
  // links with the USER's key while naming did:aroha:agent / did:aroha:provider
  // as the cart and payment grantors, then "verified" the payment against the
  // user key alone. That only passed because verifyMandate never walked the
  // chain — a cart signed by someone other than its grantor is exactly the
  // forgery the verifier must now reject. Each link is now signed by the key
  // its grantor DID commits to.
  it("intent → cart → payment verifies end-to-end", async () => {
    const user = await makeDidKey();
    const agent = await makeDidKey();
    const provider = await makeDidKey();
    const processor = await makeDidKey();

    const intent = await issueIntentMandate(user.did, agent.did, BASE, user.priv);
    const cart = await attenuateToCart(intent, provider.did, {
      spendLimitUsd: 100,
      allowedMerchants: ["merchant-a"],
    }, agent.priv);
    const payment = await attenuateToPayment(cart, processor.did, {
      spendLimitUsd: 42,
      allowedMerchants: ["merchant-a"],
    }, provider.priv);

    expect(payment.mandate.mandateTier).toBe("payment");
    expect(payment.mandate.parentMandateId).toBe(cart.mandate.mandateId);
    expect(payment.mandate.constraints.spendLimitUsd).toBe(42);

    const r = await verifyMandate(payment.token, provider.pub, processor.did);
    expect(r.valid).toBe(true);
    expect(r.chainVerified).toBe(true);
    expect(r.rootGrantor).toBe(user.did);
  });
});

describe("assertNarrowing — merchantCategory", () => {
  it("allows child to keep same merchantCategory", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: "travel" }, k.priv)
    ).resolves.toBeDefined();
  });

  it("rejects child setting merchantCategory to null when parent restricts it", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: null }, k.priv)
    ).rejects.toThrow(/merchantCategory/i);
  });

  it("rejects child setting different merchantCategory", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: "food" }, k.priv)
    ).rejects.toThrow(/merchantCategory/i);
  });
});

describe("assertNarrowing — validUntil / validFrom", () => {
  const future = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

  it("rejects child validUntil beyond parent validUntil", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validUntil: future(3_600_000), // 1 hour
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validUntil: future(7_200_000), // 2 hours — wider
      }, k.priv)
    ).rejects.toThrow(/validUntil/i);
  });

  it("allows child validUntil within parent window", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validUntil: future(3_600_000),
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validUntil: future(1_800_000), // 30 min — narrower
      }, k.priv)
    ).resolves.toBeDefined();
  });

  it("rejects child validFrom before parent validFrom", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validFrom: future(3_600_000),
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validFrom: future(1_800_000), // starts earlier than parent — wider
      }, k.priv)
    ).rejects.toThrow(/validFrom/i);
  });
});

// ─── SpendingLedger — cumulative budget enforcement ───────────────────────────

// ─── SpendingLedger — budget expiry ──────────────────────────────────────────

describe("SpendingLedger — budget expiry", () => {
  it("rejects allocate on an already-expired budget", async () => {
    const ledger = new MapSpendingLedger();
    await ledger.init("m-expired", 500, Date.now() - 1); // expired 1 ms ago
    await expect(ledger.allocate("m-expired", 100)).rejects.toBeInstanceOf(BudgetExhaustedError);
  });

  it("BudgetExhaustedError from expiry carries remainingUsd 0", async () => {
    const ledger = new MapSpendingLedger();
    await ledger.init("m-expired-meta", 500, Date.now() - 1);
    const err = await ledger.allocate("m-expired-meta", 100).catch((e) => e) as BudgetExhaustedError;
    expect(err.code).toBe("BUDGET_EXHAUSTED");
    expect(err.remainingUsd).toBe(0);
    expect(err.requestedUsd).toBe(100);
  });

  it("allows allocate when budget has not yet expired", async () => {
    const ledger = new MapSpendingLedger();
    await ledger.init("m-live", 500, Date.now() + 60_000);
    const result = await ledger.allocate("m-live", 100);
    expect(result.remainingUsd).toBe(400);
  });

  it("issueIntentMandate threads mandate expiresAt into ledger.init()", async () => {
    // Issue with a 1 ms TTL so the budget expires almost immediately.
    const k = await makeKey();
    const ledger = new MapSpendingLedger();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 500 }, k.priv,
      1,          // ttlMs — mandate expires in 1 ms
      { ledger },
    );
    // Wait long enough for the budget to expire.
    await new Promise((r) => setTimeout(r, 20));
    // attenuateToCart calls ledger.allocate() — budget is expired, must throw.
    await expect(
      attenuateToCart(intent, "did:aroha:provider", { spendLimitUsd: 100 }, k.priv, undefined, { ledger }),
    ).rejects.toBeInstanceOf(BudgetExhaustedError);
  });

  it("init is idempotent — second call with same mandateId is a no-op", async () => {
    const ledger = new MapSpendingLedger();
    await ledger.init("m-idem", 500, Date.now() + 60_000);
    await ledger.allocate("m-idem", 100);
    // Second init with different limit is silently ignored
    await ledger.init("m-idem", 999);
    const status = await ledger.status("m-idem");
    expect(status?.limitUsd).toBe(500); // original limit unchanged
    expect(status?.allocatedUsd).toBe(100);
  });
});

describe("SpendingLedger — cumulative enforcement", () => {
  it("allocates children up to parent limit", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 300 }, k.priv, 3_600_000, { ledger }
    );

    const cart1 = await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 100 }, k.priv, undefined, { ledger });
    const cart2 = await attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 100 }, k.priv, undefined, { ledger });

    expect(cart1.allocationId).toBeTruthy();
    expect(cart2.allocationId).toBeTruthy();
    expect(cart1.allocationId).not.toBe(cart2.allocationId);

    const status = await ledger.status(intent.mandate.mandateId);
    expect(status?.allocatedUsd).toBe(200);
    expect(status?.remainingUsd).toBe(100);
  });

  it("rejects allocation that would exceed parent limit", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 200 }, k.priv, 3_600_000, { ledger }
    );

    await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 150 }, k.priv, undefined, { ledger });

    // $50 remaining — $100 request must be rejected
    await expect(
      attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 100 }, k.priv, undefined, { ledger })
    ).rejects.toThrow(BudgetExhaustedError);
  });

  it("rejects duplicate full-limit children (the classic double-allocation gap)", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 500 }, k.priv, 3_600_000, { ledger }
    );

    // First child claims full limit — passes assertNarrowing AND allocates $500
    await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 500 }, k.priv, undefined, { ledger });

    // Second child tries same — passes assertNarrowing (500 ≤ 500) but ledger rejects
    await expect(
      attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 500 }, k.priv, undefined, { ledger })
    ).rejects.toThrow(/budget exhausted/i);
  });

  it("releases allocation so budget can be reused", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 200 }, k.priv, 3_600_000, { ledger }
    );

    const cart = await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 200 }, k.priv, undefined, { ledger });

    // Fully allocated — any further allocation must fail
    await expect(
      attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 1 }, k.priv, undefined, { ledger })
    ).rejects.toThrow(BudgetExhaustedError);

    // Saga compensation: release the allocation
    const { remainingUsd } = await releaseAllocation(intent.mandate.mandateId, cart.allocationId!, ledger);
    expect(remainingUsd).toBe(200);

    // Budget is restored — a new child can now be issued
    await expect(
      attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 200 }, k.priv, undefined, { ledger })
    ).resolves.toBeDefined();
  });

  it("enforces sub-allocation at the cart level too", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 500 }, k.priv, 3_600_000, { ledger }
    );

    const cart = await attenuateToCart(
      intent, "did:aroha:provider",
      { spendLimitUsd: 200 }, k.priv, undefined, { ledger }
    );
    // cart now has its own $200 pool in the ledger

    const pay1 = await attenuateToPayment(cart, "did:aroha:processor", { spendLimitUsd: 150 }, k.priv, undefined, { ledger });
    expect(pay1.allocationId).toBeTruthy();

    // $50 left in cart pool — $100 must be rejected
    await expect(
      attenuateToPayment(cart, "did:aroha:processor2", { spendLimitUsd: 100 }, k.priv, undefined, { ledger })
    ).rejects.toThrow(BudgetExhaustedError);
  });

  it("works without ledger — narrowing only (backward compat)", async () => {
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 200 }, k.priv
    );

    // Without a ledger, multiple children at the full limit are still possible
    // (old behaviour preserved)
    const cart1 = await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 200 }, k.priv);
    const cart2 = await attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 200 }, k.priv);

    expect(cart1.allocationId).toBeUndefined();
    expect(cart2.allocationId).toBeUndefined();
  });

  it("BudgetExhaustedError carries structured metadata", async () => {
    const ledger = new MapSpendingLedger();
    const k = await makeKey();
    const intent = await issueIntentMandate(
      "did:aroha:user", "did:aroha:agent",
      { spendLimitUsd: 100 }, k.priv, 3_600_000, { ledger }
    );
    await attenuateToCart(intent, "did:aroha:a", { spendLimitUsd: 80 }, k.priv, undefined, { ledger });

    try {
      await attenuateToCart(intent, "did:aroha:b", { spendLimitUsd: 50 }, k.priv, undefined, { ledger });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(BudgetExhaustedError);
      const e = err as BudgetExhaustedError;
      expect(e.code).toBe("BUDGET_EXHAUSTED");
      expect(e.requestedUsd).toBe(50);
      expect(e.remainingUsd).toBe(20);
      expect(e.mandateId).toBe(intent.mandate.mandateId);
    }
  });
});

// ─── Task mandate invariants (design spec §9.1 Layer 1) ───────────────────────

const TASK_CONSTRAINTS: TaskConstraints = {
  actionLimits: { "book-flight": 1 },
};

describe("task mandate invariants", () => {
  it("round-trips invariants through issue/verify", async () => {
    const k = await makeKey();
    const invariants: MandateInvariants = {
      payee: ["did:aroha:airline-x"],
      parameters: { destination: "JFK" },
      maxAmount: { amount: 500, currency: "USD" },
      expiry: new Date(Date.now() + 60_000).toISOString(),
    };
    const m = await issueTaskMandate(
      "did:aroha:grantor",
      "did:aroha:grantee",
      ["book-flight"],
      TASK_CONSTRAINTS,
      k.priv,
      3_600_000,
      { invariants }
    );

    const result = await verifyTaskMandate(m.token, k.pub);
    expect(result.valid).toBe(true);
    expect(result.mandate?.invariants).toEqual(invariants);
  });

  it("rejects a mandate with a tampered invariants field", async () => {
    const k = await makeKey();
    const invariants: MandateInvariants = { payee: ["did:aroha:airline-x"] };
    const m = await issueTaskMandate(
      "did:aroha:grantor",
      "did:aroha:grantee",
      ["book-flight"],
      TASK_CONSTRAINTS,
      k.priv,
      3_600_000,
      { invariants }
    );

    const decoded = JSON.parse(Buffer.from(m.token, "base64url").toString("utf8"));
    decoded.mandate.invariants.payee = ["did:aroha:attacker"];
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    const result = await verifyTaskMandate(tamperedToken, k.pub);
    expect(result.valid).toBe(false);
  });

  describe("attenuation narrowing", () => {
    it("allows a child that keeps the same payee/amount/expiry", async () => {
      const k = await makeKey();
      const parentInvariants: MandateInvariants = {
        payee: ["did:aroha:airline-x", "did:aroha:airline-y"],
        maxAmount: { amount: 500, currency: "USD" },
        expiry: new Date(Date.now() + 60_000).toISOString(),
      };
      const parent = await issueTaskMandate(
        "did:aroha:root",
        "did:aroha:planner",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        3_600_000,
        { invariants: parentInvariants }
      );

      const child = await attenuateTaskMandate(
        parent,
        "did:aroha:worker",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        undefined,
        { invariants: { payee: ["did:aroha:airline-x"], maxAmount: { amount: 300, currency: "USD" }, expiry: parentInvariants.expiry } }
      );

      expect(child.mandate.invariants?.payee).toEqual(["did:aroha:airline-x"]);
    });

    it("rejects a child that widens the payee list beyond the parent's", async () => {
      const k = await makeKey();
      const parent = await issueTaskMandate(
        "did:aroha:root",
        "did:aroha:planner",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        3_600_000,
        { invariants: { payee: ["did:aroha:airline-x"] } }
      );

      await expect(
        attenuateTaskMandate(parent, "did:aroha:worker", ["book-flight"], TASK_CONSTRAINTS, k.priv, undefined, {
          invariants: { payee: ["did:aroha:airline-x", "did:aroha:attacker"] },
        })
      ).rejects.toThrow(/payee/);
    });

    it("rejects a child that raises maxAmount above the parent's", async () => {
      const k = await makeKey();
      const parent = await issueTaskMandate(
        "did:aroha:root",
        "did:aroha:planner",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        3_600_000,
        { invariants: { maxAmount: { amount: 200, currency: "USD" } } }
      );

      await expect(
        attenuateTaskMandate(parent, "did:aroha:worker", ["book-flight"], TASK_CONSTRAINTS, k.priv, undefined, {
          invariants: { maxAmount: { amount: 500, currency: "USD" } },
        })
      ).rejects.toThrow(/maxAmount/);
    });

    it("rejects a child that changes a fixed parameter value from the parent's", async () => {
      const k = await makeKey();
      const parent = await issueTaskMandate(
        "did:aroha:root",
        "did:aroha:planner",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        3_600_000,
        { invariants: { parameters: { destination: "JFK" } } }
      );

      await expect(
        attenuateTaskMandate(parent, "did:aroha:worker", ["book-flight"], TASK_CONSTRAINTS, k.priv, undefined, {
          invariants: { parameters: { destination: "LAX" } },
        })
      ).rejects.toThrow(/parameter/);
    });

    it("rejects a child that drops invariants the parent required", async () => {
      const k = await makeKey();
      const parent = await issueTaskMandate(
        "did:aroha:root",
        "did:aroha:planner",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv,
        3_600_000,
        { invariants: { payee: ["did:aroha:airline-x"] } }
      );

      await expect(
        attenuateTaskMandate(parent, "did:aroha:worker", ["book-flight"], TASK_CONSTRAINTS, k.priv)
      ).rejects.toThrow(/invariants/);
    });
  });
});

// ─── signInvariants / verifySignedInvariants / verifyInvariants ───────────────

describe("signInvariants / verifySignedInvariants", () => {
  it("signs and verifies a valid invariants block", async () => {
    const k = await makeKey();
    const invariants: MandateInvariants = {
      payee: ["did:aroha:airline-x"],
      maxAmount: { amount: 500, currency: "USD" },
    };
    const signed = await signInvariants(invariants, "did:aroha:principal", k.priv);
    expect(await verifySignedInvariants(signed, k.pub)).toBe(true);
  });

  it("rejects a tampered invariants block", async () => {
    const k = await makeKey();
    const signed = await signInvariants({ payee: ["did:aroha:airline-x"] }, "did:aroha:principal", k.priv);
    signed.invariants.payee = ["did:aroha:attacker"];
    expect(await verifySignedInvariants(signed, k.pub)).toBe(false);
  });

  it("rejects a signature verified against the wrong public key", async () => {
    const k1 = await makeKey();
    const k2 = await makeKey();
    const signed = await signInvariants({ payee: ["did:aroha:airline-x"] }, "did:aroha:principal", k1.priv);
    expect(await verifySignedInvariants(signed, k2.pub)).toBe(false);
  });
});

describe("verifyInvariants (commit-time check)", () => {
  const invariants: MandateInvariants = {
    payee: ["did:aroha:airline-x"],
    parameters: { destination: "JFK" },
    maxAmount: { amount: 500, currency: "USD" },
  };

  it("passes when the actual action matches the bound invariants", () => {
    const result = verifyInvariants(
      { payee: "did:aroha:airline-x", parameters: { destination: "JFK" }, amount: { amount: 480, currency: "USD" } },
      invariants
    );
    expect(result.ok).toBe(true);
  });

  it("fails when the payee was redirected", () => {
    const result = verifyInvariants(
      { payee: "did:aroha:attacker", parameters: { destination: "JFK" }, amount: { amount: 480, currency: "USD" } },
      invariants
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/Payee/);
  });

  it("fails when a bound parameter was mutated by injected content", () => {
    const result = verifyInvariants(
      { payee: "did:aroha:airline-x", parameters: { destination: "LAX" }, amount: { amount: 480, currency: "USD" } },
      invariants
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/Parameter/);
  });

  it("fails when the amount exceeds the bound maxAmount", () => {
    const result = verifyInvariants(
      { payee: "did:aroha:airline-x", parameters: { destination: "JFK" }, amount: { amount: 600, currency: "USD" } },
      invariants
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/exceeds/);
  });

  it("fails when the invariants have expired", () => {
    const expired: MandateInvariants = { expiry: new Date(Date.now() - 1000).toISOString() };
    const result = verifyInvariants({}, expired);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/expired/);
  });

  it("fails closed when a bound field is missing from the actual action", () => {
    const result = verifyInvariants({}, invariants);
    expect(result.ok).toBe(false);
  });
});

describe("attenuateTaskMandate — expiry clamping", () => {
  // Regression: attenuation used to clamp the child to the parent's expiry and
  // then express that as a relative TTL, which meant a second Date.now() read
  // inside issueTaskMandate. The milliseconds between the two reads landed the
  // child one tick PAST the parent, and the chain verifier rejects that — so
  // every attenuated mandate issued without an explicit TTL was intermittently
  // invalid, failing on the receiving agent with no obvious cause.
  it("never issues a child that outlives its parent", async () => {
    const k = await makeKey();
    const parent = await issueTaskMandate(
      "did:aroha:root",
      "did:aroha:planner",
      ["book-flight"],
      TASK_CONSTRAINTS,
      k.priv,
      3_600_000
    );

    // Repeated because the failure is a race on the clock: a single pass can
    // land inside the same millisecond and pass by luck.
    for (let i = 0; i < 50; i++) {
      const child = await attenuateTaskMandate(
        parent,
        "did:aroha:worker",
        ["book-flight"],
        TASK_CONSTRAINTS,
        k.priv
      );
      expect(new Date(child.mandate.expiresAt).getTime())
        .toBeLessThanOrEqual(new Date(parent.mandate.expiresAt).getTime());
    }
  });

  it("still honours a shorter explicit ttl", async () => {
    const k = await makeKey();
    const parent = await issueTaskMandate(
      "did:aroha:root",
      "did:aroha:planner",
      ["book-flight"],
      TASK_CONSTRAINTS,
      k.priv,
      3_600_000
    );
    const child = await attenuateTaskMandate(
      parent, "did:aroha:worker", ["book-flight"], TASK_CONSTRAINTS, k.priv, 60_000
    );
    const span = new Date(child.mandate.expiresAt).getTime() - Date.now();
    expect(span).toBeGreaterThan(50_000);
    expect(span).toBeLessThanOrEqual(60_000);
  });
});
