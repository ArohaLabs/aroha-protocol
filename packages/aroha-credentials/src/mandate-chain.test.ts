// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifier-side tests for the v2 chain-carrying mandate format.
 *
 * Most of these build tokens BY HAND rather than through attenuateToCart /
 * attenuateToPayment, because the threat being tested is a delegating agent
 * that skips (or never had) the SDK's own attenuation-time checks. Whatever
 * such an agent signs, the verifier must still refuse it.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody, type SpendingConstraints } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandate,
  verifyMandateChain,
  decodeMandateToken,
  enforceSpendingConstraints,
  resolveContentAddressedKey,
  mandateSigningPayloadV2,
  SpendingConstraintViolation,
  type MandateChainLink,
  type SignedMandate,
} from "./mandate.js";
import { InMemoryRedemptionStore, redeemPaymentMandate, mandateRedemptionKey } from "./redemption.js";
import { canonicalizeJcs } from "./jcs.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface Party { priv: Uint8Array; pub: Uint8Array; did: string }

async function party(): Promise<Party> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

const ROOT_CONSTRAINTS: SpendingConstraints = {
  spendLimitUsd: 500,
  sessionLimitUsd: 200,
  requireHumanApprovalAboveUsd: 100,
  allowedMerchants: ["did:aroha:merchant-a", "did:aroha:merchant-b"],
};

/** human → agent intent, agent → provider cart, provider → processor payment. */
async function honestChain() {
  const human = await party();
  const agent = await party();
  const provider = await party();
  const processor = await party();
  const intent = await issueIntentMandate(human.did, agent.did, ROOT_CONSTRAINTS, human.priv);
  const cart = await attenuateToCart(intent, provider.did, {
    spendLimitUsd: 100, allowedMerchants: ["did:aroha:merchant-a"],
  }, agent.priv);
  const payment = await attenuateToPayment(cart, processor.did, {
    spendLimitUsd: 50, allowedMerchants: ["did:aroha:merchant-a"],
  }, provider.priv);
  return { human, agent, provider, processor, intent, cart, payment };
}

/** Sign an arbitrary body the way a v2 issuer would — no SDK-side checks. */
async function signV2(mandate: ArohaSpendingMandateBody, priv: Uint8Array): Promise<MandateChainLink> {
  const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(mandate)), priv);
  return { v: 2, mandate, signature: Buffer.from(sig).toString("base64url") };
}

function tokenV2(leaf: MandateChainLink, chain: MandateChainLink[]): string {
  return Buffer.from(JSON.stringify({ v: 2, mandate: leaf.mandate, signature: leaf.signature, chain })).toString("base64url");
}

function linkOf(s: SignedMandate): MandateChainLink {
  return { v: 2, mandate: s.mandate, signature: s.signature };
}

function childBody(parent: SignedMandate, overrides: Partial<ArohaSpendingMandateBody>): ArohaSpendingMandateBody {
  return {
    mandateTier: "cart",
    constraints: { ...parent.mandate.constraints },
    grantee: "did:aroha:someone",
    grantor: parent.mandate.grantee,
    issuedAt: new Date().toISOString(),
    expiresAt: parent.mandate.expiresAt,
    parentMandateId: parent.mandate.mandateId,
    mandateId: crypto.randomUUID(),
    ...overrides,
  };
}

/** Legacy v1 signing, exactly as the pre-v2 SDK did it. */
function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj as Record<string, unknown>).sort().reduce((acc, k) => {
      acc[k] = sortKeys((obj as Record<string, unknown>)[k]);
      return acc;
    }, {} as Record<string, unknown>);
  }
  return obj;
}
async function tokenV1(mandate: ArohaSpendingMandateBody, priv: Uint8Array): Promise<{ token: string; signature: string }> {
  const sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(mandate))), priv);
  const signature = Buffer.from(sig).toString("base64url");
  return { signature, token: Buffer.from(JSON.stringify({ mandate, signature })).toString("base64url") };
}

// ─── Happy path ───────────────────────────────────────────────────────────────

describe("verifyMandateChain — honest chain", () => {
  it("verifies intent → cart → payment back to the human root", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, undefined, {
      expectedRoot: c.human.did,
      expectedGrantee: c.processor.did,
    });
    expect(r.valid).toBe(true);
    expect(r.chainVerified).toBe(true);
    expect(r.rootGrantor).toBe(c.human.did);
    expect(r.chain?.map((m) => m.mandateTier)).toEqual(["intent", "cart", "payment"]);
  });

  it("tokens carry the parent's chain", async () => {
    const c = await honestChain();
    expect(c.payment.v).toBe(2);
    expect(c.payment.chain?.map((l) => l.mandate.mandateId)).toEqual([c.intent.mandate.mandateId, c.cart.mandate.mandateId]);
  });

  it("a decoded token can be attenuated further", async () => {
    const human = await party(); const agent = await party(); const provider = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv);
    const received = decodeMandateToken(intent.token);
    const cart = await attenuateToCart(received, provider.did, { spendLimitUsd: 10 }, agent.priv);
    expect((await verifyMandateChain(cart.token)).valid).toBe(true);
  });

  it("rejects the wrong expected root", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, undefined, { expectedRoot: c.agent.did });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/root mismatch/i);
  });

  it("rejects grantee mismatch on the leaf", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, undefined, { expectedGrantee: c.agent.did });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/grantee/i);
  });

  it("fails when an ancestor's key cannot be resolved", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, async () => null);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/resolve/i);
  });
});

// ─── Forgery ──────────────────────────────────────────────────────────────────

describe("verifyMandateChain — forged links", () => {
  it("rejects a forged child under a valid parent (signed by someone other than the grantor)", async () => {
    const c = await honestChain();
    const attacker = await party();
    // Claims to be the agent's cart, but the attacker signs it.
    const forged = await signV2(childBody(c.intent, { constraints: { ...c.intent.mandate.constraints } }), attacker.priv);
    const r = await verifyMandateChain(tokenV2(forged, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/signature/i);
  });

  it("rejects a child whose grantor is not the parent's grantee", async () => {
    const c = await honestChain();
    const attacker = await party();
    // Attacker signs honestly as themselves, hanging off someone else's intent.
    const forged = await signV2(childBody(c.intent, { grantor: attacker.did }), attacker.priv);
    const r = await verifyMandateChain(tokenV2(forged, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/not the parent's grantee/);
  });

  it("rejects a child whose parentMandateId does not name the parent", async () => {
    const c = await honestChain();
    const forged = await signV2(childBody(c.intent, { parentMandateId: crypto.randomUUID() }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(forged, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/parentMandateId/);
  });

  it("rejects a chain that does not start at a root", async () => {
    const c = await honestChain();
    // Drop the intent from the payment's chain.
    const r = await verifyMandateChain(tokenV2(linkOf(c.payment), [linkOf(c.cart)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/root/i);
  });

  it("rejects a tampered ancestor", async () => {
    const c = await honestChain();
    const tamperedIntent = linkOf(c.intent);
    tamperedIntent.mandate = { ...tamperedIntent.mandate, constraints: { ...tamperedIntent.mandate.constraints, spendLimitUsd: 99_999 } };
    const r = await verifyMandateChain(tokenV2(linkOf(c.payment), [tamperedIntent, linkOf(c.cart)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/signature/i);
  });

  it("rejects a v2 token downgraded to v1 (chain stripped)", async () => {
    const c = await honestChain();
    const stripped = Buffer.from(JSON.stringify({ mandate: c.payment.mandate, signature: c.payment.signature })).toString("base64url");
    // The v2 signature covers { mandate, v: 2 } — it cannot verify as a v1 body.
    const r1 = await verifyMandate(stripped, c.provider.pub);
    expect(r1.valid).toBe(false);
    expect(r1.reason).toMatch(/signature/i);
    expect((await verifyMandateChain(stripped)).valid).toBe(false);
  });
});

// ─── Narrowing enforced by the verifier ──────────────────────────────────────

describe("verifyMandateChain — narrowing re-run on every link", () => {
  it("rejects a validly-signed child that widens spendLimitUsd", async () => {
    const c = await honestChain();
    const widened = await signV2(childBody(c.intent, {
      constraints: { ...c.intent.mandate.constraints, spendLimitUsd: 10_000 },
    }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(widened, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/spendLimitUsd/);
  });

  it("rejects a validly-signed child that omits the parent's approval threshold", async () => {
    const c = await honestChain();
    const { requireHumanApprovalAboveUsd: _dropped, ...rest } = c.intent.mandate.constraints;
    const omitted = await signV2(childBody(c.intent, { constraints: rest }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(omitted, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/approval threshold/i);
  });

  it("rejects a validly-signed child that omits the parent's session limit", async () => {
    const c = await honestChain();
    const { sessionLimitUsd: _dropped, ...rest } = c.intent.mandate.constraints;
    const omitted = await signV2(childBody(c.intent, { constraints: rest }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(omitted, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/sessionLimitUsd/);
  });

  it("rejects a validly-signed child that drops the merchant allow-list", async () => {
    const c = await honestChain();
    const widened = await signV2(childBody(c.intent, {
      constraints: { ...c.intent.mandate.constraints, allowedMerchants: null },
    }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(widened, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/allowedMerchants/);
  });

  it("rejects a child that outlives its parent", async () => {
    const c = await honestChain();
    const later = new Date(Date.parse(c.intent.mandate.expiresAt) + 60_000).toISOString();
    const longer = await signV2(childBody(c.intent, { expiresAt: later }), c.agent.priv);
    const r = await verifyMandateChain(tokenV2(longer, [linkOf(c.intent)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/outlives/);
  });
});

describe("attenuation inherits omitted fields (honest callers keep working)", () => {
  it("copies sessionLimitUsd / approval threshold / validUntil from the parent", async () => {
    const human = await party(); const agent = await party();
    const validUntil = new Date(Date.now() + 3_600_000).toISOString();
    const intent = await issueIntentMandate(human.did, agent.did, {
      spendLimitUsd: 500, sessionLimitUsd: 200, requireHumanApprovalAboveUsd: 100, validUntil,
    }, human.priv);
    const cart = await attenuateToCart(intent, "did:aroha:p", { spendLimitUsd: 50 }, agent.priv);
    expect(cart.mandate.constraints.sessionLimitUsd).toBe(200);
    expect(cart.mandate.constraints.requireHumanApprovalAboveUsd).toBe(100);
    expect(cart.mandate.constraints.validUntil).toBe(validUntil);
    expect((await verifyMandateChain(cart.token)).valid).toBe(true);
  });

  it("never issues a child that outlives its parent (absolute expiry)", async () => {
    const human = await party(); const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv);
    for (let i = 0; i < 50; i++) {
      const cart = await attenuateToCart(intent, "did:aroha:p", { spendLimitUsd: 1 }, agent.priv);
      expect(Date.parse(cart.mandate.expiresAt)).toBeLessThanOrEqual(Date.parse(intent.mandate.expiresAt));
    }
  });
});

// ─── Tier order ───────────────────────────────────────────────────────────────

describe("verifyMandateChain — tier order", () => {
  it("rejects a cart minted under a payment mandate", async () => {
    const c = await honestChain();
    const next = await party();
    const backwards = await signV2(childBody(c.payment, { mandateTier: "cart", grantee: next.did }), c.processor.priv);
    const r = await verifyMandateChain(tokenV2(backwards, [linkOf(c.intent), linkOf(c.cart), linkOf(c.payment)]));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/tier/);
  });

  it("rejects a root that is not an intent mandate", async () => {
    const human = await party();
    const root = await signV2({
      mandateTier: "payment", constraints: { spendLimitUsd: 5 }, grantee: "did:aroha:x", grantor: human.did,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      parentMandateId: null, mandateId: crypto.randomUUID(),
    }, human.priv);
    const r = await verifyMandateChain(tokenV2(root, []));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/intent/);
  });

  it("attenuateToCart refuses a payment parent", async () => {
    const c = await honestChain();
    await expect(
      attenuateToCart(c.payment, "did:aroha:x", { spendLimitUsd: 1, allowedMerchants: ["did:aroha:merchant-a"] }, c.processor.priv)
    ).rejects.toThrow(/broader tier/);
  });
});

// ─── Time windows & revocation ────────────────────────────────────────────────

describe("verifyMandateChain — time windows and revocation", () => {
  it("rejects when validUntil has passed", async () => {
    const human = await party(); const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, {
      spendLimitUsd: 100, validUntil: new Date(Date.now() - 1_000).toISOString(),
    }, human.priv);
    const r = await verifyMandateChain(intent.token);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/validUntil/);
    // and verifyMandate checks it too now
    expect((await verifyMandate(intent.token, human.pub)).reason).toMatch(/validUntil/);
  });

  it("rejects before validFrom, beyond clock tolerance", async () => {
    const human = await party(); const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, {
      spendLimitUsd: 100, validFrom: new Date(Date.now() + 600_000).toISOString(),
    }, human.priv);
    const r = await verifyMandateChain(intent.token);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/not yet valid/);
  });

  it("tolerates validFrom within the clock tolerance", async () => {
    const human = await party(); const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, {
      spendLimitUsd: 100, validFrom: new Date(Date.now() + 5_000).toISOString(),
    }, human.priv);
    expect((await verifyMandateChain(intent.token, undefined, { clockToleranceMs: 10_000 })).valid).toBe(true);
    expect((await verifyMandateChain(intent.token, undefined, { clockToleranceMs: 0 })).valid).toBe(false);
  });

  it("rejects when an ancestor has expired", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, undefined, { now: Date.parse(c.intent.mandate.expiresAt) + 1 });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expired/i);
  });

  it("rejects when any link is revoked — including the root", async () => {
    const c = await honestChain();
    const revoked = new Set([c.intent.mandate.mandateId]);
    const r = await verifyMandateChain(c.payment.token, undefined, { isRevoked: async (id) => revoked.has(id) });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/revoked/);

    const viaVerifyMandate = await verifyMandate(c.payment.token, c.provider.pub, undefined, { isRevoked: async (id) => revoked.has(id) });
    expect(viaVerifyMandate.valid).toBe(false);
  });

  it("fails closed when the revocation hook throws", async () => {
    const c = await honestChain();
    const r = await verifyMandateChain(c.payment.token, undefined, {
      isRevoked: async () => { throw new Error("revocation service down"); },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Revocation check failed/);
  });
});

// ─── verifyMandate compatibility ─────────────────────────────────────────────

describe("verifyMandate — v1 compatibility and v2 chain enforcement", () => {
  it("still verifies a legacy v1 root token", async () => {
    const human = await party();
    const body: ArohaSpendingMandateBody = {
      mandateTier: "intent", constraints: { spendLimitUsd: 100 }, grantee: "did:aroha:agent", grantor: human.did,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      parentMandateId: null, mandateId: crypto.randomUUID(),
    };
    const { token } = await tokenV1(body, human.priv);
    const r = await verifyMandate(token, human.pub);
    expect(r.valid).toBe(true);
    expect(r.chainVerified).toBe(true);
    // A v1 root is also acceptable to the chain verifier.
    expect((await verifyMandateChain(token)).valid).toBe(true);
  });

  it("accepts a legacy v1 child via verifyMandate but flags it as NOT chain-verified", async () => {
    const agent = await party();
    const body: ArohaSpendingMandateBody = {
      mandateTier: "cart", constraints: { spendLimitUsd: 100 }, grantee: "did:aroha:provider", grantor: agent.did,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      parentMandateId: crypto.randomUUID(), mandateId: crypto.randomUUID(),
    };
    const { token } = await tokenV1(body, agent.priv);
    const r = await verifyMandate(token, agent.pub);
    expect(r.valid).toBe(true);
    expect(r.chainVerified).toBe(false);

    expect((await verifyMandateChain(token)).valid).toBe(false);
    expect((await verifyMandate(token, agent.pub, undefined, { expectedRoot: "did:aroha:human" })).valid).toBe(false);
    await expect(
      enforceSpendingConstraints(token, agent.pub, { proposedAmountUsd: 1, requireChain: true })
    ).rejects.toThrow(/root/);
  });

  it("can attenuate a legacy v1 root into a verifiable v2 chain", async () => {
    const human = await party(); const agent = await party();
    const body: ArohaSpendingMandateBody = {
      mandateTier: "intent", constraints: { spendLimitUsd: 100 }, grantee: agent.did, grantor: human.did,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      parentMandateId: null, mandateId: crypto.randomUUID(),
    };
    const v1 = await tokenV1(body, human.priv);
    const parent: SignedMandate = { mandate: body, signature: v1.signature, token: v1.token };
    const cart = await attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 10 }, agent.priv);
    expect(cart.chain?.[0].v).toBe(1);
    expect((await verifyMandateChain(cart.token, undefined, { expectedRoot: human.did })).valid).toBe(true);
  });

  it("rejects a v2 token whose chain does not verify, even though the leaf signature is good", async () => {
    const c = await honestChain();
    const attacker = await party();
    // Leaf honestly signed by the agent, but the "intent" above it is forged.
    const fakeIntent = await signV2({
      ...c.intent.mandate, constraints: { spendLimitUsd: 1_000_000 },
    }, attacker.priv);
    const cartBody = childBody(c.intent, { constraints: { spendLimitUsd: 999_999 } });
    const cart = await signV2(cartBody, c.agent.priv);
    const r = await verifyMandate(tokenV2(cart, [fakeIntent]), c.agent.pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/signature/i);
  });

  it("rejects an unsupported token version", async () => {
    const t = Buffer.from(JSON.stringify({ v: 3, mandate: {}, signature: "" })).toString("base64url");
    expect((await verifyMandateChain(t)).reason).toMatch(/version/);
  });
});

// ─── Amount hygiene ───────────────────────────────────────────────────────────

describe("non-finite amounts", () => {
  it("refuses to issue a mandate with a NaN or infinite limit", async () => {
    const human = await party();
    await expect(issueIntentMandate(human.did, "did:aroha:a", { spendLimitUsd: NaN }, human.priv)).rejects.toThrow(/finite/);
    await expect(issueIntentMandate(human.did, "did:aroha:a", { spendLimitUsd: Infinity }, human.priv)).rejects.toThrow(/finite/);
  });

  it("enforceSpendingConstraints rejects a NaN proposed amount", async () => {
    const human = await party();
    const m = await issueIntentMandate(human.did, "did:aroha:a", { spendLimitUsd: 10 }, human.priv);
    const err = await enforceSpendingConstraints(m.token, human.pub, { proposedAmountUsd: NaN }).catch((e) => e);
    expect(err).toBeInstanceOf(SpendingConstraintViolation);
    expect(err.code).toBe("INVALID_AMOUNT");
  });
});

// ─── Default key resolver ─────────────────────────────────────────────────────

describe("resolveContentAddressedKey", () => {
  it("derives the key from a content-addressed DID", async () => {
    const p = await party();
    expect(await resolveContentAddressedKey(p.did)).toEqual(p.pub);
  });

  it("returns null for namespaced and look-alike DIDs", async () => {
    expect(await resolveContentAddressedKey("did:aroha:acme.agent")).toBeNull();
    expect(await resolveContentAddressedKey("did:aroha:zoo")).toBeNull();
    expect(await resolveContentAddressedKey("did:web:example.com")).toBeNull();
  });
});

// ─── Redemption ───────────────────────────────────────────────────────────────

describe("redeemPaymentMandate", () => {
  it("allows cumulative redemption up to the limit and refuses beyond it", async () => {
    const c = await honestChain();
    const verified = await verifyMandateChain(c.payment.token);
    expect(verified.valid).toBe(true);
    const store = new InMemoryRedemptionStore();

    const r1 = await redeemPaymentMandate(store, verified.mandate!, 30, "did:aroha:merchant-a");
    expect(r1.remainingUsd).toBe(20);
    const r2 = await redeemPaymentMandate(store, verified.mandate!, 20, "did:aroha:merchant-a");
    expect(r2.remainingUsd).toBe(0);

    const err = await redeemPaymentMandate(store, verified.mandate!, 0.01, "did:aroha:merchant-a").catch((e) => e);
    expect(err).toBeInstanceOf(SpendingConstraintViolation);
    expect(err.code).toBe("REDEMPTION_LIMIT_EXCEEDED");
  });

  it("the same $50 cannot be spent at several merchants", async () => {
    const human = await party(); const agent = await party(); const provider = await party();
    const merchants = Array.from({ length: 10 }, (_, i) => `did:aroha:merchant-${i}`);
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 500, allowedMerchants: merchants }, human.priv);
    const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 50, allowedMerchants: merchants }, agent.priv);
    const payment = await attenuateToPayment(cart, "did:aroha:processor", { spendLimitUsd: 50, allowedMerchants: merchants }, provider.priv);
    const store = new InMemoryRedemptionStore();

    await redeemPaymentMandate(store, payment.mandate, 50, merchants[0]);
    for (const m of merchants.slice(1)) {
      await expect(redeemPaymentMandate(store, payment.mandate, 50, m)).rejects.toThrow(/exceed/);
    }
    expect(store.history(mandateRedemptionKey(payment.mandate))).toHaveLength(1);
  });

  it("caps at sessionLimitUsd when tighter, and does not drift with decimals", async () => {
    const c = await honestChain();
    const store = new InMemoryRedemptionStore();
    const body = { ...c.payment.mandate, constraints: { ...c.payment.mandate.constraints, spendLimitUsd: 1, sessionLimitUsd: 0.3 } };
    for (let i = 0; i < 3; i++) await redeemPaymentMandate(store, body, 0.1, "did:aroha:merchant-a");
    await expect(redeemPaymentMandate(store, body, 0.1, "did:aroha:merchant-a")).rejects.toThrow(/exceed/);
  });

  it("refuses non-payment mandates, bad amounts and disallowed merchants", async () => {
    const c = await honestChain();
    const store = new InMemoryRedemptionStore();
    await expect(redeemPaymentMandate(store, c.cart.mandate, 1, "did:aroha:merchant-a")).rejects.toThrow(/payment/);
    await expect(redeemPaymentMandate(store, c.payment.mandate, NaN, "did:aroha:merchant-a")).rejects.toThrow(/finite/);
    await expect(redeemPaymentMandate(store, c.payment.mandate, -5, "did:aroha:merchant-a")).rejects.toThrow(/finite/);
    await expect(redeemPaymentMandate(store, c.payment.mandate, 1, "did:aroha:merchant-z")).rejects.toThrow(/allowed merchant/);
  });
});

// ─── JCS & cross-SDK vectors ──────────────────────────────────────────────────

interface VectorFile {
  keys: Record<string, { privateKeyHex: string; publicKeyHex: string; did: string }>;
  jcs: { name: string; input: string; expected: string }[];
  mandates: { name: string; signer: string; mandate: ArohaSpendingMandateBody; expectedSigningPayload: string; expectedSignature: string }[];
  tokens: { name: string; token: string; verifyAt: string; expected: { valid: boolean; rootGrantor?: string; leafMandateId?: string; reasonClass?: string } }[];
}

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("../test-vectors/mandate-v2.json", import.meta.url)), "utf8")
) as VectorFile;

describe("RFC 8785 JCS", () => {
  it("matches the RFC 8785 §3.2.2 example exactly", () => {
    const v = vectors.jcs.find((x) => x.name === "rfc8785-3.2.2-sample")!;
    expect(canonicalizeJcs(JSON.parse(v.input))).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    );
  });

  it("sorts keys by UTF-16 code units (RFC 8785 §3.2.3)", () => {
    const v = vectors.jcs.find((x) => x.name === "rfc8785-3.2.3-key-sorting")!;
    // Read the order off the string: Object.keys() would hoist the integer-like "1".
    const out = canonicalizeJcs(JSON.parse(v.input));
    const order = ["Carriage Return", "One", "Control", "Latin Small", "Euro Sign", "Emoji", "Hebrew"].map((s) => out.indexOf(s));
    expect(order.every((pos, i) => pos > 0 && (i === 0 || pos > order[i - 1]))).toBe(true);
  });

  it.each(vectors.jcs.map((v) => [v.name, v] as const))("vector %s", (_n, v) => {
    expect(canonicalizeJcs(JSON.parse(v.input))).toBe(v.expected);
  });

  it("rejects non-finite numbers and lone surrogates", () => {
    expect(() => canonicalizeJcs({ a: NaN })).toThrow(/non-finite/);
    expect(() => canonicalizeJcs({ a: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalizeJcs({ a: "\ud800" })).toThrow(/surrogate/);
  });

  it("omits undefined-valued properties, like the JSON on the wire", () => {
    expect(canonicalizeJcs({ b: 1, a: undefined })).toBe('{"b":1}');
  });
});

describe("mandate v2 test vectors", () => {
  it.each(vectors.mandates.map((v) => [v.name, v] as const))("signing payload and signature for %s", async (_n, v) => {
    expect(mandateSigningPayloadV2(v.mandate)).toBe(v.expectedSigningPayload);
    const key = vectors.keys[v.signer];
    const sig = await ed.signAsync(new TextEncoder().encode(v.expectedSigningPayload), Buffer.from(key.privateKeyHex, "hex"));
    expect(Buffer.from(sig).toString("base64url")).toBe(v.expectedSignature);
  });

  it("vector keys' DIDs are content-addressed", async () => {
    for (const k of Object.values(vectors.keys)) {
      expect(Buffer.from((await resolveContentAddressedKey(k.did))!).toString("hex")).toBe(k.publicKeyHex);
    }
  });

  it.each(vectors.tokens.map((v) => [v.name, v] as const))("token verdict for %s", async (_n, v) => {
    const r = await verifyMandateChain(v.token, undefined, { now: Date.parse(v.verifyAt) });
    expect(r.valid).toBe(v.expected.valid);
    if (v.expected.valid) {
      expect(r.rootGrantor).toBe(v.expected.rootGrantor);
      expect(r.mandate?.mandateId).toBe(v.expected.leafMandateId);
    } else if (v.expected.reasonClass === "narrowing") {
      expect(r.reason).toMatch(/Cannot attenuate/);
    } else if (v.expected.reasonClass === "time") {
      expect(r.reason).toMatch(/validUntil|expired/);
    }
  });
});

describe("verifyMandate — the caller's key applies to the leaf link only", () => {
  it("does not lend the caller's key to an ancestor that names the same grantor", async () => {
    // A named (non-self-certifying) DID whose real key is what the resolver
    // returns. The attacker holds a different key, forges a root and a child
    // both naming that DID, and calls verifyMandate with the attacker key as
    // the "leaf key". The root must be checked against the REAL key and fail.
    const shop = "did:aroha:shop";
    const real = await party();
    const attacker = await party();
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const root: ArohaSpendingMandateBody = {
      mandateTier: "intent", constraints: { spendLimitUsd: 1_000_000 },
      grantor: shop, grantee: shop, issuedAt: new Date().toISOString(), expiresAt,
      parentMandateId: null, mandateId: crypto.randomUUID(),
    } as unknown as ArohaSpendingMandateBody;
    const rootLink = await signV2(root, attacker.priv);
    const child: ArohaSpendingMandateBody = {
      ...root, mandateTier: "cart", constraints: { spendLimitUsd: 1_000_000 },
      parentMandateId: root.mandateId, mandateId: crypto.randomUUID(), grantee: "did:aroha:payee",
    } as unknown as ArohaSpendingMandateBody;
    const leaf = await signV2(child, attacker.priv);
    const r = await verifyMandate(tokenV2(leaf, [rootLink]), attacker.pub, undefined, {
      resolveKey: async (did) => (did === shop ? real.pub : null),
      expectedRoot: shop,
    });
    expect(r.valid).toBe(false);
  });

  it("refuses a caller key that disagrees with a self-certifying leaf grantor", async () => {
    const { payment } = await honestChain();
    const stranger = await party();
    const r = await verifyMandate(payment.token, stranger.pub);
    expect(r.valid).toBe(false);
  });
});
