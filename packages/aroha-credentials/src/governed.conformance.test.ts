// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Conformance: the governed verifier profile.
 *
 * Claim under test: under the governed profile, every protective check is
 * on, and each one FAILS CLOSED when its prerequisite is missing — both when
 * the profile is built (governedVerification throws) and when a caller
 * hands a verifier a profile with a field dropped or overridden (the
 * verification fails rather than running a weaker check).
 */

import { describe, it, expect, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { incept, type KelEvent, type KelSource, type SpendingConstraints } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandateChain,
  verifyMandate,
  enforceSpendingConstraints,
  resolveContentAddressedKey,
  SpendingConstraintViolation,
  type MandateRevocationCheck,
} from "./mandate.js";
import { governedVerification, GovernedProfileError, GOVERNED_PROFILE, checkGovernedPrerequisites } from "./governed.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const ROOT: SpendingConstraints = { spendLimitUsd: 500 };
const CART: SpendingConstraints = { spendLimitUsd: 100 };
const PAY: SpendingConstraints = { spendLimitUsd: 50 };

const notRevoked: MandateRevocationCheck = async () => false;

async function world() {
  const alice = await incept({ kind: "person" });
  const mallory = await incept({ kind: "person" });
  const shopper = await incept({ kind: "agent", controller: alice.did });
  const provider = await incept({ kind: "agent", controller: alice.did });
  const logs = new Map<string, KelEvent[]>([alice, mallory, shopper, provider].map((i) => [i.did, i.kel]));
  const kelSource: KelSource = async (did) => logs.get(did) ?? null;

  const intent = await issueIntentMandate(alice.did, shopper.did, ROOT, alice.privateKey);
  const cart = await attenuateToCart(intent, provider.did, CART, shopper.privateKey);
  const payment = await attenuateToPayment(cart, "did:aroha:merchant", PAY, provider.privateKey);
  const providerPub = await ed.getPublicKeyAsync(provider.privateKey);
  return { alice, mallory, shopper, provider, kelSource, intent, cart, payment, providerPub };
}

describe("governedVerification — building the profile", () => {
  it("turns every protective switch on", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    expect(p).toMatchObject({ governed: true, requirePersonRoot: true, requireChain: true });
    expect(p.kelSource).toBe(w.kelSource);
    expect(p.isRevoked).toBe(notRevoked);
    expect(Object.isFrozen(p)).toBe(true);
    expect(GOVERNED_PROFILE).toEqual({ governed: true, requirePersonRoot: true, requireChain: true });
    expect("failOpen" in p).toBe(false);
  });

  it("refuses to build without isRevoked", async () => {
    const w = await world();
    expect(() => governedVerification({ kelSource: w.kelSource, trustedRoots: [w.alice.did] } as never))
      .toThrow(GovernedProfileError);
    expect(() => governedVerification({ kelSource: w.kelSource, trustedRoots: [w.alice.did] } as never))
      .toThrow(/isRevoked is required/);
  });

  it("refuses to build without kelSource", () => {
    expect(() => governedVerification({ isRevoked: notRevoked, expectedRoot: "did:aroha:x" } as never))
      .toThrow(/kelSource is required/);
  });

  it("refuses to build without a root pin (and an empty trustedRoots is not a pin)", async () => {
    const w = await world();
    expect(() => governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked }))
      .toThrow(/root pin is required/);
    expect(() => governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [] }))
      .toThrow(/root pin is required/);
  });

  it("checkGovernedPrerequisites ignores options that do not claim to be governed", () => {
    expect(checkGovernedPrerequisites({})).toBeNull();
    expect(checkGovernedPrerequisites({ governed: false })).toBeNull();
  });
});

describe("governed profile — accepted unchanged by the verifiers", () => {
  it("verifyMandateChain accepts a person-rooted chain from a trusted root", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    const r = await verifyMandateChain(w.payment.token, resolveContentAddressedKey, p);
    expect(r).toMatchObject({ valid: true, chainVerified: true, rootGrantor: w.alice.did });
  });

  it("enforceSpendingConstraints accepts the same profile plus an amount", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, expectedRootPerson: w.alice.did });
    const m = await enforceSpendingConstraints(w.payment.token, w.providerPub, { ...p, proposedAmountUsd: 10 });
    expect(m.mandateTier).toBe("payment");
    await expect(enforceSpendingConstraints(w.payment.token, w.providerPub, { ...p, proposedAmountUsd: 51 }))
      .rejects.toMatchObject({ code: "LIMIT_EXCEEDED" });
  });
});

describe("governed profile — each check fails closed", () => {
  it("revocation: a revoked link fails, and a throwing hook fails (no fail-open)", async () => {
    const w = await world();
    const revokedIntent: MandateRevocationCheck = async (id) => id === w.intent.mandate.mandateId;
    const p1 = governedVerification({ kelSource: w.kelSource, isRevoked: revokedIntent, trustedRoots: [w.alice.did] });
    expect((await verifyMandateChain(w.payment.token, undefined, p1)).reason).toMatch(/revoked/);

    const unreachable: MandateRevocationCheck = async () => { throw new Error("registry down"); };
    const p2 = governedVerification({ kelSource: w.kelSource, isRevoked: unreachable, trustedRoots: [w.alice.did] });
    const r2 = await verifyMandateChain(w.payment.token, undefined, p2);
    expect(r2.valid).toBe(false);
    expect(r2.reason).toMatch(/Revocation check failed/);
  });

  it("revocation hook dropped from a governed profile: verification fails", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    const r = await verifyMandateChain(w.payment.token, undefined, { ...p, isRevoked: undefined });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/isRevoked is required/);
    await expect(enforceSpendingConstraints(w.payment.token, w.providerPub, { ...p, isRevoked: undefined, proposedAmountUsd: 1 }))
      .rejects.toThrow(/isRevoked is required/);
  });

  it("kelSource dropped from a governed profile: verification fails", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    const r = await verifyMandateChain(w.payment.token, undefined, { ...p, kelSource: undefined });
    expect(r.reason).toMatch(/kelSource is required/);
  });

  it("KEL: a source that cannot produce a log fails the chain", async () => {
    const w = await world();
    const empty: KelSource = async () => null;
    const p = governedVerification({ kelSource: empty, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    const r = await verifyMandateChain(w.payment.token, undefined, p);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/no Key Event Log/);
  });

  it("person root switched off in a governed profile: verification fails", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, expectedRoot: w.alice.did });
    const r = await verifyMandateChain(w.payment.token, undefined, { ...p, requirePersonRoot: false as never });
    expect(r.reason).toMatch(/requirePersonRoot must stay on/);
  });

  it("person root: a chain rooted in an agent fails", async () => {
    const w = await world();
    const selfMinted = await issueIntentMandate(w.shopper.did, w.provider.did, ROOT, w.shopper.privateKey);
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.shopper.did] });
    const r = await verifyMandateChain(selfMinted.token, undefined, p);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/not a person/);
  });

  it("root pin removed from a governed profile: verification fails", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    const r = await verifyMandateChain(w.payment.token, undefined, { ...p, trustedRoots: undefined });
    expect(r.reason).toMatch(/root pin is required/);
  });

  it("root pin: a person who is not trusted is refused", async () => {
    const w = await world();
    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.mallory.did] });
    const r = await verifyMandateChain(w.payment.token, undefined, p);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/not a trusted root/);
  });

  it("requireChain cannot be switched off under the profile: a v1 child token is refused", async () => {
    const w = await world();
    // A legacy v1 child: no ancestry, signed over the old canonical form.
    const body = { ...w.payment.mandate };
    const sortKeys = (o: unknown): unknown => Array.isArray(o) ? o.map(sortKeys)
      : o && typeof o === "object" ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys((o as Record<string, unknown>)[k])])) : o;
    const sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(body))), w.provider.privateKey);
    const v1 = Buffer.from(JSON.stringify({ mandate: body, signature: Buffer.from(sig).toString("base64url") })).toString("base64url");

    const p = governedVerification({ kelSource: w.kelSource, isRevoked: notRevoked, trustedRoots: [w.alice.did] });
    await expect(enforceSpendingConstraints(v1, w.providerPub, { ...p, requireChain: false, proposedAmountUsd: 1 }))
      .rejects.toBeInstanceOf(SpendingConstraintViolation);
    const direct = await verifyMandate(v1, w.providerPub, undefined, p);
    expect(direct.valid).toBe(false);
    expect(direct.reason).toMatch(/governed profile requires a verified chain/);
  });
});

describe("non-governed defaults are unchanged", () => {
  it("verifyMandateChain without a profile still accepts a self-consistent chain, and warns once about revocation", async () => {
    vi.resetModules();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const fresh = await import("./mandate.js");
      const w = await world();
      const a = await fresh.verifyMandateChain(w.payment.token, undefined, { kelSource: w.kelSource });
      const b = await fresh.verifyMandateChain(w.payment.token, undefined, { kelSource: w.kelSource });
      expect(a.valid).toBe(true);
      expect(b.valid).toBe(true);
      const hits = warn.mock.calls.filter((c) => String(c[0]).includes("without isRevoked"));
      expect(hits).toHaveLength(1);

      warn.mockClear();
      await fresh.verifyMandateChain(w.payment.token, undefined, { kelSource: w.kelSource, isRevoked: notRevoked });
      expect(warn.mock.calls.filter((c) => String(c[0]).includes("without isRevoked"))).toHaveLength(0);
    } finally {
      warn.mockRestore();
    }
  });
});
