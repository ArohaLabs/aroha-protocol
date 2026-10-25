// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Inbound A2A mandates are verified, not just carried: verifyA2aMandate /
 * a2aToArohaVerified run the real verifyMandateChain from
 * @aroha-sdk/credentials with a required root policy, and reject
 * unverifiable, untrusted, revoked or over-limit mandates.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import {
  issueIntentMandate, attenuateToCart, attenuateToPayment, verifyMandateChain, governedVerification,
} from "@aroha-sdk/credentials";
import {
  attachMandate, verifyA2aMandate, a2aToArohaVerified, A2AMandateError, arohaMandateExtension,
  type A2AMessage, type A2AMandatePolicy,
} from "./index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function z() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
}

let human: { priv: Uint8Array; did: string }, agentA: typeof human, caller: typeof human, stranger: typeof human;
let paymentToken: string, intentMandateId: string;
beforeAll(async () => {
  [human, agentA, caller, stranger] = await Promise.all([z(), z(), z(), z()]);
  const intent = await issueIntentMandate(human.did, agentA.did, { spendLimitUsd: 100 }, human.priv);
  const cart = await attenuateToCart(intent, caller.did, { spendLimitUsd: 50 }, agentA.priv);
  const payment = await attenuateToPayment(cart, caller.did, { spendLimitUsd: 20 }, caller.priv);
  paymentToken = payment.token;
  intentMandateId = intent.mandate.mandateId;
});

const msg = (token?: string): A2AMessage => {
  const m: A2AMessage = { messageId: "m-1", role: "ROLE_USER", parts: [{ data: { capability: "pay" } }] };
  return token ? attachMandate(m, token) : m;
};

const policy = (extra: Partial<A2AMandatePolicy> = {}): A2AMandatePolicy => ({
  verifyMandateChain, expectedRoot: human.did, expectedGrantee: caller.did, isRevoked: async () => false, ...extra,
});

describe("verifyA2aMandate", () => {
  it("requires a root policy and the verifier (configuration errors throw)", async () => {
    await expect(verifyA2aMandate(msg(paymentToken), { verifyMandateChain })).rejects.toThrow(/root policy is required/);
    await expect(verifyA2aMandate(msg(paymentToken), { verifyMandateChain, trustedRoots: [] })).rejects.toThrow(/root policy is required/);
    await expect(verifyA2aMandate(msg(paymentToken), { expectedRoot: human.did } as never)).rejects.toThrow(/verifyMandateChain is required/);
  });

  it("accepts a chain to the trusted root granted to the caller", async () => {
    const r = await verifyA2aMandate(msg(paymentToken), policy({ proposedAmountUsd: 20 }));
    expect(r).toMatchObject({ ok: true, rootGrantor: human.did, mandate: { mandateTier: "payment", grantee: caller.did } });
    const viaList = await verifyA2aMandate(msg(paymentToken), policy({ expectedRoot: undefined, trustedRoots: [human.did] }));
    expect(viaList.ok).toBe(true);
  });

  it("rejects a mandate from an untrusted root, one granted to someone else, and a tampered token", async () => {
    expect(await verifyA2aMandate(msg(paymentToken), policy({ expectedRoot: stranger.did }))).toMatchObject({ ok: false });
    expect(await verifyA2aMandate(msg(paymentToken), policy({ expectedRoot: undefined, trustedRoots: [stranger.did] })))
      .toMatchObject({ ok: false, reason: expect.stringMatching(/not a trusted root/) });
    expect(await verifyA2aMandate(msg(paymentToken), policy({ expectedGrantee: stranger.did })))
      .toMatchObject({ ok: false, reason: expect.stringMatching(/grantee mismatch/) });
    const self = await issueIntentMandate(stranger.did, caller.did, { spendLimitUsd: 1_000_000 }, stranger.priv);
    expect((await verifyA2aMandate(msg(self.token), policy())).ok).toBe(false);
    expect((await verifyA2aMandate(msg(paymentToken.slice(0, -4) + "AAAA"), policy())).ok).toBe(false);
  });

  it("rejects an over-limit amount and a non-finite one", async () => {
    expect(await verifyA2aMandate(msg(paymentToken), policy({ proposedAmountUsd: 20.01 })))
      .toMatchObject({ ok: false, reason: expect.stringMatching(/exceeds mandate limit \$20/) });
    expect((await verifyA2aMandate(msg(paymentToken), policy({ proposedAmountUsd: Number.NaN }))).ok).toBe(false);
  });

  it("rejects a revoked chain, and fails closed when the revocation hook throws", async () => {
    const revoked = await verifyA2aMandate(msg(paymentToken), policy({ isRevoked: async (id) => id === intentMandateId }));
    expect(revoked).toMatchObject({ ok: false, reason: expect.stringMatching(/revoked/) });
    const down = await verifyA2aMandate(msg(paymentToken), policy({ isRevoked: async () => { throw new Error("down"); } }));
    expect(down.ok).toBe(false);
  });

  it("rejects a message with no mandate unless required: false", async () => {
    expect(await verifyA2aMandate(msg(), policy())).toMatchObject({ ok: false, reason: "No Aroha mandate on the message" });
    expect((await verifyA2aMandate(msg(), policy({ required: false }))).ok).toBe(true);
  });

  it("passes a governed profile through verifierOptions", async () => {
    const profile = governedVerification({ kelSource: async () => null, isRevoked: async () => false, trustedRoots: [human.did] });
    // The z-DID root is not a person, so the governed profile refuses it.
    const r = await verifyA2aMandate(msg(paymentToken), { verifyMandateChain, verifierOptions: { ...profile }, expectedGrantee: caller.did });
    expect(r.ok).toBe(false);
  });
});

describe("a2aToArohaVerified", () => {
  it("returns the envelope (mandate copied to credentialToken) only when the mandate verifies", async () => {
    const { envelope, rootGrantor } = await a2aToArohaVerified(msg(paymentToken), caller.did, "did:aroha:me", policy());
    expect(rootGrantor).toBe(human.did);
    expect((envelope.body as unknown as { credentialToken: string }).credentialToken).toBe(paymentToken);
    await expect(a2aToArohaVerified(msg(paymentToken), caller.did, "did:aroha:me", policy({ expectedRoot: stranger.did })))
      .rejects.toBeInstanceOf(A2AMandateError);
  });

  it("the extension description points at chain verification, not single-link verifyMandate", () => {
    expect(arohaMandateExtension().description).toMatch(/verifyMandateChain\(\)/);
    expect(arohaMandateExtension().description).not.toMatch(/verifyMandate\(\)/);
  });
});
