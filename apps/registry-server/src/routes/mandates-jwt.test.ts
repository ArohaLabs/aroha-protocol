// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// /v1/mandates with tokens in the JWT form (spec §6.10): the registry runs
// the SDK's own verifier, so a chain of JWTs is revoked and redeemed exactly
// as a native chain is. Exercised through the @aroha-sdk/credentials clients.

import { describe, it, expect, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  attenuateToCart,
  attenuateToPayment,
  httpRedemptionStore,
  httpRevocationCheck,
  issueIntentMandate,
  redeemPaymentMandate,
  revokeMandate,
  signMandateJwt,
  verifyMandateChain,
} from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";

const REG = "https://registry.test";
let t: TestApp;
let ip = 0;
beforeEach(async () => { t = await makeApp(); });

function appFetch(): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    headers.set("x-forwarded-for", `10.7.${(ip >> 8) & 255}.${ip++ & 255}`);
    return t.app.request(url.pathname + url.search, { ...init, headers }, t.env);
  }) as typeof fetch;
}

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

async function jwtChain() {
  const human = await party(), agent = await party(), provider = await party();
  const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv, 3_600_000, { format: "jwt" });
  const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 60 }, agent.priv);
  const payment = await attenuateToPayment(cart, provider.did, { spendLimitUsd: 50 }, provider.priv);
  return { human, agent, provider, intent, cart, payment };
}

const payeeVerify = (token: string) => verifyMandateChain(token, undefined, { isRevoked: httpRevocationCheck(REG, { fetch: appFetch(), cacheMs: 0 }) });

describe("/v1/mandates with JWT-form tokens", () => {
  it("the root grantor revokes a downstream cart, and the chain below it stops verifying", async () => {
    const c = await jwtChain();
    expect((await payeeVerify(c.payment.token)).valid).toBe(true);
    const r = await revokeMandate(REG, c.cart.token, c.human.priv, { fetch: appFetch() });
    expect(r.revokedBy).toBe(c.human.did);
    const after = await payeeVerify(c.payment.token);
    expect(after.valid).toBe(false);
    expect(after.reason).toMatch(/revoked/);
    expect((await payeeVerify(c.intent.token)).valid).toBe(true);
  });

  it("refuses to record a revocation for a chain that does not verify", async () => {
    const c = await jwtChain();
    const widened = await signMandateJwt("spending", { ...c.cart.mandate, constraints: { spendLimitUsd: 5000 }, mandateId: crypto.randomUUID() } as unknown as Record<string, unknown>, c.agent.priv);
    await expect(revokeMandate(REG, `${c.intent.jwt}~${widened}`, c.human.priv, { fetch: appFetch() })).rejects.toThrow(/400/);
    const stranger = await party();
    await expect(revokeMandate(REG, c.cart.token, stranger.priv, { revokerDid: c.human.did, fetch: appFetch() })).rejects.toThrow(/403/);
  });

  it("applies one cumulative cap to a JWT payment mandate, and refuses it once revoked", async () => {
    const c = await jwtChain();
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const verified = await payeeVerify(c.payment.token);
    await redeemPaymentMandate(store, verified.mandate!, 30, c.provider.did, { token: c.payment.token });
    await expect(redeemPaymentMandate(store, verified.mandate!, 30, c.provider.did, { token: c.payment.token })).rejects.toThrow();
    await revokeMandate(REG, c.intent.token, c.human.priv, { fetch: appFetch() });
    await expect(redeemPaymentMandate(store, verified.mandate!, 5, c.provider.did, { token: c.payment.token })).rejects.toThrow();
  });
});
