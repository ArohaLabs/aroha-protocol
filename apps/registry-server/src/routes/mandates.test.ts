// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// /v1/mandates — revocation and shared redemption, exercised through the
// real @aroha-sdk/credentials clients (revokeMandate, httpRevocationCheck,
// httpRedemptionStore) with their fetch routed into the Hono app over
// SQLite-backed D1. Chains are real attenuateToCart / attenuateToPayment
// output, so the server's verifyMandateChain is the payee's verifyMandateChain.

import { describe, it, expect, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandateChain,
  revokeMandate,
  httpRevocationCheck,
  httpRedemptionStore,
  redeemPaymentMandate,
  mandateRevocationPayload,
  mandateSigningPayloadV2,
  mandateRedemptionKey,
  SpendingConstraintViolation,
  type SignedMandate,
} from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";

let t: TestApp;
let ip = 0;
beforeEach(async () => { t = await makeApp(); });

const REG = "https://registry.test";
/** A fetch that serves the test app — what the SDK clients see as "the registry". */
function appFetch(): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    headers.set("x-forwarded-for", `10.9.${(ip >> 8) & 255}.${ip++ & 255}`);
    return t.app.request(url.pathname + url.search, { ...init, headers }, t.env);
  }) as typeof fetch;
}

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

async function chain(merchants: string[] | null = null) {
  const human = await party();
  const agent = await party();
  const provider = await party();
  const processor = await party();
  const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100, allowedMerchants: merchants }, human.priv);
  const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 60, allowedMerchants: merchants }, agent.priv);
  const payment = await attenuateToPayment(cart, processor.did, { spendLimitUsd: 50, allowedMerchants: merchants }, provider.priv);
  return { human, agent, provider, processor, intent, cart, payment };
}

/**
 * The squatting move: take a mandate the attacker validly signed, give it
 * someone else's mandateId, and re-sign it. The result verifies — the id is
 * the minter's to choose — so the registry must not treat it as the victim's.
 */
async function withMandateId(signed: SignedMandate, mandateId: string, grantorPriv: Uint8Array): Promise<string> {
  const raw = JSON.parse(Buffer.from(signed.token, "base64url").toString("utf8"));
  raw.mandate.mandateId = mandateId;
  const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(raw.mandate)), grantorPriv);
  raw.signature = Buffer.from(sig).toString("base64url");
  return Buffer.from(JSON.stringify(raw)).toString("base64url");
}

describe("POST /v1/mandates/:id/revoke + GET …/revoked", () => {
  it("the root grantor revokes a downstream cart; every verifier using the registry then rejects the chain", async () => {
    const c = await chain();
    const isRevoked = httpRevocationCheck(REG, { fetch: appFetch(), cacheMs: 0 });
    expect((await verifyMandateChain(c.payment.token, undefined, { isRevoked })).valid).toBe(true);

    const res = await revokeMandate(REG, c.cart.token, c.human.priv, { fetch: appFetch() });
    expect(res).toMatchObject({ mandateId: c.cart.mandate.mandateId, revoked: true, revokedBy: c.human.did });

    const after = await verifyMandateChain(c.payment.token, undefined, { isRevoked });
    expect(after.valid).toBe(false);
    expect(after.reason).toMatch(/has been revoked/);
  });

  it("the leaf's own grantor may revoke it", async () => {
    const c = await chain();
    await revokeMandate(REG, c.payment.token, c.provider.priv, { fetch: appFetch() });
    const q = `?grantor=${encodeURIComponent(c.provider.did)}`;
    const r = await t.app.request(`/v1/mandates/${c.payment.mandate.mandateId}/revoked${q}`, {}, t.env);
    expect(await r.json()).toMatchObject({ revoked: true, grantor: c.provider.did, revokedBy: c.provider.did });
  });

  it("refuses a revoker who is not a grantor in the chain (e.g. the grantee)", async () => {
    const c = await chain();
    await expect(revokeMandate(REG, c.cart.token, c.provider.priv, { fetch: appFetch(), revokerDid: c.provider.did }))
      .rejects.toThrow(/403: revoker is not a grantor/);
  });

  it("refuses a signature by a key other than the named revoker's", async () => {
    const c = await chain();
    const stranger = await party();
    await expect(revokeMandate(REG, c.cart.token, stranger.priv, { fetch: appFetch(), revokerDid: c.human.did }))
      .rejects.toThrow(/403: revocation signature does not verify/);
  });

  it("refuses a forged chain (a tampered token does not verify)", async () => {
    const c = await chain();
    const raw = JSON.parse(Buffer.from(c.cart.token, "base64url").toString("utf8"));
    raw.mandate.constraints.spendLimitUsd = 99;
    const forged = Buffer.from(JSON.stringify(raw)).toString("base64url");
    await expect(revokeMandate(REG, forged, c.human.priv, { fetch: appFetch() })).rejects.toThrow(/400: mandate chain does not verify/);
  });

  it("refuses a token whose leaf is not the :mandateId in the path", async () => {
    const c = await chain();
    const revokedAt = new Date().toISOString();
    const sig = await ed.signAsync(new TextEncoder().encode(mandateRevocationPayload(c.intent.mandate.mandateId, revokedAt)), c.human.priv);
    const res = await t.app.request(`/v1/mandates/${c.intent.mandate.mandateId}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "10.8.0.1" },
      body: JSON.stringify({ token: c.cart.token, revokedAt, revoker: c.human.did, signature: Buffer.from(sig).toString("base64url") }),
    }, t.env);
    expect(res.status).toBe(400);
  });

  it("first revocation wins; a repeat reports existing", async () => {
    const c = await chain();
    const first = await revokeMandate(REG, c.intent.token, c.human.priv, { fetch: appFetch(), revokedAt: new Date(Date.now() - 1000) });
    const second = await revokeMandate(REG, c.intent.token, c.human.priv, { fetch: appFetch() });
    expect(second.revokedAt).toBe(first.revokedAt);
  });

  it("GET …/revoked is false for an unknown mandate, and needs the grantor", async () => {
    const r = await t.app.request(`/v1/mandates/nope/revoked?grantor=did%3Aaroha%3Ax`, {}, t.env);
    // Signed now (revocation-status.test.ts checks the signature itself).
    expect(await r.json()).toEqual({
      mandateId: "nope", grantor: "did:aroha:x", revoked: false,
      checkedAt: expect.any(String), statusSignature: expect.any(String), statusKeyId: expect.any(String),
    });
    expect((await t.app.request(`/v1/mandates/nope/revoked`, {}, t.env)).status).toBe(400);
  });

  it("revoking a look-alike that reuses another grantor's mandateId leaves that grantor's mandate alone", async () => {
    const victim = await chain();
    const attacker = await chain();
    const squat = await withMandateId(attacker.intent, victim.intent.mandate.mandateId, attacker.human.priv);
    const done = await revokeMandate(REG, squat, attacker.human.priv, { fetch: appFetch() });
    expect(done.mandateId).toBe(victim.intent.mandate.mandateId);

    const isRevoked = httpRevocationCheck(REG, { fetch: appFetch(), cacheMs: 0 });
    expect((await verifyMandateChain(victim.payment.token, undefined, { isRevoked })).valid).toBe(true);
    // …while the attacker's own look-alike is revoked.
    expect((await verifyMandateChain(squat, undefined, { isRevoked })).valid).toBe(false);
  });
});

describe("POST /v1/mandates/:id/redeem", () => {
  it("enforces the cumulative cap across payees, with the limit derived from the verified token", async () => {
    const c = await chain();
    const storeA = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const storeB = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const r1 = await redeemPaymentMandate(storeA, c.payment.mandate, 30, "did:aroha:shop-a", { token: c.payment.token });
    expect(r1.redeemedTotalUsd).toBe(30);
    await expect(redeemPaymentMandate(storeB, c.payment.mandate, 30, "did:aroha:shop-b", { token: c.payment.token }))
      .rejects.toBeInstanceOf(SpendingConstraintViolation);
    expect(await storeB.redeemedMicros(mandateRedemptionKey(c.payment.mandate))).toBe(30_000_000);
    await expect(storeB.redeemedMicros(c.payment.mandate.mandateId)).rejects.toThrow(/mandateRedemptionKey/);
  });

  it("a look-alike payment mandate reusing the id does not spend the real one's cap", async () => {
    const victim = await chain();
    const attacker = await chain();
    const squat = await withMandateId(attacker.payment, victim.payment.mandate.mandateId, attacker.provider.priv);
    const post = (token: string, amountMicros: number) => t.app.request(`/v1/mandates/${victim.payment.mandate.mandateId}/redeem`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${t.apiKey}` },
      body: JSON.stringify({ token, amountMicros, merchant: "did:aroha:shop" }),
    }, t.env);
    expect((await post(squat, 50_000_000)).status).toBe(200);
    // The victim's own $50 cap is untouched by the attacker's $50.
    expect((await post(victim.payment.token, 50_000_000)).status).toBe(200);
  });

  it("ignores a caller-supplied limit: the server's limit is the token's", async () => {
    const c = await chain();
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const r = await store.tryRedeem(c.payment.mandate.mandateId, 60_000_000, 1_000_000_000, {
      redemptionId: "r1", mandateId: c.payment.mandate.mandateId, amountUsd: 60, merchant: "m", redeemedAt: "", token: c.payment.token,
    });
    expect(r).toEqual({ accepted: false, redeemedMicros: 0 });
  });

  it("refuses a revoked chain", async () => {
    const c = await chain();
    await revokeMandate(REG, c.intent.token, c.human.priv, { fetch: appFetch() });
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    await expect(redeemPaymentMandate(store, c.payment.mandate, 1, "did:aroha:shop", { token: c.payment.token }))
      .rejects.toThrow(/400: mandate chain does not verify: .*revoked/);
  });

  it("refuses non-payment mandates and disallowed merchants", async () => {
    const c = await chain(["did:aroha:shop-a"]);
    const post = (id: string, token: string, merchant: string) => t.app.request(`/v1/mandates/${id}/redeem`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${t.apiKey}` },
      body: JSON.stringify({ token, amountMicros: 1_000_000, merchant }),
    }, t.env);
    expect((await post(c.cart.mandate.mandateId, c.cart.token, "did:aroha:shop-a")).status).toBe(400);
    expect((await post(c.payment.mandate.mandateId, c.payment.token, "did:aroha:shop-z")).status).toBe(403);
    expect((await post(c.payment.mandate.mandateId, c.payment.token, "did:aroha:shop-a")).status).toBe(200);
  });

  // redemptionId is the caller's idempotency handle, scoped to its mandate:
  // another mandate reusing the same id is unaffected, and a repeat within
  // one mandate is a 409 — never the 500 a global primary key produced.
  it("scopes redemptionId to the mandate and answers a repeat with 409", async () => {
    const a = await chain();
    const b = await chain();
    const post = (c: Awaited<ReturnType<typeof chain>>) => t.app.request(`/v1/mandates/${c.payment.mandate.mandateId}/redeem`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${t.apiKey}` },
      body: JSON.stringify({ token: c.payment.token, amountMicros: 1_000_000, merchant: "did:aroha:shop", redemptionId: "order-1" }),
    }, t.env);
    expect((await post(a)).status).toBe(200);
    expect((await post(b)).status).toBe(200);
    const repeat = await post(a);
    expect(repeat.status).toBe(409);
    // The refused repeat did not spend anything.
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    expect(await store.redeemedMicros(mandateRedemptionKey(a.payment.mandate))).toBe(1_000_000);
  });

  it("requires an API key", async () => {
    const c = await chain();
    const res = await t.app.request(`/v1/mandates/${c.payment.mandate.mandateId}/redeem`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: c.payment.token, amountMicros: 1, merchant: "m" }),
    }, t.env);
    expect(res.status).toBe(401);
  });

  it("rejects non-integer amounts", async () => {
    const c = await chain();
    const res = await t.app.request(`/v1/mandates/${c.payment.mandate.mandateId}/redeem`, {
      method: "POST", headers: { "content-type": "application/json", Authorization: `Bearer ${t.apiKey}` },
      body: JSON.stringify({ token: c.payment.token, amountMicros: 1.5, merchant: "m" }),
    }, t.env);
    expect(res.status).toBe(400);
  });
});
