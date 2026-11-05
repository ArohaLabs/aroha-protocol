// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// /v1/mandates with web identities (spec §4.7): chains whose parties are
// https URLs that publish their key can be revoked and redeemed at the
// registry once the operator sets WEB_IDENTITIES=1, and are refused before
// that. Exercised through the real @aroha-sdk/credentials clients.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import dnsPromises from "node:dns/promises";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  attenuateToCart,
  attenuateToPayment,
  buildWebIdentityDocument,
  createMandateKeyResolver,
  httpRedemptionStore,
  httpRevocationCheck,
  issueIntentMandate,
  redeemPaymentMandate,
  revokeMandate,
  verifyMandateChain,
} from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { resetWebIdentityResolver } from "./mandates.js";

const REG = "https://registry.test";
const HUMAN = "https://accounts.example.com/people/kiri";
const ASSISTANT = "https://agents.example.com/assistant";
const SHOP = "https://shop.example.net/agents/checkout";

let t: TestApp;
let env: TestApp["env"] & { WEB_IDENTITIES?: string; WEB_IDENTITY_HOSTS?: string };
let ip = 0;
/** Identity documents the stubbed network serves: URL → public key. */
let published: Record<string, Uint8Array>;
let requests: string[];

beforeEach(async () => {
  t = await makeApp();
  env = { ...t.env, WEB_IDENTITIES: "1" };
  published = {};
  requests = [];
  resetWebIdentityResolver();
  // The registry resolves web identities with the global fetch. Stand in for
  // the network: serve the published documents, 404 everything else.
  vi.stubGlobal("fetch", async (input: string | URL | Request) => {
    const url = String(input);
    requests.push(url);
    const publicKey = published[url];
    if (!publicKey) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(buildWebIdentityDocument({ identity: url, publicKey })), { status: 200, headers: { "content-type": "application/json" } });
  });
  // On Node.js the SDK resolves each host before fetching it; answer with a public address.
  vi.spyOn(dnsPromises, "lookup").mockResolvedValue([{ address: "93.184.215.14", family: 4 }] as never);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  resetWebIdentityResolver();
});

/** A fetch that serves the test app: what the SDK clients see as "the registry". */
function appFetch(): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    headers.set("x-forwarded-for", `10.8.${(ip >> 8) & 255}.${ip++ & 255}`);
    return t.app.request(url.pathname + url.search, { ...init, headers }, env);
  }) as typeof fetch;
}

async function party() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, pub: await ed.getPublicKeyAsync(priv) };
}

/** A three-link chain between web identities, with their documents published. */
async function webChain() {
  const human = await party(), assistant = await party(), shop = await party();
  published = { [HUMAN]: human.pub, [ASSISTANT]: assistant.pub, [SHOP]: shop.pub };
  const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 100 }, human.priv);
  const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 60 }, assistant.priv);
  const payment = await attenuateToPayment(cart, SHOP, { spendLimitUsd: 50 }, shop.priv);
  return { human, assistant, shop, intent, cart, payment };
}

/** What a payee runs: the chain, keys from the web, revocation from the registry. */
function payeeVerify(token: string) {
  return verifyMandateChain(token, createMandateKeyResolver({ web: { fetch: globalThis.fetch, lookup: false } }), {
    expectedRoot: HUMAN,
    isRevoked: httpRevocationCheck(REG, { fetch: appFetch(), cacheMs: 0 }),
  });
}

describe("POST /v1/mandates/:id/revoke with web identities", () => {
  it("the root web identity revokes a downstream cart, and every verifier using the registry then rejects the chain", async () => {
    const c = await webChain();
    expect((await payeeVerify(c.payment.token)).valid).toBe(true);

    const r = await revokeMandate(REG, c.cart.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() });
    expect(r.revoked).toBe(true);
    expect(r.revokedBy).toBe(HUMAN);

    const after = await payeeVerify(c.payment.token);
    expect(after.valid).toBe(false);
    expect(after.reason).toMatch(/revoked/);
    // The intent above the revoked cart is untouched.
    expect((await payeeVerify(c.intent.token)).valid).toBe(true);
  });

  it("answers revocation status for a web-identity grantor", async () => {
    const c = await webChain();
    await revokeMandate(REG, c.intent.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() });
    const res = await t.app.request(`/v1/mandates/${c.intent.mandate.mandateId}/revoked?grantor=${encodeURIComponent(HUMAN)}`, {}, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: boolean; grantor: string; revokedBy: string };
    expect(body).toMatchObject({ revoked: true, grantor: HUMAN, revokedBy: HUMAN });
  });

  it("an intermediate web identity may revoke what it granted, and nothing above it", async () => {
    const c = await webChain();
    await revokeMandate(REG, c.payment.token, c.assistant.priv, { revokerDid: ASSISTANT, fetch: appFetch() });
    expect((await payeeVerify(c.payment.token)).valid).toBe(false);
    expect((await payeeVerify(c.cart.token)).valid).toBe(true);
  });

  it("refuses a revocation signed by a key the revoker's address does not publish", async () => {
    const c = await webChain();
    const thief = await party();
    await expect(revokeMandate(REG, c.cart.token, thief.priv, { revokerDid: HUMAN, fetch: appFetch() })).rejects.toThrow(/403/);
    expect((await payeeVerify(c.payment.token)).valid).toBe(true);
  });

  it("refuses a revoker that is not a grantor in the chain", async () => {
    const c = await webChain();
    const outsider = await party();
    const OUTSIDER = "https://elsewhere.example.org/agents/x";
    published[OUTSIDER] = outsider.pub;
    await expect(revokeMandate(REG, c.cart.token, outsider.priv, { revokerDid: OUTSIDER, fetch: appFetch() })).rejects.toThrow(/403/);
  });

  it("revokes a chain that mixes a did:aroha root with web identities", async () => {
    const human = await party(), assistant = await party();
    const humanDid = generateDid(human.pub);
    published = { [ASSISTANT]: assistant.pub };
    const intent = await issueIntentMandate(humanDid, ASSISTANT, { spendLimitUsd: 100 }, human.priv);
    const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 60 }, assistant.priv);
    const r = await revokeMandate(REG, cart.token, human.priv, { fetch: appFetch() });
    expect(r.revokedBy).toBe(humanDid);
  });

  it("is off by default: without WEB_IDENTITIES the chain does not verify and nothing is fetched", async () => {
    const c = await webChain();
    delete env.WEB_IDENTITIES;
    await expect(revokeMandate(REG, c.cart.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() })).rejects.toThrow(/400/);
    expect(requests).toHaveLength(0);
  });

  it("fetches only the hosts in WEB_IDENTITY_HOSTS", async () => {
    const c = await webChain();
    env.WEB_IDENTITY_HOSTS = "accounts.example.com, agents.example.com";
    // The intent names only allowed hosts.
    await revokeMandate(REG, c.intent.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() });
    // The payment is signed by shop.example.net, which is not listed.
    await expect(revokeMandate(REG, c.payment.token, c.shop.priv, { revokerDid: SHOP, fetch: appFetch() })).rejects.toThrow(/400/);
    expect(requests.some((u) => u.startsWith("https://shop.example.net/"))).toBe(false);
  });

  it("covers an address at the 2048-character limit, in revocation status too", async () => {
    const human = await party(), assistant = await party();
    const LONG = `https://accounts.example.com/${"p".repeat(2048 - 29)}`;
    expect(LONG).toHaveLength(2048);
    published = { [LONG]: human.pub, [ASSISTANT]: assistant.pub };
    const intent = await issueIntentMandate(LONG, ASSISTANT, { spendLimitUsd: 10 }, human.priv);
    const isRevoked = httpRevocationCheck(REG, { fetch: appFetch(), cacheMs: 0 });
    const resolveKey = createMandateKeyResolver({ web: { fetch: globalThis.fetch, lookup: false } });
    expect((await verifyMandateChain(intent.token, resolveKey, { isRevoked })).valid).toBe(true);
    await revokeMandate(REG, intent.token, human.priv, { revokerDid: LONG, fetch: appFetch() });
    expect((await verifyMandateChain(intent.token, resolveKey, { isRevoked })).valid).toBe(false);
  });

  it("refuses a web identity whose host resolves to an internal address", async () => {
    const c = await webChain();
    vi.mocked(dnsPromises.lookup).mockResolvedValue([{ address: "10.0.0.5", family: 4 }] as never);
    await expect(revokeMandate(REG, c.cart.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() })).rejects.toThrow(/400/);
    expect(requests).toHaveLength(0);
  });
});

describe("POST /v1/mandates/:id/redeem with web identities", () => {
  it("applies one cumulative cap to a payment mandate between web identities", async () => {
    const c = await webChain();
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const verified = await payeeVerify(c.payment.token);
    expect(verified.valid, verified.reason).toBe(true);
    await redeemPaymentMandate(store, verified.mandate!, 30, SHOP, { token: c.payment.token });
    await expect(redeemPaymentMandate(store, verified.mandate!, 30, SHOP, { token: c.payment.token })).rejects.toThrow();
    await redeemPaymentMandate(store, verified.mandate!, 20, SHOP, { token: c.payment.token });
  });

  it("refuses to redeem a revoked chain", async () => {
    const c = await webChain();
    const store = httpRedemptionStore(REG, t.apiKey, { fetch: appFetch() });
    const verified = await payeeVerify(c.payment.token);
    await revokeMandate(REG, c.intent.token, c.human.priv, { revokerDid: HUMAN, fetch: appFetch() });
    await expect(redeemPaymentMandate(store, verified.mandate!, 10, SHOP, { token: c.payment.token })).rejects.toThrow();
  });
});
