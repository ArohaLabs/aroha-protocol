// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * verifyHttpSpendRequest: the amount is checked and charged as a running
 * total against every link of the chain, keyed by grantor#mandateId, all or
 * nothing; every spending constraint is enforced; a missing input refuses.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid, type SpendingConstraints } from "@aroha-sdk/core";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp, verifyHttpMandateRequest } from "./http-mandate.js";
import { verifyHttpSpendRequest, type VerifyHttpSpendRequestOptions } from "./http-spend.js";
import { attenuateToCart, issueIntentMandate, issueTaskMandate, type SignedMandate } from "./mandate.js";
import { mandateRedemptionKey } from "./redemption.js";
import { BudgetExhaustedError, MapSpendingLedger, type ISpendingLedger } from "./spending-ledger.js";
import { buildHttpPresentationHeader, encodeHttpPresentation, presentMandateHttpUnchecked } from "./testing.js";

const AUD = "https://api.example.com";
const URL_ = "https://api.example.com/v1/invoices";
const BODY = '{"customer":"c1","amountUsd":120}';

interface Key { priv: Uint8Array; pub: Uint8Array; did: string }
async function key(): Promise<Key> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

let human: Key, agent: Key, providerA: Key, providerB: Key, stranger: Key;

beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  [human, agent, providerA, providerB, stranger] = await Promise.all([key(), key(), key(), key(), key()]);
});

const intent = (c: SpendingConstraints, grantor = human) => issueIntentMandate(grantor.did, agent.did, c, grantor.priv, 600_000);

async function header(token: string, holder: Key = agent): Promise<string> {
  return (await presentMandateHttp({
    token, holderDid: holder.did, holderPrivateKey: holder.priv, audience: AUD, method: "POST", url: URL_, body: BODY,
  }))[HTTP_MANDATE_HEADER];
}

function opts(ledger: ISpendingLedger, over: Partial<VerifyHttpSpendRequestOptions> = {}): VerifyHttpSpendRequestOptions {
  return {
    audience: AUD, method: "POST", url: "/v1/invoices", body: BODY, nonces: new InMemoryHttpPresentationNonces(),
    expectedRoot: human.did, isRevoked: null, ledger, amountUsd: 10, ...over,
  };
}

async function spend(m: SignedMandate, ledger: ISpendingLedger, over: Partial<VerifyHttpSpendRequestOptions> = {}, holder: Key = agent) {
  return verifyHttpSpendRequest(await header(m.token, holder), opts(ledger, over));
}

async function allocated(ledger: ISpendingLedger, m: SignedMandate): Promise<number> {
  return (await ledger.status(mandateRedemptionKey(m.mandate)))?.allocatedUsd ?? 0;
}

describe("verifyHttpSpendRequest — running total", () => {
  it("charges within the limit and refuses the cent that crosses it ($500.01 through a $500 mandate)", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 500 });
    const a = await spend(m, ledger, { amountUsd: 250 });
    expect(a).toMatchObject({ ok: true, holder: agent.did, rootGrantor: human.did, revocationChecked: false });
    if (!a.ok) throw new Error();
    expect(a.charge.amountUsd).toBe(250);
    expect(a.charge.allocations.map((x) => x.key)).toEqual([mandateRedemptionKey(m.mandate)]);
    expect(await spend(m, ledger, { amountUsd: 250.01 })).toMatchObject({ ok: false, code: "OVER_LIMIT", status: 403 });
    expect(await spend(m, ledger, { amountUsd: 250 })).toMatchObject({ ok: true });
    expect(await spend(m, ledger, { amountUsd: 0.01 })).toMatchObject({ ok: false, code: "OVER_LIMIT" });
    expect(await allocated(ledger, m)).toBe(500);
  });

  it("refuses a single spend above the limit without touching the ledger", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 500 });
    expect(await spend(m, ledger, { amountUsd: 500.01 })).toMatchObject({ ok: false, code: "OVER_LIMIT", status: 403 });
    expect(await ledger.status(mandateRedemptionKey(m.mandate))).toBeNull();
  });

  it("keys totals by grantor#mandateId: a stranger's mandate reusing the id does not spend this one down", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 100 });
    // A mandate of the stranger's own, under the same mandateId, presented to a server that trusts both roots.
    const forged = await issueIntentMandate(stranger.did, agent.did, { spendLimitUsd: 100 }, stranger.priv, 600_000);
    forged.mandate.mandateId = m.mandate.mandateId; // re-sign under the reused id
    const reissued = await (async () => {
      const { mandateSigningPayloadV2 } = await import("./mandate.js");
      const sig = Buffer.from(await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(forged.mandate)), stranger.priv)).toString("base64url");
      return Buffer.from(JSON.stringify({ v: 2, mandate: forged.mandate, signature: sig, chain: [] })).toString("base64url");
    })();
    const roots = { expectedRoot: undefined, trustedRoots: [human.did, stranger.did] };
    const r1 = await verifyHttpSpendRequest(await header(reissued), opts(ledger, { ...roots, amountUsd: 100 }));
    expect(r1).toMatchObject({ ok: true, rootGrantor: stranger.did });
    expect(await spend(m, ledger, { amountUsd: 100 })).toMatchObject({ ok: true });
    expect(await ledger.status(m.mandate.mandateId)).toBeNull(); // never the bare id
  });

  it("two concurrent spends cannot both take the last of the budget", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 500 });
    const [h1, h2, h3] = await Promise.all([header(m.token), header(m.token), header(m.token)]);
    const nonces = new InMemoryHttpPresentationNonces();
    const results = await Promise.all([h1, h2, h3].map((h) => verifyHttpSpendRequest(h, opts(ledger, { amountUsd: 200, nonces }))));
    expect(results.filter((r) => r.ok)).toHaveLength(2);
    expect(results.filter((r) => !r.ok && r.code === "OVER_LIMIT")).toHaveLength(1);
    expect(await allocated(ledger, m)).toBe(400);
  });

  it("release() gives the money back to every link, once", async () => {
    const ledger = new MapSpendingLedger();
    const root = await intent({ spendLimitUsd: 500 });
    const cart = await attenuateToCart(root, providerA.did, { spendLimitUsd: 300 }, agent.priv);
    const r = await spend(cart, ledger, { amountUsd: 300 }, providerA);
    if (!r.ok) throw new Error(r.reason);
    expect(r.charge.allocations).toHaveLength(2);
    expect(await allocated(ledger, root)).toBe(300);
    expect(await allocated(ledger, cart)).toBe(300);
    await r.charge.release();
    await r.charge.release();
    expect(await allocated(ledger, root)).toBe(0);
    expect(await allocated(ledger, cart)).toBe(0);
    expect(await spend(cart, ledger, { amountUsd: 300 }, providerA)).toMatchObject({ ok: true });
  });
});

describe("verifyHttpSpendRequest — delegated chains", () => {
  it("siblings share the parent's budget: the second cart cannot also claim the intent's full limit", async () => {
    const ledger = new MapSpendingLedger();
    const root = await intent({ spendLimitUsd: 500 });
    const cartA = await attenuateToCart(root, providerA.did, { spendLimitUsd: 400 }, agent.priv);
    const cartB = await attenuateToCart(root, providerB.did, { spendLimitUsd: 400 }, agent.priv);
    expect(await spend(cartA, ledger, { amountUsd: 300 }, providerA)).toMatchObject({ ok: true });
    const b = await spend(cartB, ledger, { amountUsd: 300 }, providerB);
    expect(b).toMatchObject({ ok: false, code: "OVER_LIMIT" });
    expect(!b.ok && b.reason).toContain(root.mandate.mandateId);
    expect(await allocated(ledger, cartB)).toBe(0);
    expect(await spend(cartB, ledger, { amountUsd: 200 }, providerB)).toMatchObject({ ok: true });
    expect(await allocated(ledger, root)).toBe(500);
  });

  it("rolls back the links already charged when a later link is exhausted", async () => {
    const ledger = new MapSpendingLedger();
    const root = await intent({ spendLimitUsd: 500 });
    const cart = await attenuateToCart(root, providerA.did, { spendLimitUsd: 100 }, agent.priv);
    expect(await spend(cart, ledger, { amountUsd: 60 }, providerA)).toMatchObject({ ok: true });
    // 60 more fits the intent (120 ≤ 500) but not the cart (120 > 100): the intent's charge must be undone.
    expect(await spend(cart, ledger, { amountUsd: 60 }, providerA)).toMatchObject({ ok: false, code: "OVER_LIMIT" });
    expect(await allocated(ledger, root)).toBe(60);
    expect(await allocated(ledger, cart)).toBe(60);
  });

  it("a ledger failure part-way refuses with 503 and rolls back", async () => {
    const inner = new MapSpendingLedger();
    const root = await intent({ spendLimitUsd: 500 });
    const cart = await attenuateToCart(root, providerA.did, { spendLimitUsd: 100 }, agent.priv);
    let calls = 0;
    const flaky: ISpendingLedger = {
      init: (k, l) => inner.init(k, l),
      allocate: async (k, a) => { if (++calls === 2) throw new Error("connection reset"); return inner.allocate(k, a); },
      release: (k, id) => inner.release(k, id),
      status: (k) => inner.status(k),
    };
    expect(await spend(cart, flaky, { amountUsd: 10 }, providerA)).toMatchObject({ ok: false, code: "LEDGER_UNAVAILABLE", status: 503 });
    expect(await allocated(inner, root)).toBe(0);
  });

  it("a ledger that throws BudgetExhaustedError on an unknown key is reported as over limit", async () => {
    const ledger: ISpendingLedger = {
      init: async () => {}, allocate: async (k, a) => { throw new BudgetExhaustedError(k, a, 0); },
      release: async () => ({ remainingUsd: 0 }), status: async () => null,
    };
    expect(await spend(await intent({ spendLimitUsd: 50 }), ledger)).toMatchObject({ ok: false, code: "OVER_LIMIT" });
  });
});

describe("verifyHttpSpendRequest — constraints", () => {
  it("currency: the spend's currency (default USD) must match every link's (default USD)", async () => {
    const ledger = new MapSpendingLedger();
    const eur = await intent({ spendLimitUsd: 100, currency: "EUR" });
    expect(await spend(eur, ledger)).toMatchObject({ ok: false, code: "CURRENCY_MISMATCH", status: 403 });
    expect(await spend(eur, ledger, { currency: "EUR" })).toMatchObject({ ok: true });
    const usd = await intent({ spendLimitUsd: 100 });
    expect(await spend(usd, ledger, { currency: "EUR" })).toMatchObject({ ok: false, code: "CURRENCY_MISMATCH" });
    expect(await spend(usd, ledger, { currency: "USD" })).toMatchObject({ ok: true });
  });

  it("allowedMerchants: a missing merchant refuses, a merchant off the list refuses", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 100, allowedMerchants: ["did:web:shop.example"] });
    expect(await spend(m, ledger)).toMatchObject({ ok: false, code: "MERCHANT_NOT_ALLOWED" });
    expect(await spend(m, ledger, { merchant: "did:web:other.example" })).toMatchObject({ ok: false, code: "MERCHANT_NOT_ALLOWED" });
    expect(await spend(m, ledger, { merchant: "did:web:shop.example" })).toMatchObject({ ok: true });
    const none = await intent({ spendLimitUsd: 100, allowedMerchants: [] });
    expect(await spend(none, ledger, { merchant: "did:web:shop.example" })).toMatchObject({ ok: false, code: "MERCHANT_NOT_ALLOWED" });
  });

  it("merchantCategory: required and must match when the mandate sets one", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 100, merchantCategory: "5734" });
    expect(await spend(m, ledger)).toMatchObject({ ok: false, code: "MERCHANT_CATEGORY_NOT_ALLOWED" });
    expect(await spend(m, ledger, { merchantCategory: "5812" })).toMatchObject({ ok: false, code: "MERCHANT_CATEGORY_NOT_ALLOWED" });
    expect(await spend(m, ledger, { merchantCategory: "5734" })).toMatchObject({ ok: true });
  });

  it("requireHumanApprovalAboveUsd: above the threshold needs humanApproved: true", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 500, requireHumanApprovalAboveUsd: 100 });
    expect(await spend(m, ledger, { amountUsd: 100 })).toMatchObject({ ok: true });
    expect(await spend(m, ledger, { amountUsd: 150 })).toMatchObject({ ok: false, code: "HUMAN_APPROVAL_REQUIRED" });
    expect(await spend(m, ledger, { amountUsd: 150, humanApproved: false })).toMatchObject({ ok: false, code: "HUMAN_APPROVAL_REQUIRED" });
    expect(await spend(m, ledger, { amountUsd: 150, humanApproved: true })).toMatchObject({ ok: true });
    expect(await allocated(ledger, m)).toBe(250);
  });

  it("sessionLimitUsd caps the running total when tighter than spendLimitUsd", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 500, sessionLimitUsd: 200 });
    expect(await spend(m, ledger, { amountUsd: 250 })).toMatchObject({ ok: false, code: "OVER_LIMIT" });
    expect(await spend(m, ledger, { amountUsd: 150 })).toMatchObject({ ok: true });
    expect(await spend(m, ledger, { amountUsd: 100 })).toMatchObject({ ok: false, code: "OVER_LIMIT" });
  });

  it("a delegated chain is checked link by link (root first)", async () => {
    const ledger = new MapSpendingLedger();
    const root = await intent({ spendLimitUsd: 500, allowedMerchants: ["did:web:shop.example"] });
    const cart = await attenuateToCart(root, providerA.did, { spendLimitUsd: 100, allowedMerchants: ["did:web:shop.example"] }, agent.priv);
    const r = await spend(cart, ledger, {}, providerA);
    expect(r).toMatchObject({ ok: false, code: "MERCHANT_NOT_ALLOWED" });
    expect(!r.ok && r.reason).toContain(`intent ${root.mandate.mandateId}`);
    expect(await spend(cart, ledger, { merchant: "did:web:shop.example" }, providerA)).toMatchObject({ ok: true });
  });

  it("refuses invalid amounts with 400 before consuming the presentation", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 100 });
    const h = await header(m.token);
    const nonces = new InMemoryHttpPresentationNonces();
    for (const bad of [Number.NaN, -1, 0, -0, Infinity, -Infinity, 1e-7, 1e300, "5", null, undefined]) {
      const r = await verifyHttpSpendRequest(h, opts(ledger, { amountUsd: bad as number, nonces }));
      expect(r, String(bad)).toMatchObject({ ok: false, code: "INVALID_AMOUNT", status: 400 });
    }
    expect(await verifyHttpSpendRequest(h, opts(ledger, { amountUsd: 5, nonces }))).toMatchObject({ ok: true });
  });

  it("a task mandate is refused as NOT_A_SPENDING_MANDATE", async () => {
    const task = await issueTaskMandate(human.did, agent.did, ["invoices.send"], { maxCalls: 1 } as never, human.priv, 600_000);
    expect(await spend(task as unknown as SignedMandate, new MapSpendingLedger())).toMatchObject({ ok: false, code: "NOT_A_SPENDING_MANDATE", status: 403 });
  });

  it("presentation and chain failures keep their codes", async () => {
    const ledger = new MapSpendingLedger();
    const m = await intent({ spendLimitUsd: 100 });
    expect(await verifyHttpSpendRequest(undefined, opts(ledger))).toMatchObject({ ok: false, code: "MISSING", status: 401 });
    expect(await verifyHttpSpendRequest(await header(m.token), opts(ledger, { expectedRoot: agent.did })))
      .toMatchObject({ ok: false, code: "MANDATE_INVALID", status: 403 });
    expect(await spend(m, ledger, { isRevoked: async () => true })).toMatchObject({ ok: false, code: "MANDATE_INVALID" });
    expect(await spend(m, ledger, { isRevoked: async () => false })).toMatchObject({ ok: true, revocationChecked: true });
  });

  it("throws on a server misconfiguration instead of running a weaker check", async () => {
    const m = await intent({ spendLimitUsd: 100 });
    const h = await header(m.token);
    await expect(verifyHttpSpendRequest(h, opts(undefined as never))).rejects.toThrow(/ledger is required/);
    const { expectedRoot: _r, ...noPin } = opts(new MapSpendingLedger());
    await expect(verifyHttpSpendRequest(h, noPin)).rejects.toThrow(/pin the root/);
    await expect(verifyHttpSpendRequest(h, opts(new MapSpendingLedger(), { merchant: "" }))).rejects.toThrow(/merchant/);
    const { isRevoked: _, ...noHook } = opts(new MapSpendingLedger());
    await expect(verifyHttpSpendRequest(h, noHook as never)).rejects.toThrow(/isRevoked is required/);
  });

  it("an empty pin (no enrolled DID for this customer) is a 403 refusal, not a crash; nothing is charged or consumed", async () => {
    const m = await intent({ spendLimitUsd: 100 });
    const h = await header(m.token);
    const ledger = new MapSpendingLedger();
    const nonces = new InMemoryHttpPresentationNonces();
    const enrollments = new Map<string, string>();
    for (const expectedRoot of [enrollments.get("unknown-customer"), null, ""]) {
      expect(await verifyHttpSpendRequest(h, opts(ledger, { nonces, expectedRoot })))
        .toMatchObject({ ok: false, code: "ROOT_NOT_PINNED", status: 403 });
    }
    expect(await verifyHttpSpendRequest(h, opts(ledger, { nonces, expectedRoot: undefined, trustedRoots: [] })))
      .toMatchObject({ ok: false, code: "ROOT_NOT_PINNED", status: 403 });
    expect(nonces.size).toBe(0);
    expect(await allocated(ledger, m)).toBe(0);
    expect((await verifyHttpSpendRequest(h, opts(ledger, { nonces }))).ok).toBe(true);
  });

  it("one injected clock governs presentation, nonce and mandate expiry (no sleeping)", async () => {
    const t0 = Date.now();
    const m = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv, 60_000);
    const at = async (now: number, ledger: ISpendingLedger) => verifyHttpSpendRequest(
      (await presentMandateHttp({ token: m.token, holderDid: agent.did, holderPrivateKey: agent.priv, audience: AUD, method: "POST", url: URL_, body: BODY, now }))[HTTP_MANDATE_HEADER],
      opts(ledger, { now }),
    );
    const ledger = new MapSpendingLedger();
    expect((await at(t0 + 59_000, ledger)).ok).toBe(true);
    const late = await at(t0 + 120_000, ledger);
    expect(late).toMatchObject({ ok: false, code: "MANDATE_INVALID", status: 403 });
    expect(late.ok === false && late.reason).toMatch(/expired/i);
    expect(await allocated(ledger, m)).toBe(10);
  });
});

describe("isRevoked: null is a quiet opt-out", () => {
  it("prints no warning for an explicit null, and still warns when the hook is omitted", async () => {
    vi.resetModules();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warn.mockClear();
    const fresh = await import("./http-mandate.js");
    const freshMandate = await import("./mandate.js");
    const m = await intent({ spendLimitUsd: 100 });
    const r = await fresh.verifyHttpMandateRequest(await header(m.token), {
      audience: AUD, method: "POST", url: "/v1/invoices", body: BODY, nonces: new fresh.InMemoryHttpPresentationNonces(),
      expectedRoot: human.did, isRevoked: null,
    });
    expect(r).toMatchObject({ ok: true, revocationChecked: false });
    await freshMandate.verifyMandateChain(m.token, undefined, { isRevoked: null });
    expect(warn).not.toHaveBeenCalled();
    await freshMandate.verifyMandateChain(m.token);
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe("@aroha-sdk/credentials/testing", () => {
  it("presentMandateHttpUnchecked lets a non-grantee present (refused by the server)", async () => {
    const m = await intent({ spendLimitUsd: 100 });
    await expect(presentMandateHttp({ token: m.token, holderDid: stranger.did, holderPrivateKey: stranger.priv, audience: AUD, method: "POST", url: URL_, body: BODY }))
      .rejects.toThrow(/grantee/);
    const h = (await presentMandateHttpUnchecked({ token: m.token, holderDid: stranger.did, holderPrivateKey: stranger.priv, audience: AUD, method: "post", url: URL_, body: BODY }))[HTTP_MANDATE_HEADER];
    expect(await verifyHttpSpendRequest(h, opts(new MapSpendingLedger()))).toMatchObject({ ok: false, code: "HOLDER_NOT_GRANTEE", status: 401 });
  });

  it("buildHttpPresentationHeader: an honest build verifies; each tampered field is refused with its code", async () => {
    const m = await intent({ spendLimitUsd: 100 });
    const base = { token: m.token, holder: agent.did, signerPrivateKey: agent.priv, audience: AUD, method: "POST", url: URL_, body: BODY };
    const run = async (over: Record<string, unknown>) =>
      verifyHttpMandateRequest((await buildHttpPresentationHeader({ ...base, ...over }))[HTTP_MANDATE_HEADER],
        { audience: AUD, method: "POST", url: "/v1/invoices", body: BODY, nonces: new InMemoryHttpPresentationNonces(), expectedRoot: human.did, isRevoked: null });
    expect(await run({})).toMatchObject({ ok: true });
    expect(await run({ signerPrivateKey: stranger.priv })).toMatchObject({ code: "BAD_PROOF" });
    expect(await run({ body: '{"customer":"c1","amountUsd":1200}' })).toMatchObject({ code: "BAD_PROOF" });
    expect(await run({ ttlMs: 3_600_000 })).toMatchObject({ code: "LIFETIME_TOO_LONG" });
    expect(await run({ extraMembers: { scope: "all" } })).toMatchObject({ code: "MALFORMED" });
    expect(await run({ omitMembers: ["nonce"] })).toMatchObject({ code: "MALFORMED" });
    expect(await run({ proof: "AAAA" })).toMatchObject({ code: "BAD_PROOF" });
    expect(await run({ token: "bm90IGEgdG9rZW4", mandateId: "x" })).toMatchObject({ code: "MALFORMED_TOKEN" });
    expect(encodeHttpPresentation({ b: 1, a: 2 })).toBe(Buffer.from('{"a":2,"b":1}').toString("base64url"));
  });

  it("is not reachable from the package's main entry points", async () => {
    const main = await import("./index.js");
    const mandates = await import("./mandates.js");
    for (const mod of [main, mandates] as Record<string, unknown>[]) {
      expect(mod.presentMandateHttpUnchecked).toBeUndefined();
      expect(mod.buildHttpPresentationHeader).toBeUndefined();
      expect(typeof mod.verifyHttpSpendRequest).toBe("function");
    }
  });
});
