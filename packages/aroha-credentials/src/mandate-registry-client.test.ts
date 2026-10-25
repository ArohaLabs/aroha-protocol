// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Client half of the registry's /v1/mandates endpoints, against a fetch
 * stub. The registry-server suite (routes/mandates.test.ts) runs the same
 * clients against the real routes.
 */

import { describe, it, expect, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import {
  httpRevocationCheck,
  revokeMandate,
  httpRedemptionStore,
  mandateRevocationPayload,
  MANDATE_REVOCATION_PURPOSE,
  REVOCATION_STATUS_PURPOSE,
  RevocationStatusVerificationError,
  registryKeyId,
  revocationStatusPayload,
} from "./mandate-registry-client.js";
import { issueIntentMandate, attenuateToCart, verifyMandateChain } from "./mandate.js";
import { redeemPaymentMandate } from "./redemption.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

/** A grantor DID — the registry answers per (grantor, mandateId). */
const G = "did:aroha:grantor";

describe("httpRevocationCheck", () => {
  it("refuses to look up a bare mandateId without its grantor", async () => {
    const check = httpRevocationCheck("https://reg.example", { fetch: (async () => jsonResponse(200, { revoked: false })) as unknown as typeof fetch });
    await expect((check as unknown as (id: string) => Promise<boolean>)("m1")).rejects.toThrow(/grantor/);
  });

  it("caches per grantor: a revoked look-alike id under another grantor is not this one", async () => {
    const f = vi.fn(async (u: string) => jsonResponse(200, { revoked: String(u).includes(encodeURIComponent("did:aroha:other")) }));
    const check = httpRevocationCheck("https://reg.example", { fetch: f as unknown as typeof fetch, cacheMs: 60_000 });
    expect(await check("m1", "did:aroha:other")).toBe(true);
    expect(await check("m1", G)).toBe(false);
  });

  it("reports revoked, and caches a revocation forever", async () => {
    const f = vi.fn(async () => jsonResponse(200, { revoked: true, revokedAt: "2026-01-01T00:00:00.000Z" }));
    const check = httpRevocationCheck("https://reg.example/", { fetch: f as unknown as typeof fetch, cacheMs: 0 });
    expect(await check("m1", G)).toBe(true);
    expect(await check("m1", G)).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
    expect(String((f.mock.calls[0] as unknown[])[0])).toBe("https://reg.example/v1/mandates/m1/revoked?grantor=did%3Aaroha%3Agrantor");
  });

  it("caches 'not revoked' only for cacheMs", async () => {
    vi.useFakeTimers();
    try {
      const f = vi.fn(async () => jsonResponse(200, { revoked: false }));
      const check = httpRevocationCheck("https://reg.example", { fetch: f as unknown as typeof fetch, cacheMs: 1_000 });
      expect(await check("m1", G)).toBe(false);
      expect(await check("m1", G)).toBe(false);
      expect(f).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(1_001);
      expect(await check("m1", G)).toBe(false);
      expect(f).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails CLOSED by default: an unreachable registry rejects the chain", async () => {
    const human = await party();
    const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 10 }, human.priv);
    const onError = vi.fn();
    const check = httpRevocationCheck("https://reg.example", {
      fetch: (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch,
      onError,
    });
    const r = await verifyMandateChain(intent.token, undefined, { isRevoked: check });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Revocation check failed/);
    expect(onError).toHaveBeenCalledOnce();
  });

  it("a non-2xx or malformed answer is a failure, not 'not revoked'", async () => {
    const c500 = httpRevocationCheck("https://reg.example", { fetch: (async () => jsonResponse(500, {})) as unknown as typeof fetch });
    await expect(c500("m1", G)).rejects.toThrow(/HTTP 500/);
    const cBad = httpRevocationCheck("https://reg.example", { fetch: (async () => jsonResponse(200, { revoked: "no" })) as unknown as typeof fetch });
    await expect(cBad("m1", G)).rejects.toThrow(/boolean/);
  });

  it("failOpen: true treats an unreachable registry as not revoked (opt-in)", async () => {
    const check = httpRevocationCheck("https://reg.example", {
      fetch: (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch,
      failOpen: true,
    });
    expect(await check("m1", G)).toBe(false);
  });
});

describe("httpRevocationCheck with registryKeys (signed status)", () => {
  // A stand-in for the registry's signing key and its published key document.
  const regSeed = new Uint8Array(32).fill(5);
  const regPub = ed.getPublicKey(regSeed);
  const keyDoc = [{
    keyId: registryKeyId(regPub),
    publicKeyB64: Buffer.from(regPub).toString("base64url"),
    purpose: ["audit-anchor", "revocation-status"],
  }];

  /** What GET /v1/mandates/:id/revoked answers, signed as the registry signs it. */
  function signedAnswer(
    over: Partial<{ mandateId: string; grantor: string; revoked: boolean; revokedAt: string; checkedAt: string }> = {},
    seed = regSeed,
  ) {
    const s = { mandateId: "m1", grantor: G, revoked: false, checkedAt: new Date().toISOString(), ...over };
    const sig = ed.sign(new TextEncoder().encode(revocationStatusPayload(s)), seed);
    return { ...s, statusSignature: Buffer.from(sig).toString("base64url"), statusKeyId: registryKeyId(ed.getPublicKey(seed)) };
  }
  const serve = (body: unknown) => (async () => jsonResponse(200, body)) as unknown as typeof fetch;

  it("the payload is JCS with the revocation-status purpose", () => {
    expect(revocationStatusPayload({ mandateId: "m", grantor: "g", revoked: false, checkedAt: "t" }))
      .toBe(`{"checkedAt":"t","grantor":"g","mandateId":"m","purpose":"${REVOCATION_STATUS_PURPOSE}","revoked":false}`);
  });

  it("accepts a valid signed 'not revoked' and 'revoked'", async () => {
    const ok = httpRevocationCheck("https://reg.example", { fetch: serve(signedAnswer()), registryKeys: keyDoc, cacheMs: 0 });
    expect(await ok("m1", G)).toBe(false);
    const rv = httpRevocationCheck("https://reg.example", {
      fetch: serve(signedAnswer({ revoked: true, revokedAt: "2026-01-01T00:00:00.000Z" })), registryKeys: keyDoc,
    });
    expect(await rv("m1", G)).toBe(true);
  });

  it("accepts a resolver instead of a key list", async () => {
    const check = httpRevocationCheck("https://reg.example", {
      fetch: serve(signedAnswer()),
      registryKeys: (id) => (id === registryKeyId(regPub) ? regPub : null),
    });
    expect(await check("m1", G)).toBe(false);
  });

  it("rejects (fail closed, even with failOpen) an unsigned, tampered, mis-addressed, foreign-key or stale answer", async () => {
    const cases: unknown[] = [
      { mandateId: "m1", grantor: G, revoked: false },                                        // unsigned (pre-signing registry)
      { ...signedAnswer({ revoked: true, revokedAt: "2026-01-01T00:00:00.000Z" }), revoked: false }, // flipped verdict
      signedAnswer({ mandateId: "other" }),                                                    // a different mandate's answer
      signedAnswer({ grantor: "did:aroha:other" }),                                            // a different grantor's answer
      signedAnswer({}, new Uint8Array(32).fill(6)),                                            // signed by an unknown key
      signedAnswer({ checkedAt: new Date(Date.now() - 120_000).toISOString() }),               // stale (replayed)
      signedAnswer({ checkedAt: new Date(Date.now() + 120_000).toISOString() }),               // from the future
      { ...signedAnswer(), statusSignature: "AAAA" },                                          // garbage signature
    ];
    for (const body of cases) {
      const errors: unknown[] = [];
      const check = httpRevocationCheck("https://reg.example", {
        fetch: serve(body), registryKeys: keyDoc, failOpen: true, cacheMs: 0, onError: (_id, e) => errors.push(e),
      });
      await expect(check("m1", G)).rejects.toBeInstanceOf(RevocationStatusVerificationError);
      expect(errors).toHaveLength(1);
    }
  });

  it("a rejected status makes verifyMandateChain reject the chain", async () => {
    const human = await party();
    const agent = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 10 }, human.priv);
    const isRevoked = httpRevocationCheck("https://reg.example", {
      fetch: serve({ mandateId: intent.mandate.mandateId, grantor: human.did, revoked: false }), registryKeys: keyDoc,
    });
    expect((await verifyMandateChain(intent.token, undefined, { isRevoked })).valid).toBe(false);
  });

  it("maxStatusAgeMs widens or narrows the freshness window", async () => {
    const old = signedAnswer({ checkedAt: new Date(Date.now() - 90_000).toISOString() });
    const lenient = httpRevocationCheck("https://reg.example", { fetch: serve(old), registryKeys: keyDoc, maxStatusAgeMs: 120_000 });
    expect(await lenient("m1", G)).toBe(false);
  });

  it("ignores retired keys and refuses a key list with no usable key", () => {
    expect(() => httpRevocationCheck("https://reg.example", { registryKeys: [{ ...keyDoc[0]!, retired: true }] }))
      .toThrow(/no usable/);
    expect(() => httpRevocationCheck("https://reg.example", { registryKeys: [{ keyId: "x", publicKeyB64: "short" }] }))
      .toThrow(/32-byte/);
  });

  it("without registryKeys, an unsigned answer is still accepted (backward compatible)", async () => {
    const check = httpRevocationCheck("https://reg.example", { fetch: serve({ revoked: false }) });
    expect(await check("m1", G)).toBe(false);
  });
});

describe("revokeMandate", () => {
  it("signs the revocation payload as the ancestor grantor whose key it holds", async () => {
    const human = await party();
    const agent = await party();
    const shop = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 10 }, human.priv);
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 5 }, agent.priv);

    let sent: { url: string; body: Record<string, string> } | undefined;
    const f = vi.fn(async (url: string, init: RequestInit) => {
      sent = { url, body: JSON.parse(String(init.body)) };
      return jsonResponse(200, { mandateId: cart.mandate.mandateId, revoked: true, revokedAt: sent.body.revokedAt, revokedBy: sent.body.revoker });
    });
    const res = await revokeMandate("https://reg.example", cart.token, human.priv, { fetch: f as unknown as typeof fetch });

    expect(sent!.url).toBe(`https://reg.example/v1/mandates/${cart.mandate.mandateId}/revoke`);
    expect(sent!.body.revoker).toBe(human.did); // the ROOT grantor, found by key
    expect(sent!.body.token).toBe(cart.token);
    const ok = await ed.verifyAsync(
      Buffer.from(sent!.body.signature, "base64url"),
      new TextEncoder().encode(mandateRevocationPayload(cart.mandate.mandateId, sent!.body.revokedAt)),
      human.pub,
    );
    expect(ok).toBe(true);
    expect(res).toMatchObject({ mandateId: cart.mandate.mandateId, revoked: true, revokedBy: human.did });
  });

  it("the payload is JCS with a purpose tag", () => {
    expect(mandateRevocationPayload("m1", "2026-01-01T00:00:00.000Z")).toBe(
      `{"mandateId":"m1","purpose":"${MANDATE_REVOCATION_PURPOSE}","revokedAt":"2026-01-01T00:00:00.000Z"}`
    );
  });

  it("throws with the registry's error on refusal", async () => {
    const human = await party();
    const intent = await issueIntentMandate(human.did, "did:aroha:x", { spendLimitUsd: 1 }, human.priv);
    const f = async () => jsonResponse(403, { error: "revoker is not a grantor in this chain" });
    await expect(revokeMandate("https://reg.example", intent.token, ed.utils.randomPrivateKey(), { fetch: f as unknown as typeof fetch }))
      .rejects.toThrow(/403: revoker is not a grantor/);
  });
});

describe("httpRedemptionStore", () => {
  async function paymentToken() {
    const { attenuateToPayment } = await import("./mandate.js");
    const human = await party();
    const agent = await party();
    const provider = await party();
    const processor = await party();
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv);
    const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 60 }, agent.priv);
    return attenuateToPayment(cart, processor.did, { spendLimitUsd: 50 }, provider.priv);
  }

  it("refuses to redeem without the token (the registry derives the limit from it)", async () => {
    const store = httpRedemptionStore("https://reg.example", "k", { fetch: vi.fn() as unknown as typeof fetch });
    const payment = await paymentToken();
    await expect(redeemPaymentMandate(store, payment.mandate, 10, "did:aroha:shop")).rejects.toThrow(/needs the mandate token/);
  });

  it("posts token, amount and merchant with the API key; maps 200 and 409", async () => {
    const payment = await paymentToken();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    let total = 0;
    const f = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      const body = JSON.parse(String(init.body)) as { amountMicros: number };
      if (total + body.amountMicros > 50_000_000) return jsonResponse(409, { accepted: false, redeemedMicros: total, limitMicros: 50_000_000 });
      total += body.amountMicros;
      return jsonResponse(200, { accepted: true, redeemedMicros: total, limitMicros: 50_000_000 });
    });
    const store = httpRedemptionStore("https://reg.example", "secret-key", { fetch: f as unknown as typeof fetch });
    const r = await redeemPaymentMandate(store, payment.mandate, 30, "did:aroha:shop", { token: payment.token });
    expect(r.redeemedTotalUsd).toBe(30);
    expect(calls[0].url).toBe(`https://reg.example/v1/mandates/${payment.mandate.mandateId}/redeem`);
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe("Bearer secret-key");
    expect(JSON.parse(String(calls[0].init.body))).toMatchObject({ token: payment.token, amountMicros: 30_000_000, merchant: "did:aroha:shop" });
    await expect(redeemPaymentMandate(store, payment.mandate, 30, "did:aroha:shop", { token: payment.token }))
      .rejects.toThrow(/exceed/);
  });

  it("throws on a server error instead of reporting a redemption", async () => {
    const payment = await paymentToken();
    const store = httpRedemptionStore("https://reg.example", "k", {
      fetch: (async () => jsonResponse(500, { error: "boom" })) as unknown as typeof fetch,
    });
    await expect(store.tryRedeem(payment.mandate.mandateId, 1, 10, {
      redemptionId: "r", mandateId: payment.mandate.mandateId, amountUsd: 0.000001, merchant: "m", redeemedAt: "", token: payment.token,
    })).rejects.toThrow(/HTTP 500: boom/);
  });

  it("redeemedMicros reads GET …/redemptions", async () => {
    const f = vi.fn(async () => jsonResponse(200, { mandateId: "m1", redeemedMicros: 7 }));
    const store = httpRedemptionStore("https://reg.example", "k", { fetch: f as unknown as typeof fetch });
    expect(await store.redeemedMicros(`${G}#m1`)).toBe(7);
    expect(String((f.mock.calls[0] as unknown[])[0])).toBe("https://reg.example/v1/mandates/m1/redemptions?grantor=did%3Aaroha%3Agrantor");
    await expect(store.redeemedMicros("m1")).rejects.toThrow(/mandateRedemptionKey/);
  });
});

describe("registryUrl must be https outside loopback (L10)", () => {
  it("refuses http:// to a remote registry unless allowInsecureHttp", () => {
    expect(() => httpRevocationCheck("http://reg.example")).toThrow(/registryUrl/);
    expect(() => httpRedemptionStore("http://reg.example", "k")).toThrow(/registryUrl/);
    expect(() => httpRevocationCheck("http://127.0.0.1:8787")).not.toThrow();
    expect(() => httpRevocationCheck("http://reg.example", { allowInsecureHttp: true })).not.toThrow();
  });

  it("revokeMandate refuses an http:// remote registry", async () => {
    const priv = ed.utils.randomPrivateKey();
    const did = generateDid(await ed.getPublicKeyAsync(priv));
    const m = await issueIntentMandate(did, "did:aroha:grantee", { spendLimitUsd: 1 }, priv);
    const f = vi.fn();
    await expect(revokeMandate("http://reg.example", m.token, priv, { fetch: f as never })).rejects.toThrow(/registryUrl/);
    expect(f).not.toHaveBeenCalled();
  });
});
