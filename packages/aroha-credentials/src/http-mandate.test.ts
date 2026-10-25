// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The HTTP holder proof: a mandate presented to a REST endpoint is bound to
 * the server, the method, the path and query, the body bytes and a single-use
 * nonce, and the token alone is never accepted.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  HTTP_MANDATE_HEADER,
  InMemoryHttpPresentationNonces,
  httpRequestTarget,
  httpBodySha256,
  presentMandateHttp,
  verifyHttpMandateRequest,
  verifyHttpPresentation,
  type HttpPresentationNonceStore,
} from "./http-mandate.js";
import { attenuateToCart, issueIntentMandate } from "./mandate.js";
import { issueTaskMandate } from "./mandate.js";

const AUD = "https://api.example.com";
const URL_ = "https://api.example.com/v1/orders?limit=5";
const BODY = '{"item":"widget","qty":2}';

interface Key { priv: Uint8Array; pub: Uint8Array; did: string }
async function key(): Promise<Key> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

let human: Key, agent: Key, other: Key;
let token: string;

beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  human = await key();
  agent = await key();
  other = await key();
  token = (await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100, currency: "USD" }, human.priv, 600_000)).token;
});

async function present(over: Partial<Parameters<typeof presentMandateHttp>[0]> = {}): Promise<string> {
  const h = await presentMandateHttp({
    token, holderDid: agent.did, holderPrivateKey: agent.priv, audience: AUD, method: "POST", url: URL_, body: BODY, ...over,
  });
  return h[HTTP_MANDATE_HEADER];
}

const ctx = (over: Record<string, unknown> = {}) => ({
  audience: AUD, method: "POST", url: "/v1/orders?limit=5", body: BODY, nonces: new InMemoryHttpPresentationNonces(), ...over,
});

describe("httpRequestTarget", () => {
  it("keeps path and query exactly, drops scheme, authority and fragment", () => {
    expect(httpRequestTarget("https://api.example.com/v1/pay?x=1&y=%2F#frag")).toBe("/v1/pay?x=1&y=%2F");
    expect(httpRequestTarget("https://api.example.com")).toBe("/");
    expect(httpRequestTarget("https://api.example.com?x=1")).toBe("/?x=1");
    expect(httpRequestTarget("HTTP://h:8080/a")).toBe("/a");
    expect(httpRequestTarget("/a/b?c")).toBe("/a/b?c");
    expect(httpRequestTarget("/a/%7E")).toBe("/a/%7E"); // no decoding
  });

  it("refuses targets a client or proxy would rewrite", () => {
    for (const bad of ["", "ftp://h/a", "//h/a", "a/b", "https://h/a b", "https://h/café", "https://h/a/../b",
      "https://h/a/./b", "/a/%2e%2E/b", "https://h/%zz", "https://user@h/a", "https:///a", "https://h/a\\b"]) {
      expect(() => httpRequestTarget(bad), bad).toThrow();
    }
  });
});

describe("presentMandateHttp / verifyHttpPresentation", () => {
  it("round-trips: origin-form on the server matches the absolute URL the client signed", async () => {
    const r = await verifyHttpPresentation(await present(), ctx());
    expect(r).toMatchObject({ ok: true, holder: agent.did, token });
  });

  it("accepts a Uint8Array body equal to the signed string, and an empty body as SHA-256('')", async () => {
    expect((await verifyHttpPresentation(await present(), ctx({ body: new TextEncoder().encode(BODY) }))).ok).toBe(true);
    const h = await present({ method: "get", body: undefined });
    expect((await verifyHttpPresentation(h, ctx({ method: "GET", body: "" }))).ok).toBe(true);
    expect(httpBodySha256(null)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("the token alone is never accepted", async () => {
    expect(await verifyHttpPresentation(undefined, ctx())).toMatchObject({ ok: false, code: "MISSING" });
    expect(await verifyHttpPresentation(token, ctx())).toMatchObject({ ok: false, code: "MALFORMED" });
  });

  it.each([
    ["another server", { audience: "https://evil.example.com" }],
    ["another method", { method: "PUT" }],
    ["another path", { url: "/v1/orders/1?limit=5" }],
    ["another query", { url: "/v1/orders?limit=500" }],
    ["another body", { body: '{"item":"widget","qty":200}' }],
    ["re-serialised body", { body: '{"item": "widget", "qty": 2}' }],
  ])("refuses the proof for %s", async (_n, over) => {
    expect(await verifyHttpPresentation(await present(), ctx(over))).toMatchObject({ ok: false, code: "BAD_PROOF" });
  });

  it("refuses a replayed nonce, and does not burn a nonce on a failed request", async () => {
    const nonces = new InMemoryHttpPresentationNonces();
    const h = await present();
    expect((await verifyHttpPresentation(h, ctx({ nonces, method: "PUT" }))).ok).toBe(false);
    expect((await verifyHttpPresentation(h, ctx({ nonces }))).ok).toBe(true);
    expect(await verifyHttpPresentation(h, ctx({ nonces }))).toMatchObject({ ok: false, code: "REPLAYED" });
  });

  it("refuses expired and over-long presentations", async () => {
    const h = await present({ ttlMs: 1000 });
    expect(await verifyHttpPresentation(h, ctx({ now: Date.now() + 5000 }))).toMatchObject({ ok: false, code: "EXPIRED" });
    // A presenter's ttl is capped at 5 min; a verifier whose clock is far behind sees too long a lifetime.
    const capped = await present({ ttlMs: 3_600_000 });
    expect((await verifyHttpPresentation(capped, ctx())).ok).toBe(true);
    expect(await verifyHttpPresentation(capped, ctx({ now: Date.now() - 60_000 }))).toMatchObject({ ok: false, code: "LIFETIME_TOO_LONG" });
  });

  it("refuses a holder that is not the mandate's grantee", async () => {
    await expect(present({ holderDid: other.did, holderPrivateKey: other.priv })).rejects.toThrow(/grantee/);
    // Hand-built: other signs a valid proof for agent's token.
    const json = JSON.parse(Buffer.from(await present(), "base64url").toString("utf8"));
    json.holder = other.did;
    const forged = Buffer.from(JSON.stringify(json)).toString("base64url");
    expect(await verifyHttpPresentation(forged, ctx())).toMatchObject({ ok: false, code: "HOLDER_NOT_GRANTEE" });
  });

  it("refuses a proof by a key other than the holder's", async () => {
    const json = JSON.parse(Buffer.from(await present({ holderPrivateKey: other.priv }), "base64url").toString("utf8"));
    expect(json.holder).toBe(agent.did);
    expect(await verifyHttpPresentation(Buffer.from(JSON.stringify(json)).toString("base64url"), ctx()))
      .toMatchObject({ ok: false, code: "BAD_PROOF" });
  });

  it("fails closed on malformed input", async () => {
    const good = JSON.parse(Buffer.from(await present(), "base64url").toString("utf8"));
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const cases: [unknown, string][] = [
      [["a", "b"], "MALFORMED"],
      ["not base64url!", "MALFORMED"],
      [enc([1]), "MALFORMED"],
      [enc("x"), "MALFORMED"],
      [enc({ ...good, extra: "x" }), "MALFORMED"],
      [enc({ ...good, nonce: 5 }), "MALFORMED"],
      [enc({ ...good, nonce: "short" }), "MALFORMED"],
      [enc({ ...good, expires: "2099-01-01" }), "MALFORMED"],
      [enc({ ...good, expires: "2026-02-30T00:00:00.000Z" }), "MALFORMED"],
      [enc({ ...good, token: "%%%" }), "MALFORMED_TOKEN"],
      [enc({ ...good, token: Buffer.from("{}").toString("base64url") }), "MALFORMED_TOKEN"],
      [enc({ ...good, proof: "AAAA" }), "BAD_PROOF"],
      ["A".repeat(40_000), "MALFORMED"],
    ];
    for (const [h, code] of cases) {
      expect(await verifyHttpPresentation(h as string, ctx()), String(h).slice(0, 40)).toMatchObject({ ok: false, code });
    }
  });

  it("refuses an unresolvable holder and a resolver that throws", async () => {
    const h = await present();
    expect(await verifyHttpPresentation(h, ctx({ resolvePublicKey: async () => null }))).toMatchObject({ ok: false, code: "UNKNOWN_HOLDER" });
    expect(await verifyHttpPresentation(h, ctx({ resolvePublicKey: async () => { throw new Error("down"); } })))
      .toMatchObject({ ok: false, code: "UNKNOWN_HOLDER" });
  });

  it("treats a failing nonce store as a refusal and accepts an async store", async () => {
    const h = await present();
    const broken: HttpPresentationNonceStore = { claim: async () => { throw new Error("redis down"); } };
    expect(await verifyHttpPresentation(h, ctx({ nonces: broken }))).toMatchObject({ ok: false, code: "NONCE_STORE_UNAVAILABLE" });
    const seen = new Set<string>();
    const asyncStore: HttpPresentationNonceStore = { claim: async (k) => (seen.has(k) ? false : (seen.add(k), true)) };
    expect((await verifyHttpPresentation(h, ctx({ nonces: asyncStore }))).ok).toBe(true);
    expect(await verifyHttpPresentation(h, ctx({ nonces: asyncStore }))).toMatchObject({ code: "REPLAYED" });
  });

  it("refuses a server URL it cannot normalise", async () => {
    expect(await verifyHttpPresentation(await present(), ctx({ url: "/v1/a b" }))).toMatchObject({ ok: false, code: "BAD_REQUEST" });
  });

  it("the in-memory store refuses when full rather than forgetting", () => {
    const s = new InMemoryHttpPresentationNonces({ maxEntries: 2 });
    expect(s.claim("a", 2000, 1000)).toBe(true);
    expect(s.claim("b", 2000, 1000)).toBe(true);
    expect(s.claim("c", 2000, 1000)).toBe(false);
    expect(s.claim("c", 4000, 3000)).toBe(true); // a and b expired and were pruned
  });

  it("refuses to sign a URL the HTTP client would rewrite, or a bad ttl", async () => {
    await expect(present({ url: "https://api.example.com/a/../b" })).rejects.toThrow();
    await expect(present({ url: "https://API.example.com:443/v1/orders?q='x'" })).rejects.toThrow(/would send/);
    await expect(present({ ttlMs: 0 })).rejects.toThrow(/ttlMs/);
  });
});

describe("verifyHttpMandateRequest", () => {
  const opts = (over: Record<string, unknown> = {}) => ({ ...ctx(), expectedRoot: human.did, isRevoked: null, ...over });

  it("verifies presentation and chain, returning the mandate", async () => {
    const r = await verifyHttpMandateRequest(await present(), opts());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.holder).toBe(agent.did);
      expect(r.mandate.constraints.spendLimitUsd).toBe(100);
      expect(r.rootGrantor).toBe(human.did);
    }
  });

  it("requires a pinned root and an explicit revocation decision", async () => {
    const h = await present();
    await expect(verifyHttpMandateRequest(h, { ...ctx(), isRevoked: null } as never)).rejects.toThrow(/pin the root/);
    await expect(verifyHttpMandateRequest(h, { ...ctx(), expectedRoot: 42, isRevoked: null } as never)).rejects.toThrow(/expectedRoot/);
    await expect(verifyHttpMandateRequest(h, { ...ctx(), trustedRoots: "did:x", isRevoked: null } as never)).rejects.toThrow(/trustedRoots/);
    await expect(verifyHttpMandateRequest(h, { ...ctx(), trustedRoots: [human.did, ""], isRevoked: null } as never)).rejects.toThrow(/trustedRoots/);
    await expect(verifyHttpMandateRequest(h, { ...ctx(), expectedRoot: human.did } as never)).rejects.toThrow(/isRevoked/);
    await expect(verifyHttpMandateRequest(h, { ...ctx(), expectedRoot: undefined } as never)).rejects.toThrow(/isRevoked/);
  });

  it.each([
    ["expectedRoot undefined", { expectedRoot: undefined }],
    ["expectedRoot null", { expectedRoot: null }],
    ["expectedRoot empty", { expectedRoot: "" }],
    ["trustedRoots undefined", { expectedRoot: undefined, trustedRoots: undefined }],
    ["trustedRoots null", { trustedRoots: null, expectedRoot: undefined }],
    ["trustedRoots empty", { trustedRoots: [], expectedRoot: null }],
  ])("a supplied but empty pin (%s) refuses with ROOT_NOT_PINNED, without consuming the nonce", async (_n, over) => {
    const nonces = new InMemoryHttpPresentationNonces();
    const h = await present();
    expect(await verifyHttpMandateRequest(h, opts({ nonces, ...over }))).toMatchObject({ ok: false, code: "ROOT_NOT_PINNED", status: 403 });
    expect(nonces.size).toBe(0);
    // The same header still works once the root is known.
    expect((await verifyHttpMandateRequest(h, opts({ nonces }))).ok).toBe(true);
  });

  it("an empty pin is ignored when the other pin is set, and a bad presentation still reads 401", async () => {
    expect((await verifyHttpMandateRequest(await present(), opts({ expectedRoot: undefined, trustedRoots: [human.did] }))).ok).toBe(true);
    expect((await verifyHttpMandateRequest(await present(), opts({ expectedRoot: human.did, trustedRoots: [] }))).ok).toBe(true);
    expect(await verifyHttpMandateRequest(undefined, opts({ expectedRoot: undefined }))).toMatchObject({ ok: false, code: "MISSING", status: 401 });
  });

  it("one injected clock governs mandate expiry too (no sleeping)", async () => {
    const t0 = Date.now();
    const short = (await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv, 60_000)).token;
    const at = async (now: number) => verifyHttpMandateRequest(await present({ token: short, now }), opts({ now }));
    expect((await at(t0 + 30_000)).ok).toBe(true);
    const late = await at(t0 + 120_000); // the presentation is fresh at this clock; the mandate is not
    expect(late).toMatchObject({ ok: false, code: "MANDATE_INVALID", status: 403 });
    expect(late.ok === false && late.reason).toMatch(/expired/i);
    // Presentation expiry runs on the same clock: a header made at t0 is stale at t0 + 2 min.
    expect(await verifyHttpMandateRequest(await present({ token: short, now: t0 }), opts({ now: t0 + 120_000 })))
      .toMatchObject({ ok: false, code: "EXPIRED", status: 401 });
  });

  it("refuses a chain rooted somewhere else, and does not consume the nonce", async () => {
    const nonces = new InMemoryHttpPresentationNonces();
    const h = await present();
    const r = await verifyHttpMandateRequest(h, opts({ nonces, expectedRoot: other.did }));
    expect(r).toMatchObject({ ok: false, code: "MANDATE_INVALID", status: 403 });
    expect(nonces.size).toBe(0);
    expect((await verifyHttpMandateRequest(h, opts({ nonces, trustedRoots: [other.did, human.did], expectedRoot: undefined }))).ok).toBe(true);
  });

  it("refuses a revoked mandate and a failing revocation hook", async () => {
    expect(await verifyHttpMandateRequest(await present(), opts({ isRevoked: async () => true }))).toMatchObject({ ok: false, code: "MANDATE_INVALID" });
    expect(await verifyHttpMandateRequest(await present(), opts({ isRevoked: async () => { throw new Error("x"); } })))
      .toMatchObject({ ok: false, code: "MANDATE_INVALID" });
  });

  it("verifies an attenuated chain presented by the leaf grantee", async () => {
    const intent = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 100 }, human.priv, 600_000);
    const cart = await attenuateToCart(intent, other.did, { spendLimitUsd: 10 }, agent.priv);
    const h = (await presentMandateHttp({ token: cart.token, holderDid: other.did, holderPrivateKey: other.priv, audience: AUD, method: "POST", url: URL_, body: BODY }))[HTTP_MANDATE_HEADER];
    const r = await verifyHttpMandateRequest(h, opts());
    expect(r.ok && r.mandate.mandateTier).toBe("cart");
  });

  it("presentation failures map to 401", async () => {
    expect(await verifyHttpMandateRequest(undefined, opts())).toMatchObject({ ok: false, code: "MISSING", status: 401 });
  });

  it("a task mandate is not accepted as a spending mandate", async () => {
    const task = await issueTaskMandate(human.did, agent.did, ["orders.create"], { maxCalls: 1 } as never, human.priv, 600_000);
    const h = await present({ token: task.token });
    expect((await verifyHttpPresentation(h, ctx())).ok).toBe(true); // the presentation itself is type-agnostic
    expect(await verifyHttpMandateRequest(await present({ token: task.token }), opts())).toMatchObject({ ok: false, code: "MANDATE_INVALID" });
  });
});
