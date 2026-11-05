// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Web identities (spec §4.7): an HTTPS URL that publishes its signing key can
 * be a mandate's grantor, grantee or holder, next to did:aroha identifiers.
 *
 * The shared cases live in test-vectors/web-identity-v1.json so every SDK
 * accepts and refuses the same identifiers and documents. The rest covers
 * what a JSON file cannot: limits, the cache, and mandates end to end.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { generateDid } from "@aroha-sdk/core";
import {
  buildWebIdentityDocument,
  checkWebIdentity,
  createWebIdentityResolver,
  ed25519JwkThumbprint,
  ed25519PublicKeyToJwk,
  isWebIdentity,
  jwkToEd25519PublicKey,
  looksLikeWebIdentity,
  resolveWebIdentity,
  selectWebIdentityKey,
  WEB_IDENTITY_MAX_DOCUMENT_BYTES,
  type WebIdentityResolverOptions,
} from "./web-identity.js";
import {
  attenuateToCart,
  attenuateToPayment,
  createMandateKeyResolver,
  issueIntentMandate,
  issueTaskMandate,
  mandateSigningPayloadV2,
  verifyMandateChain,
  verifyTaskMandate,
} from "./mandate.js";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp, verifyHttpMandateRequest } from "./http-mandate.js";
import { governedVerification } from "./governed.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface VectorResponse { status: number; headers: Record<string, string>; body?: unknown; bodyText?: string }
interface Vectors {
  identifiers: { id: string; valid: boolean; note: string }[];
  loopbackIdentifiers: { id: string; valid: boolean; note: string }[];
  thumbprints: { publicKeyHex: string; x: string; thumbprint: string }[];
  documents: { name: string; identity: string; responses: Record<string, VectorResponse>; expect: { keyHex?: string; kid?: string; error?: true } }[];
}
const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("../test-vectors/web-identity-v1.json", import.meta.url)), "utf8"),
) as Vectors;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** A fetch that answers from a table of URL → response, 404 otherwise, and records every request. */
function tableFetch(responses: Record<string, VectorResponse>) {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ url, init });
    const r = responses[url];
    if (!r) return new Response("not found", { status: 404 });
    const text = r.bodyText ?? JSON.stringify(r.body);
    return new Response(text, { status: r.status, headers: r.headers });
  };
  return { fetch: impl as typeof fetch, calls };
}

interface Party { priv: Uint8Array; pub: Uint8Array }
async function party(): Promise<Party> {
  const priv = ed.utils.randomPrivateKey();
  return { priv, pub: await ed.getPublicKeyAsync(priv) };
}

/** Serve one web identity per entry: URL → the public key it publishes. */
function serve(identities: Record<string, Uint8Array>, headers: Record<string, string> = {}) {
  const responses: Record<string, VectorResponse> = {};
  for (const [identity, publicKey] of Object.entries(identities)) {
    responses[identity] = { status: 200, headers: { "content-type": "application/json", ...headers }, body: buildWebIdentityDocument({ identity, publicKey }) };
  }
  return { ...tableFetch(responses), responses };
}

beforeAll(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

// ─── Shared vectors ───────────────────────────────────────────────────────────

describe("web identity vectors: identifiers", () => {
  for (const c of vectors.identifiers) {
    it(`${c.valid ? "accepts" : "refuses"} ${JSON.stringify(c.id)} (${c.note})`, () => {
      expect(isWebIdentity(c.id)).toBe(c.valid);
      expect(checkWebIdentity(c.id) === null).toBe(c.valid);
    });
  }

  for (const c of vectors.loopbackIdentifiers) {
    it(`with allowLoopbackHttp, ${c.valid ? "accepts" : "refuses"} ${JSON.stringify(c.id)} (${c.note})`, () => {
      expect(isWebIdentity(c.id, { allowLoopbackHttp: true })).toBe(c.valid);
    });
  }

  it("refuses every loopback form unless the development option is set", () => {
    for (const c of vectors.loopbackIdentifiers.filter((v) => v.id.startsWith("http://"))) {
      expect(isWebIdentity(c.id), c.id).toBe(false);
    }
  });

  it("refuses non-strings and over-long strings", () => {
    for (const bad of [undefined, null, 7, {}, ["https://example.com/a"]]) expect(isWebIdentity(bad)).toBe(false);
    expect(isWebIdentity(`https://example.com/${"a".repeat(2048)}`)).toBe(false);
  });

  it("looksLikeWebIdentity claims every http(s) string, valid or not, and nothing else", () => {
    expect(looksLikeWebIdentity("https://Example.com")).toBe(true);
    expect(looksLikeWebIdentity("http://x")).toBe(true);
    expect(looksLikeWebIdentity("did:aroha:zabc")).toBe(false);
    expect(looksLikeWebIdentity(undefined)).toBe(false);
  });
});

describe("web identity vectors: key ids", () => {
  for (const t of vectors.thumbprints) {
    it(`RFC 7638 thumbprint of ${t.publicKeyHex.slice(0, 16)}…`, () => {
      const key = new Uint8Array(Buffer.from(t.publicKeyHex, "hex"));
      expect(ed25519JwkThumbprint(key)).toBe(t.thumbprint);
      expect(ed25519PublicKeyToJwk(key)).toEqual({ kty: "OKP", crv: "Ed25519", x: t.x, kid: t.thumbprint, use: "sig", alg: "EdDSA" });
      expect(hex(jwkToEd25519PublicKey({ kty: "OKP", crv: "Ed25519", x: t.x })!)).toBe(t.publicKeyHex);
    });
  }

  it("refuses a public key that is not 32 bytes", () => {
    expect(() => ed25519JwkThumbprint(new Uint8Array(31))).toThrow(TypeError);
  });

  it("refuses a non-canonical base64url spelling of a key", () => {
    // 43 characters, but the last one sets bits that no 32-byte value has.
    const x = vectors.thumbprints[0].x;
    const last = x[x.length - 1];
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const twin = x.slice(0, -1) + alphabet[alphabet.indexOf(last) + 1];
    expect(Buffer.from(twin, "base64url").equals(Buffer.from(x, "base64url"))).toBe(true);
    expect(jwkToEd25519PublicKey({ kty: "OKP", crv: "Ed25519", x: twin })).toBeNull();
  });
});

describe("web identity vectors: documents", () => {
  for (const c of vectors.documents) {
    it(c.name, async () => {
      const { fetch } = tableFetch(c.responses);
      const r = await resolveWebIdentity(c.identity, { fetch });
      if (c.expect.error) {
        expect(r.ok, r.ok ? "resolved" : r.reason).toBe(false);
        expect(await createWebIdentityResolver({ fetch })(c.identity)).toBeNull();
      } else {
        expect(r.ok, r.ok ? "" : r.reason).toBe(true);
        if (!r.ok) return;
        expect(hex(r.key)).toBe(c.expect.keyHex);
        expect(r.kid).toBe(c.expect.kid);
        expect(hex((await createWebIdentityResolver({ fetch })(c.identity))!)).toBe(c.expect.keyHex);
      }
    });
  }
});

// ─── Requests and limits ──────────────────────────────────────────────────────

describe("web identity resolution: requests and limits", () => {
  const ID = "https://agents.example.com/shopper";

  it("asks for JSON, does not follow redirects, and makes one request per document", async () => {
    const a = await party();
    const { fetch, calls } = serve({ [ID]: a.pub });
    const r = await resolveWebIdentity(ID, { fetch });
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(ID);
    expect(calls[0].init?.redirect).toBe("manual");
    expect(calls[0].init?.method).toBe("GET");
    expect(new Headers(calls[0].init?.headers).get("accept")).toBe("application/json");
  });

  it("makes no request for an identifier that is not a web identity", async () => {
    const { fetch, calls } = tableFetch({});
    for (const bad of ["https://169.254.169.254/latest/meta-data", "https://localhost/a", "http://agents.example.com/a", "https://example.com/a?x=1"]) {
      expect((await resolveWebIdentity(bad, { fetch })).ok, bad).toBe(false);
      expect(await createWebIdentityResolver({ fetch })(bad), bad).toBeNull();
    }
    expect(calls).toHaveLength(0);
  });

  it("returns null without a request for identifiers of other kinds", async () => {
    const { fetch, calls } = tableFetch({});
    const resolve = createWebIdentityResolver({ fetch });
    expect(await resolve("did:aroha:zNotAKey")).toBeNull();
    expect(await resolve("agent-7")).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("refuses a document over the size cap, declared or not", async () => {
    const a = await party();
    const big = { ...buildWebIdentityDocument({ identity: ID, publicKey: a.pub }), pad: "x".repeat(WEB_IDENTITY_MAX_DOCUMENT_BYTES) };
    const text = JSON.stringify(big);
    const declared = async () => new Response(text, { status: 200, headers: { "content-length": String(text.length) } });
    const streamed = async () => new Response(new Blob([text]).stream(), { status: 200 });
    for (const f of [declared, streamed]) {
      const r = await resolveWebIdentity(ID, { fetch: f as unknown as typeof fetch });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/more than 5120 bytes/);
    }
    // The same document is accepted once the verifier raises its cap.
    const r = await resolveWebIdentity(ID, { fetch: streamed as unknown as typeof fetch, maxDocumentBytes: 64 * 1024 });
    expect(r.ok).toBe(true);
  });

  it("caps a jwks_uri response separately", async () => {
    const a = await party();
    const keysUrl = "https://keys.example.com/jwks.json";
    const { fetch } = tableFetch({
      [ID]: { status: 200, headers: {}, body: { client_id: ID, jwks_uri: keysUrl } },
      [keysUrl]: { status: 200, headers: {}, body: { keys: [ed25519PublicKeyToJwk(a.pub)], pad: "x".repeat(4096) } },
    });
    expect((await resolveWebIdentity(ID, { fetch })).ok).toBe(true);
    expect((await resolveWebIdentity(ID, { fetch, maxJwksBytes: 1024 })).ok).toBe(false);
  });

  it("gives up when the host does not answer within the timeout", async () => {
    const hang = (_: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    const r = await resolveWebIdentity(ID, { fetch: hang as typeof fetch, timeoutMs: 20 });
    expect(r.ok).toBe(false);
  });

  it("fails closed when fetch throws or reports a followed redirect", async () => {
    const throws = async () => { throw new Error("network down"); };
    expect((await resolveWebIdentity(ID, { fetch: throws as unknown as typeof fetch })).ok).toBe(false);
    const a = await party();
    const redirected = async () => {
      const res = new Response(JSON.stringify(buildWebIdentityDocument({ identity: ID, publicKey: a.pub })), { status: 200 });
      Object.defineProperty(res, "redirected", { value: true });
      return res;
    };
    expect((await resolveWebIdentity(ID, { fetch: redirected as unknown as typeof fetch })).ok).toBe(false);
  });

  it("asks allowHost about the identity's host and the key set's host before each request", async () => {
    const a = await party();
    const keysUrl = "https://keys.example.net/jwks.json";
    const table = {
      [ID]: { status: 200, headers: {}, body: { client_id: ID, jwks_uri: keysUrl } },
      [keysUrl]: { status: 200, headers: {}, body: { keys: [ed25519PublicKeyToJwk(a.pub)] } },
    };
    const asked: string[] = [];
    const open = tableFetch(table);
    expect((await resolveWebIdentity(ID, { fetch: open.fetch, allowHost: (h) => (asked.push(h), true) })).ok).toBe(true);
    expect(asked).toEqual(["agents.example.com", "keys.example.net"]);

    const noIdentity = tableFetch(table);
    expect((await resolveWebIdentity(ID, { fetch: noIdentity.fetch, allowHost: () => false })).ok).toBe(false);
    expect(noIdentity.calls).toHaveLength(0);

    const noKeys = tableFetch(table);
    expect((await resolveWebIdentity(ID, { fetch: noKeys.fetch, allowHost: (h) => h === "agents.example.com" })).ok).toBe(false);
    expect(noKeys.calls.map((c) => c.url)).toEqual([ID]);
  });

  it("reports why a resolution failed, and a hook that throws changes nothing", async () => {
    const { fetch } = tableFetch({});
    const reasons: string[] = [];
    expect(await createWebIdentityResolver({ fetch, onFailure: (id, why) => reasons.push(`${id}: ${why}`) })(ID)).toBeNull();
    expect(reasons).toEqual([`${ID}: GET ${ID} did not return HTTP 200`]);
    expect(await createWebIdentityResolver({ fetch, onFailure: () => { throw new Error("logger broke"); } })(ID)).toBeNull();
  });
});

// ─── Cache ────────────────────────────────────────────────────────────────────

describe("web identity resolver cache", () => {
  const ID = "https://agents.example.com/shopper";

  async function setup(options: Partial<WebIdentityResolverOptions> = {}, headers: Record<string, string> = {}) {
    const a = await party();
    const b = await party();
    const served = serve({ [ID]: a.pub }, headers);
    let t = 1_000_000;
    const resolve = createWebIdentityResolver({ fetch: served.fetch, now: () => t, ...options });
    const republish = (publicKey: Uint8Array) => { served.responses[ID].body = buildWebIdentityDocument({ identity: ID, publicKey }); };
    return { a, b, served, resolve, republish, advance: (ms: number) => { t += ms; } };
  }

  it("reuses a resolved key for five minutes by default, then asks again", async () => {
    const s = await setup();
    expect(hex((await s.resolve(ID))!)).toBe(hex(s.a.pub));
    s.republish(s.b.pub);
    s.advance(299_999);
    expect(hex((await s.resolve(ID))!)).toBe(hex(s.a.pub));
    expect(s.served.calls).toHaveLength(1);
    s.advance(2);
    expect(hex((await s.resolve(ID))!)).toBe(hex(s.b.pub));
    expect(s.served.calls).toHaveLength(2);
  });

  it("honours a shorter max-age but never a longer one", async () => {
    const short = await setup({}, { "cache-control": "public, max-age=10" });
    await short.resolve(ID);
    short.advance(10_001);
    await short.resolve(ID);
    expect(short.served.calls).toHaveLength(2);

    const long = await setup({ maxCacheMs: 60_000 }, { "cache-control": "max-age=86400" });
    await long.resolve(ID);
    long.advance(60_001);
    await long.resolve(ID);
    expect(long.served.calls).toHaveLength(2);
  });

  it("does not reuse a document marked no-store or no-cache, or when the cache is off", async () => {
    for (const s of [await setup({}, { "cache-control": "no-store" }), await setup({}, { "cache-control": "no-cache" }), await setup({ maxCacheMs: 0 })]) {
      await s.resolve(ID);
      await s.resolve(ID);
      expect(s.served.calls).toHaveLength(2);
    }
  });

  it("never caches a failure", async () => {
    const s = await setup();
    const doc = s.served.responses[ID];
    delete s.served.responses[ID];
    expect(await s.resolve(ID)).toBeNull();
    s.served.responses[ID] = doc;
    expect(hex((await s.resolve(ID))!)).toBe(hex(s.a.pub));
  });

  it("uses the shorter lifetime of the document and its key set", async () => {
    const a = await party();
    const keysUrl = "https://keys.example.com/jwks.json";
    const table = tableFetch({
      [ID]: { status: 200, headers: { "cache-control": "max-age=300" }, body: { client_id: ID, jwks_uri: keysUrl } },
      [keysUrl]: { status: 200, headers: { "cache-control": "max-age=5" }, body: { keys: [ed25519PublicKeyToJwk(a.pub)] } },
    });
    let t = 0;
    const resolve = createWebIdentityResolver({ fetch: table.fetch, now: () => t });
    await resolve(ID);
    t = 5_001;
    await resolve(ID);
    expect(table.calls).toHaveLength(4);
  });
});

// ─── Publishing ───────────────────────────────────────────────────────────────

describe("buildWebIdentityDocument", () => {
  const ID = "https://agents.example.com/shopper";

  it("builds a document that resolves back to the key", async () => {
    const a = await party();
    const doc = buildWebIdentityDocument({ identity: ID, publicKey: a.pub, name: "Shopper", uri: "https://agents.example.com", extra: { token_endpoint_auth_method: "private_key_jwt" } });
    expect(doc).toEqual({
      token_endpoint_auth_method: "private_key_jwt",
      client_id: ID,
      client_name: "Shopper",
      client_uri: "https://agents.example.com",
      jwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: Buffer.from(a.pub).toString("base64url"), kid: ed25519JwkThumbprint(a.pub), use: "sig", alg: "EdDSA" }] },
    });
    const { fetch } = tableFetch({ [ID]: { status: 200, headers: {}, body: doc } });
    const r = await resolveWebIdentity(ID, { fetch });
    expect(r.ok && hex(r.key)).toBe(hex(a.pub));
    expect(JSON.stringify(doc).length).toBeLessThan(WEB_IDENTITY_MAX_DOCUMENT_BYTES);
  });

  it("refuses an invalid identity, a bad key, and extras that would override or leak", async () => {
    const a = await party();
    expect(() => buildWebIdentityDocument({ identity: "https://example.com/", publicKey: a.pub })).toThrow(/path other than/);
    expect(() => buildWebIdentityDocument({ identity: "http://localhost:8787/agent", publicKey: a.pub })).toThrow();
    expect(buildWebIdentityDocument({ identity: "http://localhost:8787/agent", publicKey: a.pub, allowLoopbackHttp: true }).client_id).toBe("http://localhost:8787/agent");
    expect(() => buildWebIdentityDocument({ identity: ID, publicKey: new Uint8Array(16) })).toThrow(TypeError);
    for (const member of ["client_id", "jwks", "jwks_uri", "client_secret", "client_secret_expires_at"]) {
      expect(() => buildWebIdentityDocument({ identity: ID, publicKey: a.pub, extra: { [member]: "x" } }), member).toThrow(/extra must not set/);
    }
  });

  it("selectWebIdentityKey reports why a set has no usable key", () => {
    expect(selectWebIdentityKey(undefined)).toEqual({ ok: false, reason: "key set has no keys array" });
    expect(selectWebIdentityKey({ keys: [] })).toEqual({ ok: false, reason: "key set has no Ed25519 signing key" });
    expect(selectWebIdentityKey({ keys: [{ kty: "oct", k: "c2VjcmV0" }] })).toEqual({ ok: false, reason: "key set contains private key material" });
  });
});

// ─── Mandates end to end ──────────────────────────────────────────────────────

describe("mandates between web identities", () => {
  const HUMAN = "https://accounts.example.com/people/kiri";
  const ASSISTANT = "https://agents.example.com/assistant";
  const SHOP = "https://shop.example.net/agents/checkout";

  it("verifies a three-link spending chain whose parties are all web identities", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const { fetch, calls } = serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub, [SHOP]: shop.pub });

    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 200, currency: "USD" }, human.priv);
    const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 80, currency: "USD" }, assistant.priv);
    const payment = await attenuateToPayment(cart, SHOP, { spendLimitUsd: 42.5, currency: "USD" }, shop.priv);

    const resolveKey = createMandateKeyResolver({ web: { fetch } });
    const r = await verifyMandateChain(payment.token, resolveKey, { expectedRoot: HUMAN, expectedGrantee: SHOP, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(r.chainVerified).toBe(true);
    expect(r.rootGrantor).toBe(HUMAN);
    expect(r.chain?.map((m) => m.grantor)).toEqual([HUMAN, ASSISTANT, SHOP]);
    // One request per distinct signer, however often it signs.
    expect(calls.map((c) => c.url).sort()).toEqual([ASSISTANT, HUMAN, SHOP].sort());

    // The same resolver answers the second verification from its cache.
    await verifyMandateChain(payment.token, resolveKey, { expectedRoot: HUMAN, isRevoked: null });
    expect(calls).toHaveLength(3);
  });

  it("verifies a chain that mixes did:aroha and web identities", async () => {
    const human = await party(), assistant = await party(), worker = await party();
    const humanDid = generateDid(human.pub);
    const workerDid = generateDid(worker.pub);
    const { fetch } = serve({ [ASSISTANT]: assistant.pub });

    const intent = await issueIntentMandate(humanDid, ASSISTANT, { spendLimitUsd: 100, currency: "USD" }, human.priv);
    const cart = await attenuateToCart(intent, workerDid, { spendLimitUsd: 60, currency: "USD" }, assistant.priv);

    const r = await verifyMandateChain(cart.token, createMandateKeyResolver({ web: { fetch } }), { expectedRoot: humanDid, expectedGrantee: workerDid, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(r.chain?.map((m) => m.grantor)).toEqual([humanDid, ASSISTANT]);
  });

  it("is off by default: a verifier that did not opt in makes no request and refuses the chain", async () => {
    const human = await party(), assistant = await party();
    const { fetch, calls } = serve({ [HUMAN]: human.pub });
    const original = globalThis.fetch;
    globalThis.fetch = fetch;
    try {
      const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 50, currency: "USD" }, human.priv);
      for (const resolveKey of [undefined, createMandateKeyResolver(), createMandateKeyResolver({ web: false })]) {
        const r = await verifyMandateChain(intent.token, resolveKey, { isRevoked: null });
        expect(r.valid).toBe(false);
      }
      expect(calls).toHaveLength(0);
      void assistant;
    } finally {
      globalThis.fetch = original;
    }
  });

  it("sends web identities to the fallback only when web resolution is off", async () => {
    const human = await party(), assistant = await party();
    const { fetch } = serve({ [HUMAN]: assistant.pub }); // the URL publishes a DIFFERENT key
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 50, currency: "USD" }, human.priv);
    const seen: string[] = [];
    const fallback = async (id: string) => { seen.push(id); return human.pub; };

    // Pinned by the verifier: the fallback answers, and the chain verifies.
    const pinned = await verifyMandateChain(intent.token, createMandateKeyResolver({ fallback }), { isRevoked: null });
    expect(pinned.valid, pinned.reason).toBe(true);
    expect(seen).toEqual([HUMAN]);

    // With web resolution on, HTTPS is the only source for an https name.
    const web = await verifyMandateChain(intent.token, createMandateKeyResolver({ web: { fetch }, fallback }), { isRevoked: null });
    expect(web.valid).toBe(false);
    expect(seen).toEqual([HUMAN]);
  });

  it("refuses a mandate signed by a key the identity does not publish", async () => {
    const human = await party(), assistant = await party(), thief = await party();
    const { fetch } = serve({ [HUMAN]: human.pub });
    const forged = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 5000, currency: "USD" }, thief.priv);
    const r = await verifyMandateChain(forged.token, createMandateKeyResolver({ web: { fetch } }), { isRevoked: null });
    expect(r.valid).toBe(false);
    void assistant;
  });

  it("stops honouring a mandate once the identity publishes a different key", async () => {
    const human = await party(), assistant = await party(), next = await party();
    const served = serve({ [HUMAN]: human.pub });
    let t = 0;
    const resolveKey = createMandateKeyResolver({ web: { fetch: served.fetch, now: () => t } });
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 50, currency: "USD" }, human.priv);
    expect((await verifyMandateChain(intent.token, resolveKey, { isRevoked: null })).valid).toBe(true);

    served.responses[HUMAN].body = buildWebIdentityDocument({ identity: HUMAN, publicKey: next.pub });
    t = 300_001; // past the cache lifetime
    expect((await verifyMandateChain(intent.token, resolveKey, { isRevoked: null })).valid).toBe(false);
    void assistant;
  });

  it("refuses a chain when an intermediate identity cannot be fetched", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const { fetch } = serve({ [HUMAN]: human.pub }); // ASSISTANT publishes nothing
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 200, currency: "USD" }, human.priv);
    const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 80, currency: "USD" }, assistant.priv);
    const r = await verifyMandateChain(cart.token, createMandateKeyResolver({ web: { fetch } }), { isRevoked: null });
    expect(r.valid).toBe(false);
    void shop;
  });

  it("still refuses a child that widens its parent, whatever names the parties use", async () => {
    const human = await party(), assistant = await party();
    const { fetch } = serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub });
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 50, currency: "USD" }, human.priv);
    await expect(attenuateToCart(intent, SHOP, { spendLimitUsd: 500, currency: "USD" }, assistant.priv)).rejects.toThrow();
    void fetch;
  });

  it("cannot be a governed root: the governed profile still requires a did:aroha:E person", async () => {
    const human = await party();
    const { fetch } = serve({ [HUMAN]: human.pub });
    const resolveKey = createMandateKeyResolver({ web: { fetch } });
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 50, currency: "USD" }, human.priv);
    // The same token verifies under the standard profile…
    expect((await verifyMandateChain(intent.token, resolveKey, { expectedRoot: HUMAN, isRevoked: null })).valid).toBe(true);
    // …and is refused under the governed one, even with the root pinned to it.
    const profile = governedVerification({ kelSource: async () => null, isRevoked: async () => false, expectedRoot: HUMAN });
    const governed = await verifyMandateChain(intent.token, resolveKey, profile);
    expect(governed.valid).toBe(false);
    const personRoot = await verifyMandateChain(intent.token, resolveKey, { requirePersonRoot: true, kelSource: async () => null, isRevoked: null });
    expect(personRoot.valid).toBe(false);
  });

  it("verifies a task mandate issued by a web identity", async () => {
    const human = await party();
    const { fetch } = serve({ [HUMAN]: human.pub });
    const signed = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read", "inbox.archive"], { actionLimits: { "inbox.archive": 20 } }, human.priv);
    const key = await createWebIdentityResolver({ fetch })(signed.mandate.grantor);
    expect(key).not.toBeNull();
    const r = await verifyTaskMandate(signed.token, key!, ASSISTANT);
    expect(r.valid, r.reason).toBe(true);
    expect((await verifyTaskMandate(signed.token, key!, "https://agents.example.com/someone-else")).valid).toBe(false);
  });

  it("binds an HTTP presentation to a web-identity holder", async () => {
    const human = await party(), assistant = await party(), other = await party();
    const { fetch } = serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub });
    const resolveKey = createMandateKeyResolver({ web: { fetch } });
    const token = (await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 100, currency: "USD" }, human.priv, 600_000)).token;
    const request = { audience: "https://api.example.com", method: "POST", url: "https://api.example.com/v1/orders", body: '{"item":"widget"}' };
    const verify = (header: string) =>
      verifyHttpMandateRequest(header, {
        ...request, url: "/v1/orders", nonces: new InMemoryHttpPresentationNonces(),
        resolvePublicKey: resolveKey, resolveKey, expectedRoot: HUMAN, isRevoked: null,
      });

    const good = await presentMandateHttp({ token, holderDid: ASSISTANT, holderPrivateKey: assistant.priv, ...request });
    const ok = await verify(good[HTTP_MANDATE_HEADER]);
    expect(ok.ok, ok.ok ? "" : ok.reason).toBe(true);

    // The token alone is not enough: a presenter without the holder's key is refused.
    const stolen = await presentMandateHttp({ token, holderDid: ASSISTANT, holderPrivateKey: other.priv, ...request });
    expect((await verify(stolen[HTTP_MANDATE_HEADER])).ok).toBe(false);
  });
});

// ─── Interoperability ─────────────────────────────────────────────────────────

describe("published keys work with a stock JWK implementation", () => {
  it("node:crypto imports the published JWK and verifies a mandate signature with it", async () => {
    const human = await party();
    const signed = await issueIntentMandate("https://accounts.example.com/people/kiri", "https://agents.example.com/assistant", { spendLimitUsd: 25, currency: "USD" }, human.priv);
    const doc = buildWebIdentityDocument({ identity: "https://accounts.example.com/people/kiri", publicKey: human.pub });
    const jwk = doc.jwks!.keys[0] as { kty: string; crv: string; x: string };
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: "jwk" });
    const signedBytes = Buffer.from(mandateSigningPayloadV2(signed.mandate), "utf8");
    expect(nodeVerify(null, signedBytes, key, Buffer.from(signed.signature, "base64url"))).toBe(true);
    expect(nodeVerify(null, Buffer.from(signedBytes.toString("utf8").replace("25", "2500")), key, Buffer.from(signed.signature, "base64url"))).toBe(false);
  });
});
