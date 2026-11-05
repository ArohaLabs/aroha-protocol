// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The JWT form of a mandate (spec §6.10): the same mandate and the same
 * chain rules, written so a stock JWT library can read and verify each link.
 *
 * The shared cases are in test-vectors/mandate-jwt-v1.json so every SDK
 * decodes the same JWTs to the same bodies and reaches the same verdicts.
 * The rest covers issuing, the things a JSON file cannot (a stock library,
 * revocation, HTTP presentation, web identities) and the checks that keep a
 * JWT of another kind from being read as a mandate.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { createLocalJWKSet, jwtVerify, importJWK } from "jose";
import { generateDid } from "@aroha-sdk/core";
import {
  MANDATE_JWT_TYP,
  decodeMandateJwt,
  jwtClaimsToMandateBody,
  looksLikeMandateJwt,
  mandateBodyToJwtClaims,
  mandateJwtInstant,
  peekMandateToken,
  signMandateJwt,
  verifyMandateJwtSignature,
} from "./mandate-jwt.js";
import {
  attenuateTaskMandate,
  attenuateToCart,
  attenuateToPayment,
  createMandateKeyResolver,
  decodeMandateToken,
  decodeTaskMandateToken,
  enforceSpendingConstraints,
  enforceTaskConstraints,
  issueIntentMandate,
  issueTaskMandate,
  verifyMandate,
  verifyMandateChain,
  verifyTaskMandate,
  TaskConstraintViolation,
} from "./mandate.js";
import { buildWebIdentityDocument, ed25519JwkThumbprint, ed25519PublicKeyToJwk } from "./web-identity.js";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp, verifyHttpMandateRequest } from "./http-mandate.js";
import { InMemoryRedemptionStore, redeemPaymentMandate } from "./redemption.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface Vectors {
  typ: string;
  nowMs: number;
  keys: Record<string, { seedHex: string; publicKeyHex: string; did: string; kid: string }>;
  links: { name: string; kind: "spending" | "task"; signer: string; body: Record<string, unknown>; header: Record<string, unknown>; claims: Record<string, unknown>; jwt: string }[];
  tokens: { name: string; kind: "spending" | "task"; token: string; signer?: string; expect: { valid: boolean; mandateId?: string; rootGrantor?: string; links?: number } }[];
}
const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../test-vectors/mandate-jwt-v1.json", import.meta.url)), "utf8")) as Vectors;

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (v: Uint8Array | string) => Buffer.from(v).toString("base64url");
const segment = (jwt: string, i: number) => JSON.parse(Buffer.from(jwt.split(".")[i], "base64url").toString("utf8")) as Record<string, unknown>;

interface Party { priv: Uint8Array; pub: Uint8Array; did: string }
async function party(): Promise<Party> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

beforeAll(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

// ─── Shared vectors ───────────────────────────────────────────────────────────

describe("mandate JWT vectors: links", () => {
  it("uses the typ the vectors name", () => {
    expect(MANDATE_JWT_TYP).toBe(vectors.typ);
  });

  for (const link of vectors.links) {
    it(`${link.name}: the JWT decodes to the body, and the body encodes to the claims`, async () => {
      const decoded = decodeMandateJwt(link.jwt);
      expect(typeof decoded, String(decoded)).toBe("object");
      if (typeof decoded === "string") return;
      expect(decoded.kind).toBe(link.kind);
      expect(decoded.body).toEqual(link.body);
      expect(decoded.header).toEqual(link.header);
      expect(segment(link.jwt, 1)).toEqual(link.claims);
      expect(mandateBodyToJwtClaims(link.kind, link.body)).toEqual(link.claims);
      expect(jwtClaimsToMandateBody(link.claims)).toEqual({ kind: link.kind, body: link.body });

      const signer = fromHex(vectors.keys[link.signer].publicKeyHex);
      expect(await verifyMandateJwtSignature(link.jwt, signer)).toBe(true);
      for (const [name, k] of Object.entries(vectors.keys)) {
        if (name !== link.signer) expect(await verifyMandateJwtSignature(link.jwt, fromHex(k.publicKeyHex)), name).toBe(false);
      }
    });

    it(`${link.name}: signing the body again gives the same JWT`, async () => {
      const key = vectors.keys[link.signer];
      expect(await signMandateJwt(link.kind, link.body, fromHex(key.seedHex), key.kid)).toBe(link.jwt);
    });
  }
});

describe("mandate JWT vectors: tokens", () => {
  for (const c of vectors.tokens) {
    it(`${c.expect.valid ? "accepts" : "refuses"}: ${c.name}`, async () => {
      if (c.kind === "spending") {
        const r = await verifyMandateChain(c.token, undefined, { now: vectors.nowMs, isRevoked: null });
        expect(r.valid, r.reason).toBe(c.expect.valid);
        if (!c.expect.valid) return;
        expect(r.chainVerified).toBe(true);
        expect(r.mandate?.mandateId).toBe(c.expect.mandateId);
        expect(r.rootGrantor).toBe(c.expect.rootGrantor);
        expect(r.chain).toHaveLength(c.expect.links!);
      } else {
        const r = await verifyTaskMandate(c.token, fromHex(vectors.keys[c.signer!].publicKeyHex), undefined, { now: vectors.nowMs });
        expect(r.valid, r.reason).toBe(c.expect.valid);
        if (c.expect.valid) expect(r.mandate?.mandateId).toBe(c.expect.mandateId);
      }
    });
  }

  it("a refused token is refused without throwing, whatever it is", async () => {
    for (const bad of ["a.b.c", "..", "~", ".~.", "a.b.c~d.e.f", `${"x".repeat(20_000)}.y.z`, Array.from({ length: 80 }, () => "a.b.c").join("~")]) {
      expect((await verifyMandateChain(bad, undefined, { isRevoked: null })).valid, bad.slice(0, 20)).toBe(false);
      expect((await verifyTaskMandate(bad, new Uint8Array(32))).valid, bad.slice(0, 20)).toBe(false);
      expect(() => decodeMandateToken(bad)).toThrow();
    }
  });
});

// ─── Issuing ──────────────────────────────────────────────────────────────────

describe("issuing spending mandates in the JWT form", () => {
  it("issues, attenuates and verifies a chain of JWTs", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500, merchantCategory: "4511" }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300, merchantCategory: "4511" }, assistant.priv);
    const payment = await attenuateToPayment(cart, shop.did, { spendLimitUsd: 249.99, merchantCategory: "4511" }, shop.priv, 60_000);

    // A root is one plain JWT; a chain is its links joined by "~", root first.
    expect(intent.token).toBe(intent.jwt);
    expect(intent.token.split(".")).toHaveLength(3);
    expect(cart.token).toBe(`${intent.jwt}~${cart.jwt}`);
    expect(payment.token).toBe(`${intent.jwt}~${cart.jwt}~${payment.jwt}`);
    expect(payment.chain?.map((l) => l.jwt)).toEqual([intent.jwt, cart.jwt]);

    const header = segment(intent.jwt!, 0);
    expect(header).toEqual({ alg: "EdDSA", typ: MANDATE_JWT_TYP, kid: ed25519JwkThumbprint(human.pub) });
    const claims = segment(cart.jwt!, 1);
    expect(claims).toMatchObject({ iss: assistant.did, sub: shop.did, jti: cart.mandate.mandateId });
    expect(Object.keys(claims).sort()).toEqual(["authorization_details", "exp", "iat", "iss", "jti", "sub"]);
    expect(claims.authorization_details).toEqual([{ type: "https://aroha-labs.com/mandates/spending", mandateTier: "cart", constraints: { spendLimitUsd: 300, merchantCategory: "4511" }, parentMandateId: intent.mandate.mandateId }]);

    const r = await verifyMandateChain(payment.token, undefined, { expectedRoot: human.did, expectedGrantee: shop.did, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(r.chainVerified).toBe(true);
    expect(r.mandate?.constraints.spendLimitUsd).toBe(249.99);
    expect(r.chain?.map((m) => m.mandateTier)).toEqual(["intent", "cart", "payment"]);
  });

  it("writes whole-second times, and a child never outlives its parent", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    for (let i = 0; i < 5; i++) {
      const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv, 90_500, { format: "jwt" });
      const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 50 }, assistant.priv);
      for (const m of [intent.mandate, cart.mandate]) {
        expect(Date.parse(m.issuedAt) % 1000).toBe(0);
        expect(Date.parse(m.expiresAt) % 1000).toBe(0);
      }
      expect(Date.parse(cart.mandate.expiresAt)).toBeLessThanOrEqual(Date.parse(intent.mandate.expiresAt));
      expect((await verifyMandateChain(cart.token, undefined, { isRevoked: null })).valid).toBe(true);
    }
    expect(mandateJwtInstant(1_700_000_000_999)).toBe(1_700_000_000_000);
  });

  it("the default stays the native token, and a chain keeps the form of its root", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const native = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv);
    expect(looksLikeMandateJwt(native.token)).toBe(false);
    expect(native.jwt).toBeUndefined();
    const nativeChild = await attenuateToCart(native, shop.did, { spendLimitUsd: 50 }, assistant.priv);
    expect(looksLikeMandateJwt(nativeChild.token)).toBe(false);

    const jwt = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv, 3_600_000, { format: "jwt" });
    const jwtChild = await attenuateToCart(jwt, shop.did, { spendLimitUsd: 50 }, assistant.priv);
    expect(looksLikeMandateJwt(jwtChild.token)).toBe(true);
    await expect(issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 1 }, human.priv, 1000, { format: "cbor" as never })).rejects.toThrow(/format/);
  });

  it("a received token can be decoded and attenuated further", async () => {
    const human = await party(), assistant = await party(), shop = await party(), processor = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);

    const received = decodeMandateToken(cart.token);
    expect(received.jwt).toBe(cart.jwt);
    expect(received.mandate).toEqual(cart.mandate);
    expect(received.chain?.map((l) => l.jwt)).toEqual([intent.jwt]);
    const payment = await attenuateToPayment(received, processor.did, { spendLimitUsd: 200 }, shop.priv);
    expect((await verifyMandateChain(payment.token, undefined, { expectedRoot: human.did, isRevoked: null })).valid).toBe(true);

    // A parent handed over as { mandate, signature, token } alone still works…
    const bare = { mandate: cart.mandate, signature: cart.signature, token: cart.token };
    expect(looksLikeMandateJwt((await attenuateToPayment(bare, processor.did, { spendLimitUsd: 100 }, shop.priv)).token)).toBe(true);
    // …and one whose ancestors lost their JWTs is refused, not silently re-rooted.
    const broken = { ...cart, chain: cart.chain!.map(({ jwt: _jwt, ...link }) => link) };
    await expect(attenuateToPayment(broken, processor.did, { spendLimitUsd: 100 }, shop.priv)).rejects.toThrow(/JWT/);
  });

  it("refuses a widening at attenuation, and at verification when the issuer skipped the check", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    await expect(attenuateToCart(intent, shop.did, { spendLimitUsd: 600 }, assistant.priv)).rejects.toThrow(/exceeds parent/);

    const honest = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);
    const forged = await signMandateJwt("spending", { ...honest.mandate, constraints: { spendLimitUsd: 600 }, mandateId: crypto.randomUUID() }, assistant.priv);
    const r = await verifyMandateChain(`${intent.jwt}~${forged}`, undefined, { isRevoked: null });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/exceeds parent/);
  });

  it("checks revocation for every link, keyed by the grantor and the mandate id", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);
    const asked: string[] = [];
    const ok = await verifyMandateChain(cart.token, undefined, { isRevoked: async (id, grantor) => (asked.push(`${grantor}#${id}`), false) });
    expect(ok.valid).toBe(true);
    expect(asked).toEqual([`${human.did}#${intent.mandate.mandateId}`, `${assistant.did}#${cart.mandate.mandateId}`]);
    const revoked = await verifyMandateChain(cart.token, undefined, { isRevoked: async (id) => id === intent.mandate.mandateId });
    expect(revoked.valid).toBe(false);
    expect(revoked.reason).toMatch(/revoked/);
  });

  it("works with verifyMandate, enforceSpendingConstraints and redemption", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);
    const payment = await attenuateToPayment(cart, shop.did, { spendLimitUsd: 100 }, shop.priv);

    const single = await verifyMandate(payment.token, shop.pub, shop.did, { expectedRoot: human.did, isRevoked: null });
    expect(single.valid, single.reason).toBe(true);
    expect(single.chainVerified).toBe(true);
    expect((await verifyMandate(payment.token, assistant.pub, shop.did, { isRevoked: null })).valid).toBe(false);

    await enforceSpendingConstraints(payment.token, shop.pub, { proposedAmountUsd: 80, expectedRoot: human.did, isRevoked: null });
    await expect(enforceSpendingConstraints(payment.token, shop.pub, { proposedAmountUsd: 180, isRevoked: null })).rejects.toThrow();

    const store = new InMemoryRedemptionStore();
    await redeemPaymentMandate(store, single.mandate!, 60, shop.did);
    await expect(redeemPaymentMandate(store, single.mandate!, 60, shop.did)).rejects.toThrow();
  });

  it("refuses a body that cannot be written as a JWT without loss", () => {
    const body = { mandateTier: "intent", constraints: { spendLimitUsd: 1 }, grantee: "b", grantor: "a", issuedAt: "2026-01-01T00:00:00.250Z", expiresAt: "2026-01-01T01:00:00.000Z", parentMandateId: null, mandateId: "m" };
    expect(() => mandateBodyToJwtClaims("spending", body)).toThrow(/whole second/);
    expect(() => mandateBodyToJwtClaims("spending", { ...body, issuedAt: "2026-01-01T00:00:00.000Z", type: "x" })).toThrow(/type/);
  });
});

// ─── Task mandates ────────────────────────────────────────────────────────────

describe("task mandates in the JWT form", () => {
  it("issues, verifies, enforces and attenuates", async () => {
    const human = await party(), assistant = await party(), worker = await party();
    const root = await issueTaskMandate(human.did, assistant.did, ["inbox.read", "inbox.archive"], { actionLimits: { "inbox.archive": 20 }, maxDelegationDepth: 2 }, human.priv, 3_600_000, { blocked: ["inbox.delete"], format: "jwt" });
    expect(root.token).toBe(root.jwt);
    expect(segment(root.jwt!, 0)).toEqual({ alg: "EdDSA", typ: MANDATE_JWT_TYP, kid: ed25519JwkThumbprint(human.pub) });
    expect((segment(root.jwt!, 1).authorization_details as Record<string, unknown>[])[0]).toMatchObject({ type: "https://aroha-labs.com/mandates/task", mandateType: "task", allowed: ["inbox.read", "inbox.archive"], blocked: ["inbox.delete"] });

    const r = await verifyTaskMandate(root.token, human.pub, assistant.did);
    expect(r.valid, r.reason).toBe(true);
    expect((await verifyTaskMandate(root.token, assistant.pub, assistant.did)).valid).toBe(false);
    expect((await verifyTaskMandate(root.token, human.pub, worker.did)).valid).toBe(false);

    await enforceTaskConstraints(root.token, human.pub, { requestedCapability: "inbox.read" });
    await expect(enforceTaskConstraints(root.token, human.pub, { requestedCapability: "inbox.delete" })).rejects.toBeInstanceOf(TaskConstraintViolation);

    const child = await attenuateTaskMandate(root, worker.did, ["inbox.read"], { actionLimits: {}, maxDelegationDepth: 1 }, assistant.priv);
    expect(looksLikeMandateJwt(child.token)).toBe(true);
    expect(child.mandate.parentMandateId).toBe(root.mandate.mandateId);
    expect(Date.parse(child.mandate.expiresAt)).toBeLessThanOrEqual(Date.parse(root.mandate.expiresAt));
    expect((await verifyTaskMandate(child.token, assistant.pub, worker.did)).valid).toBe(true);
    await expect(attenuateTaskMandate(root, worker.did, ["inbox.read", "inbox.send"], { maxDelegationDepth: 1 }, assistant.priv)).rejects.toThrow();

    // A parent rebuilt from its token alone still yields a JWT child.
    const rebuilt = decodeTaskMandateToken(root.token);
    expect(typeof rebuilt).toBe("object");
    if (typeof rebuilt === "string") return;
    expect(rebuilt.mandate).toEqual(root.mandate);
    expect(looksLikeMandateJwt((await attenuateTaskMandate(rebuilt, worker.did, ["inbox.read"], { actionLimits: {}, maxDelegationDepth: 1 }, assistant.priv)).token)).toBe(true);
  });

  it("honours revocation and expiry", async () => {
    const human = await party(), assistant = await party();
    const signed = await issueTaskMandate(human.did, assistant.did, ["research"], {}, human.priv, 3_600_000, { format: "jwt" });
    expect((await verifyTaskMandate(signed.token, human.pub, undefined, { isRevoked: async () => true })).valid).toBe(false);
    expect((await verifyTaskMandate(signed.token, human.pub, undefined, { now: Date.now() + 2 * 3_600_000 })).valid).toBe(false);
  });
});

// ─── A stock JWT library ──────────────────────────────────────────────────────

describe("a stock JWT library (jose) reads and verifies a mandate", () => {
  it("verifies a root mandate with the grantor's published key and reads its limits", async () => {
    const human = await party(), assistant = await party();
    const HUMAN = "https://accounts.example.com/people/kiri";
    const ASSISTANT = "https://agents.example.com/assistant";
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 500, merchantCategory: "4511" }, human.priv, 3_600_000, { format: "jwt" });

    // The key set a web identity publishes (spec §4.7) is what jose expects.
    const keySet = createLocalJWKSet(buildWebIdentityDocument({ identity: HUMAN, publicKey: human.pub }).jwks as never);
    const { payload, protectedHeader } = await jwtVerify(intent.token, keySet, { issuer: HUMAN, subject: ASSISTANT, typ: MANDATE_JWT_TYP, algorithms: ["EdDSA"] });
    expect(protectedHeader.kid).toBe(ed25519JwkThumbprint(human.pub));
    expect(payload.jti).toBe(intent.mandate.mandateId);
    expect((payload.authorization_details as { type: string; constraints: { spendLimitUsd: number } }[])[0]).toMatchObject({ type: "https://aroha-labs.com/mandates/spending", constraints: { spendLimitUsd: 500 } });

    // jose refuses what the Aroha verifier refuses: another issuer's key, a changed payload.
    const other = createLocalJWKSet({ keys: [ed25519PublicKeyToJwk(assistant.pub, ed25519JwkThumbprint(human.pub))] } as never);
    await expect(jwtVerify(intent.token, other, { algorithms: ["EdDSA"] })).rejects.toThrow();
    const [h, , s] = intent.token.split(".");
    const tampered = `${h}.${b64u(JSON.stringify({ ...segment(intent.token, 1), exp: 9_999_999_999 }))}.${s}`;
    await expect(jwtVerify(tampered, keySet, { algorithms: ["EdDSA"] })).rejects.toThrow();
  });

  it("verifies each link of a chain after splitting on ~, but only the Aroha verifier checks the chain", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);

    const signers = [human, assistant];
    const links = cart.token.split("~");
    for (let i = 0; i < links.length; i++) {
      const key = await importJWK(ed25519PublicKeyToJwk(signers[i].pub) as never, "EdDSA");
      const { payload } = await jwtVerify(links[i], key, { issuer: signers[i].did, typ: MANDATE_JWT_TYP, algorithms: ["EdDSA"] });
      expect(payload.iss).toBe(signers[i].did);
    }

    // A widened child is a perfectly valid JWT. Narrowing is a chain rule,
    // which a JWT library does not know; verifyMandateChain does.
    const widened = await signMandateJwt("spending", { ...cart.mandate, constraints: { spendLimitUsd: 5000 }, mandateId: crypto.randomUUID() }, assistant.priv);
    const key = await importJWK(ed25519PublicKeyToJwk(assistant.pub) as never, "EdDSA");
    await expect(jwtVerify(widened, key, { typ: MANDATE_JWT_TYP, algorithms: ["EdDSA"] })).resolves.toBeDefined();
    expect((await verifyMandateChain(`${intent.jwt}~${widened}`, undefined, { isRevoked: null })).valid).toBe(false);
  });

  it("a JWT made by jose with the same claims verifies here", async () => {
    const { SignJWT, importJWK: importKey } = await import("jose");
    const human = await party(), assistant = await party();
    const now = Math.floor(Date.now() / 1000);
    const privateJwk = { kty: "OKP", crv: "Ed25519", x: b64u(human.pub), d: b64u(human.priv) };
    const token = await new SignJWT({
      authorization_details: [{ type: "https://aroha-labs.com/mandates/spending", mandateTier: "intent", constraints: { spendLimitUsd: 75 }, parentMandateId: null }],
    })
      .setProtectedHeader({ alg: "EdDSA", typ: MANDATE_JWT_TYP })
      .setIssuer(human.did).setSubject(assistant.did).setJti(crypto.randomUUID()).setIssuedAt(now).setExpirationTime(now + 600)
      .sign(await importKey(privateJwk, "EdDSA"));
    const r = await verifyMandateChain(token, undefined, { expectedRoot: human.did, expectedGrantee: assistant.did, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(r.mandate?.constraints.spendLimitUsd).toBe(75);
  });
});

// ─── With the rest of the SDK ─────────────────────────────────────────────────

describe("the JWT form with web identities and HTTP presentation", () => {
  const HUMAN = "https://accounts.example.com/people/kiri";
  const ASSISTANT = "https://agents.example.com/assistant";
  const SHOP = "https://shop.example.net/agents/checkout";

  function serve(identities: Record<string, Uint8Array>): typeof fetch {
    return (async (input: string | URL | Request) => {
      const publicKey = identities[String(input)];
      if (!publicKey) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(buildWebIdentityDocument({ identity: String(input), publicKey })), { status: 200 });
    }) as typeof fetch;
  }

  it("verifies a JWT chain between web identities: names and tokens an OAuth service already understands", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const resolveKey = createMandateKeyResolver({ web: { fetch: serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub, [SHOP]: shop.pub }) } });
    const intent = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 200 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, SHOP, { spendLimitUsd: 80 }, assistant.priv);
    const r = await verifyMandateChain(cart.token, resolveKey, { expectedRoot: HUMAN, expectedGrantee: SHOP, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(segment(cart.jwt!, 1)).toMatchObject({ iss: ASSISTANT, sub: SHOP });
  });

  it("binds an HTTP presentation of a JWT-form token to its holder", async () => {
    const human = await party(), assistant = await party(), other = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv, 600_000, { format: "jwt" });
    const request = { audience: "https://api.example.com", method: "POST", url: "https://api.example.com/v1/orders", body: '{"item":"widget"}' };
    const verify = (header: string) =>
      verifyHttpMandateRequest(header, { ...request, url: "/v1/orders", nonces: new InMemoryHttpPresentationNonces(), expectedRoot: human.did, isRevoked: null });

    const good = await presentMandateHttp({ token: intent.token, holderDid: assistant.did, holderPrivateKey: assistant.priv, ...request });
    const ok = await verify(good[HTTP_MANDATE_HEADER]);
    expect(ok.ok, ok.ok ? "" : ok.reason).toBe(true);
    const stolen = await presentMandateHttp({ token: intent.token, holderDid: assistant.did, holderPrivateKey: other.priv, ...request });
    expect((await verify(stolen[HTTP_MANDATE_HEADER])).ok).toBe(false);
  });
});

describe("peekMandateToken", () => {
  it("reads the leaf of either form without verifying, and nothing else", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const jwtIntent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv, 3_600_000, { format: "jwt" });
    const jwtCart = await attenuateToCart(jwtIntent, shop.did, { spendLimitUsd: 50 }, assistant.priv);
    const native = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 100 }, human.priv);
    const jwtTask = await issueTaskMandate(human.did, assistant.did, ["research"], {}, human.priv, 3_600_000, { format: "jwt" });
    const nativeTask = await issueTaskMandate(human.did, assistant.did, ["research"], {}, human.priv);

    expect(peekMandateToken(jwtCart.token)).toEqual({ kind: "spending", format: "jwt", mandateId: jwtCart.mandate.mandateId, grantor: assistant.did, grantee: shop.did });
    expect(peekMandateToken(native.token)).toEqual({ kind: "spending", format: "native", mandateId: native.mandate.mandateId, grantor: human.did, grantee: assistant.did });
    expect(peekMandateToken(jwtTask.token)).toMatchObject({ kind: "task", format: "jwt", mandateId: jwtTask.mandate.mandateId });
    expect(peekMandateToken(nativeTask.token)).toMatchObject({ kind: "task", format: "native", mandateId: nativeTask.mandate.mandateId });
    for (const bad of [undefined, null, 7, "", "a.b.c", "not-a-token", "e30"]) expect(peekMandateToken(bad)).toBeNull();
  });
});
