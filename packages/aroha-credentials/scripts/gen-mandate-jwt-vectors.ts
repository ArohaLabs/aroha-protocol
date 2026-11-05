// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/mandate-jwt-v1.json.
 *
 *   npx vite-node scripts/gen-mandate-jwt-vectors.ts
 *
 * The vectors are the cross-SDK contract for the JWT form of a mandate
 * (spec §6.10). An implementation passes when, for every entry of `links`, it
 * decodes `jwt` to `body` and verifies the signature under the grantor's key,
 * and when it reaches the same verdict on every entry of `tokens` at the
 * instant `now`. Everything is fixed (keys from RFC 8032 §7.1, hard-coded ids
 * and times) and Ed25519 is deterministic, so regenerating must produce an
 * identical file.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { generateDid } from "@aroha-sdk/core";
import { MANDATE_JWT_TYP, mandateBodyToJwtClaims, signMandateJwt, type MandateJwtKind } from "../src/mandate-jwt.js";
import { ed25519JwkThumbprint } from "../src/web-identity.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (v: Uint8Array | string) => Buffer.from(v).toString("base64url");

// RFC 8032 §7.1 TEST 1, 2 and 3 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  provider: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

/** 2026-01-01, 2100-01-01 and the instant every token is judged at (2026-09-21). */
const ISSUED = "2026-01-01T00:00:00.000Z";
const EXPIRES = "2100-01-01T00:00:00.000Z";
const NOW_MS = 1_790_000_000_000;

type Body = Record<string, unknown>;

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string; kid: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub), kid: ed25519JwkThumbprint(pub) };
  }
  const { human, agent, provider } = keys;

  const sign = (kind: MandateJwtKind, body: Body, by: KeyName) => signMandateJwt(kind, body, keys[by].priv, keys[by].kid);
  /** Sign arbitrary header and claims: for tokens a correct issuer never makes. */
  const signRaw = async (header: unknown, claims: unknown, by: KeyName) => {
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
    return `${input}.${b64u(await ed.signAsync(new TextEncoder().encode(input), keys[by].priv))}`;
  };
  const header = (by: KeyName, over: Record<string, unknown> = {}) => ({ alg: "EdDSA", typ: MANDATE_JWT_TYP, kid: keys[by].kid, ...over });
  /** Sign an exact payload text: for spellings JSON.stringify never produces. */
  const signText = async (headerValue: unknown, payloadText: string, by: KeyName) => {
    const input = `${b64u(JSON.stringify(headerValue))}.${b64u(payloadText)}`;
    return `${input}.${b64u(await ed.signAsync(new TextEncoder().encode(input), keys[by].priv))}`;
  };

  // ── Bodies ──────────────────────────────────────────────────────────────────
  const intent: Body = {
    mandateTier: "intent", constraints: { spendLimitUsd: 500, merchantCategory: "4511", currency: "USD" },
    grantee: agent.did, grantor: human.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: null, mandateId: "11111111-1111-4111-8111-111111111111",
  };
  const cart: Body = {
    mandateTier: "cart", constraints: { spendLimitUsd: 300, merchantCategory: "4511", currency: "USD" },
    grantee: provider.did, grantor: agent.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: intent.mandateId, mandateId: "22222222-2222-4222-8222-222222222222",
  };
  const payment: Body = {
    mandateTier: "payment", constraints: { spendLimitUsd: 249.99, merchantCategory: "4511", currency: "USD" },
    grantee: provider.did, grantor: provider.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: cart.mandateId, mandateId: "33333333-3333-4333-8333-333333333333", actingFor: undefined,
  };
  delete payment.actingFor;
  const payer: Body = { ...intent, mandateId: "44444444-4444-4444-8444-444444444444", actingFor: "payer" };
  const task: Body = {
    mandateType: "task", mandateTier: "intent", allowed: ["inbox.read", "inbox.archive"], blocked: ["inbox.delete"],
    taskConstraints: { actionLimits: { "inbox.archive": 20 }, maxDelegationDepth: 2 },
    grantee: agent.did, grantor: human.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: null, mandateId: "55555555-5555-4555-8555-555555555555",
  };
  const subtask: Body = {
    mandateType: "task", mandateTier: "cart", allowed: ["inbox.read"], blocked: ["inbox.delete"],
    taskConstraints: { actionLimits: {}, maxDelegationDepth: 1 },
    grantee: provider.did, grantor: agent.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: task.mandateId, mandateId: "66666666-6666-4666-8666-666666666666",
  };
  const hybrid: Body = {
    mandateType: "hybrid", mandateTier: "intent", allowed: ["flights.book"],
    taskConstraints: { reversibleOnly: true }, spendingConstraints: { spendLimitUsd: 300, currency: "USD" },
    grantee: agent.did, grantor: human.did, issuedAt: ISSUED, expiresAt: EXPIRES,
    parentMandateId: null, mandateId: "77777777-7777-4777-8777-777777777777",
  };

  const jwt = {
    intent: await sign("spending", intent, "human"),
    cart: await sign("spending", cart, "agent"),
    payment: await sign("spending", payment, "provider"),
    payer: await sign("spending", payer, "human"),
    task: await sign("task", task, "human"),
    subtask: await sign("task", subtask, "agent"),
    hybrid: await sign("task", hybrid, "human"),
  };

  const links = (
    [
      ["spending intent", "spending", intent, "human", jwt.intent],
      ["spending cart", "spending", cart, "agent", jwt.cart],
      ["spending payment (a decimal amount)", "spending", payment, "provider", jwt.payment],
      ["spending intent with actingFor", "spending", payer, "human", jwt.payer],
      ["task mandate", "task", task, "human", jwt.task],
      ["task mandate, second link", "task", subtask, "agent", jwt.subtask],
      ["hybrid task mandate", "task", hybrid, "human", jwt.hybrid],
    ] as [string, MandateJwtKind, Body, KeyName, string][]
  ).map(([name, kind, body, by, token]) => ({
    name, kind, signer: by, body,
    header: header(by),
    claims: mandateBodyToJwtClaims(kind, body),
    jwt: token,
  }));

  // ── Tokens a verifier must accept ───────────────────────────────────────────
  const chain = [jwt.intent, jwt.cart, jwt.payment].join("~");
  const accept = [
    { name: "one link: a root intent mandate is a plain JWT", kind: "spending", token: jwt.intent, expect: { valid: true, mandateId: intent.mandateId, rootGrantor: human.did, links: 1 } },
    { name: "three links joined by ~, root first", kind: "spending", token: chain, expect: { valid: true, mandateId: payment.mandateId, rootGrantor: human.did, links: 3 } },
    { name: "two links", kind: "spending", token: [jwt.intent, jwt.cart].join("~"), expect: { valid: true, mandateId: cart.mandateId, rootGrantor: human.did, links: 2 } },
    { name: "actingFor is carried in authorization_details", kind: "spending", token: jwt.payer, expect: { valid: true, mandateId: payer.mandateId, rootGrantor: human.did, links: 1 } },
    { name: "typ with the application/ prefix", kind: "spending", token: await signRaw(header("human", { typ: `application/${MANDATE_JWT_TYP}` }), mandateBodyToJwtClaims("spending", intent), "human"), expect: { valid: true, mandateId: intent.mandateId, rootGrantor: human.did, links: 1 } },
    { name: "alg Ed25519 (the RFC 9864 name)", kind: "spending", token: await signRaw(header("human", { alg: "Ed25519" }), mandateBodyToJwtClaims("spending", intent), "human"), expect: { valid: true, mandateId: intent.mandateId, rootGrantor: human.did, links: 1 } },
    { name: "no kid", kind: "spending", token: await signRaw({ alg: "EdDSA", typ: MANDATE_JWT_TYP }, mandateBodyToJwtClaims("spending", intent), "human"), expect: { valid: true, mandateId: intent.mandateId, rootGrantor: human.did, links: 1 } },
    {
      name: "whole seconds written with a fraction or an exponent (1767225600.0, 4.1024448e9)", kind: "spending",
      token: await signText(header("human"), JSON.stringify(mandateBodyToJwtClaims("spending", intent)).replace('"iat":1767225600', '"iat":1767225600.0').replace('"exp":4102444800', '"exp":4.1024448e9'), "human"),
      expect: { valid: true, mandateId: intent.mandateId, rootGrantor: human.did, links: 1 },
    },
    { name: "task mandate", kind: "task", token: jwt.task, signer: "human", expect: { valid: true, mandateId: task.mandateId } },
    { name: "hybrid task mandate", kind: "task", token: jwt.hybrid, signer: "human", expect: { valid: true, mandateId: hybrid.mandateId } },
  ];

  // ── Tokens a verifier must refuse ───────────────────────────────────────────
  const claims = (body: Body) => mandateBodyToJwtClaims("spending", body) as Record<string, unknown>;
  const detail = (body: Body) => (claims(body).authorization_details as Record<string, unknown>[])[0];
  const parts = jwt.intent.split(".");
  const widened: Body = { ...cart, constraints: { spendLimitUsd: 600, merchantCategory: "4511", currency: "USD" }, mandateId: "88888888-8888-4888-8888-888888888888" };
  const outlives: Body = { ...cart, expiresAt: "2100-01-02T00:00:00.000Z", mandateId: "99999999-9999-4999-8999-999999999999" };
  const expired: Body = { ...intent, issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-06-01T00:00:00.000Z", mandateId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
  const future: Body = { ...intent, issuedAt: "2027-01-01T00:00:00.000Z", mandateId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
  const tampered = `${parts[0]}.${b64u(JSON.stringify({ ...claims(intent), authorization_details: [{ ...detail(intent), constraints: { spendLimitUsd: 5000, merchantCategory: "4511", currency: "USD" } }] }))}.${parts[2]}`;

  const refuse: { name: string; kind: string; token: string; signer?: string }[] = [
    { name: "child widens its parent's limit", kind: "spending", token: [jwt.intent, await sign("spending", widened, "agent")].join("~") },
    { name: "child outlives its parent", kind: "spending", token: [jwt.intent, await sign("spending", outlives, "agent")].join("~") },
    { name: "child signed by a key that is not its grantor's", kind: "spending", token: [jwt.intent, await sign("spending", cart, "provider")].join("~") },
    { name: "root signed by a key that is not its grantor's", kind: "spending", token: await sign("spending", intent, "agent") },
    { name: "claims changed after signing", kind: "spending", token: tampered },
    { name: "links in the wrong order (leaf first)", kind: "spending", token: [jwt.cart, jwt.intent].join("~") },
    { name: "a link missing from the middle", kind: "spending", token: [jwt.intent, jwt.payment].join("~") },
    { name: "child presented without its parent", kind: "spending", token: jwt.cart },
    { name: "the same link twice", kind: "spending", token: [jwt.intent, jwt.intent].join("~") },
    { name: "an empty link", kind: "spending", token: `${jwt.intent}~~${jwt.cart}` },
    { name: "a trailing separator", kind: "spending", token: `${jwt.intent}~` },
    { name: "a task mandate inside a spending chain", kind: "spending", token: [jwt.intent, jwt.subtask].join("~") },
    { name: "a task mandate presented as a spending mandate", kind: "spending", token: jwt.task },
    { name: "expired", kind: "spending", token: await sign("spending", expired, "human") },
    { name: "issued in the future", kind: "spending", token: await sign("spending", future, "human") },
    { name: "alg none", kind: "spending", token: `${b64u(JSON.stringify(header("human", { alg: "none" })))}.${parts[1]}.` },
    { name: "alg HS256", kind: "spending", token: await signRaw(header("human", { alg: "HS256" }), claims(intent), "human") },
    { name: "typ missing", kind: "spending", token: await signRaw({ alg: "EdDSA", kid: human.kid }, claims(intent), "human") },
    { name: "typ JWT", kind: "spending", token: await signRaw(header("human", { typ: "JWT" }), claims(intent), "human") },
    { name: "typ at+jwt (an OAuth access token)", kind: "spending", token: await signRaw(header("human", { typ: "at+jwt" }), claims(intent), "human") },
    { name: "unknown header member crit", kind: "spending", token: await signRaw(header("human", { crit: ["exp"] }), claims(intent), "human") },
    { name: "header carries a key (jwk)", kind: "spending", token: await signRaw(header("human", { jwk: { kty: "OKP", crv: "Ed25519", x: b64u(agent.pub) } }), claims(intent), "agent") },
    { name: "unknown claim nbf", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), nbf: 4_000_000_000 }, "human") },
    { name: "unknown claim aud", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), aud: "https://api.example.com" }, "human") },
    { name: "iat is not a whole number", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), iat: 1767225600.5 }, "human") },
    { name: "exp is a string", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), exp: "4102444800" }, "human") },
    { name: "exp missing", kind: "spending", token: await signRaw(header("human"), (({ exp: _exp, ...rest }) => rest)(claims(intent) as { exp: unknown }), "human") },
    { name: "sub missing", kind: "spending", token: await signRaw(header("human"), (({ sub: _sub, ...rest }) => rest)(claims(intent) as { sub: unknown }), "human") },
    { name: "authorization_details missing", kind: "spending", token: await signRaw(header("human"), (({ authorization_details: _a, ...rest }) => rest)(claims(intent) as { authorization_details: unknown }), "human") },
    { name: "authorization_details with two entries", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), authorization_details: [detail(intent), detail(intent)] }, "human") },
    { name: "authorization_details type is not a mandate", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), authorization_details: [{ ...detail(intent), type: "payment_initiation" }] }, "human") },
    { name: "authorization_details restates the grantor", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), authorization_details: [{ ...detail(intent), grantor: agent.did }] }, "human") },
    { name: "spending detail carries mandateType", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), authorization_details: [{ ...detail(intent), mandateType: "task" }] }, "human") },
    { name: "constraints missing", kind: "spending", token: await signRaw(header("human"), { ...claims(intent), authorization_details: [{ type: "aroha_spending_mandate", mandateTier: "intent", parentMandateId: null }] }, "human") },
    { name: "payload is not JSON", kind: "spending", token: `${parts[0]}.${b64u("not json")}.${parts[2]}` },
    { name: "payload is a JSON array", kind: "spending", token: await signRaw(header("human"), [claims(intent)], "human") },
    { name: "payload base64url with padding", kind: "spending", token: `${parts[0]}.${parts[1]}=.${parts[2]}` },
    { name: "two parts instead of three", kind: "spending", token: `${parts[0]}.${parts[1]}` },
    { name: "four parts", kind: "spending", token: `${jwt.intent}.${parts[2]}` },
    { name: "signature too short", kind: "spending", token: `${parts[0]}.${parts[1]}.${parts[2].slice(0, 40)}` },
    { name: "task mandate signed by a key that is not its grantor's", kind: "task", token: await sign("task", task, "agent"), signer: "human" },
    { name: "a spending mandate presented as a task mandate", kind: "task", token: jwt.intent, signer: "human" },
    { name: "task detail without allowed", kind: "task", token: await signRaw(header("human"), { ...mandateBodyToJwtClaims("task", task), authorization_details: [{ type: "aroha_task_mandate", mandateType: "task", mandateTier: "intent", taskConstraints: {}, parentMandateId: null }] }, "human"), signer: "human" },
  ];

  const vectors = {
    description:
      "Conformance vectors for the JWT form of a mandate (spec section 6.10). `links`: each `jwt` decodes to `body`, its header and claims are `header` and `claims`, and its signature verifies under the key of `signer`. `tokens`: judge each at the instant `nowMs`. A spending token is verified as a chain, with keys derived from the did:aroha:z identifiers; a task token is verified as one link under the key of `signer`. `expect.valid` is the verdict; for a valid spending token `rootGrantor`, the leaf `mandateId` and the number of `links` must match too. Keys are the RFC 8032 section 7.1 test keys.",
    version: 1,
    typ: MANDATE_JWT_TYP,
    nowMs: NOW_MS,
    keys: Object.fromEntries((Object.keys(keys) as KeyName[]).map((n) => [n, { seedHex: KEY_SEEDS[n], publicKeyHex: hex(keys[n].pub), did: keys[n].did, kid: keys[n].kid }])),
    links,
    tokens: [...accept, ...refuse.map((r) => ({ ...r, expect: { valid: false } }))],
  };

  const out = fileURLToPath(new URL("../test-vectors/mandate-jwt-v1.json", import.meta.url));
  writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
  console.log(`links ${links.length}, tokens ${vectors.tokens.length} (${accept.length} valid, ${refuse.length} refused)`);
}

await main();
