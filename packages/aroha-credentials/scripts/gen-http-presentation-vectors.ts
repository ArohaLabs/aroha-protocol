// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/http-presentation-v1.json.
 *
 *   npx tsx scripts/gen-http-presentation-vectors.ts
 *
 * The cross-SDK contract for the HTTP mandate presentation (the
 * `Aroha-Mandate` header, spec §6.9.2). An implementation passes when it
 * reproduces every `expected` field byte for byte — target, body hash,
 * signing payload, proof, header value — and reaches the same verdict and
 * failure code on every case. Keys are RFC 8032 §7.1 test keys, nonces and
 * times are fixed, and Ed25519 is deterministic, so regenerating must produce
 * an identical file. If it does not, the wire format changed — a protocol
 * break, not a refresh.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody } from "@aroha-sdk/core";
import { canonicalizeJcs } from "../src/jcs.js";
import { mandateSigningPayloadV2 } from "../src/mandate.js";
import {
  HTTP_MANDATE_HEADER,
  HTTP_MANDATE_PRESENTATION_PURPOSE,
  InMemoryHttpPresentationNonces,
  httpBodySha256,
  httpMethodForProof,
  httpPresentationSigningPayload,
  httpRequestTarget,
  presentMandateHttp,
  verifyHttpMandateRequest,
  verifyHttpPresentation,
} from "../src/http-mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");
const unb64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

// RFC 8032 §7.1 TEST 1, 2 and 3 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  provider: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

const NOW = "2026-06-01T12:00:00.000Z";
const AUDIENCE = "https://api.example.com";
const NAMED_HOLDER = "did:aroha:named-holder";

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }

  async function signLink(signer: KeyName, mandate: ArohaSpendingMandateBody) {
    const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(mandate)), keys[signer].priv);
    return { v: 2 as const, mandate, signature: b64u(sig) };
  }
  const tokenOf = (leaf: { mandate: ArohaSpendingMandateBody; signature: string }, chain: unknown[]) =>
    b64u(JSON.stringify({ v: 2, mandate: leaf.mandate, signature: leaf.signature, chain }));

  const base = { issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" };
  const intentBody: ArohaSpendingMandateBody = {
    mandateTier: "intent", constraints: { spendLimitUsd: 100, currency: "USD" },
    grantee: keys.agent.did, grantor: keys.human.did, ...base,
    parentMandateId: null, mandateId: "00000000-0000-4000-8000-000000000101",
  };
  const cartBody: ArohaSpendingMandateBody = {
    mandateTier: "cart", constraints: { spendLimitUsd: 25, currency: "USD" },
    grantee: keys.provider.did, grantor: keys.agent.did, ...base, issuedAt: "2026-01-01T00:00:01.000Z",
    parentMandateId: intentBody.mandateId, mandateId: "00000000-0000-4000-8000-000000000102",
  };
  const namedBody: ArohaSpendingMandateBody = {
    ...intentBody, grantee: NAMED_HOLDER, mandateId: "00000000-0000-4000-8000-000000000103",
  };
  const intentLink = await signLink("human", intentBody);
  const cartLink = await signLink("agent", cartBody);
  const tokens = {
    intent: tokenOf(intentLink, []),
    cart: tokenOf(cartLink, [intentLink]),
    named: tokenOf(await signLink("human", namedBody), []),
  };

  // ── Valid presentations ────────────────────────────────────────────────────
  interface Present { token: keyof typeof tokens; holder: KeyName; method: string; url: string; body: string; nonce: string; ttlMs: number }
  interface Verify { audience: string; method: string; url: string; body: string; now: string }
  const presentCases: { name: string; description: string; present: Present; verify: Verify }[] = [
    {
      name: "post-json-absolute-url",
      description: "Client signs the absolute URL; the server sees origin-form req.url. Body is the exact JSON bytes.",
      present: { token: "intent", holder: "agent", method: "POST", url: "https://api.example.com/v1/orders?limit=5#ignored", body: b64u('{"item":"widget","qty":2}'), nonce: "AAAAAAAAAAAAAAAAAAAAAA", ttlMs: 60_000 },
      verify: { audience: AUDIENCE, method: "POST", url: "/v1/orders?limit=5", body: b64u('{"item":"widget","qty":2}'), now: NOW },
    },
    {
      name: "get-empty-body-lowercase-method-root-query",
      description: "Method is upper-cased; an empty path becomes '/'; an empty body hashes as SHA-256 of the empty string.",
      present: { token: "intent", holder: "agent", method: "get", url: "https://api.example.com?q=a%20b", body: "", nonce: "0123456789abcdef-_ABCD", ttlMs: 30_000 },
      verify: { audience: AUDIENCE, method: "GET", url: "https://api.example.com/?q=a%20b", body: "", now: NOW },
    },
    {
      name: "put-binary-body-percent-encoded-path",
      description: "Percent-escapes are signed as sent, never decoded; the body is arbitrary bytes.",
      present: { token: "intent", holder: "agent", method: "PUT", url: "https://api.example.com/v1/files/caf%C3%A9%2Fx?v=1&w=%7E", body: b64u(Uint8Array.from({ length: 256 }, (_, i) => i)), nonce: "bm9uY2Utbm9uY2Utbm9uY2U", ttlMs: 60_000 },
      verify: { audience: AUDIENCE, method: "PUT", url: "/v1/files/caf%C3%A9%2Fx?v=1&w=%7E", body: b64u(Uint8Array.from({ length: 256 }, (_, i) => i)), now: NOW },
    },
    {
      name: "cart-chain-ttl-capped",
      description: "A delegated cart presented by its grantee; a requested ttl above 5 minutes is capped at 5 minutes.",
      present: { token: "cart", holder: "provider", method: "DELETE", url: "/v1/orders/42", body: "", nonce: "cart-nonce-000000000001", ttlMs: 3_600_000 },
      verify: { audience: AUDIENCE, method: "delete", url: "/v1/orders/42", body: "", now: NOW },
    },
  ];

  const presentations = [];
  const headerOf: Record<string, string> = {};
  for (const c of presentCases) {
    const now = Date.parse(NOW);
    const h = (await presentMandateHttp({
      token: tokens[c.present.token], holderDid: keys[c.present.holder].did, holderPrivateKey: keys[c.present.holder].priv,
      audience: AUDIENCE, method: c.present.method, url: c.present.url, body: unb64u(c.present.body),
      ttlMs: c.present.ttlMs, nonce: c.present.nonce, now,
    }))[HTTP_MANDATE_HEADER];
    headerOf[c.name] = h;
    const decoded = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
    const expected = {
      method: httpMethodForProof(c.present.method),
      target: httpRequestTarget(c.present.url),
      bodySha256: httpBodySha256(unb64u(c.present.body)),
      expires: decoded.expires,
      signingPayload: httpPresentationSigningPayload({
        audience: AUDIENCE, method: httpMethodForProof(c.present.method), target: httpRequestTarget(c.present.url),
        bodySha256: httpBodySha256(unb64u(c.present.body)), mandateId: JSON.parse(Buffer.from(tokens[c.present.token], "base64url").toString("utf8")).mandate.mandateId,
        holder: keys[c.present.holder].did, nonce: c.present.nonce, expires: decoded.expires,
      }),
      proof: decoded.proof,
      headerJson: Buffer.from(h, "base64url").toString("utf8"),
      headerValue: h,
    };
    const r = await verifyHttpPresentation(h, { ...c.verify, body: unb64u(c.verify.body), now: Date.parse(c.verify.now), nonces: new InMemoryHttpPresentationNonces() });
    if (!r.ok) throw new Error(`${c.name} does not verify: ${r.reason}`);
    presentations.push({ ...c, expected: { ...expected, verify: { ok: true, holder: keys[c.present.holder].did } } });
  }

  // ── Refusals ───────────────────────────────────────────────────────────────
  const good = headerOf["post-json-absolute-url"];
  const goodJson = JSON.parse(Buffer.from(good, "base64url").toString("utf8")) as Record<string, string>;
  const enc = (o: unknown) => b64u(canonicalizeJcs(o));
  const v0 = presentCases[0].verify;

  // A proof built by hand so a field can be wrong while the signature is right.
  async function handSigned(over: { holder?: string; token?: string; signer: KeyName; nonce?: string; expires?: string }) {
    const token = over.token ?? tokens.intent;
    const holder = over.holder ?? keys.agent.did;
    const nonce = over.nonce ?? "hand-signed-nonce-0001";
    const expires = over.expires ?? "2026-06-01T12:01:00.000Z";
    const mandateId = JSON.parse(Buffer.from(token, "base64url").toString("utf8")).mandate.mandateId;
    const payload = httpPresentationSigningPayload({
      audience: AUDIENCE, method: "POST", target: "/v1/orders?limit=5", bodySha256: httpBodySha256('{"item":"widget","qty":2}'),
      mandateId, holder, nonce, expires,
    });
    const proof = b64u(await ed.signAsync(new TextEncoder().encode(payload), keys[over.signer].priv));
    return enc({ token, holder, nonce, expires, proof });
  }

  const refusals: { name: string; headerValue: string; verify: Verify; expectedCode: string }[] = [
    { name: "missing-header", headerValue: "", verify: v0, expectedCode: "MISSING" },
    { name: "bare-token-is-not-a-presentation", headerValue: tokens.intent, verify: v0, expectedCode: "MALFORMED" },
    { name: "not-base64url", headerValue: good + "=", verify: v0, expectedCode: "MALFORMED" },
    { name: "json-array", headerValue: enc([goodJson]), verify: v0, expectedCode: "MALFORMED" },
    { name: "extra-member", headerValue: enc({ ...goodJson, scope: "all" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "missing-member", headerValue: enc({ token: goodJson.token, holder: goodJson.holder, nonce: goodJson.nonce, expires: goodJson.expires }), verify: v0, expectedCode: "MALFORMED" },
    { name: "non-string-member", headerValue: enc({ ...goodJson, nonce: 12345678901234567 }), verify: v0, expectedCode: "MALFORMED" },
    { name: "nonce-too-short", headerValue: enc({ ...goodJson, nonce: "abc" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "nonce-bad-characters", headerValue: enc({ ...goodJson, nonce: "nonce with spaces 1234" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "expires-without-millis", headerValue: enc({ ...goodJson, expires: "2026-06-01T12:01:00Z" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "expires-with-offset", headerValue: enc({ ...goodJson, expires: "2026-06-01T12:01:00.000+00:00" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "expires-impossible-date", headerValue: enc({ ...goodJson, expires: "2026-02-30T12:01:00.000Z" }), verify: v0, expectedCode: "MALFORMED" },
    { name: "expired", headerValue: good, verify: { ...v0, now: "2026-06-01T12:01:00.000Z" }, expectedCode: "EXPIRED" },
    { name: "lifetime-too-long", headerValue: good, verify: { ...v0, now: "2026-06-01T11:55:29.999Z" }, expectedCode: "LIFETIME_TOO_LONG" },
    { name: "malformed-token", headerValue: enc({ ...goodJson, token: "bm90IGEgdG9rZW4" }), verify: v0, expectedCode: "MALFORMED_TOKEN" },
    { name: "holder-not-grantee", headerValue: await handSigned({ holder: keys.provider.did, signer: "provider" }), verify: v0, expectedCode: "HOLDER_NOT_GRANTEE" },
    { name: "server-url-not-normalisable", headerValue: good, verify: { ...v0, url: "/v1/orders/../orders?limit=5" }, expectedCode: "BAD_REQUEST" },
    { name: "unresolvable-holder", headerValue: await handSigned({ token: tokens.named, holder: NAMED_HOLDER, signer: "agent" }), verify: v0, expectedCode: "UNKNOWN_HOLDER" },
    { name: "wrong-audience", headerValue: good, verify: { ...v0, audience: "https://other.example.com" }, expectedCode: "BAD_PROOF" },
    { name: "wrong-method", headerValue: good, verify: { ...v0, method: "PUT" }, expectedCode: "BAD_PROOF" },
    { name: "wrong-path", headerValue: good, verify: { ...v0, url: "/v1/orders/7?limit=5" }, expectedCode: "BAD_PROOF" },
    { name: "wrong-query", headerValue: good, verify: { ...v0, url: "/v1/orders?limit=500" }, expectedCode: "BAD_PROOF" },
    { name: "query-dropped", headerValue: good, verify: { ...v0, url: "/v1/orders" }, expectedCode: "BAD_PROOF" },
    { name: "wrong-body", headerValue: good, verify: { ...v0, body: b64u('{"item":"widget","qty":200}') }, expectedCode: "BAD_PROOF" },
    { name: "body-reserialised", headerValue: good, verify: { ...v0, body: b64u('{"item": "widget", "qty": 2}') }, expectedCode: "BAD_PROOF" },
    { name: "body-dropped", headerValue: good, verify: { ...v0, body: "" }, expectedCode: "BAD_PROOF" },
    { name: "proof-by-another-key", headerValue: await handSigned({ signer: "provider" }), verify: v0, expectedCode: "BAD_PROOF" },
    { name: "proof-truncated", headerValue: enc({ ...goodJson, proof: goodJson.proof.slice(0, 80) }), verify: v0, expectedCode: "BAD_PROOF" },
    { name: "nonce-swapped", headerValue: enc({ ...goodJson, nonce: "BBBBBBBBBBBBBBBBBBBBBB" }), verify: v0, expectedCode: "BAD_PROOF" },
    { name: "expires-extended", headerValue: enc({ ...goodJson, expires: "2026-06-01T12:02:00.000Z" }), verify: v0, expectedCode: "BAD_PROOF" },
  ];
  for (const r of refusals) {
    const got = await verifyHttpPresentation(r.headerValue, { ...r.verify, body: unb64u(r.verify.body), now: Date.parse(r.verify.now), nonces: new InMemoryHttpPresentationNonces() });
    if (got.ok || got.code !== r.expectedCode) throw new Error(`${r.name}: expected ${r.expectedCode}, got ${got.ok ? "ok" : got.code}`);
  }

  // ── Replay: the same header twice against one nonce store ──────────────────
  const replay = { name: "replay", headerValue: good, verify: v0, expectedCodes: [null, "REPLAYED"] };

  // ── Full request check (presentation + chain, root pinned) ─────────────────
  const mandateRequests = [
    { name: "intent-pinned-root", headerValue: good, verify: v0, expectedRoot: keys.human.did, expected: { ok: true, holder: keys.agent.did, rootGrantor: keys.human.did, mandateId: intentBody.mandateId } },
    { name: "cart-trusted-roots", headerValue: headerOf["cart-chain-ttl-capped"], verify: presentCases[3].verify, trustedRoots: [keys.provider.did, keys.human.did], expected: { ok: true, holder: keys.provider.did, rootGrantor: keys.human.did, mandateId: cartBody.mandateId } },
    { name: "root-not-pinned-one", headerValue: good, verify: v0, expectedRoot: keys.agent.did, expected: { ok: false, code: "MANDATE_INVALID", status: 403 } },
    { name: "root-not-trusted", headerValue: good, verify: v0, trustedRoots: [keys.provider.did], expected: { ok: false, code: "MANDATE_INVALID", status: 403 } },
    { name: "presentation-failure-is-401", headerValue: good, verify: { ...v0, method: "PATCH" }, expectedRoot: keys.human.did, expected: { ok: false, code: "BAD_PROOF", status: 401 } },
  ];
  for (const m of mandateRequests) {
    const got = await verifyHttpMandateRequest(m.headerValue, {
      ...m.verify, body: unb64u(m.verify.body), now: Date.parse(m.verify.now), nonces: new InMemoryHttpPresentationNonces(),
      expectedRoot: m.expectedRoot, trustedRoots: m.trustedRoots, isRevoked: null,
    } as Parameters<typeof verifyHttpMandateRequest>[1]);
    const summary = got.ok
      ? { ok: true, holder: got.holder, rootGrantor: got.rootGrantor, mandateId: got.mandate.mandateId }
      : { ok: false, code: got.code, status: got.status };
    if (JSON.stringify(summary) !== JSON.stringify(m.expected)) throw new Error(`${m.name}: got ${JSON.stringify(summary)}`);
  }

  const out = {
    description:
      "Cross-SDK vectors for the HTTP mandate presentation (Aroha-Mandate header, spec section 6.9.2). " +
      "Generated by packages/aroha-credentials/scripts/gen-http-presentation-vectors.ts; do not edit by hand. " +
      "Bodies are base64url of the exact body bytes (empty string = empty body). 'now' is the verifier's clock. " +
      "A conforming SDK reproduces every 'expected' field byte for byte and reaches the same verdict and code.",
    header: HTTP_MANDATE_HEADER,
    purpose: HTTP_MANDATE_PRESENTATION_PURPOSE,
    maxTtlMs: 300_000,
    clockSkewMs: 30_000,
    audience: AUDIENCE,
    presentedAt: NOW,
    keys: Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, { privateKeyHex: hex(k.priv), publicKeyHex: hex(k.pub), did: k.did }])),
    tokens,
    presentations,
    refusals,
    replay,
    mandateRequests,
  };
  const path = fileURLToPath(new URL("../test-vectors/http-presentation-v1.json", import.meta.url));
  writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${path}: ${presentations.length} presentations, ${refusals.length} refusals, ${mandateRequests.length} mandate requests`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
