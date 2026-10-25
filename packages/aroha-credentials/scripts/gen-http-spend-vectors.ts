// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/http-spend-v1.json.
 *
 *   npx tsx scripts/gen-http-spend-vectors.ts
 *
 * The cross-SDK contract for verifyHttpSpendRequest / verify_http_spend_request:
 * the holder proof and chain check of http-presentation-v1, then the amount
 * and every spending constraint on every link, then a running total charged
 * against every link under grantor#mandateId, all or nothing.
 *
 * Each case starts with an EMPTY ledger and an empty nonce store, runs its
 * steps in order, and ends with the expected running totals. A step is
 * either a request (a header plus the spend inputs) with its expected
 * verdict, or `{ release: i }` — release the charge made by step i. An
 * implementation passes when every step reaches the same verdict, code and
 * status, every successful step charges the listed keys, and the totals match.
 *
 * Amounts that JSON cannot carry are given as `amountFloat` ("NaN",
 * "Infinity", "-Infinity") instead of `amountUsd`.
 *
 * Keys are RFC 8032 §7.1 test keys, mandate bodies, nonces and times are
 * fixed, and Ed25519 is deterministic, so regenerating produces an identical file.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody, type ArohaTaskMandateBody, type SpendingConstraints } from "@aroha-sdk/core";
import { mandateSigningPayloadV2, taskMandateSigningPayloadV2 } from "../src/mandate.js";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp } from "../src/http-mandate.js";
import { verifyHttpSpendRequest, type HttpSpendRequestResult } from "../src/http-spend.js";
import { mandateRedemptionKey } from "../src/redemption.js";
import { MapSpendingLedger } from "../src/spending-ledger.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const b64u = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

// RFC 8032 §7.1 TEST 1, 2 and 3 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  provider: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

const NOW = "2026-06-01T12:00:00.000Z";
const AUDIENCE = "https://api.example.com";
const URL_ = "/v1/invoices";
const BODY = '{"customer":"c-1","invoice":"inv-1"}';
const MERCHANT = "did:web:shop.example";
/** intentShort expires 30 minutes after NOW; LATER is after that. */
const SHORT_EXPIRY = "2026-06-01T12:30:00.000Z";
const LATER = "2026-06-01T13:00:00.000Z";

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }

  const base = { issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" };
  let seq = 0;
  const id = () => `00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`;
  const link = async (signer: KeyName, mandate: ArohaSpendingMandateBody) => ({
    v: 2 as const, mandate,
    signature: b64u(await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(mandate)), keys[signer].priv)),
  });
  const tokenOf = (leaf: { mandate: unknown; signature: string }, chain: unknown[]) =>
    b64u(JSON.stringify({ v: 2, mandate: leaf.mandate, signature: leaf.signature, chain }));

  const bodies: Record<string, ArohaSpendingMandateBody> = {};
  const tokens: Record<string, string> = {};
  const holders: Record<string, KeyName> = {};
  async function intent(name: string, constraints: SpendingConstraints, expiresAt = base.expiresAt) {
    const m: ArohaSpendingMandateBody = {
      mandateTier: "intent", constraints, grantee: keys.agent.did, grantor: keys.human.did, ...base, expiresAt, parentMandateId: null, mandateId: id(),
    };
    const l = await link("human", m);
    bodies[name] = m; tokens[name] = tokenOf(l, []); holders[name] = "agent";
    return l;
  }
  async function cart(name: string, parent: Awaited<ReturnType<typeof link>>, constraints: SpendingConstraints) {
    const m: ArohaSpendingMandateBody = {
      mandateTier: "cart", constraints, grantee: keys.provider.did, grantor: keys.agent.did, ...base,
      issuedAt: "2026-01-01T00:00:01.000Z", parentMandateId: parent.mandate.mandateId, mandateId: id(),
    };
    const l = await link("agent", m);
    bodies[name] = m; tokens[name] = tokenOf(l, [parent]); holders[name] = "provider";
  }

  const i500 = await intent("intent500", { spendLimitUsd: 500 });
  await cart("cartA400", i500, { spendLimitUsd: 400 });
  await cart("cartB400", i500, { spendLimitUsd: 400 });
  await cart("cart100", i500, { spendLimitUsd: 100 });
  await intent("intentEur", { spendLimitUsd: 100, currency: "EUR" });
  await intent("intentMerchants", { spendLimitUsd: 100, allowedMerchants: [MERCHANT] });
  await intent("intentCategory", { spendLimitUsd: 100, merchantCategory: "5734" });
  await intent("intentApproval", { spendLimitUsd: 500, requireHumanApprovalAboveUsd: 100 });
  await intent("intentSession", { spendLimitUsd: 500, sessionLimitUsd: 200 });
  await intent("intentShort", { spendLimitUsd: 100 }, SHORT_EXPIRY);

  // A task mandate, signed the way task mandates are; this endpoint spends money.
  const task: ArohaTaskMandateBody = {
    mandateType: "task", mandateTier: "intent", allowed: ["invoices.send"], taskConstraints: {},
    grantee: keys.agent.did, grantor: keys.human.did, ...base, parentMandateId: null, mandateId: "task-0001",
  } as ArohaTaskMandateBody;
  tokens.task = b64u(JSON.stringify({
    v: 2, mandate: task, chain: [],
    signature: b64u(await ed.signAsync(new TextEncoder().encode(taskMandateSigningPayloadV2(task)), keys.human.priv)),
  }));
  holders.task = "agent";

  let nonceSeq = 0;
  async function headerFor(token: string, over: { method?: string; now?: string } = {}) {
    const holder = keys[holders[token]];
    return (await presentMandateHttp({
      token: tokens[token], holderDid: holder.did, holderPrivateKey: holder.priv, audience: AUDIENCE,
      method: over.method ?? "POST", url: `${AUDIENCE}${URL_}`, body: BODY,
      nonce: `spend-vector-nonce-${String(++nonceSeq).padStart(4, "0")}`, now: Date.parse(over.now ?? NOW),
    }))[HTTP_MANDATE_HEADER];
  }

  interface Spend {
    amountUsd?: unknown; amountFloat?: "NaN" | "Infinity" | "-Infinity";
    currency?: string; merchant?: string; merchantCategory?: string; humanApproved?: boolean;
    expectedRoot?: string | null;
  }
  type Step = ({ token: string; headerValue?: string; method?: string; now?: string } & Spend) | { release: number };
  const cases: { name: string; description: string; steps: Step[] }[] = [
    { name: "within-limit", description: "One spend inside the limit is charged.", steps: [{ token: "intent500", amountUsd: 120 }] },
    { name: "over-limit-single", description: "One spend above the limit is refused before the ledger is touched.", steps: [{ token: "intent500", amountUsd: 500.01 }] },
    {
      name: "over-running-total", description: "The running total, not each spend, is held to the limit: $500.01 cannot pass a $500 mandate in parts.",
      steps: [{ token: "intent500", amountUsd: 250 }, { token: "intent500", amountUsd: 250.01 }, { token: "intent500", amountUsd: 250 }, { token: "intent500", amountUsd: 0.01 }],
    },
    {
      name: "sibling-exceeds-parent", description: "Two carts under one $500 intent each claim $400; together they cannot spend more than the intent's $500.",
      steps: [{ token: "cartA400", amountUsd: 300 }, { token: "cartB400", amountUsd: 300 }, { token: "cartB400", amountUsd: 200 }],
    },
    {
      name: "leaf-exhausted-rolls-back-parent", description: "The second $60 fits the intent but not the $100 cart; the intent's charge is undone.",
      steps: [{ token: "cart100", amountUsd: 60 }, { token: "cart100", amountUsd: 60 }],
    },
    {
      name: "currency-mismatch", description: "Spend currency defaults to USD and must equal every link's currency (default USD).",
      steps: [{ token: "intentEur", amountUsd: 10 }, { token: "intentEur", amountUsd: 10, currency: "EUR" }, { token: "intent500", amountUsd: 10, currency: "EUR" }, { token: "intent500", amountUsd: 10, currency: "USD" }],
    },
    {
      name: "merchant", description: "allowedMerchants: a missing merchant refuses (fail closed); a merchant off the list refuses.",
      steps: [{ token: "intentMerchants", amountUsd: 10 }, { token: "intentMerchants", amountUsd: 10, merchant: "did:web:other.example" }, { token: "intentMerchants", amountUsd: 10, merchant: MERCHANT }],
    },
    {
      name: "merchant-category", description: "merchantCategory: required and must match.",
      steps: [{ token: "intentCategory", amountUsd: 10 }, { token: "intentCategory", amountUsd: 10, merchantCategory: "5812" }, { token: "intentCategory", amountUsd: 10, merchantCategory: "5734" }],
    },
    {
      name: "human-approval", description: "Above requireHumanApprovalAboveUsd the server must assert humanApproved: true; at the threshold it need not.",
      steps: [{ token: "intentApproval", amountUsd: 150 }, { token: "intentApproval", amountUsd: 150, humanApproved: false }, { token: "intentApproval", amountUsd: 150, humanApproved: true }, { token: "intentApproval", amountUsd: 100 }],
    },
    {
      name: "session-limit", description: "The running-total limit is min(spendLimitUsd, sessionLimitUsd).",
      steps: [{ token: "intentSession", amountUsd: 250 }, { token: "intentSession", amountUsd: 150 }, { token: "intentSession", amountUsd: 100 }],
    },
    {
      name: "invalid-amounts", description: "Invalid amounts refuse with 400 before the presentation is checked, so the same header still works with a valid amount.",
      steps: [
        { token: "intent500", headerValue: "shared", amountFloat: "NaN" },
        { token: "intent500", headerValue: "shared", amountFloat: "Infinity" },
        { token: "intent500", headerValue: "shared", amountFloat: "-Infinity" },
        { token: "intent500", headerValue: "shared", amountUsd: -1 },
        { token: "intent500", headerValue: "shared", amountUsd: 0 },
        { token: "intent500", headerValue: "shared", amountUsd: 1e-7 },
        { token: "intent500", headerValue: "shared", amountUsd: 1e300 },
        { token: "intent500", headerValue: "shared", amountUsd: "5" },
        { token: "intent500", headerValue: "shared", amountUsd: true },
        { token: "intent500", headerValue: "shared", amountUsd: null },
        { token: "intent500", headerValue: "shared", amountUsd: 5 },
      ],
    },
    { name: "task-mandate", description: "A task mandate presented to a spending endpoint is refused.", steps: [{ token: "task", amountUsd: 10 }] },
    {
      name: "release-after-failed-side-effect", description: "release() returns the charge to every link.",
      steps: [{ token: "cartA400", amountUsd: 300 }, { release: 0 }, { token: "cartB400", amountUsd: 400 }],
    },
    {
      name: "presentation-and-chain-failures", description: "Refusals from the presentation (401) and the chain (403) keep their codes and charge nothing.",
      steps: [{ token: "intent500", amountUsd: 10, method: "PUT" }, { token: "intent500", amountUsd: 10, expectedRoot: "agent" }],
    },
    {
      name: "root-not-pinned", description: "expectedRoot supplied but null (a customer with no enrolled DID) refuses with ROOT_NOT_PINNED 403 without consuming the nonce: the same header then succeeds with the root pinned.",
      steps: [{ token: "intent500", headerValue: "shared", amountUsd: 10, expectedRoot: null }, { token: "intent500", headerValue: "shared", amountUsd: 10 }],
    },
    {
      name: "mandate-expiry-on-injected-clock", description: "The step's now (when given) is the one clock for the presentation, the nonce and the mandate: a fresh presentation of a mandate that expired before that clock is refused.",
      steps: [{ token: "intentShort", amountUsd: 10 }, { token: "intentShort", amountUsd: 10, now: LATER }],
    },
  ];

  const out = [];
  for (const c of cases) {
    const ledger = new MapSpendingLedger();
    const nonces = new InMemoryHttpPresentationNonces();
    const results: HttpSpendRequestResult[] = [];
    let shared: string | undefined;
    const steps = [];
    for (const s of c.steps) {
      if ("release" in s) {
        const r = results[s.release];
        if (!r?.ok) throw new Error(`${c.name}: release of a step that did not charge`);
        await r.charge.release();
        results.push(r);
        steps.push({ release: s.release });
        continue;
      }
      // The header is presented by the token's holder but signed for POST; a step with `method` is verified as that method.
      const headerValue = s.headerValue === "shared" ? (shared ??= await headerFor(s.token)) : await headerFor(s.token, { now: s.now });
      const amount = s.amountFloat !== undefined ? Number(s.amountFloat) : s.amountUsd;
      const expectedRoot = s.expectedRoot === null ? null : s.expectedRoot !== undefined ? keys[s.expectedRoot as KeyName].did : keys.human.did;
      const r = await verifyHttpSpendRequest(headerValue, {
        audience: AUDIENCE, method: s.method ?? "POST", url: URL_, body: BODY, nonces, now: Date.parse(s.now ?? NOW),
        expectedRoot, isRevoked: null, ledger, amountUsd: amount as number,
        currency: s.currency, merchant: s.merchant, merchantCategory: s.merchantCategory, humanApproved: s.humanApproved,
      });
      results.push(r);
      const { token, headerValue: _h, method, expectedRoot: er, now: stepNow, ...spend } = s;
      steps.push({
        token, headerValue, ...(method ? { method } : {}), ...(er !== undefined ? { expectedRoot } : {}), ...(stepNow ? { now: stepNow } : {}), ...spend,
        expected: r.ok
          ? { ok: true, chargedKeys: r.charge.allocations.map((a) => a.key) }
          : { ok: false, code: r.code, status: r.status },
      });
    }
    const totals: Record<string, number> = {};
    for (const [name, m] of Object.entries(bodies)) {
      const st = await ledger.status(mandateRedemptionKey(m));
      if (st && st.allocatedUsd !== 0) totals[`${name}`] = st.allocatedUsd;
    }
    out.push({ name: c.name, description: c.description, steps, expectedTotals: totals });
  }

  const doc = {
    description:
      "Cross-SDK vectors for verifyHttpSpendRequest (HTTP mandate presentation + spend enforcement). " +
      "Generated by packages/aroha-credentials/scripts/gen-http-spend-vectors.ts; do not edit by hand. " +
      "Each case starts with an empty ledger and nonce store. Request steps are verified with the top-level " +
      "audience, url, body and now (unless the step gives its own now: the one clock for presentation, nonce and " +
      "mandate expiry), method POST unless the step says otherwise, isRevoked null, and expectedRoot the human unless " +
      "the step has an expectedRoot member (null = supplied but empty, which must refuse with ROOT_NOT_PINNED). A step {release: i} releases the charge of step i. expectedTotals " +
      "gives each mandate's running total (by mandates[name]; keyed in the ledger by grantor#mandateId); " +
      "mandates not listed have a total of 0. amountFloat carries amounts JSON cannot (NaN, Infinity, -Infinity).",
    audience: AUDIENCE,
    url: URL_,
    body: BODY,
    now: NOW,
    keys: Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, { privateKeyHex: hex(k.priv), publicKeyHex: hex(k.pub), did: k.did }])),
    mandates: Object.fromEntries(Object.entries(bodies).map(([n, m]) => [n, { ledgerKey: mandateRedemptionKey(m), mandate: m }])),
    tokens,
    cases: out,
  };
  const path = fileURLToPath(new URL("../test-vectors/http-spend-v1.json", import.meta.url));
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  console.log(`wrote ${path}: ${out.length} cases, ${out.reduce((n, c) => n + c.steps.length, 0)} steps`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
