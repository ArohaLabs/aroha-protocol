// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/mandate-v2.json.
 *
 *   npx vite-node scripts/gen-test-vectors.ts
 *
 * The vectors are the cross-SDK contract for v2 mandate signing: a Python,
 * Go or Rust implementation passes when it reproduces every
 * `expected` / `expectedSigningPayload` / `expectedSignature` byte for byte
 * and reaches the same verdict on every token. Everything here is fixed
 * (keys from RFC 8032 §7.1, hard-coded ids and timestamps) and Ed25519 is
 * deterministic, so regenerating must produce an identical file. If it does
 * not, the canonical form changed — which is a protocol break, not a refresh.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody } from "@aroha-sdk/core";
import { canonicalizeJcs } from "../src/jcs.js";
import { mandateSigningPayloadV2 } from "../src/mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

// RFC 8032 §7.1 TEST 1 and TEST 2 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  human: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  agent: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  provider: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }

  // ── Pure JCS vectors (RFC 8785 §3.2.2 / §3.2.3 examples + mandate-relevant numbers)
  const jcsInputs: { name: string; input: string }[] = [
    {
      name: "rfc8785-3.2.2-sample",
      input: '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
    },
    {
      name: "rfc8785-3.2.3-key-sorting",
      input: '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
    },
    {
      name: "amounts",
      input: '{"a":42,"b":42.50,"c":42.07,"d":0.1,"e":1e21,"f":-0,"g":100.0,"h":1e-7}',
    },
    {
      name: "nested-and-whitespace",
      input: '{ "z" : [ 1 , { "y" : null , "x" : "é" } ] , "a" : { } }',
    },
  ];
  const jcs = jcsInputs.map(({ name, input }) => ({
    name,
    input,
    expected: canonicalizeJcs(JSON.parse(input)),
  }));

  // ── Mandate signing vectors
  const intent: ArohaSpendingMandateBody = {
    mandateTier: "intent",
    constraints: {
      spendLimitUsd: 500,
      sessionLimitUsd: 200.5,
      requireHumanApprovalAboveUsd: 100,
      allowedMerchants: ["did:aroha:merchant-a", "did:aroha:merchant-b"],
      validUntil: "2099-01-01T00:00:00.000Z",
    },
    grantee: keys.agent.did,
    grantor: keys.human.did,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z",
    parentMandateId: null,
    mandateId: "00000000-0000-4000-8000-000000000001",
  };
  const cart: ArohaSpendingMandateBody = {
    mandateTier: "cart",
    constraints: {
      spendLimitUsd: 42.07,
      sessionLimitUsd: 42.07,
      requireHumanApprovalAboveUsd: 100,
      allowedMerchants: ["did:aroha:merchant-a"],
      validUntil: "2099-01-01T00:00:00.000Z",
    },
    grantee: keys.provider.did,
    grantor: keys.agent.did,
    issuedAt: "2026-01-01T00:00:01.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z",
    parentMandateId: intent.mandateId,
    mandateId: "00000000-0000-4000-8000-000000000002",
  };
  // Correctly signed by the agent, but omits the parent's approval threshold
  // and raises the spend limit: must be REJECTED by a conforming verifier.
  const widenedCart: ArohaSpendingMandateBody = {
    ...cart,
    constraints: { spendLimitUsd: 1000, allowedMerchants: ["did:aroha:merchant-a"], validUntil: "2099-01-01T00:00:00.000Z" },
    mandateId: "00000000-0000-4000-8000-000000000003",
  };

  async function sign(signer: KeyName, mandate: ArohaSpendingMandateBody) {
    const payload = mandateSigningPayloadV2(mandate);
    const sig = await ed.signAsync(new TextEncoder().encode(payload), keys[signer].priv);
    return { payload, signature: Buffer.from(sig).toString("base64url") };
  }

  const mandates = [];
  const signed: Record<string, { mandate: ArohaSpendingMandateBody; signature: string }> = {};
  for (const [name, signer, mandate] of [
    ["intent-root", "human", intent],
    ["cart-child", "agent", cart],
    ["cart-widened", "agent", widenedCart],
  ] as const) {
    const { payload, signature } = await sign(signer, mandate);
    signed[name] = { mandate, signature };
    mandates.push({ name, signer, mandate, expectedSigningPayload: payload, expectedSignature: signature });
  }

  const tokenOf = (leaf: string, chain: string[]) =>
    Buffer.from(JSON.stringify({
      v: 2,
      mandate: signed[leaf].mandate,
      signature: signed[leaf].signature,
      chain: chain.map((c) => ({ v: 2, ...signed[c] })),
    })).toString("base64url");

  const tokens = [
    {
      name: "valid-intent-to-cart",
      token: tokenOf("cart-child", ["intent-root"]),
      verifyAt: "2027-01-01T00:00:00.000Z",
      expected: { valid: true, rootGrantor: keys.human.did, leafMandateId: cart.mandateId },
    },
    {
      name: "widened-child-rejected",
      token: tokenOf("cart-widened", ["intent-root"]),
      verifyAt: "2027-01-01T00:00:00.000Z",
      expected: { valid: false, reasonClass: "narrowing" },
    },
    {
      name: "expired-validUntil-rejected",
      token: tokenOf("cart-child", ["intent-root"]),
      verifyAt: "2099-06-01T00:00:00.000Z",
      expected: { valid: false, reasonClass: "time" },
    },
  ];

  const out = {
    description:
      "Aroha spending-mandate v2 conformance vectors. Canonicalisation is RFC 8785 (JCS). " +
      "A v2 signature is Ed25519(privateKey, UTF-8(JCS({\"mandate\": <body>, \"v\": 2}))), base64url without padding. " +
      "Tokens are base64url(JSON({v: 2, mandate, signature, chain})) with chain root-first, excluding the leaf. " +
      "Public keys resolve from content-addressed DIDs (did:aroha:z<base58btc(pubkey)>). Keys are the RFC 8032 §7.1 test keys — never use them for anything real.",
    generatedBy: "packages/aroha-credentials/scripts/gen-test-vectors.ts",
    keys: Object.fromEntries(
      (Object.keys(keys) as KeyName[]).map((n) => [n, { privateKeyHex: hex(keys[n].priv), publicKeyHex: hex(keys[n].pub), did: keys[n].did }])
    ),
    jcs,
    mandates,
    tokens,
  };

  const target = fileURLToPath(new URL("../test-vectors/mandate-v2.json", import.meta.url));
  writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${target}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
