// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Offline verification cost of a two-link mandate chain (human -> orchestrator -> agent).
// No network: content-addressed did:aroha:z DIDs resolve locally. Revocation lookup is not
// included; add your revocation hook's own latency on top.
// Run after `npm run build`:  npm run benchmark:b6
import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, attenuateToPayment, verifyMandateChain } from "@aroha-sdk/credentials";
const h = await generateKeyPair(), o = await generateKeyPair(), f = await generateKeyPair();
const H = generateDid(h.publicKey), O = generateDid(o.publicKey), F = generateDid(f.publicKey);
const intent = await issueIntentMandate(H, O, { spendLimitUsd: 500, merchantCategory: "4511" }, h.privateKey, 3_600_000);
const pay = await attenuateToPayment(intent, F, { spendLimitUsd: 300, merchantCategory: "4511" }, o.privateKey);
const r0 = await verifyMandateChain(pay.token, undefined, { expectedRoot: H, expectedGrantee: F });
if (!r0.valid || !r0.chainVerified) throw new Error("chain did not verify: " + r0.reason);
process.removeAllListeners("warning");
for (let i = 0; i < 200; i++) await verifyMandateChain(pay.token, undefined, { expectedRoot: H, expectedGrantee: F });
const N = 2000, t = [];
for (let i = 0; i < N; i++) { const s = process.hrtime.bigint(); await verifyMandateChain(pay.token, undefined, { expectedRoot: H, expectedGrantee: F }); t.push(Number(process.hrtime.bigint() - s) / 1e6); }
t.sort((a, b) => a - b);
const q = p => t[Math.floor(p * N)].toFixed(3);
console.log(JSON.stringify({ node: process.version, links: 2, tokenBytes: Buffer.byteLength(pay.token), iterations: N, p50ms: q(0.5), p95ms: q(0.95), p99ms: q(0.99), network: "none" }));
