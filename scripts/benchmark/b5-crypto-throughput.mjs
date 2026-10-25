// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Benchmark B5 — Ed25519 Signing Throughput
 *
 * Measures raw sign/verify operations per second.
 * See docs/benchmark-methodology.md §B5 for methodology.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m) => sha512(...m);

const OPERATIONS = 10_000;

export async function runB5() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const message = new TextEncoder().encode("aroha-benchmark-payload-b5");

  // ── Signing ───────────────────────────────────────────────────────────────
  const signStart = performance.now();
  for (let i = 0; i < OPERATIONS; i++) {
    await ed.signAsync(message, privateKey);
  }
  const signMs = performance.now() - signStart;

  // ── Verification ──────────────────────────────────────────────────────────
  const sig = await ed.signAsync(message, privateKey);
  const verifyStart = performance.now();
  for (let i = 0; i < OPERATIONS; i++) {
    await ed.verifyAsync(sig, message, publicKey);
  }
  const verifyMs = performance.now() - verifyStart;

  return {
    scenario: "B5",
    description: "Ed25519 signing throughput",
    operations: OPERATIONS,
    signing: {
      totalMs: Math.round(signMs),
      opsPerSecond: Math.round((OPERATIONS / signMs) * 1000),
    },
    verification: {
      totalMs: Math.round(verifyMs),
      opsPerSecond: Math.round((OPERATIONS / verifyMs) * 1000),
    },
  };
}

if (process.argv[1].endsWith("b5-crypto-throughput.mjs")) {
  const result = await runB5();
  console.log(JSON.stringify(result, null, 2));
  console.log(`\nSigning:      ${result.signing.opsPerSecond.toLocaleString()} ops/s`);
  console.log(`Verification: ${result.verification.opsPerSecond.toLocaleString()} ops/s`);
}
