// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Benchmark B1 — Single-hop signed envelope latency
 *
 * Measures end-to-end latency for building + signing + validating
 * a single ArohaEnvelope (the cryptographic overhead of one request/response).
 * See docs/benchmark-methodology.md §B1 for methodology.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { randomBytes } from "@noble/hashes/utils";
import { v4 as uuidv4 } from "uuid";

ed.etc.sha512Sync = (...m) => sha512(...m);

const WARM_REQUESTS = 1_000;

function percentile(sortedMs, p) {
  const idx = Math.ceil((p / 100) * sortedMs.length) - 1;
  return sortedMs[Math.max(0, idx)];
}

async function signEnvelope(from, to, privateKey) {
  const now = new Date();
  const expires = new Date(now.getTime() + 300_000);
  const envelope = {
    "@context": ["https://aroha-labs.com/contexts/v1"],
    id: `urn:uuid:${uuidv4()}`,
    type: "ArohaRequest",
    from,
    to,
    created: now.toISOString(),
    expires: expires.toISOString(),
    nonce: Buffer.from(randomBytes(32)).toString("hex"),
    correlationId: `saga-${uuidv4()}`,
    body: { capability: "benchmark", params: { run: "b1" } },
  };

  const payload = new TextEncoder().encode(
    JSON.stringify({ ...envelope, type: undefined }, Object.keys(envelope).sort())
  );
  const sig = await ed.signAsync(payload, privateKey);
  return { envelope, sig };
}

async function verifyEnvelope(envelope, sig, publicKey) {
  const payload = new TextEncoder().encode(
    JSON.stringify({ ...envelope, type: undefined }, Object.keys(envelope).sort())
  );
  return ed.verifyAsync(sig, payload, publicKey);
}

export async function runB1() {
  const senderPriv = ed.utils.randomPrivateKey();
  const senderPub = await ed.getPublicKeyAsync(senderPriv);
  const from = "did:aroha:benchmark-sender";
  const to = "did:aroha:benchmark-receiver";

  const latencies = [];

  for (let i = 0; i < WARM_REQUESTS; i++) {
    const t0 = performance.now();
    const { envelope, sig } = await signEnvelope(from, to, senderPriv);
    await verifyEnvelope(envelope, sig, senderPub);
    latencies.push(performance.now() - t0);
  }

  latencies.sort((a, b) => a - b);

  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const p99 = percentile(latencies, 99);
  const throughput = Math.round((WARM_REQUESTS / latencies.reduce((a, b) => a + b, 0)) * 1000);

  return {
    scenario: "B1",
    description: "Single-hop signed envelope (build + sign + verify)",
    requests: WARM_REQUESTS,
    latencyMs: {
      p50: parseFloat(p50.toFixed(3)),
      p95: parseFloat(p95.toFixed(3)),
      p99: parseFloat(p99.toFixed(3)),
    },
    throughput: { reqs_per_second: throughput },
  };
}

if (process.argv[1].endsWith("b1-single-hop.mjs")) {
  const result = await runB1();
  console.log(JSON.stringify(result, null, 2));
  console.log(`\np50: ${result.latencyMs.p50}ms  p95: ${result.latencyMs.p95}ms  p99: ${result.latencyMs.p99}ms`);
  console.log(`Throughput: ${result.throughput.reqs_per_second.toLocaleString()} req/s`);
}
