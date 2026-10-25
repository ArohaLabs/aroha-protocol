// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Benchmark B2 — Capability Discovery
 *
 * Measures time to resolve a capability query against an in-memory registry
 * at sizes of 10, 100, and 1,000 entries.
 * See docs/benchmark-methodology.md §B2 for methodology.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m) => sha512(...m);

const QUERIES_PER_SIZE = 500;

async function makePublicKey() {
  const priv = ed.utils.randomPrivateKey();
  return ed.getPublicKeyAsync(priv);
}

// Inline minimal registry to avoid TypeScript build dependency
class MinimalRegistry {
  records = new Map();
  capabilityIndex = new Map();

  hashKey(s) {
    let h = 0n;
    for (const c of s) h = (h * 31n + BigInt(c.charCodeAt(0))) & 0xffffffffn;
    return h.toString(16);
  }

  async register(did, pubKey, capabilityIds = []) {
    const record = { did, publicKeyB64: Buffer.from(pubKey).toString("base64url"), active: true };
    this.records.set(did, record);
    for (const cap of capabilityIds) {
      const key = this.hashKey(cap);
      if (!this.capabilityIndex.has(key)) this.capabilityIndex.set(key, new Set());
      this.capabilityIndex.get(key).add(did);
    }
  }

  queryByCapability(capIds) {
    const matched = new Set();
    for (const cap of capIds) {
      const key = this.hashKey(cap);
      const agents = this.capabilityIndex.get(key);
      if (agents) for (const did of agents) matched.add(did);
    }
    return Array.from(matched).map((did) => this.records.get(did)).filter(Boolean);
  }
}

async function benchmarkAtSize(size) {
  const registry = new MinimalRegistry();
  const capabilities = ["book-flight", "book-hotel", "currency-conversion", "process-payment"];

  for (let i = 0; i < size; i++) {
    const pubKey = await makePublicKey();
    const cap = capabilities[i % capabilities.length];
    await registry.register(`did:aroha:agent-${i}`, pubKey, [cap]);
  }

  const start = performance.now();
  for (let i = 0; i < QUERIES_PER_SIZE; i++) {
    registry.queryByCapability(["book-flight"]);
  }
  const totalMs = performance.now() - start;

  return {
    registrySize: size,
    queries: QUERIES_PER_SIZE,
    totalMs: Math.round(totalMs),
    p50Ms: parseFloat((totalMs / QUERIES_PER_SIZE).toFixed(3)),
  };
}

export async function runB2() {
  const sizes = [10, 100, 1000];
  const results = await Promise.all(sizes.map(benchmarkAtSize));

  return {
    scenario: "B2",
    description: "Capability discovery latency vs registry size",
    results,
  };
}

if (process.argv[1].endsWith("b2-discovery.mjs")) {
  const result = await runB2();
  console.log(JSON.stringify(result, null, 2));
  for (const r of result.results) {
    console.log(`\nRegistry size ${r.registrySize.toLocaleString()}: avg ${r.p50Ms}ms/query`);
  }
}
