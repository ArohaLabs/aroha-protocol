// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Benchmark Suite — Main Entry Point
 *
 * Runs all benchmark scenarios and writes results to benchmark-results/.
 * See docs/benchmark-methodology.md for the full methodology and
 * interpretation guide.
 *
 * Usage:
 *   npm run benchmark          # all scenarios
 *   npm run benchmark:b1       # single scenario
 */

import { writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import { runB1 } from "./b1-single-hop.mjs";
import { runB2 } from "./b2-discovery.mjs";
import { runB5 } from "./b5-crypto-throughput.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = join(__dirname, "../../benchmark-results");

function pad(s, n) { return String(s).padEnd(n); }

function printTable(result) {
  if (result.scenario === "B1") {
    console.log(`\n${result.description}`);
    console.log(`  Requests: ${result.requests.toLocaleString()}`);
    console.log(`  p50: ${result.latencyMs.p50}ms  p95: ${result.latencyMs.p95}ms  p99: ${result.latencyMs.p99}ms`);
    console.log(`  Throughput: ${result.throughput.reqs_per_second.toLocaleString()} req/s`);
  } else if (result.scenario === "B2") {
    console.log(`\n${result.description}`);
    console.log(`  ${pad("Registry size", 16)} ${pad("Avg latency", 14)}`);
    for (const r of result.results) {
      console.log(`  ${pad(r.registrySize.toLocaleString(), 16)} ${r.p50Ms}ms`);
    }
  } else if (result.scenario === "B5") {
    console.log(`\n${result.description}`);
    console.log(`  Signing:      ${result.signing.opsPerSecond.toLocaleString()} ops/s`);
    console.log(`  Verification: ${result.verification.opsPerSecond.toLocaleString()} ops/s`);
  }
}

async function main() {
  const date = new Date().toISOString().split("T")[0];
  const nodeVersion = process.version;

  console.log("Aroha Benchmark Suite");
  console.log("=====================");
  console.log(`Date:         ${date}`);
  console.log(`Node.js:      ${nodeVersion}`);
  console.log(`Platform:     ${process.platform} ${process.arch}`);
  console.log("\nRunning scenarios...");

  const scenarios = [
    { name: "B1 — Single-hop latency", run: runB1 },
    { name: "B2 — Capability discovery", run: runB2 },
    { name: "B5 — Ed25519 throughput", run: runB5 },
  ];

  const allResults = [];

  for (const { name, run } of scenarios) {
    process.stdout.write(`\nRunning ${name}... `);
    const t0 = Date.now();
    const result = await run();
    console.log(`done (${Date.now() - t0}ms)`);
    allResults.push(result);
    printTable(result);
  }

  // Write results artifact
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const artifact = {
    date,
    nodeVersion,
    platform: `${process.platform} ${process.arch}`,
    scenarios: allResults,
  };

  const outPath = join(OUTPUT_DIR, `benchmark-${date}.json`);
  writeFileSync(outPath, JSON.stringify(artifact, null, 2));
  console.log(`\nResults written to: ${outPath}`);
  console.log("ASSUMPTION: B3 (saga) and B4 (rollback) require a live agent network — not run here.");
  console.log("See docs/benchmark-methodology.md §B3 and §B4 for the manual runbook.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
