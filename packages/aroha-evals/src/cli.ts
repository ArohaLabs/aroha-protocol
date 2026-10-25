#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
/**
 * aroha-evals CLI
 *
 * Usage:
 *   npx @aroha-sdk/evals run --endpoint http://localhost:8000 --suite ./evals.json
 *   npx @aroha-sdk/evals run --endpoint https://my-agent.fly.dev --bearer $TOKEN --judge-model gpt-4o
 */

import { readFileSync } from "node:fs";
import { runEvals, postEvalsToReputation } from "./runner.js";
import type { EvalSuite, RunEvalsOptions } from "./types.js";

const args = process.argv.slice(2);
const cmd  = args[0];

function flag(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 ? args[idx + 1] : undefined;
}

if (cmd !== "run") {
  console.error(`Usage: aroha-evals run --endpoint <url> --suite <path> [--bearer <token>]`);
  console.error(`                       [--judge-url <url>] [--judge-key <key>] [--judge-model <model>]`);
  console.error(`                       [--threshold <0-1>] [--concurrency <n>]`);
  console.error(`                       [--did <didHash>] [--reputation-url <url>] [--reputation-key <key>]`);
  process.exit(1);
}

const endpoint  = flag("endpoint");
const suitePath = flag("suite");

if (!endpoint || !suitePath) {
  console.error("--endpoint and --suite are required");
  process.exit(1);
}

let suite: EvalSuite;
try {
  suite = JSON.parse(readFileSync(suitePath, "utf8")) as EvalSuite;
} catch (err) {
  console.error(`Failed to read suite: ${err}`);
  process.exit(1);
}

const opts: RunEvalsOptions = {
  endpoint,
  bearerToken:  flag("bearer"),
  passThreshold: flag("threshold") ? parseFloat(flag("threshold")!) : undefined,
  concurrency:   flag("concurrency") ? parseInt(flag("concurrency")!, 10) : undefined,
  timeoutMs:     flag("timeout") ? parseInt(flag("timeout")!, 10) : undefined,
};

const judgeUrl   = flag("judge-url")   ?? flag("judge-api-url");
const judgeKey   = flag("judge-key")   ?? flag("judge-api-key");
const judgeModel = flag("judge-model") ?? "gpt-4o-mini";

if (judgeUrl && judgeKey) {
  opts.judge = { apiUrl: judgeUrl, apiKey: judgeKey, model: judgeModel };
} else if (process.env.OPENAI_API_KEY) {
  opts.judge = {
    apiUrl:  "https://api.openai.com/v1",
    apiKey:  process.env.OPENAI_API_KEY,
    model:   judgeModel,
  };
}

console.log(`\nRunning eval suite "${suite.name}" against ${endpoint}`);
console.log(`Cases: ${suite.cases.length}  Concurrency: ${opts.concurrency ?? 4}\n`);

const report = await runEvals(suite, opts);

for (const r of report.results) {
  const icon = r.outcome === "pass" ? "✓" : r.outcome === "error" ? "✗" : "✗";
  const score = r.judgeScore !== undefined ? ` [judge: ${(r.judgeScore * 100).toFixed(0)}%]` : "";
  console.log(`  ${icon} ${r.caseName}${score}  (${r.durationMs}ms)`);
  if (r.outcome !== "pass" && r.error)           console.log(`      Error: ${r.error}`);
  if (r.outcome !== "pass" && r.judgeReasoning)  console.log(`      Judge: ${r.judgeReasoning}`);
}

const { summary } = report;
console.log(`\n─────────────────────────────────────────`);
console.log(`Total: ${summary.total}  Pass: ${summary.passed}  Fail: ${summary.failed}  Error: ${summary.errored}`);
if (summary.avgJudgeScore !== undefined)
  console.log(`Avg judge score: ${(summary.avgJudgeScore * 100).toFixed(1)}%`);
if (summary.avgTrajectoryScore !== undefined)
  console.log(`Avg trajectory score: ${(summary.avgTrajectoryScore * 100).toFixed(1)}%`);
console.log();

const reputationUrl = flag("reputation-url");
const reputationKey = flag("reputation-key");
const agentDid      = flag("did");

if (reputationUrl && reputationKey && agentDid) {
  try {
    await postEvalsToReputation(agentDid, report, { reputationUrl, apiKey: reputationKey });
    console.log(`✓ Scores posted to reputation service (${reputationUrl})\n`);
  } catch (err) {
    console.warn(`⚠ Failed to post scores to reputation service: ${err}\n`);
  }
}

process.exit(summary.failed + summary.errored > 0 ? 1 : 0);
