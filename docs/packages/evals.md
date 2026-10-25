<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/evals

LLM-as-judge evaluation framework for Aroha agents. Runs structured test suites against a live agent endpoint, scores outputs with exact match and LLM-graded quality, and optionally posts results to the Aroha reputation system.

```bash
npm install @aroha-sdk/evals
```

---

## Quick start

```typescript
import { runEvals } from "@aroha-sdk/evals";

const report = await runEvals({
  endpoint:    "http://localhost:3000",  // Your agent's /v1/run endpoint
  bearerToken: process.env.AGENT_TOKEN,
  judgeModel:  "claude-sonnet-4-6",     // Omit to skip LLM grading
  suite: {
    name: "Travel agent smoke tests",
    cases: [
      {
        name:     "Flight search",
        input:    "Find flights from London to Tokyo next Friday",
        expected: "LHR",                // Must appear in output
        tags:     ["smoke", "flights"],
      },
      {
        name:  "Currency conversion",
        input: "Convert 100 USD to JPY",
        expectedTrajectory: ["currency_convert"],  // Must call this tool
      },
      {
        name:  "Off-topic rejection",
        input: "Write me a poem about cats",
        // No `expected` — judge scores quality 0–1
      },
    ],
  },
});

console.log(report.summary);
// { total: 3, passed: 2, failed: 1, avgJudgeScore: 0.82 }
```

---

## EvalCase

```typescript
export interface EvalCase {
  name:   string;
  input:  string;

  /** Substring that must appear in the agent's output. */
  expected?: string;

  /**
   * Ordered list of tool call names expected in the response.
   * Partial matches are scored as a fraction (2/3 = 0.67).
   */
  expectedTrajectory?: string[];

  /** Tags for filtering with --tags flag in the CLI. */
  tags?: string[];
}
```

---

## EvalReport

```typescript
export interface EvalReport {
  suiteName: string;
  runAt:     string;           // ISO 8601
  results:   EvalResult[];
  summary: {
    total:         number;
    passed:        number;
    failed:        number;
    errors:        number;
    avgJudgeScore: number | null;
  };
}

export interface EvalResult {
  caseName:          string;
  outcome:           "pass" | "fail" | "error";
  input:             string;
  output:            string;
  expected?:         string;
  exactScore?:       number;    // 0–1 substring presence
  judgeScore?:       number;    // 0–1 LLM-graded quality
  judgeReasoning?:   string;    // LLM's reasoning for the score
  trajectoryScore?:  number;    // 0–1 fraction of expected tools called
  durationMs:        number;
}
```

---

## LLM-as-judge

When `judgeModel` is set, each case without an `expected` string (or that fails the exact match) is re-scored by a second Claude call that evaluates the output on task completion, factual accuracy, and relevance.

```typescript
import { judge } from "@aroha-sdk/evals";

const score = await judge({
  input:    "What is the capital of France?",
  output:   "The capital of France is Paris.",
  model:    "claude-sonnet-4-6",
});
// { score: 1.0, reasoning: "Correct and concise answer." }
```

---

## Posting results to reputation

Evaluation scores can feed the Aroha registry's trust signals, so high-performing agents are surfaced more prominently in discovery.

```typescript
import { runEvals, postEvalsToReputation } from "@aroha-sdk/evals";

const report = await runEvals({ endpoint, suite });

await postEvalsToReputation("agent-did-hash", report, {
  reputationUrl: process.env.REPUTATION_URL,
  apiKey:        process.env.REPUTATION_API_KEY,
});
```

---

## CLI usage

The package installs an `aroha-evals` binary (it is not a subcommand of `@aroha-sdk/cli`).

```bash
# Run one eval suite (JSON file) against an agent
npx -p @aroha-sdk/evals aroha-evals run --endpoint http://localhost:3000 --suite evals/smoke.json

# Fail if the pass rate is below a threshold, and post results to a reputation service
npx -p @aroha-sdk/evals aroha-evals run --endpoint http://localhost:3000 --suite evals/smoke.json --threshold 0.8 --did <didHash> --reputation-url <url> --reputation-key <key>
```

Other flags: `--bearer`, `--judge-url`, `--judge-key`, `--judge-model`, `--concurrency`, `--timeout`.

---

## CI integration

```yaml
# .github/workflows/ci.yml
- name: Run agent evals
  run: npx -p @aroha-sdk/evals aroha-evals run --endpoint ${{ env.AGENT_URL }} --suite evals/smoke.json --threshold 0.8
```
