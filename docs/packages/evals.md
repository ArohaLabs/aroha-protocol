<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/evals

LLM-as-judge evaluation framework for Aroha agents. Runs structured test suites against a live agent endpoint, scores outputs with exact match, tool-call trajectory and LLM-graded quality, and optionally posts results to a registry's reputation signals.

```bash
npm install @aroha-sdk/evals
```

---

## Quick start

```typescript
import { runEvals, type EvalSuite } from "@aroha-sdk/evals";

const suite: EvalSuite = {
  name: "Travel agent smoke tests",
  cases: [
    {
      name:     "Flight search",
      input:    "Find flights from London to Tokyo next Friday",
      expected: "LHR",                // compared with the whole output (trimmed, case- and whitespace-insensitive)
      tags:     ["smoke", "flights"],
    },
    {
      name:  "Currency conversion",
      input: "Convert 100 USD to JPY",
      expectedTrajectory: ["currency_convert"],  // must call this tool
    },
    {
      name:  "Off-topic rejection",
      input: "Write me a poem about cats",
      // No `expected` — the judge scores quality 0–1
    },
  ],
};

const report = await runEvals(suite, {
  endpoint:    "http://localhost:3000",  // agent base URL; /v1/run is appended
  bearerToken: process.env.AGENT_TOKEN,
  // Optional LLM-as-judge: any OpenAI-compatible chat completions API
  judge: { apiUrl: "https://api.openai.com/v1", apiKey: process.env.OPENAI_API_KEY ?? "", model: "gpt-4o-mini" },
  passThreshold: 0.7,                    // per-case minimum judge / trajectory score (default 0.7)
});

console.log(report.summary);
// { total: 3, passed: 2, failed: 1, errored: 0, avgJudgeScore: 0.82 }
```

---

## EvalCase

```typescript
export interface EvalCase {
  name:   string;
  input:  string;

  /** Expected output, compared after trimming, lower-casing and collapsing whitespace. */
  expected?: string;

  /**
   * Ordered list of tool call names expected in the response.
   * Partial matches are scored as a fraction (2/3 = 0.67).
   */
  expectedTrajectory?: string[];

  tags?: string[];
}
```

---

## EvalReport

```typescript
export interface EvalReport {
  suite:     string;
  endpoint:  string;
  runAt:     string;           // ISO 8601
  results:   EvalResult[];
  summary: {
    total:               number;
    passed:              number;
    failed:              number;
    errored:             number;
    avgJudgeScore?:      number;
    avgTrajectoryScore?: number;
  };
}

export interface EvalResult {
  caseName:            string;
  outcome:             "pass" | "fail" | "error";
  input:               string;
  output:              string;
  expected?:           string;
  exactScore?:         number;    // 1 when the normalised output equals `expected`
  judgeScore?:         number;    // 0–1 LLM-graded quality
  judgeReasoning?:     string;    // LLM's reasoning for the score
  trajectoryScore?:    number;    // 0–1 fraction of expected tools called, in order
  observedTrajectory?: string[];
  durationMs:          number;
  error?:              string;
}
```

---

## LLM-as-judge

When `judge` is set, every case is also scored by the judge model, which evaluates the output against the input (and `expected`, if given). A case fails when its judge score is below `passThreshold`; without a judge, a case with `expected` fails on an exact-match miss.

```typescript
import { judge } from "@aroha-sdk/evals";

const result = await judge({
  input:  "What is the capital of France?",
  output: "The capital of France is Paris.",
  judge:  { apiUrl: "https://api.openai.com/v1", apiKey: process.env.OPENAI_API_KEY!, model: "gpt-4o-mini" },
});
// { score: 1.0, reasoning: "Correct and concise answer." }
```

---

## Posting results to reputation

Evaluation scores can feed a registry's reputation signals. `postEvalsToReputation` posts the success rate and quality score to `<reputationUrl>/v1/signals`, which on the reference registry server is an admin route (Bearer admin secret) — use it with a registry you operate.

```typescript
import { runEvals, postEvalsToReputation } from "@aroha-sdk/evals";

const report = await runEvals(suite, { endpoint });

await postEvalsToReputation("agent-did-hash", report, {
  reputationUrl: process.env.REPUTATION_URL!,
  apiKey:        process.env.REPUTATION_API_KEY!,
});
```

---

## CLI usage

The package installs an `aroha-evals` binary (it is not a subcommand of `@aroha-sdk/cli`). It exits with status 1 when any case fails or errors.

```bash
# Run one eval suite (JSON file) against an agent
npx -p @aroha-sdk/evals aroha-evals run --endpoint http://localhost:3000 --suite evals/smoke.json

# Set the per-case pass threshold, and post results to a reputation service
npx -p @aroha-sdk/evals aroha-evals run --endpoint http://localhost:3000 --suite evals/smoke.json --threshold 0.8 --did <didHash> --reputation-url <url> --reputation-key <key>
```

Other flags: `--bearer`, `--judge-url`, `--judge-key`, `--judge-model` (default `gpt-4o-mini`), `--concurrency`, `--timeout`. Without `--judge-url`/`--judge-key`, the CLI uses the OpenAI API as judge when `OPENAI_API_KEY` is set.

---

## CI integration

```yaml
# .github/workflows/ci.yml
- name: Run agent evals
  run: npx -p @aroha-sdk/evals aroha-evals run --endpoint ${{ env.AGENT_URL }} --suite evals/smoke.json --threshold 0.8
```
