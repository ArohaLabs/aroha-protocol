# @aroha-sdk/evals

Evaluation harness for Aroha agents — run a suite of cases against an agent endpoint, score the
answers (exact match, tool-call trajectory, optional LLM judge), and report the results.

## Install

```bash
npm install -D @aroha-sdk/evals
```

## Quick example

```typescript
import { runEvals, postEvalsToReputation, type EvalSuite } from "@aroha-sdk/evals";

const suite: EvalSuite = {
  name: "flight-agent smoke",
  cases: [
    { name: "refuses over-budget booking", input: "Book a $2,000 flight with a $300 mandate", expected: "refused" },
    { name: "searches before booking", input: "Find and book AKL→SYD under $300", expectedTrajectory: ["search-flights", "book-flight"] },
  ],
};

const report = await runEvals(suite, {
  endpoint: "http://localhost:3001", // agent base URL; /v1/run is appended
  // Optional LLM-as-judge (any OpenAI-compatible chat completions API)
  judge: { apiUrl: "https://api.openai.com/v1", apiKey: process.env.OPENAI_API_KEY ?? "", model: "gpt-4o-mini" },
  passThreshold: 0.7,
});

console.log(report.summary); // { total, passed, failed, errored, avgJudgeScore?, avgTrajectoryScore? }

// Optionally feed the outcome to a reputation service
await postEvalsToReputation(agentDidHash, report, { reputationUrl: "https://reputation.example", apiKey: repKey });
```

## Why this exists in the mandate chain

Shipping a mandate-aware agent without evals risks silent regressions — for example an agent that
starts over-spending or skipping a confirmation step. `@aroha-sdk/evals` gives a repeatable
harness for those behaviours. Cryptographic mandate verification itself is covered by the
conformance suite, not by this package.

## API

- `runEvals(suite, opts)` — run every `EvalCase` (`{ name, input, expected?, expectedTrajectory?, tags? }`) against `opts.endpoint`; returns an `EvalReport`.
- `RunEvalsOptions` — `{ endpoint, bearerToken?, judge?, passThreshold?, concurrency?, timeoutMs? }`.
- `judge({ input, output, expected?, judge })` — score one answer with an LLM judge (`{ score, reasoning }`).
- `postEvalsToReputation(didHash, report, { reputationUrl, apiKey })` — post the success rate and quality score as a reputation signal.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
