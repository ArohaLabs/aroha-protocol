// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { EvalCase, EvalResult, EvalReport, EvalSuite, RunEvalsOptions } from "./types.js";
import { judge as llmJudge } from "./judge.js";

/**
 * Post eval scores to an Aroha reputation endpoint so agent performance
 * measurements feed the registry's trust signals.
 *
 * @param didHash   Agent's didHash
 * @param report    Report from runEvals()
 * @param opts      Reputation service URL + auth
 */
export async function postEvalsToReputation(
  didHash:  string,
  report:   EvalReport,
  opts: {
    reputationUrl: string;
    apiKey:        string;
  },
): Promise<void> {
  const { summary } = report;
  if (summary.total === 0) return;

  const successRate = summary.passed / summary.total;
  const qualityScore = summary.avgJudgeScore ?? successRate;

  await fetch(`${opts.reputationUrl}/v1/signals`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${opts.apiKey}` },
    body:    JSON.stringify({
      agentDID:    didHash,
      source:      "evals",
      successRate,
      qualityScore,
      sampleSize:  summary.total,
      reportedAt:  report.runAt,
    }),
  });
}

async function runCase(
  evalCase:   EvalCase,
  opts:       RunEvalsOptions,
): Promise<EvalResult> {
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30_000);

    const res = await fetch(`${opts.endpoint.replace(/\/$/, "")}/v1/run`, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        ...(opts.bearerToken ? { Authorization: `Bearer ${opts.bearerToken}` } : {}),
      },
      body:    JSON.stringify({ message: evalCase.input, stream: true }),
      signal:  controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return {
        caseName: evalCase.name,
        outcome:  "error",
        input:    evalCase.input,
        output:   "",
        durationMs: Date.now() - start,
        error:    `HTTP ${res.status}: ${await res.text()}`,
      };
    }

    // Collect streaming events
    let output = "";
    const observedTrajectory: string[] = [];

    const body = res.body;
    if (body) {
      const decoder = new TextDecoder();
      const reader  = body.getReader();
      let buffer    = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith("data: ")) continue;
          try {
            const event = JSON.parse(line.slice(6)) as { type: string; delta?: string; name?: string; message?: string };
            if (event.type === "final")     output = event.message ?? "";
            if (event.type === "tool_call") observedTrajectory.push(event.name ?? "");
          } catch { /* skip */ }
        }
      }
    }

    const durationMs = Date.now() - start;

    // Exact string match
    let exactScore: number | undefined;
    if (evalCase.expected !== undefined) {
      const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");
      exactScore = norm(output) === norm(evalCase.expected) ? 1 : 0;
    }

    // Trajectory score
    let trajectoryScore: number | undefined;
    if (evalCase.expectedTrajectory?.length) {
      const expected = evalCase.expectedTrajectory;
      let matched = 0;
      let obsIdx  = 0;
      for (const step of expected) {
        while (obsIdx < observedTrajectory.length && observedTrajectory[obsIdx] !== step) obsIdx++;
        if (obsIdx < observedTrajectory.length) { matched++; obsIdx++; }
      }
      trajectoryScore = matched / expected.length;
    }

    // LLM-as-judge
    let judgeScore:     number | undefined;
    let judgeReasoning: string | undefined;

    if (opts.judge) {
      const judgment = await llmJudge({
        input:    evalCase.input,
        output,
        expected: evalCase.expected,
        judge:    opts.judge,
      });
      judgeScore     = judgment.score;
      judgeReasoning = judgment.reasoning;
    }

    // Determine outcome
    const threshold = opts.passThreshold ?? 0.7;
    let outcome: EvalResult["outcome"] = "pass";

    if (judgeScore !== undefined && judgeScore < threshold) outcome = "fail";
    if (exactScore !== undefined && exactScore < 1 && judgeScore === undefined) outcome = "fail";
    if (trajectoryScore !== undefined && trajectoryScore < threshold) outcome = "fail";

    return {
      caseName: evalCase.name,
      outcome,
      input:    evalCase.input,
      output,
      expected: evalCase.expected,
      exactScore,
      judgeScore,
      judgeReasoning,
      trajectoryScore,
      observedTrajectory: observedTrajectory.length ? observedTrajectory : undefined,
      durationMs,
    };
  } catch (err) {
    return {
      caseName:  evalCase.name,
      outcome:   "error",
      input:     evalCase.input,
      output:    "",
      durationMs: Date.now() - start,
      error:     err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Run an eval suite against an agent endpoint.
 * Returns a full EvalReport including per-case results and aggregate summary.
 */
export async function runEvals(
  suite:  EvalSuite,
  opts:   RunEvalsOptions,
): Promise<EvalReport> {
  const concurrency = opts.concurrency ?? 4;
  const cases       = suite.cases;
  const results:    EvalResult[] = [];

  // Process in batches of `concurrency`
  for (let i = 0; i < cases.length; i += concurrency) {
    const batch  = cases.slice(i, i + concurrency);
    const batch_results = await Promise.all(batch.map((c) => runCase(c, opts)));
    results.push(...batch_results);
  }

  const passed  = results.filter((r) => r.outcome === "pass").length;
  const failed  = results.filter((r) => r.outcome === "fail").length;
  const errored = results.filter((r) => r.outcome === "error").length;

  const judgedResults = results.filter((r) => r.judgeScore !== undefined);
  const avgJudgeScore = judgedResults.length
    ? judgedResults.reduce((s, r) => s + (r.judgeScore ?? 0), 0) / judgedResults.length
    : undefined;

  const trajResults = results.filter((r) => r.trajectoryScore !== undefined);
  const avgTrajectoryScore = trajResults.length
    ? trajResults.reduce((s, r) => s + (r.trajectoryScore ?? 0), 0) / trajResults.length
    : undefined;

  return {
    suite:    suite.name,
    endpoint: opts.endpoint,
    runAt:    new Date().toISOString(),
    results,
    summary: { total: cases.length, passed, failed, errored, avgJudgeScore, avgTrajectoryScore },
  };
}
