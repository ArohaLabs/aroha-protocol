// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// ── Eval case ─────────────────────────────────────────────────────────────────

export interface EvalCase {
  /** Human-readable name for this test case. */
  name:   string;
  /** The message sent to the agent. */
  input:  string;
  /** Optional expected output — used for exact/fuzzy string matching. */
  expected?: string;
  /**
   * Optional sequence of expected tool call names in order.
   * Used for trajectory evaluation — did the agent call the right tools?
   */
  expectedTrajectory?: string[];
  /** Optional tags for filtering / grouping results. */
  tags?:  string[];
}

export interface EvalSuite {
  /** Suite name shown in reports. */
  name:  string;
  cases: EvalCase[];
}

// ── Eval result ───────────────────────────────────────────────────────────────

export type EvalOutcome = "pass" | "fail" | "error";

export interface EvalResult {
  caseName:          string;
  outcome:           EvalOutcome;
  input:             string;
  output:            string;
  expected?:         string;
  /** Exact string match score 0–1. */
  exactScore?:       number;
  /** LLM-as-judge score 0–1, with reasoning. */
  judgeScore?:       number;
  judgeReasoning?:   string;
  /** Trajectory match fraction (matched steps / total expected). */
  trajectoryScore?:  number;
  observedTrajectory?: string[];
  durationMs:        number;
  error?:            string;
}

export interface EvalReport {
  suite:       string;
  endpoint:    string;
  runAt:       string;
  results:     EvalResult[];
  summary: {
    total:    number;
    passed:   number;
    failed:   number;
    errored:  number;
    /** Average judge score across all judged cases (0–1). */
    avgJudgeScore?: number;
    /** Average trajectory score across all trajectory cases (0–1). */
    avgTrajectoryScore?: number;
  };
}

// ── Runner options ────────────────────────────────────────────────────────────

export interface RunEvalsOptions {
  /** URL of the agent's /v1/run endpoint. */
  endpoint:      string;
  /** Bearer token for authenticated agents. */
  bearerToken?:  string;
  /**
   * LLM judge configuration. When provided, each case is graded by an LLM
   * that receives (input, output, expected?) and returns a score + reasoning.
   */
  judge?: {
    /** Any OpenAI-compatible chat completions endpoint. */
    apiUrl:   string;
    apiKey:   string;
    model:    string;
  };
  /**
   * Score threshold 0–1 below which a case is marked "fail".
   * Applies to judgeScore when a judge is configured. Default: 0.7
   */
  passThreshold?: number;
  /** Maximum concurrent agent calls. Default: 4 */
  concurrency?:   number;
  /** Timeout per case in ms. Default: 30000 */
  timeoutMs?:     number;
}
