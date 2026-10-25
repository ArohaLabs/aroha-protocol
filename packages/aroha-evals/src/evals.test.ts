// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runEvals, postEvalsToReputation } from "./runner.js";
import { judge } from "./judge.js";
import type { EvalSuite, EvalReport } from "./types.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeSuite(overrides: Partial<EvalSuite> = {}): EvalSuite {
  return {
    name: "test-suite",
    cases: [
      { name: "greeting", input: "Hello!", expected: "Hi there!" },
      { name: "math",     input: "What is 2+2?", expected: "4" },
    ],
    ...overrides,
  };
}

function mockAgentResponse(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain" },
  });
}

// ─── runEvals ─────────────────────────────────────────────────────────────────

describe("runEvals", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns a report with correct summary counts on pass", async () => {
    vi.mocked(fetch).mockResolvedValue(
      mockAgentResponse('data: {"type":"final","message":"Hi there!"}\n\n')
    );

    const suite = makeSuite({ cases: [{ name: "greeting", input: "Hello!", expected: "hi there!" }] });
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.suite).toBe("test-suite");
    expect(report.summary.total).toBe(1);
    expect(report.summary.passed).toBe(1);
    expect(report.summary.failed).toBe(0);
    expect(report.summary.errored).toBe(0);
    expect(report.results[0].outcome).toBe("pass");
    expect(report.results[0].output).toBe("Hi there!");
  });

  it("marks case as fail when exact string does not match", async () => {
    vi.mocked(fetch).mockResolvedValue(
      mockAgentResponse('data: {"type":"final","message":"Wrong answer"}\n\n')
    );

    const suite = makeSuite({ cases: [{ name: "math", input: "2+2", expected: "4" }] });
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.results[0].outcome).toBe("fail");
    expect(report.summary.failed).toBe(1);
  });

  it("marks case as error on HTTP failure", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("Internal Server Error", { status: 500 }));

    const suite = makeSuite({ cases: [{ name: "err-case", input: "boom" }] });
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.results[0].outcome).toBe("error");
    expect(report.results[0].error).toContain("500");
    expect(report.summary.errored).toBe(1);
  });

  it("marks case as error on network failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("ECONNREFUSED"));

    const suite = makeSuite({ cases: [{ name: "net-err", input: "ping" }] });
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.results[0].outcome).toBe("error");
    expect(report.results[0].error).toContain("ECONNREFUSED");
  });

  it("runs multiple cases and aggregates correctly", async () => {
    let call = 0;
    vi.mocked(fetch).mockImplementation(async () => {
      call++;
      const msg = call === 1 ? "hi there!" : "wrong";
      return mockAgentResponse(`data: {"type":"final","message":"${msg}"}\n\n`);
    });

    const suite = makeSuite();
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.summary.total).toBe(2);
    expect(report.summary.passed).toBe(1);
    expect(report.summary.failed).toBe(1);
  });

  it("records trajectory from tool_call events", async () => {
    const stream = [
      'data: {"type":"tool_call","name":"search"}',
      'data: {"type":"tool_call","name":"format"}',
      'data: {"type":"final","message":"done"}',
    ].join("\n\n") + "\n\n";

    vi.mocked(fetch).mockResolvedValue(mockAgentResponse(stream));

    const suite = makeSuite({
      cases: [{ name: "traj", input: "find and format", expectedTrajectory: ["search", "format"] }],
    });
    const report = await runEvals(suite, { endpoint: "http://agent.local" });

    expect(report.results[0].trajectoryScore).toBe(1);
    expect(report.results[0].observedTrajectory).toEqual(["search", "format"]);
  });

  it("attaches bearer token when provided", async () => {
    vi.mocked(fetch).mockResolvedValue(
      mockAgentResponse('data: {"type":"final","message":"ok"}\n\n')
    );

    await runEvals(makeSuite({ cases: [{ name: "auth", input: "hi" }] }), {
      endpoint: "http://agent.local",
      bearerToken: "tok-abc",
    });

    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer tok-abc");
  });
});

// ─── judge ────────────────────────────────────────────────────────────────────

describe("judge", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const cfg = { apiUrl: "https://api.openai.com/v1", apiKey: "sk-test", model: "gpt-4o-mini" };

  it("parses score and reasoning from JSON response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({
        choices: [{ message: { content: '{"score":0.9,"reasoning":"Good answer"}' } }],
      }), { status: 200 })
    );

    const result = await judge({ input: "hello", output: "hi", judge: cfg });
    expect(result.score).toBe(0.9);
    expect(result.reasoning).toBe("Good answer");
  });

  it("clamps score to [0, 1]", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({
        choices: [{ message: { content: '{"score":1.5,"reasoning":"too high"}' } }],
      }), { status: 200 })
    );

    const result = await judge({ input: "x", output: "y", judge: cfg });
    expect(result.score).toBe(1);
  });

  it("falls back to float extraction on malformed JSON", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({
        choices: [{ message: { content: "score: 0.75 — pretty good response" } }],
      }), { status: 200 })
    );

    const result = await judge({ input: "x", output: "y", judge: cfg });
    expect(result.score).toBeCloseTo(0.75);
  });

  it("throws on non-200 response", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("Unauthorized", { status: 401 }));

    await expect(judge({ input: "x", output: "y", judge: cfg })).rejects.toThrow("401");
  });
});

// ─── postEvalsToReputation ────────────────────────────────────────────────────

describe("postEvalsToReputation", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 200 }));
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const makeReport = (overrides: Partial<EvalReport["summary"]> = {}): EvalReport => ({
    suite: "test",
    endpoint: "http://agent.local",
    runAt: new Date().toISOString(),
    results: [],
    summary: { total: 10, passed: 8, failed: 2, errored: 0, ...overrides },
  });

  it("posts success rate to reputation service", async () => {
    await postEvalsToReputation("abc123", makeReport(), {
      reputationUrl: "https://rep.local",
      apiKey: "key",
    });

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://rep.local/v1/signals");
    const body = JSON.parse(init.body as string);
    expect(body.successRate).toBeCloseTo(0.8);
    expect(body.agentDID).toBe("abc123");
  });

  it("skips post when total is 0", async () => {
    await postEvalsToReputation("abc123", makeReport({ total: 0 }), {
      reputationUrl: "https://rep.local",
      apiKey: "key",
    });

    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("uses avgJudgeScore as qualityScore when available", async () => {
    await postEvalsToReputation("abc123", makeReport({ avgJudgeScore: 0.92 }), {
      reputationUrl: "https://rep.local",
      apiKey: "key",
    });

    const body = JSON.parse((vi.mocked(fetch).mock.calls[0][1] as RequestInit).body as string);
    expect(body.qualityScore).toBeCloseTo(0.92);
  });
});
