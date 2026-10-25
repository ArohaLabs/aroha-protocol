// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { ArohaTracer, type SpanRecord } from "./tracer.js";

const TRACEPARENT_RE = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

describe("ArohaTracer", () => {
  // ─── startSagaSpan ──────────────────────────────────────────────────────────

  describe("startSagaSpan", () => {
    it("produces a root span with a valid traceparent", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("saga-xyz");
      expect(span.traceparent()).toMatch(TRACEPARENT_RE);
    });

    it("encodes saga id in the span name", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("my-saga");
      expect(span.name).toBe("saga:my-saga");
    });

    it("has no parentSpanId on a root span", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("saga-root");
      expect(span.parentSpanId).toBeUndefined();
    });

    it("each call produces a unique traceId", () => {
      const tracer = new ArohaTracer();
      const a = tracer.startSagaSpan("saga-1");
      const b = tracer.startSagaSpan("saga-2");
      expect(a.traceId).not.toBe(b.traceId);
    });
  });

  // ─── span.end ──────────────────────────────────────────────────────────────

  describe("span.end()", () => {
    it("returns a SpanRecord with a non-negative durationMs", async () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("saga-end");
      await new Promise((r) => setTimeout(r, 5));
      const record = span.end();
      expect(record.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("SpanRecord contains the correct traceId and spanId", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("saga-ids");
      const record = span.end();
      expect(record.traceId).toBe(span.traceId);
      expect(record.spanId).toBe(span.spanId);
    });

    it("SpanRecord traceparent matches span.traceparent()", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("saga-tp");
      const tp = span.traceparent();
      const record = span.end();
      expect(record.traceparent).toBe(tp);
    });
  });

  // ─── startChildSpan ────────────────────────────────────────────────────────

  describe("startChildSpan", () => {
    it("inherits the traceId from the parent traceparent", () => {
      const tracer = new ArohaTracer();
      const root = tracer.startSagaSpan("saga-parent");
      const child = tracer.startChildSpan("handle-request", root.traceparent());
      expect(child.traceId).toBe(root.traceId);
    });

    it("assigns a different spanId to the child", () => {
      const tracer = new ArohaTracer();
      const root = tracer.startSagaSpan("saga-ids");
      const child = tracer.startChildSpan("child-span", root.traceparent());
      expect(child.spanId).not.toBe(root.spanId);
    });

    it("sets parentSpanId to the parent's spanId", () => {
      const tracer = new ArohaTracer();
      const root = tracer.startSagaSpan("saga-link");
      const child = tracer.startChildSpan("child", root.traceparent());
      expect(child.parentSpanId).toBe(root.spanId);
    });

    it("child traceparent preserves the traceId", () => {
      const tracer = new ArohaTracer();
      const root = tracer.startSagaSpan("saga-chain");
      const child = tracer.startChildSpan("step", root.traceparent());
      const childTp = child.traceparent();
      expect(childTp).toMatch(TRACEPARENT_RE);
      expect(childTp.split("-")[1]).toBe(root.traceId);
    });

    it("generates a new traceId when the parent traceparent is invalid", () => {
      const tracer = new ArohaTracer();
      const child = tracer.startChildSpan("orphan", "not-a-valid-traceparent");
      expect(child.traceId).toMatch(/^[0-9a-f]{32}$/);
      expect(child.parentSpanId).toBeUndefined();
    });

    it("invokes onSpanEnd callback when child span ends", () => {
      const onSpanEnd = vi.fn();
      const tracer = new ArohaTracer({ onSpanEnd });
      const root = tracer.startSagaSpan("saga-cb");
      const child = tracer.startChildSpan("step", root.traceparent());
      child.end();
      expect(onSpanEnd).toHaveBeenCalledTimes(1);
      const record: SpanRecord = onSpanEnd.mock.calls[0][0];
      expect(record.name).toBe("step");
      expect(record.traceId).toBe(root.traceId);
    });

    it("does NOT invoke onSpanEnd for root saga spans", () => {
      const onSpanEnd = vi.fn();
      const tracer = new ArohaTracer({ onSpanEnd });
      const root = tracer.startSagaSpan("saga-no-cb");
      root.end();
      expect(onSpanEnd).not.toHaveBeenCalled();
    });
  });

  // ─── parseTraceparent ──────────────────────────────────────────────────────

  describe("parseTraceparent", () => {
    it("parses a valid W3C traceparent string", () => {
      const tracer = new ArohaTracer();
      const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
      const ctx = tracer.parseTraceparent(tp);
      expect(ctx).not.toBeNull();
      expect(ctx!.traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
      expect(ctx!.spanId).toBe("00f067aa0ba902b7");
      expect(ctx!.flags).toBe("01");
      expect(ctx!.traceparent).toBe(tp);
    });

    it("returns null for a string with the wrong number of segments", () => {
      const tracer = new ArohaTracer();
      expect(tracer.parseTraceparent("00-abc-def")).toBeNull();
    });

    it("returns null when the version is not '00'", () => {
      const tracer = new ArohaTracer();
      expect(
        tracer.parseTraceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
      ).toBeNull();
    });

    it("returns null when traceId has wrong length", () => {
      const tracer = new ArohaTracer();
      expect(
        tracer.parseTraceparent("00-tooshort-00f067aa0ba902b7-01")
      ).toBeNull();
    });

    it("returns null when spanId has wrong length", () => {
      const tracer = new ArohaTracer();
      expect(
        tracer.parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-short-01")
      ).toBeNull();
    });

    it("round-trips: span.traceparent() → parseTraceparent()", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startSagaSpan("round-trip");
      const tp = span.traceparent();
      const ctx = tracer.parseTraceparent(tp);
      expect(ctx).not.toBeNull();
      expect(ctx!.traceId).toBe(span.traceId);
      expect(ctx!.spanId).toBe(span.spanId);
    });
  });

  // ─── startRunSpan ──────────────────────────────────────────────────────────

  describe("startRunSpan", () => {
    it("produces a span named 'run:<agentName>'", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("my-agent", "claude-sonnet-4-6", "ses-1");
      expect(span.name).toBe("run:my-agent");
    });

    it("span.end() attaches static GenAI attributes", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("agent", "claude-opus-4-8", "ses-42");
      const record = span.end();
      expect(record.genAi?.["gen_ai.request.model"]).toBe("claude-opus-4-8");
      expect(record.genAi?.["gen_ai.aroha.session_id"]).toBe("ses-42");
    });

    it("merges runtime GenAI attributes with static ones", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("agent", "model", "ses");
      const record = span.end({
        "gen_ai.usage.input_tokens":  100,
        "gen_ai.usage.output_tokens": 50,
        "gen_ai.usage.total_tokens":  150,
      });
      expect(record.genAi?.["gen_ai.usage.input_tokens"]).toBe(100);
      expect(record.genAi?.["gen_ai.usage.output_tokens"]).toBe(50);
      expect(record.genAi?.["gen_ai.request.model"]).toBe("model");
    });

    it("includes trust attribute when provided", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("agent", "model", "ses", undefined, "untrusted");
      const record = span.end();
      expect(record.genAi?.["gen_ai.aroha.trust"]).toBe("untrusted");
    });

    it("omits trust attribute when not provided", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("agent", "model", "ses");
      const record = span.end();
      expect(record.genAi?.["gen_ai.aroha.trust"]).toBeUndefined();
    });

    it("links to parent trace when parentTraceparent is supplied", () => {
      const tracer = new ArohaTracer();
      const root = tracer.startSagaSpan("parent-saga");
      const span = tracer.startRunSpan("child-agent", "model", "ses", root.traceparent());
      expect(span.traceId).toBe(root.traceId);
      expect(span.parentSpanId).toBe(root.spanId);
    });

    it("creates a new root trace when no parentTraceparent", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("standalone", "model", "ses");
      expect(span.parentSpanId).toBeUndefined();
      expect(span.traceId).toMatch(/^[0-9a-f]{32}$/);
    });

    it("invokes onSpanEnd callback when run span ends", () => {
      const onSpanEnd = vi.fn();
      const tracer = new ArohaTracer({ onSpanEnd });
      const span = tracer.startRunSpan("agent", "model", "ses");
      span.end({ "gen_ai.usage.total_tokens": 99 });
      expect(onSpanEnd).toHaveBeenCalledTimes(1);
      const record: SpanRecord = onSpanEnd.mock.calls[0][0];
      expect(record.genAi?.["gen_ai.usage.total_tokens"]).toBe(99);
      expect(record.genAi?.["gen_ai.request.model"]).toBe("model");
    });

    it("runtime GenAI attributes override static ones", () => {
      const tracer = new ArohaTracer();
      const span = tracer.startRunSpan("agent", "original-model", "ses");
      const record = span.end({ "gen_ai.request.model": "override-model" });
      expect(record.genAi?.["gen_ai.request.model"]).toBe("override-model");
    });
  });
});
