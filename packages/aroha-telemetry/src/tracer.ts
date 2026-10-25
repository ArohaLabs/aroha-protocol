// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Telemetry — Distributed Tracing
 *
 * Propagates W3C Trace Context (traceparent) through Aroha envelopes so that
 * multi-agent sagas appear as a single distributed trace in Datadog, Jaeger,
 * Grafana Tempo, or any W3C-compliant APM tool.
 *
 * Zero hard dependencies — uses Node.js crypto for ID generation.
 * Optionally integrates with @opentelemetry/api if present in the host app.
 */

import { randomBytes } from "crypto";

// ─── Traceparent format: 00-<traceId:32hex>-<spanId:16hex>-<flags:2hex> ───────

export interface TraceContext {
  traceId: string;   // 128-bit / 32 hex chars
  spanId: string;    // 64-bit / 16 hex chars
  flags: string;     // 8-bit / 2 hex chars (01 = sampled)
  traceparent: string;
}

function hexBytes(n: number): string {
  return randomBytes(n).toString("hex");
}

function parseTraceparent(tp: string): TraceContext | null {
  const parts = tp.split("-");
  if (parts.length !== 4 || parts[0] !== "00") return null;
  const [, traceId, spanId, flags] = parts;
  if (traceId.length !== 32 || spanId.length !== 16) return null;
  return { traceId, spanId, flags, traceparent: tp };
}

// ─── Span ─────────────────────────────────────────────────────────────────────

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTime: number;
  /** Finish the span and record its duration. Optionally attach GenAI attributes. */
  end(genAi?: GenAiAttributes): SpanRecord;
  /** Build the traceparent string to inject into the next outbound envelope. */
  traceparent(): string;
}

/**
 * OpenTelemetry GenAI semantic conventions (gen_ai.*).
 * Captured per /v1/run invocation when the agent emits usage/model data.
 * Ref: https://opentelemetry.io/docs/specs/semconv/gen-ai/
 */
export interface GenAiAttributes {
  /** gen_ai.system — e.g. "anthropic", "openai" */
  "gen_ai.system"?:                 string;
  /** gen_ai.request.model — e.g. "claude-sonnet-4-6" */
  "gen_ai.request.model"?:          string;
  /** gen_ai.usage.input_tokens */
  "gen_ai.usage.input_tokens"?:     number;
  /** gen_ai.usage.output_tokens */
  "gen_ai.usage.output_tokens"?:    number;
  /** gen_ai.usage.total_tokens */
  "gen_ai.usage.total_tokens"?:     number;
  /** Number of tool calls made during this invocation. */
  "gen_ai.tool_calls.count"?:       number;
  /** Name of the session (aroha sessionId). */
  "gen_ai.aroha.session_id"?:       string;
  /** Content trust level of the inbound request. */
  "gen_ai.aroha.trust"?:            "trusted" | "untrusted";
}

export interface SpanRecord {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  durationMs: number;
  traceparent: string;
  /** Wall-clock start and end (ms since epoch). Used by the OTLP exporter. */
  startTimeMs?: number;
  endTimeMs?: number;
  /** Extra span attributes (e.g. aroha.action_receipt.hash), exported as OTLP attributes. */
  attributes?: Record<string, string | number | boolean>;
  /** GenAI semantic convention attributes — populated when available. */
  genAi?: GenAiAttributes;
}

class SpanImpl implements Span {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly name: string;
  readonly startTime: number;

  constructor(name: string, traceId: string, parentSpanId?: string) {
    this.name = name;
    this.traceId = traceId;
    this.spanId = hexBytes(8);
    this.parentSpanId = parentSpanId;
    this.startTime = Date.now();
  }

  traceparent(): string {
    return `00-${this.traceId}-${this.spanId}-01`;
  }

  end(genAi?: GenAiAttributes): SpanRecord {
    return {
      traceId: this.traceId,
      spanId: this.spanId,
      parentSpanId: this.parentSpanId,
      name: this.name,
      durationMs: Date.now() - this.startTime,
      startTimeMs: this.startTime,
      endTimeMs: Date.now(),
      traceparent: this.traceparent(),
      ...(genAi && Object.keys(genAi).length ? { genAi } : {}),
    };
  }
}

// ─── Tracer ───────────────────────────────────────────────────────────────────

export class ArohaTracer {
  private readonly onSpanEnd?: (record: SpanRecord) => void;

  constructor(opts: { onSpanEnd?: (record: SpanRecord) => void } = {}) {
    this.onSpanEnd = opts.onSpanEnd;
  }

  /**
   * Start a new root span for a saga.
   * Use the returned span's .traceparent() to inject into outbound envelopes.
   */
  startSagaSpan(sagaId: string): Span {
    return new SpanImpl(`saga:${sagaId}`, hexBytes(16));
  }

  /**
   * Start a child span from an inbound envelope's traceparent.
   * Use for agent-side span creation when handling a request.
   */
  startChildSpan(name: string, parentTraceparent: string): Span {
    const parent = parseTraceparent(parentTraceparent);
    const traceId = parent?.traceId ?? hexBytes(16);
    const span = new SpanImpl(name, traceId, parent?.spanId);

    const originalEnd = span.end.bind(span);
    const onSpanEnd = this.onSpanEnd;
    (span as SpanImpl & { end: () => SpanRecord }).end = () => {
      const record = originalEnd();
      onSpanEnd?.(record);
      return record;
    };
    return span;
  }

  /**
   * Start a span for a /v1/run invocation with GenAI semantic conventions.
   * Call span.end(genAiAttrs) after the handler completes.
   *
   * @example
   * const span = tracer.startRunSpan("my-agent", "claude-sonnet-4-6", sessionId, parentTraceparent);
   * // ... run handler ...
   * span.end({ "gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 45 });
   */
  startRunSpan(
    agentName:          string,
    model:              string,
    sessionId:          string,
    parentTraceparent?: string,
    trust?:             "trusted" | "untrusted",
  ): Span {
    const traceId = parentTraceparent
      ? (parseTraceparent(parentTraceparent)?.traceId ?? hexBytes(16))
      : hexBytes(16);
    const parentSpanId = parentTraceparent
      ? parseTraceparent(parentTraceparent)?.spanId
      : undefined;

    const span = new SpanImpl(`run:${agentName}`, traceId, parentSpanId);

    // Pre-populate static GenAI attributes so they are present even if end() is called without them
    const staticGenAi: GenAiAttributes = {
      "gen_ai.request.model":      model,
      "gen_ai.aroha.session_id":   sessionId,
      ...(trust ? { "gen_ai.aroha.trust": trust } : {}),
    };

    const originalEnd = span.end.bind(span);
    (span as SpanImpl & { end: (g?: GenAiAttributes) => SpanRecord }).end = (genAi?: GenAiAttributes) => {
      const merged: GenAiAttributes = { ...staticGenAi, ...genAi };
      const record = originalEnd(merged);
      this.onSpanEnd?.(record);
      return record;
    };

    return span;
  }

  /** Parse a raw traceparent string into its components. */
  parseTraceparent(tp: string): TraceContext | null {
    return parseTraceparent(tp);
  }
}
