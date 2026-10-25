// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Best-effort OTLP/HTTP JSON span exporter.
 *
 * WHY THIS EXISTS. The tracer produced SpanRecords and left shipping them to
 * the host app. Most hosts never wired it, so a receipt's traceparent pointed
 * at a span no collector had. This exporter posts finished spans to any
 * OTLP/HTTP endpoint (`/v1/traces`, JSON encoding) with the platform `fetch`
 * — no OpenTelemetry SDK, no new dependency.
 *
 * BEST-EFFORT BY DESIGN. Telemetry must never change what an agent does:
 * export() never throws, never awaits the network on the caller's path, and a
 * collector that is down only costs dropped spans (counted in `stats`). The
 * queue is bounded (oldest spans are dropped first) so an unreachable
 * collector cannot grow memory without limit.
 *
 * gen_ai.* attributes are exported as recorded. The OpenTelemetry GenAI
 * conventions are not marked stable, so names may change upstream; nothing
 * here depends on a collector understanding them.
 */

import type { SpanRecord } from "./tracer.js";

export interface OtlpHttpExporterOptions {
  /** Full traces URL, e.g. "http://localhost:4318/v1/traces". */
  endpoint: string;
  /** service.name resource attribute. */
  serviceName: string;
  /** Extra resource attributes (e.g. service.version, deployment.environment). */
  resourceAttributes?: Record<string, string | number | boolean>;
  /** Extra request headers (e.g. an API key for a hosted collector). */
  headers?: Record<string, string>;
  /** Spans per request. Default 64. A full batch is sent immediately. */
  maxBatchSize?: number;
  /** Most spans held while the collector is unreachable. Default 2048. */
  maxQueueSize?: number;
  /** Send a partial batch after this many ms. Default 2000. 0 = only on flush() or a full batch. */
  flushIntervalMs?: number;
  /** Per-request timeout. Default 5000 ms. */
  timeoutMs?: number;
  /** Injected for tests. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

export interface OtlpExporterStats {
  exported: number;
  dropped: number;
  failedRequests: number;
}

type OtlpValue =
  | { stringValue: string }
  | { boolValue: boolean }
  | { intValue: string }
  | { doubleValue: number };

function toValue(v: string | number | boolean): OtlpValue {
  if (typeof v === "boolean") return { boolValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  return { stringValue: v };
}

function toAttributes(obj: Record<string, unknown> | undefined): { key: string; value: OtlpValue }[] {
  if (!obj) return [];
  const out: { key: string; value: OtlpValue }[] = [];
  for (const [key, v] of Object.entries(obj)) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out.push({ key, value: toValue(v) });
  }
  return out;
}

/** Milliseconds since epoch → OTLP's decimal-string nanoseconds. */
function nanos(ms: number): string {
  return (BigInt(Math.round(ms)) * 1_000_000n).toString();
}

/** One SpanRecord in OTLP/JSON form. Exported so tests and other sinks can reuse the mapping. */
export function spanRecordToOtlp(record: SpanRecord): Record<string, unknown> {
  const end = record.endTimeMs ?? Date.now();
  const start = record.startTimeMs ?? end - record.durationMs;
  return {
    traceId: record.traceId,
    spanId: record.spanId,
    ...(record.parentSpanId ? { parentSpanId: record.parentSpanId } : {}),
    name: record.name,
    kind: 1, // SPAN_KIND_INTERNAL
    startTimeUnixNano: nanos(start),
    endTimeUnixNano: nanos(end),
    attributes: [...toAttributes(record.genAi as Record<string, unknown> | undefined), ...toAttributes(record.attributes)],
  };
}

export class OtlpHttpExporter {
  readonly stats: OtlpExporterStats = { exported: 0, dropped: 0, failedRequests: 0 };
  private queue: SpanRecord[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private inflight = new Set<Promise<void>>();
  private readonly opts: Required<Omit<OtlpHttpExporterOptions, "resourceAttributes" | "headers" | "fetch">> &
    Pick<OtlpHttpExporterOptions, "resourceAttributes" | "headers" | "fetch">;

  constructor(options: OtlpHttpExporterOptions) {
    let url: URL;
    try {
      url = new URL(options.endpoint);
    } catch {
      throw new Error(`OtlpHttpExporter: endpoint is not a URL: ${options.endpoint}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("OtlpHttpExporter: endpoint must be http(s)");
    this.opts = {
      maxBatchSize: 64,
      maxQueueSize: 2048,
      flushIntervalMs: 2000,
      timeoutMs: 5000,
      ...options,
    };
  }

  /** Use as ArohaTracer's onSpanEnd: `new ArohaTracer({ onSpanEnd: exporter.export })`. Never throws. */
  readonly export = (record: SpanRecord): void => {
    try {
      this.queue.push(record);
      while (this.queue.length > this.opts.maxQueueSize) {
        this.queue.shift();
        this.stats.dropped++;
      }
      if (this.queue.length >= this.opts.maxBatchSize) {
        this.sendBatch();
      } else if (this.opts.flushIntervalMs > 0 && !this.timer) {
        this.timer = setTimeout(() => {
          this.timer = null;
          this.sendBatch();
        }, this.opts.flushIntervalMs);
        // Do not keep a process alive just to ship telemetry.
        (this.timer as { unref?: () => void }).unref?.();
      }
    } catch {
      this.stats.dropped++;
    }
  };

  /** Send everything queued and wait for in-flight requests. Resolves even when the collector is down. */
  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    while (this.queue.length > 0) this.sendBatch();
    await Promise.allSettled([...this.inflight]);
  }

  /** Flush and stop the timer. */
  async shutdown(): Promise<void> {
    await this.flush();
  }

  /** The OTLP/JSON request body for a batch. */
  body(batch: SpanRecord[]): Record<string, unknown> {
    return {
      resourceSpans: [{
        resource: { attributes: toAttributes({ "service.name": this.opts.serviceName, ...this.opts.resourceAttributes }) },
        scopeSpans: [{ scope: { name: "@aroha-sdk/telemetry" }, spans: batch.map(spanRecordToOtlp) }],
      }],
    };
  }

  private sendBatch(): void {
    const batch = this.queue.splice(0, this.opts.maxBatchSize);
    if (batch.length === 0) return;
    const p = this.post(batch).finally(() => this.inflight.delete(p));
    this.inflight.add(p);
  }

  private async post(batch: SpanRecord[]): Promise<void> {
    const doFetch = this.opts.fetch ?? globalThis.fetch;
    if (typeof doFetch !== "function") {
      this.stats.dropped += batch.length;
      return;
    }
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.opts.timeoutMs);
    (t as { unref?: () => void }).unref?.();
    try {
      const res = await doFetch(this.opts.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", ...this.opts.headers },
        body: JSON.stringify(this.body(batch)),
        signal: ac.signal,
      });
      if (res.ok) this.stats.exported += batch.length;
      else {
        this.stats.failedRequests++;
        this.stats.dropped += batch.length;
      }
    } catch {
      this.stats.failedRequests++;
      this.stats.dropped += batch.length;
    } finally {
      clearTimeout(t);
    }
  }
}
