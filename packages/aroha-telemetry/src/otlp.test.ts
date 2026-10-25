// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { ArohaTracer } from "./tracer.js";
import { OtlpHttpExporter, spanRecordToOtlp } from "./otlp.js";
import { annotateSpanWithReceipt, isValidTraceparent, withReceiptTraceparent, RECEIPT_HASH_ATTRIBUTE } from "./receipt-trace.js";

describe("OtlpHttpExporter", () => {
  it("posts OTLP/JSON spans to a real HTTP collector", async () => {
    const bodies: any[] = [];
    const server = createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        bodies.push({ path: req.url, ct: req.headers["content-type"], json: JSON.parse(data) });
        res.writeHead(200, { "content-type": "application/json" }).end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      const exporter = new OtlpHttpExporter({ endpoint: `http://127.0.0.1:${port}/v1/traces`, serviceName: "test-agent", flushIntervalMs: 0 });
      const tracer = new ArohaTracer({ onSpanEnd: exporter.export });
      const span = tracer.startRunSpan("agent", "model-x", "sess-1", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
      span.end({ "gen_ai.usage.input_tokens": 12 });
      await exporter.flush();
      expect(exporter.stats).toEqual({ exported: 1, dropped: 0, failedRequests: 0 });
      expect(bodies[0].path).toBe("/v1/traces");
      expect(bodies[0].ct).toBe("application/json");
      const rs = bodies[0].json.resourceSpans[0];
      expect(rs.resource.attributes).toContainEqual({ key: "service.name", value: { stringValue: "test-agent" } });
      const s = rs.scopeSpans[0].spans[0];
      expect(s.traceId).toBe("0af7651916cd43dd8448eb211c80319c");
      expect(s.parentSpanId).toBe("b7ad6b7169203331");
      expect(s.attributes).toContainEqual({ key: "gen_ai.usage.input_tokens", value: { intValue: "12" } });
      expect(BigInt(s.endTimeUnixNano) >= BigInt(s.startTimeUnixNano)).toBe(true);
    } finally {
      server.close();
    }
  });

  it("never throws when the collector is unreachable; spans are counted as dropped", async () => {
    const exporter = new OtlpHttpExporter({
      endpoint: "http://127.0.0.1:9/v1/traces", serviceName: "x", flushIntervalMs: 0, timeoutMs: 500,
      fetch: (async () => { throw new Error("ECONNREFUSED"); }) as typeof fetch,
    });
    const tracer = new ArohaTracer({ onSpanEnd: exporter.export });
    tracer.startChildSpan("a", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").end();
    await exporter.flush();
    expect(exporter.stats.dropped).toBe(1);
    expect(exporter.stats.failedRequests).toBe(1);
  });

  it("bounds the queue", async () => {
    const exporter = new OtlpHttpExporter({ endpoint: "http://127.0.0.1:9/v1/traces", serviceName: "x", flushIntervalMs: 0, maxBatchSize: 1000, maxQueueSize: 3, fetch: (async () => new Response("", { status: 200 })) as typeof fetch });
    const tracer = new ArohaTracer({ onSpanEnd: exporter.export });
    for (let i = 0; i < 5; i++) tracer.startChildSpan(`s${i}`, "").end();
    expect(exporter.stats.dropped).toBe(2);
    await exporter.flush();
    expect(exporter.stats.exported).toBe(3);
  });

  it("refuses a non-http endpoint at construction", () => {
    expect(() => new OtlpHttpExporter({ endpoint: "file:///tmp/x", serviceName: "x" })).toThrow();
  });
});

describe("receipt trace links", () => {
  it("puts a span's traceparent into a receipt input, and refuses a malformed one", () => {
    const tracer = new ArohaTracer();
    const span = tracer.startSagaSpan("s1");
    const input = withReceiptTraceparent({ agentDid: "did:aroha:z1", action: "x" }, span);
    expect(isValidTraceparent(input.traceparent)).toBe(true);
    expect(input.traceparent).toBe(span.traceparent());
    expect(withReceiptTraceparent({ a: 1 }, "not-a-traceparent")).toEqual({ a: 1 });
    expect(withReceiptTraceparent({ a: 1 }, "00-00000000000000000000000000000000-b7ad6b7169203331-01")).toEqual({ a: 1 });
  });

  it("annotates a span record with the receipt hash as an OTLP attribute", () => {
    const rec = new ArohaTracer().startChildSpan("act", "").end();
    const otlp = spanRecordToOtlp(annotateSpanWithReceipt(rec, "ab".repeat(32))) as { attributes: unknown[] };
    expect(otlp.attributes).toContainEqual({ key: RECEIPT_HASH_ATTRIBUTE, value: { stringValue: "ab".repeat(32) } });
  });
});
