<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/telemetry

Distributed tracing for multi-agent sagas using the W3C Trace Context standard (`traceparent`). Drop into any Aroha deployment to see every agent hop as a single distributed trace in Datadog, Grafana Tempo, Jaeger, or Honeycomb — no custom instrumentation required.

---

## The problem it solves

When a saga spans five agents across three vendors, a 500ms latency spike is impossible to diagnose from logs alone. You need distributed traces that correlate every message in the saga under a single trace ID, with each agent-to-agent hop as a child span.

---

## How it works

`@aroha-sdk/telemetry` uses the W3C Trace Context format:

```
traceparent: 00-{traceId:32hex}-{spanId:16hex}-{flags:2hex}
```

The `traceparent` is carried as a top-level field on every `ArohaEnvelope` — it's signed as part of the envelope so it can't be tampered with in transit. Each receiving agent extracts it, starts a child span, and propagates the same `traceId` forward.

---

## Installation

```bash
npm install @aroha-sdk/telemetry
```

No peer dependencies required — uses Node.js `crypto` for ID generation.
Optionally integrates with `@opentelemetry/api` if present in the host app.

---

## Quickstart

### Orchestrator side — start a trace

```typescript
import { ArohaTracer, TracingArohaClient } from "@aroha-sdk/telemetry";
import { ArohaClient } from "@aroha-sdk/core";

const tracer = new ArohaTracer({
  onSpanEnd: (record) => console.log("[trace]", record),
});

const client = new TracingArohaClient(new ArohaClient());

// Start a root span for this saga
const span = tracer.startSagaSpan(sagaId);
client.setActiveSpan(span);

// All subsequent client.send() calls automatically inject traceparent
await client.send(agentEndpoint, envelope);

const record = span.end();
console.log(`Saga trace: https://your-apm.example.com/trace/${record.traceId}`);
```

### Provider side — continue the trace

```typescript
import { ArohaTracer, createTracingMiddleware } from "@aroha-sdk/telemetry";

const tracer = new ArohaTracer();

const server = new ArohaServer({
  // ...
  middleware: [
    createTracingMiddleware(tracer, (span, envelope) => {
      // span.traceId links this agent to the orchestrator's trace
      console.log(`[${envelope.type}] traceId=${span.traceId}`);
    }),
  ],
});
```

---

## API

### `ArohaTracer`

```typescript
const tracer = new ArohaTracer({ onSpanEnd?: (record: SpanRecord) => void });

// Start a root span for a new saga
tracer.startSagaSpan(sagaId: string): Span

// Continue a trace from an inbound envelope's traceparent
tracer.startChildSpan(name: string, parentTraceparent: string): Span

// Parse a raw traceparent string
tracer.parseTraceparent(tp: string): TraceContext | null
```

### `Span`

```typescript
span.traceId: string       // W3C 128-bit trace ID
span.spanId: string        // W3C 64-bit span ID
span.traceparent(): string // "00-{traceId}-{spanId}-01"
span.end(): SpanRecord     // finish and capture duration
```

### `TracingArohaClient`

Wraps `ArohaClient` — all methods are identical. The active span's `traceparent` is automatically injected into every outbound envelope.

```typescript
const client = new TracingArohaClient(new ArohaClient());
client.setActiveSpan(span);    // inject into all sends
client.clearActiveSpan();      // stop injecting
```

### `createTracingMiddleware(tracer, onSpan?): ArohaMiddleware`

Server-side middleware. Extracts `traceparent` from the inbound envelope and fires `onSpan(span, envelope)` so application code can log or forward the active trace context.

### `OtlpHttpExporter` and receipt links

`new OtlpHttpExporter({ endpoint: "http://localhost:4318/v1/traces", serviceName })` posts finished spans to any OTLP/HTTP collector with `fetch` (JSON encoding, no OpenTelemetry SDK required). Pass `exporter.export` as the tracer's `onSpanEnd`, and call `await exporter.flush()` before exit. Export is best-effort: it never throws, holds at most `maxQueueSize` spans (oldest dropped first) and counts drops in `exporter.stats`. `gen_ai.*` attributes are exported as recorded. The upstream conventions are not yet stable.

`withReceiptTraceparent(receiptInput, span)` adds the span's `traceparent` to an action-receipt input before `signActionReceipt` from `@aroha-sdk/core`, so the signed receipt links to the span. `annotateSpanWithReceipt(record, actionReceiptHash(receipt))` links the span back to the receipt.

---

## Integrating with OpenTelemetry

If you already use `@opentelemetry/api`, bridge the span IDs:

```typescript
import * as otel from "@opentelemetry/api";
import { ArohaTracer } from "@aroha-sdk/telemetry";

const otelTracer = otel.trace.getTracer("aroha");

const tracer = new ArohaTracer({
  onSpanEnd: (record) => {
    // Use the Aroha traceId as the OTel trace ID for correlation
    const ctx = otel.propagation.extract(otel.context.active(), {
      traceparent: record.traceparent,
    });
    const span = otelTracer.startSpan(record.name, {}, ctx);
    span.end();
  },
});
```

---

## How traceparent flows through a saga

```
Orchestrator                Flight Agent              Hotel Agent
     │                           │                         │
startSagaSpan()                  │                         │
 traceId=abc123                  │                         │
     │                           │                         │
     ├── ArohaReserve ────────────>│                         │
     │    traceparent:            │                         │
     │    00-abc123-span1-01      │ startChildSpan()        │
     │                           │  parentSpanId=span1     │
     │<── ArohaReserveAck ─────────│                         │
     │                           │                         │
     ├── ArohaReserve ─────────────────────────────────────>│
     │    traceparent:            │                         │ startChildSpan()
     │    00-abc123-span2-01      │                         │  parentSpanId=span2
     │<── ArohaReserveAck ──────────────────────────────────│
     │                           │                         │
span.end()                       │                         │
```

All three agents appear in the same distributed trace under `traceId=abc123`.
