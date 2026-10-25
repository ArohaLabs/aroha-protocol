# @aroha-sdk/telemetry

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/telemetry)

W3C trace-context propagation and saga metrics for Aroha agent chains — follow one request from
the orchestrator through every sub-agent, with OpenTelemetry GenAI attribute names.

## Install

```bash
npm install @aroha-sdk/telemetry
```

## Quick example

```typescript
import {
  ArohaTracer, TracingArohaClient, createTracingMiddleware,
  SagaMetrics, PrometheusBuffer, prometheusTextSink,
} from "@aroha-sdk/telemetry";
import { ArohaClient } from "@aroha-sdk/core";

// Spans are handed to you on end(); export them to any backend you like
const tracer = new ArohaTracer({ onSpanEnd: (record) => exportSpan(record) });

// Orchestrator: every outbound envelope carries the active span's traceparent
const client = new TracingArohaClient(new ArohaClient());
const sagaSpan = tracer.startSagaSpan("saga-123");
client.setActiveSpan(sagaSpan);
await client.send(flightAgentEndpoint, requestEnvelope);
sagaSpan.end();

// Sub-agent: continue the trace from the inbound envelope (ArohaServer middleware)
const tracing = createTracingMiddleware(tracer, (span, envelope) => {
  // ... handle the request, then:
  span.end();
});

// Saga metrics in Prometheus text format (pass `metrics` to SagaEngineOptions)
const buffer = new PrometheusBuffer();
const metrics = new SagaMetrics(prometheusTextSink(buffer));
const scrapeBody = buffer.getText(); // serve on /metrics
```

## Why this exists in the mandate chain

To audit or debug a multi-agent mandate chain, you need distributed traces that follow the work
from the orchestrator to every sub-agent. `traceparent` travels in the signed envelope, so the
whole chain can be stitched together in any trace backend.

## API

- `ArohaTracer({ onSpanEnd? })` — `startSagaSpan(sagaId)`, `startChildSpan(name, parentTraceparent)`, `startRunSpan(agentName, model, sessionId, parentTraceparent?, trust?)`, `parseTraceparent(tp)`.
- `Span` — `end(genAi?) → SpanRecord`, `traceparent()`; `GenAiAttributes` uses `gen_ai.*` names.
- `TracingArohaClient(client)` — injects `traceparent` into outbound envelopes (`setActiveSpan`, `clearActiveSpan`, `send`).
- `createTracingMiddleware(tracer, onSpan?)` — `ArohaServer` middleware.
- `SagaMetrics(sink)`, `consoleSink()`, `PrometheusBuffer`, `prometheusTextSink(buffer)`.
- `OtlpHttpExporter({ endpoint, serviceName, … })` sends spans to an OTLP/HTTP collector (`/v1/traces`, JSON) using `fetch`. Pass `exporter.export` as `onSpanEnd`, and call `flush()` or `shutdown()` on exit. Export is best-effort: it never throws, the queue is bounded, and failures are counted in `stats`.
- `withReceiptTraceparent(input, span)` puts a valid `traceparent` into an `@aroha-sdk/core` action-receipt input. `annotateSpanWithReceipt(record, receiptHash)` adds `aroha.action_receipt.hash` to a span record. `isValidTraceparent(tp)` checks the header format.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
