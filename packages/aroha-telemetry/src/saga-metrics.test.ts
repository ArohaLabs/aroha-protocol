// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { SagaMetrics, PrometheusBuffer, prometheusTextSink } from "./saga-metrics.js";

describe("SagaMetrics", () => {
  it("calls the sink with the event", () => {
    const sink = vi.fn();
    const metrics = new SagaMetrics(sink);
    metrics.record({ type: "saga_started", sagaId: "s1", stepCount: 3 });
    expect(sink).toHaveBeenCalledWith(expect.objectContaining({ type: "saga_started", sagaId: "s1" }));
  });

  it("PrometheusBuffer increments counters", () => {
    const buf = new PrometheusBuffer();
    buf.increment("aroha_saga_started_total", { agent: "did:aroha:a" });
    buf.increment("aroha_saga_started_total", { agent: "did:aroha:a" });
    expect(buf.getText()).toContain('aroha_saga_started_total{agent="did:aroha:a"} 2');
  });

  it("PrometheusBuffer observeHistogram produces cumulative buckets with _sum and _count", () => {
    const buf = new PrometheusBuffer();
    buf.observeHistogram("aroha_saga_duration_ms", 100);
    buf.observeHistogram("aroha_saga_duration_ms", 300);
    const text = buf.getText();
    // 100ms falls in ≤100, ≤250, ... ≤+Inf buckets
    expect(text).toContain('aroha_saga_duration_ms_bucket{le="100"} 1');
    expect(text).toContain('aroha_saga_duration_ms_bucket{le="250"} 2'); // cumulative: both 100+300
    expect(text).toContain('aroha_saga_duration_ms_sum 400');
    expect(text).toContain('aroha_saga_duration_ms_count 2');
  });

  it("prometheusTextSink increments on record", () => {
    const buf = new PrometheusBuffer();
    const metrics = new SagaMetrics(prometheusTextSink(buf));
    metrics.record({ type: "saga_committed", sagaId: "s2", agentDID: "did:aroha:b" });
    expect(buf.getText()).toContain("aroha_saga_committed_total");
  });
});
