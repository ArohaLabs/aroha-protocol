// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export interface SagaMetricEvent {
  type:
    | "saga_started"
    | "saga_committed"
    | "saga_compensated"
    | "saga_failed"
    | "compensation_dlq_push"
    | "compensation_dlq_resolved"
    | "envelope_rejected"
    | "nonce_replay_detected";
  sagaId?: string;
  agentDID?: string;
  capability?: string;
  durationMs?: number;
  stepCount?: number;
  reason?: string;
}

export type MetricSink = (event: SagaMetricEvent) => void;

export class SagaMetrics {
  constructor(private readonly sink: MetricSink = consoleSink()) {}

  record(event: SagaMetricEvent): void {
    this.sink(event);
  }
}

export function consoleSink(): MetricSink {
  return (event) => {
    console.log(JSON.stringify({ aroha_metric: true, ...event, ts: new Date().toISOString() }));
  };
}

export class PrometheusBuffer {
  private readonly counters = new Map<string, number>();
  private readonly histograms = new Map<string, { buckets: Map<number, number>; sum: number; count: number }>();
  private readonly metricTypes = new Map<string, "counter" | "histogram">();

  increment(name: string, labels: Record<string, string> = {}): void {
    this.metricTypes.set(name, "counter");
    const key = this.labelKey(name, labels);
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
  }

  observeHistogram(name: string, value: number, labels: Record<string, string> = {}): void {
    this.metricTypes.set(name, "histogram");
    const key = this.labelKey(name, labels);
    if (!this.histograms.has(key)) {
      // Standard bucket boundaries in ms: 10, 50, 100, 250, 500, 1000, 2500, 5000, +Inf
      this.histograms.set(key, {
        buckets: new Map([[10,0],[50,0],[100,0],[250,0],[500,0],[1000,0],[2500,0],[5000,0],[Infinity,0]]),
        sum: 0,
        count: 0,
      });
    }
    const h = this.histograms.get(key)!;
    h.sum += value;
    h.count += 1;
    for (const [le] of h.buckets) {
      if (value <= le) h.buckets.set(le, (h.buckets.get(le) ?? 0) + 1);
    }
  }

  getText(): string {
    const lines: string[] = [];

    for (const [metricName, type] of this.metricTypes) {
      lines.push(`# TYPE ${metricName} ${type}`);
    }

    for (const [key, val] of this.counters) {
      lines.push(`${key} ${val}`);
    }

    for (const [key, h] of this.histograms) {
      // key is "metric_name{labels...}" or just "metric_name"
      // extract base name and label string
      const braceIdx = key.indexOf("{");
      const baseName = braceIdx >= 0 ? key.slice(0, braceIdx) : key;
      const labelPart = braceIdx >= 0 ? key.slice(braceIdx, -1) : ""; // without closing }

      // Cumulative buckets (Prometheus requirement)
      let cumulative = 0;
      for (const [le, count] of h.buckets) {
        cumulative += count;
        const leLabel = le === Infinity ? '+Inf' : String(le);
        const allLabels = labelPart
          ? `{${labelPart.slice(1)},le="${leLabel}"}`
          : `{le="${leLabel}"}`;
        lines.push(`${baseName}_bucket${allLabels} ${cumulative}`);
      }
      const sumLabels = labelPart ? `{${labelPart.slice(1)}}` : "";
      lines.push(`${baseName}_sum${sumLabels} ${h.sum}`);
      lines.push(`${baseName}_count${sumLabels} ${h.count}`);
    }

    return lines.join("\n") + "\n";
  }

  private labelKey(name: string, labels: Record<string, string>): string {
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
    return labelStr ? `${name}{${labelStr}}` : name;
  }
}

export function prometheusTextSink(buffer: PrometheusBuffer): MetricSink {
  return (event) => {
    const labels: Record<string, string> = {};
    if (event.agentDID) labels["agent"] = event.agentDID;
    if (event.capability) labels["capability"] = event.capability;
    buffer.increment(`aroha_${event.type}_total`, labels);
    if (event.durationMs !== undefined) {
      buffer.observeHistogram("aroha_saga_duration_ms", event.durationMs, labels);
    }
  };
}
