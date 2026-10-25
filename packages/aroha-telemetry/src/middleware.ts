// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Telemetry — Server middleware and client wrapper
 */

import { type ArohaMiddleware } from "@aroha-sdk/core";
import { type ArohaClient, type SendOptions } from "@aroha-sdk/core";
import { type ArohaEnvelope, buildEnvelope } from "@aroha-sdk/core";
import { type ArohaMessageType } from "@aroha-sdk/core";
import { ArohaTracer, type Span } from "./tracer.js";

// ─── Server middleware ────────────────────────────────────────────────────────

/**
 * Server-side tracing middleware.
 * Extracts traceparent from the inbound envelope and calls onSpan with the
 * active context so application code can continue the trace.
 */
export function createTracingMiddleware(
  tracer: ArohaTracer,
  onSpan?: (span: Span, envelope: ArohaEnvelope) => void
): ArohaMiddleware {
  return async (envelope, _reject) => {
    if (envelope.traceparent) {
      const span = tracer.startChildSpan(
        `aroha:${envelope.type}`,
        envelope.traceparent
      );
      onSpan?.(span, envelope);
    }
  };
}

// ─── Tracing client wrapper ───────────────────────────────────────────────────

/**
 * Wraps ArohaClient.send() to automatically inject the active span's
 * traceparent into every outbound envelope.
 *
 * Usage:
 *   const tracingClient = createTracingClient(client, tracer);
 *   const activeSpan = tracer.startSagaSpan(sagaId);
 *   tracingClient.setActiveSpan(activeSpan);
 */
export class TracingArohaClient {
  private activeSpan?: Span;

  constructor(private readonly inner: ArohaClient) {}

  setActiveSpan(span: Span): void {
    this.activeSpan = span;
  }

  clearActiveSpan(): void {
    this.activeSpan = undefined;
  }

  async send(
    endpoint: string,
    envelope: ArohaEnvelope,
    opts?: SendOptions
  ): Promise<ArohaEnvelope | null> {
    const traceparent = this.activeSpan?.traceparent();
    const outbound = traceparent ? { ...envelope, traceparent } : envelope;
    return this.inner.send(endpoint, outbound, opts);
  }

  stream(wsEndpoint: string, correlationId: string): AsyncIterable<ArohaEnvelope> {
    return this.inner.stream(wsEndpoint, correlationId);
  }

  fetchDIDDocument(agentBaseUrl: string): Promise<Record<string, unknown>> {
    return this.inner.fetchDIDDocument(agentBaseUrl);
  }
}
