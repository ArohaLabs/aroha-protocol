// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Telemetry — Server middleware and client wrapper
 */

import { type ArohaMiddleware } from "@aroha-sdk/core";
import { type ArohaClient, type SendOptions } from "@aroha-sdk/core";
import { type ArohaEnvelope, type BuildEnvelopeOptions, buildEnvelope } from "@aroha-sdk/core";
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
 * Wraps ArohaClient so outbound envelopes carry the active span's traceparent.
 *
 * `traceparent` is part of the signed envelope (canonicalisation excludes only
 * `proof`), so it has to be in place BEFORE signing. Build signed envelopes with
 * `tracingClient.buildEnvelope(...)`, which passes the active span's
 * traceparent to core's `buildEnvelope`. `send()` never modifies an envelope
 * that already carries a `proof`: adding a field after signing would make the
 * receiver reject it. Only unsigned (trusted-mesh) envelopes get a traceparent
 * added in `send()`.
 *
 * Usage:
 *   const tracingClient = new TracingArohaClient(new ArohaClient());
 *   tracingClient.setActiveSpan(tracer.startSagaSpan(sagaId));
 *   const envelope = await tracingClient.buildEnvelope(type, from, to, body, correlationId, privateKey);
 *   await tracingClient.send(endpoint, envelope);
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

  /**
   * Build and sign an envelope with core's `buildEnvelope`, carrying the active
   * span's traceparent so it is covered by the signature. An explicit
   * `opts.traceparent` takes precedence over the active span.
   */
  async buildEnvelope<T extends ArohaMessageType>(
    type: T,
    from: string,
    to: string,
    body: Parameters<typeof buildEnvelope<T>>[3],
    correlationId: string,
    privateKey: Uint8Array,
    opts: BuildEnvelopeOptions = {}
  ): Promise<ArohaEnvelope<T>> {
    const traceparent = opts.traceparent ?? this.activeSpan?.traceparent();
    return buildEnvelope(type, from, to, body, correlationId, privateKey, {
      ...opts,
      ...(traceparent ? { traceparent } : {}),
    });
  }

  /**
   * Send an envelope. A signed envelope (one with a `proof`) is passed through
   * unchanged; build it with `buildEnvelope()` above to trace it. An unsigned
   * envelope without a traceparent gets the active span's traceparent.
   */
  async send(
    endpoint: string,
    envelope: ArohaEnvelope,
    opts?: SendOptions
  ): Promise<ArohaEnvelope | null> {
    const traceparent = this.activeSpan?.traceparent();
    const canAdd = traceparent && !envelope.proof && !envelope.traceparent;
    const outbound = canAdd ? { ...envelope, traceparent } : envelope;
    return this.inner.send(endpoint, outbound, opts);
  }

  stream(wsEndpoint: string, correlationId: string): AsyncIterable<ArohaEnvelope> {
    return this.inner.stream(wsEndpoint, correlationId);
  }

  fetchDIDDocument(agentBaseUrl: string): Promise<Record<string, unknown>> {
    return this.inner.fetchDIDDocument(agentBaseUrl);
  }
}
