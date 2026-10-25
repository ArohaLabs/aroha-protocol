// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Linking signed action receipts to traces.
 *
 * An action receipt v2 (@aroha-sdk/core) has an optional, signed
 * `traceparent`. Putting the acting span's traceparent there lets an auditor
 * go from a receipt to the span (and its gen_ai.* attributes) in a
 * collector, and from a span back to the receipt via the
 * `aroha.action_receipt.hash` attribute.
 *
 * Kept free of a runtime import of @aroha-sdk/core: the helpers work on the
 * receipt input object structurally, so this package does not pin a core
 * version for what is a string copy.
 */

import type { Span, SpanRecord } from "./tracer.js";

/** W3C Trace Context traceparent, version 00, non-zero ids. */
const TRACEPARENT = /^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}$/;

export function isValidTraceparent(tp: unknown): tp is string {
  return typeof tp === "string" && TRACEPARENT.test(tp);
}

function traceparentOf(source: Span | SpanRecord | string): string {
  if (typeof source === "string") return source;
  if (typeof (source as Span).traceparent === "function") return (source as Span).traceparent();
  return (source as SpanRecord).traceparent;
}

/**
 * Return a copy of a receipt input with `traceparent` set from a span, span
 * record or raw header. An invalid traceparent is left out rather than
 * signed: a receipt must not carry a malformed link it can never resolve.
 *
 * @example
 *   const receipt = await signActionReceipt(withReceiptTraceparent(input, span), agentKey);
 */
export function withReceiptTraceparent<T extends object>(input: T, source: Span | SpanRecord | string | undefined): T & { traceparent?: string } {
  if (source === undefined) return input;
  const tp = traceparentOf(source);
  return isValidTraceparent(tp) ? { ...input, traceparent: tp } : input;
}

/** The span attribute that points from a span to a receipt (actionReceiptHash in @aroha-sdk/core). */
export const RECEIPT_HASH_ATTRIBUTE = "aroha.action_receipt.hash";

/** Attach a receipt hash to a finished span record before export. */
export function annotateSpanWithReceipt(record: SpanRecord, receiptHash: string): SpanRecord {
  return { ...record, attributes: { ...record.attributes, [RECEIPT_HASH_ATTRIBUTE]: receiptHash } };
}
