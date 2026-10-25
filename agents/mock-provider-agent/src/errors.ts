// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Agent error model — shared by every bridge agent under agents/ (each agent
 * carries its own copy so the agents stay independently publishable and no
 * new surface is added to packages/*).
 *
 * Why this exists: before, every handler answered a failure with
 * `message: String(err)`, which forwarded whatever the upstream SaaS API
 * said — request URLs, internal record ids, validation text naming fields,
 * sometimes fragments of the request — to whichever peer sent the envelope.
 * Now there are three kinds of failure, and only the first one's text ever
 * leaves the process:
 *
 *   AgentError     — a refusal this agent decided on (bad params, unknown
 *                    token, approval required). Its message is written by
 *                    us, so it is safe to return verbatim.
 *   UpstreamError  — the third-party API said no. The detail is logged
 *                    locally; the peer gets a generic code chosen from the
 *                    HTTP status (see toErrorBody).
 *   anything else  — a bug or a network fault. Logged locally; the peer gets
 *                    Aroha_INTERNAL_ERROR / Aroha_SERVICE_UNAVAILABLE.
 */

import { ArohaErrorCode } from "@aroha-sdk/core";

export class AgentError extends Error {
  constructor(
    readonly code: ArohaErrorCode,
    message: string,
    readonly retryable = false,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AgentError";
  }
}

/** A parameter failed validation. Always safe to echo: we wrote the message. */
export function invalidParams(message: string): AgentError {
  return new AgentError(ArohaErrorCode.InvalidParams, message);
}

export class UpstreamError extends Error {
  constructor(
    readonly service: string,
    readonly status: number,
    /** Upstream response text — for the local log ONLY, never sent to a peer. */
    readonly detail: string,
  ) {
    super(`${service} API responded ${status}`);
    this.name = "UpstreamError";
  }
}

export interface ErrorBody {
  code: ArohaErrorCode;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}

/** Upper bound on how much upstream text reaches the local log per failure. */
const MAX_LOGGED_DETAIL = 500;

/**
 * Map any thrown value to the body of an ArohaError reply, logging the
 * non-public detail locally. `logPrefix` is the agent's usual "[X Agent]" tag.
 *
 * The log line never includes request headers, so credentials cannot end up
 * in it; upstream bodies are truncated because some APIs echo the request.
 */
export function toErrorBody(e: unknown, logPrefix: string): ErrorBody {
  if (e instanceof AgentError) {
    return { code: e.code, message: e.message, retryable: e.retryable, ...(e.details ? { details: e.details } : {}) };
  }
  if (e instanceof UpstreamError) {
    console.error(`${logPrefix} ${e.service} upstream ${e.status}: ${e.detail.slice(0, MAX_LOGGED_DETAIL)}`);
    return upstreamToBody(e.service, e.status);
  }
  console.error(`${logPrefix} unexpected failure:`, e instanceof Error ? e.message : e);
  // A TypeError from fetch() is how undici reports DNS/connect/TLS faults —
  // the dependency is unreachable, which is a retryable condition.
  if (e instanceof TypeError && /fetch failed/i.test(e.message)) {
    return { code: ArohaErrorCode.ServiceUnavailable, message: "Upstream service unreachable", retryable: true };
  }
  return { code: ArohaErrorCode.InternalError, message: "Internal error", retryable: false };
}

function upstreamToBody(service: string, status: number): ErrorBody {
  if (status === 400 || status === 422) {
    return { code: ArohaErrorCode.InvalidParams, message: `${service} rejected the request parameters`, retryable: false };
  }
  if (status === 404) {
    return { code: ArohaErrorCode.InvalidParams, message: `${service} resource not found`, retryable: false };
  }
  if (status === 409) {
    return { code: ArohaErrorCode.CommitFailed, message: `${service} reported a conflicting state`, retryable: false };
  }
  if (status === 429) {
    return { code: ArohaErrorCode.CapacityExceeded, message: `${service} rate limit reached`, retryable: true };
  }
  // 401/403 mean THIS agent's credential is wrong or under-scoped — an
  // operator problem, not the caller's, so it is reported as the dependency
  // being unavailable rather than as a permission error the caller could act on.
  return { code: ArohaErrorCode.ServiceUnavailable, message: `${service} request failed`, retryable: status >= 500 };
}
