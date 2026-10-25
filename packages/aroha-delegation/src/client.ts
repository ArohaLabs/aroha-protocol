// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Root-caller side of a delegation web. The originator (a human's personal
// agent, a CLI, an orchestrator entry point) issues the ROOT mandate and
// calls the first agent; every hop after that uses ctx.delegate().

import { randomUUID } from "node:crypto";
import * as ed from "@noble/ed25519";
import type { TaskConstraints } from "@aroha-sdk/core";
import { assertSecureEndpoint } from "@aroha-sdk/core/endpoints";
import { issueTaskMandate } from "@aroha-sdk/credentials";
import type { RunResponse } from "@aroha-sdk/run";
import { DELEGATION_CONTEXT_KEY, type DelegationEnvelope } from "./chain.js";
import { RECEIPT_ARTIFACT_KIND, type TaskReceiptArtifact } from "./receipts.js";

export interface RootIdentity {
  did: string;
  privateKey: Uint8Array;
}

export interface IssueDelegationOptions {
  allowed: string[];
  constraints?: TaskConstraints;
  blocked?: string[];
  ttlMs?: number;
  correlationId?: string;
}

/**
 * Issue a root task mandate to `granteeDID` and wrap it in the envelope that
 * rides RunRequest.context from hop to hop.
 */
export async function issueDelegation(
  root: RootIdentity,
  granteeDID: string,
  options: IssueDelegationOptions
): Promise<{ envelope: DelegationEnvelope; context: Record<string, unknown> }> {
  const signed = await issueTaskMandate(
    root.did,
    granteeDID,
    options.allowed,
    options.constraints ?? {},
    root.privateKey,
    options.ttlMs ?? 3_600_000,
    { blocked: options.blocked }
  );

  const rootPub = await ed.getPublicKeyAsync(root.privateKey);
  const envelope: DelegationEnvelope = {
    v: 1,
    chain: [signed.token],
    rootKeyB64: Buffer.from(rootPub).toString("base64"),
    correlationId: options.correlationId ?? randomUUID(),
  };

  return { envelope, context: { [DELEGATION_CONTEXT_KEY]: envelope } };
}

export interface CallDelegatedOptions {
  sessionId?: string;
  bearerToken?: string;
  extraContext?: Record<string, unknown>;
  /**
   * DEVELOPMENT ONLY: allow http:// to a non-loopback endpoint. The request
   * carries the whole mandate chain and any bearer token; in cleartext every
   * hop on the path can copy and replay them.
   */
  allowInsecureHttp?: boolean;
  /** Request timeout in ms. Default 120 000 (delegated runs can be long). */
  timeoutMs?: number;
}

export interface DelegatedResponse extends RunResponse {
  /** Task receipts extracted from the response's artifacts, if the callee emitted any. */
  receipts: TaskReceiptArtifact[];
}

/**
 * POST a message + delegation envelope to an agent's /v1/run endpoint.
 */
export async function callDelegated(
  endpoint: string,
  message: string,
  envelope: DelegationEnvelope,
  options: CallDelegatedOptions = {}
): Promise<DelegatedResponse> {
  // The endpoint is often registry-supplied; refuse cleartext to a remote host.
  assertSecureEndpoint(endpoint, { allowInsecureHttp: options.allowInsecureHttp, label: "delegate endpoint" });
  const base = endpoint.replace(/\/$/, "").replace(/\/v1\/run$/, "");
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.bearerToken) headers["Authorization"] = `Bearer ${options.bearerToken}`;

  const res = await fetch(`${base}/v1/run`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      message,
      sessionId: options.sessionId,
      trust: "untrusted",
      context: { ...options.extraContext, [DELEGATION_CONTEXT_KEY]: envelope },
    }),
    signal: AbortSignal.timeout(options.timeoutMs ?? 120_000),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Delegated call to ${base} failed: HTTP ${res.status} ${body.slice(0, 200)}`);
  }

  // serve() responds with SSE whenever the handler is an async generator —
  // which serveDelegated's wrapper always is. Accept both formats.
  const contentType = res.headers.get("content-type") ?? "";
  let data: RunResponse;
  if (contentType.startsWith("text/event-stream")) {
    data = await readSseFinal(await res.text(), base);
  } else {
    data = (await res.json()) as RunResponse;
  }

  const receipts = (data.artifacts ?? []).filter(
    (a): a is TaskReceiptArtifact =>
      typeof a === "object" && a !== null &&
      (a as { kind?: string }).kind === RECEIPT_ARTIFACT_KIND
  );
  return { ...data, receipts };
}

/** Collapse an SSE event stream to its `final` event (or throw on `error`). */
function readSseFinal(sse: string, endpoint: string): RunResponse {
  let final: RunResponse | null = null;
  let firstError: string | null = null;
  for (const line of sse.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    try {
      const event = JSON.parse(line.slice(6)) as
        | { type: "final"; message: string; sessionId: string; artifacts?: unknown[]; usage?: Record<string, number> }
        | { type: "error"; message?: string }
        | { type: string };
      if (event.type === "final") {
        const f = event as Extract<typeof event, { type: "final" }>;
        final = { message: f.message, sessionId: f.sessionId, artifacts: f.artifacts, usage: f.usage };
      } else if (event.type === "error" && !firstError) {
        firstError = (event as { message?: string }).message ?? "agent error";
      }
    } catch {
      /* non-JSON SSE line — ignore */
    }
  }
  if (final) return final;
  throw new Error(`Delegated call to ${endpoint} failed: ${firstError ?? "stream ended without a final event"}`);
}
