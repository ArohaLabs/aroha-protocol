// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ A2A bridge.
 *
 * A2A (Agent2Agent) is an open protocol governed under the Linux Foundation.
 * This module targets the **A2A 1.0** wire shapes (a2a.proto, JSON mapping):
 *
 *   Message  { messageId, contextId?, taskId?, role: "ROLE_USER" | "ROLE_AGENT",
 *              parts: Part[], metadata?, extensions?, referenceTaskIds? }
 *   Part     exactly one of { text | raw | url | data }, plus metadata?,
 *            filename?, mediaType?            (no `kind` discriminator in 1.0)
 *   Task     { id, contextId?, status: { state: "TASK_STATE_*", message?, timestamp? },
 *              artifacts?, history?, metadata? }
 *   JSON-RPC method `SendMessage`, params SendMessageRequest { message, configuration?, metadata? },
 *   result SendMessageResponse — one of { task } | { message }.
 *
 * Aroha is complementary to A2A: A2A is the transport, Aroha adds authority.
 * An Aroha mandate token travels in `message.metadata["aroha.mandate"]`, and
 * the message lists the Aroha mandate extension URI in `message.extensions`.
 * An agent advertises that it understands (or requires) the mandate by
 * declaring the extension in `AgentCard.capabilities.extensions`. An A2A peer
 * that does not know the extension can ignore it; one that does MUST verify
 * the whole chain back to a root it trusts before acting on it — use
 * `verifyA2aMandate` / `a2aToArohaVerified` below, which run
 * `verifyMandateChain` from `@aroha-sdk/credentials` with a required root
 * policy. (Single-link `verifyMandate` is not enough: a bare leaf proves
 * only that its immediate grantor signed it, and any agent can sign itself
 * a root.)
 *
 * Mapping:
 *   A2A messageId        ↔  Aroha id (urn:a2a:<messageId>)
 *   A2A taskId/contextId ↔  Aroha correlationId
 *   ROLE_USER            ↔  ArohaRequest / ArohaReserve (caller → provider)
 *   ROLE_AGENT           ↔  every other Aroha type (provider → caller)
 *   A2A parts            ↔  Aroha body (first data part, or JSON in a text part)
 *
 * Security note: A2A messages do not carry an Aroha Ed25519 envelope proof.
 * An envelope produced by a2aToAroha() has no `proof` and MUST NOT be passed
 * to validation that would treat it as signed. Authority comes from the
 * mandate token (verify it), and caller identity from the A2A transport's
 * own authentication.
 */

import { type ArohaEnvelope, type KelSource, type KelStore } from "@aroha-sdk/core";

// ─── A2A 1.0 types ─────────────────────────────────────────────────────────────

export type A2ARole = "ROLE_UNSPECIFIED" | "ROLE_USER" | "ROLE_AGENT";

/** A2A 1.0 Part: exactly one of text / raw / url / data. */
export type A2APart = (
  | { text: string; raw?: never; url?: never; data?: never }
  | { raw: string; text?: never; url?: never; data?: never } // base64 in JSON
  | { url: string; text?: never; raw?: never; data?: never }
  | { data: unknown; text?: never; raw?: never; url?: never }
) & {
  metadata?: Record<string, unknown>;
  filename?: string;
  mediaType?: string;
};

export interface A2AMessage {
  messageId: string;
  contextId?: string;
  taskId?: string;
  role: A2ARole;
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  extensions?: string[];
  referenceTaskIds?: string[];
}

export type A2ATaskState =
  | "TASK_STATE_UNSPECIFIED"
  | "TASK_STATE_SUBMITTED"
  | "TASK_STATE_WORKING"
  | "TASK_STATE_COMPLETED"
  | "TASK_STATE_FAILED"
  | "TASK_STATE_CANCELED"
  | "TASK_STATE_INPUT_REQUIRED"
  | "TASK_STATE_REJECTED"
  | "TASK_STATE_AUTH_REQUIRED";

export interface A2ATaskStatus {
  state: A2ATaskState;
  message?: A2AMessage;
  timestamp?: string;
}

export interface A2AArtifact {
  artifactId: string;
  name?: string;
  description?: string;
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  extensions?: string[];
}

export interface A2ATask {
  id: string;
  contextId?: string;
  status: A2ATaskStatus;
  artifacts?: A2AArtifact[];
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

export interface A2AAgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;
}

export interface A2AAgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  extensions?: A2AAgentExtension[];
  extendedAgentCard?: boolean;
}

export interface A2AAgentInterface {
  url: string;
  /** e.g. "JSONRPC", "GRPC", "HTTP+JSON" */
  protocolBinding: string;
  tenant?: string;
  protocolVersion: string;
}

export interface A2AAgentSkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
}

/** JWS-style signature over the Agent Card (A2A 1.0 signed cards). */
export interface A2AAgentCardSignature {
  /** base64url-encoded JWS protected header */
  protected: string;
  /** base64url-encoded signature */
  signature: string;
  header?: Record<string, unknown>;
}

export interface A2AAgentCard {
  name: string;
  description: string;
  supportedInterfaces: A2AAgentInterface[];
  provider?: { organization: string; url: string };
  version: string;
  documentationUrl?: string;
  capabilities: A2AAgentCapabilities;
  securitySchemes?: Record<string, unknown>;
  securityRequirements?: unknown[];
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: A2AAgentSkill[];
  signatures?: A2AAgentCardSignature[];
  iconUrl?: string;
}

export interface A2ASendMessageRequest {
  tenant?: string;
  message: A2AMessage;
  configuration?: {
    acceptedOutputModes?: string[];
    historyLength?: number;
    /** A2A 1.0: return as soon as the task exists, without waiting for it to finish. */
    returnImmediately?: boolean;
    /** @deprecated The pre-1.0 (0.3) name; A2A 1.0 servers ignore it. Use `returnImmediately`. */
    blocking?: boolean;
    [k: string]: unknown;
  };
  metadata?: Record<string, unknown>;
}

/** SendMessageResponse: one of { task } | { message }. */
export type A2ASendMessageResult =
  | { kind: "task"; task: A2ATask }
  | { kind: "message"; message: A2AMessage };

// ─── Aroha mandate extension ──────────────────────────────────────────────────

/** URI identifying the Aroha mandate extension to A2A. */
export const AROHA_MANDATE_EXTENSION_URI = "https://aroha-labs.com/a2a/extensions/mandate/v1";

/** Metadata key under which the mandate token travels on an A2A Message. */
export const AROHA_MANDATE_METADATA_KEY = "aroha.mandate";

/** The A2A protocol version this bridge speaks. */
export const A2A_PROTOCOL_VERSION = "1.0";

/**
 * Build the AgentExtension declaration for the Aroha mandate extension, for
 * inclusion in `AgentCard.capabilities.extensions`.
 *
 * @param required When true, the agent rejects messages without a mandate.
 */
export function arohaMandateExtension(required = false): A2AAgentExtension {
  return {
    uri: AROHA_MANDATE_EXTENSION_URI,
    description:
      `Carries an Aroha mandate token (signed, scoped delegation of authority) in ` +
      `message.metadata["${AROHA_MANDATE_METADATA_KEY}"]. Verify the full chain back to a trusted root ` +
      `with verifyMandateChain() from @aroha-sdk/credentials before acting on it.`,
    required,
    params: { metadataKey: AROHA_MANDATE_METADATA_KEY },
  };
}

/** Return a copy of `card` that declares the Aroha mandate extension (idempotent). */
export function withArohaMandateExtension(card: A2AAgentCard, required = false): A2AAgentCard {
  const existing = card.capabilities.extensions ?? [];
  const others = existing.filter((e) => e.uri !== AROHA_MANDATE_EXTENSION_URI);
  return {
    ...card,
    capabilities: { ...card.capabilities, extensions: [...others, arohaMandateExtension(required)] },
  };
}

/** True if the agent card declares the Aroha mandate extension. */
export function cardSupportsArohaMandate(card: A2AAgentCard): boolean {
  return (card.capabilities.extensions ?? []).some((e) => e.uri === AROHA_MANDATE_EXTENSION_URI);
}

/** Return a copy of `message` carrying `mandateToken` in metadata and listing the extension. */
export function attachMandate(message: A2AMessage, mandateToken: string): A2AMessage {
  const extensions = message.extensions ?? [];
  return {
    ...message,
    metadata: { ...(message.metadata ?? {}), [AROHA_MANDATE_METADATA_KEY]: mandateToken },
    extensions: extensions.includes(AROHA_MANDATE_EXTENSION_URI)
      ? extensions
      : [...extensions, AROHA_MANDATE_EXTENSION_URI],
  };
}

/** Read the mandate token from a message, or undefined if absent or not a string. */
export function extractMandate(message: A2AMessage): string | undefined {
  const v = message.metadata?.[AROHA_MANDATE_METADATA_KEY];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

// ─── Inbound mandate verification ─────────────────────────────────────────────

/**
 * The parts of @aroha-sdk/credentials' MandateVerificationResult this bridge
 * reads. Declared structurally so the bridge keeps no runtime dependency on
 * credentials: the caller passes `verifyMandateChain` in, which also keeps
 * the verification code the SAME code every other payee runs.
 */
export interface A2AMandateVerificationResult {
  valid: boolean;
  reason?: string;
  chainVerified?: boolean;
  rootGrantor?: string;
  mandate?: {
    mandateId: string;
    mandateTier: string;
    grantor: string;
    grantee: string;
    constraints: { spendLimitUsd: number };
  };
}

/** Signature of `verifyMandateChain` from @aroha-sdk/credentials. */
export type A2AMandateChainVerifier = (
  token: string,
  resolveKey: ((did: string) => Promise<Uint8Array | null>) | undefined,
  options: Record<string, unknown>
) => Promise<A2AMandateVerificationResult>;

/**
 * How an inbound A2A mandate is verified. A ROOT POLICY IS REQUIRED — at
 * least one of expectedRoot, a non-empty trustedRoots, expectedRootPerson,
 * requirePersonRoot with a kelSource, or a governed profile in
 * verifierOptions — because a chain proves provenance only relative to a
 * root you trust; without one any agent can sign itself a root and "carry"
 * whatever authority it likes.
 */
export interface A2AMandatePolicy {
  /** Pass `verifyMandateChain` from @aroha-sdk/credentials. */
  verifyMandateChain: A2AMandateChainVerifier;
  /** Resolver for non-self-certifying DIDs in the chain. Default: content-addressed DIDs only. */
  resolveKey?: (did: string) => Promise<Uint8Array | null>;
  /** The chain's root grantor must be exactly this DID. */
  expectedRoot?: string;
  /** The chain's root grantor must be one of these DIDs. */
  trustedRoots?: string[];
  /** The root must be exactly this person (implies a person root; needs kelSource). */
  expectedRootPerson?: string;
  /** The root must be a person whose KEL verifies (needs kelSource). */
  requirePersonRoot?: boolean;
  /** Key Event Log source for E-DIDs in the chain. */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. */
  kelStore?: KelStore;
  /** Revocation hook consulted for every link. Strongly recommended. */
  isRevoked?: (mandateId: string, grantor: string) => Promise<boolean>;
  /**
   * The leaf must be granted to this DID — normally the A2A caller's DID as
   * established by the A2A transport's own authentication.
   */
  expectedGrantee?: string;
  /**
   * The amount (USD) the request would spend. When set, a leaf whose
   * spendLimitUsd is lower is rejected as over-limit, as is a non-finite or
   * negative amount. Redemption (cumulative spend) is still the payee's job.
   */
  proposedAmountUsd?: number;
  /**
   * Extra options passed to verifyMandateChain as-is, e.g. a
   * governedVerification() profile from @aroha-sdk/credentials. The fields
   * above override the same fields here.
   */
  verifierOptions?: Record<string, unknown>;
  /** Reject a message that carries no mandate. Default true. */
  required?: boolean;
}

export type A2AMandateCheck =
  | { ok: true; token: string; mandate: NonNullable<A2AMandateVerificationResult["mandate"]>; rootGrantor: string }
  | { ok: true; token: undefined; mandate: undefined; rootGrantor: undefined }
  | { ok: false; reason: string };

/** Thrown by a2aToArohaVerified when the carried mandate does not verify. */
export class A2AMandateError extends Error {
  readonly code = "AROHA_MANDATE_REJECTED";
  constructor(message: string) {
    super(message);
    this.name = "A2AMandateError";
  }
}

function hasRootPolicy(p: A2AMandatePolicy): boolean {
  if (p.expectedRoot !== undefined || p.expectedRootPerson !== undefined) return true;
  if (Array.isArray(p.trustedRoots) && p.trustedRoots.length > 0) return true;
  if (p.requirePersonRoot === true && p.kelSource !== undefined) return true;
  return p.verifierOptions?.governed === true;
}

/**
 * Verify the Aroha mandate an A2A message carries: the whole chain back to a
 * trusted root, revocation (when a hook is given), the grantee and,
 * optionally, the amount against the leaf's limit. Returns a result; never
 * throws for a bad mandate. Throws only for a policy that has no root
 * policy, which is a configuration error.
 */
export async function verifyA2aMandate(message: A2AMessage | LegacyA2AMessage, policy: A2AMandatePolicy): Promise<A2AMandateCheck> {
  if (typeof policy?.verifyMandateChain !== "function") {
    throw new Error("verifyA2aMandate: policy.verifyMandateChain is required (pass verifyMandateChain from @aroha-sdk/credentials)");
  }
  if (!hasRootPolicy(policy)) {
    throw new Error(
      "verifyA2aMandate: a root policy is required — expectedRoot, trustedRoots, expectedRootPerson, " +
      "requirePersonRoot with a kelSource, or a governed profile. Without one any agent can sign itself a root mandate."
    );
  }

  const token = extractMandate(normalizeMessage(message));
  if (token === undefined) {
    return policy.required === false
      ? { ok: true, token: undefined, mandate: undefined, rootGrantor: undefined }
      : { ok: false, reason: "No Aroha mandate on the message" };
  }

  const options: Record<string, unknown> = { ...(policy.verifierOptions ?? {}) };
  const set = (k: string, v: unknown) => { if (v !== undefined) options[k] = v; };
  set("expectedRoot", policy.expectedRoot);
  set("trustedRoots", policy.trustedRoots?.length ? policy.trustedRoots : undefined);
  set("expectedRootPerson", policy.expectedRootPerson);
  set("requirePersonRoot", policy.requirePersonRoot);
  set("kelSource", policy.kelSource);
  set("kelStore", policy.kelStore);
  set("isRevoked", policy.isRevoked);
  set("expectedGrantee", policy.expectedGrantee);

  let result: A2AMandateVerificationResult;
  try {
    result = await policy.verifyMandateChain(token, policy.resolveKey, options);
  } catch (err) {
    return { ok: false, reason: `Mandate verification failed: ${(err as Error).message}` };
  }
  if (!result.valid || result.chainVerified !== true || !result.mandate || !result.rootGrantor) {
    return { ok: false, reason: result.reason ?? "Mandate does not verify back to a root" };
  }

  if (policy.proposedAmountUsd !== undefined) {
    const amount = policy.proposedAmountUsd;
    if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) {
      return { ok: false, reason: `Proposed amount ${String(amount)} is not a finite, non-negative number` };
    }
    if (amount > result.mandate.constraints.spendLimitUsd) {
      return { ok: false, reason: `Proposed $${amount} exceeds mandate limit $${result.mandate.constraints.spendLimitUsd}` };
    }
  }
  return { ok: true, token, mandate: result.mandate, rootGrantor: result.rootGrantor };
}

/**
 * a2aToAroha, but only after the carried mandate verifies under `policy`.
 * Throws A2AMandateError when it does not. This is the documented inbound
 * path: the plain a2aToAroha copies the token without looking at it.
 */
export async function a2aToArohaVerified(
  a2aMsg: A2AMessage | LegacyA2AMessage,
  fromDID: string,
  toDID: string,
  policy: A2AMandatePolicy
): Promise<{ envelope: ArohaEnvelope; mandate: A2AMandateVerificationResult["mandate"]; rootGrantor?: string }> {
  const check = await verifyA2aMandate(a2aMsg, policy);
  if (!check.ok) throw new A2AMandateError(check.reason);
  return { envelope: a2aToAroha(a2aMsg, fromDID, toDID), mandate: check.mandate, rootGrantor: check.rootGrantor };
}

// ─── A2A → Aroha ───────────────────────────────────────────────────────────────

/** Legacy (pre-1.0) message shape accepted by a2aToAroha for compatibility. */
export interface LegacyA2AMessage {
  messageId: string;
  taskId?: string;
  contextId?: string;
  role: "user" | "agent";
  parts: Array<{ type?: string; kind?: string; text?: string; data?: Record<string, unknown> }>;
  metadata?: Record<string, unknown>;
}

/**
 * Convert an inbound A2A message into an Aroha envelope.
 *
 * The resulting envelope has **no proof**. If the message carried an Aroha
 * mandate, it is copied to `body.credentialToken` (the field Aroha providers
 * such as @aroha-sdk/mcp-bridge already read) UNVERIFIED. Prefer
 * a2aToArohaVerified, which refuses a mandate that does not verify back to a
 * trusted root.
 *
 * Accepts A2A 1.0 messages and, for compatibility, pre-1.0 messages
 * (`role: "user" | "agent"`, parts with `type`/`kind`).
 */
export function a2aToAroha(
  a2aMsg: A2AMessage | LegacyA2AMessage,
  fromDID: string,
  toDID: string
): ArohaEnvelope {
  const msg = normalizeMessage(a2aMsg);
  const bodyData: Record<string, unknown> = { ...extractData(msg.parts) };
  const mandate = extractMandate(msg);
  if (mandate !== undefined) bodyData.credentialToken = mandate;

  const arohaType = msg.role === "ROLE_USER" ? "ArohaRequest" : "ArohaResponse";

  const now = new Date();
  const expires = new Date(now.getTime() + 300_000); // 5 min TTL

  return {
    "@context": [
      "https://aroha-labs.com/contexts/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: `urn:a2a:${msg.messageId}`,
    type: arohaType as ArohaEnvelope["type"],
    from: fromDID,
    to: toDID,
    created: now.toISOString(),
    expires: expires.toISOString(),
    nonce: msg.messageId, // A2A requires messageId to be unique per message
    correlationId: msg.taskId ?? msg.contextId ?? msg.messageId,
    body: bodyData as unknown as ArohaEnvelope["body"],
    // No proof — A2A messages are not Aroha-signed
  };
}

// ─── Aroha → A2A ───────────────────────────────────────────────────────────────

export interface ArohaToA2aOptions {
  /** Attach this mandate token to the message (see attachMandate). */
  mandateToken?: string;
  /** A2A contextId to use; defaults to the envelope's correlationId. */
  contextId?: string;
}

/**
 * Convert an outbound Aroha envelope into an A2A 1.0 message.
 * The envelope body becomes a single `data` part with mediaType application/json.
 */
export function arohaToA2a(envelope: ArohaEnvelope, opts: ArohaToA2aOptions = {}): A2AMessage {
  const role: A2ARole =
    envelope.type === "ArohaRequest" || envelope.type === "ArohaReserve" ? "ROLE_USER" : "ROLE_AGENT";

  const message: A2AMessage = {
    messageId: envelope.id.replace("urn:uuid:", "").replace("urn:a2a:", ""),
    contextId: opts.contextId ?? envelope.correlationId,
    taskId: envelope.correlationId,
    role,
    parts: [{ data: envelope.body as unknown, mediaType: "application/json" }],
    metadata: {
      "aroha.type": envelope.type,
      "aroha.from": envelope.from,
      "aroha.to": envelope.to,
    },
  };
  return opts.mandateToken ? attachMandate(message, opts.mandateToken) : message;
}

/** Convert an Aroha ArohaStream event into an A2A task status. */
export function arohaStreamToA2aStatus(envelope: ArohaEnvelope): Pick<A2ATask, "status"> {
  const body = envelope.body as { progressPct?: number };
  const pct = body.progressPct ?? 0;
  return {
    status: {
      state: pct >= 100 ? "TASK_STATE_COMPLETED" : "TASK_STATE_WORKING",
      timestamp: new Date().toISOString(),
    },
  };
}

// ─── JSON-RPC client ──────────────────────────────────────────────────────────

export class A2AJsonRpcError extends Error {
  constructor(
    message: string,
    readonly code: number | undefined,
    readonly data?: unknown
  ) {
    super(message);
    this.name = "A2AJsonRpcError";
  }
}

export interface SendMessageOptions {
  /** Attach an Aroha mandate token to the message before sending. */
  mandateToken?: string;
  /** SendMessageRequest.configuration */
  configuration?: A2ASendMessageRequest["configuration"];
  /** SendMessageRequest.metadata */
  metadata?: Record<string, unknown>;
  /** Extra HTTP headers (e.g. Authorization). */
  headers?: Record<string, string>;
  /** Injected fetch, for tests or custom agents. Defaults to global fetch. */
  fetch?: typeof fetch;
  /** JSON-RPC request id. Defaults to a random UUID. */
  id?: string | number;
  signal?: AbortSignal;
}

/**
 * Call an A2A agent's JSON-RPC `SendMessage` method.
 *
 * @param url The agent's JSON-RPC endpoint — the `url` of the AgentInterface
 *            whose `protocolBinding` is "JSONRPC" in its Agent Card.
 * @returns   Either the Task or the direct Message the agent returned.
 * @throws    A2AJsonRpcError on a JSON-RPC error or a malformed response;
 *            Error on a non-2xx HTTP status.
 */
export async function sendMessage(
  url: string,
  message: A2AMessage,
  opts: SendMessageOptions = {}
): Promise<A2ASendMessageResult> {
  const msg = opts.mandateToken ? attachMandate(message, opts.mandateToken) : message;
  const params: A2ASendMessageRequest = { message: msg };
  if (opts.configuration) params.configuration = opts.configuration;
  if (opts.metadata) params.metadata = opts.metadata;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    "A2A-Version": A2A_PROTOCOL_VERSION,
    ...(opts.headers ?? {}),
  };
  if (msg.extensions && msg.extensions.length > 0) {
    headers["A2A-Extensions"] = msg.extensions.join(",");
  }

  return parseSendMessageResult(await jsonRpcCall(url, "SendMessage", params, headers, opts));
}

/** Options for getTask / cancelTask. */
export type TaskCallOptions = Pick<SendMessageOptions, "headers" | "fetch" | "id" | "signal">;

/**
 * Call an A2A agent's JSON-RPC `GetTask` method.
 * @throws A2AJsonRpcError — code -32001 (TaskNotFoundError) for an unknown task.
 */
export async function getTask(
  url: string,
  taskId: string,
  opts: TaskCallOptions & { historyLength?: number } = {}
): Promise<A2ATask> {
  const params: Record<string, unknown> = { id: taskId };
  if (opts.historyLength !== undefined) params.historyLength = opts.historyLength;
  return parseTask(await jsonRpcCall(url, "GetTask", params, baseHeaders(opts.headers), opts));
}

/**
 * Call an A2A agent's JSON-RPC `CancelTask` method.
 * @throws A2AJsonRpcError — -32001 for an unknown task, -32002 (TaskNotCancelableError) for a finished one.
 */
export async function cancelTask(
  url: string,
  taskId: string,
  opts: TaskCallOptions & { metadata?: Record<string, unknown> } = {}
): Promise<A2ATask> {
  const params: Record<string, unknown> = { id: taskId };
  if (opts.metadata) params.metadata = opts.metadata;
  return parseTask(await jsonRpcCall(url, "CancelTask", params, baseHeaders(opts.headers), opts));
}

function baseHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { "Content-Type": "application/json", Accept: "application/json", "A2A-Version": A2A_PROTOCOL_VERSION, ...extra };
}

function parseTask(result: unknown): A2ATask {
  const r = result as Record<string, unknown> | null;
  if (r && typeof r === "object" && typeof r.id === "string" && r.status && typeof r.status === "object") return r as unknown as A2ATask;
  throw new A2AJsonRpcError("Malformed task result: expected a Task", undefined, result);
}

async function jsonRpcCall(
  url: string,
  method: string,
  params: unknown,
  headers: Record<string, string>,
  opts: TaskCallOptions
): Promise<unknown> {
  const doFetch = opts.fetch ?? fetch;
  const res = await doFetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: opts.id ?? crypto.randomUUID(), method, params }),
    signal: opts.signal,
  });
  if (!res.ok) {
    throw new Error(`A2A ${method} failed: HTTP ${res.status}`);
  }
  const json = (await res.json()) as {
    jsonrpc?: string;
    result?: unknown;
    error?: { code?: number; message?: string; data?: unknown };
  };
  if (json.error) {
    throw new A2AJsonRpcError(json.error.message ?? "A2A JSON-RPC error", json.error.code, json.error.data);
  }
  return json.result;
}

/**
 * Interpret a SendMessage result. Accepts the 1.0 wrapper ({ task } / { message })
 * and, defensively, a bare Task or Message.
 */
export function parseSendMessageResult(result: unknown): A2ASendMessageResult {
  if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (r.task && typeof r.task === "object") return { kind: "task", task: r.task as A2ATask };
    if (r.message && typeof r.message === "object") return { kind: "message", message: r.message as A2AMessage };
    if (typeof r.messageId === "string" && Array.isArray(r.parts)) {
      return { kind: "message", message: r as unknown as A2AMessage };
    }
    if (typeof r.id === "string" && r.status && typeof r.status === "object") {
      return { kind: "task", task: r as unknown as A2ATask };
    }
  }
  throw new A2AJsonRpcError("Malformed SendMessage result: expected a Task or a Message", undefined, result);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeMessage(m: A2AMessage | LegacyA2AMessage): A2AMessage {
  const role: A2ARole =
    m.role === "user" ? "ROLE_USER" : m.role === "agent" ? "ROLE_AGENT" : (m.role as A2ARole);
  const parts = (m.parts as Array<Record<string, unknown>>).map((p): A2APart => {
    if (typeof p.text === "string") return { text: p.text };
    if (p.data !== undefined) return { data: p.data };
    if (typeof p.url === "string") return { url: p.url };
    if (typeof p.raw === "string") return { raw: p.raw };
    return { text: "" };
  });
  return { ...(m as A2AMessage), role, parts };
}

function extractData(parts: A2APart[]): Record<string, unknown> {
  for (const part of parts) {
    if (part.data !== undefined) {
      return part.data && typeof part.data === "object" && !Array.isArray(part.data)
        ? (part.data as Record<string, unknown>)
        : { data: part.data };
    }
    if (typeof part.text === "string") {
      try {
        const parsed = JSON.parse(part.text) as unknown;
        return parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : { text: part.text };
      } catch {
        return { text: part.text };
      }
    }
  }
  return {};
}

// A2A server side (signed Agent Card + JSON-RPC SendMessage). Node-only (node:http, node:crypto).
export * from "./server.js";
