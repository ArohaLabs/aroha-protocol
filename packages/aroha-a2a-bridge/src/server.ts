// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * A2A server side: a signed Agent Card and a JSON-RPC `SendMessage`
 * endpoint that turns inbound A2A messages into Aroha envelopes ONLY after
 * the carried mandate verifies (a2aToArohaVerified).
 *
 * WHY. The bridge was client-only: an Aroha agent could call A2A agents but
 * no A2A client could call an Aroha agent, and nothing tested the bridge
 * against a peer. This module serves both halves of discovery and
 * invocation with the platform's own HTTP server (node:http) and no new
 * dependency.
 *
 * Card signatures. An A2A 1.0 Agent Card may carry JWS signatures (RFC 7515).
 * Here the JWS payload is the RFC 8785 (JCS) canonical form of the card with
 * `signatures` removed, detached (not repeated in the card); the protected
 * header is { alg: "EdDSA", typ: "JOSE", kid }, and the signature is Ed25519
 * over ASCII(BASE64URL(protected) || "." || BASE64URL(payload)) — the RFC 7515
 * signing input. `kid` names the agent key (`<did>#key-1`), so a verifier
 * resolves it the way it resolves any Aroha key; a content-addressed
 * did:aroha:z… DID needs no lookup at all.
 *
 * What a card signature proves: the card was published by the holder of the
 * agent's key. It does not authorise anything — authority still comes only
 * from a mandate chain that verifies back to a trusted root.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { canonicalizeJcs, fromMultibase, type ArohaEnvelope } from "@aroha-sdk/core";
import {
  A2A_PROTOCOL_VERSION,
  A2AMandateError,
  a2aToArohaVerified,
  type A2AAgentCard,
  type A2AAgentCardSignature,
  type A2AMandatePolicy,
  type A2AMandateVerificationResult,
  type A2AMessage,
  type A2ASendMessageResult,
  type A2ATask,
} from "./index.js";

// Ed25519 through node:crypto, so the bridge takes no new dependency. Raw
// 32-byte keys are wrapped in the fixed PKCS#8 / SPKI prefixes for Ed25519.
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

function edSign(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(privateKey)]), format: "der", type: "pkcs8" });
  return nodeSign(null, data, key);
}

function edVerify(sig: Uint8Array, data: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32 || sig.length !== 64) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(publicKey)]), format: "der", type: "spki" });
  return nodeVerify(null, data, key, sig);
}

/** Where A2A clients discover an agent (A2A 1.0). */
export const AGENT_CARD_WELL_KNOWN_PATH = "/.well-known/agent-card.json";

/** JSON-RPC error code for a mandate that does not verify (implementation-defined server range). */
export const AROHA_MANDATE_REJECTED_RPC_CODE = -32010;

/** A2A 1.0 JSON-RPC error codes (specification §5.4) this server answers with. */
export const A2A_RPC_ERROR = {
  TASK_NOT_FOUND: -32001,
  TASK_NOT_CANCELABLE: -32002,
  PUSH_NOTIFICATION_NOT_SUPPORTED: -32003,
  UNSUPPORTED_OPERATION: -32004,
  VERSION_NOT_SUPPORTED: -32009,
} as const;

// A2A 1.0 methods this server does not implement. They are part of the
// protocol, so they get UnsupportedOperationError (§3.3.4: streaming without
// capabilities.streaming MUST) — not JSON-RPC "method not found".
const UNSUPPORTED_A2A_METHODS = new Set(["SendStreamingMessage", "SubscribeToTask", "ListTasks", "GetExtendedAgentCard"]);
const PUSH_CONFIG_METHODS = new Set([
  "CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig",
]);
const TERMINAL_STATES = new Set(["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"]);

const te = new TextEncoder();
const b64u = (b: Uint8Array | string) => Buffer.from(typeof b === "string" ? te.encode(b) : b).toString("base64url");

// A2A 1.0 §8.4.1: before signing, a field that holds its proto default ("",
// false, an empty list or map) is omitted unless it is REQUIRED or declared
// `optional` (explicit presence). These are the REQUIRED fields of the
// AgentCard messages; a2a.proto marks them with field_behavior REQUIRED.
type CardShape = { required: ReadonlySet<string>; children?: Record<string, CardShape> };
const ANY: CardShape = { required: new Set() };
const EXTENSION: CardShape = { required: new Set(), children: { params: { required: new Set(["*"]) } } };
const CARD_SHAPE: CardShape = {
  required: new Set(["name", "description", "supportedInterfaces", "version", "capabilities", "defaultInputModes", "defaultOutputModes", "skills",
    // `optional` fields: present when set, even to their default
    "documentationUrl", "iconUrl"]),
  children: {
    supportedInterfaces: { required: new Set(["url", "protocolBinding", "protocolVersion"]) },
    provider: { required: new Set(["url", "organization"]) },
    capabilities: { required: new Set(["streaming", "pushNotifications", "extendedAgentCard"]), children: { extensions: EXTENSION } },
    skills: { required: new Set(["id", "name", "description", "tags"]) },
  },
};

function isDefault(v: unknown): boolean {
  if (v === undefined || v === null || v === "" || v === false) return true;
  if (Array.isArray(v)) return v.length === 0;
  return typeof v === "object" && Object.keys(v as object).length === 0;
}

function omitDefaults(value: unknown, shape: CardShape): unknown {
  if (Array.isArray(value)) return value.map((v) => omitDefaults(v, shape));
  if (!value || typeof value !== "object") return value;
  // A google.protobuf.Struct (an extension's params) is free-form: kept as-is.
  if (shape.required.has("*")) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined || v === null) continue;
    if (!shape.required.has(k) && isDefault(v)) continue;
    out[k] = omitDefaults(v, shape.children?.[k] ?? ANY);
  }
  return out;
}

/**
 * The exact bytes a card signature's payload is (A2A 1.0 §8.4.1): JCS
 * (RFC 8785) of the card without `signatures`, with every field that holds
 * its proto default omitted unless it is REQUIRED or explicitly `optional`
 * — so `required: false` on an extension, `tenant: ""`, an empty
 * `securitySchemes` map and the like are not part of the payload.
 *
 * Up to 2.0.0 the payload was JCS of the card as-is, which other A2A
 * implementations could not verify for a card carrying a default-valued
 * field (and this bridge could not verify cards they serve with defaults
 * spelled out). verifyAgentCardSignature still accepts that older payload.
 */
export function agentCardSigningPayload(card: A2AAgentCard): string {
  const { signatures: _s, ...rest } = card;
  return canonicalizeJcs(omitDefaults(JSON.parse(JSON.stringify(rest)), CARD_SHAPE) as Record<string, unknown>);
}

/** The signing payload used up to 2.0.0 (JCS of the card as-is, without `signatures`). */
export function agentCardSigningPayloadAsIs(card: A2AAgentCard): string {
  const { signatures: _s, ...rest } = card;
  return canonicalizeJcs(JSON.parse(JSON.stringify(rest)));
}

/** Append a detached EdDSA JWS signature to a card. */
export async function signAgentCard(card: A2AAgentCard, privateKey: Uint8Array, kid: string): Promise<A2AAgentCard> {
  const protectedB64 = b64u(JSON.stringify({ alg: "EdDSA", typ: "JOSE", kid }));
  const signingInput = `${protectedB64}.${b64u(agentCardSigningPayload(card))}`;
  const sig = edSign(te.encode(signingInput), privateKey);
  const signature: A2AAgentCardSignature = { protected: protectedB64, signature: b64u(sig) };
  return { ...card, signatures: [...(card.signatures ?? []), signature] };
}

/** Resolve a JWS `kid` to an Ed25519 public key. */
export type CardKeyResolver = (kid: string) => Uint8Array | null | Promise<Uint8Array | null>;

/** Default resolver: a content-addressed did:aroha:z… kid carries its own key. Anything else is unresolvable. */
export const contentAddressedCardKey: CardKeyResolver = (kid) => {
  const did = kid.split("#")[0];
  if (!did.startsWith("did:aroha:z")) return null;
  try {
    return fromMultibase(did.slice("did:aroha:".length));
  } catch {
    return null;
  }
};

export type CardVerification = { ok: true; kid: string } | { ok: false; reason: string };

/**
 * Verify an Agent Card's signatures. Passes when at least one signature is
 * an EdDSA JWS whose kid resolves and whose signature covers the card as
 * received. With `expectedKid`, only a signature by that key counts.
 */
export async function verifyAgentCardSignature(
  card: A2AAgentCard,
  resolveKey: CardKeyResolver = contentAddressedCardKey,
  opts: { expectedKid?: string } = {},
): Promise<CardVerification> {
  if (!Array.isArray(card?.signatures) || card.signatures.length === 0) return { ok: false, reason: "the agent card is unsigned" };
  // The §8.4.1 payload, then the one used up to 2.0.0 so older bridge-signed cards keep verifying.
  const payloads = [...new Set([agentCardSigningPayload(card), agentCardSigningPayloadAsIs(card)])].map((p) => b64u(p));
  let lastReason = "no signature verified";
  for (const s of card.signatures) {
    let header: { alg?: unknown; kid?: unknown };
    try {
      header = JSON.parse(Buffer.from(s.protected, "base64url").toString("utf8"));
    } catch {
      lastReason = "a signature's protected header is not base64url JSON";
      continue;
    }
    if (header.alg !== "EdDSA" || typeof header.kid !== "string") {
      lastReason = "a signature is not EdDSA with a kid";
      continue;
    }
    if (opts.expectedKid !== undefined && header.kid !== opts.expectedKid) continue;
    let key: Uint8Array | null = null;
    try {
      key = await resolveKey(header.kid);
    } catch {
      key = null;
    }
    if (!key) {
      lastReason = `no key for ${header.kid}`;
      continue;
    }
    let ok = false;
    for (const payloadB64 of payloads) {
      try {
        ok = edVerify(Buffer.from(s.signature, "base64url"), te.encode(`${s.protected}.${payloadB64}`), key);
      } catch {
        ok = false;
      }
      if (ok) break;
    }
    if (ok) return { ok: true, kid: header.kid };
    lastReason = `the signature by ${header.kid} does not verify`;
  }
  return { ok: false, reason: lastReason };
}

/**
 * Fetch an agent's card from `/.well-known/agent-card.json` and verify its
 * signature. Throws when the card is unsigned or no signature verifies —
 * a client that wants an unsigned card can fetch it itself.
 */
export async function fetchAgentCard(
  baseUrl: string,
  opts: { resolveKey?: CardKeyResolver; expectedKid?: string; fetch?: typeof fetch } = {},
): Promise<{ card: A2AAgentCard; kid: string }> {
  const doFetch = opts.fetch ?? fetch;
  const res = await doFetch(new URL(AGENT_CARD_WELL_KNOWN_PATH, baseUrl).toString(), { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`Agent card fetch failed: HTTP ${res.status}`);
  const card = (await res.json()) as A2AAgentCard;
  const v = await verifyAgentCardSignature(card, opts.resolveKey, { expectedKid: opts.expectedKid });
  if (!v.ok) throw new Error(`Agent card signature rejected: ${v.reason}`);
  return { card, kid: v.kid };
}

// ─── Server ───────────────────────────────────────────────────────────────────

export interface A2AHandlerContext {
  /** The caller DID as established by the transport (resolveCaller). */
  callerDid: string;
  /** The verified mandate leaf, when the message carried one. */
  mandate: A2AMandateVerificationResult["mandate"];
  rootGrantor?: string;
  /** The original A2A message. */
  message: A2AMessage;
}

/** A handler returns either a full SendMessage result, or a body to send back as a single data part. */
export type A2AMessageHandler = (
  envelope: ArohaEnvelope,
  ctx: A2AHandlerContext,
) => Promise<A2ASendMessageResult | Record<string, unknown>> | A2ASendMessageResult | Record<string, unknown>;

export interface A2AServerOptions {
  /** The card to serve, unsigned; it is signed once at startup. */
  card: A2AAgentCard;
  /** The agent's DID: the `to` of every converted envelope, and the card key's DID. */
  agentDid: string;
  /** The agent's Ed25519 private key (signs the card only). */
  privateKey: Uint8Array;
  /** JWS kid. Default `${agentDid}#key-1`. */
  kid?: string;
  /** Path of the JSON-RPC endpoint. Default "/a2a". Must match the card's JSONRPC interface URL. */
  rpcPath?: string;
  /**
   * The caller's DID from the transport's own authentication (mTLS, a
   * verified bearer token, an `aroha-sig` header). Return null to refuse with
   * HTTP 401. Never read it from the message body: an A2A message is not
   * signed by its sender.
   */
  resolveCaller: (req: IncomingMessage) => string | null | Promise<string | null>;
  /** Mandate verification policy (root policy required; see verifyA2aMandate). */
  mandatePolicy: A2AMandatePolicy;
  /** The Aroha-side handler for verified messages. */
  handle: A2AMessageHandler;
  /** Request body limit. Default 1 MiB. */
  maxBodyBytes?: number;
  /**
   * Called on `CancelTask` for a task that is not yet terminal, before the
   * task is marked TASK_STATE_CANCELED. Stop the work here. Throwing
   * leaves the task as it was and answers JSON-RPC -32603.
   */
  onCancel?: (task: A2ATask, ctx: { callerDid: string }) => void | Promise<void>;
  /** How many tasks `GetTask` / `CancelTask` remember (oldest dropped first). Default 1000. */
  maxTasks?: number;
}

type RpcId = string | number | null;

function rpcError(id: RpcId, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": String(Buffer.byteLength(data)), ...headers });
  res.end(data);
}

function readBody(req: IncomingMessage, limit: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function isA2AMessage(x: unknown): x is A2AMessage {
  if (!x || typeof x !== "object") return false;
  const m = x as Record<string, unknown>;
  return typeof m.messageId === "string" && m.messageId.length > 0 && typeof m.role === "string" && Array.isArray(m.parts);
}

/**
 * Build a request handler for node:http's createServer. Serves the signed
 * card at /.well-known/agent-card.json and JSON-RPC `SendMessage` at
 * `rpcPath`. Every inbound message goes through a2aToArohaVerified before the
 * handler sees it; a mandate that does not verify is answered with JSON-RPC
 * error AROHA_MANDATE_REJECTED_RPC_CODE and never reaches the handler.
 */
export async function createA2aRequestHandler(
  opts: A2AServerOptions,
): Promise<(req: IncomingMessage, res: ServerResponse) => void> {
  const rpcPath = opts.rpcPath ?? "/a2a";
  const limit = opts.maxBodyBytes ?? 1024 * 1024;
  const kid = opts.kid ?? `${opts.agentDid}#key-1`;
  const signedCard = await signAgentCard(opts.card, opts.privateKey, kid);
  const maxTasks = opts.maxTasks ?? 1000;
  // Tasks this agent returned, for GetTask / CancelTask. Only the caller that
  // created a task can see or cancel it; anyone else gets TaskNotFound.
  const tasks = new Map<string, { owner: string; task: A2ATask }>();
  const remember = (owner: string, task: A2ATask) => {
    tasks.delete(task.id);
    tasks.set(task.id, { owner, task });
    while (tasks.size > maxTasks) tasks.delete(tasks.keys().next().value as string);
  };

  async function handleRpc(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const callerDid = await opts.resolveCaller(req);
    if (!callerDid) return send(res, 401, rpcError(null, -32600, "Caller not authenticated"));
    // A2A 1.0 §3.6.2: an absent or empty A2A-Version means 0.3, which this agent does not speak.
    const version = req.headers["a2a-version"];
    if (version !== A2A_PROTOCOL_VERSION) {
      const asked = version === undefined || version === "" ? "0.3 (no A2A-Version header)" : String(version);
      return send(res, 200, rpcError(null, A2A_RPC_ERROR.VERSION_NOT_SUPPORTED, `Unsupported A2A version ${asked}; this agent speaks ${A2A_PROTOCOL_VERSION}`));
    }
    const raw = await readBody(req, limit);
    if (raw === null) return send(res, 413, rpcError(null, -32600, "Request body too large"));
    let rpc: { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
    try {
      rpc = JSON.parse(raw);
    } catch {
      return send(res, 200, rpcError(null, -32700, "Parse error"));
    }
    const id: RpcId = typeof rpc?.id === "string" || typeof rpc?.id === "number" ? rpc.id : null;
    if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") return send(res, 200, rpcError(id, -32600, "Invalid request"));
    if (UNSUPPORTED_A2A_METHODS.has(rpc.method)) {
      return send(res, 200, rpcError(id, A2A_RPC_ERROR.UNSUPPORTED_OPERATION, `${rpc.method} is not supported by this agent`));
    }
    if (PUSH_CONFIG_METHODS.has(rpc.method)) {
      return send(res, 200, rpcError(id, A2A_RPC_ERROR.PUSH_NOTIFICATION_NOT_SUPPORTED, "Push notifications are not supported by this agent"));
    }
    if (rpc.method === "GetTask" || rpc.method === "CancelTask") {
      const taskId = (rpc.params as { id?: unknown } | undefined)?.id;
      if (typeof taskId !== "string" || taskId.length === 0) return send(res, 200, rpcError(id, -32602, "params.id must be a task id"));
      const entry = tasks.get(taskId);
      if (!entry || entry.owner !== callerDid) return send(res, 200, rpcError(id, A2A_RPC_ERROR.TASK_NOT_FOUND, `Task not found: ${taskId}`));
      if (rpc.method === "CancelTask" && entry.task.status.state !== "TASK_STATE_CANCELED") {
        if (TERMINAL_STATES.has(entry.task.status.state)) {
          return send(res, 200, rpcError(id, A2A_RPC_ERROR.TASK_NOT_CANCELABLE, `Task not cancelable: ${taskId} is ${entry.task.status.state}`));
        }
        try {
          await opts.onCancel?.(entry.task, { callerDid });
        } catch {
          return send(res, 200, rpcError(id, -32603, "Internal error"));
        }
        entry.task = { ...entry.task, status: { state: "TASK_STATE_CANCELED", timestamp: new Date().toISOString() } };
      }
      return send(res, 200, { jsonrpc: "2.0", id, result: entry.task });
    }
    if (rpc.method !== "SendMessage") return send(res, 200, rpcError(id, -32601, `Method not found: ${rpc.method}`));
    const message = (rpc.params as { message?: unknown } | undefined)?.message;
    if (!isA2AMessage(message)) return send(res, 200, rpcError(id, -32602, "params.message must be an A2A Message"));

    let converted: Awaited<ReturnType<typeof a2aToArohaVerified>>;
    try {
      converted = await a2aToArohaVerified(message, callerDid, opts.agentDid, { ...opts.mandatePolicy, expectedGrantee: opts.mandatePolicy.expectedGrantee ?? callerDid });
    } catch (err) {
      if (err instanceof A2AMandateError) return send(res, 200, rpcError(id, AROHA_MANDATE_REJECTED_RPC_CODE, err.message));
      return send(res, 200, rpcError(id, -32603, "Internal error"));
    }

    let out: A2ASendMessageResult | Record<string, unknown>;
    try {
      out = await opts.handle(converted.envelope, { callerDid, mandate: converted.mandate, rootGrantor: converted.rootGrantor, message });
    } catch {
      // The handler's error text may carry internals; the caller gets a generic code.
      return send(res, 200, rpcError(id, -32603, "Internal error"));
    }
    if ((out as A2ASendMessageResult).kind === "task") remember(callerDid, (out as { task: A2ATask }).task);
    const result =
      (out as A2ASendMessageResult).kind === "task"
        ? { task: (out as { task: unknown }).task }
        : (out as A2ASendMessageResult).kind === "message"
          ? { message: (out as { message: unknown }).message }
          : {
              message: {
                messageId: crypto.randomUUID(),
                contextId: message.contextId,
                taskId: message.taskId,
                role: "ROLE_AGENT",
                parts: [{ data: out, mediaType: "application/json" }],
              } satisfies A2AMessage,
            };
    return send(res, 200, { jsonrpc: "2.0", id, result });
  }

  return (req, res) => {
    const path = (req.url ?? "/").split("?")[0];
    if (req.method === "GET" && path === AGENT_CARD_WELL_KNOWN_PATH) {
      return send(res, 200, signedCard, { "cache-control": "public, max-age=300" });
    }
    if (path === rpcPath) {
      if (req.method !== "POST") return send(res, 405, rpcError(null, -32600, "Use POST"), { allow: "POST" });
      handleRpc(req, res).catch(() => {
        if (!res.headersSent) send(res, 500, rpcError(null, -32603, "Internal error"));
      });
      return;
    }
    send(res, 404, { error: "not found" });
  };
}
