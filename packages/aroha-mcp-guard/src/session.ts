// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// GuardSession — the transport-independent core of mcp-guard. It sits between
// one MCP client and one wrapped MCP server, sees every JSON-RPC message in
// both directions, and decides what happens to each tools/call.
//
// Human gates, negotiated by protocol revision:
//   - 2026-07-28 clients (a request whose `_meta` names the protocol
//     version): Multi Round-Trip Requests. The guard answers the call itself
//     with `resultType: "input_required"`, an embedded form elicitation and an
//     HMAC-protected `requestState` carrying the approval id. The client
//     retries with `inputResponses`; only an approval whose state verifies
//     and names the same tool and the same arguments lets the call through.
//   - older clients: the guard sends a server→client `elicitation/create`
//     and forwards the call on an explicit accept (the pre-2026 behaviour).
//
// Re-approval on tool definition change: the guard fingerprints every tool in
// each tools/list result it sees (name, description, schemas, annotations).
// When a later list shows a different definition for a tool, the next call to
// that tool needs a human approval even if no rule gates it. When the list
// carried a `ttlMs` (2026-07-28 cacheable result) and it has expired, the
// guard fetches a fresh list from the wrapped server before letting a call
// through, so an expired cache cannot hide a changed definition.

import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { type Decision, GuardEngine } from "./engine.js";

export interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface GuardAuditEntry {
  tool: string;
  decision: string;
  detail?: string;
}

export interface GuardSessionOptions {
  engine: GuardEngine;
  toClient: (msg: JsonRpcMessage) => void;
  toServer: (msg: JsonRpcMessage) => void;
  audit?: (entry: GuardAuditEntry) => void;
  /** Legacy elicitation timeout in ms (default 120s). */
  gateTimeoutMs?: number;
  /** HMAC key for requestState (≥ 32 bytes). Default: random per session. */
  stateKey?: Uint8Array;
  /** requestState lifetime in seconds (default 600). */
  stateTtlSeconds?: number;
  now?: () => number;
}

export const PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion";
export const CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities";
/** Key of the guard's approval form inside inputRequests / inputResponses. */
export const GUARD_INPUT_KEY = "aroha_guard_approval";
const STATE_PREFIX = "aroha-guard.v1.";
const MODERN_FROM = "2026-07-28";

interface GuardState {
  /** Approval id. */
  a: string;
  /** Tool name. */
  t: string;
  /** SHA-256 of the canonical arguments. */
  h: string;
  /** Expiry, unix seconds. */
  e: number;
  /** Set once the human approved: the call is in flight upstream. */
  ok?: true;
  /** The wrapped server's own requestState, when it asked for input itself. */
  u?: string;
  /** Tool fingerprint the approval re-pins (definition-change approvals). */
  fp?: string;
}

/** Deterministic JSON (sorted keys) for hashing. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).filter((k) => obj[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

/** Fingerprint of a tool definition: what a model is told the tool does and takes. */
export function toolFingerprint(tool: Record<string, unknown>): string {
  return sha256(stableStringify({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema,
    annotations: tool.annotations,
  }));
}

function isModernRequest(msg: JsonRpcMessage): boolean {
  const meta = msg.params?._meta as Record<string, unknown> | undefined;
  const v = meta?.[PROTOCOL_VERSION_META_KEY];
  return typeof v === "string" && v >= MODERN_FROM;
}

function errorResult(id: string | number, text: string, modern: boolean): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    result: { ...(modern ? { resultType: "complete" } : {}), content: [{ type: "text", text }], isError: true },
  };
}

interface ParkedCall { msg: JsonRpcMessage }

/** Why a gated call did or did not run. */
type GateOutcome = "approved" | "declined" | "cancelled" | "timeout" | "client-error";

/** The refusal the model (and, through it, the person) is shown for each outcome. */
function refusalFor(tool: string, why: GateOutcome, timeoutMs: number): string {
  switch (why) {
    case "cancelled":
      return `⛔ mcp-guard: the approval prompt for "${tool}" was dismissed, so it was not run. Do not retry — ask the user what they would like to do instead.`;
    case "timeout":
      return `⛔ mcp-guard: nobody answered the approval prompt for "${tool}" within ${Math.round(timeoutMs / 1000)}s, so it was not run. Ask the user whether to try again.`;
    case "client-error":
      return `⛔ mcp-guard: the client could not show the approval prompt for "${tool}", so it was not run and nobody was asked. Use a client that supports approval prompts, or change this tool's rule in the mcp-guard configuration.`;
    default:
      return `⛔ mcp-guard: the human declined "${tool}". Do not retry — ask the user what they would like to do instead.`;
  }
}

export class GuardSession {
  private readonly engine: GuardEngine;
  private readonly key: Uint8Array;
  private readonly ttl: number;
  private readonly now: () => number;
  private gateCounter = 0;
  private listCounter = 0;
  /** Legacy elicitation gates keyed by our injected request id. */
  private readonly pendingGates = new Map<string, { resolve: (approved: boolean, why?: GateOutcome, detail?: string) => void; timer: NodeJS.Timeout }>();
  /** Client tools/list request ids we forwarded (their responses carry definitions). */
  private readonly listRequests = new Set<string | number>();
  /** Guard-originated tools/list refreshes, with the calls waiting on them. */
  private readonly refreshes = new Map<string, ParkedCall[]>();
  /** Approved tools/call ids in flight upstream, with the state to re-wrap an upstream input_required. */
  private readonly approvedInFlight = new Map<string | number, GuardState>();
  /** Approved (pinned) fingerprints, and the latest seen ones. */
  private readonly pinned = new Map<string, string>();
  private readonly latest = new Map<string, string>();
  private listExpiresAt: number | undefined;
  private refreshInFlight: string | undefined;
  /** Whether the client declared elicitation in its 2025-era initialize. */
  private legacyElicitation = false;
  callsAllowed = 0;
  callsDenied = 0;

  constructor(private readonly opts: GuardSessionOptions) {
    this.engine = opts.engine;
    if (opts.stateKey && opts.stateKey.length < 32) throw new Error("mcp-guard: stateKey must be at least 32 bytes");
    this.key = opts.stateKey ?? new Uint8Array(randomBytes(32));
    this.ttl = opts.stateTtlSeconds ?? 600;
    this.now = opts.now ?? Date.now;
  }

  // ── state codec ───────────────────────────────────────────────────────────

  private mint(state: Omit<GuardState, "e">): string {
    const body = Buffer.from(JSON.stringify({ ...state, e: Math.floor(this.now() / 1000) + this.ttl })).toString("base64url");
    const mac = createHmac("sha256", this.key).update(`${STATE_PREFIX}${body}`).digest("base64url");
    return `${STATE_PREFIX}${body}.${mac}`;
  }

  /** null = not ours; "invalid" = ours but forged / expired. */
  private open(state: unknown): GuardState | null | "invalid" {
    if (typeof state !== "string" || !state.startsWith(STATE_PREFIX)) return null;
    const rest = state.slice(STATE_PREFIX.length);
    const dot = rest.lastIndexOf(".");
    if (dot < 0) return "invalid";
    const body = rest.slice(0, dot);
    const mac = Buffer.from(rest.slice(dot + 1), "base64url");
    const expected = createHmac("sha256", this.key).update(`${STATE_PREFIX}${body}`).digest();
    if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return "invalid";
    try {
      const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as GuardState;
      if (typeof parsed.e !== "number" || parsed.e * 1000 < this.now()) return "invalid";
      return parsed;
    } catch {
      return "invalid";
    }
  }

  // ── client → server ───────────────────────────────────────────────────────

  fromClient(msg: JsonRpcMessage): void {
    if (msg.id !== undefined && typeof msg.id === "string" && this.pendingGates.has(msg.id) && msg.method === undefined) {
      this.resolveLegacyGate(msg);
      return;
    }
    if (msg.method === "initialize") {
      const caps = (msg.params?.capabilities ?? {}) as Record<string, unknown>;
      this.legacyElicitation = caps.elicitation !== undefined;
    }
    if (msg.method === "tools/list" && msg.id !== undefined) this.listRequests.add(msg.id);
    if (msg.method === "tools/call" && msg.id !== undefined) {
      this.onToolCall(msg);
      return;
    }
    this.opts.toServer(msg);
  }

  private onToolCall(msg: JsonRpcMessage): void {
    // An expired cached list: refresh it before deciding, so an expired
    // cache cannot hide a changed definition.
    if (this.listExpiresAt !== undefined && this.now() >= this.listExpiresAt) {
      this.refreshThen(msg);
      return;
    }
    this.decideCall(msg);
  }

  private refreshThen(msg: JsonRpcMessage): void {
    if (this.refreshInFlight) {
      this.refreshes.get(this.refreshInFlight)!.push({ msg });
      return;
    }
    const id = `aroha-guard-list-${++this.listCounter}`;
    this.refreshInFlight = id;
    this.refreshes.set(id, [{ msg }]);
    // Same protocol envelope as the call that triggered the refresh.
    const meta = msg.params?._meta as Record<string, unknown> | undefined;
    const envelope: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(meta ?? {})) if (k.startsWith("io.modelcontextprotocol/")) envelope[k] = v;
    this.opts.toServer({ jsonrpc: "2.0", id, method: "tools/list", params: Object.keys(envelope).length ? { _meta: envelope } : {} });
  }

  private decideCall(msg: JsonRpcMessage): void {
    const params = msg.params ?? {};
    const tool = String(params.name ?? "");
    const modern = isModernRequest(msg);
    const opened = modern ? this.open(params.requestState) : null;
    if (opened === "invalid") {
      this.callsDenied++;
      this.audit({ tool, decision: "state-rejected" });
      this.opts.toClient(errorResult(msg.id!, "⛔ mcp-guard: the approval state is invalid or expired. Call the tool again to request a new approval.", modern));
      return;
    }

    // A retry of a call the human already approved, continuing the wrapped
    // server's own multi-round-trip exchange.
    if (opened && opened.ok) {
      if (opened.t !== tool || opened.h !== sha256(stableStringify(params.arguments ?? {}))) {
        this.callsDenied++;
        this.audit({ tool, decision: "state-mismatch" });
        this.opts.toClient(errorResult(msg.id!, "⛔ mcp-guard: the approval does not match this call.", modern));
        return;
      }
      this.forwardApproved(msg, opened, opened.u);
      return;
    }

    const decision = this.engine.decide(tool);
    const fp = this.latest.get(tool);
    const pinned = this.pinned.get(tool);
    const changed = fp !== undefined && pinned !== fp;
    let effective: Decision = decision;
    if (decision.action === "allow" && changed) {
      effective = { action: "gate", reason: `The definition of "${tool}" changed since it was approved` };
    }

    switch (effective.action) {
      case "allow":
        this.engine.recordCall(tool);
        this.callsAllowed++;
        this.audit({ tool, decision: "allow" });
        this.opts.toServer(msg);
        return;
      case "block":
      case "limit-exceeded":
        this.callsDenied++;
        this.audit({ tool, decision: effective.action, detail: effective.reason });
        this.opts.toClient(errorResult(msg.id!, `⛔ mcp-guard: ${effective.reason}`, modern));
        return;
      case "gate":
        if (modern) this.mrtrGate(msg, tool, effective.reason, opened, changed ? fp : undefined);
        else this.legacyGate(msg, tool, effective.reason, changed ? fp : undefined);
        return;
    }
  }

  // ── 2026-07-28: MRTR gate ─────────────────────────────────────────────────

  private mrtrGate(msg: JsonRpcMessage, tool: string, reason: string, state: GuardState | null, repin: string | undefined): void {
    const params = msg.params ?? {};
    const argsHash = sha256(stableStringify(params.arguments ?? {}));
    const caps = ((params._meta as Record<string, unknown> | undefined)?.[CLIENT_CAPABILITIES_META_KEY] ?? {}) as Record<string, unknown>;

    if (state) {
      if (state.t !== tool || state.h !== argsHash) {
        this.callsDenied++;
        this.audit({ tool, decision: "state-mismatch" });
        this.opts.toClient(errorResult(msg.id!, "⛔ mcp-guard: the approval does not match this call.", true));
        return;
      }
      const responses = (params.inputResponses ?? {}) as Record<string, unknown>;
      const answer = responses[GUARD_INPUT_KEY] as { action?: unknown; content?: { approve?: unknown } } | undefined;
      if (answer && typeof answer === "object") {
        if (answer.action === "accept" && answer.content?.approve === true) {
          if (state.fp) this.pinned.set(tool, state.fp);
          this.engine.recordCall(tool);
          this.callsAllowed++;
          this.audit({ tool, decision: "gate-approved", detail: `approval ${state.a}` });
          this.forwardApproved(msg, { ...state, ok: true }, undefined);
          return;
        }
        this.callsDenied++;
        this.audit({ tool, decision: "gate-denied", detail: `approval ${state.a}` });
        this.opts.toClient(errorResult(msg.id!, `⛔ mcp-guard: the human declined "${tool}". Do not retry — ask the user what they would like to do instead.`, true));
        return;
      }
      // No answer yet: ask again under the same approval id.
      this.askMrtr(msg, tool, reason, state.a, argsHash, state.fp);
      return;
    }

    if (caps.elicitation === undefined) {
      this.callsDenied++;
      this.audit({ tool, decision: "gate-unsupported" });
      this.opts.toClient(errorResult(msg.id!,
        `⛔ mcp-guard: "${tool}" requires human approval, and this client does not support elicitation. ` +
        "Approve it from a client that does, or relax the gate in the mcp-guard configuration.", true));
      return;
    }
    this.audit({ tool, decision: "gate-requested" });
    this.askMrtr(msg, tool, reason, randomUUID(), argsHash, repin);
  }

  private askMrtr(msg: JsonRpcMessage, tool: string, reason: string, approvalId: string, argsHash: string, repin: string | undefined): void {
    const args = JSON.stringify((msg.params ?? {}).arguments ?? {});
    const preview = args.length > 400 ? `${args.slice(0, 400)}…` : args;
    this.opts.toClient({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        resultType: "input_required",
        inputRequests: {
          [GUARD_INPUT_KEY]: {
            method: "elicitation/create",
            params: {
              mode: "form",
              message: `mcp-guard: approve tool call "${tool}"? (${reason})\nArguments: ${preview}`,
              requestedSchema: {
                type: "object",
                properties: { approve: { type: "boolean", title: "Approve this tool call", description: "true to allow, false to deny" } },
                required: ["approve"],
              },
            },
          },
        },
        requestState: this.mint({ a: approvalId, t: tool, h: argsHash, ...(repin ? { fp: repin } : {}) }),
      },
    });
  }

  /** Forward an approved call, stripping the guard's own MRTR fields and restoring the server's. */
  private forwardApproved(msg: JsonRpcMessage, state: GuardState, upstreamState: string | undefined): void {
    const params: Record<string, unknown> = { ...(msg.params ?? {}) };
    const responses = { ...((params.inputResponses ?? {}) as Record<string, unknown>) };
    delete responses[GUARD_INPUT_KEY];
    if (Object.keys(responses).length > 0) params.inputResponses = responses;
    else delete params.inputResponses;
    if (upstreamState !== undefined) params.requestState = upstreamState;
    else delete params.requestState;
    if (msg.id !== undefined) this.approvedInFlight.set(msg.id, { ...state, u: undefined });
    this.opts.toServer({ ...msg, params });
  }

  // ── pre-2026: elicitation gate ────────────────────────────────────────────

  private legacyGate(original: JsonRpcMessage, tool: string, reason: string, repin: string | undefined): void {
    // A client that did not declare elicitation in initialize cannot show the
    // prompt. Asking anyway used to end in an error or a timeout that was then
    // reported as "the human declined" — so a person who was never asked was
    // told they had said no. Say what actually happened, at once.
    if (!this.legacyElicitation) {
      this.callsDenied++;
      this.audit({ tool, decision: "gate-unsupported" });
      this.opts.toClient(errorResult(original.id!,
        `⛔ mcp-guard: "${tool}" needs your approval, but this client cannot show approval prompts ` +
        "(it did not declare MCP elicitation support), so it was not run and nobody was asked. " +
        "Use a client that supports approval prompts, or change this tool's rule in the mcp-guard configuration.", false));
      return;
    }
    this.audit({ tool, decision: "gate-requested" });
    const gateId = `aroha-guard-${++this.gateCounter}`;
    const args = JSON.stringify((original.params ?? {}).arguments ?? {});
    const preview = args.length > 400 ? `${args.slice(0, 400)}…` : args;

    const settle = (approved: boolean, why: GateOutcome = approved ? "approved" : "declined", detail?: string) => {
      const pending = this.pendingGates.get(gateId);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pendingGates.delete(gateId);
      if (approved) {
        if (repin) this.pinned.set(tool, repin);
        this.engine.recordCall(tool);
        this.callsAllowed++;
        this.audit({ tool, decision: "gate-approved" });
        this.opts.toServer(original);
      } else {
        this.callsDenied++;
        this.audit({ tool, decision: why === "declined" ? "gate-denied" : `gate-${why}`, ...(detail ? { detail } : {}) });
        this.opts.toClient(errorResult(original.id!, refusalFor(tool, why, this.opts.gateTimeoutMs ?? 120_000), false));
      }
    };
    const timer = setTimeout(() => settle(false, "timeout"), this.opts.gateTimeoutMs ?? 120_000);
    timer.unref?.();
    this.pendingGates.set(gateId, { resolve: settle, timer });

    this.opts.toClient({
      jsonrpc: "2.0",
      id: gateId,
      method: "elicitation/create",
      params: {
        message: `mcp-guard: approve tool call "${tool}"? (${reason})\nArguments: ${preview}`,
        requestedSchema: {
          type: "object",
          properties: { approve: { type: "boolean", title: "Approve this tool call", description: "true to allow, false to deny" } },
          required: ["approve"],
        },
      },
    });
  }

  private resolveLegacyGate(msg: JsonRpcMessage): void {
    const pending = this.pendingGates.get(msg.id as string)!;
    // Every outcome other than an explicit "accept, approve: true" denies —
    // but each is reported as what it was, not as a decision the person made.
    if (msg.error) {
      const e = msg.error as { message?: unknown };
      pending.resolve(false, "client-error", typeof e.message === "string" ? e.message.slice(0, 200) : undefined);
      return;
    }
    const result = msg.result as { action?: string; content?: { approve?: unknown } } | undefined;
    if (result?.action === "accept") {
      pending.resolve(result.content?.approve === true, "declined");
    } else {
      pending.resolve(false, result?.action === "cancel" ? "cancelled" : "declined");
    }
  }

  // ── server → client ───────────────────────────────────────────────────────

  fromServer(msg: JsonRpcMessage): void {
    if (msg.id !== undefined && msg.method === undefined) {
      // Our own list refresh.
      if (typeof msg.id === "string" && this.refreshes.has(msg.id)) {
        const parked = this.refreshes.get(msg.id)!;
        this.refreshes.delete(msg.id);
        this.refreshInFlight = undefined;
        if (msg.result) this.observeToolList(msg.result);
        else this.listExpiresAt = undefined; // refresh failed: decide on what we have, do not loop
        for (const p of parked) this.decideCall(p.msg);
        return;
      }
      if (this.listRequests.has(msg.id)) {
        this.listRequests.delete(msg.id);
        if (msg.result) this.observeToolList(msg.result);
      }
      const approved = this.approvedInFlight.get(msg.id);
      if (approved) {
        this.approvedInFlight.delete(msg.id);
        const result = msg.result as Record<string, unknown> | undefined;
        if (result?.resultType === "input_required") {
          // The wrapped server asks for more input on an approved call: wrap
          // its state in ours so the retry is recognised as already approved.
          const upstream = typeof result.requestState === "string" ? result.requestState : undefined;
          const state: Omit<GuardState, "e"> = { a: approved.a, t: approved.t, h: approved.h, ok: true, ...(upstream !== undefined ? { u: upstream } : {}) };
          this.opts.toClient({ ...msg, result: { ...result, requestState: this.mint(state) } });
          return;
        }
      }
    }
    this.opts.toClient(msg);
  }

  /** Record tool fingerprints and the list's freshness window. */
  private observeToolList(result: unknown): void {
    const r = result as { tools?: unknown; ttlMs?: unknown };
    if (!Array.isArray(r.tools)) return;
    for (const t of r.tools) {
      if (!t || typeof t !== "object") continue;
      const name = String((t as { name?: unknown }).name ?? "");
      if (!name) continue;
      const fp = toolFingerprint(t as Record<string, unknown>);
      this.latest.set(name, fp);
      // First sight pins the definition the session starts with.
      if (!this.pinned.has(name)) this.pinned.set(name, fp);
    }
    this.listExpiresAt = typeof r.ttlMs === "number" && r.ttlMs > 0 ? this.now() + r.ttlMs : undefined;
  }

  private audit(entry: GuardAuditEntry): void {
    this.opts.audit?.(entry);
  }
}
