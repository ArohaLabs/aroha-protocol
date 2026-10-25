// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { RunRequest, RunResponse, RunEvent } from "./types.js";
import { signRequest } from "./signing.js";
import { assertSecureEndpoint, resolveRegistryUrl, resolveIpfsGateway } from "@aroha-sdk/core/endpoints";

/** Default timeout for a registry/IPFS lookup, in ms. */
const LOOKUP_TIMEOUT_MS = 10_000;
/** Default timeout for an agent call, in ms (agent runs can be long). */
const CALL_TIMEOUT_MS = 120_000;

interface AgentRecord {
  endpointUrl?: string | null;
  manifestCID?: string;
  did?:         string;
  active?:      boolean;
}

interface CallOptions {
  sessionId?:    string;
  history?:      Array<{ role: string; content: string }>;
  context?:      Record<string, unknown>;
  bearerToken?:  string;
  registryUrl?:  string;
  trust?:        "trusted" | "untrusted";
  /**
   * Call as this agent, for a callee running `auth: "aroha-sig"`.
   *
   * The request is signed with the DID's Ed25519 key, which proves *which*
   * agent is calling — something a bearer token cannot do, since every holder
   * of a shared token is indistinguishable.
   *
   * `bearerToken` and `signAs` are different schemes; a callee runs one or the
   * other. Passing both sends both, which is harmless but means you have not
   * decided which you rely on.
   */
  signAs?: { did: string; privateKey: Uint8Array };
  /**
   * DEVELOPMENT ONLY: allow http:// endpoints on non-loopback hosts. The
   * endpoint URL comes from the registry — data anyone who registers an
   * agent controls — so by default it must be https:// (or loopback).
   */
  allowInsecureHttp?: boolean;
  /** Abort the agent call after this many ms. Default 120 000. */
  timeoutMs?: number;
}

/** Validate a registry-supplied endpoint and return it without a trailing slash. */
function agentEndpoint(endpointUrl: string, opts: CallOptions): string {
  assertSecureEndpoint(endpointUrl, { allowInsecureHttp: opts.allowInsecureHttp, label: "agent endpointUrl" });
  return endpointUrl.replace(/\/$/, "");
}

/**
 * Build the headers and the exact body string for a call.
 *
 * The body is serialised ONCE and returned, because the signature covers a hash
 * of the body bytes. Re-serialising before sending — even to JSON that looks
 * identical but orders keys differently — produces a different hash and the
 * callee rejects it. Returning the string forces the caller to send what was
 * actually signed.
 */
async function prepareRequest(
  path: string,
  payload: RunRequest,
  opts: CallOptions,
): Promise<{ headers: Record<string, string>; body: string }> {
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (opts.bearerToken) headers["Authorization"] = `Bearer ${opts.bearerToken}`;

  if (opts.signAs) {
    // The signed path must match what the server verifies, which is the URL
    // pathname alone — no origin, no query string.
    const signed = await signRequest({
      did:        opts.signAs.did,
      privateKey: opts.signAs.privateKey,
      method:     "POST",
      path,
      body,
    });
    Object.assign(headers, signed);
  }

  return { headers, body };
}

/** Turn a rejected call into a message that names the scheme actually in play. */
function authError(status: number, opts: CallOptions): Error | null {
  if (status !== 401) return null;
  if (opts.signAs) {
    return new Error(
      "Agent rejected the signature (401). The caller DID may not be on its " +
      "allowedCallers list, its public key may not resolve from the registry, " +
      "or the clock skew may exceed the accepted window.",
    );
  }
  return new Error(
    "Agent requires authentication (401) — pass bearerToken, or signAs for an " +
    "agent running auth: \"aroha-sig\"",
  );
}

/**
 * Resolve an agent record from the Aroha registry by didHash.
 */
export async function resolveAgent(
  didHash:    string,
  registryUrl?: string,
): Promise<AgentRecord> {
  const base = resolveRegistryUrl(registryUrl);
  assertSecureEndpoint(base, { label: "registryUrl" });
  const res = await fetch(`${base}/v1/agents/${encodeURIComponent(didHash)}`, {
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Registry returned ${res.status} for ${didHash}`);
  return res.json() as Promise<AgentRecord>;
}

/**
 * Resolve the agent manifest from IPFS by CID.
 */
export async function resolveManifest(cid: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${resolveIpfsGateway()}/${encodeURIComponent(cid)}`, {
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`IPFS returned ${res.status} for CID ${cid}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Call an Aroha agent by didHash. Resolves the endpoint from the registry,
 * then POSTs to /v1/run.
 *
 * @example
 * const { message, sessionId } = await callAgent("abc123", "Hello!");
 */
export async function callAgent(
  didHash: string,
  message: string,
  opts:    CallOptions = {},
): Promise<RunResponse> {
  const { registryUrl, sessionId, history = [], context = {} } = opts;

  const record = await resolveAgent(didHash, registryUrl);
  if (!record.endpointUrl) {
    throw new Error(
      `Agent ${didHash} has no hosted endpoint — it requires callers to supply their own LLM API key. Use the Hub chat UI instead.`
    );
  }

  const endpoint = agentEndpoint(record.endpointUrl, opts);
  const { headers, body } = await prepareRequest(
    "/v1/run",
    { message, sessionId, history, context, trust: opts.trust },
    opts,
  );

  const res = await fetch(`${endpoint}/v1/run`, {
    method: "POST", headers, body,
    signal: AbortSignal.timeout(opts.timeoutMs ?? CALL_TIMEOUT_MS),
  });

  const authErr = authError(res.status, opts);
  if (authErr) throw authErr;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Agent returned ${res.status}: ${text}`);
  }

  return res.json() as Promise<RunResponse>;
}

/**
 * Stream typed events from an Aroha agent. Resolves the endpoint from the
 * registry, POSTs to /v1/run with stream:true, and yields parsed RunEvent
 * objects as they arrive over SSE.
 *
 * @example
 * for await (const event of streamAgent("abc123", "Hello!")) {
 *   if (event.type === "token")  process.stdout.write(event.delta);
 *   if (event.type === "final")  console.log("\nDone:", event.message);
 *   if (event.type === "tool_call") console.log("Tool:", event.name, event.args);
 * }
 */
export async function* streamAgent(
  didHash: string,
  message: string,
  opts:    CallOptions = {},
): AsyncGenerator<RunEvent> {
  const { registryUrl, sessionId, history = [], context = {}, trust } = opts;

  const record = await resolveAgent(didHash, registryUrl);
  if (!record.endpointUrl) {
    throw new Error(
      `Agent ${didHash} has no hosted endpoint — use the Hub chat UI instead.`
    );
  }

  const endpoint = agentEndpoint(record.endpointUrl, opts);
  const { headers, body } = await prepareRequest(
    "/v1/run",
    { message, sessionId, history, context, stream: true, trust },
    opts,
  );

  const res = await fetch(`${endpoint}/v1/run`, {
    method: "POST", headers, body,
    signal: AbortSignal.timeout(opts.timeoutMs ?? CALL_TIMEOUT_MS),
  });

  const authErr = authError(res.status, opts);
  if (authErr) throw authErr;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Agent returned ${res.status}: ${text}`);
  }

  if (!res.body) throw new Error("Expected a streaming response body");

  const decoder = new TextDecoder();
  const reader  = res.body.getReader();
  let buffer    = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE lines: "data: {...}\n\n"
    const parts = buffer.split("\n\n");
    buffer = parts.pop() ?? "";  // last (possibly incomplete) chunk stays in buffer

    for (const part of parts) {
      const line = part.trim();
      if (!line.startsWith("data: ")) continue;
      try {
        const event = JSON.parse(line.slice(6)) as RunEvent;
        yield event;
      } catch {
        // malformed line — skip
      }
    }
  }
}

/**
 * Returns a version of callAgent / streamAgent with forced trust attenuation.
 * All calls made through the returned functions will have:
 *   - trust: "untrusted"  (content from this agent chain is flagged as untrusted)
 *   - any additional forced options you supply
 *
 * Use when an orchestrator delegates to a worker that may relay user-supplied
 * or external content — prevents the worker's output from being treated as
 * privileged instructions by downstream agents.
 *
 * @example
 * const { call, stream } = attenuateCallAgent({ trust: "untrusted" });
 * const result = await call(workerDidHash, userMessage);
 */
export function attenuateCallAgent(forced: Pick<CallOptions, "trust" | "context">): {
  call:   typeof callAgent;
  stream: typeof streamAgent;
} {
  return {
    call: (didHash, message, opts = {}) =>
      callAgent(didHash, message, { ...opts, ...forced }),
    stream: (didHash, message, opts = {}) =>
      streamAgent(didHash, message, { ...opts, ...forced }),
  };
}

/**
 * List agents from the Aroha registry.
 */
export async function listAgents(opts: {
  org?:          string;
  limit?:        number;
  registryUrl?:  string;
} = {}): Promise<AgentRecord[]> {
  const { org, limit = 20, registryUrl: registryOverride } = opts;
  const registryUrl = resolveRegistryUrl(registryOverride);
  const params = new URLSearchParams({ limit: String(limit) });
  if (org) params.set("org", org);
  const res = await fetch(`${registryUrl}/v1/agents?${params}`);
  if (!res.ok) throw new Error(`Registry returned ${res.status}`);
  const data = await res.json() as { agents?: AgentRecord[] };
  return data.agents ?? [];
}

// ── MCP servers ──────────────────────────────────────────────────────────────

export interface McpRecord {
  did:           string;
  didHash:       string;
  publishedBy:   string | null;
  name:          string;
  description:   string;
  endpointUrl:   string;
  toolIds:       string[];
  manifestCID:   string;
  active:        boolean;
  registeredAt:  number;
  lastUpdatedAt: number;
}

function randomId(): string {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2) + Date.now().toString(36);
}

/**
 * Register an MCP server on the Aroha registry.
 *
 * POST /v1/mcps requires `did`, `name`, and `endpointUrl` — a request missing
 * `did` gets 400. One is generated when omitted.
 *
 * The registry indexes tool NAMES only (`toolIds`); passing full MCP tool
 * definitions here is fine — only `name` is extracted from each.
 */
export async function registerMcp(opts: {
  name:         string;
  endpointUrl:  string;
  description?: string;
  tools?:       Array<string | { name: string }>;
  did?:         string;
  apiKey:       string;
  registryUrl?: string;
}): Promise<{ didHash: string }> {
  const { name, endpointUrl, description = "", tools = [], apiKey, registryUrl: registryOverride } = opts;
  const registryUrl = resolveRegistryUrl(registryOverride);
  const did = opts.did ?? `did:aroha:studio:${randomId()}`;
  const toolIds = tools.map((t) => (typeof t === "string" ? t : t.name)).filter(Boolean);

  const res = await fetch(`${registryUrl}/v1/mcps`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body:    JSON.stringify({ did, name, description, endpointUrl, toolIds }),
  });
  if (!res.ok) throw new Error(`Registry returned ${res.status}: ${await res.text()}`);
  return res.json() as Promise<{ didHash: string }>;
}

/** Resolve a single MCP server by DID or didHash. */
export async function resolveMcp(didOrHash: string, registryOverride?: string): Promise<McpRecord> {
  const registryUrl = resolveRegistryUrl(registryOverride);
  const res = await fetch(`${registryUrl}/v1/mcps/${encodeURIComponent(didOrHash)}`);
  if (!res.ok) throw new Error(`Registry returned ${res.status}`);
  return res.json() as Promise<McpRecord>;
}

/** List registered MCP servers. Unlike listAgents, this endpoint returns a bare array. */
export async function listMcps(opts: {
  limit?:       number;
  offset?:      number;
  registryUrl?: string;
} = {}): Promise<McpRecord[]> {
  const { limit = 50, offset = 0, registryUrl: registryOverride } = opts;
  const registryUrl = resolveRegistryUrl(registryOverride);
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const res = await fetch(`${registryUrl}/v1/mcps?${params}`);
  if (!res.ok) throw new Error(`Registry returned ${res.status}`);
  return res.json() as Promise<McpRecord[]>;
}

// ── Registry skill listings ──────────────────────────────────────────────────
//
// NAMING COLLISION, stated rather than left to be discovered. "Skill" here
// means a REGISTRY LISTING: a name, a description and an endpoint, published
// so others can look the service up. It is a directory entry.
//
// Everywhere else in the industry — and now in aroha-runtime — a skill is an
// Agent Skill in the open SKILL.md format: a folder of procedural knowledge
// that an agent loads into its context to learn how a task is done here. That
// spec was opened in December 2025 and is read by roughly forty agent
// products. It is not this.
//
// These functions are kept because the registry serves them today and clients
// depend on them; removing them would break a deployed service. New work
// wanting agent capability should use the runtime's SkillStore, not this.
//
// `skillType` in particular is the field the capability-honesty design called
// out: it is validated, stored and round-tripped, and nothing reads it to
// change any behaviour. Treat it as a label on a listing, never as a
// statement about what an agent can do.

/**
 * @deprecated Registry listing, NOT an Agent Skill. Validated, stored and round-tripped; read by nothing to change any behaviour.
 * An Agent Skill is a SKILL.md folder of procedural knowledge in the open
 * format ~40 agent products read; see aroha-runtime's SkillStore. These
 * remain because the registry serves them and clients depend on them.
 */
export const SKILL_TYPES = ["rag", "web-search", "memory", "code", "data", "custom"] as const;
export type SkillType = typeof SKILL_TYPES[number];

export interface SkillRecord {
  did:           string;
  didHash:       string;
  publishedBy:   string | null;
  name:          string;
  description:   string;
  skillType:     SkillType;
  endpointUrl:   string | null;
  manifestCID:   string;
  active:        boolean;
  registeredAt:  number;
  lastUpdatedAt: number;
}

/**
 * Register a skill on the Aroha registry.
 *
 * POST /v1/skills requires `did` and `name` — a request missing `did` gets 400.
 * One is generated when omitted. `skillType` defaults to "custom" server-side.
 */
/**
 * @deprecated Registry listing, NOT an Agent Skill. Publishes a registry listing, not an Agent Skill.
 * An Agent Skill is a SKILL.md folder of procedural knowledge in the open
 * format ~40 agent products read; see aroha-runtime's SkillStore. These
 * remain because the registry serves them and clients depend on them.
 */
export async function registerSkill(opts: {
  name:         string;
  skillType?:   SkillType;
  description?: string;
  endpointUrl?: string;
  did?:         string;
  apiKey:       string;
  registryUrl?: string;
}): Promise<{ didHash: string }> {
  const { name, skillType = "custom", description = "", endpointUrl, apiKey, registryUrl: registryOverride } = opts;
  const registryUrl = resolveRegistryUrl(registryOverride);
  const did = opts.did ?? `did:aroha:studio:${randomId()}`;

  const body: Record<string, unknown> = { did, name, description, skillType };
  if (endpointUrl) body.endpointUrl = endpointUrl;

  const res = await fetch(`${registryUrl}/v1/skills`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body:    JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Registry returned ${res.status}: ${await res.text()}`);
  return res.json() as Promise<{ didHash: string }>;
}

/** Resolve a single skill by DID or didHash. */
/**
 * @deprecated Registry listing, NOT an Agent Skill. Resolves a registry listing, not an Agent Skill.
 * An Agent Skill is a SKILL.md folder of procedural knowledge in the open
 * format ~40 agent products read; see aroha-runtime's SkillStore. These
 * remain because the registry serves them and clients depend on them.
 */
export async function resolveSkill(didOrHash: string, registryOverride?: string): Promise<SkillRecord> {
  const registryUrl = resolveRegistryUrl(registryOverride);
  const res = await fetch(`${registryUrl}/v1/skills/${encodeURIComponent(didOrHash)}`);
  if (!res.ok) throw new Error(`Registry returned ${res.status}`);
  return res.json() as Promise<SkillRecord>;
}

/** List registered skills, optionally filtered by skillType. */
/**
 * @deprecated Registry listing, NOT an Agent Skill. Lists registry listings, not Agent Skills.
 * An Agent Skill is a SKILL.md folder of procedural knowledge in the open
 * format ~40 agent products read; see aroha-runtime's SkillStore. These
 * remain because the registry serves them and clients depend on them.
 */
export async function listSkills(opts: {
  skillType?:   SkillType;
  limit?:       number;
  offset?:      number;
  registryUrl?: string;
} = {}): Promise<SkillRecord[]> {
  const { skillType, limit = 50, offset = 0, registryUrl: registryOverride } = opts;
  const registryUrl = resolveRegistryUrl(registryOverride);
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (skillType) params.set("type", skillType);
  const res = await fetch(`${registryUrl}/v1/skills?${params}`);
  if (!res.ok) throw new Error(`Registry returned ${res.status}`);
  return res.json() as Promise<SkillRecord[]>;
}
