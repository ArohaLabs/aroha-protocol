// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ LangChain/AutoGen Bridge
 *
 * Aroha is the transport and identity layer. Your existing agent framework
 * (LangChain, AutoGen, Semantic Kernel, LlamaIndex) keeps its reasoning,
 * memory, and tool-calling logic unchanged.
 *
 * This bridge lets you:
 *   1. Expose LangChain tools as Aroha capabilities (so other Aroha agents
 *      can discover and call your tools with signed envelopes).
 *   2. Wrap Aroha capabilities as LangChain tools (so your LangChain agent
 *      can call remote Aroha agents transparently).
 */

import {
  ArohaClient,
  ArohaServer,
  buildEnvelope,
  newCorrelationId,
  generateKeyPair,
  generateDid,
  assertSecureEndpoint,
  type ArohaEnvelope,
  type ArohaServerOptions,
  type MessageHandler,
  type ArohaRequestBody,
  type ArohaResponseBody,
} from "@aroha-sdk/core";
import {
  type LangChainToolLike,
  type OpenAIFunctionLike,
  type ArohaCapabilityDescriptor,
} from "./types.js";

// ─── Aroha capability → LangChain tool ────────────────────────────────────────

export interface ArohaCapabilityToToolOptions {
  /** The Aroha endpoint URL of the remote agent. */
  endpoint: string;
  /** The DID of the remote agent (the "to" field). */
  agentDID: string;
  /** DID of the calling agent (the "from" field). */
  callerDID: string;
  /** Ed25519 private key of the calling agent for signing envelopes. */
  callerPrivateKey: Uint8Array;
  /** Human-readable description used by the LLM to decide when to call this tool. */
  description: string;
  /** JSON Schema for the capability's params. Optional. */
  schema?: Record<string, unknown>;
  client?: ArohaClient;
}

/** OpenAI function names: letters, digits, `_` and `-`, at most 64 characters. */
export const OPENAI_FUNCTION_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * The tool name for a capability id: every character outside
 * [a-zA-Z0-9_-] becomes `_`. A result longer than 64 characters (the
 * OpenAI limit) keeps its first 55 characters plus `_` and an 8-hex-digit
 * hash of the full capability id, so two long ids do not collapse into one
 * name. The name is only a label for the model; calls still send the
 * original capability id.
 */
export function toolNameFor(capabilityId: string): string {
  if (typeof capabilityId !== "string" || capabilityId.length === 0) {
    throw new TypeError("capabilityId must be a non-empty string");
  }
  const name = capabilityId.replace(/[^a-zA-Z0-9_-]/g, "_");
  if (name.length <= 64) return name;
  // FNV-1a (32-bit): stable across runs and platforms, no dependency.
  let h = 0x811c9dc5;
  for (const ch of capabilityId) {
    h ^= ch.codePointAt(0)!;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `${name.slice(0, 55)}_${h.toString(16).padStart(8, "0")}`;
}

/**
 * Wrap a single Aroha capability as a LangChain-compatible tool.
 *
 * The returned tool sends a signed ArohaRequest to the remote agent and
 * returns the JSON-serialised result as a string (what LangChain expects).
 */
export function arohaCapabilityToLangChainTool(
  capabilityId: string,
  opts: ArohaCapabilityToToolOptions
): LangChainToolLike {
  const client = opts.client ?? new ArohaClient();

  return {
    name: toolNameFor(capabilityId),
    description: opts.description,
    schema: opts.schema,

    async call(input: string | Record<string, unknown>): Promise<string> {
      const params: Record<string, unknown> =
        typeof input === "string" ? JSON.parse(input) : input;

      const body: ArohaRequestBody = { capability: capabilityId, params };
      const correlationId = newCorrelationId();
      const envelope = await buildEnvelope(
        "ArohaRequest",
        opts.callerDID,
        opts.agentDID,
        body,
        correlationId,
        opts.callerPrivateKey
      );

      const response = await client.send(opts.endpoint, envelope);
      if (!response) throw new Error(`No response from ${opts.agentDID}`);
      if (response.type === "ArohaError") {
        throw new Error((response.body as { message: string }).message);
      }

      const result = (response.body as ArohaResponseBody).result;
      return typeof result === "string" ? result : JSON.stringify(result);
    },
  };
}

/**
 * Wrap a single Aroha capability as an OpenAI Chat Completions function tool:
 * `{ type: "function", function: { name, description, parameters } }`, plus
 * an `invoke(args)` method. JSON serialisation drops functions, so the
 * object can be passed to an OpenAI client's `tools` as-is.
 *
 * `schema`, when given, must be a JSON Schema whose top-level `type` is
 * "object" — the OpenAI API rejects anything else. Without a schema,
 * `parameters` is omitted, which OpenAI reads as "no parameters". `strict`
 * is not set.
 */
export function arohaCapabilityToOpenAITool(
  capabilityId: string,
  opts: ArohaCapabilityToToolOptions
): OpenAIFunctionLike {
  if (opts.schema !== undefined && (opts.schema === null || typeof opts.schema !== "object" || opts.schema.type !== "object")) {
    throw new TypeError(`arohaCapabilityToOpenAITool: schema for ${capabilityId} must be a JSON Schema with type "object"`);
  }
  const langChainTool = arohaCapabilityToLangChainTool(capabilityId, opts);
  return {
    type: "function",
    function: {
      name: langChainTool.name,
      description: langChainTool.description,
      parameters: opts.schema,
    },
    async invoke(args: Record<string, unknown>): Promise<unknown> {
      const result = await langChainTool.call(args);
      try { return JSON.parse(result); } catch { return result; }
    },
  };
}

// ─── LangChain tools → Aroha provider ─────────────────────────────────────────

export interface LangChainAgentToArohaOptions {
  agentDID: string;
  agentPrivateKey: Uint8Array;
  port: number;
  resolvePublicKey: ArohaServerOptions["resolvePublicKey"];
  didDocument: ArohaServerOptions["didDocument"];
}

/**
 * Expose a set of LangChain tools as a Aroha provider agent.
 *
 * Each tool becomes a Aroha capability. Inbound ArohaRequest envelopes are
 * routed to the matching tool. The tool's string result is returned as a
 * ArohaResponse.
 *
 * Returns the ArohaServer — call .start() to begin accepting connections.
 */
export function langChainAgentToArohaProvider(
  tools: LangChainToolLike[],
  opts: LangChainAgentToArohaOptions
): ArohaServer {
  const toolMap = new Map(tools.map((t) => [t.name, t]));

  const onMessage: MessageHandler = async (envelope, respond) => {
    if (envelope.type !== "ArohaRequest") return;

    const body = envelope.body as ArohaRequestBody;
    const tool = toolMap.get(body.capability);

    if (!tool) {
      const errEnvelope = await buildEnvelope(
        "ArohaError",
        opts.agentDID,
        envelope.from,
        {
          code: "Aroha_UNKNOWN_CAPABILITY" as never,
          message: `Unknown capability: ${body.capability}`,
          retryable: false,
        },
        envelope.correlationId,
        opts.agentPrivateKey
      );
      respond(errEnvelope);
      return;
    }

    try {
      const rawResult = await tool.call(body.params);
      let result: Record<string, unknown>;
      try { result = JSON.parse(rawResult); } catch { result = { output: rawResult }; }

      const responseBody: ArohaResponseBody = { capability: body.capability, result };
      const reply = await buildEnvelope(
        "ArohaResponse",
        opts.agentDID,
        envelope.from,
        responseBody,
        envelope.correlationId,
        opts.agentPrivateKey
      );
      respond(reply);
    } catch (err) {
      const errEnvelope = await buildEnvelope(
        "ArohaError",
        opts.agentDID,
        envelope.from,
        {
          code: "Aroha_INTERNAL_ERROR" as never,
          message: String(err),
          retryable: true,
        },
        envelope.correlationId,
        opts.agentPrivateKey
      );
      respond(errEnvelope);
    }
  };

  return new ArohaServer({
    agentDID: opts.agentDID,
    didDocument: opts.didDocument,
    port: opts.port,
    onMessage,
    resolvePublicKey: opts.resolvePublicKey,
  });
}

// ─── createArohaLangChainTool() — zero-config convenience ────────────────────

/**
 * Create a LangChain-compatible tool that calls a remote Aroha agent —
 * without managing DIDs or private keys yourself.
 *
 * This is the zero-friction path for LangChain developers:
 *
 * ```typescript
 * import { createArohaLangChainTool } from "@aroha-sdk/langchain-bridge";
 *
 * const flightTool = await createArohaLangChainTool(
 *   "http://localhost:3001",
 *   "search-flights",
 *   "Search available flights by origin, destination, and date"
 * );
 *
 * const agent = createOpenAIFunctionsAgent({ tools: [flightTool], ... });
 * ```
 *
 * The caller identity is an ephemeral, per-call content-addressed DID whose
 * key verifiers can derive from the DID itself. The remote agent's DID is
 * `opts.agentDID` when given, else discovered from its
 * /.well-known/aroha-agent.json — and if neither yields one, this throws.
 */
export async function createArohaLangChainTool(
  endpoint: string,
  capabilityId: string,
  description: string,
  opts?: {
    schema?: Record<string, unknown>;
    client?: ArohaClient;
    /** The remote agent's DID. Recommended: pin it rather than trusting discovery. */
    agentDID?: string;
    /** DEVELOPMENT ONLY: allow http:// to a non-loopback endpoint. */
    allowInsecureHttp?: boolean;
  }
): Promise<LangChainToolLike> {
  assertSecureEndpoint(endpoint, { allowInsecureHttp: opts?.allowInsecureHttp, label: "endpoint" });

  // Ephemeral caller identity. WHY not node:crypto's generateKeyPairSync:
  // its PKCS#8 DER export is a 48-byte ASN.1 blob, not the 32-byte Ed25519
  // seed buildEnvelope signs with — every request was signed with garbage.
  // And the DID used to be `did:aroha:caller-<time>`, which no verifier can
  // resolve to a key; the content-addressed form carries its own key.
  const { privateKey: callerPrivateKey, publicKey } = await generateKeyPair();
  const callerDID = generateDid(publicKey);

  // The recipient DID goes into the signed envelope's `to`. It used to fall
  // back to `did:aroha:unknown` — a request addressed to nobody, which a
  // conformant server rejects and a careless one might not.
  let agentDID = opts?.agentDID;
  if (!agentDID) {
    try {
      const wellKnown = await fetch(`${endpoint}/.well-known/aroha-agent.json`, {
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (wellKnown.ok) {
        const doc = await wellKnown.json() as { did?: unknown; id?: unknown };
        const found = typeof doc.did === "string" ? doc.did : typeof doc.id === "string" ? doc.id : undefined;
        if (found && found.startsWith("did:")) agentDID = found;
      }
    } catch {
      // handled below
    }
  }
  if (!agentDID) {
    throw new Error(
      `createArohaLangChainTool: could not determine the agent DID for ${endpoint}; pass opts.agentDID`
    );
  }

  return arohaCapabilityToLangChainTool(capabilityId, {
    endpoint,
    agentDID,
    callerDID,
    callerPrivateKey,
    description,
    schema: opts?.schema,
    client: opts?.client,
  });
}

// ─── Describe Aroha capabilities ──────────────────────────────────────────────

/**
 * Convert a LangChain tool list to Aroha capability descriptors.
 * Use these to register the agent in InMemoryRegistry or ArohaRegistry.
 */
export function langChainToolsToCapabilities(
  tools: LangChainToolLike[]
): ArohaCapabilityDescriptor[] {
  return tools.map((t) => ({
    capabilityId: t.name,
    description: t.description,
    inputSchema: t.schema,
  }));
}
