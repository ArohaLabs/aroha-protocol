// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ MCP Bridge
 *
 * Two directions:
 *
 *   toMcp()    — Wrap a discovered Aroha agent's capabilities as MCP tool definitions.
 *                Claude Desktop / any MCP client can call them as normal tools.
 *                The bridge transparently sends ArohaRequest messages under the hood.
 *
 *   fromMcp()  — Expose an MCP server's tools as a Aroha capability manifest.
 *                Any Aroha orchestrator can discover and call the MCP server
 *                without knowing it's MCP-backed.
 *
 * The bridge is purely an adapter — it translates formats.
 * It adds no business logic and changes no message semantics.
 */

import {
  buildDIDDocument,
  buildEnvelope,
  validateEnvelope,
  NonceRegistry,
  ArohaClient,
  readBody,
  type ArohaEnvelope,
  type PublicKeyResolver,
} from "@aroha-sdk/core";
import * as ed from "@noble/ed25519";
import { type ArohaRequestBody, type ArohaReserveBody } from "@aroha-sdk/core";
import { type DiscoveredAgent, type CapabilityDefinition, ArohaHttpRegistry } from "@aroha-sdk/registry";
import {
  verifyMandateChain,
  createMandateKeyResolver,
  redeemPaymentMandate,
  InMemoryRedemptionStore,
  SpendingConstraintViolation,
  governedVerification,
  type GovernedVerificationOptions,
  type MandateRevocationCheck,
  type RedemptionStore,
} from "@aroha-sdk/credentials";
import type { ArohaSpendingMandateBody, KelSource, KelStore } from "@aroha-sdk/core";
import { MANDATE_META_KEY, PresentationNonces, verifyPresentation } from "./mcp-wire.js";

export {
  MANDATE_META_KEY,
  MANDATE_PRESENTATION_PURPOSE,
  presentMandate,
  verifyPresentation,
  argsDigest,
  PresentationNonces,
  type MandatePresentation,
} from "./mcp-wire.js";

// ─── MCP Types (subset of the MCP spec we need) ───────────────────────────────

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  /** Aroha metadata — carried as an extension field */
  _aroha?: {
    agentDID: string;
    capabilityId: string;
    sagaRole: "none" | "participant";
  };
}

export type McpToolCallResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

// ─── Aroha → MCP ───────────────────────────────────────────────────────────────

export interface ArohaAgentToMcpToolsOptions {
  /**
   * Spending/authority mandate to carry on every outgoing request, in
   * body.credentialToken (where wrapMcp and other Aroha providers read it).
   * A function picks one per call — e.g. a payment mandate only for priced
   * tools. Without it requests carry no mandate, and a provider that
   * requires one refuses them.
   */
  mandateToken?: string | ((toolName: string, args: Record<string, unknown>) => string | undefined | Promise<string | undefined>);
  /**
   * Resolves the provider's DID to its Ed25519 key, used to verify the
   * response envelope's signature. When set, response verification is ON
   * by default.
   */
  resolvePublicKey?: PublicKeyResolver;
  /**
   * Verify every response envelope: signed by the agent's DID, addressed to
   * the orchestrator, unexpired, not replayed, and carrying the request's
   * correlationId. Default: true when resolvePublicKey is given, false
   * otherwise. Setting it true without a resolver throws — a verification
   * that cannot run must not be reported as on.
   */
  verifyResponse?: boolean;
}

/**
 * Convert a discovered Aroha agent's capabilities into MCP tool definitions.
 * Returns both the definitions (for registering with MCP) and a handler
 * function that executes the tool call via Aroha.
 *
 * Outbound trust: the result of a tool call is whatever the provider's
 * response says. Without response verification, anything on the path to the
 * provider (or a provider endpoint answering for a different DID) can put
 * words in that DID's mouth, and the MCP client shows them as the agent's
 * result. Pass `options.resolvePublicKey` to verify every response.
 */
export function arohaAgentToMcpTools(
  agent: DiscoveredAgent,
  orchestratorDID: string,
  orchestratorPrivateKey: Uint8Array,
  client: ArohaClient,
  correlationId: string,
  options: ArohaAgentToMcpToolsOptions = {}
): {
  tools: McpToolDefinition[];
  handleToolCall: (toolName: string, args: Record<string, unknown>) => Promise<McpToolCallResult>;
} {
  const verifyResponse = options.verifyResponse ?? options.resolvePublicKey !== undefined;
  if (verifyResponse && !options.resolvePublicKey) {
    throw new Error("arohaAgentToMcpTools: verifyResponse needs resolvePublicKey to resolve the agent's signing key");
  }
  // One replay window per tool set, for the life of the returned handler.
  const responseNonces = new NonceRegistry();

  const tools: McpToolDefinition[] = agent.manifest.capabilities.map((cap) =>
    capabilityToMcpTool(cap, agent.manifest.did)
  );

  const handleToolCall = async (
    toolName: string,
    args: Record<string, unknown>
  ): Promise<McpToolCallResult> => {
    const cap = agent.manifest.capabilities.find(
      (c) => mcpToolName(c.id) === toolName
    );
    if (!cap) {
      return { content: [{ type: "text", text: `Unknown tool: ${toolName}` }], isError: true };
    }

    try {
      const body: ArohaRequestBody = { capability: cap.id, params: args };
      const mandate = typeof options.mandateToken === "function"
        ? await options.mandateToken(toolName, args)
        : options.mandateToken;
      if (mandate !== undefined) body.credentialToken = mandate;
      const envelope = await buildEnvelope(
        "ArohaRequest",
        orchestratorDID,
        agent.manifest.did,
        body,
        correlationId,
        orchestratorPrivateKey
      );

      const response = await client.send(agent.endpoint, envelope);
      if (!response) {
        return { content: [{ type: "text", text: "Agent returned no response (async)" }] };
      }

      if (verifyResponse) {
        const problem = await checkResponseEnvelope(
          response, agent.manifest.did, orchestratorDID, correlationId, options.resolvePublicKey!, responseNonces
        );
        if (problem) {
          return { content: [{ type: "text", text: `Response rejected: ${problem}` }], isError: true };
        }
      }

      if (response.type === "ArohaError") {
        const err = response.body as { message: string };
        return { content: [{ type: "text", text: err.message }], isError: true };
      }

      const result = (response.body as { result: unknown }).result;
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      return { content: [{ type: "text", text: String(err) }], isError: true };
    }
  };

  return { tools, handleToolCall };
}

// ─── MCP → Aroha ───────────────────────────────────────────────────────────────

/**
 * Convert MCP tool definitions into a Aroha capability manifest fragment.
 * Use this to register an MCP server as a Aroha agent.
 */
export function mcpToolsToArohaCapabilities(
  tools: McpToolDefinition[]
): CapabilityDefinition[] {
  return tools.map((tool) => ({
    id: arohaCapabilityId(tool.name),
    version: "1.0.0",
    description: tool.description,
    inputSchema: tool.inputSchema as Record<string, unknown>,
    outputSchema: { type: "object", properties: { result: { type: "object" } } },
    async: false,
    maxResponseMs: 30_000,
    requiredTrustLevel: 1,
    pricing: { model: "free" },
    sagaRole: "none",
  }));
}

// ─── wrapMcp() — one-line adoption path ───────────────────────────────────────

export interface WrapMcpOptions {
  /** Display name for this agent (used to derive the DID and registry entry). */
  name: string;
  /**
   * The actual MCP tool implementations, keyed by tool name (McpToolDefinition.name,
   * not the derived Aroha capability id). Every tool passed to wrapMcp() must have
   * a matching entry here — a tool with no handler is a config error, not something
   * to silently no-op on, so start() throws immediately if any are missing rather
   * than waiting to discover it on the first real request.
   */
  handlers: Record<string, (args: Record<string, unknown>) => Promise<McpToolCallResult>>;
  /**
   * Resolves a caller DID to its Ed25519 public key — required to verify
   * that an incoming request was actually signed by the DID it claims to be
   * from. Use registryPublicKeyResolver() for the common case (resolve
   * against the Aroha registry); supply your own for a private deployment
   * or a test double.
   *
   * There is deliberately no default here: a silent fallback that accepted
   * unverifiable senders is exactly the gap this option closes.
   */
  resolvePublicKey: PublicKeyResolver;
  /**
   * When true, every request must carry a spending mandate (in
   * body.credentialToken) whose chain verifies back to a TRUSTED root
   * (see expectedRoot / trustedRoots / requirePersonRoot) and whose leaf
   * grants the calling agent's DID. Requests with no mandate, an expired,
   * revoked or untrusted one, or one granted to a different DID are rejected
   * with 403 before any tool runs. Default: false (no mandate required) —
   * but forced on by `governed`, and required for any priced tool unless
   * `allowUnchargedPricing` is set.
   *
   * start() REFUSES to run with requireMandate unless a root policy is set:
   * a kelSource (person roots), expectedRoot, or trustedRoots. Without one,
   * "chain verified" only means "someone signed the first link" — any agent
   * can mint itself a root intent mandate and pay with it.
   */
  requireMandate?: boolean;
  /** The chain's root grantor must be exactly this DID. */
  expectedRoot?: string;
  /** The chain's root grantor must be one of these DIDs. */
  trustedRoots?: string[];
  /**
   * Require the root to be a PERSON (`did:aroha:E…` of kind "person" whose
   * KEL verifies and is unrevoked). Needs kelSource. Default: true when a
   * kelSource is configured, false otherwise.
   */
  requirePersonRoot?: boolean;
  /** Key Event Log source for rotatable E-DIDs in the chain (e.g. httpKelSource(registryUrl)). */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. */
  kelStore?: KelStore;
  /**
   * Revocation hook consulted for every link (e.g. httpRevocationCheck(registryUrl)).
   * Strongly recommended for any priced tool.
   */
  isRevoked?: MandateRevocationCheck;
  /**
   * Where priced calls are charged against the payment mandate's cumulative
   * limit. Default: a per-process InMemoryRedemptionStore (logged) — use
   * httpRedemptionStore / D1RedemptionStore when more than one process (or
   * payee) can be paid with the same mandate.
   */
  redemption?: RedemptionStore;
  /**
   * Governed mode: every protective mandate check on, and start() refuses to
   * run unless each one can actually be enforced. Under governed:
   *   - requireMandate is forced on (passing requireMandate: false throws);
   *   - the chain is verified with governedVerification() from
   *     @aroha-sdk/credentials — person root, KEL, revocation, pinned root;
   *   - start() refuses without isRevoked, a kelSource, a root pin
   *     (expectedRoot or a non-empty trustedRoots) and a DURABLE `redemption`
   *     store. An InMemoryRedemptionStore is refused: its totals vanish on
   *     restart and are invisible to other processes, so the same payment
   *     mandate could be spent again.
   * Default false (existing behaviour).
   */
  governed?: boolean;
  /**
   * Allow tools with a price > 0 while requireMandate is false. start()
   * otherwise refuses: without a mandate gate a priced tool advertises a
   * price that is never charged, which callers and registries would read as
   * "this call costs money and is paid for". Set it only when payment is
   * collected some other way (and say so in the tool description).
   */
  allowUnchargedPricing?: boolean;
  /** Port to listen on. Default: 3001. */
  port?: number;
  /**
   * Interface to bind. Default "127.0.0.1" (it bound every interface).
   * Pass "0.0.0.0" to accept connections from other machines.
   */
  host?: string;
  /** Request-body cap in bytes; larger requests get 413. Default 1 MiB. */
  maxBodyBytes?: number;
  /**
   * Price per call in USD for every tool. Default: 0 (free). A price above
   * zero needs requireMandate (start() refuses otherwise, unless
   * allowUnchargedPricing is set).
   */
  price?: number;
  /**
   * Per-tool price in USD, keyed by MCP tool name or Aroha capability id.
   * Overrides `price` for that tool. A priced call (with requireMandate)
   * needs a PAYMENT-tier mandate and is redeemed against it before the tool
   * runs; a call that would exceed the mandate's cumulative limit is refused.
   */
  capabilityPrices?: Record<string, number>;
  /** Envelope lifetime cap in ms, forwarded to validateEnvelope (default 5 min). */
  maxTtlMs?: number;
  /** Max future skew of envelope `created`, forwarded to validateEnvelope. */
  maxFutureSkewMs?: number;
  /** Clock tolerance for envelope expiry, forwarded to validateEnvelope. */
  clockToleranceMs?: number;
  /**
   * Also serve the tools as an MCP server on the wire: Streamable HTTP (MCP
   * 2026-07-28, stateless fallback for 2025-era clients) at `path` (default
   * "/mcp") on the same port. Calls pass the same mandate gate as the
   * envelope endpoint; the mandate travels in `_meta["aroha/mandate"]` with a
   * holder proof (see presentMandate()). Without requireMandate the MCP
   * endpoint has no caller authentication, so start() refuses it on a
   * non-loopback host unless `allowUnauthenticated` is set.
   */
  mcp?: {
    path?: string;
    /** Serve MCP without a mandate gate on a non-loopback host. Put your own authentication in front. */
    allowUnauthenticated?: boolean;
    /** Extra Host header names accepted (DNS-rebinding protection); loopback names are always accepted. */
    allowedHosts?: string[];
  };
  /** Override the auto-generated DID. Format: did:aroha:<name> */
  did?: string;
  /** Override the auto-generated Ed25519 private key (32-byte raw seed). */
  privateKey?: Uint8Array;
}

/**
 * A PublicKeyResolver backed by the Aroha registry — resolves a DID to its
 * registered Ed25519 public key over HTTP. Suitable as wrapMcp()'s
 * resolvePublicKey for agents whose expected callers are registered there.
 */
export function registryPublicKeyResolver(baseUrl?: string): PublicKeyResolver {
  // apiKey is required by ArohaHttpRegistryOptions' type, but DID resolution
  // is a public read — the registry's GET /v1/agents/:id accepts anonymous
  // callers (falls back to public-only visibility on a missing/invalid key
  // rather than rejecting), so an empty key here is correct, not a workaround.
  const registry = new ArohaHttpRegistry({ ...(baseUrl ? { baseUrl } : {}), apiKey: "" });
  return async (senderDID: string): Promise<Uint8Array | null> => {
    const record = await registry.resolveByDID(senderDID);
    if (!record || !record.active) return null;
    try {
      return new Uint8Array(Buffer.from(record.publicKeyB64, "base64url"));
    } catch {
      return null;
    }
  };
}

export interface WrappedMcpAgent {
  /** The DID assigned to this agent. */
  did: string;
  /** The port this agent is listening on. */
  port: number;
  /** Endpoint URL (http://localhost:<port>). */
  endpoint: string;
  /** The Aroha capability definitions derived from the MCP tools. */
  capabilities: CapabilityDefinition[];
  /**
   * Start accepting Aroha requests. Returns a stop() function.
   * Under the hood this runs a minimal HTTP server that validates
   * Ed25519-signed ArohaRequest envelopes and routes them to the
   * matching MCP tool handler.
   */
  start(): Promise<{ stop(): void }>;
}

/**
 * Wrap an array of MCP tool definitions as an Aroha provider agent.
 *
 * This is the adoption path for existing MCP server authors — supply your
 * tool definitions AND their real implementations:
 *
 * ```typescript
 * import { wrapMcp } from "@aroha-sdk/mcp-bridge";
 *
 * const agent = await wrapMcp(myMcpServer.listTools(), {
 *   name: "my-tools",
 *   resolvePublicKey: registryPublicKeyResolver(), // verifies who's actually calling
 *   handlers: {
 *     // one entry per tool name returned by listTools(), each returning the
 *     // tool's real result — not a placeholder.
 *     search: async (args) => ({ content: [{ type: "text", text: await mySearch(args) }] }),
 *   },
 * });
 * await agent.start(); // throws if any tool in the list has no handler entry
 * console.log(`Agent running at ${agent.endpoint} as ${agent.did}`);
 * ```
 *
 * The agent:
 * - Auto-generates an Ed25519 keypair and did:aroha: DID on first run
 * - Verifies each request's signature, expiry, and nonce (replay) before
 *   anything else runs — via the same validateEnvelope() every other Aroha
 *   transport in this codebase uses, not a bespoke check
 * - Optionally requires a valid spending mandate (opts.requireMandate) before
 *   a tool runs, verified against the mandate's actual signature — not just
 *   checked for presence
 * - Routes each incoming ArohaRequest to the matching handler and returns its result
 * - Returns signed ArohaResponse envelopes
 * - Serves its DID Document at /.well-known/aroha-agent.json
 */
export async function wrapMcp(
  tools: McpToolDefinition[] | (() => Promise<McpToolDefinition[]>),
  opts: WrapMcpOptions
): Promise<WrappedMcpAgent> {
  const resolvedTools = typeof tools === "function" ? await tools() : tools;
  const port = opts.port ?? 3001;

  // Auto-generate identity if not provided
  const safeName = opts.name.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const did = opts.did ?? `did:aroha:${safeName}`;

  // Must be a raw 32-byte seed — what @noble/ed25519's signAsync (used by
  // buildEnvelope/signMessage) actually consumes. node:crypto's
  // generateKeyPairSync("ed25519") + a PKCS8 DER export was used here
  // previously; PKCS8 wraps the seed in an ASN.1 prefix, so every signed
  // reply — success or error — threw "Uint8Array expected" the moment a real
  // request reached it, for any agent that didn't supply its own privateKey.
  const privateKey: Uint8Array = opts.privateKey ?? ed.utils.randomPrivateKey();

  // Price per tool: capabilityPrices (by tool name or capability id) over price.
  const priceOf = (tool: McpToolDefinition): number => {
    const p = opts.capabilityPrices?.[tool.name] ?? opts.capabilityPrices?.[arohaCapabilityId(tool.name)] ?? opts.price ?? 0;
    if (typeof p !== "number" || !Number.isFinite(p) || p < 0) {
      throw new Error(`wrapMcp: price for tool "${tool.name}" must be a finite, non-negative number`);
    }
    return p;
  };

  // Build capability definitions from MCP tool list
  const capabilities = mcpToolsToArohaCapabilities(resolvedTools).map((cap, i) => {
    const p = priceOf(resolvedTools[i]);
    return {
      ...cap,
      pricing: p > 0
        ? { model: "per-call" as const, priceUsd: p }
        : { model: "free" as const },
    };
  }) as CapabilityDefinition[];

  // Build a tool lookup map for routing
  const toolMap = new Map(resolvedTools.map((t) => [arohaCapabilityId(t.name), t]));

  const endpoint = `http://localhost:${port}`;

  return {
    did,
    port,
    endpoint,
    capabilities,
    async start() {
      // Fail at startup, not on the first request that happens to hit a gap.
      const missing = resolvedTools.map((t) => t.name).filter((name) => !opts.handlers[name]);
      if (missing.length > 0) {
        throw new Error(
          `wrapMcp: no handler provided for tool(s): ${missing.join(", ")}. ` +
          `Every tool passed to wrapMcp() needs a matching entry in opts.handlers.`
        );
      }

      // Money-gate policy, checked at startup for the same reason as handlers.
      const governed = opts.governed === true;
      if (governed && opts.requireMandate === false) {
        throw new Error("wrapMcp: governed mode requires a mandate on every call; remove requireMandate: false");
      }
      if (governed && opts.requirePersonRoot === false) {
        throw new Error("wrapMcp: governed mode requires person roots; remove requirePersonRoot: false");
      }
      const requireMandate = governed || opts.requireMandate === true;
      const requirePersonRoot = governed || (opts.requirePersonRoot ?? opts.kelSource !== undefined);
      if (requirePersonRoot && !opts.kelSource) {
        throw new Error("wrapMcp: requirePersonRoot needs a kelSource to verify the root person's Key Event Log");
      }
      if (requireMandate && !requirePersonRoot && !opts.expectedRoot && !(opts.trustedRoots?.length)) {
        throw new Error(
          "wrapMcp: requireMandate is set but no root policy is configured. Set expectedRoot, trustedRoots, " +
          "or a kelSource (person roots). Without one, any agent can sign itself a root mandate and it would be accepted."
        );
      }
      const anyPriced = resolvedTools.some((t) => priceOf(t) > 0);
      // A price with no mandate gate is never charged: refuse to advertise
      // one unless the operator says payment is handled elsewhere.
      if (anyPriced && !requireMandate && opts.allowUnchargedPricing !== true) {
        const priced = resolvedTools.filter((t) => priceOf(t) > 0).map((t) => t.name);
        throw new Error(
          `wrapMcp: tool(s) ${priced.join(", ")} have a price but requireMandate is off, so the price would be ` +
          "advertised and never charged. Set requireMandate: true (with a root policy and a redemption store), " +
          "or allowUnchargedPricing: true if payment is collected some other way."
        );
      }

      let profile: GovernedVerificationOptions | undefined;
      if (governed) {
        try {
          profile = governedVerification({
            kelSource: opts.kelSource!,
            kelStore: opts.kelStore,
            isRevoked: opts.isRevoked!,
            expectedRoot: opts.expectedRoot,
            trustedRoots: opts.trustedRoots,
          });
        } catch (err) {
          throw new Error(`wrapMcp: governed mode: ${(err as Error).message}`);
        }
        if (!opts.redemption) {
          throw new Error(
            "wrapMcp: governed mode requires a durable `redemption` store (httpRedemptionStore / D1RedemptionStore)"
          );
        }
        if (opts.redemption instanceof InMemoryRedemptionStore) {
          throw new Error(
            "wrapMcp: governed mode refuses an InMemoryRedemptionStore — its totals are per process and lost on " +
            "restart, so a mandate could be spent again. Use httpRedemptionStore or D1RedemptionStore."
          );
        }
      }

      let redemption = opts.redemption;
      if (requireMandate && anyPriced && !redemption) {
        redemption = new InMemoryRedemptionStore();
        console.warn(
          "[aroha-mcp-bridge] priced tools with no `redemption` store: using a per-process InMemoryRedemptionStore. " +
          "A mandate can be spent again in another process — pass httpRedemptionStore/D1RedemptionStore in production."
        );
      }
      const gate: MandateGate = {
        resolvePublicKey: opts.resolvePublicKey,
        expectedRoot: opts.expectedRoot,
        trustedRoots: opts.trustedRoots,
        requirePersonRoot,
        kelSource: opts.kelSource,
        kelStore: opts.kelStore,
        isRevoked: opts.isRevoked,
        profile,
      };

      const { createServer } = await import("node:http");

      // Optional MCP-on-the-wire endpoint.
      const mcpPath = opts.mcp ? ((opts.mcp.path ?? "/mcp").replace(/\/+$/, "") || "/mcp") : undefined;
      const bindHost = opts.host ?? "127.0.0.1";
      const loopback = ["127.0.0.1", "::1", "localhost"].includes(bindHost);
      if (opts.mcp && !requireMandate && !loopback && opts.mcp.allowUnauthenticated !== true) {
        throw new Error(
          "wrapMcp: the MCP endpoint has no caller authentication without requireMandate; refusing to serve it on " +
          `${bindHost}. Set requireMandate, bind to loopback, or set mcp.allowUnauthenticated with your own gate in front.`
        );
      }
      let mcpFetch: ((request: Request) => Promise<Response>) | undefined;
      let closeMcp: (() => Promise<void>) | undefined;
      if (opts.mcp) {
        const sdk = await import("@modelcontextprotocol/server");
        const presentationNonces = new PresentationNonces();
        const runTool = async (tool: McpToolDefinition, args: Record<string, unknown>, meta: Record<string, unknown> | undefined): Promise<McpToolCallResult> => {
          const fail = (text: string): McpToolCallResult => ({ content: [{ type: "text", text }], isError: true });
          if (requireMandate) {
            const pres = await verifyPresentation(meta?.[MANDATE_META_KEY], {
              audience: did, tool: tool.name, args, resolvePublicKey: opts.resolvePublicKey, nonces: presentationNonces,
            });
            if (!pres.ok) return fail(pres.reason);
            const mandateCheck = await checkMandate(
              { capability: arohaCapabilityId(tool.name), params: args, credentialToken: pres.token } as ArohaRequestBody,
              pres.holder,
              gate
            );
            if (!mandateCheck.ok) return fail(mandateCheck.reason);
            const price = priceOf(tool);
            if (price > 0) {
              const charge = await chargeMandate(mandateCheck.mandate, mandateCheck.token, price, did, redemption!);
              if (!charge.ok) return fail(charge.reason);
            }
          }
          try {
            return await opts.handlers[tool.name](args);
          } catch (err) {
            return fail(`Tool "${tool.name}" failed: ${(err as Error).message}`);
          }
        };
        const handler = sdk.createMcpHandler(() => {
          const server = new sdk.McpServer(
            { name: safeName, version: "1.0.0" },
            { capabilities: { tools: {} }, cacheHints: { "tools/list": { ttlMs: 60_000, cacheScope: "public" } } },
          );
          for (const tool of resolvedTools) {
            server.registerTool(tool.name, {
              description: tool.description,
              inputSchema: sdk.fromJsonSchema<Record<string, unknown>>(tool.inputSchema as never),
              _meta: { "aroha/agentDid": did, ...(priceOf(tool) > 0 ? { "aroha/priceUsd": priceOf(tool) } : {}) },
            }, async (args, ctx) => runTool(tool, args, ctx.mcpReq._meta as Record<string, unknown> | undefined));
          }
          return server;
        }, { maxRequestBodySize: opts.maxBodyBytes ?? 1_048_576 });
        const allowedHosts = ["localhost", "127.0.0.1", "[::1]", ...(opts.mcp.allowedHosts ?? [])];
        mcpFetch = async (request) =>
          sdk.hostHeaderValidationResponse(request, allowedHosts)
            ?? sdk.originValidationResponse(request, ["localhost", "127.0.0.1", "[::1]"])
            ?? handler.fetch(request);
        closeMcp = () => handler.close();
      }

      // One nonce registry per running server instance — replay detection
      // needs to persist across requests for the life of the process, the
      // same lifetime ArohaServer gives it.
      const nonceRegistry = new NonceRegistry();

      // Built with core's buildDIDDocument so the verificationMethod (and the
      // authentication/assertionMethod/keyAgreement refs) are in exactly the
      // form extractPublicKey reads. Without it no resolver could get the key
      // the bridge signs its replies with (`${did}#key-1`).
      const coreDoc = buildDIDDocument(
        did.replace(/^did:aroha:/, ""), await ed.getPublicKeyAsync(privateKey), endpoint, new Date().toISOString()
      );
      // buildDIDDocument always mints did:aroha:<id>; re-point its key refs at
      // `did` in case an override uses another method.
      const rebase = (ref: string) => (ref.startsWith(`${coreDoc.id}#`) ? did + ref.slice(coreDoc.id.length) : ref);
      const didDocument = {
        ...coreDoc,
        id: did,
        verificationMethod: coreDoc.verificationMethod.map((vm) => ({ ...vm, id: rebase(vm.id), controller: did })),
        authentication: coreDoc.authentication.map(rebase),
        assertionMethod: coreDoc.assertionMethod.map(rebase),
        keyAgreement: coreDoc.keyAgreement.map(rebase),
        // The original ArohaAgent entry stays; core's ArohaEndpoint entry is
        // what extractEndpoint looks for. Its id gets its own fragment because
        // `${did}#aroha` is already taken and service ids must be unique.
        service: [
          { id: `${did}#aroha`, type: "ArohaAgent", serviceEndpoint: endpoint },
          ...coreDoc.service.map((s) => ({ ...s, id: `${did}#aroha-endpoint` })),
        ],
      };

      const server = createServer(async (req, res) => {
        res.setHeader("Content-Type", "application/json");

        if (req.method === "GET" && req.url === "/.well-known/aroha-agent.json") {
          res.writeHead(200);
          res.end(JSON.stringify({ did, capabilities, endpoint, ...didDocument }));
          return;
        }

        if (req.method === "POST" && req.url === "/aroha/v1") {
          // Capped read BEFORE any verification: an unauthenticated client
          // must not be able to make the bridge buffer an unbounded body.
          let body: string;
          try {
            body = await readBody(req, opts.maxBodyBytes ?? 1_048_576);
          } catch (err) {
            const tooLarge = (err as { code?: string }).code === "PAYLOAD_TOO_LARGE";
            res.writeHead(tooLarge ? 413 : 400);
            res.end(JSON.stringify({ error: tooLarge ? "Request body too large" : "Could not read request body" }));
            return;
          }

          let envelope: ArohaEnvelope;
          try { envelope = JSON.parse(body); }
          catch { res.writeHead(400); res.end(JSON.stringify({ error: "Invalid JSON" })); return; }

          if (envelope.type !== "ArohaRequest") {
            res.writeHead(400);
            res.end(JSON.stringify({ error: `Unexpected message type: ${envelope.type}` }));
            return;
          }

          // Who is this really from? Resolve BEFORE trusting anything else in
          // the envelope — an unresolvable sender is rejected the same as an
          // invalid signature, not treated as a different, softer case.
          // Pass the proof's verificationMethod so a multi-key DID resolves
          // the key that actually signed, not whichever key comes first.
          const senderPubKey = await opts.resolvePublicKey(envelope.from, envelope.proof?.verificationMethod);
          if (!senderPubKey) {
            res.writeHead(401);
            res.end(JSON.stringify({ error: `Cannot resolve public key for sender: ${envelope.from}` }));
            return;
          }

          // Signature, expiry, and nonce-replay — the checks every other
          // Aroha transport in this codebase runs via ArohaServer. wrapMcp()
          // used to run none of them; any well-formed JSON claiming to be an
          // ArohaRequest was executed as-is.
          const validation = await validateEnvelope(envelope, senderPubKey, did, nonceRegistry, {
            ...(opts.maxTtlMs !== undefined ? { maxTtlMs: opts.maxTtlMs } : {}),
            ...(opts.maxFutureSkewMs !== undefined ? { maxFutureSkewMs: opts.maxFutureSkewMs } : {}),
            ...(opts.clockToleranceMs !== undefined ? { clockToleranceMs: opts.clockToleranceMs } : {}),
          });
          if (!validation.valid) {
            res.writeHead(401);
            res.end(JSON.stringify({ error: validation.reason }));
            return;
          }

          const reqBody = envelope.body as ArohaRequestBody;

          // Tool first: the price — and so what the mandate must cover — is per tool.
          const tool = toolMap.get(reqBody.capability);

          if (!tool) {
            res.writeHead(404);
            res.end(JSON.stringify({ error: `Unknown capability: ${reqBody.capability}` }));
            return;
          }

          if (requireMandate) {
            const mandateCheck = await checkMandate(reqBody, envelope.from, gate);
            if (!mandateCheck.ok) {
              res.writeHead(403);
              res.end(JSON.stringify({ error: mandateCheck.reason }));
              return;
            }
            // Charge BEFORE running the tool: a priced call is only executed
            // once its cost has been atomically taken from the mandate's
            // cumulative limit. (A tool that then fails is not refunded —
            // compensation is the caller's saga, not the bridge's.)
            const price = priceOf(tool);
            if (price > 0) {
              const charge = await chargeMandate(mandateCheck.mandate, mandateCheck.token, price, did, redemption!);
              if (!charge.ok) {
                res.writeHead(402);
                res.end(JSON.stringify({ error: charge.reason }));
                return;
              }
            }
          }

          try {
            const params = reqBody.params as Record<string, unknown>;
            // start() already verified every tool has a handler, so this lookup
            // cannot miss — but guard anyway rather than trust that invariant
            // silently across a future refactor.
            const handler = opts.handlers[tool.name];
            if (!handler) {
              throw new Error(`No handler registered for tool "${tool.name}"`);
            }

            const toolResult = await handler(params);

            if (toolResult.isError) {
              // Mirror arohaAgentToMcpTools' symmetric handling: an MCP-side tool
              // error becomes an ArohaError, not a 200 with an error buried in it.
              const errEnv = await buildEnvelope(
                "ArohaError",
                did,
                envelope.from,
                {
                  code: "AROHA_INTERNAL_ERROR" as never,
                  message: toolResult.content.map((c) => c.text).join("\n") || `Tool "${tool.name}" reported an error`,
                  retryable: true,
                },
                envelope.correlationId,
                privateKey
              );
              res.writeHead(502);
              res.end(JSON.stringify(errEnv));
              return;
            }

            const reply = await buildEnvelope(
              "ArohaResponse",
              did,
              envelope.from,
              { capability: reqBody.capability, result: toolResult },
              envelope.correlationId,
              privateKey
            );
            res.writeHead(200);
            res.end(JSON.stringify(reply));
          } catch (err) {
            const errEnv = await buildEnvelope(
              "ArohaError",
              did,
              envelope.from,
              { code: "AROHA_INTERNAL_ERROR" as never, message: String(err), retryable: true },
              envelope.correlationId,
              privateKey
            );
            res.writeHead(500);
            res.end(JSON.stringify(errEnv));
          }
          return;
        }

        if (mcpFetch && mcpPath && (req.url ?? "").split("?")[0].replace(/\/+$/, "") === mcpPath) {
          await serveWeb(req, res, mcpFetch, opts.maxBodyBytes ?? 1_048_576);
          return;
        }

        res.writeHead(404);
        res.end(JSON.stringify({ error: "Not found" }));
      });

      await new Promise<void>((resolve) => server.listen(port, bindHost, resolve));
      console.log(`[aroha-mcp-bridge] ${did} listening on ${endpoint}`);
      console.log(`[aroha-mcp-bridge] ${capabilities.length} capabilities: ${capabilities.map((c) => c.id).join(", ")}`);
      if (mcpPath) console.log(`[aroha-mcp-bridge] MCP endpoint ${endpoint}${mcpPath}`);

      return { stop: () => { void closeMcp?.(); server.close(); server.closeAllConnections?.(); } };
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Serve one node request through a web-standard fetch handler (capped body). */
async function serveWeb(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  fetchHandler: (request: Request) => Promise<Response>,
  maxBodyBytes: number
): Promise<void> {
  let body: string | undefined;
  if (req.method === "POST") {
    try {
      body = await readBody(req, maxBodyBytes);
    } catch (err) {
      const tooLarge = (err as { code?: string }).code === "PAYLOAD_TOO_LARGE";
      res.writeHead(tooLarge ? 413 : 400);
      res.end(JSON.stringify({ error: tooLarge ? "Request body too large" : "Could not read request body" }));
      return;
    }
  }
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) for (const item of v) headers.append(k, item);
    else headers.set(k, v);
  }
  const response = await fetchHandler(new Request(new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`), {
    method: req.method,
    headers,
    ...(body !== undefined ? { body } : {}),
  }));
  const out: Record<string, string> = {};
  response.headers.forEach((value, key) => { out[key] = value; });
  res.writeHead(response.status, out);
  if (!response.body) { res.end(); return; }
  const { Readable } = await import("node:stream");
  Readable.fromWeb(response.body as never).pipe(res);
}

/**
 * Verify a provider's response envelope: from the agent we called, signed by
 * that agent's key, addressed to us, unexpired, not a replay, and about the
 * request we sent (correlationId). Returns null when it verifies, otherwise
 * the reason.
 */
async function checkResponseEnvelope(
  response: ArohaEnvelope,
  agentDID: string,
  orchestratorDID: string,
  correlationId: string,
  resolvePublicKey: PublicKeyResolver,
  nonces: NonceRegistry
): Promise<string | null> {
  if (response.from !== agentDID) return `response is from ${String(response.from)}, not ${agentDID}`;
  if (response.correlationId !== correlationId) return "response correlationId does not match the request";
  let key: Uint8Array | null;
  try {
    key = await resolvePublicKey(agentDID, response.proof?.verificationMethod);
  } catch {
    key = null;
  }
  if (!key) return `cannot resolve the public key for ${agentDID}`;
  const v = await validateEnvelope(response, key, orchestratorDID, nonces);
  return v.valid ? null : (v.reason ?? "invalid response signature");
}

interface MandateGate {
  resolvePublicKey: PublicKeyResolver;
  expectedRoot?: string;
  trustedRoots?: string[];
  requirePersonRoot: boolean;
  kelSource?: KelSource;
  kelStore?: KelStore;
  isRevoked?: MandateRevocationCheck;
  /** Set in governed mode: the governedVerification() options every chain is verified with. */
  profile?: GovernedVerificationOptions;
}

/**
 * Verify that the request carries a spending mandate whose chain verifies
 * back to a TRUSTED root and whose leaf grants `callerDID`.
 *
 * WHY verifyMandateChain and a root policy: this used to call verifyMandate
 * against the leaf grantor's key and accept anything with chainVerified —
 * which is true for a ROOT the caller signed itself. Any agent could mint an
 * intent mandate naming itself as grantee and "pay" with it. A chain proves
 * provenance only relative to a root you trust, so the gate now requires one
 * (expectedRoot / trustedRoots / a person root via kelSource) and refuses to
 * start without it (see wrapMcp start()).
 *
 * Keys: z-DIDs from the DID itself, E-DIDs from their verified KEL (when
 * kelSource is set — never from the registry resolver), anything else via
 * resolvePublicKey.
 */
async function checkMandate(
  reqBody: ArohaRequestBody,
  callerDID: string,
  gate: MandateGate
): Promise<{ ok: true; mandate: ArohaSpendingMandateBody; token: string } | { ok: false; reason: string }> {
  const token = (reqBody as { credentialToken?: string }).credentialToken;
  if (typeof token !== "string" || token.length === 0) {
    return { ok: false, reason: "No spending mandate provided (credentialToken missing)" };
  }

  const resolveKey = createMandateKeyResolver({
    kelSource: gate.kelSource,
    kelStore: gate.kelStore,
    fallback: (d) => gate.resolvePublicKey(d),
  });
  const result = await verifyMandateChain(token, resolveKey, gate.profile
    ? { ...gate.profile, expectedGrantee: callerDID }
    : {
        expectedGrantee: callerDID,
        expectedRoot: gate.expectedRoot,
        requirePersonRoot: gate.requirePersonRoot,
        kelSource: gate.kelSource,
        kelStore: gate.kelStore,
        isRevoked: gate.isRevoked,
      });
  if (!result.valid || !result.mandate) {
    return { ok: false, reason: result.reason ?? "Mandate verification failed" };
  }
  if (gate.trustedRoots?.length && !gate.trustedRoots.includes(result.rootGrantor ?? "")) {
    return { ok: false, reason: `Mandate root ${String(result.rootGrantor)} is not a trusted root` };
  }
  return { ok: true, mandate: result.mandate, token };
}

/** Redeem `priceUsd` against the verified payment mandate; the bridge's DID is the merchant. */
async function chargeMandate(
  mandate: ArohaSpendingMandateBody,
  token: string,
  priceUsd: number,
  merchantDID: string,
  store: RedemptionStore
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (mandate.mandateTier !== "payment") {
    return { ok: false, reason: `This tool costs $${priceUsd} per call and needs a payment mandate (got ${mandate.mandateTier})` };
  }
  try {
    await redeemPaymentMandate(store, mandate, priceUsd, merchantDID, { token });
    return { ok: true };
  } catch (err) {
    if (err instanceof SpendingConstraintViolation) return { ok: false, reason: err.message };
    // Store unreachable / unknown outcome: do not run the tool.
    return { ok: false, reason: `Could not charge the mandate: ${(err as Error).message}` };
  }
}

function capabilityToMcpTool(
  cap: CapabilityDefinition,
  agentDID: string
): McpToolDefinition {
  return {
    name: mcpToolName(cap.id),
    description: cap.description ?? cap.id,
    inputSchema: {
      type: "object",
      properties: (cap.inputSchema as { properties?: Record<string,unknown> })?.properties ?? {},
      required: (cap.inputSchema as { required?: string[] })?.required,
    },
    _aroha: {
      agentDID,
      capabilityId: cap.id,
      sagaRole: cap.sagaRole,
    },
  };
}

/** Convert a Aroha capability ID to a valid MCP tool name (snake_case). */
function mcpToolName(capabilityId: string): string {
  return `aroha_${capabilityId.replace(/-/g, "_")}`;
}

/** Convert an MCP tool name back to a Aroha capability ID. */
function arohaCapabilityId(mcpName: string): string {
  return mcpName.replace(/^aroha_/, "").replace(/_/g, "-");
}
