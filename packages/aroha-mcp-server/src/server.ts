// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The Aroha MCP tool set, built per principal.
 *
 * One `McpServer` is built for each serving unit (one HTTP request, or one
 * stdio connection) by `createArohaMcpServer(runtime, principal)`. The
 * principal decides which signing key every mandate, envelope and receipt is
 * signed with — never a key shared between users.
 *
 * Human approvals use the MCP 2026-07-28 Multi Round-Trip Request pattern: a
 * gated tool answers `input_required` with an embedded form elicitation and an
 * integrity-protected `requestState` that carries the approval id (and the
 * mandate id, when one is in play). The client retries with `inputResponses`;
 * the retry is accepted only when the state verifies (HMAC, unexpired, bound
 * to this principal and method) and names the same tool and the same
 * arguments. Older (2025-era) clients get the same handler through the SDK's
 * elicitation shim.
 *
 * Long-running calls (aroha_call) are returned as MCP Tasks to clients that
 * declare the `io.modelcontextprotocol/tasks` extension — after the approval
 * round trip has resolved, never instead of it (see tasks.ts).
 *
 * A principal signed in through Enterprise-Managed Authorization is keyed by
 * its enterprise identity (IdP issuer, tenant, subject); the mandates it
 * issues report that identity as their root (see enterprise.ts).
 */

import { randomUUID } from "node:crypto";
import {
  McpServer,
  acceptedContent,
  createRequestStateCodec,
  fromJsonSchema,
  inputRequired,
  inputResponse,
  TRACEPARENT_META_KEY,
  type AuthInfo,
  type CallToolResult,
  type InputRequiredResult,
  type RequestStateCodec,
  type ServerContext,
  type ToolAnnotations,
} from "@modelcontextprotocol/server";
import { buildEnvelope, validateEnvelope, NonceRegistry, type ArohaEnvelope } from "@aroha-sdk/core/messages";
import { assertSecureEndpoint } from "@aroha-sdk/core/endpoints";
import { isInceptionDid, kelKeyResolver, resolveKelState, type KelSource } from "@aroha-sdk/core/identity";
import { hashReceiptArgs, signActionReceipt, verifyActionReceipt, receiptMatches, requireApprovalIfTainted, type ArohaActionReceipt } from "@aroha-sdk/core/receipts";
import type { TaskConstraints } from "@aroha-sdk/core";
import {
  issueTaskMandate,
  issueIntentMandate,
  verifyMandateChain,
  verifyTaskMandate,
  decodeMandateToken,
  resolveContentAddressedKey,
  governedVerification,
  httpRevocationCheck,
  revokeMandate,
  type MandateRevocationCheck,
} from "@aroha-sdk/credentials/mandates";
import { httpKelSource } from "@aroha-sdk/registry";
import type { ResolvedConfig } from "./config.js";
import type { McpIdentity } from "./identity.js";
import { LOCAL_PRINCIPAL, principalFromToken, type PrincipalKeyStore } from "./keystore.js";
import { safeFetch, EndpointRefusedError, type HostLookup } from "./safe-fetch.js";
import {
  ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION,
  enterprisePrincipal,
  enterpriseRoot,
  isEnterpriseIdentity,
  type EnterpriseIdentity,
} from "./enterprise.js";
import {
  TASKS_EXTENSION,
  TaskLimitError,
  TaskStore,
  clientDeclaredTasks,
  createTaskResult,
  registerTaskHandlers,
  taskOwner,
} from "./tasks.js";

export const SERVER_NAME = "aroha-hub";
export const SERVER_VERSION = "2.0.0";

/** The key of the approval form inside `inputRequests` / `inputResponses`. */
export const APPROVAL_INPUT_KEY = "aroha_approval";

/** What travels in `requestState` across an approval round trip. */
export interface ApprovalState {
  v: 1;
  approvalId: string;
  tool: string;
  argsSha256: string;
  mandateId?: string;
}

/** Bounded per-principal receipt memory. */
export class ReceiptStore {
  private readonly byPrincipal = new Map<string, Map<string, unknown>>();
  constructor(private readonly maxPerPrincipal = 500) {}
  put(principal: string, id: string, receipt: unknown): void {
    let m = this.byPrincipal.get(principal);
    if (!m) { m = new Map(); this.byPrincipal.set(principal, m); }
    m.set(id, receipt);
    while (m.size > this.maxPerPrincipal) m.delete(m.keys().next().value as string);
  }
  get(principal: string, id: string): unknown {
    return this.byPrincipal.get(principal)?.get(id);
  }
}

/** Shared, process-wide state the per-request servers draw on. */
export interface ArohaMcpRuntime {
  config: ResolvedConfig;
  keyStore: PrincipalKeyStore;
  receipts: ReceiptStore;
  stateCodec: RequestStateCodec<ApprovalState>;
  responseNonces: NonceRegistry;
  kelSource: KelSource;
  /** Registry revocation hook (signed when registry keys are configured). */
  isRevoked: MandateRevocationCheck;
  /** Registry fetch (operator-configured URL). Agent endpoints go through safeFetch instead. */
  fetch: typeof fetch;
  /** DNS resolver for agent endpoints (tests). */
  lookup?: HostLookup;
  /** MCP Tasks state; absent when tasks are disabled. */
  tasks?: TaskStore;
  /** Local diagnostics (never sent to the MCP caller). */
  log: (line: string) => void;
}

/** What the server knows about the caller beyond its principal. */
export interface PrincipalContext {
  /** The OAuth client the access token was issued to. */
  clientId?: string;
  /** Set when the token was issued from an ID-JAG. */
  enterprise?: EnterpriseIdentity;
}

/**
 * The principal for a request: the enterprise identity of a token issued from
 * an ID-JAG, else `iss|sub` from a verified token, else the single local user
 * on stdio / unauthenticated development mode.
 */
export function principalFromAuthInfo(authInfo: AuthInfo | undefined): string {
  const enterprise = authInfo?.extra?.enterprise;
  if (isEnterpriseIdentity(enterprise)) return enterprisePrincipal(enterprise);
  const sub = authInfo?.extra?.sub;
  if (typeof sub !== "string" || sub.length === 0) return LOCAL_PRINCIPAL;
  const iss = authInfo?.extra?.iss;
  return principalFromToken(typeof iss === "string" ? iss : undefined, sub);
}

/** The caller context for a request (client id and enterprise identity, when known). */
export function principalContextFromAuthInfo(authInfo: AuthInfo | undefined): PrincipalContext {
  const enterprise = authInfo?.extra?.enterprise;
  return {
    ...(authInfo?.clientId ? { clientId: authInfo.clientId } : {}),
    ...(isEnterpriseIdentity(enterprise) ? { enterprise } : {}),
  };
}

export function createRuntime(
  config: ResolvedConfig,
  keyStore: PrincipalKeyStore,
  opts: {
    fetch?: typeof fetch; kelSource?: KelSource; isRevoked?: MandateRevocationCheck; lookup?: HostLookup; log?: (line: string) => void;
    /** Replace the task store (tests: an injected clock). Ignored when tasks are disabled. */
    tasks?: TaskStore;
  } = {},
): ArohaMcpRuntime {
  assertSecureEndpoint(config.registry.url, { allowInsecureHttp: config.registry.allowInsecureHttp, label: "AROHA_REGISTRY_URL" });
  const doFetch = opts.fetch ?? fetch;
  // A per-process random key is safe for a single process: every round of an
  // approval lands on the process that minted it. Multi-instance deployments
  // must configure AROHA_MCP_STATE_KEY.
  const key = config.approvals.stateKey ?? crypto.getRandomValues(new Uint8Array(32));
  const stateCodec = createRequestStateCodec<ApprovalState>({
    key,
    ttlSeconds: config.approvals.stateTtlSeconds,
    bind: (ctx) => `${ctx.mcpReq.method}\0${principalFromAuthInfo(ctx.http?.authInfo)}`,
  });
  const kelSource = opts.kelSource ?? httpKelSource(config.registry.url, { allowInsecureHttp: config.registry.allowInsecureHttp, fetch: doFetch });
  const isRevoked = opts.isRevoked ?? httpRevocationCheck(config.registry.url, {
    allowInsecureHttp: config.registry.allowInsecureHttp,
    fetch: doFetch,
    ...(config.registry.keys ? { registryKeys: config.registry.keys } : {}),
  });
  const log = opts.log ?? ((line: string) => process.stderr.write(`${line}
`));
  const tasks = config.tasks ? (opts.tasks ?? new TaskStore({ ...config.tasks, log })) : undefined;
  return {
    config,
    keyStore,
    receipts: new ReceiptStore(),
    stateCodec,
    responseNonces: new NonceRegistry(),
    kelSource,
    isRevoked,
    fetch: doFetch,
    lookup: opts.lookup,
    tasks,
    log,
  };
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function text(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

function errorResult(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

const READ_ONLY: ToolAnnotations = { readOnlyHint: true, openWorldHint: true };

/** Resolve a DID's key without trusting the registry for self-certifying forms. */
async function resolveAgentKey(rt: ArohaMcpRuntime, did: string, registryRecord?: Record<string, unknown>): Promise<Uint8Array | null> {
  if (isInceptionDid(did)) return kelKeyResolver(rt.kelSource)(did);
  const derived = await resolveContentAddressedKey(did);
  if (derived) return derived;
  const b64 = registryRecord?.publicKeyB64;
  if (typeof b64 !== "string") return null;
  try {
    const key = new Uint8Array(Buffer.from(b64, "base64url"));
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

async function didKeyResolver(rt: ArohaMcpRuntime, did: string): Promise<Uint8Array | null> {
  return resolveAgentKey(rt, did);
}

// ─── server ───────────────────────────────────────────────────────────────────

/** Build the MCP server for one principal. */
export function createArohaMcpServer(rt: ArohaMcpRuntime, principal: string, context: PrincipalContext = {}): McpServer {
  const { config } = rt;
  const extensions: Record<string, Record<string, never>> = {};
  if (rt.tasks) extensions[TASKS_EXTENSION] = {};
  if (config.auth?.enterprise) extensions[ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION] = {};
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    {
      capabilities: { tools: {}, ...(Object.keys(extensions).length > 0 ? { extensions } : {}) },
      instructions:
        "Aroha: discover and call registered agents with signed, person-scoped mandates. " +
        "Mandates, envelopes and receipts are signed with the signed-in user's own key. " +
        "Tools that grant or spend authority ask the user to approve first.",
      // The tool list is identical for every principal.
      cacheHints: {
        "tools/list": { ttlMs: 300_000, cacheScope: "public" },
        "server/discover": { ttlMs: 300_000, cacheScope: "public" },
      },
      requestState: { verify: (state, ctx) => rt.stateCodec.verify(state, ctx) },
    },
  );

  const identity = (): Promise<McpIdentity> => rt.keyStore.get(principal);
  // An enterprise user's mandates name the enterprise subject as their root.
  const rootOf = (grantorDid: string): Record<string, unknown> =>
    context.enterprise ? { grantorRoot: enterpriseRoot(context.enterprise, grantorDid) } : {};
  const owner = taskOwner(principal, context.clientId);
  if (rt.tasks) registerTaskHandlers(server, rt.tasks, owner);

  async function registryGet(path: string): Promise<unknown> {
    const res = await rt.fetch(`${config.registry.url}${path}`, {
      headers: config.registry.apiKey ? { Authorization: `Bearer ${config.registry.apiKey}` } : {},
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`Registry ${path}: HTTP ${res.status}`);
    return res.json();
  }

  /**
   * Run the approval round trip for a gated call. Returns the approval when
   * granted, or the result to hand back (input_required, or a refusal).
   */
  async function approvalGate(
    ctx: ServerContext,
    tool: string,
    args: unknown,
    summary: string,
    mandateId?: string,
  ): Promise<{ approval: { approvalId: string; approvedAt: string } } | { result: CallToolResult | InputRequiredResult }> {
    const argsSha256 = hashReceiptArgs(args);
    const state = ctx.mcpReq.requestState<ApprovalState>();
    const ask = async (approvalId: string): Promise<{ result: InputRequiredResult }> => ({
      result: inputRequired({
        inputRequests: {
          [APPROVAL_INPUT_KEY]: inputRequired.elicit({
            message: `Approve "${tool}"? ${summary}`,
            requestedSchema: {
              type: "object",
              properties: { approve: { type: "boolean", title: "Approve", description: "true to allow this action" } },
              required: ["approve"],
            },
          }),
        },
        requestState: await rt.stateCodec.mint(
          { v: 1, approvalId, tool, argsSha256, ...(mandateId ? { mandateId } : {}) },
          ctx,
        ),
      }),
    });

    if (!state || typeof state !== "object") return ask(randomUUID());
    // The state verified (HMAC, expiry, principal binding) before we got
    // here; it must also describe THIS call, or an approval for one action
    // could be replayed onto another.
    if (state.v !== 1 || state.tool !== tool || state.argsSha256 !== argsSha256 || (state.mandateId ?? undefined) !== (mandateId ?? undefined)) {
      return { result: errorResult("Approval state does not match this call; the approval was not applied.") };
    }
    const view = inputResponse(ctx.mcpReq.inputResponses, APPROVAL_INPUT_KEY);
    if (view.kind === "missing") return ask(state.approvalId);
    const content = acceptedContent<{ approve?: unknown }>(ctx.mcpReq.inputResponses, APPROVAL_INPUT_KEY);
    if (content?.approve !== true) {
      return { result: errorResult(`The user declined "${tool}". Do not retry; ask the user what they want instead.`) };
    }
    return { approval: { approvalId: state.approvalId, approvedAt: new Date().toISOString() } };
  }

  const gated = (tool: string): boolean => config.approvals.tools.has(tool);

  // ── aroha_discover ──────────────────────────────────────────────────────────
  server.registerTool(
    "aroha_discover",
    {
      title: "Discover Aroha agents",
      description:
        "Search the Aroha Hub registry for agents that can perform a capability " +
        "(e.g. 'book-flight', 'check-balance', 'send-email', 'research'). " +
        "Returns agent DIDs, names, capabilities, and reputation scores.",
      inputSchema: fromJsonSchema<{ capability?: string; query?: string }>({
        type: "object",
        properties: {
          capability: { type: "string", description: "Capability ID to search for (e.g. 'book-flight')" },
          query: { type: "string", description: "Free-text search query for agent name or description" },
        },
      }),
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const params = new URLSearchParams();
        if (args.capability) params.set("capabilities", args.capability);
        if (args.query) params.set("q", args.query);
        const qs = params.toString() ? `?${params}` : "";
        const agents = await registryGet(`/v1/agents${qs}`);
        const obj = agents as Record<string, unknown>;
        const list = Array.isArray(agents) ? agents : ((obj.agents ?? obj.data ?? []) as unknown[]);
        if (!list.length) return text("No agents found matching your search. Try a broader capability or query.");
        return text(list.slice(0, 10).map((a) => {
          const agent = a as Record<string, unknown>;
          return {
            did: agent.did ?? agent.didHash,
            name: agent.name ?? agent.manifestName ?? "(unnamed)",
            capabilities: agent.capabilities ?? [],
            reputation: agent.reputationScore ?? "N/A",
            endpoint: agent.endpoint ?? agent.endpointUrl ?? "(unknown)",
          };
        }));
      } catch (err) {
        return errorResult(`Discovery failed: ${String(err)}`);
      }
    },
  );

  // ── aroha_call ──────────────────────────────────────────────────────────────
  interface CallArgs {
    agentDid: string; capability: string; params: Record<string, unknown>;
    spendLimitUsd?: number; purpose?: string; taskDescription?: string; mandateToken?: string;
  }
  server.registerTool(
    "aroha_call",
    {
      title: "Call an Aroha agent",
      description:
        "Call a vendor agent on the Aroha Hub with a signed Aroha envelope from the signed-in user's own DID. " +
        "Attach a mandate (from aroha_issue_task_mandate / aroha_issue_spending_mandate) in mandateToken for a " +
        "conformant agent; without one, spendLimitUsd/purpose travel only as a sandbox hint. The agent's response " +
        "envelope is verified (signer, recipient, expiry, replay, correlation) before its result is returned. " +
        "Returns a receipt id; use aroha_get_receipt for the audit trail. Calls that carry spending authority ask " +
        "the user to approve first. Clients that support MCP Tasks get a task handle after approval and poll for the result.",
      inputSchema: fromJsonSchema<CallArgs>({
        type: "object",
        required: ["agentDid", "capability", "params"],
        properties: {
          agentDid: { type: "string", description: "DID of the vendor agent (from aroha_discover)" },
          capability: { type: "string", description: "Capability to invoke (must be in the agent's capability list)" },
          params: { type: "object", description: "Parameters to pass to the capability" },
          spendLimitUsd: { type: "number", description: "Maximum spend in USD for this call (default: 0 for free calls)" },
          purpose: { type: "string", description: "Human-readable reason for this call (appears in audit trail)" },
          taskDescription: { type: "string", description: "Description of the task being delegated (for non-monetary tasks)" },
          mandateToken: { type: "string", description: "A signed mandate token to present to the agent (body.credentialToken)" },
        },
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async (args, ctx) => {
      const { agentDid, capability, params, spendLimitUsd = 0, purpose, taskDescription, mandateToken } = args;
      let mandateId: string | undefined;
      let mandateGrantor: string | undefined;
      if (mandateToken !== undefined) {
        try {
          const decoded = decodeTaskOrSpendingLeaf(mandateToken);
          mandateId = decoded.mandateId;
          mandateGrantor = decoded.grantor;
        } catch (err) {
          return errorResult(`mandateToken is not a mandate token: ${(err as Error).message}`);
        }
      }

      let approval: { approvalId: string; approvedAt: string } | undefined;
      if (gated("aroha_call") && (spendLimitUsd > 0 || mandateToken !== undefined)) {
        const gate = await approvalGate(
          ctx, "aroha_call", args,
          `Agent ${agentDid}, capability ${capability}${spendLimitUsd > 0 ? `, spend up to $${spendLimitUsd}` : ""}` +
          `${mandateId ? `, under mandate ${mandateId}` : ""}.`,
          mandateId,
        );
        if ("result" in gate) return gate.result;
        approval = gate.approval;
      }

      const traceparent = ctx.mcpReq._meta?.[TRACEPARENT_META_KEY];
      // Everything below runs only once the approval (if any) is granted, and
      // runs the same whether the client waits for it or polls a task.
      const perform = async (signal?: AbortSignal, taskId?: string): Promise<CallToolResult> => {
        try {
          const didHash = agentDid.split(":").pop() ?? agentDid;
          let agentRecord: Record<string, unknown>;
          try {
            agentRecord = (await registryGet(`/v1/agents/${encodeURIComponent(didHash)}`)) as Record<string, unknown>;
          } catch {
            return errorResult(`Agent ${agentDid} not found in the Hub registry. Use aroha_discover to find valid agents.`);
          }
          const endpoint = (agentRecord.endpoint ?? agentRecord.endpointUrl) as string | undefined;
          if (!endpoint) return errorResult(`Agent ${agentDid} has no registered endpoint.`);
          // Registry-supplied: refuse cleartext to a remote host.
          assertSecureEndpoint(endpoint, { allowInsecureHttp: config.registry.allowInsecureHttp, label: "agent endpoint" });

          const me = await identity();
          const correlationId = randomUUID();
          const startedAt = Date.now();
          const body: Record<string, unknown> = { capability, params };
          if (mandateToken !== undefined) {
            body.credentialToken = mandateToken;
          } else {
            // SANDBOX-ONLY hint, not a mandate: a conformant agent ignores it.
            body.mandateIntent = {
              spendLimitUsd,
              purpose: purpose ?? taskDescription ?? `aroha_call via MCP: ${capability}`,
              sandboxOnly: true,
            };
          }
          const envelope = await buildEnvelope("ArohaRequest", me.did, agentDid, body as never, correlationId, me.privateKey);
          // The endpoint is registrant-controlled: vet and pin it (no private
          // targets, no redirects, capped body) before sending anything.
          let response: { status: number; ok: boolean; text: string };
          try {
            response = await safeFetch(endpoint.endsWith("/") ? `${endpoint}aroha/v1` : `${endpoint}/aroha/v1`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                ...(typeof traceparent === "string" ? { traceparent } : {}),
              },
              body: JSON.stringify(envelope),
            }, { allowPrivate: config.allowPrivateEndpoints, lookup: rt.lookup, timeoutMs: 30_000, maxBytes: 1_048_576, signal });
          } catch (err) {
            rt.log(`[aroha-mcp-server] aroha_call to ${agentDid} at ${endpoint} failed: ${(err as Error).message}`);
            return errorResult(err instanceof EndpointRefusedError
              ? `Agent ${agentDid} has an endpoint this server will not call (not a public address).`
              : `Agent ${agentDid} could not be reached.`);
          }
          const durationMs = Date.now() - startedAt;
          let responseBody: Record<string, unknown> | undefined;
          try { responseBody = JSON.parse(response.text) as Record<string, unknown>; } catch { responseBody = undefined; }

          let verification: string | null = null;
          if (response.ok && responseBody === undefined) verification = "the agent's response is not JSON";
          else if (response.ok && config.verifyResponses) {
            verification = await checkResponse(rt, responseBody!, agentDid, me.did, correlationId, agentRecord);
          }
          // Bodies from failed or unverifiable responses stay local: echoing
          // them would turn this server into a reader for whatever the endpoint
          // returns.
          if (!response.ok || verification) {
            rt.log(`[aroha-mcp-server] aroha_call ${correlationId}: HTTP ${response.status}${verification ? `, ${verification}` : ""}; body ${response.text.length} bytes withheld`);
          }

          const actionReceipt = await signActionReceipt({
            agentDid: me.did,
            action: capability,
            argsSha256: hashReceiptArgs(params),
            // The server cannot see the model's context; it cannot vouch that no
            // untrusted content shaped this call, so it says so.
            tainted: true,
            provenance: ["delegated"],
            ...(approval ? { approval: { approverDid: me.did, approvedAt: approval.approvedAt, approvalId: approval.approvalId } } : {}),
            ...(mandateId ? { mandateId } : {}),
            ...(mandateGrantor ? { mandateGrantor } : {}),
            correlationId,
          }, me.privateKey);

          const ok = response.ok && verification === null;
          const receiptId = `rcpt-${correlationId}`;
          rt.receipts.put(principal, receiptId, {
            receiptId,
            mandateId: mandateId ?? null,
            correlationId,
            executedByDid: agentDid,
            issuedByDid: me.did,
            startedAt: new Date(startedAt).toISOString(),
            completedAt: new Date().toISOString(),
            status: ok ? "complete" : "failed",
            httpStatus: response.status,
            responseVerified: config.verifyResponses ? verification === null : "not-checked",
            ...(verification ? { verificationFailure: verification } : {}),
            ...(typeof traceparent === "string" ? { traceparent } : {}),
            ...(taskId ? { taskId } : {}),
            ...(context.enterprise ? { enterpriseRoot: enterpriseRoot(context.enterprise, me.did) } : {}),
            actionReceipt,
            ...(ok ? { agentResponse: responseBody } : {}),
            durationMs,
          });

          if (verification) {
            return errorResult(JSON.stringify({ error: `Response rejected: ${verification}`, receiptId }, null, 2));
          }
          if (!response.ok) {
            return errorResult(JSON.stringify({ error: `Agent returned HTTP ${response.status}`, receiptId }, null, 2));
          }
          const result = (responseBody!.body as Record<string, unknown> | undefined)?.result ?? responseBody;
          return text({ success: true, result, receiptId, correlationId, durationMs, actionReceipt });
        } catch (err) {
          return errorResult(`Call failed: ${String(err)}`);
        }
      };

      if (rt.tasks && clientDeclaredTasks(ctx)) {
        let taskId = "";
        try {
          const task = rt.tasks.create(owner, (signal) => perform(signal, taskId));
          taskId = task.taskId;
          // CreateTaskResult (resultType "task"): the SDK passes it through on tools/call.
          return createTaskResult(task) as unknown as CallToolResult;
        } catch (err) {
          if (err instanceof TaskLimitError) return errorResult(`The call was not started: ${err.message}. Wait for a task to finish, or cancel one, and retry.`);
          throw err;
        }
      }
      return perform();
    },
  );

  // ── aroha_issue_task_mandate ────────────────────────────────────────────────
  interface TaskArgs {
    agentDid: string; allowed: string[]; blocked?: string[]; actionLimits?: Record<string, number>;
    reversibleOnly?: boolean; humanGates?: string[]; maxLlmTokens?: number; maxWebRequests?: number; ttlMinutes?: number;
  }
  server.registerTool(
    "aroha_issue_task_mandate",
    {
      title: "Issue a task mandate",
      description:
        "Issue a task mandate, signed with the signed-in user's own key, authorising a vendor agent to perform " +
        "specific capabilities with explicit resource limits: action counts, compute budgets and reversibility.",
      inputSchema: fromJsonSchema<TaskArgs>({
        type: "object",
        required: ["agentDid", "allowed"],
        properties: {
          agentDid: { type: "string", description: "DID of the agent to authorise" },
          allowed: { type: "array", items: { type: "string" }, description: "Capability IDs the agent may invoke" },
          blocked: { type: "array", items: { type: "string" }, description: "Capability IDs to explicitly deny" },
          actionLimits: { type: "object", description: "Max invocations per capability: { 'send-email': 3 }" },
          reversibleOnly: { type: "boolean", description: "When true, block all irreversible capabilities" },
          humanGates: { type: "array", items: { type: "string" }, description: "Capabilities requiring human approval" },
          maxLlmTokens: { type: "number", description: "Max LLM tokens the agent may consume" },
          maxWebRequests: { type: "number", description: "Max outbound HTTP requests" },
          ttlMinutes: { type: "number", description: "Mandate expiry in minutes (default: 60)" },
        },
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const { agentDid, allowed, blocked, actionLimits, reversibleOnly, humanGates, maxLlmTokens, maxWebRequests, ttlMinutes = 60 } = args;
      if (gated("aroha_issue_task_mandate")) {
        const gate = await approvalGate(ctx, "aroha_issue_task_mandate", args,
          `Grant ${agentDid} the capabilities [${allowed.join(", ")}] for ${ttlMinutes} minutes.`);
        if ("result" in gate) return gate.result;
      }
      const me = await identity();
      const computeLimit: NonNullable<TaskConstraints["computeLimit"]> = {};
      if (maxLlmTokens !== undefined) computeLimit.llmTokens = maxLlmTokens;
      if (maxWebRequests !== undefined) computeLimit.webRequests = maxWebRequests;
      const taskConstraints: TaskConstraints = {
        actionLimits: actionLimits ?? {},
        reversibleOnly: reversibleOnly ?? false,
        humanGates: humanGates ?? [],
        ...(Object.keys(computeLimit).length > 0 ? { computeLimit } : {}),
      };
      const signed = await issueTaskMandate(me.did, agentDid, allowed, taskConstraints, me.privateKey, ttlMinutes * 60_000, {
        blocked: blocked ?? [],
      });
      return text({
        mandateId: signed.mandate.mandateId,
        summary: `Task mandate issued to ${agentDid}`,
        allowed,
        blocked: blocked ?? [],
        constraints: taskConstraints,
        validUntil: signed.mandate.expiresAt,
        mandate: signed.mandate,
        token: signed.token,
        grantorDid: me.did,
        ...rootOf(me.did),
      });
    },
  );

  // ── aroha_issue_spending_mandate ────────────────────────────────────────────
  interface SpendArgs { agentDid: string; capability: string; spendLimitUsd: number; allowedMerchants?: string[]; ttlMinutes?: number }
  server.registerTool(
    "aroha_issue_spending_mandate",
    {
      title: "Issue a spending mandate",
      description:
        "Issue a signed intent-tier spending mandate (Ed25519, the signed-in user's own DID) authorising a vendor " +
        "agent to spend up to a specified amount. The agent attenuates it to cart/payment tiers; it can never " +
        "exceed spendLimitUsd. Asks the user to approve first.",
      inputSchema: fromJsonSchema<SpendArgs>({
        type: "object",
        required: ["agentDid", "capability", "spendLimitUsd"],
        properties: {
          agentDid: { type: "string", description: "DID of the agent to authorise" },
          capability: { type: "string", description: "The specific capability this spend is authorised for" },
          spendLimitUsd: { type: "number", description: "Maximum spend in USD" },
          allowedMerchants: { type: "array", items: { type: "string" }, description: "Optional: restrict to specific merchant DIDs" },
          ttlMinutes: { type: "number", description: "Mandate expiry in minutes (default: 10)" },
        },
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const { agentDid, capability, spendLimitUsd, allowedMerchants, ttlMinutes = 10 } = args;
      if (gated("aroha_issue_spending_mandate")) {
        const gate = await approvalGate(ctx, "aroha_issue_spending_mandate", args,
          `Let ${agentDid} spend up to $${spendLimitUsd} USD for ${capability} within ${ttlMinutes} minutes.`);
        if ("result" in gate) return gate.result;
      }
      const me = await identity();
      const signed = await issueIntentMandate(
        me.did, agentDid,
        { spendLimitUsd, currency: "USD", allowedMerchants: allowedMerchants ?? null },
        me.privateKey, ttlMinutes * 60_000,
      );
      return text({
        mandateId: signed.mandate.mandateId,
        summary: `Spending mandate: up to $${spendLimitUsd} USD for ${capability} with ${agentDid}`,
        capability,
        spendLimitUsd,
        allowedMerchants: allowedMerchants ?? "any",
        validUntil: signed.mandate.expiresAt,
        mandate: signed.mandate,
        token: signed.token,
        grantorDid: me.did,
        ...rootOf(me.did),
      });
    },
  );

  // ── aroha_get_receipt ───────────────────────────────────────────────────────
  server.registerTool(
    "aroha_get_receipt",
    {
      title: "Get a call receipt",
      description:
        "Retrieve the receipt for an Aroha call made by the signed-in user: what was called, under which mandate " +
        "and approval, whether the agent's response verified, and the signed action receipt.",
      inputSchema: fromJsonSchema<{ receiptId: string }>({
        type: "object",
        required: ["receiptId"],
        properties: { receiptId: { type: "string", description: "Receipt ID returned by aroha_call" } },
      }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ receiptId }) => {
      const receipt = rt.receipts.get(principal, receiptId);
      if (!receipt) return errorResult(`Receipt ${receiptId} not found. Receipts are kept in memory per user, for this process.`);
      return text(receipt);
    },
  );

  // ── verify_mandate ──────────────────────────────────────────────────────────
  server.registerTool(
    "verify_mandate",
    {
      title: "Verify a mandate",
      description:
        "Verify a mandate token: signatures (spending chains link by link back to the root), time window, " +
        "revocation of every link, and the expected grantee. Uses the governed profile (person root, KEL, " +
        "revocation, pinned root) when the server is configured for it.",
      inputSchema: fromJsonSchema<{ token: string; expectedGrantee?: string }>({
        type: "object",
        required: ["token"],
        properties: {
          token: { type: "string", description: "The mandate token" },
          expectedGrantee: { type: "string", description: "DID the mandate must be granted to" },
        },
      }),
      annotations: READ_ONLY,
    },
    async ({ token, expectedGrantee }) => {
      let leaf: { kind: "task" | "spending"; grantor: string };
      try {
        leaf = decodeTaskOrSpendingLeaf(token);
      } catch (err) {
        return errorResult(`Not a mandate token: ${(err as Error).message}`);
      }
      try {
        if (leaf.kind === "task") {
          const key = await didKeyResolver(rt, leaf.grantor);
          if (!key) return text({ valid: false, kind: "task", reason: `cannot resolve the grantor key for ${leaf.grantor}` });
          const r = await verifyTaskMandate(token, key, expectedGrantee, { isRevoked: rt.isRevoked });
          return text({ valid: r.valid, kind: "task", reason: r.reason, mandate: r.mandate, profile: "single-link" });
        }
        const resolveKey = (did: string) => didKeyResolver(rt, did);
        const opts = config.governed
          ? { ...governedVerification({ kelSource: rt.kelSource, isRevoked: rt.isRevoked, expectedRoot: config.governed.expectedRoot, trustedRoots: config.governed.trustedRoots }), ...(expectedGrantee ? { expectedGrantee } : {}) }
          : { isRevoked: rt.isRevoked, kelSource: rt.kelSource, ...(expectedGrantee ? { expectedGrantee } : {}) };
        const r = await verifyMandateChain(token, resolveKey, opts);
        return text({
          valid: r.valid,
          kind: "spending",
          reason: r.reason,
          chainVerified: r.chainVerified,
          rootGrantor: r.rootGrantor,
          mandate: r.mandate,
          profile: config.governed ? "governed" : "standard",
        });
      } catch (err) {
        return text({ valid: false, reason: `verification could not complete: ${(err as Error).message}` });
      }
    },
  );

  // ── revoke_mandate ──────────────────────────────────────────────────────────
  server.registerTool(
    "revoke_mandate",
    {
      title: "Revoke a mandate",
      description:
        "Revoke a spending mandate the signed-in user granted (or one beneath it): signs the revocation with the " +
        "user's key and records it at the registry. Everything attenuated from the revoked mandate stops verifying.",
      inputSchema: fromJsonSchema<{ token: string }>({
        type: "object",
        required: ["token"],
        properties: { token: { type: "string", description: "The mandate token to revoke" } },
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async (args, ctx) => {
      let decoded: ReturnType<typeof decodeMandateToken>;
      try {
        decoded = decodeMandateToken(args.token);
      } catch (err) {
        return errorResult(`revoke_mandate takes a spending mandate token: ${(err as Error).message}`);
      }
      const me = await identity();
      const grantors = [...(decoded.chain ?? []).map((l) => l.mandate.grantor), decoded.mandate.grantor];
      if (!grantors.includes(me.did)) {
        return errorResult(`You (${me.did}) did not grant this mandate or any link above it, so you cannot revoke it.`);
      }
      if (gated("revoke_mandate")) {
        const gate = await approvalGate(ctx, "revoke_mandate", args, `Revoke mandate ${decoded.mandate.mandateId}.`, decoded.mandate.mandateId);
        if ("result" in gate) return gate.result;
      }
      try {
        const r = await revokeMandate(config.registry.url, args.token, me.privateKey, {
          revokerDid: me.did,
          allowInsecureHttp: config.registry.allowInsecureHttp,
          fetch: rt.fetch,
        });
        return text(r);
      } catch (err) {
        return errorResult(`Revocation failed: ${(err as Error).message}`);
      }
    },
  );

  // ── check_revocation_status ─────────────────────────────────────────────────
  server.registerTool(
    "check_revocation_status",
    {
      title: "Check revocation status",
      description:
        "Ask the registry whether a mandate is revoked. The answer is accepted only when it is signed by a pinned " +
        "registry key, names the mandate asked about and is fresh.",
      inputSchema: fromJsonSchema<{ mandateId: string; grantor: string }>({
        type: "object",
        required: ["mandateId", "grantor"],
        properties: {
          mandateId: { type: "string", description: "The mandate id" },
          grantor: { type: "string", description: "The DID that granted the mandate" },
        },
      }),
      annotations: READ_ONLY,
    },
    async ({ mandateId, grantor }) => {
      if (!config.registry.keys || config.registry.keys.length === 0) {
        return errorResult(
          "Signed revocation status needs the registry's signing keys; the server has none configured " +
          "(AROHA_MCP_REGISTRY_KEYS). An unsigned answer is not reported.",
        );
      }
      try {
        const check = httpRevocationCheck(config.registry.url, {
          allowInsecureHttp: config.registry.allowInsecureHttp,
          registryKeys: config.registry.keys,
          cacheMs: 0,
          fetch: rt.fetch,
        });
        const revoked = await check(mandateId, grantor);
        return text({ mandateId, grantor, revoked, signatureVerified: true, checkedAt: new Date().toISOString() });
      } catch (err) {
        return errorResult(`Revocation status unavailable: ${(err as Error).message}`);
      }
    },
  );

  // ── verify_receipt ──────────────────────────────────────────────────────────
  server.registerTool(
    "verify_receipt",
    {
      title: "Verify an action receipt",
      description:
        "Verify a signed Aroha action receipt against its agent's key, optionally check it describes an expected " +
        "action (agent, action name, arguments), and report whether an action derived from untrusted input " +
        "carries a human approval.",
      inputSchema: fromJsonSchema<{ receipt: unknown; expectedAgentDid?: string; expectedAction?: string; expectedArgs?: unknown }>({
        type: "object",
        required: ["receipt"],
        properties: {
          receipt: { description: "The receipt object (or its JSON text)" },
          expectedAgentDid: { type: "string" },
          expectedAction: { type: "string" },
          expectedArgs: { description: "The arguments the action should have been taken with" },
        },
      }),
      annotations: READ_ONLY,
    },
    async ({ receipt, expectedAgentDid, expectedAction, expectedArgs }) => {
      let value = receipt;
      if (typeof value === "string") {
        try { value = JSON.parse(value); } catch { return text({ ok: false, reason: "receipt is not JSON" }); }
      }
      const v = await verifyActionReceipt(value, (did) => didKeyResolver(rt, did));
      if (!v.ok) return text({ ok: false, reason: v.reason });
      const r: ArohaActionReceipt = v.receipt;
      let mismatch: string | null = null;
      if (expectedAgentDid !== undefined || expectedAction !== undefined || expectedArgs !== undefined) {
        mismatch = receiptMatches(r, {
          agentDid: expectedAgentDid ?? r.agentDid,
          action: expectedAction ?? r.action,
          args: expectedArgs ?? {},
        });
        if (expectedArgs === undefined && mismatch?.includes("arguments")) mismatch = null;
      }
      return text({
        ok: mismatch === null,
        signatureVerified: true,
        ...(mismatch ? { reason: mismatch } : {}),
        approvalPolicy: requireApprovalIfTainted(r) ?? "satisfied",
        receipt: r,
      });
    },
  );

  // ── lookup_kel ──────────────────────────────────────────────────────────────
  server.registerTool(
    "lookup_kel",
    {
      title: "Look up a Key Event Log",
      description:
        "Fetch and verify the Key Event Log of a rotatable did:aroha:E… identity (and its controller's): current " +
        "keys, kind, controller and whether it or its controller is revoked.",
      inputSchema: fromJsonSchema<{ did: string }>({
        type: "object",
        required: ["did"],
        properties: { did: { type: "string", description: "A did:aroha:E… DID" } },
      }),
      annotations: READ_ONLY,
    },
    async ({ did }) => {
      if (!isInceptionDid(did)) {
        return text({ did, kelBacked: false, note: "Not a KEL-backed (did:aroha:E…) DID; content-addressed DIDs carry their key in the DID." });
      }
      try {
        const state = await resolveKelState(did, rt.kelSource);
        if (!state) return text({ did, found: false });
        return text({
          did: state.did,
          found: true,
          verified: true,
          kind: state.kind,
          controller: state.controller,
          currentKeys: state.currentKeys,
          revoked: state.revoked,
          controllerRevoked: state.controllerRevoked,
          sequence: state.sequence,
          lastDigest: state.lastDigest,
          keyHistory: state.keyHistory,
        });
      } catch (err) {
        return errorResult(`KEL did not verify: ${(err as Error).message}`);
      }
    },
  );

  return server;
}

/** Decode the leaf of a task or spending token (no verification). */
function decodeTaskOrSpendingLeaf(token: string): { kind: "task" | "spending"; mandateId: string; grantor: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    throw new Error("malformed token");
  }
  const m = (raw as { mandate?: Record<string, unknown> } | null)?.mandate;
  if (!m || typeof m.mandateId !== "string" || typeof m.grantor !== "string") throw new Error("malformed token");
  const kind = m.mandateType === "task" || m.mandateType === "hybrid" ? "task" : "spending";
  if (kind === "spending") decodeMandateToken(token); // throws on a malformed spending token
  return { kind, mandateId: m.mandateId, grantor: m.grantor };
}

/** Verify an agent's response envelope. Returns null when it verifies, else the reason. */
async function checkResponse(
  rt: ArohaMcpRuntime,
  body: Record<string, unknown>,
  agentDid: string,
  myDid: string,
  correlationId: string,
  agentRecord: Record<string, unknown>,
): Promise<string | null> {
  const env = body as unknown as ArohaEnvelope;
  if (typeof env.type !== "string" || typeof env.from !== "string" || !env.proof) return "the agent's response is not a signed Aroha envelope";
  if (env.from !== agentDid) return `the response is from ${String(env.from)}, not ${agentDid}`;
  if (env.correlationId !== correlationId) return "the response's correlationId does not match the request";
  const key = await resolveAgentKey(rt, agentDid, agentRecord);
  if (!key) return `cannot resolve the public key for ${agentDid}`;
  const v = await validateEnvelope(env, key, myDid, rt.responseNonces);
  return v.valid ? null : (v.reason ?? "invalid response signature");
}
