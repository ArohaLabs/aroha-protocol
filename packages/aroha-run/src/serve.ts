// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import type {
  Handler, HandlerContext, RunRequest, RunResponse, RunEvent,
  ApprovalDecision, ServeOptions, ArohaAgent, RegisterOptions, McpToolDefinition,
  Caller,
} from "./types.js";
import { ANONYMOUS_CALLER } from "./types.js";
import { InMemorySessionStore } from "./session.js";
import {
  verifySignedRequest, createNonceGuard, registryKeyResolver,
  signBytes, publicKeyFromPrivate, bytesToBase64Url,
} from "./signing.js";
import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";

/** Default request-body cap for serve(): 1 MiB. */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

class BodyTooLargeError extends Error {}

/**
 * Read a request body as text, refusing anything over `maxBytes`.
 * Checks Content-Length first, then counts streamed bytes, so a chunked
 * upload with no length header is still cut off.
 */
async function readCappedBody(request: Request, maxBytes: number): Promise<string> {
  const declared = Number(request.headers.get("content-length") ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) throw new BodyTooLargeError();
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new BodyTooLargeError();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString("utf8");
}

function isAsyncGen(
  fn: Handler,
): fn is (ctx: HandlerContext) => AsyncGenerator<string | RunEvent, void, ApprovalDecision | undefined> {
  return fn.constructor.name === "AsyncGeneratorFunction";
}

function safeCompare(a: string, b: string): boolean {
  try {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ba.length !== bb.length) {
      timingSafeEqual(ba, Buffer.alloc(ba.length));
      return false;
    }
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

/**
 * Normalise all handler shapes into a typed RunEvent stream.
 *
 * Bidirectional generator protocol for HITL:
 *   handler yields  { type: "approval_required", id, action }
 *   streamEvents    emits it to SSE, awaits /v1/resume, calls gen.next(decision)
 *   handler receives the ApprovalDecision as the yield's return value
 */
async function* streamEvents(
  handler:          Handler,
  ctx:              HandlerContext,
  sessionId:        string,
  requestId:        string,
  pendingApprovals: Map<string, (d: ApprovalDecision) => void>,
  approvalTimeoutMs = 300_000,
): AsyncGenerator<RunEvent> {
  let accumulated  = "";
  let finalEmitted = false;

  try {
    if (isAsyncGen(handler)) {
      const gen = handler(ctx);
      let nextInput: ApprovalDecision | undefined = undefined;

      while (true) {
        const { value, done } = await gen.next(nextInput);
        if (done) break;
        nextInput = undefined;

        if (typeof value === "string") {
          accumulated += value;
          yield { type: "token", delta: value };
        } else if (value.type === "token") {
          accumulated += value.delta;
          yield value;
        } else if (value.type === "approval_required") {
          yield value;
          // Suspend the generator until /v1/resume resolves this approval or timeout.
          const decision = await Promise.race([
            new Promise<ApprovalDecision>((resolve) => {
              pendingApprovals.set(value.id, resolve);
            }),
            new Promise<ApprovalDecision>((_, reject) =>
              setTimeout(() => {
                pendingApprovals.delete(value.id);
                reject(new Error(`Approval ${value.id} timed out after ${approvalTimeoutMs}ms`));
              }, approvalTimeoutMs)
            ),
          ]);
          nextInput = decision;
        } else if (value.type === "final") {
          finalEmitted = true;
          accumulated  = value.message ?? accumulated;
          yield { ...value, sessionId };
        } else {
          yield value;
        }
      }
    } else {
      const reply = await (handler as (c: HandlerContext) => string | Promise<string>)(ctx);
      accumulated  = String(reply);
      yield { type: "token", delta: accumulated };
    }

    if (!finalEmitted) {
      yield { type: "final", message: accumulated, sessionId };
    }
  } catch (err) {
    console.error(`[aroha-run] handler error [requestId=${requestId}]`, err);
    yield { type: "error", requestId, message: err instanceof Error ? err.message : String(err) };
  }
}

export function serve(name: string, handler: Handler, options: ServeOptions = {}): ArohaAgent {
  const {
    description       = "",
    provider          = "anthropic",
    model             = "claude-sonnet-4-6",
    systemPrompt      = "",
    memory            = "none",
    sessionStore:       customStore,
    pendingApprovals:   suppliedApprovals,
    // Signed requests by default: an agent that answers anyone who can reach
    // it is a decision, so "none" must be asked for. (The default was "none".)
    auth              = "aroha-sig",
    bearerTokens      = [],
    verifyBearer,
    version           = "1.0",
    exposeMcp         = false,
    mcpTools          = [],
    contentGuard,
    approvalTimeoutMs = 300_000,
    allowedCallers,
    resolveCallerKey,
    resolveCaller,
    consumeNonce,
    maxSkewMs,
    cors: corsOption,
    maxBodyBytes      = DEFAULT_MAX_BODY_BYTES,
    host: defaultHost = "127.0.0.1",
  } = options;

  /**
   * CORS headers for a response, or none. Off by default: a browser page on
   * any origin could otherwise drive this agent with the visitor's network
   * position (an agent on localhost or a private LAN is exactly that). Pass
   * `cors: { origins: [...] }` to allow specific origins, or
   * `cors: { origins: "*" }` for a public, unauthenticated agent. `false`
   * (or omitting it) sends no CORS headers at all — e.g. for a gateway that
   * applies its own CORS policy in front.
   */
  function corsHeaders(request: Request): Record<string, string> {
    if (!corsOption) return {};
    const base = {
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Aroha-DID, X-Aroha-Timestamp, X-Aroha-Nonce, X-Aroha-Signature",
    };
    if (corsOption.origins === "*") return { "Access-Control-Allow-Origin": "*", ...base };
    const origin = request.headers.get("Origin");
    if (origin && corsOption.origins.includes(origin)) {
      return { "Access-Control-Allow-Origin": origin, Vary: "Origin", ...base };
    }
    return { Vary: "Origin" };
  }

  const tokenSet = new Set(Array.isArray(bearerTokens) ? bearerTokens : [...bearerTokens]);
  const envToken = process.env.AROHA_BEARER_TOKEN?.trim();
  if (envToken) tokenSet.add(envToken);

  if (auth === "bearer" && tokenSet.size === 0 && !verifyBearer) {
    throw new Error(
      "serve(): auth='bearer' requires bearerTokens, verifyBearer, or AROHA_BEARER_TOKEN env var"
    );
  }

  // Session store — only instantiated when memory is enabled
  const sessionStore = memory !== "none" ? (customStore ?? new InMemorySessionStore()) : null;

  // Pending HITL approvals, keyed by approvalId.
  //
  // Supplied by the caller when the same agent may be re-served while it is
  // running: a fresh map would strand every approval the previous instance
  // raised, answering /v1/resume with 404 while the old generator sits
  // suspended until its timeout. See ServeOptions.pendingApprovals.
  const pendingApprovals =
    suppliedApprovals ?? new Map<string, (d: ApprovalDecision) => void>();

  const manifestBody = JSON.stringify({
    arohaProtocolVersion: "1.0",
    name, description, provider, model, systemPrompt,
    memory: { type: memory },
    auth:   { type: auth },
    version,
  });

  // ── Auth ─────────────────────────────────────────────────────────────────────

  // Default replay guard for signed requests — one per agent instance.
  const nonceGuard = consumeNonce ?? createNonceGuard(maxSkewMs);
  const callerKeyResolver = resolveCallerKey ?? registryKeyResolver();

  async function checkAuth(authHeader: string | undefined | null): Promise<boolean> {
    if (auth !== "bearer") return true;
    if (!authHeader?.startsWith("Bearer ")) return false;
    const token = authHeader.slice(7).trim();
    if (verifyBearer) return await verifyBearer(token);
    for (const t of tokenSet) {
      if (safeCompare(token, t)) return true;
    }
    return false;
  }

  /**
   * Authorize a request under whichever mode is configured.
   * Signed mode needs the exact raw body, so callers must pass it unparsed.
   */
  async function authorize(
    request: Request,
    path: string,
    rawBody: string,
  ): Promise<{ ok: boolean; reason?: string; callerDid?: string }> {
    if (auth === "aroha-sig") {
      const result = await verifySignedRequest({
        headers: request.headers,
        method: request.method,
        path,
        body: rawBody,
        resolvePublicKey: callerKeyResolver,
        allowedCallers,
        maxSkewMs,
        consumeNonce: nonceGuard,
      });
      return { ok: result.ok, reason: result.reason, callerDid: result.did };
    }
    const ok = await checkAuth(request.headers.get("Authorization"));
    return { ok, reason: ok ? undefined : "Bearer token required" };
  }

  // ── MCP JSON-RPC handler ──────────────────────────────────────────────────────

  const builtInRunTool: McpToolDefinition = {
    name:        "run",
    description: description || `Send a message to the ${name} agent and receive a response.`,
    inputSchema: {
      type:       "object",
      properties: {
        message:   { type: "string",              description: "Message to send to the agent" },
        sessionId: { type: "string",              description: "Session ID for multi-turn conversations" },
        history:   { type: "array" as "object",  description: "Prior conversation history" },
      },
      required: ["message"],
    },
  };

  const allMcpTools: McpToolDefinition[] = [builtInRunTool, ...mcpTools];

  async function handleMcp(
    body: Record<string, unknown>,
    authz: { ok: boolean; reason?: string },
    cors: Record<string, string>,
  ): Promise<Response> {
    const json = (data: unknown, status = 200) =>
      new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...cors } });

    if (!authz.ok) return json({ error: authz.reason ?? "Unauthorized" }, 401);

    const method = body.method as string;
    const id     = body.id ?? null;

    if (method === "tools/list") {
      return json({ jsonrpc: "2.0", id, result: { tools: allMcpTools } });
    }

    if (method === "tools/call") {
      const params = body.params as { name: string; arguments?: Record<string, unknown> } | undefined;
      const toolName = params?.name ?? "";
      const args     = params?.arguments ?? {};

      if (toolName === "run") {
        const message   = String(args.message ?? "");
        const sessionId = args.sessionId as string | undefined;
        const history   = args.history   as Array<{ role: string; content: string }> | undefined;

        try {
          // MCP clients are local desktop apps with no Aroha identity of
          // their own, so there is nobody to name here.
          const ctx = buildHandlerContext({ message, sessionId, history }, pendingApprovals, ANONYMOUS_CALLER);
          let reply = "";
          for await (const event of streamEvents(handler, ctx, ctx.sessionId!, randomUUID(), pendingApprovals)) {
            if (event.type === "final") reply = event.message;
          }
          return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: reply }] } });
        } catch (err) {
          return json({
            jsonrpc: "2.0", id,
            result: { content: [{ type: "text", text: String(err) }], isError: true },
          });
        }
      }

      const customTool = (options.mcpTools ?? []).find((t) => t.name === toolName);
      if (customTool) {
        try {
          const result = await customTool.handler(args);
          return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: result }] } });
        } catch (err) {
          return json({
            jsonrpc: "2.0", id,
            result: { content: [{ type: "text", text: String(err) }], isError: true },
          });
        }
      }

      return json({ jsonrpc: "2.0", id, error: { code: -32601, message: `Tool not found: ${toolName}` } }, 404);
    }

    return json({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } }, 404);
  }

  // ── Build HandlerContext ───────────────────────────────────────────────────────

  function buildHandlerContext(
    req: RunRequest,
    approvals: Map<string, (d: ApprovalDecision) => void>,
    caller: Caller,
  ): HandlerContext {
    return {
      ...req,
      // AFTER the spread, deliberately: `req` is parsed wire input, and a
      // caller that could name itself in its own request body could name
      // anyone. Whatever arrived is overwritten, never merged.
      caller,
      requestApproval: (action: unknown) => {
        const id = randomUUID();
        return new Promise<ApprovalDecision>((resolve) => {
          approvals.set(id, resolve);
          // The caller must emit { type: "approval_required", id, action } separately;
          // this method just registers the resolver. For non-generator handlers,
          // the event is emitted by the serve layer after requestApproval returns its id.
        });
      },
    };
  }

  // ── Fetch handler ─────────────────────────────────────────────────────────────

  const fetchHandler = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const cors = corsHeaders(request);
    const tooLarge = () =>
      new Response(JSON.stringify({ error: `Request body exceeds ${maxBodyBytes} bytes` }), {
        status: 413, headers: { "Content-Type": "application/json", ...cors },
      });
    const readBody = async (): Promise<string | Response> => {
      try {
        return await readCappedBody(request, maxBodyBytes);
      } catch (err) {
        if (err instanceof BodyTooLargeError) return tooLarge();
        return "";
      }
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return new Response(JSON.stringify({ ok: true, agent: name }), {
        headers: { "Content-Type": "application/json", ...cors },
      });
    }

    if (url.pathname === "/.well-known/aroha-agent.json" && request.method === "GET") {
      return new Response(manifestBody, {
        headers: { "Content-Type": "application/json", ...cors },
      });
    }

    // ── MCP endpoint ────────────────────────────────────────────────────────────
    if (exposeMcp && url.pathname === "/mcp" && request.method === "POST") {
      const rawBody = await readBody();
      if (rawBody instanceof Response) return rawBody;
      let body: Record<string, unknown>;
      try { body = JSON.parse(rawBody) as Record<string, unknown>; }
      catch { return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: cors }); }
      const authz = await authorize(request, url.pathname, rawBody);
      return handleMcp(body, authz, cors);
    }

    // ── Resume HITL approval ────────────────────────────────────────────────────
    if (url.pathname === "/v1/resume" && request.method === "POST") {
      const rawBody = await readBody();
      if (rawBody instanceof Response) return rawBody;
      const authz = await authorize(request, url.pathname, rawBody);
      if (!authz.ok) {
        return new Response(JSON.stringify({ error: authz.reason ?? "Unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json", ...cors },
        });
      }

      let decision: ApprovalDecision;
      try { decision = JSON.parse(rawBody) as ApprovalDecision; }
      catch { return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: cors }); }

      const resolve = pendingApprovals.get(decision.approvalId);
      if (!resolve) {
        return new Response(JSON.stringify({ error: "Unknown approvalId" }), {
          status: 404, headers: { "Content-Type": "application/json", ...cors },
        });
      }

      pendingApprovals.delete(decision.approvalId);
      resolve(decision);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json", ...cors },
      });
    }

    // ── /v1/run ─────────────────────────────────────────────────────────────────
    if (url.pathname === "/v1/run" && request.method === "POST") {
      // Read the raw body first: signed requests are verified against the exact
      // bytes, so parsing before verifying would break the signature check.
      const rawBody = await readBody();
      if (rawBody instanceof Response) return rawBody;
      let body: RunRequest;
      try {
        body = JSON.parse(rawBody) as RunRequest;
      } catch {
        return new Response(JSON.stringify({ error: "Invalid JSON" }), {
          status: 400, headers: { "Content-Type": "application/json", ...cors },
        });
      }

      const authz = await authorize(request, url.pathname, rawBody);
      if (!authz.ok) {
        return new Response(JSON.stringify({ error: authz.reason ?? "Unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Content guard — runs before auth so injection can't probe token validity
      if (contentGuard) {
        const guard = await contentGuard(body);
        if (guard.blocked) {
          return new Response(JSON.stringify({ error: guard.reason ?? "Request blocked by content guard" }), {
            status: 400, headers: { "Content-Type": "application/json", ...cors },
          });
        }
      }

      const sessionId = body.sessionId ?? randomUUID();
      const requestId = randomUUID();

      // Load session history from store and merge with caller-supplied history
      const storedHistory = sessionStore ? await sessionStore.load(sessionId) : [];
      const mergedHistory = [...storedHistory, ...(body.history ?? [])];

      // Precedence: a verified signature outranks the host's assertion,
      // because one is proof and the other is a claim. Neither present means
      // unattributed — never a guess.
      const caller: Caller = authz.callerDid
        ? { kind: "agent", id: authz.callerDid }
        : (await resolveCaller?.(request)) ?? ANONYMOUS_CALLER;

      const ctx = buildHandlerContext(
        { ...body, sessionId, history: mergedHistory },
        pendingApprovals,
        caller,
      );

      const doStream = body.stream || isAsyncGen(handler);

      if (doStream) {
        const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
        const writer  = writable.getWriter();
        const encoder = new TextEncoder();
        const emitEvent = (event: RunEvent) =>
          writer.write(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));

        (async () => {
          let finalMessage = "";
          try {
            for await (const event of streamEvents(handler, ctx, sessionId, requestId, pendingApprovals, approvalTimeoutMs)) {
              await emitEvent(event);
              if (event.type === "final") finalMessage = event.message;
            }
            // Persist to session store after the stream completes
            if (sessionStore && finalMessage) {
              await sessionStore.append(sessionId, [
                { role: "user",      content: body.message },
                { role: "assistant", content: finalMessage },
              ]);
            }
          } finally {
            await writer.close();
          }
        })();

        return new Response(readable, {
          headers: {
            "Content-Type":      "text/event-stream",
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            ...cors,
          },
        });
      }

      // Non-streaming: collect the full message from the event stream.
      try {
        let message   = "";
        let artifacts: unknown[] | undefined;
        let usage:     Record<string, number> | undefined;

        for await (const event of streamEvents(handler, ctx, sessionId, requestId, pendingApprovals, approvalTimeoutMs)) {
          if (event.type === "final") {
            message   = event.message;
            artifacts = event.artifacts;
            usage     = event.usage;
          } else if (event.type === "error") {
            return new Response(JSON.stringify({ error: event.message ?? "Internal error", requestId }), {
              status: 500, headers: { "Content-Type": "application/json", ...cors },
            });
          }
        }

        // Persist to session store
        if (sessionStore && message) {
          await sessionStore.append(sessionId, [
            { role: "user",      content: body.message },
            { role: "assistant", content: message },
          ]);
        }

        const res: RunResponse = { message, sessionId };
        if (artifacts) res.artifacts = artifacts;
        if (usage)     res.usage     = usage;

        return new Response(JSON.stringify(res), {
          headers: { "Content-Type": "application/json", ...cors },
        });
      } catch (err) {
        console.error(`[aroha-run] handler error [requestId=${requestId}]`, err);
        return new Response(JSON.stringify({ error: "Internal error", requestId }), {
          status: 500, headers: { "Content-Type": "application/json", ...cors },
        });
      }
    }

    return new Response("Not found", { status: 404, headers: cors });
  };

  // ── Node.js http server bridge ────────────────────────────────────────────────

  function start(port = 8000, host = defaultHost): void {
    const server = createServer(async (req, res) => {
      // Cap the body HERE too: the bridge buffers before fetchHandler sees
      // anything, so an uncapped read would hold any upload in memory.
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of req) {
        total += (chunk as Buffer).length;
        if (total > maxBodyBytes) {
          res.writeHead(413, { "Content-Type": "application/json", Connection: "close" });
          res.end(JSON.stringify({ error: `Request body exceeds ${maxBodyBytes} bytes` }));
          req.destroy();
          return;
        }
        chunks.push(chunk as Buffer);
      }
      const bodyText = Buffer.concat(chunks).toString("utf8");

      const url     = `http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`;
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
      }

      const request = new Request(url, {
        method:  req.method ?? "GET",
        headers,
        body:    req.method !== "GET" && req.method !== "HEAD" && bodyText ? bodyText : null,
      });

      const response = await fetchHandler(request);

      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));

      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
          if (typeof (res as unknown as { flush?: () => void }).flush === "function") {
            (res as unknown as { flush: () => void }).flush();
          }
        }
      }
      res.end();
    });

    // Bound how long a slow or idle client can hold a socket. requestTimeout
    // stays generous because SSE runs stream for as long as the handler does.
    server.headersTimeout = 15_000;
    server.keepAliveTimeout = 5_000;
    server.requestTimeout = 0;
    server.listen(port, host, () => {
      console.log(`[aroha-run] "${name}" listening on http://${host}:${port}`);
      console.log(`  /v1/run                       — invoke (stream: true for SSE)`);
      console.log(`  /v1/resume                    — resolve a pending approval`);
      if (exposeMcp) console.log(`  /mcp                          — MCP JSON-RPC endpoint`);
      console.log(`  /health                       — liveness probe`);
      console.log(`  /.well-known/aroha-agent.json — manifest`);
    });
  }

  // ── Register ──────────────────────────────────────────────────────────────────

  async function register(
    endpointUrl: string,
    opts: RegisterOptions = {},
  ): Promise<Record<string, unknown>> {
    const apiKey      = opts.apiKey      ?? process.env.AROHA_API_KEY;
    const registryUrl = resolveRegistryUrl(opts.registryUrl);
    if (!apiKey) throw new Error("Pass apiKey or set AROHA_API_KEY env var");
    // The registry's contract: did + manifestCID + publicKeyB64, plus a
    // signed challenge proving the caller holds the key. This used to POST
    // the inline manifest with `endpoint`, which the registry never accepted.
    if (!opts.did) throw new Error("register(): pass did — the DID this agent is registered under");
    if (!opts.manifestCID) throw new Error("register(): pass manifestCID — the IPFS CID of the agent manifest");
    const isEDid = opts.did.startsWith("did:aroha:E");
    let publicKey = opts.publicKey;
    if (opts.privateKey) {
      const derived = await publicKeyFromPrivate(opts.privateKey);
      if (publicKey && bytesToBase64Url(publicKey) !== bytesToBase64Url(derived)) {
        throw new Error("register(): publicKey does not match privateKey");
      }
      publicKey = derived;
    }
    const sign = opts.sign ?? (opts.privateKey ? (m: Uint8Array) => signBytes(opts.privateKey!, m) : undefined);
    if (!isEDid && (!sign || !publicKey)) {
      throw new Error(
        "register(): a signer is required — pass privateKey (32-byte Ed25519 seed), or sign + publicKey. " +
        "The registry only registers a DID whose key the caller proves it holds."
      );
    }
    const headers = { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` };
    const fail = async (res: Response) => new Error(`Registry error ${res.status}: ${await res.text()}`);

    const body: Record<string, unknown> = { did: opts.did, manifestCID: opts.manifestCID, endpointUrl };
    if (publicKey) body.publicKeyB64 = bytesToBase64Url(publicKey);
    if (!isEDid) {
      const ch = await fetch(`${registryUrl}/v1/agents/challenge`, {
        method: "POST", headers, body: JSON.stringify({ did: opts.did }),
      });
      if (!ch.ok) throw await fail(ch);
      const { nonce } = (await ch.json()) as { nonce?: unknown };
      if (typeof nonce !== "string" || !nonce) throw new Error("Registry returned no challenge nonce");
      // Exactly the registry's canonical string — key order matters.
      const message = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did: opts.did, nonce }));
      const sig = await sign!(message);
      if (!(sig instanceof Uint8Array) || sig.length !== 64) throw new Error("register(): signer must return a 64-byte Ed25519 signature");
      body.challengeNonce = nonce;
      body.challengeSignature = bytesToBase64Url(sig);
    }

    const res = await fetch(`${registryUrl}/v1/agents`, { method: "POST", headers, body: JSON.stringify(body) });
    if (!res.ok) throw await fail(res);
    return res.json() as Promise<Record<string, unknown>>;
  }

  return { start, fetch: fetchHandler, register };
}
