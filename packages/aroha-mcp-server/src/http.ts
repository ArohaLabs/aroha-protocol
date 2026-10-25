// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Streamable HTTP transport (MCP 2026-07-28, with the SDK's stateless
 * fallback for 2025-era clients) acting as an OAuth 2.1 protected resource.
 *
 * Routes:
 *   GET  /.well-known/oauth-protected-resource[<path>]  RFC 9728 metadata
 *   POST <path> (default /mcp)                          MCP; Bearer token required
 *   GET  /healthz                                       liveness
 *
 * A request without a valid token gets 401 with
 * `WWW-Authenticate: Bearer resource_metadata="…"` (and `scope` when scopes
 * are required), so a client discovers the authorization server from the
 * challenge. Host and Origin headers are checked against an allowlist
 * (DNS-rebinding protection). Binds 127.0.0.1 unless configured otherwise.
 */

import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import {
  CLIENT_CAPABILITIES_META_KEY,
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  hostHeaderValidationResponse,
  originValidationResponse,
  requireBearerAuth,
  type AuthInfo,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/server";
import { jwtAccessTokenVerifier, protectedResourceMetadata } from "./auth.js";
import { TASKS_EXTENSION } from "./tasks.js";
import { createArohaMcpServer, principalContextFromAuthInfo, principalFromAuthInfo, type ArohaMcpRuntime } from "./server.js";

export interface HttpServerOptions {
  runtime: ArohaMcpRuntime;
  /** Replace the JWT verifier (introspection, tests). */
  verifier?: OAuthTokenVerifier;
  /** Log sink; defaults to stderr. */
  log?: (line: string) => void;
}

export interface RunningHttpServer {
  /** The bound URL of the MCP endpoint (may differ from the public URL behind a proxy). */
  url: string;
  port: number;
  server: HttpServer;
  close(): Promise<void>;
}

class BodyTooLargeError extends Error {}

async function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  const declared = Number(req.headers["content-length"] ?? "0");
  if (declared > max) throw new BodyTooLargeError();
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const b = chunk as Buffer;
    total += b.length;
    if (total > max) throw new BodyTooLargeError();
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

function toWebRequest(req: IncomingMessage, base: URL, body: Buffer | undefined): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) for (const item of v) headers.append(k, item);
    else headers.set(k, v);
  }
  const url = new URL(req.url ?? "/", base);
  const ctrl = new AbortController();
  req.on("close", () => { if (!req.complete) ctrl.abort(); });
  return new Request(url, {
    method: req.method,
    headers,
    ...(body && req.method !== "GET" && req.method !== "HEAD" ? { body: new Uint8Array(body) } : {}),
    signal: ctrl.signal,
  });
}

async function sendWebResponse(res: ServerResponse, response: Response): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, key) => {
    const prev = headers[key];
    headers[key] = prev === undefined ? value : Array.isArray(prev) ? [...prev, value] : [prev, value];
  });
  res.writeHead(response.status, headers);
  if (!response.body) {
    res.end();
    return;
  }
  const stream = Readable.fromWeb(response.body as never);
  res.on("close", () => stream.destroy());
  stream.pipe(res);
}

/**
 * Tasks spec: a `subscriptions/listen` asking for task notifications from a
 * client that did not declare the extension MUST get -32021. The SDK serves
 * the listen stream itself (and would acknowledge it), so this is checked
 * before it. Returns the error response, or null to proceed.
 */
async function undeclaredTaskSubscription(request: Request): Promise<Response | null> {
  if (request.method !== "POST" || !(request.headers.get("content-type") ?? "").includes("json")) return null;
  const msg = (await request.clone().json().catch(() => null)) as
    { id?: unknown; method?: unknown; params?: { notifications?: { taskIds?: unknown }; _meta?: Record<string, unknown> } } | null;
  if (!msg || msg.method !== "subscriptions/listen" || msg.params?.notifications?.taskIds === undefined) return null;
  const caps = msg.params._meta?.[CLIENT_CAPABILITIES_META_KEY] as { extensions?: Record<string, unknown> } | undefined;
  if (caps?.extensions && Object.hasOwn(caps.extensions, TASKS_EXTENSION)) return null;
  return json(400, {
    jsonrpc: "2.0",
    id: typeof msg.id === "string" || typeof msg.id === "number" ? msg.id : null,
    error: { code: -32021, message: "Missing required client capability", data: { requiredCapabilities: { extensions: { [TASKS_EXTENSION]: {} } } } },
  });
}

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });
}

/** Start the HTTP transport. Resolves once listening. */
export async function startHttpServer(opts: HttpServerOptions): Promise<RunningHttpServer> {
  const { runtime } = opts;
  const { config } = runtime;
  const log = opts.log ?? ((l: string) => process.stderr.write(`${l}\n`));
  const publicUrl = config.http.publicUrl;
  const resource = publicUrl.href.replace(/\/$/, "");
  const metadataUrl = getOAuthProtectedResourceMetadataUrl(publicUrl);
  const metadataPath = new URL(metadataUrl).pathname;

  let gate: ((request: Request) => Promise<AuthInfo | Response>) | null = null;
  if (config.auth) {
    const verifier = opts.verifier ?? jwtAccessTokenVerifier({
      issuer: config.auth.issuer,
      audience: config.auth.audience,
      jwksUrl: config.auth.jwksUrl,
      algorithms: config.auth.algorithms,
      allowedClientIds: config.auth.allowedClientIds,
      requireClientIdMetadataDocument: config.auth.requireClientIdMetadataDocument,
      enterprise: config.auth.enterprise,
      fetch: runtime.fetch,
    });
    gate = requireBearerAuth({
      verifier,
      requiredScopes: config.auth.requiredScopes,
      resourceMetadataUrl: metadataUrl,
      expectedResource: new URL(config.auth.audience),
    });
  } else {
    log("[aroha-mcp-server] WARNING: HTTP transport without OAuth (development mode, loopback only)");
  }

  const handler = createMcpHandler(
    (ctx) => createArohaMcpServer(runtime, principalFromAuthInfo(ctx.authInfo), principalContextFromAuthInfo(ctx.authInfo)),
    { onerror: (err) => log(`[aroha-mcp-server] ${err.message}`), maxRequestBodySize: config.http.maxBodyBytes },
  );

  const route = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const rejected = hostHeaderValidationResponse(request, config.http.allowedHosts)
      ?? originValidationResponse(request, [...config.http.allowedOrigins, "localhost", "127.0.0.1", "[::1]"]);
    if (rejected) return rejected;

    if (url.pathname === "/healthz") return json(200, { ok: true });

    if (url.pathname === metadataPath || url.pathname === "/.well-known/oauth-protected-resource") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET" } });
      }
      if (request.method !== "GET") return json(405, { error: "method_not_allowed" }, { Allow: "GET" });
      if (!config.auth) return json(404, { error: "this server is not configured as a protected resource" });
      return json(200, protectedResourceMetadata({
        resource,
        issuer: config.auth.issuer,
        scopesSupported: config.auth.scopesSupported,
      }), { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=3600" });
    }

    if (url.pathname === config.http.path || url.pathname === `${config.http.path}/`) {
      let authInfo: AuthInfo | undefined;
      if (gate) {
        const outcome = await gate(request);
        if (outcome instanceof Response) return outcome;
        authInfo = outcome;
      }
      if (runtime.tasks) {
        const refused = await undeclaredTaskSubscription(request);
        if (refused) return refused;
      }
      return handler.fetch(request, authInfo ? { authInfo } : {});
    }
    return json(404, { error: "not_found" });
  };

  const server = createServer(async (req, res) => {
    try {
      let body: Buffer | undefined;
      if (req.method === "POST" || req.method === "PUT" || req.method === "DELETE") {
        body = await readBody(req, config.http.maxBodyBytes);
      }
      const request = toWebRequest(req, new URL(`http://${req.headers.host ?? "localhost"}`), body);
      await sendWebResponse(res, await route(request));
    } catch (err) {
      if (res.headersSent) { res.destroy(); return; }
      const tooLarge = err instanceof BodyTooLargeError;
      res.writeHead(tooLarge ? 413 : 500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: tooLarge ? "request body too large" : "internal error" }));
      if (!tooLarge) log(`[aroha-mcp-server] request failed: ${(err as Error).message}`);
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.http.port, config.http.host, () => resolve());
  });
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : config.http.port;
  const hostForUrl = config.http.host.includes(":") ? `[${config.http.host}]` : config.http.host;
  const url = `http://${hostForUrl}:${port}${config.http.path}`;
  log(`[aroha-mcp-server] MCP endpoint ${url} (public ${resource})${config.auth ? `, authorization server ${config.auth.issuer}` : ""}`);

  return {
    url,
    port,
    server,
    async close() {
      runtime.tasks?.closeAll();
      await handler.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections?.();
    },
  };
}
