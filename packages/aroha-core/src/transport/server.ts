// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 0 Transport Server (core)
 *
 * Responsibilities (protocol only):
 *   - Serve /.well-known/aroha-agent.json
 *   - Accept POST /aroha/v1, validate envelope (sig + nonce + expiry + recipient)
 *   - Run optional middleware chain before dispatch
 *   - Dispatch valid envelopes to the application handler
 *   - Handle WebSocket streams
 *   - Delegate unknown HTTP routes to optional httpRoutes handlers
 *
 * What this server deliberately does NOT do:
 *   - RBAC / credential verification  →  @aroha-sdk/credentials createRbacMiddleware()
 *   - Credential registry endpoints   →  @aroha-sdk/credentials credentialRegistryRoutes()
 *   - Settlement                      →  @aroha-sdk/settlement
 */

import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { readBody } from "./http-utils.js";
import { WebSocketServer, WebSocket } from "ws";
import { randomBytes } from "@noble/hashes/utils";
import { type ArohaEnvelope } from "../messages/envelope.js";
import { validateEnvelope, type ValidationResult } from "../messages/envelope.js";
import { NonceRegistry, type NonceStore } from "../messages/nonce.js";
import { type DIDDocument } from "../identity/did.js";
import { isSealedEnvelope, unsealEnvelope, type SealedEnvelope } from "./seal.js";

const PROTOCOL_VERSION = "1.0";

// ─── Middleware types ──────────────────────────────────────────────────────────

/**
 * A ArohaMiddleware runs after envelope validation and before dispatch.
 * Call reject() to short-circuit with an HTTP error. Return without calling
 * reject to pass the envelope to the next middleware or the handler.
 */
export type ArohaMiddleware = (
  envelope: ArohaEnvelope,
  reject: (status: number, errorCode: string, reason: string) => void
) => Promise<void>;

/**
 * An additional HTTP route registered on ArohaServer.
 * Use credentialRegistryRoutes() from @aroha-sdk/credentials to mount the
 * credential registry without coupling aroha-core to auth logic.
 */
export interface ArohaHttpRoute {
  method: string;
  test: (url: string) => boolean;
  handle: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}

/**
 * What a `beforeRequest` hook returns to answer a request itself: the status,
 * an optional JSON body (serialised with JSON.stringify; omitted → empty
 * body) and optional extra response headers.
 */
export interface ArohaEarlyResponse {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

/**
 * Runs first for every HTTP request — see ArohaServerOptions.beforeRequest.
 * Return a response to answer and stop; return nothing to continue.
 */
export type ArohaBeforeRequestHook = (
  req: IncomingMessage
) => ArohaEarlyResponse | void | undefined | Promise<ArohaEarlyResponse | void | undefined>;

// ─── Handler types ────────────────────────────────────────────────────────────

export type MessageHandler = (
  envelope: ArohaEnvelope,
  respond: (reply: ArohaEnvelope) => void,
  stream: (event: ArohaEnvelope) => void
) => Promise<void>;

import type { PublicKeyResolver } from "../identity/did-cache.js";
export type { PublicKeyResolver };

// ─── Options ──────────────────────────────────────────────────────────────────

export interface ArohaServerOptions {
  agentDID: string;
  didDocument: DIDDocument;
  port: number;
  /**
   * Interface to bind. Default "127.0.0.1" — loopback only.
   *
   * WHY loopback by default: an agent listener that binds every interface is
   * reachable from the whole LAN (and, on a cloud VM with a public IP, the
   * internet) the moment it starts — including in development, where devMode
   * or a signature bypass may be on. Exposure should be a decision, not a
   * side effect of `listen(port)`.
   *
   * To serve other machines — a LAN listener, a container behind a load
   * balancer — pass host: "0.0.0.0" (or "::") EXPLICITLY.
   */
  host?: string;
  /**
   * Node HTTP server timeouts, in ms. Defaults: headersTimeout 15 000,
   * requestTimeout 30 000, keepAliveTimeout 5 000. They bound how long a
   * slow or idle client can hold a socket (and its memory) open.
   */
  timeouts?: { headersTimeoutMs?: number; requestTimeoutMs?: number; keepAliveTimeoutMs?: number };
  onMessage: MessageHandler;
  resolvePublicKey: PublicKeyResolver;
  /**
   * Optional did:aroha-web: document to serve at the well-known path.
   * When set, the server serves GET /.well-known/aroha/agents/{path}/did.json
   * in addition to the standard /.well-known/aroha-agent.json endpoint.
   */
  webDIDDocument?: import("../identity/web-did.js").WebDIDDocument;
  /**
   * Middleware chain — runs in order after envelope validation.
   * Any middleware may call reject() to abort processing.
   * Mount RBAC here via createRbacMiddleware() from @aroha-sdk/credentials.
   */
  middleware?: ArohaMiddleware[];
  /**
   * Admission hook, run FIRST for every HTTP request — before the built-in
   * routes, before `httpRoutes`, and before a single byte of the body is
   * read. Return an `ArohaEarlyResponse` to answer the request with it (and
   * do nothing else); return nothing to let the request continue as normal.
   *
   * WHY it exists: every POST /aroha/v1 costs a body read, a JSON parse, an
   * optional decryption and an Ed25519 verification before `middleware`
   * (which only sees validated envelopes) gets a say. Admission decisions
   * that need none of that — a per-source-IP rate limit, an IP allow-list,
   * a maintenance switch — belong in front of that work, where refusing is
   * cheap. Before this hook, applications reached into the server's private
   * http.Server to wrap its request listeners.
   *
   * Sees only the request line, headers and socket (e.g.
   * `req.socket.remoteAddress`); it must not consume the body. If it throws
   * or rejects, the request is answered 500 and not processed (fail
   * closed). Not called for WebSocket upgrades, which do not go through the
   * HTTP request path.
   */
  beforeRequest?: ArohaBeforeRequestHook;
  /**
   * Additional HTTP route handlers mounted alongside /aroha/v1.
   * Checked in order after built-in routes. First match wins.
   * Mount credential registry here via credentialRegistryRoutes() from @aroha-sdk/credentials.
   */
  httpRoutes?: ArohaHttpRoute[];
  /**
   * @deprecated UNSAFE on its own — use `bypassSignatureForRequest`.
   *
   * DID allow-list for signature bypass. ONLY honoured together with
   * `bypassSignatureForRequest`: the constructor throws if it is set alone.
   * When both are set, a request bypasses signature verification only if
   * BOTH return true — the transport check decides who is talking, this
   * narrows which claimed DIDs that peer may act as.
   *
   * WHY it can no longer stand alone: its only input is `envelope.from`,
   * the very field a signature exists to authenticate. With signatures
   * skipped, ANY client that can reach the listener can write an
   * allow-listed DID into `from` and be accepted as that agent.
   */
  bypassSignatureFor?: (senderDID: string) => boolean;
  /**
   * Trusted mesh / VPC mode, transport-aware: return true to skip Ed25519
   * signature verification for THIS request.
   *
   * Receives the raw `IncomingMessage` so the decision can rest on something
   * the sender cannot simply type into the envelope — e.g. a verified mTLS
   * client certificate (`(req.socket as TLSSocket).getPeerCertificate()`,
   * `authorized`), or `req.socket.remoteAddress` on a listener bound to a
   * private interface. `senderDID` is the CLAIMED `from` and is provided
   * only so the transport identity can be matched against it; never decide
   * on `senderDID` alone. When `bypassSignatureFor` is also set, both must
   * return true.
   * Default (unset): deny — every envelope must be signed.
   */
  bypassSignatureForRequest?: (req: IncomingMessage, senderDID: string) => boolean;
  /**
   * Development mode — skips ALL cryptographic validation (signatures, nonce
   * replay, expiry) so you can spin up agents with zero ceremony on localhost.
   *
   * Set devMode: false (or omit) before deploying to production. The flip
   * requires no other code changes — your capability handlers are identical.
   *
   * @aroha-sdk/micro sets this automatically when devMode: true is passed there.
   */
  devMode?: boolean;
  /**
   * Minimum client protocol version accepted.
   * Requests with X-Aroha-Client-Version below this are rejected with 400.
   * Default: "1.0".
   */
  minClientVersion?: string;
  /**
   * Custom nonce store for distributed deployments.
   * Defaults to in-process MapNonceStore (breaks in multi-instance deployments).
   * In production, inject a Redis-backed NonceStore to share nonce state
   * across all instances and prevent cross-instance replay attacks.
   */
  nonceStore?: NonceStore;
  /**
   * Clock skew tolerance applied to envelope expiry checks, in milliseconds.
   * Recommended value for cross-region deployments: 5000.
   * Default: 0 (strict — rejects messages expired by even 1ms).
   */
  clockToleranceMs?: number;
  /**
   * Maximum accepted envelope lifetime (`expires - created`), in ms.
   * Forwarded to validateEnvelope. Default DEFAULT_MAX_ENVELOPE_TTL_MS (5 min).
   *
   * WHY it is configurable here: validateEnvelope gained this cap so that a
   * signed envelope cannot be replayed for longer than the nonce store
   * remembers it, but ArohaServer — the transport almost every agent uses —
   * had no way to set it. A deployment whose clients legitimately send
   * longer-lived envelopes (slow batch hops, store-and-forward relays) had to
   * choose between rejecting them and bypassing the server. Raise it ONLY
   * together with a persistent/shared `nonceStore` whose retention is at least
   * this long, or a replay becomes possible once the nonce is evicted.
   */
  maxTtlMs?: number;
  /**
   * How far an envelope's `created` may lie in the future, in ms. Forwarded
   * to validateEnvelope. Default max(clockToleranceMs, DEFAULT_MAX_FUTURE_SKEW_MS).
   * A future-dated envelope extends its own replay window by the skew, so this
   * is the other half of the TTL cap above.
   */
  maxFutureSkewMs?: number;
  /**
   * Maximum allowed request body size in bytes.
   * Requests exceeding this limit are rejected with HTTP 413.
   * Default: 1_048_576 (1 MiB).
   */
  maxBodyBytes?: number;
  /**
   * Reject any inbound envelope whose body is not sealed (see ./seal.ts),
   * and transparently unseal (decrypt) it with `privateKey` before
   * validation. Design spec §6.1: "encryption becomes mandatory off-TLS" —
   * set this on any listener that is NOT behind TLS (a LAN socket, a relay
   * hop). Leave unset for an ordinary HTTPS-fronted deployment, where TLS
   * already provides confidentiality and this would just be redundant CPU
   * cost. Requires `privateKey`.
   */
  requireEncryption?: boolean;
  /**
   * This agent's own Ed25519 private key — only needed when
   * requireEncryption is true, to unseal (decrypt) inbound envelope bodies.
   * The server is otherwise stateless with respect to key material: replies
   * are pre-built (and, if the transport needs it, pre-sealed) by the
   * application before being handed to `respond`/`stream`.
   *
   * Ignored when `resolvePrivateKey` is set — see that option for the
   * multi-identity case this single static key can't cover.
   */
  privateKey?: Uint8Array;
  /**
   * Multi-agent variant of `privateKey`: resolve which private key to
   * unseal an inbound envelope with, based on its own `to` field. A
   * SealedEnvelope's `to` is NOT part of the encrypted body (seal.ts only
   * ever touches `body`) — it's visible in cleartext on the wire before
   * decryption, which is exactly what makes routing by recipient DID
   * possible without a separate listener per agent. Return `undefined` for
   * a `to` this server doesn't hold a key for; the request is then rejected
   * the same way a bad decryption already is, rather than falling back to
   * `privateKey` (a fallback there would silently misroute a message meant
   * for one agent onto another agent's key). When set, takes precedence
   * over `privateKey` entirely.
   */
  resolvePrivateKey?: (recipientDID: string) => Uint8Array | undefined;
}

// ─── Server ───────────────────────────────────────────────────────────────────

export class ArohaServer {
  private readonly nonceRegistry: NonceRegistry;
  private readonly wsClients = new Map<string, WebSocket>();
  private readonly streamTokens = new Map<string, { cid: string; expiresMs: number }>();
  private server: ReturnType<typeof createServer> | null = null;
  private wss: WebSocketServer | null = null;
  private warnedLegacyBypass = false;

  constructor(private readonly opts: ArohaServerOptions) {
    this.nonceRegistry = new NonceRegistry(60_000, opts.nonceStore);
    if (opts.requireEncryption && !opts.privateKey && !opts.resolvePrivateKey) {
      throw new Error("[Aroha] ArohaServerOptions.privateKey or resolvePrivateKey is required when requireEncryption is true");
    }
    if (opts.bypassSignatureFor && !opts.bypassSignatureForRequest) {
      throw new Error(
        "[Aroha] bypassSignatureFor (DID-only) is refused on its own: it trusts the unauthenticated " +
        "envelope.from. Set bypassSignatureForRequest(req, senderDID) to decide on transport identity " +
        "(mTLS peer certificate / source address); bypassSignatureFor then further narrows it."
      );
    }
  }

  start(): Promise<void> {
    if (this.opts.devMode) {
      if (process.env.NODE_ENV !== "development") {
        throw new Error(
          `[Aroha] devMode can only be enabled when NODE_ENV=development. ` +
          `Current NODE_ENV: "${process.env.NODE_ENV ?? "(unset)"}". ` +
          `Remove devMode: true before deploying.`
        );
      }
      console.warn(
        "[Aroha] WARNING: devMode is ENABLED — ALL cryptographic validation is bypassed. " +
        "Never use devMode in production."
      );
    }
    return new Promise((resolve) => {
      const server = createServer((req, res) => this.handleHttp(req, res));
      const t = this.opts.timeouts ?? {};
      server.headersTimeout = t.headersTimeoutMs ?? 15_000;
      server.requestTimeout = t.requestTimeoutMs ?? 30_000;
      server.keepAliveTimeout = t.keepAliveTimeoutMs ?? 5_000;
      this.server = server;
      this.wss = new WebSocketServer({ server: this.server, maxPayload: this.opts.maxBodyBytes ?? 1_048_576 });
      this.wss.on("connection", (ws, req) => this.handleWsConnection(ws, req));
      const host = this.opts.host ?? "127.0.0.1";
      this.server.listen(this.opts.port, host, () => {
        console.log(`[Aroha] ${this.opts.agentDID} listening on ${host}:${this.opts.port}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    this.nonceRegistry.destroy();
    return new Promise((resolve, reject) => {
      this.server?.close((err) => (err ? reject(err) : resolve()));
    });
  }

  // ─── Version helpers ───────────────────────────────────────────────────────

  private versionLessThan(a: string, b: string): boolean {
    const [aMaj, aMin = 0] = a.split(".").map(Number);
    const [bMaj, bMin = 0] = b.split(".").map(Number);
    return aMaj < bMaj || (aMaj === bMaj && aMin < bMin);
  }

  private writeJson(res: ServerResponse, status: number, body: object): void {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "X-Aroha-Version": PROTOCOL_VERSION,
    });
    res.end(JSON.stringify(body));
  }

  // ─── HTTP ──────────────────────────────────────────────────────────────────

  private async handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? "/";

    if (this.opts.beforeRequest) {
      let early: ArohaEarlyResponse | void | undefined;
      try {
        early = await this.opts.beforeRequest(req);
      } catch {
        // Fail closed: an admission check that could not decide has not
        // admitted the request. The error itself is not echoed — it may
        // describe the deployment's own policy.
        this.writeJson(res, 500, { error: "Request admission failed" });
        return;
      }
      if (early) {
        res.writeHead(early.status, {
          "Content-Type": "application/json",
          "X-Aroha-Version": PROTOCOL_VERSION,
          ...early.headers,
        });
        res.end(early.body === undefined ? undefined : JSON.stringify(early.body));
        return;
      }
    }

    if (req.method === "GET" && url === "/.well-known/aroha-agent.json") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(this.opts.didDocument));
      return;
    }

    // did:aroha-web: well-known document — served at the agent's specific path
    if (req.method === "GET" && this.opts.webDIDDocument) {
      const { wellKnownPath } = await import("../identity/web-did.js");
      const expectedPath = wellKnownPath(this.opts.webDIDDocument.id);
      if (url === expectedPath || url === expectedPath.replace(/\/did\.json$/, "")) {
        res.writeHead(200, {
          "Content-Type":                "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control":               "no-cache",
        });
        res.end(JSON.stringify(this.opts.webDIDDocument, null, 2));
        return;
      }
    }

    if (req.method === "POST" && url === "/aroha/v1") {
      await this.handleInbound(req, res);
      return;
    }

    for (const route of this.opts.httpRoutes ?? []) {
      if (route.method === req.method && route.test(url)) {
        await route.handle(req, res);
        return;
      }
    }

    res.writeHead(404);
    res.end();
  }

  private async handleInbound(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // ── Protocol version check ──────────────────────────────────────────────
    const clientVersion = req.headers["x-aroha-client-version"] as string | undefined;
    if (this.opts.minClientVersion) {
      const effectiveVersion = clientVersion ?? "0.0";
      if (this.versionLessThan(effectiveVersion, this.opts.minClientVersion)) {
        this.writeJson(res, 400, {
          error: `Protocol version ${effectiveVersion} below minimum ${this.opts.minClientVersion}`,
          code: "VERSION_NOT_SUPPORTED",
          serverVersion: PROTOCOL_VERSION,
        });
        return;
      }
    }

    let body: string;
    try {
      body = await readBody(req, this.opts.maxBodyBytes ?? 1_048_576);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "PAYLOAD_TOO_LARGE") {
        this.writeJson(res, 413, { error: "Payload too large" });
        return;
      }
      this.writeJson(res, 400, { error: "Invalid body" });
      return;
    }

    let envelope: ArohaEnvelope;
    try { envelope = JSON.parse(body) as ArohaEnvelope; }
    catch {
      this.writeJson(res, 400, { error: "Invalid JSON" });
      return;
    }

    // ── Mandatory off-TLS encryption (design spec §6.1) ──────────────────────
    // Checked before devMode too — devMode skips signature/nonce/expiry
    // checks for zero-ceremony local hacking, but "this listener has no TLS
    // underneath it" is a transport fact devMode has no business overriding.
    if (this.opts.requireEncryption) {
      if (!isSealedEnvelope(envelope)) {
        this.writeJson(res, 400, {
          error: "This listener requires encrypted envelope bodies (off-TLS transport)",
          code: "Aroha_INVALID_PARAMS",
          docsUrl: "https://aroha-labs.com/docs/errors#Aroha_INVALID_PARAMS",
        });
        return;
      }
      // Route by the sealed envelope's own (cleartext) `to` field when this
      // server holds more than one agent's key — see resolvePrivateKey's
      // doc comment. A `to` this resolver doesn't recognize is rejected the
      // same way a bad decryption is, never silently retried against
      // `privateKey`.
      const unsealKey = this.opts.resolvePrivateKey
        ? this.opts.resolvePrivateKey((envelope as unknown as SealedEnvelope).to)
        : this.opts.privateKey;
      if (!unsealKey) {
        this.writeJson(res, 400, {
          error: "No key held for this envelope's recipient",
          code: "Aroha_INVALID_PARAMS",
          docsUrl: "https://aroha-labs.com/docs/errors#Aroha_INVALID_PARAMS",
        });
        return;
      }
      try {
        envelope = await unsealEnvelope(envelope as unknown as SealedEnvelope, unsealKey);
      } catch {
        this.writeJson(res, 400, {
          error: "Failed to decrypt sealed envelope body",
          code: "Aroha_INVALID_PARAMS",
          docsUrl: "https://aroha-labs.com/docs/errors#Aroha_INVALID_PARAMS",
        });
        return;
      }
    }

    // ── Dev mode: skip all crypto/auth — localhost hackathon mode ───────────
    if (this.opts.devMode) {
      let syncReply: ArohaEnvelope | null = null;
      const respond = (reply: ArohaEnvelope) => { syncReply = reply; };
      const stream  = (event: ArohaEnvelope) => {
        const ws = this.wsClients.get(envelope.correlationId);
        if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(event));
      };
      await this.opts.onMessage(envelope, respond, stream);
      if (syncReply) {
        this.writeJson(res, 200, syncReply);
      } else {
        const streamToken = Buffer.from(randomBytes(16)).toString("base64url");
        this.streamTokens.set(streamToken, { cid: envelope.correlationId, expiresMs: Date.now() + 30_000 });
        this.writeJson(res, 202, { streamToken });
      }
      return;
    }

    // Pass the proof's verificationMethod id so a resolver backed by a DID
    // document can select the signing key (multi-device DIDs). Resolvers
    // that only take the DID simply ignore the second argument.
    const senderPubKey = await this.opts.resolvePublicKey(
      envelope.from,
      envelope.proof?.verificationMethod
    );
    if (!senderPubKey) {
      this.writeJson(res, 401, {
        error: "Unknown sender DID",
        code: "Aroha_UNAUTHORIZED",
        docsUrl: "https://aroha-labs.com/docs/errors#Aroha_UNAUTHORIZED",
      });
      return;
    }

    const skipSignature = this.shouldBypassSignature(req, envelope.from);
    // Multi-agent listener: the recipient check below exists to make sure a
    // message meant for someone else wasn't accepted, but for a
    // resolvePrivateKey listener that already happened — unsealing above
    // only succeeded because resolvePrivateKey(envelope.to) returned a real
    // key AND decryption worked with it, which is a strictly stronger
    // recipient proof than this equality check. Passing envelope.to itself
    // here just makes an already-settled check trivially pass instead of
    // incorrectly re-litigating it against the listener's single static
    // agentDID (which, for a multi-agent listener, is just one of several
    // identities it holds — not "the" identity every inbound message must
    // match).
    const expectedRecipient = this.opts.resolvePrivateKey ? envelope.to : this.opts.agentDID;
    const result: ValidationResult = await validateEnvelope(
      envelope,
      senderPubKey,
      expectedRecipient,
      this.nonceRegistry,
      {
        ...(skipSignature ? { skipSignature: true } : {}),
        ...(this.opts.clockToleranceMs !== undefined
          ? { clockToleranceMs: this.opts.clockToleranceMs }
          : {}),
        ...(this.opts.maxTtlMs !== undefined ? { maxTtlMs: this.opts.maxTtlMs } : {}),
        ...(this.opts.maxFutureSkewMs !== undefined ? { maxFutureSkewMs: this.opts.maxFutureSkewMs } : {}),
      }
    );

    if (!result.valid) {
      // Case-insensitive: the replay reason is "Nonce replay detected"
      // (capital N), which a case-sensitive "nonce" match never caught, so
      // replays were reported as a generic Aroha_UNAUTHORIZED.
      const reason = result.reason?.toLowerCase() ?? "";
      const code = reason.includes("nonce")     ? "Aroha_REPLAY_DETECTED"
                 : reason.includes("expired")   ? "Aroha_EXPIRED_MESSAGE"
                 : reason.includes("signature") ? "Aroha_INVALID_SIGNATURE"
                 : "Aroha_UNAUTHORIZED";
      this.writeJson(res, 401, {
        error: result.reason,
        code,
        docsUrl: `https://aroha-labs.com/docs/errors#${code}`,
      });
      return;
    }

    // ── Middleware chain ────────────────────────────────────────────────────
    for (const mw of this.opts.middleware ?? []) {
      let wasRejected = false;
      let rejectStatus = 0, rejectCode = "", rejectReason = "";
      await mw(envelope, (status, code, reason) => {
        wasRejected = true; rejectStatus = status; rejectCode = code; rejectReason = reason;
      });
      if (wasRejected) {
        this.writeJson(res, rejectStatus, { error: rejectReason, code: rejectCode });
        return;
      }
    }

    // ── Dispatch ────────────────────────────────────────────────────────────
    let syncReply: ArohaEnvelope | null = null;
    const respond = (reply: ArohaEnvelope) => { syncReply = reply; };
    const stream  = (event: ArohaEnvelope) => {
      const ws = this.wsClients.get(envelope.correlationId);
      if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(event));
    };

    await this.opts.onMessage(envelope, respond, stream);

    if (syncReply) {
      this.writeJson(res, 200, syncReply);
    } else {
      const streamToken = Buffer.from(randomBytes(16)).toString("base64url");
      this.streamTokens.set(streamToken, { cid: envelope.correlationId, expiresMs: Date.now() + 30_000 });
      this.writeJson(res, 202, { streamToken });
    }
  }

  /**
   * Signature-bypass decision. Default deny. Prefers the transport-aware
   * `bypassSignatureForRequest`; falls back to the deprecated DID-only
   * predicate with a one-time warning (see its doc comment for why).
   */
  private shouldBypassSignature(req: IncomingMessage, senderDID: string): boolean {
    // The constructor guarantees bypassSignatureFor never stands alone.
    if (!this.opts.bypassSignatureForRequest) return false;
    if (this.opts.bypassSignatureForRequest(req, senderDID) !== true) return false;
    if (this.opts.bypassSignatureFor) {
      if (!this.warnedLegacyBypass) {
        this.warnedLegacyBypass = true;
        console.warn(
          "[Aroha] WARNING: bypassSignatureFor is deprecated — it is applied only as an extra " +
          "DID filter on top of bypassSignatureForRequest."
        );
      }
      return this.opts.bypassSignatureFor(senderDID) === true;
    }
    return true;
  }

  // ─── WebSocket ─────────────────────────────────────────────────────────────

  private handleWsConnection(ws: WebSocket, req: IncomingMessage): void {
    const url = new URL(req.url ?? "/", "http://localhost");
    const cid = url.searchParams.get("cid");
    if (!cid) { ws.close(1008, "Missing cid parameter"); return; }

    const tok = url.searchParams.get("tok");

    // In production mode, stream token is required.
    // In devMode, the token is optional (hackathon / localhost convenience).
    if (!this.opts.devMode) {
      if (!tok) {
        ws.close(1008, "Stream token required in production mode");
        return;
      }
      // Consume first (atomic remove), then validate — prevents TOCTOU race
      const entry = this.streamTokens.get(tok);
      this.streamTokens.delete(tok);
      if (!entry || entry.cid !== cid || entry.expiresMs < Date.now()) {
        ws.close(1008, "Invalid or expired stream token");
        return;
      }
    } else if (tok) {
      // devMode but token provided — consume first, then validate
      const entry = this.streamTokens.get(tok);
      this.streamTokens.delete(tok);
      if (!entry || entry.cid !== cid || entry.expiresMs < Date.now()) {
        ws.close(1008, "Invalid or expired stream token");
        return;
      }
    }

    this.wsClients.set(cid, ws);
    ws.on("close", () => this.wsClients.delete(cid));
  }
}
