// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 0 Transport Client
 *
 * Sends Aroha messages to remote agents over HTTPS.
 * Handles streaming responses via WebSocket.
 *
 * This is protocol infrastructure. It does not know what the messages
 * mean or what to do with responses — that is the orchestrator's job.
 */

import { WebSocket } from "ws";
import { type ArohaEnvelope } from "../messages/envelope.js";
import { assertSecureEndpoint } from "../endpoints/index.js";

// ─── Connection Pool ──────────────────────────────────────────────────────────

export interface ConnectionPoolConfig {
  /**
   * Maximum number of concurrent connections per origin (scheme+host+port).
   * Default: 10
   */
  connections?: number;
  /**
   * How long an idle connection is kept alive in ms.
   * Default: 60_000 (60 seconds)
   */
  keepAliveTimeoutMs?: number;
}

/**
 * AgentConnectionPool — maintains persistent HTTP connections per origin.
 *
 * Uses undici (built into Node.js 22+) to pool connections, eliminating
 * the TCP+TLS handshake overhead on every ArohaClient.send() call.
 *
 * For an orchestrator talking to 20 agents at 100 msg/s, this removes
 * ~2,000 TLS handshakes per second (~400ms each = 800s of saved latency/s).
 *
 * Usage:
 *   const pool = new AgentConnectionPool();
 *   const client = new ArohaClient({ pool });
 */
export class AgentConnectionPool {
  private readonly connections: number;
  private readonly keepAliveTimeoutMs: number;
  // Map from origin → undici Pool instance (lazy-created)
  private readonly pools = new Map<string, import("undici").Pool>();

  constructor(config: ConnectionPoolConfig = {}) {
    this.connections       = config.connections       ?? 10;
    this.keepAliveTimeoutMs = config.keepAliveTimeoutMs ?? 60_000;
  }

  async fetch(url: string, init: RequestInit): Promise<Response> {
    const origin = new URL(url).origin;
    let pool = this.pools.get(origin);

    if (!pool) {
      const { Pool } = await import("undici");
      pool = new Pool(origin, {
        connections: this.connections,
        keepAliveTimeout: this.keepAliveTimeoutMs / 1000,
        keepAliveMaxTimeout: this.keepAliveTimeoutMs / 1000,
      });
      this.pools.set(origin, pool);
    }

    const { fetch: undiciFetch } = await import("undici");
    return undiciFetch(url, { ...init, dispatcher: pool } as Parameters<typeof undiciFetch>[1]) as unknown as Response;
  }

  async destroy(): Promise<void> {
    await Promise.all([...this.pools.values()].map((p) => p.destroy()));
    this.pools.clear();
  }

  get poolCount(): number {
    return this.pools.size;
  }
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SendOptions {
  timeoutMs?: number;
}

export interface ArohaClientOptions {
  /** Optional connection pool for persistent keep-alive connections. */
  pool?: AgentConnectionPool;
  /**
   * DEVELOPMENT ONLY: allow http:// and ws:// to non-loopback hosts. By
   * default every endpoint must be https:// / wss:// unless it is loopback.
   * Envelope signatures protect integrity, not confidentiality — bodies,
   * stream tokens and mandate tokens would cross the network in clear.
   */
  allowInsecureHttp?: boolean;
}

// ─── Client ───────────────────────────────────────────────────────────────────

export class ArohaClient {
  private readonly pool?: AgentConnectionPool;
  private readonly allowInsecureHttp: boolean;

  constructor(opts: ArohaClientOptions = {}) {
    this.pool = opts.pool;
    this.allowInsecureHttp = opts.allowInsecureHttp === true;
  }

  /**
   * Send an Aroha message and await a synchronous response.
   * Returns the response ArohaEnvelope, or null when the provider responds
   * with 202 Accepted (async / streaming — use stream() for WebSocket events).
   */
  async send(
    endpoint: string,
    envelope: ArohaEnvelope,
    opts: SendOptions = {}
  ): Promise<ArohaEnvelope | null> {
    assertSecureEndpoint(endpoint, { allowInsecureHttp: this.allowInsecureHttp, label: "endpoint" });
    const { timeoutMs = 30_000 } = opts;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const fetchFn = this.pool
      ? (url: string, init: RequestInit) => this.pool!.fetch(url, init)
      : fetch;

    let response: Response;
    try {
      response = await fetchFn(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 202) {
      return null;
    }

    if (!response.ok) {
      const error = await response.text();
      throw new ArohaTransportError(response.status, error);
    }

    return response.json() as Promise<ArohaEnvelope>;
  }

  /**
   * Open a WebSocket stream to receive ArohaStream events for a given saga.
   *
   * @param wsEndpoint    WebSocket URL (wss://<host>/aroha/stream)
   * @param correlationId The saga correlationId to subscribe to
   * @param streamToken   One-time token from the 202 response (recommended)
   */
  stream(
    wsEndpoint: string,
    correlationId: string,
    streamToken?: string
  ): AsyncIterable<ArohaEnvelope> {
    const u = assertSecureEndpoint(wsEndpoint, { allowInsecureHttp: this.allowInsecureHttp, label: "wsEndpoint" });
    u.searchParams.set("cid", correlationId);
    if (streamToken) u.searchParams.set("tok", streamToken);
    const ws = new WebSocket(u.toString());

    return {
      [Symbol.asyncIterator]() {
        const queue: ArohaEnvelope[] = [];
        let resolve: ((value: IteratorResult<ArohaEnvelope>) => void) | null = null;
        let done = false;
        let error: Error | null = null;

        ws.on("message", (data) => {
          const envelope = JSON.parse(data.toString()) as ArohaEnvelope;
          if (resolve) {
            const r = resolve;
            resolve = null;
            r({ value: envelope, done: false });
          } else {
            queue.push(envelope);
          }
        });

        ws.on("close", () => {
          done = true;
          if (resolve) {
            const r = resolve;
            resolve = null;
            r({ value: undefined as unknown as ArohaEnvelope, done: true });
          }
        });

        ws.on("error", (err) => {
          error = err;
          if (resolve) {
            const r = resolve;
            resolve = null;
            r({ value: undefined as unknown as ArohaEnvelope, done: true });
          }
        });

        return {
          next(): Promise<IteratorResult<ArohaEnvelope>> {
            if (error) return Promise.reject(error);
            if (queue.length > 0) {
              return Promise.resolve({ value: queue.shift()!, done: false });
            }
            if (done) {
              return Promise.resolve({ value: undefined as unknown as ArohaEnvelope, done: true });
            }
            return new Promise((r) => { resolve = r; });
          },
          return(): Promise<IteratorResult<ArohaEnvelope>> {
            ws.close();
            return Promise.resolve({ value: undefined as unknown as ArohaEnvelope, done: true });
          },
        };
      },
    };
  }

  /**
   * Fetch the DID Document from an agent's well-known endpoint.
   */
  async fetchDIDDocument(agentBaseUrl: string): Promise<Record<string, unknown>> {
    assertSecureEndpoint(agentBaseUrl, { allowInsecureHttp: this.allowInsecureHttp, label: "agentBaseUrl" });
    const response = await fetch(`${agentBaseUrl}/.well-known/aroha-agent.json`, {
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Failed to fetch DID Document from ${agentBaseUrl}`);
    return response.json() as Promise<Record<string, unknown>>;
  }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

export class ArohaTransportError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: string
  ) {
    super(`Aroha transport error ${statusCode}: ${body}`);
    this.name = "ArohaTransportError";
  }
}
