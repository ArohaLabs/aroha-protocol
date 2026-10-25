// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * AgentRelay — the relay broker Durable Object (design spec §6.3, §8.4, M10).
 *
 * One instance per agent DID (keyed by didHash, matching the rest of this
 * Worker's convention). Holds a persistent OUTBOUND WebSocket that the
 * agent's own runtime opens to this DO — "outbound" from the agent's side,
 * which is the entire point: NAT is never traversed inward, because
 * nothing ever connects in. The same pattern GitHub Actions runners and
 * Slack Socket Mode use.
 *
 * WebSocket Hibernation (`state.acceptWebSocket`, not `ws.accept()`) lets
 * Cloudflare evict this object from memory while the socket stays open —
 * decisive, per the spec, "since most laptops are asleep": an idle agent
 * costs almost nothing.
 *
 * Deliberately NOT a trust boundary: "the relay is untrusted at every
 * rung" (§6.2) because every envelope is already signed and, off-TLS,
 * encrypted (§6.1, seal.ts) end to end. This DO is pure store-and-forward —
 * it does not verify envelope signatures (the recipient's own runtime does
 * that on delivery, exactly as it would for any other transport). Its job
 * is: hold the socket, queue what it can't deliver yet, redeliver on
 * reconnect, and refuse to let one abusive sender exhaust another agent's
 * storage.
 *
 * Durable inbox (§8.4): every relayed message is persisted BEFORE attempting
 * live delivery, with a monotonic sequence number. A live delivery is only
 * removed from storage once the agent's own socket sends back an explicit
 * ack for that sequence number — at-least-once delivery, survives a crash
 * between "message pushed down the socket" and "agent actually processed
 * it," and gives a reconnecting agent (new laptop network, woke from sleep)
 * a correlation-based way to catch up on exactly what it missed.
 */

/// <reference types="@cloudflare/workers-types" />

interface QueuedMessage {
  seq: number;
  envelope: unknown;
  queuedAt: number;
}

const MAX_QUEUED_MESSAGES = 200;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_PER_SENDER = 60;
/** Set by routes/relay.ts from the authenticated API key; see RELAY_SENDER_HEADER there. */
const SENDER_HEADER = "X-Aroha-Relay-Sender";

export class AgentRelay {
  constructor(
    private readonly state: DurableObjectState,
    private readonly env: unknown,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.endsWith("/socket") && request.headers.get("Upgrade") === "websocket") {
      return this.handleSocketUpgrade();
    }
    if (url.pathname.endsWith("/send") && request.method === "POST") {
      return this.handleSend(request);
    }
    if (url.pathname.endsWith("/status") && request.method === "GET") {
      return this.handleStatus();
    }
    return new Response("Not found", { status: 404 });
  }

  // ── Agent's own persistent connection ─────────────────────────────────────

  private async handleSocketUpgrade(): Promise<Response> {
    // Refuse a second live connection rather than silently displacing the
    // first — two sockets for one DID is a caller bug (two processes
    // claiming the same identity), not something to paper over.
    if (this.state.getWebSockets().length > 0) {
      return new Response("An agent is already connected to this relay", { status: 409 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];

    // acceptWebSocket (not server.accept()) is what makes hibernation work —
    // the runtime can now evict this object from memory between messages
    // and reconstruct it (with the socket still attached) on the next event.
    this.state.acceptWebSocket(server);

    // Deliver anything still queued from before this connection existed —
    // the correlation-based resumption the durable inbox exists for.
    await this.flushQueueTo(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  /** Hibernation-compatible handler — the runtime calls this on any message from an attached socket, even after eviction/rehydration. */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return; // binary frames unused by this protocol
    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      return; // malformed frame — ignore rather than tear down the whole connection
    }
    const ack = parsed as { type?: string; seq?: number };
    if (ack.type === "ack" && typeof ack.seq === "number") {
      await this.state.storage.delete(queueKey(ack.seq));
    }
  }

  async webSocketClose(_ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    // Nothing to clean up — undelivered messages stay queued for the next
    // connection. The socket itself is torn down by the runtime.
  }

  async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    // Same as close: queued messages simply wait for the next connection.
  }

  // ── Inbound relay delivery (another party sending TO this DID) ───────────

  private async handleSend(request: Request): Promise<Response> {
    let envelope: unknown;
    try {
      envelope = await request.json();
    } catch {
      return jsonResponse(400, { error: "Invalid JSON body" });
    }

    const from = typeof (envelope as { from?: unknown })?.from === "string"
      ? (envelope as { from: string }).from
      : null;
    if (!from) {
      return jsonResponse(400, { error: "envelope.from is required" });
    }

    // The per-sender budget is keyed on the AUTHENTICATED sender (the API
    // key hash the Worker verified), not on envelope.from: a caller chooses
    // `from` freely, so keying on it let one key rotate through invented
    // DIDs and fill this agent's inbox. Without the header (a request that
    // did not come through the Worker's /send route) there is no sender to
    // charge, so it is refused.
    const sender = request.headers.get(SENDER_HEADER);
    if (!sender) {
      return jsonResponse(400, { error: "missing authenticated sender" });
    }

    const limited = await this.peekRateLimit(sender);
    if (!limited.ok) {
      return jsonResponse(429, { error: "Rate limit exceeded for this sender", retryAfterMs: limited.retryAfterMs });
    }

    const queueSize = await this.queueSize();
    if (queueSize >= MAX_QUEUED_MESSAGES) {
      return jsonResponse(507, { error: "This agent's inbox is full — it has not connected recently enough to drain it" });
    }

    const seq = ((await this.state.storage.get<number>("seq-counter")) ?? 0) + 1;
    const queued: QueuedMessage = { seq, envelope, queuedAt: Date.now() };
    // Message, sequence counter and the sender's rate counter in ONE
    // multi-key put, which Durable Object storage applies atomically. The
    // counter used to be incremented before the queue write, so a full inbox
    // (507) or a failed put still charged the sender — and the sequence
    // counter could advance with no message behind it.
    await this.state.storage.put<unknown>({
      [queueKey(seq)]: queued,
      "seq-counter": seq,
      [limited.key]: limited.next,
    });

    // Best-effort immediate delivery — the durable-storage write above is
    // what actually guarantees at-least-once, so a live-delivery failure
    // here is not itself an error response; the message is still queued
    // for the next successful connection/flush.
    const sockets = this.state.getWebSockets();
    let delivered = false;
    for (const ws of sockets) {
      try {
        ws.send(JSON.stringify({ type: "relay-message", seq, envelope }));
        delivered = true;
      } catch {
        // socket in a bad state — leave the message queued
      }
    }

    return jsonResponse(202, { ok: true, seq, delivered });
  }

  private async handleStatus(): Promise<Response> {
    return jsonResponse(200, {
      connected: this.state.getWebSockets().length > 0,
      queuedMessages: await this.queueSize(),
    });
  }

  // ── Durable inbox helpers ──────────────────────────────────────────────────


  private async flushQueueTo(ws: WebSocket): Promise<void> {
    const entries = await this.state.storage.list<QueuedMessage>({ prefix: "queue:" });
    for (const [, msg] of entries) {
      try {
        ws.send(JSON.stringify({ type: "relay-message", seq: msg.seq, envelope: msg.envelope }));
      } catch {
        // stop trying to flush if the socket is already unusable — the next
        // connection will retry from durable storage, nothing is lost
        return;
      }
    }
  }

  private async queueSize(): Promise<number> {
    const entries = await this.state.storage.list({ prefix: "queue:" });
    return entries.size;
  }


  // ── Abuse controls ─────────────────────────────────────────────────────────
  // Per-sender fixed-window counter keyed on the authenticated sender (see
  // handleSend). This only READS: it returns the record to write, and
  // handleSend writes it in the same atomic put as the message, so a
  // refused or failed delivery never consumes the sender's budget.
  private async peekRateLimit(
    sender: string,
  ): Promise<
    | { ok: true; key: string; next: { windowStart: number; count: number } }
    | { ok: false; retryAfterMs: number }
  > {
    const key = `ratelimit:${sender}`;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    const record = (await this.state.storage.get<{ windowStart: number; count: number }>(key)) ?? null;
    if (!record || record.windowStart < windowStart) {
      return { ok: true, key, next: { windowStart: now, count: 1 } };
    }
    if (record.count >= RATE_LIMIT_MAX_PER_SENDER) {
      return { ok: false, retryAfterMs: record.windowStart + RATE_LIMIT_WINDOW_MS - now };
    }
    return { ok: true, key, next: { windowStart: record.windowStart, count: record.count + 1 } };
  }
}

function queueKey(seq: number): string {
  return `queue:${String(seq).padStart(12, "0")}`;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
