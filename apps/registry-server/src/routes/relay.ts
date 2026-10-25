// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/relay — the HTTP/WebSocket front door to AgentRelay (design spec §6.3,
 * §7.8, §8.4, M10). This route layer does everything the Durable Object
 * itself deliberately doesn't:
 *
 *   - Proves the caller attaching to a DID's socket actually holds that
 *     DID's private key (the DO would otherwise let anyone claim to BE any
 *     agent simply by opening a WebSocket to its relay endpoint).
 *   - Resolves §7.8 "agents behind agents": if the target DID's own SAR
 *     declares its transport as "via:<parentDID>", relay traffic is routed
 *     to the PARENT's Durable Object instead — a child sub-agent never
 *     gets its own socket, DNS record, or public exposure.
 *
 * Envelope signature verification for the delivered message itself is
 * deliberately NOT done here — see agent-relay.ts's module comment for why
 * ("the relay is untrusted at every rung"; that's the recipient's job).
 */

import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { authMiddleware, sha256hex } from "../auth.js";
import { decodeB64 } from "../b64.js";
import type { HonoEnv, Env } from "../index.js";
import { hashDID } from "./agents.js";
import { canViewAgent } from "../visibility.js";

export const relayRoutes = new Hono<HonoEnv>();

const CONNECT_TIMESTAMP_WINDOW_MS = 5 * 60_000;
const CONNECT_TOKEN_TTL_MS = 60_000;

/**
 * Header carrying the authenticated sender's API-key hash from this Worker
 * to the AgentRelay Durable Object. The DO is reachable only through this
 * Worker, and the Worker always overwrites the header (never forwards a
 * caller's value), so the DO can key its per-sender limit on it.
 */
export const RELAY_SENDER_HEADER = "X-Aroha-Relay-Sender";

/** An envelope is a signed, possibly sealed message — never a file transfer. */
const MAX_RELAY_ENVELOPE_BYTES = 64 * 1024;
const relayBodyLimit = bodyLimit({
  maxSize: MAX_RELAY_ENVELOPE_BYTES,
  onError: (c) => c.json({ error: `envelope exceeds ${MAX_RELAY_ENVELOPE_BYTES} bytes` }, 413),
});

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function connectCanonicalString(did: string, timestamp: number): string {
  return JSON.stringify({ action: "relay-connect", did, timestamp });
}

/** AGENT_RELAY is optional on Env only so the non-Workers test harness type-checks — see index.ts's comment. Any real deployment's wrangler.toml always binds it. */
function requireRelayNamespace(env: Env): DurableObjectNamespace {
  if (!env.AGENT_RELAY) {
    throw new Error("AGENT_RELAY Durable Object binding is not configured on this deployment");
  }
  return env.AGENT_RELAY;
}

/**
 * POST /v1/relay/connect — prove key possession, get a short-lived one-time
 * token to open the actual WebSocket with (query-param based rather than an
 * Authorization header, since a browser's native WebSocket constructor
 * cannot set custom headers — the same constraint ArohaServer's SSE
 * streamToken already works around, see @aroha-sdk/core transport/server.ts).
 *
 * Verifies against the DID's ALREADY-REGISTERED public key (repo.getAgent),
 * not a caller-supplied one — same reasoning as rotate-key: trusting a
 * fresh key handed in by the request would defeat the point of proving
 * anything.
 */
relayRoutes.post("/connect", authMiddleware, async (c) => {
  const body = await c.req.json<{ did?: string; timestamp?: number; signatureHex?: string }>().catch(() => ({}) as Record<string, never>);
  if (!body.did || typeof body.timestamp !== "number" || !body.signatureHex) {
    return c.json({ error: "did, timestamp, and signatureHex are required" }, 400);
  }
  if (Math.abs(Date.now() - body.timestamp) > CONNECT_TIMESTAMP_WINDOW_MS) {
    return c.json({ error: "timestamp is outside the freshness window" }, 400);
  }

  const didHash = hashDID(body.did);
  const agent = await c.get("repo").getAgent(didHash);
  if (!agent) return c.json({ error: "Not a registered agent" }, 404);

  const sigBytes = hexToBytes(body.signatureHex);
  const keyBytes = decodeB64(agent.publicKeyB64);
  if (!sigBytes || sigBytes.length !== 64 || !keyBytes) {
    return c.json({ error: "malformed signature or on-file public key" }, 400);
  }

  const message = new TextEncoder().encode(connectCanonicalString(body.did, body.timestamp));
  let valid: boolean;
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
    valid = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, message);
  } catch {
    return c.json({ error: "signature verification failed" }, 403);
  }
  if (!valid) return c.json({ error: "signature does not verify against this DID's registered key" }, 403);

  // One proof, one token. The timestamp alone allowed the same signed proof
  // to be replayed for the whole ±5 min window, minting a token each time.
  // A server-issued nonce would also close that, but it would change the
  // connect protocol for every relay client; remembering accepted proofs
  // until they could no longer pass the freshness check needs no client
  // change (migration 017, pruned by the scheduled retention job).
  const fresh = await c.get("repo").consumeRelayConnectProof(
    await sha256hex(body.signatureHex.toLowerCase()),
    didHash,
    body.timestamp + CONNECT_TIMESTAMP_WINDOW_MS,
  );
  if (!fresh) return c.json({ error: "this connect proof was already used — sign a new timestamp" }, 409);

  const token = crypto.randomUUID();
  await c.get("repo").createRelayConnectToken(token, didHash, Date.now() + CONNECT_TOKEN_TTL_MS);

  return c.json({ token, expiresInMs: CONNECT_TOKEN_TTL_MS, socketUrl: `/v1/relay/${didHash}/socket?token=${token}` });
});

/** GET /v1/relay/:didHash/socket?token=... — upgrade to the agent's own persistent relay connection. */
relayRoutes.get("/:didHash/socket", async (c) => {
  const didHash = c.req.param("didHash")!;
  const token = c.req.query("token");
  if (!token) return c.json({ error: "token query param is required" }, 400);

  const consumed = await c.get("repo").consumeRelayConnectToken(token, didHash, Date.now());
  if (!consumed) return c.json({ error: "token not found, already used, expired, or issued for a different DID" }, 403);

  const relayNs = requireRelayNamespace(c.env as unknown as Env);
  const id = relayNs.idFromName(didHash);
  const stub = relayNs.get(id);
  // Strip the token before forwarding — the DO has no business seeing it,
  // and it's already single-use-consumed above.
  const forwardUrl = new URL(c.req.url);
  forwardUrl.searchParams.delete("token");
  return stub.fetch(forwardUrl.toString(), c.req.raw);
});

/**
 * POST /v1/relay/:didHash/send — deliver an envelope to this DID's relay.
 * Resolves §7.8 sub-agent routing before forwarding: if the target's own
 * SAR declares a "via:<parentDID>" transport, this DID has no socket of
 * its own — route to the parent's Durable Object instead.
 */
relayRoutes.post("/:didHash/send", authMiddleware, relayBodyLimit, async (c) => {
  const didHash = c.req.param("didHash")!;
  const repo = c.get("repo");

  const agent = await repo.getAgent(didHash);
  let targetHash = didHash;
  if (agent) {
    const sars = await repo.querySar({ did: agent.did, now: Date.now() });
    const viaEntry = sars
      .flatMap((s) => s.transports)
      .map((t) => /^via:(.+)$/.exec(t)?.[1])
      .find((parentDid): parentDid is string => Boolean(parentDid));
    if (viaEntry) {
      targetHash = hashDID(viaEntry);
    }
  }

  const relayNs = requireRelayNamespace(c.env as unknown as Env);
  const id = relayNs.idFromName(targetHash);
  const stub = relayNs.get(id);
  const forwardUrl = new URL(c.req.url);
  forwardUrl.pathname = `/v1/relay/${targetHash}/send`;
  // The DO rate-limits per sender. It used to key on the envelope's own
  // `from` field — caller-chosen, so one API key could rotate it freely and
  // fill any agent's inbox. The key hash authMiddleware just verified is the
  // identity the registry actually knows; it is SET here (any value the
  // caller sent in this header is discarded).
  const headers = new Headers(c.req.raw.headers);
  headers.set(RELAY_SENDER_HEADER, c.get("keyHash"));
  headers.delete("Authorization");
  return stub.fetch(new Request(forwardUrl.toString(), {
    method: "POST",
    headers,
    body: c.req.raw.body,
    // Required by the Fetch spec for a streamed request body.
    duplex: "half",
  } as RequestInit));
});

/**
 * GET /v1/relay/:didHash/status — connected + queue depth, for debugging/ops.
 * Whether a private agent is online is as private as the agent itself, so
 * the same visibility rule as GET /v1/agents/:did applies before the Durable
 * Object is ever asked.
 */
relayRoutes.get("/:didHash/status", authMiddleware, async (c) => {
  const didHash = c.req.param("didHash")!;
  const repo = c.get("repo");
  const agent = await repo.getAgent(didHash);
  if (!agent || !(await canViewAgent(repo, agent, c.get("keyHash")))) {
    return c.json({ error: "Not found" }, 404);
  }
  const relayNs = requireRelayNamespace(c.env as unknown as Env);
  const id = relayNs.idFromName(didHash);
  const stub = relayNs.get(id);
  const forwardUrl = new URL(c.req.url);
  forwardUrl.pathname = `/v1/relay/${didHash}/status`;
  return stub.fetch(forwardUrl.toString(), c.req.raw);
});
