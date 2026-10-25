// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * OpenID Shared Signals Framework (SSF 1.0) transmitter — configuration and
 * stream management. Event building, signing and delivery are in ../ssf.ts.
 *
 *   GET    /.well-known/ssf-configuration     transmitter metadata                    — public
 *   GET    /.well-known/jwks.json             the registry key as a JWK Set           — public
 *   POST   /v1/ssf/streams                    create a stream                         — API key
 *   GET    /v1/ssf/streams[?stream_id=]       read one stream, or list the caller's   — API key
 *   DELETE /v1/ssf/streams?stream_id=         delete a stream and its queued SETs     — API key
 *   GET    /v1/ssf/status?stream_id=          stream status                           — API key
 *   POST   /v1/ssf/status                     set status enabled | paused | disabled  — API key
 *   POST   /v1/ssf/verify                     queue a verification SET                — API key
 *   POST   /v1/ssf/poll/:streamId             RFC 8936 poll + acknowledge             — API key
 *
 * RECEIVERS. A receiver is an org API key holder (authMiddleware); a stream
 * belongs to the key that created it and no other key can read, poll or
 * delete it (404, so a stream id cannot be probed).
 *
 * SUBJECTS. default_subjects is "ALL": every enabled stream receives every
 * revocation event type it requested, SUBJECT TO VISIBILITY — an event about
 * a registered agent reaches a stream only if that agent is public, owned by
 * the stream's API key, or granted to it, checked at queueing and again at
 * every push retry and poll (ssf.ts, WHO RECEIVES WHAT). Receiver-managed
 * subject filtering (add/remove subject endpoints) is not implemented.
 *
 * PUSH ENDPOINTS must be https and carry no userinfo. Workers egress cannot
 * reach private address ranges (the same platform property routes/agents.ts
 * verify-domain relies on), and redirects are not followed.
 */

import { Hono, type Context } from "hono";
import { authMiddleware } from "../auth.js";
import { rateLimiter, authKeyId } from "../middleware/rate-limit.js";
import type { HonoEnv } from "../index.js";
import { publishedJwks, REGISTRY_SIGNING_UNCONFIGURED_MESSAGE, currentSigningKey } from "../registry-signing.js";
import { sealPushCredential } from "../ssf-credential.js";
import {
  DELIVERY_POLL,
  DELIVERY_PUSH,
  EVENTS_SUPPORTED,
  EVENT_VERIFICATION,
  SSF_SPEC_VERSION,
  emitToStream,
  eventsDelivered,
  settleInBackground,
  stillVisible,
  type StreamRow,
} from "../ssf.js";

/** Streams one API key may hold. Each one multiplies the work of every revocation. */
const MAX_STREAMS_PER_KEY = 10;
/** RFC 8936 maxEvents ceiling per poll. */
const MAX_POLL_EVENTS = 100;
const MAX_URL_LENGTH = 2048;

const streamWriteLimiter = rateLimiter({
  windowMs: 60_000,
  max: 20,
  keyFn: async (c) => `ssf-write:${await authKeyId(c)}`,
  message: "Too many stream management requests — try again later",
});

const pollLimiter = rateLimiter({
  windowMs: 60_000,
  max: 120,
  keyFn: async (c) => `ssf-poll:${await authKeyId(c)}`,
  message: "Too many poll requests — wait 60 seconds",
});

function issuerOf(c: Context<HonoEnv>): string {
  return new URL(c.req.url).origin;
}

/** The stream configuration as SSF 1.0 §8.1.1 returns it (never the authorization header). */
function streamConfig(row: StreamRow) {
  return {
    stream_id: row.stream_id,
    iss: row.iss,
    aud: row.aud,
    delivery: { method: row.delivery_method, endpoint_url: row.endpoint_url },
    events_supported: [...EVENTS_SUPPORTED],
    events_requested: JSON.parse(row.events_requested) as string[],
    events_delivered: eventsDelivered(row),
    ...(row.description ? { description: row.description } : {}),
  };
}

async function ownedStream(c: Context<HonoEnv>, streamId: string | undefined | null): Promise<StreamRow | null> {
  if (!streamId || streamId.length > 128) return null;
  const row = await c.env.DB.prepare(`SELECT * FROM ssf_streams WHERE stream_id = ?`).bind(streamId).first<StreamRow>();
  return row && row.owner_key_hash === c.get("keyHash") ? row : null;
}

function pushUrlProblem(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    return "delivery.endpoint_url is required for push delivery";
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return "delivery.endpoint_url is not a URL";
  }
  if (u.protocol !== "https:") return "delivery.endpoint_url must use https";
  if (u.username || u.password) return "delivery.endpoint_url must not carry credentials";
  return null;
}

const notFound = (c: Context<HonoEnv>) => c.json({ error: "Stream not found" }, 404);

// ─── /.well-known ─────────────────────────────────────────────────────────────

export const ssfWellKnownRoutes = new Hono<HonoEnv>();

/** SSF 1.0 §7.1 transmitter configuration metadata. */
ssfWellKnownRoutes.get("/ssf-configuration", (c) => {
  if (!currentSigningKey(c.env)) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
  const iss = issuerOf(c);
  c.header("Cache-Control", "public, max-age=300");
  return c.json({
    spec_version: SSF_SPEC_VERSION,
    issuer: iss,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    delivery_methods_supported: [DELIVERY_PUSH, DELIVERY_POLL],
    configuration_endpoint: `${iss}/v1/ssf/streams`,
    status_endpoint: `${iss}/v1/ssf/status`,
    verification_endpoint: `${iss}/v1/ssf/verify`,
    authorization_schemes: [{ spec_urn: "urn:ietf:rfc:6750" }],
    default_subjects: "ALL",
    // Not part of SSF metadata: what this transmitter emits, and the one
    // non-CAEP credential_type it uses (see ssf.ts).
    events_supported: [...EVENTS_SUPPORTED],
    aroha_credential_types: ["aroha-did-key"],
  });
});

/** The registry's signing keys as a JWK Set — SET verification (jwks_uri). */
ssfWellKnownRoutes.get("/jwks.json", (c) => {
  const jwks = publishedJwks(c.env);
  if (!jwks) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
  c.header("Cache-Control", "public, max-age=300");
  return c.json(jwks);
});

// ─── /v1/ssf ──────────────────────────────────────────────────────────────────

export const ssfRoutes = new Hono<HonoEnv>();

ssfRoutes.use("*", authMiddleware);
ssfRoutes.use("*", async (c, next) => {
  await next();
  c.res.headers.set("Cache-Control", "no-store");
});

/**
 * Create a stream. Body (SSF 1.0 §8.1.1.1):
 *   { delivery: { method, endpoint_url?, authorization_header? }, events_requested: string[], description?, aud? }
 * `aud` is an Aroha extension (the transmitter otherwise sets
 * "urn:aroha:ssf:stream:<stream_id>"). Poll streams get this registry's poll URL.
 *   201 stream configuration
 */
ssfRoutes.post("/streams", streamWriteLimiter, async (c) => {
  if (!currentSigningKey(c.env)) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
  const body = await c.req
    .json<{ delivery?: { method?: unknown; endpoint_url?: unknown; authorization_header?: unknown }; events_requested?: unknown; description?: unknown; aud?: unknown }>()
    .catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);

  const method = body.delivery?.method ?? DELIVERY_POLL;
  if (method !== DELIVERY_PUSH && method !== DELIVERY_POLL) {
    return c.json({ error: `delivery.method must be ${DELIVERY_PUSH} or ${DELIVERY_POLL}` }, 400);
  }
  const requested = body.events_requested ?? [];
  if (!Array.isArray(requested) || requested.some((e) => typeof e !== "string") || requested.length > 32) {
    return c.json({ error: "events_requested must be an array of event-type URIs" }, 400);
  }
  const description = body.description;
  if (description !== undefined && (typeof description !== "string" || description.length > 256)) {
    return c.json({ error: "description must be a string of at most 256 characters" }, 400);
  }
  const audIn = body.aud;
  if (audIn !== undefined && (typeof audIn !== "string" || audIn.length === 0 || audIn.length > 512)) {
    return c.json({ error: "aud must be a non-empty string" }, 400);
  }

  let endpointUrl: string;
  let authorizationHeader: string | null = null;
  const streamId = crypto.randomUUID();
  const iss = issuerOf(c);
  if (method === DELIVERY_PUSH) {
    const problem = pushUrlProblem(body.delivery?.endpoint_url);
    if (problem) return c.json({ error: problem }, 400);
    endpointUrl = body.delivery!.endpoint_url as string;
    const auth = body.delivery?.authorization_header;
    if (auth !== undefined) {
      if (typeof auth !== "string" || auth.length > 4096 || /[\r\n]/.test(auth)) {
        return c.json({ error: "delivery.authorization_header must be a single-line string" }, 400);
      }
      // Sealed at rest: it is the receiver's own credential and must be
      // replayed on every push, so it cannot be hashed (see ssf-credential.ts).
      authorizationHeader = await sealPushCredential(c.env, streamId, auth);
    }
  } else {
    endpointUrl = `${iss}/v1/ssf/poll/${streamId}`;
  }

  const keyHash = c.get("keyHash");
  const count = await c.env.DB
    .prepare(`SELECT COUNT(*) AS n FROM ssf_streams WHERE owner_key_hash = ?`)
    .bind(keyHash)
    .first<{ n: number }>();
  if ((count?.n ?? 0) >= MAX_STREAMS_PER_KEY) {
    return c.json({ error: `at most ${MAX_STREAMS_PER_KEY} streams per API key` }, 409);
  }

  const supported = new Set(EVENTS_SUPPORTED);
  const delivered = [...new Set(requested as string[])].filter((e) => supported.has(e));
  const now = Date.now();
  const row: StreamRow = {
    stream_id: streamId,
    owner_key_hash: keyHash,
    iss,
    aud: (audIn as string | undefined) ?? `urn:aroha:ssf:stream:${streamId}`,
    delivery_method: method,
    endpoint_url: endpointUrl,
    authorization_header: authorizationHeader,
    events_requested: JSON.stringify(requested),
    events_delivered: JSON.stringify(delivered),
    description: (description as string | undefined) ?? null,
    status: "enabled",
    status_reason: null,
    created_at: now,
    updated_at: now,
  };
  await c.env.DB
    .prepare(
      `INSERT INTO ssf_streams (stream_id, owner_key_hash, iss, aud, delivery_method, endpoint_url, authorization_header,
         events_requested, events_delivered, description, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'enabled', ?, ?)`,
    )
    .bind(
      row.stream_id, row.owner_key_hash, row.iss, row.aud, row.delivery_method, row.endpoint_url, row.authorization_header,
      row.events_requested, row.events_delivered, row.description, now, now,
    )
    .run();
  void c.get("repo").recordAuditAction("ssf.stream_created", keyHash, streamId).catch(() => {});
  return c.json(streamConfig(row), 201);
});

/** Read one stream (?stream_id=) or list the caller's streams. */
ssfRoutes.get("/streams", async (c) => {
  const id = c.req.query("stream_id");
  if (id !== undefined) {
    const row = await ownedStream(c, id);
    return row ? c.json(streamConfig(row)) : notFound(c);
  }
  const { results } = await c.env.DB
    .prepare(`SELECT * FROM ssf_streams WHERE owner_key_hash = ? ORDER BY created_at ASC`)
    .bind(c.get("keyHash"))
    .all<StreamRow>();
  return c.json((results ?? []).map(streamConfig));
});

/** Delete a stream and everything queued for it. 204. */
ssfRoutes.delete("/streams", streamWriteLimiter, async (c) => {
  const row = await ownedStream(c, c.req.query("stream_id"));
  if (!row) return notFound(c);
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM ssf_outbox WHERE stream_id = ?`).bind(row.stream_id),
    c.env.DB.prepare(`DELETE FROM ssf_streams WHERE stream_id = ?`).bind(row.stream_id),
  ]);
  void c.get("repo").recordAuditAction("ssf.stream_deleted", c.get("keyHash"), row.stream_id).catch(() => {});
  return c.body(null, 204);
});

/** SSF 1.0 §8.1.2.1 — { stream_id, status, reason? } */
ssfRoutes.get("/status", async (c) => {
  const row = await ownedStream(c, c.req.query("stream_id"));
  if (!row) return notFound(c);
  return c.json({ stream_id: row.stream_id, status: row.status, ...(row.status_reason ? { reason: row.status_reason } : {}) });
});

/** SSF 1.0 §8.1.2.2 — body { stream_id, status, reason? } */
ssfRoutes.post("/status", streamWriteLimiter, async (c) => {
  const body = await c.req.json<{ stream_id?: unknown; status?: unknown; reason?: unknown }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const row = await ownedStream(c, typeof body.stream_id === "string" ? body.stream_id : null);
  if (!row) return notFound(c);
  const status = body.status;
  if (status !== "enabled" && status !== "paused" && status !== "disabled") {
    return c.json({ error: "status must be enabled, paused or disabled" }, 400);
  }
  const reason = typeof body.reason === "string" ? body.reason.slice(0, 256) : null;
  await c.env.DB
    .prepare(`UPDATE ssf_streams SET status = ?, status_reason = ?, updated_at = ? WHERE stream_id = ?`)
    .bind(status, reason, Date.now(), row.stream_id)
    .run();
  return c.json({ stream_id: row.stream_id, status, ...(reason ? { reason } : {}) });
});

/** SSF 1.0 §8.1.4 — body { stream_id, state? }; queues (and pushes) a verification SET. 204. */
ssfRoutes.post("/verify", streamWriteLimiter, async (c) => {
  const body = await c.req.json<{ stream_id?: unknown; state?: unknown }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const row = await ownedStream(c, typeof body.stream_id === "string" ? body.stream_id : null);
  if (!row) return notFound(c);
  if (row.status === "disabled") return c.json({ error: "stream is disabled" }, 409);
  if (!currentSigningKey(c.env)) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
  const state = typeof body.state === "string" ? body.state.slice(0, 256) : undefined;
  const { push } = await emitToStream(c.env, row, {
    type: EVENT_VERIFICATION,
    subject: { format: "opaque", id: row.stream_id },
    payload: state !== undefined ? { state } : {},
    audienceDids: [],
  });
  await settleInBackground(c, push);
  return c.body(null, 204);
});

/**
 * RFC 8936 poll. Body { maxEvents?, returnImmediately?, ack?: string[], setErrs?: object }
 *   200 { sets: { [jti]: SET }, moreAvailable }
 * Acknowledged jtis are marked delivered and never returned again; anything
 * unacknowledged is returned on every poll until it is (or until retention).
 * setErrs entries are treated as acknowledgements (the receiver will not
 * accept that SET; re-sending it would not change that) and logged.
 * returnImmediately is accepted, but long polling is not implemented: every
 * poll answers at once.
 */
ssfRoutes.post("/poll/:streamId", pollLimiter, async (c) => {
  const row = await ownedStream(c, c.req.param("streamId"));
  if (!row || row.delivery_method !== DELIVERY_POLL) return notFound(c);
  const body = await c.req
    .json<{ maxEvents?: unknown; ack?: unknown; setErrs?: unknown }>()
    .catch(() => ({}) as { maxEvents?: unknown; ack?: unknown; setErrs?: unknown });
  const acks: string[] = [];
  if (Array.isArray(body.ack)) for (const j of body.ack) if (typeof j === "string" && j.length <= 64) acks.push(j);
  if (body.setErrs && typeof body.setErrs === "object") {
    for (const [jti, err] of Object.entries(body.setErrs as Record<string, unknown>).slice(0, MAX_POLL_EVENTS)) {
      if (jti.length > 64) continue;
      acks.push(jti);
      console.error(`[ssf] receiver rejected SET ${jti} on stream ${row.stream_id}:`, JSON.stringify(err).slice(0, 200));
    }
  }
  const now = Date.now();
  for (const jti of acks.slice(0, 2 * MAX_POLL_EVENTS)) {
    await c.env.DB
      .prepare(`UPDATE ssf_outbox SET delivered_at = ? WHERE stream_id = ? AND jti = ? AND delivered_at IS NULL`)
      .bind(now, row.stream_id, jti)
      .run();
  }

  const maxRaw = typeof body.maxEvents === "number" && Number.isSafeInteger(body.maxEvents) ? body.maxEvents : MAX_POLL_EVENTS;
  const max = Math.min(MAX_POLL_EVENTS, Math.max(0, maxRaw));
  if (row.status !== "enabled" || max === 0) return c.json({ sets: {}, moreAvailable: false });
  const { results } = await c.env.DB
    .prepare(
      `SELECT stream_id, jti, set_jwt, subject_dids FROM ssf_outbox
       WHERE stream_id = ? AND delivered_at IS NULL AND failed_at IS NULL
       ORDER BY created_at ASC, jti ASC LIMIT ?`,
    )
    .bind(row.stream_id, max + 1)
    .all<{ stream_id: string; jti: string; set_jwt: string; subject_dids: string }>();
  // Visibility re-checked at delivery time (ssf.ts WHO RECEIVES WHAT): a
  // subject made private since queueing is marked failed, never returned.
  const rows: Array<{ jti: string; set_jwt: string }> = [];
  for (const r of results ?? []) {
    if (await stillVisible(c.env.DB, row.owner_key_hash, r, now)) rows.push(r);
  }
  const sets: Record<string, string> = {};
  for (const r of rows.slice(0, max)) sets[r.jti] = r.set_jwt;
  return c.json({ sets, moreAvailable: rows.length > max });
});
