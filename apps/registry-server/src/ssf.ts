// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * OpenID Shared Signals Framework (SSF 1.0) transmitter — the event side.
 * Stream management lives in routes/ssf.ts; this module builds, signs,
 * queues and delivers Security Event Tokens (SETs, RFC 8417).
 *
 * WHY. Revocation at this registry was pull-only: verifiers asked for a
 * mandate's status or re-fetched a KEL, each behind its own cache. IETF WIMSE
 * AIMS names Shared Signals as the revocation primitive for agent identity,
 * and enterprise identity platforms consume CAEP events, so an Aroha
 * revocation now reaches a subscribed receiver the same way any other
 * credential or session revocation does.
 *
 * WHAT IS EMITTED. Each accepted revocation produces two SETs per stream that
 * requested them — one standard CAEP event, one Aroha event carrying the
 * Aroha-specific facts (SSF 1.0: a SET SHOULD carry a single event):
 *
 *   POST /v1/mandates/:id/revoke (new revocation)
 *     CAEP session-revoked   sub_id { format: "opaque", id: "<grantor>#<mandateId>" }
 *     Aroha mandate-revoked  same subject; { mandate_id, grantor, revoked_by, revoked_at }
 *   POST /v1/kel/:did (log newly ending in a revoke; cascades to controlled agents)
 *     CAEP credential-change sub_id { format: "uri", uri: "<did>" };
 *                            { credential_type: "aroha-did-key", change_type: "revoke" }
 *     Aroha did-revoked      same subject; { did, reason, sequence?, controller? }
 *
 * "aroha-did-key" is not one of CAEP's listed credential types; CAEP permits
 * a type "supported mutually by the Transmitter and the Receiver", and the
 * transmitter configuration documents it.
 *
 * SIGNING. Compact JWS, alg EdDSA, typ "secevent+jwt", kid = registry key id,
 * with REGISTRY_SIGNING_KEY (registry-signing.ts). Receivers verify with
 * the JWKS at /.well-known/jwks.json (the ssf-configuration's jwks_uri).
 *
 * DELIVERY. Every SET is written to ssf_outbox first (durable), then:
 *   push (RFC 8935)  POSTed at once, within the request that accepted the
 *                    revocation (via waitUntil on Workers, so the response is
 *                    not held); a 5 s timeout per attempt; retried by the
 *                    hourly cron with exponential backoff, at most
 *                    MAX_PUSH_ATTEMPTS times, then marked failed.
 *   poll (RFC 8936)  kept until the receiver acknowledges the jti.
 * A paused stream queues without pushing; a disabled stream records nothing
 * (SSF 1.0 §8.1.2).
 *
 * WHO RECEIVES WHAT. Streams default to every subject (SSF default_subjects
 * "ALL"), but an event never tells a stream more than a GET would. Each event
 * lists the DIDs it discloses (audienceDids: the revoked DID and its
 * controller, a mandate's grantor and revoker). A stream receives it only if,
 * for every one of those DIDs that is a registered agent, the agent is
 * public, the stream's owner key owns it, or that key holds a live grant on
 * it — the rule GET /v1/agents/:did applies to a private agent
 * (visibility.ts), made stricter for "unlisted", whose identifier a
 * broadcast would otherwise reveal. DIDs that are not registered agents (a
 * person's E-DID, an unregistered grantor) carry no visibility and do not
 * restrict. The check is repeated before every later push retry and every
 * poll, so an agent made private after an event was queued is not disclosed
 * by the queue either; such rows are marked failed ("subject no longer
 * visible to this stream").
 *
 * FAIL CLOSED. Without a usable REGISTRY_SIGNING_KEY nothing is emitted and
 * the revocation itself still succeeds: the revocation is the fact, the
 * signal is a notification about it, and an unsigned SET would be worse
 * than none. The miss is logged.
 */

import { currentSigningKey, signCompactJws, type RegistryKeyEnv } from "./registry-signing.js";
import { openPushCredential } from "./ssf-credential.js";
import { D1Repository } from "./d1-repository.js";
import { hashDID } from "./routes/agents.js";

// ─── Event types ──────────────────────────────────────────────────────────────

export const SSF_SPEC_VERSION = "1_0";
export const DELIVERY_PUSH = "urn:ietf:rfc:8935";
export const DELIVERY_POLL = "urn:ietf:rfc:8936";

export const EVENT_VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification";
export const CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
export const CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
export const AROHA_MANDATE_REVOKED = "https://aroha-labs.com/secevent/aroha/event-type/mandate-revoked";
export const AROHA_DID_REVOKED = "https://aroha-labs.com/secevent/aroha/event-type/did-revoked";

/** Event types a stream may request. Verification is always delivered (SSF 1.0 §8.1.4). */
export const EVENTS_SUPPORTED: readonly string[] = [
  CAEP_SESSION_REVOKED,
  CAEP_CREDENTIAL_CHANGE,
  AROHA_MANDATE_REVOKED,
  AROHA_DID_REVOKED,
];

/** Per push attempt. The 5-second figure is the delivery target, not a guarantee. */
export const PUSH_TIMEOUT_MS = 5_000;
export const MAX_PUSH_ATTEMPTS = 10;
/** Rows a single cron run retries — bounds one invocation's subrequests. */
const RETRY_BATCH = 40;

export type SubjectId =
  | { format: "opaque"; id: string }
  | { format: "uri"; uri: string };

export interface SecurityEvent {
  type: string;
  subject: SubjectId;
  /** The event object under `events[type]`. */
  payload: Record<string, unknown>;
  /** Optional transaction id shared by the SETs one action produced. */
  txn?: string;
  /**
   * DIDs this event discloses. A stream receives the event only if it may
   * see every one of them (see WHO RECEIVES WHAT). Empty: no restriction.
   */
  audienceDids: string[];
}

export interface StreamRow {
  stream_id: string;
  owner_key_hash: string;
  iss: string;
  aud: string;
  delivery_method: string;
  endpoint_url: string;
  authorization_header: string | null;
  events_requested: string;
  events_delivered: string;
  description: string | null;
  status: "enabled" | "paused" | "disabled";
  status_reason: string | null;
  created_at: number;
  updated_at: number;
}

interface OutboxRow {
  stream_id: string;
  jti: string;
  set_jwt: string;
  attempts: number;
  /** JSON array of the event's audienceDids, re-checked before every later delivery. */
  subject_dids: string;
}

export const NOT_VISIBLE_ERROR = "subject no longer visible to this stream";

/**
 * May the API key that owns a stream see every DID in `dids`? Registered
 * agents: public, owned by that key, or granted to it. A DID that is not a
 * registered agent does not restrict.
 */
export async function streamMaySee(db: D1Database, ownerKeyHash: string, dids: readonly string[]): Promise<boolean> {
  for (const did of new Set(dids)) {
    const didHash = hashDID(did);
    const row = await db
      .prepare(`SELECT visibility, owner_key_hash FROM agent_records WHERE did_hash = ?`)
      .bind(didHash)
      .first<{ visibility: string; owner_key_hash: string }>();
    if (!row) continue;
    if (row.visibility === "public") continue;
    if (row.owner_key_hash === ownerKeyHash) continue;
    if (await new D1Repository(db).hasGrant(didHash, { keyHash: ownerKeyHash })) continue;
    return false;
  }
  return true;
}

/** Re-check a queued row; marks it failed (never delivered) when its subject is no longer visible. */
export async function stillVisible(
  db: D1Database,
  ownerKeyHash: string,
  row: Pick<OutboxRow, "stream_id" | "jti" | "subject_dids">,
  now = Date.now(),
): Promise<boolean> {
  if (await streamMaySee(db, ownerKeyHash, parseList(row.subject_dids))) return true;
  await db
    .prepare(`UPDATE ssf_outbox SET failed_at = ?, last_error = ? WHERE stream_id = ? AND jti = ? AND delivered_at IS NULL`)
    .bind(now, NOT_VISIBLE_ERROR, row.stream_id, row.jti)
    .run();
  return false;
}

export interface SsfEnv extends RegistryKeyEnv {
  DB: D1Database;
}

export function parseList(json: string): string[] {
  try {
    const v = JSON.parse(json) as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export function eventsDelivered(row: Pick<StreamRow, "events_delivered">): string[] {
  return parseList(row.events_delivered);
}

/** Build the SET claims for one stream. */
export function buildSetClaims(stream: Pick<StreamRow, "iss" | "aud">, event: SecurityEvent, now = Date.now()) {
  return {
    iss: stream.iss,
    aud: stream.aud,
    jti: crypto.randomUUID().replace(/-/g, ""),
    iat: Math.floor(now / 1000),
    ...(event.txn ? { txn: event.txn } : {}),
    sub_id: event.subject,
    events: { [event.type]: event.payload },
  };
}

/** Queue a SET for one stream. Returns the outbox row, or null when nothing was queued. */
async function enqueue(env: SsfEnv, stream: StreamRow, event: SecurityEvent, now: number): Promise<OutboxRow | null> {
  const key = currentSigningKey(env);
  if (!key) {
    console.error(`[ssf] REGISTRY_SIGNING_KEY unusable — ${event.type} not emitted to stream ${stream.stream_id}`);
    return null;
  }
  const claims = buildSetClaims(stream, event, now);
  const setJwt = signCompactJws({ typ: "secevent+jwt" }, claims, key);
  const subjectDids = JSON.stringify(event.audienceDids);
  await env.DB
    .prepare(
      `INSERT INTO ssf_outbox (stream_id, jti, event_type, set_jwt, subject_dids, created_at, attempts, next_attempt_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
    )
    .bind(stream.stream_id, claims.jti, event.type, setJwt, subjectDids, now, now)
    .run();
  return { stream_id: stream.stream_id, jti: claims.jti, set_jwt: setJwt, attempts: 0, subject_dids: subjectDids };
}

/**
 * One push attempt (RFC 8935 §2): POST the SET as application/secevent+jwt;
 * 202 (or any 2xx) is acceptance. Records the outcome on the outbox row.
 */
export async function pushOnce(env: SsfEnv, stream: StreamRow, row: OutboxRow, now = Date.now()): Promise<boolean> {
  let error: string | null = null;
  const credential = await openPushCredential(env, stream.stream_id, stream.authorization_header);
  if (credential.resealed) {
    // Legacy plaintext, or sealed under a rotated-out key: store it under the
    // current key now so the old form does not linger.
    await env.DB.prepare(`UPDATE ssf_streams SET authorization_header = ? WHERE stream_id = ?`)
      .bind(credential.resealed, stream.stream_id)
      .run();
  }
  try {
    const res = await fetch(stream.endpoint_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/secevent+jwt",
        Accept: "application/json",
        ...(credential.value ? { Authorization: credential.value } : {}),
      },
      body: row.set_jwt,
      redirect: "manual",
      signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
    });
    if (res.status < 200 || res.status >= 300) error = `HTTP ${res.status}`;
  } catch (err) {
    error = String((err as Error)?.message ?? err).slice(0, 200);
  }
  const attempts = row.attempts + 1;
  if (!error) {
    await env.DB
      .prepare(`UPDATE ssf_outbox SET delivered_at = ?, attempts = ?, last_error = NULL WHERE stream_id = ? AND jti = ?`)
      .bind(now, attempts, row.stream_id, row.jti)
      .run();
    return true;
  }
  // Backoff: 1, 2, 4 … minutes, capped at 6 hours. The cron is hourly, so
  // in practice a failed push is retried on the next cron run after this.
  const delay = Math.min(6 * 60 * 60_000, 60_000 * 2 ** (attempts - 1));
  const failed = attempts >= MAX_PUSH_ATTEMPTS;
  await env.DB
    .prepare(
      `UPDATE ssf_outbox SET attempts = ?, next_attempt_at = ?, last_error = ?, failed_at = ?
       WHERE stream_id = ? AND jti = ?`,
    )
    .bind(attempts, now + delay, error, failed ? now : null, row.stream_id, row.jti)
    .run();
  return false;
}

/**
 * Emit events to every subscribed stream. Returns a promise for the
 * immediate push attempts — the caller hands it to waitUntil (Workers) or
 * awaits it. Never throws: an emission failure must not undo the revocation
 * that triggered it.
 */
export async function emitSecurityEvents(env: SsfEnv, events: SecurityEvent[]): Promise<{ queued: number; pushes: Promise<unknown> }> {
  let queued = 0;
  const pushes: Promise<unknown>[] = [];
  try {
    if (events.length === 0) return { queued, pushes: Promise.resolve() };
    const { results } = await env.DB
      .prepare(`SELECT * FROM ssf_streams WHERE status != 'disabled'`)
      .all<StreamRow>();
    const now = Date.now();
    for (const stream of results ?? []) {
      const wanted = new Set(eventsDelivered(stream));
      for (const event of events) {
        if (!wanted.has(event.type)) continue;
        // Never queued at all for a stream that could not GET the subject.
        if (!(await streamMaySee(env.DB, stream.owner_key_hash, event.audienceDids))) continue;
        const row = await enqueue(env, stream, event, now);
        if (!row) continue;
        queued++;
        if (stream.delivery_method === DELIVERY_PUSH && stream.status === "enabled") {
          pushes.push(pushOnce(env, stream, row).catch((err) => console.error("[ssf] push failed:", err)));
        }
      }
    }
  } catch (err) {
    console.error("[ssf] emission failed:", err);
  }
  return { queued, pushes: Promise.all(pushes) };
}

/** Queue one event for one stream regardless of its subscription (verification events). */
export async function emitToStream(env: SsfEnv, stream: StreamRow, event: SecurityEvent): Promise<{ push: Promise<unknown> }> {
  const row = await enqueue(env, stream, event, Date.now());
  if (row && stream.delivery_method === DELIVERY_PUSH && stream.status === "enabled") {
    return { push: pushOnce(env, stream, row).catch((err) => console.error("[ssf] push failed:", err)) };
  }
  return { push: Promise.resolve() };
}

/** Cron: retry due push deliveries. Returns attempts made. */
export async function retryPendingPushes(env: SsfEnv, now = Date.now()): Promise<number> {
  const { results } = await env.DB
    .prepare(
      `SELECT o.stream_id, o.jti, o.set_jwt, o.attempts, o.subject_dids
       FROM ssf_outbox o JOIN ssf_streams s ON s.stream_id = o.stream_id
       WHERE o.delivered_at IS NULL AND o.failed_at IS NULL AND o.next_attempt_at <= ?
         AND s.delivery_method = ? AND s.status = 'enabled'
       ORDER BY o.next_attempt_at ASC LIMIT ?`,
    )
    .bind(now, DELIVERY_PUSH, RETRY_BATCH)
    .all<OutboxRow>();
  let attempted = 0;
  for (const row of results ?? []) {
    const stream = await env.DB.prepare(`SELECT * FROM ssf_streams WHERE stream_id = ?`).bind(row.stream_id).first<StreamRow>();
    if (!stream) continue;
    if (!(await stillVisible(env.DB, stream.owner_key_hash, row, now))) continue;
    await pushOnce(env, stream, row, now);
    attempted++;
  }
  return attempted;
}

// ─── Event builders ───────────────────────────────────────────────────────────

/** The two SETs for a newly recorded mandate revocation. */
export function mandateRevokedEvents(input: {
  mandateId: string;
  grantor: string;
  revokedBy: string;
  revokedAtMs: number;
}): SecurityEvent[] {
  const subject: SubjectId = { format: "opaque", id: `${input.grantor}#${input.mandateId}` };
  const txn = crypto.randomUUID();
  const audienceDids = [input.grantor, input.revokedBy];
  return [
    {
      type: CAEP_SESSION_REVOKED,
      subject,
      txn,
      audienceDids,
      payload: {
        event_timestamp: Math.floor(input.revokedAtMs / 1000),
        initiating_entity: "user",
        reason_admin: { en: "Aroha mandate revoked by a grantor in its delegation chain" },
      },
    },
    {
      type: AROHA_MANDATE_REVOKED,
      subject,
      txn,
      audienceDids,
      payload: {
        mandate_id: input.mandateId,
        grantor: input.grantor,
        revoked_by: input.revokedBy,
        revoked_at: new Date(input.revokedAtMs).toISOString(),
        event_timestamp: Math.floor(input.revokedAtMs / 1000),
      },
    },
  ];
}

/** The two SETs for a DID whose KEL (or controller's KEL) is newly revoked. */
export function didRevokedEvents(input: {
  did: string;
  reason: "kel-revoked" | "controller-revoked";
  sequence?: number;
  controller?: string;
  atMs?: number;
}): SecurityEvent[] {
  const at = input.atMs ?? Date.now();
  const subject: SubjectId = { format: "uri", uri: input.did };
  const txn = crypto.randomUUID();
  const audienceDids = [input.did, ...(input.controller ? [input.controller] : [])];
  return [
    {
      type: CAEP_CREDENTIAL_CHANGE,
      subject,
      txn,
      audienceDids,
      payload: {
        event_timestamp: Math.floor(at / 1000),
        credential_type: "aroha-did-key",
        change_type: "revoke",
        initiating_entity: "user",
        reason_admin: {
          en: input.reason === "kel-revoked"
            ? "Aroha DID revoked in its key event log"
            : "Aroha agent DID revoked through its controlling person's key event log",
        },
      },
    },
    {
      type: AROHA_DID_REVOKED,
      subject,
      txn,
      audienceDids,
      payload: {
        did: input.did,
        reason: input.reason,
        ...(input.sequence !== undefined ? { sequence: input.sequence } : {}),
        ...(input.controller ? { controller: input.controller } : {}),
        event_timestamp: Math.floor(at / 1000),
      },
    },
  ];
}

/**
 * Hand delivery promises to the Workers runtime when there is one, so the
 * HTTP response is not held; otherwise (tests, Node) wait for them.
 */
export async function settleInBackground(c: { executionCtx: { waitUntil(p: Promise<unknown>): void } }, work: Promise<unknown>): Promise<void> {
  let ctx: { waitUntil(p: Promise<unknown>): void } | null = null;
  try {
    ctx = c.executionCtx;
  } catch {
    ctx = null;
  }
  if (ctx) ctx.waitUntil(work);
  else await work;
}
