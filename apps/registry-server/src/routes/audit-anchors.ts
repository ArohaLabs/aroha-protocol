// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/audit-anchors — an external witness for runtime audit heads, and
 * /.well-known/aroha-registry-keys.json — the keys that witness signs with.
 *
 *   POST /v1/audit-anchors                          append a signed live-head checkpoint — no API key, rate limited
 *   GET  /v1/audit-anchors/:installDid?after=&limit= the install's anchors, ascending by seq — public
 *   GET  /.well-known/aroha-registry-keys.json      the registry's signing keys — public
 *
 * WHY A WITNESS. The runtime signs checkpoints of its audit log's live head
 * (apps/aroha-runtime/src/host/audit-rotate.ts), which makes rewriting
 * history behind a checkpoint require the install key. Its documented known
 * limit is the tail: removing the newest checkpoints together with the
 * matching log entries leaves files that still verify, because every piece
 * of evidence lives on the same machine. Sending each checkpoint here moves
 * a copy off that machine: the registry checks the install's signature,
 * refuses to go backwards, timestamps it, chains it to the previous anchor
 * and countersigns the result. A later verifier compares the local log with
 * this record; a truncation past an anchored seq is then a visible gap.
 *
 * WHAT IS SIGNED. The install signs exactly what the runtime signs for a
 * live-head checkpoint — headPayload() below, copied from audit-rotate.ts
 * (the source of truth; keep the two byte-identical). The registry signs
 * RFC 8785 JCS of the `anchor` object with REGISTRY_SIGNING_KEY.
 *
 * WHO MAY ANCHOR. Only a content-addressed `did:aroha:z…` install DID: its
 * key is derived from the DID itself, so verifying the signature needs no
 * registry lookup and no prior registration. A rotatable E-DID would make the
 * witness depend on KEL state at append time — out of scope for v1.
 *
 * APPEND-ONLY. seq must be strictly greater than the last anchored seq for
 * that install (409 otherwise). The check and the insert are one conditional
 * statement, and (install_did, log_index) is unique, so two racing appends
 * cannot both take the same position in the chain.
 */

import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { resolveContentAddressedKey } from "@aroha-sdk/credentials/mandates";
import type { HonoEnv } from "../index.js";
import { rateLimiter, clientIp } from "../middleware/rate-limit.js";
import {
  REGISTRY_SIGNING_UNCONFIGURED_MESSAGE,
  b64urlToBytes,
  currentSigningKey,
  jcsSha256Hex,
  publishedKeys,
  signJcs,
} from "../registry-signing.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

export const AUDIT_ANCHOR_PURPOSE = "aroha.audit-anchor/v1";

/** A signedAt may not lie further in the future than this (clock skew). */
const MAX_SIGNED_AT_FUTURE_SKEW_MS = 5 * 60_000;
/** Per-install appends per minute. The runtime anchors every 100 entries or 5 minutes. */
const PER_INSTALL_MAX_PER_MIN = 20;
const MAX_LIST_LIMIT = 100;
/** An anchor body is five short fields; anything near this is not one. */
const MAX_ANCHOR_BODY_BYTES = 4 * 1024;

const anchorBodyLimit = bodyLimit({
  maxSize: MAX_ANCHOR_BODY_BYTES,
  onError: (c) => c.json({ error: `request body exceeds ${MAX_ANCHOR_BODY_BYTES} bytes` }, 413),
});

/**
 * COPIED from apps/aroha-runtime/src/host/audit-rotate.ts headPayload() —
 * that file is the source of truth for what a live-head checkpoint signs.
 * The registry cannot import the runtime (a Node app), and a divergence here
 * would make every honest anchor fail verification, so a test pins the bytes.
 */
export function headPayload(c: { seq: number; hash: string; signedAt: string }): Uint8Array {
  return new TextEncoder().encode("aroha-audit-head/v1\n" + JSON.stringify([c.seq, c.hash, c.signedAt]));
}

export interface AuditAnchor {
  purpose: typeof AUDIT_ANCHOR_PURPOSE;
  installDid: string;
  seq: number;
  hash: string;
  signedAt: string;
  anchoredAt: string;
  logIndex: number;
  prevAnchorHash: string;
}

interface AnchorRow {
  install_did: string;
  seq: number;
  hash: string;
  signed_at: string;
  anchored_at: string;
  log_index: number;
  prev_anchor_hash: string;
  witness_signature: string;
  witness_key_id: string;
}

function anchorFromRow(r: AnchorRow): AuditAnchor {
  return {
    purpose: AUDIT_ANCHOR_PURPOSE,
    installDid: r.install_did,
    seq: r.seq,
    hash: r.hash,
    signedAt: r.signed_at,
    anchoredAt: r.anchored_at,
    logIndex: r.log_index,
    prevAnchorHash: r.prev_anchor_hash,
  };
}

/** Per-IP bound on the CPU an unauthenticated caller can spend on signature checks. */
const anchorIpLimiter = rateLimiter({
  windowMs: 60_000,
  max: 60,
  keyFn: (c) => `audit-anchor-ip:${clientIp(c)}`,
  message: "Too many audit-anchor requests — try again later",
});

// Per-install bound. The install DID is in the body, so this cannot be a
// keyFn middleware; it runs after parsing, same sliding-window semantics.
const perInstall = new Map<string, { count: number; resetAt: number }>();
function installRateLimited(installDid: string, now = Date.now()): boolean {
  const b = perInstall.get(installDid);
  if (!b || now >= b.resetAt) {
    perInstall.set(installDid, { count: 1, resetAt: now + 60_000 });
  } else if (++b.count > PER_INSTALL_MAX_PER_MIN) {
    return true;
  }
  if (perInstall.size > 5_000) {
    for (const [k, v] of perInstall) if (now >= v.resetAt) perInstall.delete(k);
  }
  return false;
}

/** The runtime writes hex; base64url is accepted too. 64 raw bytes either way. */
function signatureBytes(sig: string): Uint8Array | null {
  if (/^[0-9a-fA-F]{128}$/.test(sig)) return Uint8Array.from(sig.match(/../g)!.map((h) => parseInt(h, 16)));
  const b = b64urlToBytes(sig);
  return b && b.length === 64 ? b : null;
}

function unconfigured(c: Context<HonoEnv>) {
  return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);
}

// ─── /.well-known/aroha-registry-keys.json ────────────────────────────────────

export const registryKeysRoutes = new Hono<HonoEnv>();

registryKeysRoutes.get("/aroha-registry-keys.json", (c) => {
  const keys = publishedKeys(c.env);
  if (!keys) return unconfigured(c);
  // Short cache: long enough to spare the Worker, short enough that a
  // rotation reaches verifiers within minutes.
  c.header("Cache-Control", "public, max-age=300");
  return c.json({ keys });
});

// ─── /v1/audit-anchors ────────────────────────────────────────────────────────

export const auditAnchorRoutes = new Hono<HonoEnv>();

/**
 * Body: { installDid, seq, hash, signedAt, signature }
 *   200 { anchor, witnessSignature, witnessKeyId }
 *   400 malformed / installDid not did:aroha:z…
 *   403 signature does not verify under the install DID's key
 *   409 seq is not greater than the last anchored seq
 *   413 body over 4 KiB
 *   429 rate limited (per IP, per installDid)
 *   503 REGISTRY_SIGNING_KEY not configured
 */
auditAnchorRoutes.post("/", anchorIpLimiter, anchorBodyLimit, async (c) => {
  const key = currentSigningKey(c.env);
  if (!key) return unconfigured(c);

  const body = await c.req
    .json<{ installDid?: unknown; seq?: unknown; hash?: unknown; signedAt?: unknown; signature?: unknown }>()
    .catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const { installDid, seq, hash, signedAt, signature } = body;
  if (typeof installDid !== "string" || !installDid.startsWith("did:aroha:z") || installDid.length > 128) {
    return c.json({ error: "installDid must be a content-addressed did:aroha:z… DID" }, 400);
  }
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) {
    return c.json({ error: "seq must be a non-negative integer" }, 400);
  }
  if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
    return c.json({ error: "hash must be a lowercase hex SHA-256" }, 400);
  }
  if (typeof signedAt !== "string" || signedAt.length > 64 || Number.isNaN(Date.parse(signedAt))) {
    return c.json({ error: "signedAt must be an ISO 8601 date" }, 400);
  }
  if (Date.parse(signedAt) > Date.now() + MAX_SIGNED_AT_FUTURE_SKEW_MS) {
    return c.json({ error: "signedAt is in the future" }, 400);
  }
  if (typeof signature !== "string") return c.json({ error: "signature (hex or base64url) is required" }, 400);

  if (installRateLimited(installDid)) {
    return c.json({ error: "Too many anchors for this install — try again later" }, 429, { "Retry-After": "60" });
  }

  const publicKey = await resolveContentAddressedKey(installDid);
  if (!publicKey) return c.json({ error: "installDid does not encode an Ed25519 key" }, 400);
  const sig = signatureBytes(signature);
  let ok = false;
  try {
    ok = sig !== null && (await ed.verifyAsync(sig, headPayload({ seq, hash, signedAt }), publicKey));
  } catch {
    ok = false;
  }
  if (!ok) return c.json({ error: "signature does not verify under the install DID's key" }, 403);

  const db = c.env.DB;
  const last = await db
    .prepare(
      `SELECT install_did, seq, hash, signed_at, anchored_at, log_index, prev_anchor_hash, witness_signature, witness_key_id
       FROM audit_anchors WHERE install_did = ? ORDER BY log_index DESC LIMIT 1`,
    )
    .bind(installDid)
    .first<AnchorRow>();
  if (last && seq <= last.seq) {
    return c.json({ error: "seq must be greater than the last anchored seq", lastSeq: last.seq }, 409);
  }

  const anchor: AuditAnchor = {
    purpose: AUDIT_ANCHOR_PURPOSE,
    installDid,
    seq,
    hash,
    signedAt,
    anchoredAt: new Date().toISOString(),
    logIndex: last ? last.log_index + 1 : 0,
    prevAnchorHash: last ? jcsSha256Hex(anchorFromRow(last)) : "",
  };
  const witnessSignature = signJcs(anchor, key);

  // Conditional insert: only if nothing at or beyond this seq / log position
  // has appeared since the read above. A racing append loses here (or on the
  // unique (install_did, log_index) index) and is answered 409, never a fork.
  let changes = 0;
  try {
    const res = await db
      .prepare(
        `INSERT INTO audit_anchors
           (install_did, seq, hash, signed_at, anchored_at, log_index, prev_anchor_hash,
            witness_signature, witness_key_id, install_signature)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE NOT EXISTS (
           SELECT 1 FROM audit_anchors WHERE install_did = ? AND (seq >= ? OR log_index >= ?)
         )`,
      )
      .bind(
        installDid, seq, hash, signedAt, anchor.anchoredAt, anchor.logIndex, anchor.prevAnchorHash,
        witnessSignature, key.keyId, signature,
        installDid, seq, anchor.logIndex,
      )
      .run();
    changes = res.meta.changes ?? 0;
  } catch (err) {
    if (!/UNIQUE constraint failed|SQLITE_CONSTRAINT/i.test(String(err))) throw err;
  }
  if (changes === 0) {
    return c.json({ error: "a concurrent anchor for this install was recorded first — retry with a newer seq" }, 409);
  }

  return c.json({ anchor, witnessSignature, witnessKeyId: key.keyId });
});

/** { anchors: [{ anchor, witnessSignature, witnessKeyId }] } ascending by seq — public. */
auditAnchorRoutes.get("/:installDid", async (c) => {
  const installDid = decodeURIComponent(c.req.param("installDid") ?? "");
  if (!installDid.startsWith("did:aroha:z") || installDid.length > 128) {
    return c.json({ error: "installDid must be a content-addressed did:aroha:z… DID" }, 400);
  }
  const afterRaw = c.req.query("after");
  let after = -1;
  if (afterRaw !== undefined) {
    const n = Number(afterRaw);
    if (!Number.isSafeInteger(n)) return c.json({ error: "after must be an integer seq" }, 400);
    after = n;
  }
  const limitRaw = Number(c.req.query("limit") ?? 100);
  const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, Number.isFinite(limitRaw) ? Math.trunc(limitRaw) : MAX_LIST_LIMIT));

  const { results } = await c.env.DB
    .prepare(
      `SELECT install_did, seq, hash, signed_at, anchored_at, log_index, prev_anchor_hash, witness_signature, witness_key_id
       FROM audit_anchors WHERE install_did = ? AND seq > ? ORDER BY seq ASC LIMIT ?`,
    )
    .bind(installDid, after, limit)
    .all<AnchorRow>();
  // A verifier comparing its log against this record must see the newest
  // anchor, not a cached page from before it.
  c.header("Cache-Control", "no-store");
  return c.json({
    anchors: (results ?? []).map((r) => ({
      anchor: anchorFromRow(r),
      witnessSignature: r.witness_signature,
      witnessKeyId: r.witness_key_id,
    })),
  });
});
