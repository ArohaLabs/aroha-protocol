// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Per-agent identity documents for other ecosystems, and "know your agent"
 * facts. Mounted beside routes/agents.ts under /v1/agents.
 *
 *   GET  /v1/agents/:didHash/client-metadata.json   OAuth Client ID Metadata Document   — public
 *   GET  /v1/agents/:didHash/jwks.json              the agent's current key as a JWK Set — public
 *   GET  /v1/agents/:didHash/monitoring             signed monitoring summary + tier    — visibility rule
 *   POST /v1/agents/:didHash/audited                record / clear an independent audit — admin secret
 *
 * CLIENT ID METADATA DOCUMENT (draft-ietf-oauth-client-id-metadata-document-02).
 * MCP 2026-07-28 deprecates Dynamic Client Registration in favour of CIMD:
 * the client_id IS an https URL, and the authorization server fetches the
 * client's metadata from it. The URL of this route is that client_id, so any
 * CIMD-capable authorization server can identify an Aroha agent without a
 * bilateral registration. Per the draft:
 *   - client_id equals the URL the document was fetched from (origin + path,
 *     the request's own URL — so it matches by simple string comparison);
 *   - token_endpoint_auth_method is private_key_jwt — never a shared-secret
 *     method, and no client_secret is ever present;
 *   - only public keys, through jwks_uri — this registry's /jwks.json for the
 *     agent, which follows key rotation: an E-DID's key is read from its
 *     verified Key Event Log (refused once revoked, controller-revoked or
 *     forked), any other DID's as mandate verification resolves it;
 *   - errors are not cached (no-store); documents are cached 5 minutes, so a
 *     rotation reaches authorization servers within that window.
 * redirect_uris: `<endpointUrl>/oauth/callback` when the agent registered an
 * https endpoint — an Aroha convention (ASSUMPTION: no agent manifest field
 * declares redirect URIs yet); without one the document offers only the
 * client_credentials grant.
 *
 * MONITORING SUMMARY. Counts of facts the registry itself recorded, signed
 * with REGISTRY_SIGNING_KEY over JCS of the summary (purpose
 * "aroha.agent-monitoring/v1"). It is not a reputation claim or a safety
 * rating; it says what the registry has seen, nothing about how the agent
 * behaves.
 */

import { Hono, type Context } from "hono";
import { sha256 } from "@noble/hashes/sha256";
import { adminMiddleware, optionalAuthMiddleware } from "../auth.js";
import { discoveryIpLimiter } from "../middleware/rate-limit.js";
import type { HonoEnv } from "../index.js";
import type { AgentRow } from "../repository.js";
import { hashDID } from "./agents.js";
import { canViewAgent } from "../visibility.js";
import {
  REGISTRY_SIGNING_UNCONFIGURED_MESSAGE,
  bytesToB64url,
  currentSigningKey,
  signJcs,
} from "../registry-signing.js";
import { computeAgentFacts, currentAgentKey, tierFromFacts } from "../agent-tier.js";

export const AGENT_MONITORING_PURPOSE = "aroha.agent-monitoring/v1";

export const agentIdentityRoutes = new Hono<HonoEnv>();

function didHashParam(c: Context<HonoEnv>): string {
  const raw = decodeURIComponent(c.req.param("didHash") ?? "");
  return raw.startsWith("0x") ? raw : hashDID(raw);
}

function noStore404(c: Context<HonoEnv>) {
  c.header("Cache-Control", "no-store");
  return c.json({ error: "Not found" }, 404);
}

/** RFC 7638 thumbprint of an Ed25519 OKP key — a stable kid that changes with the key. */
export function okpThumbprint(x: string): string {
  return bytesToB64url(sha256(new TextEncoder().encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`)));
}

/** An active agent anyone may see (CIMD and JWKS are fetched without credentials). */
async function publicAgent(c: Context<HonoEnv>): Promise<AgentRow | null> {
  const repo = c.get("repo");
  const row = await repo.getAgent(didHashParam(c));
  if (!row || !(await canViewAgent(repo, row, null))) return null;
  return row;
}

async function agentJwk(c: Context<HonoEnv>, row: AgentRow) {
  const key = await currentAgentKey(c.get("repo"), row);
  if (!key || key.length !== 32) return null;
  const x = bytesToB64url(key);
  return { kty: "OKP", crv: "Ed25519", x, kid: okpThumbprint(x), use: "sig", alg: "EdDSA" };
}

function httpsRedirectUri(endpointUrl: string | undefined | null): string | null {
  if (!endpointUrl) return null;
  try {
    const u = new URL(endpointUrl);
    if (u.protocol !== "https:" || u.username || u.password || u.hash) return null;
    return `${u.origin}${u.pathname.replace(/\/+$/, "")}/oauth/callback`;
  } catch {
    return null;
  }
}

// ─── GET /v1/agents/:didHash/client-metadata.json ─────────────────────────────

agentIdentityRoutes.get("/:didHash/client-metadata.json", discoveryIpLimiter, async (c) => {
  const row = await publicAgent(c);
  if (!row) return noStore404(c);
  // Without a key the registry vouches for, there is nothing for an
  // authorization server to verify a client assertion against: not found,
  // rather than a document that cannot work.
  if (!(await agentJwk(c, row))) return noStore404(c);

  const url = new URL(c.req.url);
  const clientId = `${url.origin}${url.pathname}`;
  const redirect = httpsRedirectUri(row.endpointUrl);
  const facts = await computeAgentFacts(c.env.DB, c.get("repo"), row);
  c.header("Cache-Control", "public, max-age=300");
  return c.json({
    client_id: clientId,
    client_name: row.orgName ? `${row.orgName} (Aroha agent)` : row.did,
    jwks_uri: `${url.origin}/v1/agents/${row.didHash}/jwks.json`,
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "EdDSA",
    grant_types: redirect ? ["authorization_code", "client_credentials"] : ["client_credentials"],
    response_types: redirect ? ["code"] : [],
    ...(redirect ? { redirect_uris: [redirect] } : {}),
    software_id: row.did,
    // Aroha extensions (unregistered metadata; ignored by servers that do not know them).
    aroha_did: row.did,
    aroha_certification_tier: tierFromFacts(facts),
  });
});

// ─── GET /v1/agents/:didHash/jwks.json ────────────────────────────────────────

agentIdentityRoutes.get("/:didHash/jwks.json", discoveryIpLimiter, async (c) => {
  const row = await publicAgent(c);
  if (!row) return noStore404(c);
  const jwk = await agentJwk(c, row);
  if (!jwk) return noStore404(c);
  c.header("Cache-Control", "public, max-age=300");
  return c.json({ keys: [jwk] });
});

// ─── GET /v1/agents/:didHash/monitoring ───────────────────────────────────────

interface CountRow { n: number }

agentIdentityRoutes.get("/:didHash/monitoring", discoveryIpLimiter, optionalAuthMiddleware, async (c) => {
  const repo = c.get("repo");
  c.header("Cache-Control", "no-store");
  c.header("Vary", "Authorization");
  // Inactive (revoked, deactivated) agents are included: their history is
  // exactly what a counterparty checking them wants to see.
  const row = await repo.getAgentAny(didHashParam(c));
  if (!row || !(await canViewAgent(repo, row, c.get("keyHash") ?? null))) return c.json({ error: "Not found" }, 404);
  const key = currentSigningKey(c.env);
  if (!key) return c.json({ error: REGISTRY_SIGNING_UNCONFIGURED_MESSAGE }, 503);

  const db = c.env.DB;
  const one = <T>(sql: string, ...binds: unknown[]) => db.prepare(sql).bind(...binds).first<T>();
  const [granted, issued, rotated, kel, duplicity, linkConflicts, attest] = await Promise.all([
    one<CountRow>(`SELECT COUNT(*) AS n FROM mandate_revocations WHERE grantor = ?`, row.did),
    one<CountRow>(`SELECT COUNT(*) AS n FROM mandate_revocations WHERE revoked_by = ?`, row.did),
    one<CountRow>(`SELECT COUNT(*) AS n FROM revoked_keys WHERE did_hash = ?`, row.didHash),
    one<{ sequence: number; updated_at: number; events_json: string }>(
      `SELECT sequence, updated_at, events_json FROM kel_logs WHERE did = ?`, row.did),
    one<CountRow>(`SELECT COUNT(*) AS n FROM kel_duplicity WHERE did = ?`, row.did),
    one<CountRow>(`SELECT COUNT(*) AS n FROM identity_linkage_conflicts WHERE from_did = ?`, row.did),
    one<{ n: number; ok: number | null; last: number | null }>(
      `SELECT COUNT(*) AS n, SUM(CASE WHEN success THEN 1 ELSE 0 END) AS ok, MAX(submitted_at) AS last
       FROM caller_attestations WHERE agent_did_hash = ?`, row.didHash),
  ]);
  const facts = await computeAgentFacts(db, repo, row);
  let kelRevoked = false;
  try {
    kelRevoked = kel ? (JSON.parse(kel.events_json) as Array<{ type?: string }>).some((e) => e.type === "revoke") : false;
  } catch {
    kelRevoked = false;
  }
  const lastSeenMs = Math.max(row.lastUpdatedAt ?? 0, kel?.updated_at ?? 0, attest?.last ?? 0);

  const summary = {
    purpose: AGENT_MONITORING_PURPOSE,
    did: row.did,
    didHash: row.didHash,
    generatedAt: new Date().toISOString(),
    certificationTier: tierFromFacts(facts),
    facts,
    counts: {
      mandatesRevoked: granted?.n ?? 0,
      revocationsIssued: issued?.n ?? 0,
      rotatedKeys: rotated?.n ?? 0,
      kelEvents: kel ? kel.sequence + 1 : 0,
      kelRevoked,
      duplicityAlarms: duplicity?.n ?? 0,
      linkageConflicts: linkConflicts?.n ?? 0,
      attestations: attest?.n ?? 0,
      attestationsSuccessful: attest?.ok ?? 0,
    },
    // The latest write the registry recorded from or about this agent
    // (registration/manifest/key update, KEL submission, caller attestation).
    lastSeenAt: lastSeenMs > 0 ? new Date(lastSeenMs).toISOString() : null,
    notice: "Counts of registry-recorded facts. Not a reputation score, safety rating or endorsement.",
  };
  const { purpose: _purpose, ...unsigned } = summary;
  return c.json({ summary: unsigned, signature: signJcs(summary, key), keyId: key.keyId });
});

// ─── POST /v1/agents/:didHash/audited ─────────────────────────────────────────

/**
 * Body { audited: true, reference: string } records an independent audit
 * (reference: the report's URL or identifier, ≤ 512 chars);
 * { audited: false } clears it. Written to the admin audit log.
 */
agentIdentityRoutes.post("/:didHash/audited", adminMiddleware, async (c) => {
  const didHash = didHashParam(c);
  const body = await c.req.json<{ audited?: unknown; reference?: unknown }>().catch(() => null);
  if (!body || typeof body.audited !== "boolean") return c.json({ error: "audited (boolean) is required" }, 400);
  let reference: string | null = null;
  if (body.audited) {
    if (typeof body.reference !== "string" || body.reference.length === 0 || body.reference.length > 512) {
      return c.json({ error: "reference (the audit report's URL or identifier) is required" }, 400);
    }
    reference = body.reference;
  }
  const now = Date.now();
  const res = await c.env.DB
    .prepare(`UPDATE agent_records SET audited_at = ?, audit_reference = ? WHERE did_hash = ?`)
    .bind(body.audited ? now : null, reference, didHash)
    .run();
  if ((res.meta.changes ?? 0) === 0) return c.json({ error: "Not found" }, 404);
  const ip = c.req.header("CF-Connecting-IP") ?? undefined;
  void c.get("repo")
    .recordAuditAction(body.audited ? "agent.audited_set" : "agent.audited_cleared", "admin", didHash, ip)
    .catch(() => {});
  return c.json({ didHash, audited: body.audited, auditedAt: body.audited ? new Date(now).toISOString() : null, reference });
});
