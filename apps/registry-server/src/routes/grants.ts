// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/grants — explicit access grants for private agents, MCP servers, and skills.
 *
 * A grant is "the owner of <resource> permits <grantee> access". Two grantee
 * forms, serving different layers:
 *
 *   granteeDid      — an agent DID. Checked at CALL time by the agent itself
 *                     (see `allowedCallers` in @aroha-sdk/run) and usable for
 *                     DID-scoped checks.
 *   granteeKeyHash  — derived server-side from `granteeApiKey`. Used at
 *                     DISCOVERY time, because registry callers authenticate
 *                     with an API key rather than a DID.
 *
 * Every route is owner-scoped: the caller's API key must be the one that
 * registered the resource.
 *
 *   POST   /v1/grants              create (or replace) a grant
 *   GET    /v1/grants?resource=…   list live grants on a resource
 *   DELETE /v1/grants/:id          revoke (soft delete — audit trail survives)
 *   GET    /v1/grants/check        does a grant exist? (for agent-side checks)
 */

import { Hono } from "hono";
import { authMiddleware, adminMiddleware, sha256hex } from "../auth.js";
import type { HonoEnv } from "../index.js";
import type { ResourceType } from "../repository.js";
import { viewerDependent } from "../visibility.js";
import { hashDID } from "./agents.js";

export const grantRoutes = new Hono<HonoEnv>();

const MAX_GRANT_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1 year

function asResourceType(v: unknown): ResourceType | null {
  return v === "agent" || v === "mcp" || v === "skill" ? v : null;
}

/**
 * Resolve `expiresAt` / `ttlMs` to an absolute expiry, capped at
 * MAX_GRANT_TTL_MS from now. The cap used to apply to ttlMs only, so an
 * absolute expiresAt (or a non-finite one) could create a grant that never
 * lapses in practice — the one-year ceiling has to hold whichever form the
 * caller used.
 */
function grantExpiry(body: { expiresAt?: unknown; ttlMs?: unknown }): { expiresAt: number | null } | { error: string } {
  const now = Date.now();
  let expiresAt: number | null = null;
  if (body.expiresAt !== undefined && body.expiresAt !== null) {
    if (typeof body.expiresAt !== "number" || !Number.isFinite(body.expiresAt)) return { error: "expiresAt must be a Unix ms number" };
    expiresAt = body.expiresAt;
  } else if (body.ttlMs !== undefined && body.ttlMs !== null) {
    if (typeof body.ttlMs !== "number" || !Number.isFinite(body.ttlMs)) return { error: "ttlMs must be a number" };
    expiresAt = now + body.ttlMs;
  }
  if (expiresAt !== null && expiresAt <= now) return { error: "expiry must be in the future" };
  if (expiresAt !== null) expiresAt = Math.min(expiresAt, now + MAX_GRANT_TTL_MS);
  return { expiresAt };
}

/** POST /v1/grants — grant access to a private resource. */
grantRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{
    resourceDidHash?: string;
    resourceType?: string;
    /** Agent DID to grant to (call-time scoping). */
    granteeDid?: string;
    /** Raw API key of the grantee org (discovery scoping) — hashed, never stored raw. */
    granteeApiKey?: string;
    /** Pre-hashed grantee key, if the caller already has the hash. */
    granteeKeyHash?: string;
    capabilities?: string[];
    note?: string;
    /** Relative TTL in ms. Mutually exclusive with expiresAt. */
    ttlMs?: number;
    /** Absolute expiry, Unix ms. */
    expiresAt?: number;
  }>().catch(() => ({}) as Record<string, never>);

  const resourceType = asResourceType(body.resourceType);
  if (!body.resourceDidHash || !resourceType) {
    return c.json({ error: "resourceDidHash and resourceType (agent|mcp|skill) are required" }, 422);
  }

  const granteeKeyHash = body.granteeApiKey
    ? await sha256hex(body.granteeApiKey.trim())
    : (body.granteeKeyHash ?? null);

  if (!body.granteeDid && !granteeKeyHash) {
    return c.json({ error: "Provide granteeDid and/or granteeApiKey (or granteeKeyHash)" }, 422);
  }

  const expiry = grantExpiry(body);
  if ("error" in expiry) return c.json({ error: expiry.error }, 422);
  const expiresAt = expiry.expiresAt;

  const grant = await c.get("repo").createGrant(
    {
      resourceDidHash: body.resourceDidHash,
      resourceType,
      granteeDid: body.granteeDid ?? null,
      granteeKeyHash,
      capabilities: body.capabilities ?? null,
      note: body.note ?? null,
      expiresAt,
    },
    c.get("keyHash"),
  );

  // Same response for "doesn't exist" and "not yours" — never confirm the
  // existence of a resource the caller doesn't own.
  if (!grant) return c.json({ error: "Not found, or not yours to share" }, 403);

  void c.get("repo").recordEvent("grant.created", body.resourceDidHash).catch(() => {});
  // grantedByKeyHash and granteeKeyHash are secrets-adjacent — never echoed back.
  return c.json({
    id: grant.id,
    resourceDidHash: grant.resourceDidHash,
    resourceType: grant.resourceType,
    granteeDid: grant.granteeDid,
    granteeScoped: !!grant.granteeKeyHash,
    capabilities: grant.capabilities,
    note: grant.note,
    expiresAt: grant.expiresAt,
    createdAt: grant.createdAt,
  }, 201);
});

/** GET /v1/grants?resource=<didHash> — list live grants the caller has issued. */
grantRoutes.get("/", authMiddleware, async (c) => {
  const resource = c.req.query("resource");
  if (!resource) return c.json({ error: "resource query parameter is required" }, 422);

  const grants = await c.get("repo").listGrants(resource, c.get("keyHash"));
  viewerDependent(c);
  return c.json(
    grants.map((g) => ({
      id: g.id,
      resourceDidHash: g.resourceDidHash,
      resourceType: g.resourceType,
      granteeDid: g.granteeDid,
      granteeScoped: !!g.granteeKeyHash,
      capabilities: g.capabilities,
      note: g.note,
      expiresAt: g.expiresAt,
      createdAt: g.createdAt,
    })),
  );
});

/** DELETE /v1/grants/:id — revoke a grant. */
grantRoutes.delete("/:id", authMiddleware, async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id) || id <= 0) return c.json({ error: "Invalid grant id" }, 422);

  const ok = await c.get("repo").revokeGrant(id, c.get("keyHash"));
  if (!ok) return c.json({ error: "Not found, or not yours to revoke" }, 403);

  void c.get("repo").recordEvent("grant.revoked", null).catch(() => {});
  return c.json({ ok: true, id });
});

/**
 * GET /v1/grants/check?resource=<didHash>&did=<granteeDid>
 * Does a live grant exist? Used by agents enforcing their own allow-lists.
 * Returns only a boolean.
 *
 * Answered only for a party to the grant: the key that owns the resource,
 * or the key that owns the grantee agent `did`. It used to be anonymous,
 * which made it an oracle for who has access to whose private agents —
 * anyone could enumerate (resource, did) pairs. Anyone else gets the same
 * 404 a hidden private agent gets.
 */
grantRoutes.get("/check", authMiddleware, async (c) => {
  const resource = c.req.query("resource");
  const did = c.req.query("did");
  if (!resource || !did) return c.json({ error: "resource and did are required" }, 422);
  const repo = c.get("repo");
  const caller = c.get("keyHash");
  const ownsResource =
    (await repo.ownsResource(resource, "agent", caller)) ||
    (await repo.ownsResource(resource, "mcp", caller)) ||
    (await repo.ownsResource(resource, "skill", caller));
  const grantee = ownsResource ? null : await repo.getAgentAny(hashDID(did));
  if (!ownsResource && !(grantee && grantee.did === did && grantee.ownerKeyHash === caller)) {
    return c.json({ error: "Not found" }, 404);
  }
  const granted = await repo.hasGrant(resource, { did });
  viewerDependent(c);
  return c.json({ granted });
});

// ─── Admin-delegated (Studio) ────────────────────────────────────────────────
//
// Studio registers resources with a short-lived org key it doesn't retain, so
// the web app proves ownership by org name using the admin secret instead. These
// routes resolve that proof back to the real owner key and then run exactly the
// same owner-scoped logic — no parallel permission path.

/** POST /v1/grants/admin — create a grant on behalf of a Studio-owned resource. */
grantRoutes.post("/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{
    orgName?: string; resourceDidHash?: string; resourceType?: string;
    granteeDid?: string; granteeApiKey?: string; granteeKeyHash?: string;
    capabilities?: string[]; note?: string; ttlMs?: number; expiresAt?: number;
  }>().catch(() => ({}) as Record<string, never>);

  const resourceType = asResourceType(body.resourceType);
  if (!body.orgName || !body.resourceDidHash || !resourceType) {
    return c.json({ error: "orgName, resourceDidHash, and resourceType are required" }, 422);
  }

  const repo = c.get("repo");
  const ownerKeyHash = await repo.getOwnerKeyHashForOrg(body.resourceDidHash, resourceType, body.orgName);
  if (!ownerKeyHash) return c.json({ error: "Not found or not owned by this orgName" }, 404);

  const granteeKeyHash = body.granteeApiKey
    ? await sha256hex(body.granteeApiKey.trim())
    : (body.granteeKeyHash ?? null);
  if (!body.granteeDid && !granteeKeyHash) {
    return c.json({ error: "Provide granteeDid and/or granteeApiKey" }, 422);
  }

  const expiry = grantExpiry(body);
  if ("error" in expiry) return c.json({ error: expiry.error }, 422);
  const expiresAt = expiry.expiresAt;

  const grant = await repo.createGrant(
    {
      resourceDidHash: body.resourceDidHash, resourceType,
      granteeDid: body.granteeDid ?? null, granteeKeyHash,
      capabilities: body.capabilities ?? null, note: body.note ?? null, expiresAt,
    },
    ownerKeyHash,
  );
  if (!grant) return c.json({ error: "Not found" }, 404);

  return c.json({
    id: grant.id, resourceDidHash: grant.resourceDidHash, resourceType: grant.resourceType,
    granteeDid: grant.granteeDid, granteeScoped: !!grant.granteeKeyHash,
    capabilities: grant.capabilities, note: grant.note,
    expiresAt: grant.expiresAt, createdAt: grant.createdAt,
  }, 201);
});

/** GET /v1/grants/admin?resource=…&orgName=… — list grants for a Studio resource. */
grantRoutes.get("/admin", adminMiddleware, async (c) => {
  const resource = c.req.query("resource");
  const orgName = c.req.query("orgName");
  const resourceType = asResourceType(c.req.query("resourceType") ?? "agent");
  if (!resource || !orgName || !resourceType) {
    return c.json({ error: "resource, orgName, and resourceType are required" }, 422);
  }

  const repo = c.get("repo");
  const ownerKeyHash = await repo.getOwnerKeyHashForOrg(resource, resourceType, orgName);
  if (!ownerKeyHash) return c.json({ error: "Not found or not owned by this orgName" }, 404);

  const grants = await repo.listGrants(resource, ownerKeyHash);
  return c.json(grants.map((g) => ({
    id: g.id, resourceDidHash: g.resourceDidHash, resourceType: g.resourceType,
    granteeDid: g.granteeDid, granteeScoped: !!g.granteeKeyHash,
    capabilities: g.capabilities, note: g.note,
    expiresAt: g.expiresAt, createdAt: g.createdAt,
  })));
});

/** DELETE /v1/grants/:id/admin — revoke a grant on a Studio-owned resource. */
grantRoutes.delete("/:id/admin", adminMiddleware, async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json<{ orgName?: string; resourceDidHash?: string; resourceType?: string }>()
    .catch(() => ({}) as Record<string, never>);
  const resourceType = asResourceType(body.resourceType ?? "agent");
  if (!Number.isInteger(id) || id <= 0) return c.json({ error: "Invalid grant id" }, 422);
  if (!body.orgName || !body.resourceDidHash || !resourceType) {
    return c.json({ error: "orgName, resourceDidHash, and resourceType are required" }, 422);
  }

  const repo = c.get("repo");
  const ownerKeyHash = await repo.getOwnerKeyHashForOrg(body.resourceDidHash, resourceType, body.orgName);
  if (!ownerKeyHash) return c.json({ error: "Not found or not owned by this orgName" }, 404);

  const ok = await repo.revokeGrant(id, ownerKeyHash);
  if (!ok) return c.json({ error: "Grant not found" }, 404);
  return c.json({ ok: true, id });
});

/** PATCH /v1/grants/visibility/admin — set visibility on a Studio-owned resource. */
grantRoutes.patch("/visibility/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{
    orgName?: string; resourceDidHash?: string; resourceType?: string; visibility?: string;
  }>().catch(() => ({}) as Record<string, never>);

  const resourceType = asResourceType(body.resourceType ?? "agent");
  const v = body.visibility;
  if (!body.orgName || !body.resourceDidHash || !resourceType) {
    return c.json({ error: "orgName, resourceDidHash, and resourceType are required" }, 422);
  }
  if (v !== "public" && v !== "unlisted" && v !== "private") {
    return c.json({ error: "visibility must be one of: public, unlisted, private" }, 422);
  }

  const repo = c.get("repo");
  const ownerKeyHash = await repo.getOwnerKeyHashForOrg(body.resourceDidHash, resourceType, body.orgName);
  if (!ownerKeyHash) return c.json({ error: "Not found or not owned by this orgName" }, 404);

  const ok = await repo.setVisibility(body.resourceDidHash, resourceType, v, ownerKeyHash);
  if (!ok) return c.json({ error: "Not found" }, 404);
  return c.json({ didHash: body.resourceDidHash, visibility: v });
});
