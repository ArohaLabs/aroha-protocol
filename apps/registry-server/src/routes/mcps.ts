// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { Hono } from "hono";
import { keccak_256 } from "@noble/hashes/sha3";
import { authMiddleware, adminMiddleware, optionalAuthMiddleware } from "../auth.js";
import type { McpRow } from "../repository.js";
import type { HonoEnv } from "../index.js";
import { parsePagination } from "../pagination.js";

export const mcpRoutes = new Hono<HonoEnv>();

function hashDID(did: string): string {
  const bytes = new TextEncoder().encode(did);
  const hash = keccak_256(bytes);
  return "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * @param viewer The caller's key hash, when they gave one.
 *
 * `visibility` and `mine` are here so a client can say WHY it can see a row.
 * Without them a listing made with a key and one made without are the same
 * shape, and an app showing both cannot tell a public server from one a
 * partner shared privately with this firm — which is the whole difference
 * between a marketplace and a supplier.
 *
 * `mine` rather than the owner's key hash: the question a reader has is
 * "is this ours?", and a hash answers it only by being compared to another
 * hash they would also have to be given.
 */
function toApiRecord(row: McpRow, viewer?: string | null) {
  return {
    did:          row.did,
    visibility:   row.visibility ?? "public",
    mine:         Boolean(viewer && row.ownerKeyHash === viewer),
    didHash:      row.didHash,
    publishedBy:  row.orgName || null,
    name:         row.name,
    description:  row.description,
    endpointUrl:  row.endpointUrl,
    toolIds:      row.toolIds,
    manifestCID:  row.manifestCID,
    active:       row.active,
    registeredAt:   row.registeredAt,
    lastUpdatedAt:  row.lastUpdatedAt,
  };
}

/** POST /v1/mcps — register a new MCP server */
mcpRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{
    did?: string;
    name?: string;
    description?: string;
    endpointUrl?: string;
    toolIds?: string[];
    manifestCid?: string;
  }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Request body must be a JSON object" }, 400);

  if (!body.did || !body.name || !body.endpointUrl) {
    return c.json({ error: "did, name, and endpointUrl are required" }, 400);
  }

  try {
    const u = new URL(body.endpointUrl);
    if (!["http:", "https:"].includes(u.protocol)) throw new Error();
  } catch {
    return c.json({ error: "endpointUrl must be an http(s) URL" }, 400);
  }

  const didHash = hashDID(body.did);
  const repo = c.get("repo");
  const existing = await repo.getMcp(didHash);
  if (existing) return c.json({ error: "DID already registered" }, 409);

  const now = Date.now();
  await repo.insertMcp({
    didHash,
    did:          body.did,
    ownerKeyHash: c.get("keyHash"),
    orgName:      c.get("orgName"),
    name:         body.name,
    description:  body.description ?? "",
    endpointUrl:  body.endpointUrl,
    toolIds:      body.toolIds ?? [],
    manifestCID:  body.manifestCid ?? "",
    active:       true,
    registeredAt:  now,
    lastUpdatedAt: now,
  } as McpRow);

  return c.json({ didHash }, 201);
});

/** GET /v1/mcps — list all active MCP servers */
mcpRoutes.get("/", optionalAuthMiddleware, async (c) => {
  const { limit, offset } = parsePagination(c);
  const viewer = c.get("keyHash") ?? null;
  const rows = (await c.get("repo").listMcps(limit, offset, viewer))
    .filter((r) => r.visibility !== "unlisted" || r.ownerKeyHash === viewer);
  return c.json(rows.map((r) => toApiRecord(r, viewer)));
});

/** GET /v1/mcps/:didHash — resolve a single MCP (private → owner/grantee only) */
mcpRoutes.get("/:didHash", optionalAuthMiddleware, async (c) => {
  const param   = decodeURIComponent(c.req.param("didHash")!);
  const didHash = param.startsWith("0x") ? param : hashDID(param);
  const repo = c.get("repo");
  const row = await repo.getMcp(didHash);
  if (!row) return c.json({ error: "Not found" }, 404);

  const viewer = c.get("keyHash") ?? null;
  if (row.visibility === "private") {
    const allowed =
      (!!viewer && row.ownerKeyHash === viewer) ||
      (!!viewer && (await repo.hasGrant(didHash, { keyHash: viewer })));
    if (!allowed) return c.json({ error: "Not found" }, 404);
  }
  return c.json(toApiRecord(row, viewer));
});

/** PATCH /v1/mcps/:didHash/visibility — public | unlisted | private (owner only) */
mcpRoutes.patch("/:didHash/visibility", authMiddleware, async (c) => {
  const didHash = decodeURIComponent(c.req.param("didHash")!);
  const body = await c.req.json<{ visibility?: string }>().catch(() => ({}) as { visibility?: string });
  const v = body.visibility;
  if (v !== "public" && v !== "unlisted" && v !== "private") {
    return c.json({ error: "visibility must be one of: public, unlisted, private" }, 422);
  }
  const ok = await c.get("repo").setVisibility(didHash, "mcp", v, c.get("keyHash"));
  if (!ok) return c.json({ error: "Not found, or not yours" }, 403);
  return c.json({ didHash, visibility: v });
});

/** DELETE /v1/mcps/:didHash/admin — admin-delegated deactivation */
mcpRoutes.delete("/:didHash/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{ orgName?: string }>().catch(() => ({} as { orgName?: string }));
  if (!body.orgName) return c.json({ error: "orgName required" }, 400);
  const ok = await c.get("repo").deactivateMcpByOrgName(c.req.param("didHash")!, body.orgName);
  if (!ok) return c.json({ error: "Not found or not owned by this orgName" }, 404);
  return c.json({ ok: true });
});
