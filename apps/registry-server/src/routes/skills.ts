// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { Hono } from "hono";
import { keccak_256 } from "@noble/hashes/sha3";
import { authMiddleware, adminMiddleware, optionalAuthMiddleware } from "../auth.js";
import type { SkillRow } from "../repository.js";
import type { HonoEnv } from "../index.js";
import { parsePagination } from "../pagination.js";

export const skillRoutes = new Hono<HonoEnv>();

export const SKILL_TYPES = ["rag", "web-search", "memory", "code", "data", "custom"] as const;

function hashDID(did: string): string {
  const bytes = new TextEncoder().encode(did);
  const hash = keccak_256(bytes);
  return "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function toApiRecord(row: SkillRow) {
  return {
    did:          row.did,
    didHash:      row.didHash,
    publishedBy:  row.orgName || null,
    name:         row.name,
    description:  row.description,
    skillType:    row.skillType,
    endpointUrl:  row.endpointUrl || null,
    manifestCID:  row.manifestCID,
    active:       row.active,
    registeredAt:  row.registeredAt,
    lastUpdatedAt: row.lastUpdatedAt,
  };
}

/** POST /v1/skills — register a new skill */
skillRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{
    did?: string;
    name?: string;
    description?: string;
    skillType?: string;
    endpointUrl?: string;
    manifestCid?: string;
  }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Request body must be a JSON object" }, 400);

  if (!body.did || !body.name) {
    return c.json({ error: "did and name are required" }, 400);
  }

  const skillType = body.skillType ?? "custom";
  if (!SKILL_TYPES.includes(skillType as typeof SKILL_TYPES[number])) {
    return c.json({ error: `skillType must be one of: ${SKILL_TYPES.join(", ")}` }, 400);
  }

  if (body.endpointUrl) {
    try {
      const u = new URL(body.endpointUrl);
      if (!["http:", "https:"].includes(u.protocol)) throw new Error();
    } catch {
      return c.json({ error: "endpointUrl must be an http(s) URL" }, 400);
    }
  }

  const didHash = hashDID(body.did);
  const repo = c.get("repo");
  const existing = await repo.getSkill(didHash);
  if (existing) return c.json({ error: "DID already registered" }, 409);

  const now = Date.now();
  await repo.insertSkill({
    didHash,
    did:          body.did,
    ownerKeyHash: c.get("keyHash"),
    orgName:      c.get("orgName"),
    name:         body.name,
    description:  body.description ?? "",
    skillType,
    endpointUrl:  body.endpointUrl ?? "",
    manifestCID:  body.manifestCid ?? "",
    active:       true,
    registeredAt:  now,
    lastUpdatedAt: now,
  } as SkillRow);

  return c.json({ didHash }, 201);
});

/** GET /v1/skills — list all active skills, optionally filtered by type */
skillRoutes.get("/", optionalAuthMiddleware, async (c) => {
  const { limit, offset } = parsePagination(c);
  const skillType = c.req.query("type");
  const viewer    = c.get("keyHash") ?? null;
  const rows = (await c.get("repo").listSkills(limit, offset, skillType, viewer))
    .filter((r) => r.visibility !== "unlisted" || r.ownerKeyHash === viewer);
  return c.json(rows.map(toApiRecord));
});

/** GET /v1/skills/:didHash — resolve a single skill (private → owner/grantee only) */
skillRoutes.get("/:didHash", optionalAuthMiddleware, async (c) => {
  const param   = decodeURIComponent(c.req.param("didHash")!);
  const didHash = param.startsWith("0x") ? param : hashDID(param);
  const repo = c.get("repo");
  const row = await repo.getSkill(didHash);
  if (!row) return c.json({ error: "Not found" }, 404);

  if (row.visibility === "private") {
    const viewer = c.get("keyHash") ?? null;
    const allowed =
      (!!viewer && row.ownerKeyHash === viewer) ||
      (!!viewer && (await repo.hasGrant(didHash, { keyHash: viewer })));
    if (!allowed) return c.json({ error: "Not found" }, 404);
  }
  return c.json(toApiRecord(row));
});

/** PATCH /v1/skills/:didHash/visibility — public | unlisted | private (owner only) */
skillRoutes.patch("/:didHash/visibility", authMiddleware, async (c) => {
  const didHash = decodeURIComponent(c.req.param("didHash")!);
  const body = await c.req.json<{ visibility?: string }>().catch(() => ({}) as { visibility?: string });
  const v = body.visibility;
  if (v !== "public" && v !== "unlisted" && v !== "private") {
    return c.json({ error: "visibility must be one of: public, unlisted, private" }, 422);
  }
  const ok = await c.get("repo").setVisibility(didHash, "skill", v, c.get("keyHash"));
  if (!ok) return c.json({ error: "Not found, or not yours" }, 403);
  return c.json({ didHash, visibility: v });
});

/** DELETE /v1/skills/:didHash/admin — admin-delegated deactivation */
skillRoutes.delete("/:didHash/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{ orgName?: string }>().catch(() => ({} as { orgName?: string }));
  if (!body.orgName) return c.json({ error: "orgName required" }, 400);
  const ok = await c.get("repo").deactivateSkillByOrgName(c.req.param("didHash")!, body.orgName);
  if (!ok) return c.json({ error: "Not found or not owned by this orgName" }, 404);
  return c.json({ ok: true });
});
