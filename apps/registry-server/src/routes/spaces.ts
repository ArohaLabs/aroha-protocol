// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/spaces — a named place a firm shares work into, and the firms it shares with.
 *
 * `/v1/grants` already answers "may this grantee reach this resource", and
 * nothing here replaces it. What a grant cannot do is match how people work:
 * eight agents shared with five partner firms is forty grants to create and
 * forty to remember when somebody leaves. A space is the grouping over that.
 *
 * ADDING TO A SPACE WRITES ORDINARY GRANTS
 *
 * Every membership and every shared resource materialises rows in
 * `access_grants`, tagged `via_space_id`. So discovery filtering,
 * /v1/grants/check, and the agent-side allowedCallers check all keep working
 * unchanged and keep agreeing — there is still exactly one table that answers
 * whether a caller may reach a resource.
 *
 * The alternative, joining spaces in at query time, stores less and creates a
 * second path to the same answer. That is where access control goes wrong:
 * two checks that must agree, and the one on the call-time path forgotten.
 *
 *   POST   /v1/spaces                     create one
 *   GET    /v1/spaces                     the ones you own or belong to
 *   GET    /v1/spaces/:id                 detail, members and contents
 *   POST   /v1/spaces/:id/invites         mint a one-time code to send someone
 *   POST   /v1/spaces/join                redeem a code with your own key
 *   DELETE /v1/spaces/:id/members/:hash   remove a firm, revoking what it gave them
 *   POST   /v1/spaces/:id/resources       share an agent into it
 *   DELETE /v1/spaces/:id/resources/:hash stop sharing it
 *   DELETE /v1/spaces/:id                 archive
 */

import { Hono } from "hono";
import { authMiddleware, sha256hex } from "../auth.js";
import type { HonoEnv } from "../index.js";
import { viewerDependentMiddleware } from "../visibility.js";
import type { ResourceType } from "../repository.js";

export const spaceRoutes = new Hono<HonoEnv>();
// Every answer here is about the calling org's own spaces / budgets — never
// cacheable, and never the same for two Authorization headers.
spaceRoutes.use("*", viewerDependentMiddleware);

/** Long enough that guessing is hopeless, short enough to paste into a message. */
const INVITE_CODE_BYTES = 24;
const MAX_INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function asResourceType(v: unknown): ResourceType | null {
  return v === "agent" || v === "mcp" || v === "skill" ? v : null;
}

function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 20)}`;
}

/** A code a person will copy into a chat window, not a URL-safe token. */
function newInviteCode(): string {
  const bytes = new Uint8Array(INVITE_CODE_BYTES);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(36).padStart(2, "0")).join("").slice(0, 32);
}

/** POST /v1/spaces — create one. The caller's org owns it. */
spaceRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{ name?: string; description?: string }>()
    .catch(() => ({}) as Record<string, never>);
  const name = body.name?.trim();
  if (!name) return c.json({ error: "name is required" }, 422);

  const repo = c.get("repo");
  const space = await repo.createSpace({
    id: newId("spc"),
    name,
    description: body.description?.trim() ?? null,
    ownerKeyHash: c.get("keyHash"),
    ownerOrg: c.get("orgName"),
  });
  void repo.recordAuditAction("space.created", c.get("orgName"), space.id)
    .catch((err) => console.error("[audit] space.created not recorded:", err));
  return c.json({ space }, 201);
});

/** GET /v1/spaces — the ones this org owns, and the ones it was invited into. */
spaceRoutes.get("/", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const keyHash = c.get("keyHash");
  const [owned, joined] = await Promise.all([
    repo.listSpacesOwnedBy(keyHash),
    repo.listSpacesJoinedBy(keyHash),
  ]);
  // Reported separately, because they are not the same thing: one you can
  // invite into and share from, the other you can only read.
  return c.json({ owned, joined });
});

/** GET /v1/spaces/:id — detail. Owner sees members; a member sees contents. */
spaceRoutes.get("/:id", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const keyHash = c.get("keyHash");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);

  const isOwner = space.ownerKeyHash === keyHash;
  const isMember = isOwner || (await repo.isSpaceMember(id, keyHash));
  if (!isMember) {
    // 404 rather than 403: a space id somebody is not in should not be
    // confirmable by asking about it.
    return c.json({ error: "No such space" }, 404);
  }

  const resources = await repo.listSpaceResources(id);
  // Members are the owner's business. A partner firm can see what is shared
  // with it without learning who else is in the room.
  const members = isOwner ? await repo.listSpaceMembers(id) : undefined;
  return c.json({ space, resources, ...(members ? { members } : {}) });
});

/**
 * POST /v1/spaces/:id/invites — mint a one-time code.
 *
 * Membership is keyed by API key hash and one org cannot learn another's, so
 * an invitation cannot name its recipient. It names nobody: whoever redeems
 * the code with their own key becomes the member. The code is returned once
 * and only its hash is kept — a registry that can read back its own
 * invitation codes is one whose database leak grants space access.
 */
spaceRoutes.post("/:id/invites", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);
  if (space.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the space's owner may invite" }, 403);
  }

  const body = await c.req.json<{ note?: string; ttlMs?: number }>()
    .catch(() => ({}) as Record<string, never>);
  const ttl = Math.min(body.ttlMs ?? MAX_INVITE_TTL_MS, MAX_INVITE_TTL_MS);

  const code = newInviteCode();
  const invite = await repo.createSpaceInvite({
    id: newId("inv"),
    spaceId: id,
    codeHash: await sha256hex(code),
    createdBy: c.get("keyHash"),
    note: body.note?.trim() ?? null,
    expiresAt: Date.now() + ttl,
  });
  void repo.recordAuditAction("space.invite_created", c.get("orgName"), id)
    .catch((err) => console.error("[audit] space.invite_created not recorded:", err));

  // The only time this value exists anywhere outside the caller's screen.
  return c.json({ invite: { ...invite, code } }, 201);
});

/**
 * POST /v1/spaces/join — redeem a code.
 *
 * Deliberately not under /:id: whoever holds a code does not necessarily know
 * the space it belongs to, and requiring them to name it would mean sending
 * the id alongside the code for no gain.
 */
spaceRoutes.post("/join", authMiddleware, async (c) => {
  const body = await c.req.json<{ code?: string }>().catch(() => ({}) as Record<string, never>);
  const code = body.code?.trim();
  if (!code) return c.json({ error: "code is required" }, 422);

  const repo = c.get("repo");
  const invite = await repo.findSpaceInviteByCodeHash(await sha256hex(code));
  // One message for every failure — expired, revoked, already used, never
  // existed. Distinguishing them turns this into an oracle for guessing codes.
  const unusable = !invite
    || invite.revokedAt !== null
    || invite.redeemedAt !== null
    || (invite.expiresAt !== null && invite.expiresAt <= Date.now());
  if (unusable) return c.json({ error: "That invitation cannot be used" }, 404);

  const space = await repo.getSpace(invite!.spaceId);
  if (!space || space.archivedAt) return c.json({ error: "That invitation cannot be used" }, 404);

  const keyHash = c.get("keyHash");
  if (space.ownerKeyHash === keyHash) {
    return c.json({ error: "You already own this space" }, 409);
  }

  const joined = await repo.joinSpace({
    spaceId: space.id,
    inviteId: invite!.id,
    memberKeyHash: keyHash,
    memberOrg: c.get("orgName"),
    invitedBy: invite!.createdBy,
  });
  // Lost the race for a one-time code (another redeemer claimed it between
  // the read above and the conditional update) — same message as any other
  // unusable invitation.
  if (!joined) return c.json({ error: "That invitation cannot be used" }, 404);
  void repo.recordAuditAction("space.joined", c.get("orgName"), space.id)
    .catch((err) => console.error("[audit] space.joined not recorded:", err));
  return c.json({ space, grantsCreated: joined.grantsCreated });
});

/** POST /v1/spaces/:id/resources — share something into the space. */
spaceRoutes.post("/:id/resources", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);
  if (space.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the space's owner may share into it" }, 403);
  }

  const body = await c.req.json<{ resourceDidHash?: string; resourceType?: string }>()
    .catch(() => ({}) as Record<string, never>);
  const resourceType = asResourceType(body.resourceType);
  if (!body.resourceDidHash || !resourceType) {
    return c.json({ error: "resourceDidHash and resourceType (agent|mcp|skill) are required" }, 422);
  }

  // Ownership of the RESOURCE, not just the space. Sharing something you do
  // not own would let anybody grant access to anybody else's private agent by
  // adding it to a space they happen to run.
  const owns = await repo.ownsResource(body.resourceDidHash, resourceType, c.get("keyHash"));
  if (!owns) return c.json({ error: "You do not own that resource" }, 403);

  const added = await repo.addSpaceResource({
    spaceId: id,
    resourceDidHash: body.resourceDidHash,
    resourceType,
    addedBy: c.get("keyHash"),
  });
  void repo.recordAuditAction("space.resource_added", c.get("orgName"), id)
    .catch((err) => console.error("[audit] space.resource_added not recorded:", err));
  return c.json({ added: true, grantsCreated: added.grantsCreated }, 201);
});

/** DELETE /v1/spaces/:id/resources/:hash — stop sharing it. */
spaceRoutes.delete("/:id/resources/:hash", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);
  if (space.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the space's owner may change what it shares" }, 403);
  }
  const removed = await repo.removeSpaceResource(id, c.req.param("hash")!);
  void repo.recordAuditAction("space.resource_removed", c.get("orgName"), id)
    .catch((err) => console.error("[audit] space.resource_removed not recorded:", err));
  return c.json({ removed: removed.removed, grantsRevoked: removed.grantsRevoked });
});

/**
 * DELETE /v1/spaces/:id/members/:hash — remove a firm.
 *
 * Revokes exactly the grants that membership created, by via_space_id, and
 * leaves anything granted by hand alone. Somebody who was given direct access
 * to one agent before being invited keeps it afterwards, which is what they
 * were told when it was granted.
 */
spaceRoutes.delete("/:id/members/:hash", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);
  if (space.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the space's owner may remove a member" }, 403);
  }
  const out = await repo.removeSpaceMember(id, c.req.param("hash")!);
  void repo.recordAuditAction("space.member_removed", c.get("orgName"), id)
    .catch((err) => console.error("[audit] space.member_removed not recorded:", err));
  return c.json({ removed: out.removed, grantsRevoked: out.grantsRevoked });
});

/** DELETE /v1/spaces/:id — archive it, revoking everything it granted. */
spaceRoutes.delete("/:id", authMiddleware, async (c) => {
  const repo = c.get("repo");
  const id = c.req.param("id")!;
  const space = await repo.getSpace(id);
  if (!space || space.archivedAt) return c.json({ error: "No such space" }, 404);
  if (space.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the space's owner may archive it" }, 403);
  }
  const out = await repo.archiveSpace(id);
  void repo.recordAuditAction("space.archived", c.get("orgName"), id)
    .catch((err) => console.error("[audit] space.archived not recorded:", err));
  return c.json({ archived: true, grantsRevoked: out.grantsRevoked });
});
