// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Admin endpoints — operator-only inspection and management tooling.
 *
 * GET /v1/admin/audit         — paginated admin audit log (requires admin secret)
 */

import { Hono } from "hono";
import { adminMiddleware } from "../auth.js";
import type { HonoEnv } from "../index.js";
import { parsePagination } from "../pagination.js";

export const adminRoutes = new Hono<HonoEnv>();

adminRoutes.get("/audit", adminMiddleware, async (c) => {
  const { limit, offset } = parsePagination(c, { maxLimit: 200 });

  const entries = await c.get("repo").listAuditLog(limit, offset);
  return c.json({ entries, limit, offset });
});

/**
 * License a firm to provision a vanity subdomain (POST /v1/admin/firm-licenses).
 *
 * This is the actual access control behind /v1/provision-subdomain — no
 * automated billing integration exists yet to populate it any other way, so
 * an Aroha Labs operator registers each firm manually at purchase time with
 * the public key its studio install already minted
 * (store.firm_identity().publicKey, hex-encoded).
 */
adminRoutes.post("/firm-licenses", adminMiddleware, async (c) => {
  const body = await c.req.json().catch(() => null) as { firmDid?: unknown; publicKeyHex?: unknown; name?: unknown } | null;
  if (!body || typeof body.firmDid !== "string" || typeof body.publicKeyHex !== "string") {
    return c.json({ error: "firmDid and publicKeyHex are required" }, 400);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(body.publicKeyHex)) {
    return c.json({ error: "publicKeyHex must be 64 hex characters (32 bytes)" }, 400);
  }
  const name = typeof body.name === "string" ? body.name : "";

  await c.get("repo").upsertFirmLicense(body.firmDid, body.publicKeyHex, name);
  return c.json({ ok: true });
});

/** Revoke a firm's license (DELETE /v1/admin/firm-licenses/:firmDid). */
adminRoutes.delete("/firm-licenses/:firmDid", adminMiddleware, async (c) => {
  const firmDid = c.req.param("firmDid");
  if (!firmDid) return c.json({ error: "firmDid is required" }, 400);

  const revoked = await c.get("repo").revokeFirmLicense(decodeURIComponent(firmDid));
  if (!revoked) return c.json({ error: "No live license found for that firm" }, 404);
  return c.json({ ok: true });
});
