// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * POST /v1/auth/keys — provision a new org API key.
 * Protected by ADMIN_SECRET (set via `wrangler secret put ADMIN_SECRET`).
 *
 * The raw key is returned exactly once — it is never stored.
 * The response is the key itself; the caller must save it securely.
 */

import { Hono } from "hono";
import { adminMiddleware, authMiddleware } from "../auth.js";
import { generateKey, sha256hex } from "../auth.js";
import type { HonoEnv } from "../index.js";
import { decodeB64 } from "../b64.js";

export const keyRoutes = new Hono<HonoEnv>();

/** GET /v1/auth/ping — validate an API key; used by the IPFS gateway to verify callers */
keyRoutes.get("/ping", authMiddleware, (c) => {
  return c.json({ ok: true, orgName: c.get("orgName") });
});

/** GET /v1/auth/keys/list?ownerId= — list active keys for a stable owner ID (admin only) */
keyRoutes.get("/keys/list", adminMiddleware, async (c) => {
  const ownerId = c.req.query("ownerId");
  if (!ownerId) return c.json({ error: "ownerId query param required" }, 400);
  const keys = await c.get("repo").listKeysByOwner(ownerId);
  return c.json(keys);
});

/** DELETE /v1/auth/keys/:hash — revoke a key, scoped to owner ID (admin only) */
keyRoutes.delete("/keys/:hash", adminMiddleware, async (c) => {
  const body = await c.req.json<{ ownerId?: string }>().catch(() => ({} as { ownerId?: string }));
  if (!body.ownerId) return c.json({ error: "ownerId required in body" }, 400);
  const revoked = await c.get("repo").revokeKey(c.req.param("hash")!, body.ownerId);
  if (!revoked) return c.json({ error: "Key not found or not owned by this identity" }, 404);
  return c.json({ ok: true });
});

/**
 * PUT /v1/auth/org-key — register (or rotate) the org's Ed25519 signing public key.
 *
 * The org proves domain control by hosting their public key at:
 *   https://<domain>/.well-known/aroha-org.json  →  { "orgPublicKeyB64": "base64..." }
 *
 * Once registered, the org can sign agent registrations with the matching private key
 * to elevate newly registered agents to verificationTier: 'org-signed'.
 *
 * Request body: { "orgPublicKeyB64": "base64...", "domain": "acme.com" }
 * Auth: Bearer API key (the key whose org_public_key_b64 is being set)
 */
keyRoutes.put("/org-key", authMiddleware, async (c) => {
  const body = await c.req.json<{ orgPublicKeyB64?: string; domain?: string }>().catch(() => ({} as Record<string, never>));
  if (!body.orgPublicKeyB64) return c.json({ error: "orgPublicKeyB64 is required" }, 400);
  if (!body.domain) return c.json({ error: "domain is required" }, 400);

  // Validate domain format — no IPs, ports, or paths
  const domainRe = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRe.test(body.domain)) return c.json({ error: "invalid domain format" }, 400);

  // Validate the submitted key is a valid 32-byte Ed25519 public key (base64 = 44 chars)
  const keyBytes = decodeB64(body.orgPublicKeyB64);
  if (!keyBytes) return c.json({ error: "orgPublicKeyB64 is not valid base64" }, 400);
  if (keyBytes.length !== 32) {
    return c.json({ error: "orgPublicKeyB64 must be a 32-byte Ed25519 public key" }, 400);
  }

  // Fetch the well-known file to prove domain control + key ownership simultaneously.
  // SSRF note: Cloudflare Workers cannot reach RFC1918/loopback/link-local/CGNAT addresses.
  let wellKnown: { orgPublicKeyB64?: string };
  try {
    const res = await fetch(`https://${body.domain}/.well-known/aroha-org.json`, {
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok || res.status >= 300) {
      return c.json({ error: `Well-known fetch failed — host { "orgPublicKeyB64": "<key>" } at https://${body.domain}/.well-known/aroha-org.json` }, 422);
    }
    wellKnown = await res.json() as { orgPublicKeyB64?: string };
  } catch {
    return c.json({ error: `Could not reach https://${body.domain}/.well-known/aroha-org.json` }, 422);
  }

  if (wellKnown.orgPublicKeyB64 !== body.orgPublicKeyB64) {
    return c.json({
      error: "Key mismatch — the orgPublicKeyB64 in .well-known must match the submitted key",
    }, 422);
  }

  const ok = await c.get("repo").setOrgKey(c.get("keyHash"), body.orgPublicKeyB64, body.domain);
  if (!ok) return c.json({ error: "Failed to register org key" }, 500);

  void c.get("repo").recordAuditAction("org.key_registered", c.get("orgName"), body.domain)
    .catch((err) => console.error("[audit] org.key_registered not recorded:", err));
  return c.json({ ok: true, domain: body.domain });
});

keyRoutes.post("/keys", adminMiddleware, async (c) => {
  const body = await c.req.json<{ orgName?: string; ownerId?: string; label?: string }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Request body must be a JSON object" }, 400);
  const orgName = body?.orgName?.trim();
  const ownerId = body?.ownerId?.trim();
  // Display only, and trimmed to something a list can show. Never used
  // for scoping — owner_id alone decides whose key this is.
  const label = body?.label?.trim().slice(0, 80) || null;
  if (!orgName) return c.json({ error: "orgName is required" }, 400);
  if (!ownerId) return c.json({ error: "ownerId is required" }, 400);

  const rawKey = generateKey();
  const keyHash = await sha256hex(rawKey);
  await c.get("repo").insertKey(keyHash, orgName, ownerId, label);

  return c.json(
    {
      key: rawKey,
      orgName,
      note: "Store this key securely — it will not be shown again.",
    },
    201,
  );
});
