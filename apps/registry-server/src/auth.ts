// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Auth helpers for the Aroha Registry Worker.
 *
 * API keys are UUID v4 strings issued at org sign-up. Only their SHA-256 hash
 * is persisted — the raw key is shown once and never stored. This means:
 *   • A compromised DB exposes no usable keys
 *   • SHA-256 (not bcrypt) is used because Workers have a 10 ms CPU budget
 *     and bcrypt is too slow; SHA-256 over a random 128-bit key is secure
 *   • The same hash algorithm works identically in Postgres (pgcrypto or app-level)
 *     so migration requires no re-hashing
 */

import type { Context, Next } from "hono";
import type { HonoEnv } from "./index.js";
import { checkAdmin, logAdminUnconfigured, ADMIN_UNCONFIGURED_MESSAGE } from "./secrets.js";

/** SHA-256 of `input`, returned as lowercase hex. Uses Web Crypto (available in Workers + Postgres hosts). */
export async function sha256hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Generate a cryptographically random API key (UUID v4 without dashes, 32 hex chars). */
export function generateKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Middleware: validates `Authorization: Bearer <key>` on every request.
 * Attaches `keyHash` and `orgName` to the Hono context for use in route handlers.
 */
export async function authMiddleware(c: Context<HonoEnv>, next: Next) {
  const header = c.req.header("Authorization");
  if (!header?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or malformed Authorization header" }, 401);
  }

  const rawKey = header.slice(7).trim();
  const keyHash = await sha256hex(rawKey);
  const repo = c.get("repo");
  const keyRow = await repo.getKey(keyHash);

  if (!keyRow || !keyRow.active) {
    return c.json({ error: "Invalid or revoked API key" }, 401);
  }

  c.set("keyHash", keyHash);
  c.set("orgName", keyRow.orgName);
  c.set("orgPublicKeyB64", keyRow.orgPublicKeyB64);
  await next();
}

/**
 * Middleware: authenticate *if* a key is presented, otherwise continue anonymously.
 *
 * Discovery endpoints are public, but a caller who identifies themselves should
 * additionally see private resources they own or hold a grant for. This never
 * rejects: an absent or invalid key simply yields an anonymous view (public
 * records only), so a bad key can never be used to probe for private records.
 */
export async function optionalAuthMiddleware(c: Context<HonoEnv>, next: Next) {
  const header = c.req.header("Authorization");
  if (header?.startsWith("Bearer ")) {
    const keyHash = await sha256hex(header.slice(7).trim());
    const keyRow = await c.get("repo").getKey(keyHash);
    if (keyRow?.active) {
      c.set("keyHash", keyHash);
      c.set("orgName", keyRow.orgName);
      c.set("orgPublicKeyB64", keyRow.orgPublicKeyB64);
    }
  }
  await next();
}

/**
 * Middleware: validates the admin secret for key-provisioning endpoints.
 * Protects POST /v1/auth/keys so only operators can issue new org keys.
 * Fire-and-forget audit log entry is written for every admin request.
 */
export async function adminMiddleware(c: Context<HonoEnv>, next: Next) {
  // Constant-time, fail-closed comparison — see secrets.ts for why both.
  const check = await checkAdmin(c);
  if (check === "unconfigured") {
    logAdminUnconfigured();
    return c.json({ error: ADMIN_UNCONFIGURED_MESSAGE }, 503);
  }
  if (check !== "ok") {
    return c.json({ error: "Admin access required" }, 403);
  }

  const ip = c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? null;
  // Fire-and-forget, but never an unhandled rejection: a failed audit write
  // must not turn an admin request into a crash report, and it is logged so
  // a gap in the audit trail is still visible to the operator.
  void c.get("repo").recordAuditAction(
    `admin.${c.req.method.toLowerCase()}.${new URL(c.req.url).pathname}`,
    "admin_secret",
    undefined,
    ip ?? undefined,
  ).catch((err) => console.error("[audit] admin action not recorded:", err));

  return next();
}
