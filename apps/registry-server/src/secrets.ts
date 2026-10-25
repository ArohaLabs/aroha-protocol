// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Operator secrets — the one place ADMIN_SECRET and CREDENTIAL_SECRET are read.
 *
 * Three routes used to compare the admin bearer token with `===` / `!==`
 * (auth.ts, routes/signals.ts, routes/health.ts), and the credential route
 * derived its JWT key by string concatenation. Both are now here so the
 * rules below hold everywhere at once:
 *
 *   • Constant-time comparison. Both sides are hashed with SHA-256 first and
 *     the fixed-length digests compared with a full-length XOR fold, so the
 *     time taken does not depend on how many leading characters matched or
 *     on the secret's length.
 *   • Fail closed. An unset or short (< 32 chars) ADMIN_SECRET never matches
 *     anything — not even an empty or equally short token — and the caller
 *     gets a fixed 503 rather than a 403, so a misconfigured deployment is
 *     visible to its operator instead of silently open or silently closed.
 *   • Key separation. Credential JWTs are signed with
 *     HMAC-SHA256(secret, "aroha-credential-v1") where the secret is
 *     CREDENTIAL_SECRET when set, else ADMIN_SECRET. Setting
 *     CREDENTIAL_SECRET lets an operator rotate admin access without
 *     invalidating every outstanding credential (and vice versa).
 */

import type { Context } from "hono";
import type { HonoEnv } from "./index.js";

/** Shortest secret accepted. 32 chars of a random string is well past brute force. */
export const MIN_SECRET_LENGTH = 32;

/** Fixed body for a deployment with no usable admin secret — no detail about why. */
export const ADMIN_UNCONFIGURED_MESSAGE = "Admin access is not configured on this deployment";

/** True when `secret` is present and long enough to be used. */
export function isUsableSecret(secret: string | undefined | null): secret is string {
  return typeof secret === "string" && secret.length >= MIN_SECRET_LENGTH;
}

async function sha256(input: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
}

/**
 * Compare two strings in time independent of where they differ. Hashing
 * first gives both sides the same 32-byte length, so neither the secret's
 * length nor a matching prefix shows up in timing.
 */
export async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([sha256(a), sha256(b)]);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i]! ^ db[i]!;
  return diff === 0;
}

export type AdminCheck = "ok" | "denied" | "unconfigured";

/** Read `Authorization: Bearer <token>` and compare it with ADMIN_SECRET. */
export async function checkAdmin(c: Context<HonoEnv>): Promise<AdminCheck> {
  const expected = c.env.ADMIN_SECRET;
  if (!isUsableSecret(expected)) return "unconfigured";
  const header = c.req.header("Authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return "denied";
  return (await constantTimeEqual(token, expected)) ? "ok" : "denied";
}

/** Log once per request that the deployment is misconfigured; the response body stays fixed. */
export function logAdminUnconfigured(): void {
  console.error(
    `[secrets] ADMIN_SECRET is unset or shorter than ${MIN_SECRET_LENGTH} characters — admin routes are refusing every request`,
  );
}

const CREDENTIAL_KEY_LABEL = "aroha-credential-v1";

/**
 * The HMAC key credential JWTs are signed and verified with, or null when no
 * usable secret exists — callers must then refuse to sign (and to verify:
 * a key derived from nothing would accept tokens anyone can mint).
 *
 * A CREDENTIAL_SECRET that is set but too short is NOT silently replaced by
 * ADMIN_SECRET: an operator who set one meant it to be used, so a bad value
 * fails closed rather than falling back.
 */
export async function credentialSigningKey(env: {
  ADMIN_SECRET?: string;
  CREDENTIAL_SECRET?: string;
}): Promise<CryptoKey | null> {
  const source = env.CREDENTIAL_SECRET !== undefined && env.CREDENTIAL_SECRET !== ""
    ? env.CREDENTIAL_SECRET
    : env.ADMIN_SECRET;
  if (!isUsableSecret(source)) return null;

  const secretKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(source), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const derived = new Uint8Array(
    await crypto.subtle.sign("HMAC", secretKey, new TextEncoder().encode(CREDENTIAL_KEY_LABEL)),
  );
  return crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
