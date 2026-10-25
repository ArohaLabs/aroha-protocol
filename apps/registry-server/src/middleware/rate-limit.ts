// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * In-process sliding-window rate limiter for Cloudflare Workers.
 *
 * State lives in a closure Map — per-isolate, resets on isolate recycle.
 * Cloudflare routes requests from the same origin IP to the same PoP (and
 * usually the same isolate), so in-memory limiting catches burst attacks
 * without a distributed store.
 *
 * For sustained cross-PoP DDoS, add Cloudflare WAF Rate Limiting rules in
 * the dashboard — those run at the network edge before the Worker starts.
 *
 * Map growth: entries are evicted when they expire (window elapsed) during
 * a check. If the map exceeds 5 000 keys a full prune runs — handles
 * adversarial key-space flooding (e.g., attacker cycling IPs) without OOM.
 *
 * SCOPE (manual control): every limiter here is PER ISOLATE. Cloudflare runs
 * many isolates across many PoPs, so a determined client spread across them
 * sees a multiple of these numbers. They bound bursts and a single noisy
 * client; the shared, authoritative control is Cloudflare WAF rate-limiting
 * rules on the zone (dashboard / Terraform), which must be configured and
 * verified manually — nothing in this repository enforces them.
 *
 * Keys never hold a raw credential: limiters keyed by API key use
 * `authKeyId`, a SHA-256 of the Authorization header, so a heap snapshot or
 * debug dump of this Map cannot leak a usable key.
 */

import type { MiddlewareHandler } from "hono";
import type { HonoEnv } from "../index.js";

interface Bucket {
  count: number;
  resetAt: number; // Unix ms when this window ends
}

export function rateLimiter({
  windowMs,
  max,
  keyFn,
  message = "Too many requests — try again later",
}: {
  windowMs: number;
  max: number;
  keyFn: (c: Parameters<MiddlewareHandler<HonoEnv>>[0]) => string | Promise<string>;
  message?: string;
}): MiddlewareHandler<HonoEnv> {
  const buckets = new Map<string, Bucket>();

  return async (c, next) => {
    const key = await keyFn(c);
    const now = Date.now();
    const existing = buckets.get(key);

    if (!existing || now >= existing.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
    } else {
      existing.count++;
      if (existing.count > max) {
        const retryAfterS = Math.ceil((existing.resetAt - now) / 1000);
        return c.json(
          { error: message },
          429,
          { "Retry-After": String(retryAfterS) },
        );
      }
    }

    // Prevent unbounded growth under adversarial key-cycling.
    if (buckets.size > 5_000) {
      for (const [k, b] of buckets) {
        if (now >= b.resetAt) buckets.delete(k);
      }
    }

    await next();
  };
}

/** Client IP as Cloudflare reports it. */
export function clientIp(c: Parameters<MiddlewareHandler<HonoEnv>>[0]): string {
  return c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown";
}

/**
 * A stable, non-secret identifier for the caller's credential: SHA-256 of the
 * Authorization header (hex), or "anon". The raw header used to be the Map
 * key itself.
 */
export async function authKeyId(c: Parameters<MiddlewareHandler<HonoEnv>>[0]): Promise<string> {
  const header = c.req.header("Authorization");
  if (!header) return "anon";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(header));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Pre-built limiters ───────────────────────────────────────────────────────
// Import these directly rather than calling rateLimiter() inline so each
// endpoint shares one Map instance across all requests (not a new Map per call).

/** 200 req/min per Cloudflare-reported IP — applied globally to /v1/*. */
export const globalIpLimiter = rateLimiter({
  windowMs: 60_000,
  max: 200,
  keyFn: (c) =>
    `ip:${c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown"}`,
});

/**
 * 5 rotate-key attempts per minute per didHash.
 * Ed25519 verification is the expensive op — tight limit prevents CPU DoS
 * and nonce-table pollution from unauthenticated callers.
 */
export const rotateKeyLimiter = rateLimiter({
  windowMs: 60_000,
  max: 5,
  keyFn: (c) => `rotate:${c.req.param("didHash") ?? "unknown"}`,
  message: "Too many key-rotation attempts — wait 60 seconds",
});

/** 30 budget-init calls per minute per API key hash. */
export const budgetInitLimiter = rateLimiter({
  windowMs: 60_000,
  max: 30,
  keyFn: async (c) => `budget-init:${await authKeyId(c)}`,
  message: "Too many budget-init requests — wait 60 seconds",
});

/** 120 allocate calls per minute per API key hash. */
export const allocateLimiter = rateLimiter({
  windowMs: 60_000,
  max: 120,
  keyFn: async (c) => `allocate:${await authKeyId(c)}`,
  message: "Too many allocate requests — wait 60 seconds",
});

/**
 * 120 public discovery requests per minute per IP.
 * Applied to GET /v1/agents and GET /v1/agents/:didHash to prevent scraping
 * and to reserve the global budget for authenticated callers.
 */
export const discoveryIpLimiter = rateLimiter({
  windowMs: 60_000,
  max: 120,
  keyFn: (c) =>
    `discovery:${c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown"}`,
  message: "Too many discovery requests — try again later",
});

/**
 * 30 KEL / linkage submissions per minute per IP.
 * POST /v1/kel/:did and POST /v1/linkage need no API key — a Key Event Log
 * and a linkage are self-authenticating, so anyone may relay them — but each
 * submission replays a whole log (one Ed25519 verification per event, plus
 * the controller's log). This bounds the CPU one address can spend; the
 * per-request event cap in kel-store.ts bounds the cost of each call.
 */
export const kelSubmitLimiter = rateLimiter({
  windowMs: 60_000,
  max: 30,
  keyFn: (c) =>
    `kel-submit:${c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown"}`,
  message: "Too many KEL submissions — try again later",
});

/**
 * 60 SAR publications per minute per IP. POST /v1/sar needs no API key (the
 * record's self-signature is the access control) and each call verifies a
 * signature — and possibly replays an attached KEL — so it gets its own
 * budget below the global one.
 */
export const sarPublishLimiter = rateLimiter({
  windowMs: 60_000,
  max: 60,
  keyFn: (c) => `sar-publish:${clientIp(c)}`,
  message: "Too many SAR publications — try again later",
});

/**
 * 60 verify-caller / attest calls per minute per IP. Both are unauthenticated
 * and each costs a registry lookup plus an Ed25519 verification (attest also
 * writes), so they are bounded per address.
 */
export const callerProofLimiter = rateLimiter({
  windowMs: 60_000,
  max: 60,
  keyFn: (c) => `caller-proof:${clientIp(c)}`,
  message: "Too many caller-verification requests — try again later",
});
