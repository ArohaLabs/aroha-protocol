// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Agent Verifiable Credentials
 *
 * GET  /v1/credential/:didHash  — issue a 24-hour HMAC-HS256 JWT for an agent
 * POST /v1/credential/verify    — verify and decode a previously issued credential
 *
 * The JWT is signed with a key derived by secrets.ts's credentialSigningKey:
 *   key = HMAC-SHA256(CREDENTIAL_SECRET ?? ADMIN_SECRET, "aroha-credential-v1")
 *
 * This means:
 *   • Credential keys and admin-route access use different key material — the
 *     derived key is a proper HMAC output, not the secret with a suffix
 *   • Setting CREDENTIAL_SECRET decouples the two: admin access can rotate
 *     without invalidating every outstanding credential, and vice versa
 *   • With no usable secret (unset, or under 32 characters) the registry
 *     refuses to sign or verify rather than minting tokens under a weak key
 *
 * Enterprises present the JWT to downstream consumers as proof that the agent
 * exists in the Aroha registry with the stated reputation and public key.
 * Consumers call POST /v1/credential/verify to check the signature and expiry.
 */

import { Hono } from "hono";
import type { HonoEnv } from "../index.js";
import { optionalAuthMiddleware } from "../auth.js";
import { credentialSigningKey } from "../secrets.js";
import { canViewAgent, viewerDependent } from "../visibility.js";

export const credentialRoutes = new Hono<HonoEnv>();

// ─── JWT helpers ─────────────────────────────────────────────────────────────

function b64url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return btoa(String.fromCharCode(...Array.from(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function b64urlDecode(s: string): Uint8Array {
  const padding = (4 - (s.length % 4)) % 4;
  return Uint8Array.from(
    atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding)),
    (c) => c.charCodeAt(0),
  );
}

const JWT_HEADER = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));

const CREDENTIAL_UNCONFIGURED = "Credential signing is not configured on this deployment";

async function signJWT(payload: object, key: CryptoKey): Promise<string> {
  const body = b64url(JSON.stringify(payload));
  const data = `${JWT_HEADER}.${body}`;
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(
  token: string,
  key: CryptoKey,
): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sigStr] = parts;
  try {
    const sig = b64urlDecode(sigStr);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sig,
      new TextEncoder().encode(`${header}.${body}`),
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (typeof payload.exp === "number" && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload as Record<string, unknown>;
  } catch {
    return null;
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────

/**
 * GET /v1/credential/:didHash
 *
 * Issue a 24-hour HMAC-signed JWT attesting the agent's current registry state.
 * Public for public and unlisted agents. A private agent gets the same
 * owner/grant check as GET /v1/agents/:did — otherwise this route would
 * sign and hand out exactly the record the resolve route hides, and its
 * 200-vs-404 would confirm that the private agent exists.
 */
credentialRoutes.get("/:didHash", optionalAuthMiddleware, async (c) => {
  const didHash = c.req.param("didHash")!;
  const repo = c.get("repo");
  const agent = await repo.getAgent(didHash);
  if (!agent || !(await canViewAgent(repo, agent, c.get("keyHash") ?? null))) {
    return c.json({ error: "Agent not found" }, 404);
  }

  const now = Math.floor(Date.now() / 1000);
  const minAgeS = 7 * 24 * 60 * 60;
  const verified =
    agent.active &&
    agent.reputationScore >= 7_000 &&
    now - Math.floor(agent.registeredAt / 1000) >= minAgeS;

  const payload = {
    iss: "aroha-registry",
    sub: didHash,
    iat: now,
    exp: now + 24 * 60 * 60, // 24 hours
    agent: {
      did: agent.did,
      publicKeyB64: agent.publicKeyB64,
      reputationScore: agent.reputationScore,
      keyVersion: agent.keyVersion,
      registeredAt: agent.registeredAt,
      verified,
    },
  };

  const key = await credentialSigningKey(c.env);
  if (!key) {
    console.error("[credential] no usable CREDENTIAL_SECRET or ADMIN_SECRET — refusing to sign");
    return c.json({ error: CREDENTIAL_UNCONFIGURED }, 503);
  }
  const token = await signJWT(payload, key);
  viewerDependent(c);
  return c.json({ token, expiresAt: payload.exp });
});

/**
 * POST /v1/credential/verify
 *
 * Verify and decode a credential JWT issued by this registry.
 * Returns the decoded payload on success, 401 on invalid/expired token.
 */
credentialRoutes.post("/verify", async (c) => {
  const body = await c.req
    .json<{ token?: string }>()
    .catch(() => ({} as { token?: string }));
  if (!body.token) return c.json({ error: "token required" }, 400);

  const key = await credentialSigningKey(c.env);
  if (!key) return c.json({ error: CREDENTIAL_UNCONFIGURED }, 503);
  const payload = await verifyJWT(body.token, key);
  if (!payload) return c.json({ error: "Invalid or expired credential" }, 401);
  return c.json({ valid: true, payload });
});
