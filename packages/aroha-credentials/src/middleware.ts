// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/credentials — ArohaServer middleware and HTTP route helpers
 *
 * Wire RBAC and the credential registry into ArohaServer without coupling
 * aroha-core to this package.
 *
 *   import { createRbacMiddleware, credentialRegistryRoutes } from "@aroha-sdk/credentials";
 *
 *   const server = new ArohaServer({
 *     ...
 *     middleware: [createRbacMiddleware(policy)],
 *     httpRoutes: credentialRegistryRoutes(registry, { resolveIssuerPublicKey }),
 *   });
 */

import { type IncomingMessage, type ServerResponse } from "http";
import { type ArohaEnvelope, type ArohaMiddleware, type ArohaHttpRoute, readBody } from "@aroha-sdk/core";
import { verifyHumanCredential, deserializeCredential, serializeCredential, isHumanCredentialShape } from "./credentials.js";
import { verifyRevokeProof, CredentialRegistry } from "./registry.js";
import { checkPermission, actionForMessageType, DEFAULT_RBAC_PERMISSIONS, type RbacPolicy } from "./rbac.js";
import { type ArohaRole } from "./types.js";
import { type HumanCredential } from "./types.js";

// ─── RBAC middleware ──────────────────────────────────────────────────────────

/**
 * Create a ArohaServer middleware that enforces RBAC on every inbound message.
 *
 * @example
 *   server = new ArohaServer({
 *     middleware: [createRbacMiddleware({
 *       resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
 *       resolveIssuerPublicKey: async (did) => issuerKeys.get(did) ?? null,
 *     })],
 *   });
 */
export function createRbacMiddleware(policy: RbacPolicy): ArohaMiddleware {
  return async (envelope: ArohaEnvelope, reject) => {
    const result = await checkRbac(envelope, policy);
    if (!result.allowed) {
      const status = result.unauthorized ? 401 : 403;
      const code   = result.unauthorized ? "Aroha_UNAUTHORIZED" : "Aroha_FORBIDDEN";
      reject(status, code, result.reason ?? "Access denied");
    }
  };
}

async function checkRbac(
  envelope: ArohaEnvelope,
  policy: RbacPolicy
): Promise<{ allowed: boolean; unauthorized?: boolean; reason?: string }> {
  const action = actionForMessageType(envelope.type as Parameters<typeof actionForMessageType>[0]);
  if (!action) return { allowed: true }; // acks and responses skip RBAC

  const permissions = policy.permissions ?? DEFAULT_RBAC_PERMISSIONS;
  const body = envelope.body as unknown as Record<string, unknown>;
  const credentialId    = body?.credentialId    as string | undefined;
  const credentialToken = body?.credentialToken as string | undefined;

  let roles: ArohaRole[];

  if (credentialId) {
    if (!policy.credentialRegistry) {
      return { allowed: false, unauthorized: true, reason: "credentialId supplied but no credential registry configured" };
    }
    const cred = await policy.credentialRegistry.resolve(credentialId);
    if (!cred) {
      return { allowed: false, unauthorized: true, reason: `Credential not found or expired: ${credentialId}` };
    }
    if (!isHumanCredentialShape(cred)) {
      return { allowed: false, unauthorized: true, reason: `Registry credential ${credentialId} is malformed` };
    }
    if (!policy.resolveIssuerPublicKey && policy.allowUnverifiedCredentials !== true) {
      // Fail closed. The registry entry's roles are only trustworthy if its
      // issuer signature verifies, and that needs an issuer key resolver.
      return {
        allowed: false, unauthorized: true,
        reason: "credentialId supplied but no resolveIssuerPublicKey configured to verify it",
      };
    }
    if (policy.resolveIssuerPublicKey) {
      const issuerPubKey = await policy.resolveIssuerPublicKey(cred.issuerDID);
      // An issuer we cannot resolve is a REJECTION, not a skipped check. This
      // used to fall through and grant the stored roles unverified, so a
      // credential registered via registerTrusted (or an unauthenticated
      // POST /aroha/credentials) under an unknown issuer DID got its roles
      // honoured on a server that had configured issuer verification.
      if (!issuerPubKey) {
        return { allowed: false, unauthorized: true, reason: `Unknown credential issuer: ${cred.issuerDID}` };
      }
      const token = serializeCredential(cred as HumanCredential);
      const verifyResult = await verifyHumanCredential(token, issuerPubKey);
      if (!verifyResult.valid) {
        return { allowed: false, unauthorized: true, reason: `Registry credential signature invalid: ${verifyResult.reason}` };
      }
    }
    roles = (cred as HumanCredential).roles;

  } else if (credentialToken) {
    if (!policy.resolveIssuerPublicKey) {
      return { allowed: false, unauthorized: true, reason: "Server does not accept human credentials (no resolveIssuerPublicKey configured)" };
    }
    const parsed = deserializeCredential(credentialToken);
    if (!parsed) {
      return { allowed: false, unauthorized: true, reason: "credentialToken is malformed" };
    }
    const issuerPubKey = await policy.resolveIssuerPublicKey(parsed.issuerDID);
    if (!issuerPubKey) {
      return { allowed: false, unauthorized: true, reason: `Unknown credential issuer: ${parsed.issuerDID}` };
    }
    const verifyResult = await verifyHumanCredential(credentialToken, issuerPubKey);
    if (!verifyResult.valid) {
      return { allowed: false, unauthorized: true, reason: verifyResult.reason };
    }
    roles = verifyResult.credential!.roles;

  } else {
    roles = await policy.resolveAgentRoles(envelope.from);
    if (roles.length === 0) {
      return { allowed: false, unauthorized: false, reason: `Agent ${envelope.from} has no assigned roles` };
    }
  }

  const result = checkPermission(roles, action, permissions);
  return { allowed: result.allowed, reason: result.reason };
}

// ─── Credential registry HTTP routes ─────────────────────────────────────────

export interface CredentialRegistryRouteOptions {
  /**
   * Resolve the issuer's public key for signature verification on register/revoke.
   * REQUIRED: without it (and without allowUnverifiedCredentials) the
   * register and revoke routes answer 401. They used to store any POSTed
   * credential unverified and revoke any credential on an unauthenticated
   * DELETE — i.e. anyone who could reach the port could mint roles.
   */
  resolveIssuerPublicKey?: (issuerDID: string) => Promise<Uint8Array | null>;
  /**
   * TESTS AND LOCAL DEVELOPMENT ONLY. With no resolveIssuerPublicKey, store
   * POSTed credentials without verifying their signature and revoke without
   * a proof. Never enable on a server reachable by anyone you do not trust.
   */
  allowUnverifiedCredentials?: boolean;
}

function refuseUnverified(res: ServerResponse): void {
  res.writeHead(401, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Credential registry has no resolveIssuerPublicKey configured; refusing unverified writes" }));
}

/**
 * Returns ArohaHttpRoute[] that mount credential registry endpoints on ArohaServer.
 *
 * Endpoints added:
 *   POST   /aroha/credentials          — register a credential
 *   GET    /aroha/credentials/:id      — resolve by ID
 *   GET    /aroha/credentials?userId=  — list by user
 *   DELETE /aroha/credentials/:id      — revoke (requires X-Revoke-Proof header)
 *
 * @example
 *   const registry = new CredentialRegistry();
 *   const server = new ArohaServer({
 *     httpRoutes: credentialRegistryRoutes(registry, { resolveIssuerPublicKey }),
 *   });
 */
export function credentialRegistryRoutes(
  registry: CredentialRegistry,
  opts: CredentialRegistryRouteOptions = {}
): ArohaHttpRoute[] {
  return [
    {
      method: "POST",
      test: (url) => url === "/aroha/credentials",
      handle: (req, res) => handleRegister(req, res, registry, opts),
    },
    {
      method: "DELETE",
      test: (url) => /^\/aroha\/credentials\/[^?/]+$/.test(url),
      handle: (req, res) => handleRevoke(req, res, registry, opts),
    },
    {
      method: "GET",
      test: (url) => /^\/aroha\/credentials\/[^?/]+$/.test(url),
      handle: (req, res) => handleResolve(req, res, registry),
    },
    {
      method: "GET",
      test: (url) => url === "/aroha/credentials" || url.startsWith("/aroha/credentials?"),
      handle: (req, res) => handleList(req, res, registry),
    },
  ];
}

// ─── Route handlers ───────────────────────────────────────────────────────────

async function handleRegister(
  req: IncomingMessage,
  res: ServerResponse,
  registry: CredentialRegistry,
  opts: CredentialRegistryRouteOptions
): Promise<void> {
  const body = await readBody(req).catch(() => null);
  if (!body) { res.writeHead(400); res.end(JSON.stringify({ error: "Invalid body" })); return; }

  let cred: unknown;
  try { cred = JSON.parse(body); }
  catch { res.writeHead(400); res.end(JSON.stringify({ error: "Invalid JSON" })); return; }
  if (!isHumanCredentialShape(cred)) {
    res.writeHead(400);
    res.end(JSON.stringify({ error: "Malformed credential (missing fields or unknown roles)" }));
    return;
  }

  if (!opts.resolveIssuerPublicKey && opts.allowUnverifiedCredentials !== true) {
    refuseUnverified(res);
    return;
  }

  if (opts.resolveIssuerPublicKey) {
    const pubKey = await opts.resolveIssuerPublicKey(cred.issuerDID);
    if (!pubKey) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: `Unknown credential issuer: ${cred.issuerDID}` }));
      return;
    }
    const ok = await registry.register(cred, pubKey);
    if (!ok) { res.writeHead(400); res.end(JSON.stringify({ error: "Credential signature invalid" })); return; }
  } else {
    registry.registerTrusted(cred);
  }

  res.writeHead(201, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ credentialId: cred.credentialId, stored: true }));
}

async function handleRevoke(
  req: IncomingMessage,
  res: ServerResponse,
  registry: CredentialRegistry,
  opts: CredentialRegistryRouteOptions
): Promise<void> {
  const credentialId = decodeURIComponent((req.url ?? "").split("/").pop() ?? "");
  // Checked before the lookup so an unauthenticated caller cannot use
  // DELETE to probe which credential IDs exist.
  if (!opts.resolveIssuerPublicKey && opts.allowUnverifiedCredentials !== true) {
    refuseUnverified(res);
    return;
  }
  const cred = registry.resolve(credentialId);
  if (!cred) { res.writeHead(404); res.end(JSON.stringify({ error: "Credential not found" })); return; }

  if (opts.resolveIssuerPublicKey) {
    const pubKey = await opts.resolveIssuerPublicKey(cred.issuerDID);
    if (!pubKey) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: `Unknown credential issuer: ${cred.issuerDID}` }));
      return;
    }
    const proof = req.headers["x-revoke-proof"] as string | undefined;
    if (!proof) { res.writeHead(401); res.end(JSON.stringify({ error: "X-Revoke-Proof header required" })); return; }
    const valid = await verifyRevokeProof(credentialId, proof, pubKey);
    if (!valid) { res.writeHead(403); res.end(JSON.stringify({ error: "Revoke proof invalid" })); return; }
  }

  registry.revoke(credentialId);
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ credentialId, revoked: true }));
}

async function handleResolve(
  _req: IncomingMessage,
  res: ServerResponse,
  registry: CredentialRegistry
): Promise<void> {
  const credentialId = decodeURIComponent((_req.url ?? "").split("?")[0].split("/").pop() ?? "");
  const cred = registry.resolve(credentialId);
  if (!cred) { res.writeHead(404); res.end(JSON.stringify({ error: "Credential not found or expired" })); return; }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(cred));
}

async function handleList(
  req: IncomingMessage,
  res: ServerResponse,
  registry: CredentialRegistry
): Promise<void> {
  const urlObj = new URL(req.url ?? "/", "http://localhost");
  const userId = urlObj.searchParams.get("userId");
  if (!userId) { res.writeHead(400); res.end(JSON.stringify({ error: "userId query param required" })); return; }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(registry.listForUser(userId)));
}

