// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Caller-uniqueness layer: KYC issuer trust, verify-caller nullifier
// submission, and caller-signed outcome attestations. See
// migrations/005_caller_uniqueness.sql and @aroha-sdk/trust for the design.

import { Hono } from "hono";
import { authMiddleware } from "../auth.js";
import { callerProofLimiter } from "../middleware/rate-limit.js";
import { decodeB64 } from "../b64.js";
import { verifyCallerSignature, hashDid } from "../caller-signature.js";
import { verifyCertificate, verifyUniquenessProof, type KycCertificate, type NullifierProof } from "@aroha-sdk/trust";
import type { HonoEnv } from "../index.js";

export const trustRoutes = new Hono<HonoEnv>();

/** Every proof must be scoped to this fixed value — server-enforced, not client-chosen, so a client can't pick a scope that dodges dedup. */
const VERIFIED_CALLER_SCOPE = "verified-caller";

/**
 * NullifierProof's fields are Uint8Array — meaningless once JSON.stringify'd
 * (it turns a Uint8Array into `{"0":1,"1":2,...}`, not usable bytes). This is
 * the wire shape: every binary field as base64url, decoded back into a real
 * NullifierProof at the boundary before any crypto touches it.
 */
interface NullifierProofWire {
  commitment: string;
  scope: string;
  nullifier: string;
  r1: string;
  r2: string;
  z: string;
}

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function decodeNullifierProof(wire: NullifierProofWire): NullifierProof {
  return {
    commitment: b64urlToBytes(wire.commitment),
    scope: wire.scope,
    nullifier: b64urlToBytes(wire.nullifier),
    r1: b64urlToBytes(wire.r1),
    r2: b64urlToBytes(wire.r2),
    z: b64urlToBytes(wire.z),
  };
}

// ─── POST /v1/kyc-issuers — register an issuer via domain-ownership proof ───
//
// Mirrors PUT /v1/auth/org-key (routes/keys.ts) exactly, applied to a
// distinct issuer role rather than the agent-signing key: the org hosts its
// public key at a well-known path, the registry fetches it, and a match
// proves the submitter controls both the domain and the key.

trustRoutes.post("/kyc-issuers", authMiddleware, async (c) => {
  const body = await c.req.json<{ issuerDid?: string; publicKeyB64?: string; domain?: string }>()
    .catch(() => ({}) as Record<string, never>);
  if (!body.issuerDid) return c.json({ error: "issuerDid is required" }, 400);
  if (!body.publicKeyB64) return c.json({ error: "publicKeyB64 is required" }, 400);
  if (!body.domain) return c.json({ error: "domain is required" }, 400);

  const domainRe = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRe.test(body.domain)) return c.json({ error: "invalid domain format" }, 422);

  const keyBytes = decodeB64(body.publicKeyB64);
  if (!keyBytes) return c.json({ error: "publicKeyB64 is not valid base64" }, 400);
  if (keyBytes.length !== 32) return c.json({ error: "publicKeyB64 must be a 32-byte Ed25519 public key" }, 422);

  // SSRF note: `domainRe` above already rejects IP literals (no TLD-shaped
  // final label matches, so 127.0.0.1 / 169.254.169.254 / 10.x.x.x all fail
  // before reaching here). The residual risk — a real hostname whose DNS
  // resolves to a private address — is blocked at the platform layer:
  // Cloudflare Workers' fetch() cannot reach RFC1918/loopback/link-local/CGNAT
  // addresses unless this Worker is bound to a VPC network (it isn't — see
  // wrangler.toml). If VPC binding is ever added here, this stops holding and
  // needs an explicit resolve-and-classify check before that point.
  let wellKnown: { issuerPublicKeyB64?: string };
  try {
    const res = await fetch(`https://${body.domain}/.well-known/aroha-kyc-issuer.json`, {
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok || res.status >= 300) {
      return c.json({
        error: `Well-known fetch failed — host { "issuerPublicKeyB64": "<key>" } at https://${body.domain}/.well-known/aroha-kyc-issuer.json`,
      }, 422);
    }
    wellKnown = await res.json() as { issuerPublicKeyB64?: string };
  } catch {
    return c.json({ error: `Could not reach https://${body.domain}/.well-known/aroha-kyc-issuer.json` }, 422);
  }

  if (wellKnown.issuerPublicKeyB64 !== body.publicKeyB64) {
    return c.json({ error: "Key mismatch — issuerPublicKeyB64 in .well-known must match the submitted key" }, 422);
  }

  const created = await c.get("repo").insertKycIssuer(body.issuerDid, body.publicKeyB64, body.domain);
  void c.get("repo").recordAuditAction("kyc_issuer.registered", body.issuerDid, body.domain).catch(() => {});
  return c.json({ issuerDid: body.issuerDid, domain: body.domain }, created ? 201 : 200);
});

// ─── POST /v1/verify-caller — submit a nullifier proof to become a verified caller ───

// callerProofLimiter: per-isolate burst bound for an unauthenticated route
// that costs a lookup + Ed25519 verification per call (see rate-limit.ts on
// why Cloudflare WAF rules are the shared control).
trustRoutes.post("/verify-caller", callerProofLimiter, async (c) => {
  const body = await c.req.json<{
    callerDid?: string;
    callerSignature?: string;           // over canonical({ callerDid, kycCertificate, nullifierProof })
    kycCertificate?: KycCertificate;
    nullifierProof?: NullifierProofWire;
  }>().catch(() => ({}) as Record<string, never>);

  if (!body.callerDid) return c.json({ error: "callerDid is required" }, 400);
  if (!body.callerSignature) return c.json({ error: "callerSignature is required" }, 400);
  if (!body.kycCertificate) return c.json({ error: "kycCertificate is required" }, 400);
  if (!body.nullifierProof) return c.json({ error: "nullifierProof is required" }, 400);

  const repo = c.get("repo");

  // 1. The submitter controls callerDid — without this, anyone could bind a
  //    valid nullifier proof to a DID they don't hold, denying the real
  //    holder that verified-caller slot. Signs the WIRE shape (as sent),
  //    since that's what both sides can independently reconstruct.
  const payload = { callerDid: body.callerDid, kycCertificate: body.kycCertificate, nullifierProof: body.nullifierProof };
  const sigResult = await verifyCallerSignature(repo, body.callerDid, payload, body.callerSignature);
  if (!sigResult.ok) return c.json({ error: `caller signature invalid: ${sigResult.reason}` }, 401);

  // 2. Server-enforced scope — reject before checking anything else if the
  //    client tried to submit a proof for some other scope.
  if (body.nullifierProof.scope !== VERIFIED_CALLER_SCOPE) {
    return c.json({ error: `nullifierProof.scope must be "${VERIFIED_CALLER_SCOPE}"` }, 422);
  }

  // 3. The KYC certificate must be signed by a trusted (domain-proven) issuer,
  //    unexpired, and certifying the SAME commitment the nullifier proof uses.
  const issuer = await repo.getKycIssuer(body.kycCertificate.issuerDID);
  if (!issuer) return c.json({ error: `unknown or revoked KYC issuer: ${body.kycCertificate.issuerDID}` }, 403);

  const issuerKeyBytes = decodeB64(issuer.publicKeyB64);
  if (!issuerKeyBytes) return c.json({ error: "stored issuer key is corrupt" }, 500);
  const certResult = await verifyCertificate(body.kycCertificate, issuerKeyBytes);
  if (!certResult.ok) return c.json({ error: `KYC certificate invalid: ${certResult.reason}` }, 403);

  if (body.kycCertificate.commitment !== body.nullifierProof.commitment) {
    return c.json({ error: "kycCertificate.commitment does not match nullifierProof.commitment" }, 422);
  }

  // 4. The Chaum-Pedersen proof itself — knowledge of the certified secret,
  //    correctly bound to this nullifier for this scope. Decode wire bytes
  //    only now — nothing before this point needed the actual curve points.
  let proof: NullifierProof;
  try {
    proof = decodeNullifierProof(body.nullifierProof);
  } catch {
    return c.json({ error: "nullifierProof fields are not valid base64url" }, 400);
  }
  const zkResult = verifyUniquenessProof(proof);
  if (!zkResult.ok) return c.json({ error: `nullifier proof invalid: ${zkResult.reason}` }, 403);

  // 5. The actual Sybil-resistance enforcement: this exact nullifier must not
  //    already have a live row.
  const inserted = await repo.insertVerifiedCallerNullifier({
    nullifier:  body.nullifierProof.nullifier,
    scope:      VERIFIED_CALLER_SCOPE,
    commitment: body.kycCertificate.commitment,
    issuerDid:  body.kycCertificate.issuerDID,
    callerDid:  body.callerDid,
    verifiedAt: Date.now(),
  });
  if (!inserted) {
    return c.json({ error: "this credential has already been used to verify a caller — one certified secret grants one verified-caller slot" }, 409);
  }

  void repo.recordAuditAction("caller.verified", body.callerDid, body.kycCertificate.issuerDID).catch(() => {});
  return c.json({ callerDid: body.callerDid, tier: "kyc-verified" }, 201);
});

// ─── POST /v1/signals/attest — caller-signed outcome attestation ───
//
// The Layer-0 piece: an individual caller DID signs a claim about a
// specific, real interaction. This is the first path in the codebase where a
// reputation-affecting signal is attributed to and verified against a
// specific caller identity, rather than gated by one shared admin key.

trustRoutes.post("/signals/attest", callerProofLimiter, async (c) => {
  const body = await c.req.json<{
    callerDid?: string;
    callerSignature?: string;    // over canonical({ callerDid, sagaId, agentDid, success, domain })
    sagaId?: string;
    agentDid?: string;
    success?: boolean;
    domain?: string;
  }>().catch(() => ({}) as Record<string, never>);

  if (!body.callerDid) return c.json({ error: "callerDid is required" }, 400);
  if (!body.callerSignature) return c.json({ error: "callerSignature is required" }, 400);
  if (!body.sagaId) return c.json({ error: "sagaId is required" }, 400);
  if (!body.agentDid) return c.json({ error: "agentDid is required" }, 400);
  if (typeof body.success !== "boolean") return c.json({ error: "success (boolean) is required" }, 400);

  const domain = body.domain ?? "general";
  const repo = c.get("repo");

  const payload = { callerDid: body.callerDid, sagaId: body.sagaId, agentDid: body.agentDid, success: body.success, domain };
  const sigResult = await verifyCallerSignature(repo, body.callerDid, payload, body.callerSignature);
  if (!sigResult.ok) return c.json({ error: `caller signature invalid: ${sigResult.reason}` }, 401);

  const agent = await repo.getAgent(hashDid(body.agentDid));
  if (!agent) return c.json({ error: "agentDid does not resolve to a registered agent" }, 404);

  const verified = await repo.isCallerVerified(body.callerDid);
  const callerWeight = verified ? 1.0 : 0.05; // mirrors CALLER_WEIGHTS in @aroha-sdk/reputation

  const inserted = await repo.insertCallerAttestation({
    sagaId: body.sagaId,
    agentDidHash: agent.didHash,
    callerDid: body.callerDid,
    success: body.success,
    domain,
    callerWeight,
    submittedAt: Date.now(),
  });
  if (!inserted) {
    return c.json({ error: "an attestation for this (sagaId, callerDid) pair was already submitted" }, 409);
  }

  return c.json({
    sagaId: body.sagaId, agentDid: body.agentDid, callerTier: verified ? "kyc-verified" : "unverified", callerWeight,
  }, 201);
});
