// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Human Credential System (Layer 1 extension)
 *
 * Human users are not DID-bearing agents. They authenticate to their Personal
 * Agent (out of band — password, OAuth, passkey, etc.), which then issues them
 * a short-lived signed credential. That credential travels in the body of any
 * Aroha message the user triggers, letting provider agents verify who initiated
 * the request and what they are allowed to do.
 *
 * The credential is signed by the issuing agent's Ed25519 private key using
 * the same canonicalization rules as Aroha envelope proofs.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { ArohaRole, type HumanCredential } from "./types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// Re-export so consumers can import from this module
export type { HumanCredential } from "./types.js";

export interface CredentialVerificationResult {
  valid: boolean;
  credential?: HumanCredential;
  reason?: string;
}

// ─── Issue ────────────────────────────────────────────────────────────────────

/**
 * Issue a signed HumanCredential.
 *
 * @param userId      Application user identifier
 * @param roles       Roles to grant (e.g. ["human:user"])
 * @param issuerDID   DID of the issuing agent (the Personal Agent)
 * @param privateKey  Ed25519 private key of the issuing agent (32 bytes)
 * @param ttlMs       Time-to-live in milliseconds (default: 1 hour)
 * @param email       Optional email for display purposes
 */
export async function issueHumanCredential(
  userId: string,
  roles: ArohaRole[],
  issuerDID: string,
  privateKey: Uint8Array,
  ttlMs = 3_600_000,
  email?: string
): Promise<HumanCredential> {
  const now = new Date();
  const credential: Omit<HumanCredential, "signature"> = {
    credentialId: crypto.randomUUID(),
    userId,
    roles,
    issuedAt:  now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    issuerDID,
    ...(email ? { email } : {}),
  };

  const canonical = canonicalizeCredential(credential);
  const bytes = new TextEncoder().encode(canonical);
  const sig = await ed.signAsync(bytes, privateKey);

  return {
    ...credential,
    signature: Buffer.from(sig).toString("base64url"),
  };
}

/**
 * Serialize a HumanCredential to a compact base64url token suitable for
 * embedding in a Aroha message body as `credentialToken`.
 */
export function serializeCredential(cred: HumanCredential): string {
  return Buffer.from(JSON.stringify(cred)).toString("base64url");
}

/**
 * Deserialize a credentialToken back to a HumanCredential object.
 * Returns null if the token is malformed.
 */
export function deserializeCredential(token: string): HumanCredential | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  return isHumanCredentialShape(parsed) ? parsed : null;
}

const KNOWN_ROLES: ReadonlySet<string> = new Set(Object.values(ArohaRole));

/** True when every entry is a known ArohaRole value. */
export function isArohaRoleList(roles: unknown): roles is ArohaRole[] {
  return Array.isArray(roles) && roles.every((r) => typeof r === "string" && KNOWN_ROLES.has(r));
}

/**
 * Structural check for a decoded HumanCredential. WHY: the token is
 * caller-supplied bytes. A `roles` value that is not an array of known roles
 * — a string, an object, "human:admin " with a trailing space — used to flow
 * straight into checkPermission, whose behaviour on unexpected input is not
 * a security property anyone designed for. Unknown roles are rejected, not
 * ignored, so a typo in an issuer's role list surfaces at once.
 */
export function isHumanCredentialShape(x: unknown): x is HumanCredential {
  if (typeof x !== "object" || x === null || Array.isArray(x)) return false;
  const c = x as Record<string, unknown>;
  for (const f of ["credentialId", "userId", "issuedAt", "expiresAt", "issuerDID", "signature"]) {
    if (typeof c[f] !== "string" || (c[f] as string).length === 0) return false;
  }
  if (c.email !== undefined && typeof c.email !== "string") return false;
  return isArohaRoleList(c.roles);
}

// ─── Verify ───────────────────────────────────────────────────────────────────

/**
 * True when `iso` is in the past OR unparseable. WHY the second half:
 * `new Date("garbage") < new Date()` is false (NaN compares false with
 * everything), so the old check read a malformed expiry as "never expires".
 * An expiry we cannot read must fail closed.
 */
export function isExpiredAt(iso: unknown, now: number = Date.now()): boolean {
  if (typeof iso !== "string") return true;
  const t = Date.parse(iso);
  return Number.isNaN(t) || t < now;
}

/**
 * Verify a HumanCredential.
 *
 * Checks:
 *   1. Token is parseable
 *   2. Expiry has not passed
 *   3. Ed25519 signature is valid against the issuer's public key
 *
 * @param token       The base64url credentialToken from the message body
 * @param issuerPublicKey  Ed25519 public key of the issuer DID (32 bytes)
 */
export async function verifyHumanCredential(
  token: string,
  issuerPublicKey: Uint8Array
): Promise<CredentialVerificationResult> {
  const cred = deserializeCredential(token);
  if (!cred) {
    return { valid: false, reason: "Credential token is malformed" };
  }

  if (isExpiredAt(cred.expiresAt)) {
    return { valid: false, reason: `Credential expired or has an invalid expiry (${String(cred.expiresAt)})` };
  }

  const { signature, ...body } = cred;
  const canonical = canonicalizeCredential(body);
  const bytes = new TextEncoder().encode(canonical);

  try {
    const sig = Buffer.from(signature, "base64url");
    const ok = await ed.verifyAsync(sig, bytes, issuerPublicKey);
    if (!ok) return { valid: false, reason: "Credential signature invalid" };
    return { valid: true, credential: cred };
  } catch {
    return { valid: false, reason: "Credential signature verification threw an error" };
  }
}

// ─── Canonicalization ─────────────────────────────────────────────────────────

/** Canonical JSON for signing — excludes `signature`, sorts keys. */
function canonicalizeCredential(cred: Omit<HumanCredential, "signature">): string {
  return JSON.stringify(sortKeysDeep(cred));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
