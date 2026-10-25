// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Verifies that a request body was signed by a specific caller DID's
// registered Ed25519 key — the proof that binds a verify-caller or
// attest-outcome submission to the DID it claims to act as, rather than an
// unrelated party using someone else's DID string in a JSON field.
//
// Uses native WebCrypto, matching the existing org-signature verification in
// routes/agents.ts — no new crypto dependency for this specific check.

import { keccak_256 } from "@noble/hashes/sha3";
import type { RegistryRepository } from "./repository.js";
import { decodeB64 } from "./b64.js";

/**
 * Deterministic JSON: object keys sorted at every level, not just the top
 * one. `JSON.stringify(obj, Object.keys(obj).sort())` — the pattern used
 * elsewhere in this codebase (aroha-credentials' canonicalizeCredential) —
 * only sorts the top level; a nested object built with different insertion
 * order produces a different string for identical content. Since this is
 * meant to be reproduced independently by more than one SDK, that fragility
 * would show up as spurious signature failures rather than a cosmetic diff.
 */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/** Canonical string signed by the caller — deterministic regardless of how the payload object was constructed. */
export function callerCanonicalString(payload: Record<string, unknown>): string {
  return JSON.stringify(sortKeysDeep(payload));
}

export interface CallerSignatureResult {
  ok: boolean;
  reason?: string;
}

/**
 * Resolve callerDid's registered public key from agent_records and verify
 * `signatureB64` over `callerCanonicalString(payload)`.
 *
 * The caller must already be a registered agent — this does not create
 * identity, it only proves control of an existing one.
 */
export async function verifyCallerSignature(
  repo: RegistryRepository,
  callerDid: string,
  payload: Record<string, unknown>,
  signatureB64: string,
): Promise<CallerSignatureResult> {
  const didHash = hashDid(callerDid);
  // Active rows only, and never one the registry itself took down. This used
  // getAgentAny, so a deactivated agent — including one deactivated because
  // its controlling person revoked it (deactivated_reason) — could still
  // sign as itself here, with the very key its controller meant to retire.
  const agent = await repo.getAgent(didHash);
  if (!agent || agent.deactivatedReason || agent.did !== callerDid) {
    return { ok: false, reason: `caller DID ${callerDid} is not an active registered agent` };
  }

  const sigBytes = decodeB64(signatureB64);
  const keyBytes = decodeB64(agent.publicKeyB64);
  if (!sigBytes || !keyBytes) {
    return { ok: false, reason: "signature or stored key is not valid base64" };
  }
  if (sigBytes.length !== 64) return { ok: false, reason: "signature must be 64 bytes" };

  const message = new TextEncoder().encode(callerCanonicalString(payload));
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, message);
    if (!valid) return { ok: false, reason: "invalid signature" };
    return { ok: true };
  } catch {
    return { ok: false, reason: "signature verification failed" };
  }
}

export function hashDid(did: string): string {
  const bytes = new TextEncoder().encode(did);
  const hash = keccak_256(bytes);
  return "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}
