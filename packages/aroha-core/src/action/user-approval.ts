// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The bytes a UserApproval's `userSignature` covers, and helpers to sign and
 * check them.
 *
 * WHY THIS LIVES IN CORE. The runtime signs and verifies person approvals,
 * and before `presentedHash` existed it built the signed bytes inline. Two
 * forms now exist (legacy and presented-hash-bound), and a signer and a
 * verifier that disagree on which form applies would reject every approval
 * or, worse, accept one under the wrong rule. One function, here, decides.
 *
 * The two forms:
 *   - legacy (presentedHash absent): JSON.stringify of the invariants with
 *     object keys sorted — byte-identical to what the runtime has always
 *     signed, so approvals issued before this change still verify;
 *   - v2 (presentedHash present): RFC 8785 JCS of
 *     { invariants, presentedHash, purpose: "aroha.user-approval/v2" }.
 *     The purpose tag keeps a v2 approval signature from verifying as any
 *     other Aroha object, and a legacy signature from verifying as v2.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "../crypto/jcs.js";
import type { MandateInvariants } from "../messages/types.js";
import type { UserApproval } from "./types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** Domain tag inside a presented-hash-bound approval signature. */
export const USER_APPROVAL_PURPOSE_V2 = "aroha.user-approval/v2" as const;

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Key-sorted copy (objects only; arrays kept in order), as the legacy signer did. */
function sortKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return obj;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj as Record<string, unknown>).sort()) {
    out[k] = sortKeys((obj as Record<string, unknown>)[k]);
  }
  return out;
}

/** The exact bytes `userSignature` covers, chosen by whether presentedHash is set. */
export function userApprovalSigningBytes(
  approval: { invariants: MandateInvariants; presentedHash?: string },
): Uint8Array {
  if (approval.presentedHash === undefined) {
    return new TextEncoder().encode(JSON.stringify(sortKeys(approval.invariants)));
  }
  if (!SHA256_HEX.test(approval.presentedHash)) {
    throw new Error("presentedHash must be 64 lowercase hex characters (SHA-256)");
  }
  return new TextEncoder().encode(
    canonicalizeJcs({ invariants: approval.invariants, presentedHash: approval.presentedHash, purpose: USER_APPROVAL_PURPOSE_V2 }),
  );
}

/** Sign an approval payload with the person's Ed25519 key; returns base64url. */
export async function signUserApprovalPayload(
  approval: { invariants: MandateInvariants; presentedHash?: string },
  userPrivateKey: Uint8Array,
): Promise<string> {
  const sig = await ed.signAsync(userApprovalSigningBytes(approval), userPrivateKey);
  return Buffer.from(sig).toString("base64url");
}

/**
 * Check `userSignature` against `userPublicKey` under the form the approval
 * names. This checks ONLY the person's signature; the caller must first
 * check `agentAttestation` (which pins the key to the person) — verifying a
 * signature against a key the sender also chose proves nothing.
 */
export async function verifyUserApprovalSignature(
  approval: Pick<UserApproval, "invariants" | "presentedHash" | "userSignature">,
  userPublicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(
      Buffer.from(approval.userSignature, "base64url"),
      userApprovalSigningBytes(approval),
      userPublicKey,
    );
  } catch {
    return false;
  }
}
