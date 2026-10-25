// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Action-request wire shapes (design spec §5).
 *
 * The write counterpart to a consult's read. An action request travels as an
 * ordinary ArohaRequest with capability "action" — no new message type and
 * no protocol version bump, same as consults.
 *
 * The safety property these shapes exist to carry: the receiving agent never
 * trusts the caller's claim that a human approved. The caller attaches a
 * SignedInvariants block binding the exact parameters, and the receiver
 * verifies both the signature and that the binding still matches what it is
 * about to do. If anything mutated in between — injected content, a bug, a
 * hostile relay — the check fails and the receiver refuses.
 */

import type { MandateInvariants, SignedInvariants } from "../messages/types.js";

/** The capability name an action request carries. */
export const ACTION_CAPABILITY = "action";

/**
 * An approval signed by a HUMAN's own key, plus the agent's attestation
 * that the key belongs to that human (human-identity spec Phase 3).
 *
 * Two signatures because the receiver can verify only one of them unaided:
 * the calling agent's key is recoverable from its content-addressed DID,
 * while a person DID resolves to nothing without an org-wide directory. So
 * the agent vouches, once, for the binding — and the human's signature is
 * the part the agent itself cannot forge.
 *
 * WHAT THIS PROVES, precisely: the approval was signed by a key the calling
 * runtime holds under that person's account. An agent claiming "Dana
 * approved" while Dana did not now has to steal Dana's key rather than
 * write her name in a field.
 *
 * WHAT IT DOES NOT PROVE: that the human was present. A session credential
 * still triggers the signing. And the agent remains the only attester that
 * this key belongs to this person — without an org directory there is
 * nobody else to ask.
 */
export interface UserApproval {
  /** The human's DID (did:aroha:personal:<uuid>). */
  userDid: string;
  /** Their Ed25519 public key, hex. */
  userPublicKey: string;
  /**
   * The human's signature, base64url, over userApprovalSigningBytes():
   * the canonical invariants alone when `presentedHash` is absent (legacy),
   * or JCS of { invariants, presentedHash, purpose: "aroha.user-approval/v2" }
   * when it is present.
   */
  userSignature: string;
  /** The agent's signature over "userDid|userPublicKey", binding the two. */
  agentAttestation: string;
  /** The invariants the human signed. */
  invariants: MandateInvariants;
  /**
   * SHA-256 hex of the RFC 8785 JCS form of exactly what was shown to the
   * approver (hashPresentedContent). Covered by `userSignature` when present.
   *
   * WHY: invariants bind the call; they do not bind what the person was told
   * about it. An approval surface that rendered one thing and submitted
   * another still produced a valid signature. With this hash inside the
   * signed bytes, anyone holding the presented content can check the
   * approval was for that content, and the receipt carries the same hash.
   * Absent = a legacy approval that makes no statement about presentation.
   */
  presentedHash?: string;
}

export interface ActionRequestParams {
  /** Capability id from CAPABILITY_TAXONOMY, e.g. "send-email". */
  action: string;
  /** Exact values the action will execute with. Bound by the approval. */
  parameters: Record<string, string | number | boolean>;
  /**
   * Stable across retries of ONE logical request — not per attempt. The
   * receiver records completed keys and replays the original result rather
   * than acting twice (design spec §5.3).
   */
  idempotencyKey: string;
  /**
   * The caller's human's approval, binding these exact parameters. Absent on
   * the first attempt: the receiver replies with what it WOULD do, the
   * caller gets that approved and signed, then re-sends the identical
   * request with this attached.
   */
  approval?: SignedInvariants;
  /**
   * An approval signed by the human themselves (human-identity Phase 3).
   * Stronger than `approval`, and preferred when the calling runtime has a
   * key for the approving person. Both remain valid: a runtime with no
   * named users has no user key to sign with and must keep working.
   */
  userApproval?: UserApproval;
  /**
   * Withdraw a request that was described but never approved (design spec
   * §5.5). Carries the idempotencyKey of the request being abandoned.
   *
   * Without this a pending request simply expires, which bounds the risk but
   * leaves the receiver unable to distinguish "the human is still deciding"
   * from "the human said no" — and leaves a later stray approval for that
   * key indistinguishable from a legitimate one.
   */
  cancel?: boolean;
}

/** Provider-side proof the action happened (design spec §5.4). */
export interface ActionEvidence {
  /** Provider-side identifier — a message id, a booking reference. */
  confirmation: string;
  /** ISO8601. */
  completedAt: string;
  /** Optional provider signature over the confirmation, where one exists. */
  providerSignature?: string;
}

/**
 * What the receiver returns.
 *
 * "replayed" is deliberately distinct from "done": a caller that cannot tell
 * "I did this" from "this had already been done" cannot reason about its own
 * retries, and would have no way to detect a duplicate submission.
 */
export type ActionRequestResult =
  | {
      status: "pending-approval";
      /** Exactly what the receiver would do, for a human to approve or refuse. */
      describes: { action: string; parameters: Record<string, string | number | boolean> };
      /** When an approval signed for this request stops being accepted. */
      expiresAt: string;
    }
  | { status: "done"; evidence: ActionEvidence }
  | { status: "replayed"; evidence: ActionEvidence }
  /** The request was withdrawn before approval (design spec §5.5). */
  | { status: "cancelled" };
