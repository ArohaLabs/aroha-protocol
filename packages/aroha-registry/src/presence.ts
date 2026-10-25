// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Presence records — the volatile half of reachability (design spec §6.4).
 *
 * A DID document holds stable facts (keys, declared transports) but a
 * laptop's actual address changes per network and is unreachable while
 * asleep — "DID documents cannot hold your address." A presence record is
 * the volatile counterpart: current transport candidates, published on
 * connect, TTL-bounded, expired on disconnect.
 *
 * Deliberately mirrors sar.ts's shape and verification model rather than
 * inventing a new one: self-signed by the agent's own key, verifiable
 * offline via the DID's own committed key (content-addressed DIDs only —
 * see publicKeyFromDid in sar.ts, reused here unchanged), no registry
 * required to trust. The registry (or any index) that stores presence
 * records is exactly as untrusted as a SAR index: it can omit a record or
 * serve a stale one, but it cannot forge one.
 */

import { verifyCanonicalSignature, signCanonical } from "@aroha-sdk/core";
import { publicKeyFromDid } from "./sar.js";

/**
 * A transport ladder candidate (design spec §6.2). Only rungs 1 (direct
 * HTTPS) and 2 (LAN direct) are modeled — rung 3 (ICE/STUN P2P) and rung 4
 * (relay broker, §6.3/M10) are deliberately out of scope here; §6.5's build
 * order calls for rungs 1-2 plus presence first, "proving the
 * transport-agnostic model before any NAT-traversal work."
 */
export interface TransportCandidate {
  rung: 1 | 2;
  kind: "https" | "lan";
  /** Rung 1: an https:// URL. Rung 2: a LAN-resolvable host:port (mDNS-discovered). */
  address: string;
}

export interface UnsignedPresence {
  did: string;
  candidates: TransportCandidate[];
  issuedAt: number;
  /** Milliseconds after issuedAt this record should be considered stale. */
  ttl: number;
}

export interface SignedPresence extends UnsignedPresence {
  signature: string;
}

// Short by design — "volatile facts," per §6.4, not a long-lived claim like
// a SAR's capabilities. A stale presence record just means a stale address,
// not a security hole, but a short TTL keeps candidate lists honest without
// needing an explicit "disconnect" signal from every possible failure mode
// (crash, network loss, sleep) — absence of a fresh record IS the signal.
const DEFAULT_TTL_MS = 2 * 60_000;

export interface BuildPresenceInput {
  did: string;
  privateKey: Uint8Array;
  candidates: TransportCandidate[];
  ttlMs?: number;
}

export async function buildPresence(input: BuildPresenceInput): Promise<SignedPresence> {
  const unsigned: UnsignedPresence = {
    did: input.did,
    candidates: input.candidates,
    issuedAt: Date.now(),
    ttl: input.ttlMs ?? DEFAULT_TTL_MS,
  };
  const signature = await signCanonical(unsigned as unknown as Record<string, unknown>, input.privateKey);
  return { ...unsigned, signature };
}

export type PresenceVerifyResult =
  | { valid: true; presence: SignedPresence }
  | { valid: false; reason: "bad_shape" | "expired" | "not_self_certifying" | "bad_signature" };

function hasValidShape(value: unknown): value is SignedPresence {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.did === "string" &&
    Array.isArray(v.candidates) &&
    v.candidates.every(
      (c) =>
        typeof c === "object" && c !== null &&
        ((c as TransportCandidate).rung === 1 || (c as TransportCandidate).rung === 2) &&
        ((c as TransportCandidate).kind === "https" || (c as TransportCandidate).kind === "lan") &&
        typeof (c as TransportCandidate).address === "string",
    ) &&
    typeof v.issuedAt === "number" &&
    typeof v.ttl === "number" &&
    typeof v.signature === "string"
  );
}

function isExpired(presence: SignedPresence, now = Date.now()): boolean {
  return presence.issuedAt + presence.ttl < now;
}

/** Verify a presence record entirely offline against the key its own content-addressed DID commits to. */
export async function verifyPresence(candidate: unknown, now = Date.now()): Promise<PresenceVerifyResult> {
  if (!hasValidShape(candidate)) return { valid: false, reason: "bad_shape" };
  if (isExpired(candidate, now)) return { valid: false, reason: "expired" };

  const publicKey = publicKeyFromDid(candidate.did);
  if (!publicKey) return { valid: false, reason: "not_self_certifying" };

  const { signature, ...unsigned } = candidate;
  const ok = await verifyCanonicalSignature(unsigned as unknown as Record<string, unknown>, signature, publicKey);
  return ok ? { valid: true, presence: candidate } : { valid: false, reason: "bad_signature" };
}

/**
 * Merge a DID document's static rung-1 endpoint with a live presence
 * record's candidates into one ordered list (design spec §6.4's "ordered
 * candidate list merging DID-document transports with the live presence
 * record"). Presence candidates sort before the static endpoint at the same
 * rung, since they're a live confirmation rather than a standing claim;
 * within presence, lower rung (more direct) sorts first, matching the
 * ladder's own preference order.
 *
 * `staticHttpsEndpoint` is optional — a DID that has never declared a
 * static ArohaEndpoint service still resolves fine from presence alone.
 */
export function resolveCandidates(
  staticHttpsEndpoint: string | undefined,
  presence: SignedPresence | undefined,
): TransportCandidate[] {
  const candidates: TransportCandidate[] = [];
  if (presence) {
    candidates.push(...[...presence.candidates].sort((a, b) => a.rung - b.rung));
  }
  if (staticHttpsEndpoint) {
    candidates.push({ rung: 1, kind: "https", address: staticHttpsEndpoint });
  }
  return candidates;
}
