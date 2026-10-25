// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Signed Agent Records — federated discovery (design spec §7.2, §7.3).
 *
 * The gap this closes: MCP has no discovery, A2A's `/.well-known/agent.json`
 * has no cross-domain index, and a registry is a single point of trust,
 * failure, and censorship. A SAR is the unit that makes discovery not need
 * to be trusted at all: it is a self-signed record, verifiable offline by
 * any party with no network call and no trusted third party, because a
 * content-addressed `did:aroha:` already commits to its own signing key
 * (aroha-core's `generateDid`).
 *
 * This is what makes indexes safe to federate: an index can omit a record
 * (censor it, go offline, be slow) but cannot forge one — the same
 * guarantee Certificate Transparency gives you over a log operator. Clients
 * are expected to query several indexes and verify every result themselves;
 * this module is exactly that verification, plus the (much simpler)
 * construction side that an agent uses to describe itself.
 *
 * Rotatable DIDs. For `did:aroha:E…` (aroha-core kel.ts) the DID commits to
 * an inception event, not a key, so the record carries — or the verifier
 * fetches — the agent's Key Event Log, and the signature is checked against
 * the CURRENT key of that verified log. Never against a key written into the
 * record: an index could write any key it liked there. The `kel` field is an
 * unsigned attachment (excluded from the signed bytes): the log authenticates
 * itself, and leaving it outside the signature lets an index attach a newer
 * log without invalidating the record — and if the newer log has rotated
 * away from the signing key, the record correctly stops verifying, because a
 * record signed by a superseded key is exactly what should age out.
 *
 * Worker-safe on purpose. This module is published as the
 * `@aroha-sdk/registry/sar` subpath, and the Cloudflare registry server
 * (apps/registry-server) verifies published records with it directly — one
 * implementation of the rule instead of a server-side copy that had to be
 * kept byte-for-byte in step. So it imports only the `@aroha-sdk/core`
 * SUBPATHS `./identity` and `./crypto`, never the barrel: the barrel
 * re-exports the transport module, which pulls in `ws`/`undici` and through
 * them `fs`, `http`, `path` and `string_decoder`, none of which exist in the
 * Workers runtime. The two subpaths depend on @noble/* only.
 * worker-safety.test.ts bundles this file for a platform with no Node
 * built-ins and fails if that ever stops being true.
 */

import {
  fromMultibase,
  extractNamespace,
  isInceptionDid,
  resolveKelState,
  type KelEvent,
  type KelSource,
  type KelState,
  type KelStore,
} from "@aroha-sdk/core/identity";
import { signCanonical, verifyCanonicalSignature } from "@aroha-sdk/core/crypto";

export interface SarTerms {
  pricing?: { amount: number; currency: string };
  sla?: { maxResponseMs: number; uptime: number };
}

/** An unsigned SAR — what gets canonicalized and signed. */
export interface UnsignedSar {
  did: string;
  capabilities: string[];
  /** Transport candidates, e.g. "https://...", or "via:<parent-did>" (spec §7.8). */
  transports: string[];
  /** Settlement rail identifiers this agent accepts (spec §8.1). */
  settlementRails: string[];
  terms: SarTerms;
  issuedAt: number;
  /** Milliseconds after issuedAt this record should be considered stale. */
  ttl: number;
}

export interface SignedAgentRecord extends UnsignedSar {
  signature: string;
  /**
   * E-DIDs only: the agent's Key Event Log, attached so the record verifies
   * with no lookup. NOT covered by `signature` (see the module comment).
   */
  kel?: KelEvent[];
}

export interface BuildSarInput {
  did: string;
  privateKey: Uint8Array;
  capabilities?: string[];
  transports?: string[];
  settlementRails?: string[];
  terms?: SarTerms;
  /** Default 1 hour — short enough that a stale record ages out on its own. */
  ttlMs?: number;
  /** E-DIDs: the agent's KEL to attach. `privateKey` must be its current key. */
  kel?: KelEvent[];
}

const DEFAULT_TTL_MS = 60 * 60_000;

export async function buildSar(input: BuildSarInput): Promise<SignedAgentRecord> {
  const unsigned: UnsignedSar = {
    did: input.did,
    capabilities: input.capabilities ?? [],
    transports: input.transports ?? [],
    settlementRails: input.settlementRails ?? [],
    terms: input.terms ?? {},
    issuedAt: Date.now(),
    ttl: input.ttlMs ?? DEFAULT_TTL_MS,
  };
  // signCanonical only excludes a "proof" field, not "signature" — signing
  // the unsigned object (no signature key present yet) is what keeps the
  // record from having to sign over its own signature.
  const signature = await signCanonical(unsigned as unknown as Record<string, unknown>, input.privateKey);
  return input.kel ? { ...unsigned, signature, kel: input.kel } : { ...unsigned, signature };
}

export type SarVerifyResult =
  | { valid: true; sar: SignedAgentRecord }
  | {
      valid: false;
      reason:
        | "bad_shape"
        | "expired"
        | "not_self_certifying"
        | "bad_signature"
        /** E-DID with no KEL attached and none obtainable from `kelSource`. */
        | "kel_unavailable"
        /** E-DID whose KEL failed verification (tampered, stale, forked, controller missing). */
        | "kel_invalid"
        /** E-DID that is revoked, or whose controller person is. */
        | "revoked";
    };

export interface VerifySarOptions {
  /**
   * Where to fetch KELs for E-DIDs (the agent's own, when not attached, and
   * its controller's — needed when the agent's log has controller events).
   */
  kelSource?: KelSource;
  /** Highest-seen KEL memory: rejects stale and forked logs across calls. */
  kelStore?: KelStore;
  /**
   * Take over E-DID resolution entirely: given the DID and the log attached
   * to the record (if any), return the verified state — null when no log is
   * attached or known, throw when a log exists but is rejected. When set,
   * `kelSource` and `kelStore` are not consulted.
   *
   * For verifiers whose KEL memory has rules of its own beyond `acceptKel` —
   * the registry server routes every log through one acceptance path that
   * also records seal-proven forks and keeps its agent rows in step with the
   * log. Injecting that path means a SAR carrying a log cannot be a side door
   * around those rules, while the signature rule itself (check against the
   * CURRENT key of the verified log, never a key in the record) stays this
   * module's, in one place.
   */
  resolveKel?: (did: string, attached: KelEvent[] | undefined) => Promise<KelState | null>;
}

/**
 * Derive the Ed25519 public key a `did:aroha:<base58btc(pubkey)>` DID
 * commits to — the entire mechanism that makes a SAR verifiable offline.
 * Returns null for the namespaced form (`did:aroha:<namespace>.<agentId>`),
 * which is NOT content-addressed (design spec §2.1) and has no key to
 * derive; verifying one of those requires an external resolver, which is a
 * deliberately separate, explicit path — see `verifySarWithResolver`.
 *
 * Also null for rotatable `did:aroha:E…` DIDs: their key is not in the DID
 * (it lives in a Key Event Log), which `verifySar` handles separately.
 */
export function publicKeyFromDid(did: string): Uint8Array | null {
  if (!did.startsWith("did:aroha:")) return null;
  if (extractNamespace(did) !== null) return null; // namespaced — not content-addressed
  const suffix = did.slice("did:aroha:".length);
  try {
    const key = fromMultibase(suffix);
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

/**
 * Structural check for a SAR, before any cryptography. Exported because an
 * index storing records needs its own type evidence for the fields it
 * persists, rather than casting what `verifySar` narrowed in its own scope.
 *
 * Capabilities must be strings and `terms` a non-null object: an index
 * queries and re-serves exactly these fields, and a record correctly signed
 * over `capabilities: [{…}]` or `terms: null` is still not one anyone can
 * match a capability against or read terms from.
 */
export function hasSarShape(value: unknown): value is SignedAgentRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.did === "string" &&
    Array.isArray(v.capabilities) &&
    v.capabilities.every((c) => typeof c === "string") &&
    Array.isArray(v.transports) &&
    Array.isArray(v.settlementRails) &&
    typeof v.terms === "object" &&
    v.terms !== null &&
    typeof v.issuedAt === "number" &&
    typeof v.ttl === "number" &&
    typeof v.signature === "string" &&
    (v.kel === undefined || Array.isArray(v.kel))
  );
}

/** The bytes a SAR signature covers: everything except `signature` and the `kel` attachment. */
function signedPart(sar: SignedAgentRecord): Record<string, unknown> {
  const { signature: _signature, kel: _kel, ...unsigned } = sar;
  return unsigned as unknown as Record<string, unknown>;
}

async function verifyEDidSar(
  candidate: SignedAgentRecord,
  options: VerifySarOptions
): Promise<SarVerifyResult> {
  const attached = candidate.kel;
  if (options.resolveKel) {
    let injected: KelState | null;
    try {
      injected = await options.resolveKel(candidate.did, attached);
    } catch {
      return { valid: false, reason: "kel_invalid" };
    }
    return checkAgainstKelState(candidate, injected);
  }
  // The attached log and the source's log are both untrusted transports of
  // a self-authenticating object: take the longer (newer) one and let
  // verification — and the store, when given — decide.
  const source: KelSource = async (did) => {
    const fetched = options.kelSource ? await options.kelSource(did).catch(() => null) : null;
    const own = did === candidate.did ? attached : undefined;
    if (fetched && own) return fetched.length >= own.length ? fetched : own;
    return fetched ?? own ?? null;
  };
  let state;
  try {
    state = await resolveKelState(candidate.did, source, { store: options.kelStore });
  } catch {
    return { valid: false, reason: "kel_invalid" };
  }
  return checkAgainstKelState(candidate, state);
}

/** The E-DID rule: a live identity, and a signature by its CURRENT key. */
async function checkAgainstKelState(
  candidate: SignedAgentRecord,
  state: KelState | null
): Promise<SarVerifyResult> {
  if (!state) return { valid: false, reason: "kel_unavailable" };
  if (state.revoked || state.controllerRevoked || !state.currentKey) return { valid: false, reason: "revoked" };
  const ok = await verifyCanonicalSignature(signedPart(candidate), candidate.signature, state.currentKey);
  return ok ? { valid: true, sar: candidate } : { valid: false, reason: "bad_signature" };
}

function isExpired(sar: SignedAgentRecord, now = Date.now()): boolean {
  return sar.issuedAt + sar.ttl < now;
}

/**
 * Verify a SAR with no trusted third party.
 *   - `did:aroha:z<pubkey>`: entirely offline, against the key the DID
 *     commits to (unchanged behaviour).
 *   - `did:aroha:E…`: against the CURRENT key of the agent's verified KEL —
 *     attached to the record (`kel`) or fetched via `options.kelSource`.
 *     Offline when the log is attached and has no controller-authorised
 *     events; an agent recovered or revoked by its controller also needs the
 *     controller's log from `kelSource`.
 *   - anything else: `not_self_certifying` — see `verifySarWithResolver`.
 */
export async function verifySar(
  candidate: unknown,
  now = Date.now(),
  options: VerifySarOptions = {}
): Promise<SarVerifyResult> {
  if (!hasSarShape(candidate)) return { valid: false, reason: "bad_shape" };
  if (isExpired(candidate, now)) return { valid: false, reason: "expired" };

  if (isInceptionDid(candidate.did)) return verifyEDidSar(candidate, options);

  const publicKey = publicKeyFromDid(candidate.did);
  if (!publicKey) return { valid: false, reason: "not_self_certifying" };

  const ok = await verifyCanonicalSignature(signedPart(candidate), candidate.signature, publicKey);
  return ok ? { valid: true, sar: candidate } : { valid: false, reason: "bad_signature" };
}

/**
 * Verify a SAR whose DID is namespaced (not content-addressed), using a
 * caller-supplied resolver — e.g. a registry lookup or a `did:aroha-web`
 * DNS+HTTPS proof. Kept as an explicit separate function rather than an
 * optional fallback inside `verifySar`, so callers cannot accidentally trust
 * a resolver they didn't mean to consult.
 */
export async function verifySarWithResolver(
  candidate: unknown,
  resolvePublicKey: (did: string) => Promise<Uint8Array | null> | Uint8Array | null,
  now = Date.now(),
): Promise<SarVerifyResult> {
  if (!hasSarShape(candidate)) return { valid: false, reason: "bad_shape" };
  if (isExpired(candidate, now)) return { valid: false, reason: "expired" };

  const publicKey = await resolvePublicKey(candidate.did);
  if (!publicKey) return { valid: false, reason: "bad_signature" };

  const ok = await verifyCanonicalSignature(signedPart(candidate), candidate.signature, publicKey);
  return ok ? { valid: true, sar: candidate } : { valid: false, reason: "bad_signature" };
}
