// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Mandate-chain verification — the chain-of-custody primitive for multi-hop
// agent networks (A → B → C → …).
//
// verifyTaskMandate() checks ONE link. This module checks the WHOLE chain:
// every signature, grantor→grantee continuity, parentMandateId linkage,
// expiry containment, allowed-subset narrowing, and delegation depth.
//
// Depth is enforced HERE, not in @aroha-sdk/credentials: attenuateTaskMandate
// narrows allowed/limits but does not decrement maxDelegationDepth. The chain
// verifier is the component with visibility over the full path, so it owns the
// depth rule:
//   parent.maxDelegationDepth === 0        → no child may follow
//   parent.maxDelegationDepth === n        → child must declare ≤ n − 1
//   parent.maxDelegationDepth === undefined → no per-link limit, but the
//                                            whole chain is still capped at
//                                            ChainVerifyOptions.maxDepth
//                                            (default 8, the same bound
//                                            spending-mandate chains have)
//
// The cap used to be absent: a root that set no maxDelegationDepth allowed
// sub-agents to delegate to sub-agents without end, and nothing bounded how
// far authority could travel from the person who granted it.

import type { ArohaTaskMandateBody } from "@aroha-sdk/core";
import { isInceptionDid, type KelSource, type KelStore } from "@aroha-sdk/core/identity";
import {
  checkTaskMandateShape, checkTaskNarrowing, checkTaskRevocation, createKelLookup,
  taskMandateTokenVersion, verifyTaskMandateSignature,
  type SignedTaskMandate, type MandateRevocationCheck,
} from "@aroha-sdk/credentials";
import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";

/** Default cap on task-mandate chain length (root and leaf included) when maxDepth is not set. */
export const DEFAULT_TASK_CHAIN_MAX_DEPTH = 8;

/** Key under RunRequest.context that carries the delegation envelope. */
export const DELEGATION_CONTEXT_KEY = "aroha";

/**
 * The envelope that rides RunRequest.context.aroha from hop to hop.
 * chain[0] is the root mandate; chain[chain.length − 1] is granted to the
 * receiving agent. Each hop appends exactly one token.
 */
export interface DelegationEnvelope {
  v: 1;
  chain: string[];
  /** base64 raw Ed25519 public key of chain[0]'s grantor — the trust anchor. */
  rootKeyB64: string;
  /** Propagated unchanged across every hop for end-to-end tracing. */
  correlationId: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  /** The leaf mandate — the authority granted to `expectedGrantee`. */
  mandate?: ArohaTaskMandateBody;
  /** Every mandate in the chain, root first. Present when valid. */
  mandates?: ArohaTaskMandateBody[];
  /** Number of links, i.e. hops from the root issuer. */
  depth: number;
  reason?: string;
}

export interface ChainVerifyOptions {
  /** The verifying agent's DID — matched against the leaf's grantee. */
  expectedGrantee?: string;
  /**
   * Resolves an intermediate grantor DID to its raw Ed25519 public key.
   * Required for chains longer than one link (link i>0 is signed by the
   * previous hop, whose key is not the root key). Return null for unknown
   * DIDs — the chain is then rejected.
   */
  resolvePublicKey?: (did: string) => Promise<Uint8Array | null>;
  /**
   * Revocation hook, consulted for EVERY link with (mandateId, grantor) —
   * revoking the root task mandate kills every sub-delegation beneath it. A
   * hook that throws rejects the chain (fail closed).
   */
  isRevoked?: MandateRevocationCheck;
  /**
   * Key Event Log source for rotatable `did:aroha:E…` DIDs, as for spending
   * mandates. When set, every E-DID grantor's signature is checked against
   * its CURRENT key from the verified log (overriding rootPublicKey and
   * resolvePublicKey for that DID — the log, not a resolver, is
   * authoritative), and a link whose grantor or grantee is revoked, or whose
   * controller has been revoked, rejects the chain. A missing, stale or
   * forked log rejects it too.
   */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. */
  kelStore?: KelStore;
  /**
   * Maximum number of links accepted, root and leaf included. Default
   * DEFAULT_TASK_CHAIN_MAX_DEPTH (8). Applies whether or not the mandates
   * set maxDelegationDepth.
   */
  maxDepth?: number;
}

/** Thrown by parseTaskMandateToken for a token that is not a well-formed task mandate. */
export class TaskMandateTokenError extends Error {
  readonly code = "MALFORMED_TASK_MANDATE";
  constructor(message: string) {
    super(message);
    this.name = "TaskMandateTokenError";
  }
}

/**
 * Decode a task-mandate token and validate its shape.
 *
 * Throws TaskMandateTokenError (it used to return null) and runs the SAME
 * structural check as @aroha-sdk/credentials' verifyTaskMandate. WHY: the
 * old check only asked "is there a mandate and a signature", so a link with
 * an unparseable expiresAt or a non-array `allowed` reached the comparisons
 * below — and `NaN < now` is false, which read as "not expired". Does NOT
 * verify the signature; callers that act on the result must still verify it.
 */
export function parseTaskMandateToken(token: string): SignedTaskMandate {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    throw new TaskMandateTokenError("Malformed task mandate token: not base64url JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TaskMandateTokenError("Malformed task mandate token: not an object");
  }
  const raw = parsed as Record<string, unknown>;
  if (typeof raw.signature !== "string" || raw.signature.length === 0) {
    throw new TaskMandateTokenError("Malformed task mandate token: signature missing");
  }
  const v = taskMandateTokenVersion(raw);
  if (v === null) throw new TaskMandateTokenError(`Malformed task mandate token: unsupported version ${String(raw.v)}`);
  const shape = checkTaskMandateShape(raw.mandate);
  if (shape) throw new TaskMandateTokenError(`Malformed task mandate token: ${shape}`);
  return { mandate: raw.mandate as ArohaTaskMandateBody, signature: raw.signature, token, v };
}

/** Non-throwing form for call sites that branch on validity. */
function tryParseTaskMandateToken(token: string): SignedTaskMandate | string {
  try {
    return parseTaskMandateToken(token);
  } catch (err) {
    return err instanceof Error ? err.message : "Malformed task mandate token";
  }
}

/**
 * Verify a full TASK-mandate delegation chain, root → leaf.
 *
 * Fails closed: any missing key, broken linkage, widened scope, blown depth,
 * revoked link (when isRevoked is given), revoked identity (when kelSource is
 * given) or expired link rejects the whole chain.
 *
 * Signatures: each link is checked under the rule its own token version
 * names (v2 purpose-tagged JCS, or legacy v1), via the same function
 * @aroha-sdk/credentials' verifyTaskMandate uses — the local copy of the v1
 * canonicaliser that used to live here is gone, so the two cannot drift.
 *
 * Named for task mandates because @aroha-sdk/credentials now exports its own
 * `verifyMandateChain` for SPENDING mandates, with a different signature. A
 * consumer importing both packages would otherwise get two functions with
 * one name and no compiler warning about which it had.
 */
export async function verifyTaskMandateChain(
  chain: string[],
  rootPublicKey: Uint8Array,
  options: ChainVerifyOptions = {}
): Promise<ChainVerificationResult> {
  if (!Array.isArray(chain) || chain.length === 0) {
    return { valid: false, depth: 0, reason: "Empty mandate chain" };
  }
  const maxDepth = options.maxDepth ?? DEFAULT_TASK_CHAIN_MAX_DEPTH;
  if (chain.length > maxDepth) {
    return { valid: false, depth: chain.length, reason: `Delegation depth exceeded: chain has ${chain.length} links; maximum is ${maxDepth}` };
  }
  const kelStateOf = options.kelSource ? createKelLookup(options.kelSource, options.kelStore) : null;

  const parsed: SignedTaskMandate[] = [];
  for (let i = 0; i < chain.length; i++) {
    const p = tryParseTaskMandateToken(chain[i]);
    if (typeof p === "string") return { valid: false, depth: chain.length, reason: `${p} at link ${i}` };
    parsed.push(p);
  }

  const now = Date.now();

  for (let i = 0; i < parsed.length; i++) {
    const { mandate } = parsed[i];
    const at = `link ${i}`;

    // ── Expiry ────────────────────────────────────────────────────────────
    // Date.parse, not `new Date(x) < now`: an unparseable date is NaN, every
    // comparison with NaN is false, and the old form read that as "not
    // expired". The shape check above already rejects non-dates; this is
    // the belt to its braces.
    const expiresAtMs = Date.parse(mandate.expiresAt);
    if (Number.isNaN(expiresAtMs) || expiresAtMs < now) {
      return { valid: false, depth: chain.length, reason: `Mandate expired at ${at}` };
    }
    if (expiresAtMs < Date.parse(mandate.issuedAt)) {
      return { valid: false, depth: chain.length, reason: `Mandate expires before it was issued at ${at}` };
    }

    // ── Signature ─────────────────────────────────────────────────────────
    let signerKey: Uint8Array | null;
    if (kelStateOf && isInceptionDid(mandate.grantor)) {
      // The verified log is authoritative for an E-DID: a revoked grantor
      // (or one whose controller is revoked) cannot have issued a live link.
      const r = await kelStateOf(mandate.grantor);
      if ("error" in r) {
        return { valid: false, depth: chain.length, reason: `Grantor ${mandate.grantor} at ${at}: ${r.error}` };
      }
      const current = r.state.currentKey;
      if (!current) {
        return { valid: false, depth: chain.length, reason: `Grantor ${mandate.grantor} at ${at}: Key Event Log has no current key` };
      }
      signerKey = current;
      // The root key the envelope carries must BE that current key, or the
      // trust-anchor check upstream pinned a key the log has since replaced.
      if (i === 0 && !sameKey(current, rootPublicKey)) {
        return { valid: false, depth: chain.length, reason: `Root key does not match the current key in ${mandate.grantor}'s Key Event Log` };
      }
    } else if (i === 0) {
      signerKey = rootPublicKey;
    } else {
      if (!options.resolvePublicKey) {
        return {
          valid: false, depth: chain.length,
          reason: `Chain has ${chain.length} links but no resolvePublicKey to verify intermediate signers`,
        };
      }
      signerKey = await options.resolvePublicKey(mandate.grantor);
      if (!signerKey) {
        return { valid: false, depth: chain.length, reason: `Unknown signer key for ${mandate.grantor} at ${at}` };
      }
    }
    if (!(await verifyTaskMandateSignature(parsed[i], signerKey))) {
      return { valid: false, depth: chain.length, reason: `Invalid signature at ${at}` };
    }

    // ── Grantee identity (KEL) ────────────────────────────────────────────
    // The grantee holds this link's authority: if its identity was revoked,
    // so was that authority.
    if (kelStateOf && isInceptionDid(mandate.grantee)) {
      const r = await kelStateOf(mandate.grantee);
      if ("error" in r) {
        return { valid: false, depth: chain.length, reason: `Grantee ${mandate.grantee} at ${at}: ${r.error}` };
      }
    }

    // ── Revocation ────────────────────────────────────────────────────────
    // Checked on EVERY link, root included: revoking the person's root task
    // mandate must stop every sub-agent beneath it, not only the first hop.
    const revoked = await checkTaskRevocation(mandate, options.isRevoked);
    if (revoked) return { valid: false, depth: chain.length, reason: `${revoked} (${at})` };

    // ── Linkage + narrowing against the previous hop ──────────────────────
    if (i > 0) {
      const parent = parsed[i - 1].mandate;

      if (mandate.grantor !== parent.grantee) {
        return {
          valid: false, depth: chain.length,
          reason: `Broken custody at ${at}: grantor ${mandate.grantor} is not previous grantee ${parent.grantee}`,
        };
      }
      if (mandate.parentMandateId !== parent.mandateId) {
        return { valid: false, depth: chain.length, reason: `parentMandateId mismatch at ${at}` };
      }
      // ── Narrowing: every constraint the parent sets must survive ────────
      // checkTaskNarrowing is the SAME function attenuateTaskMandate runs on
      // the issuing side. Here it is the security control: an issuing agent
      // can skip its own check, and before this the verifier only compared
      // allowed/blocked/expiry — so a child that simply omitted the parent's
      // actionLimits, humanGates, reversibleOnly, dataAccess, spending
      // constraints or invariants carried more authority than its parent
      // and still verified. Omission is widening.
      const widened = checkTaskNarrowing(parent, mandate);
      if (widened) {
        return { valid: false, depth: chain.length, reason: `Scope widened at ${at}: ${widened}` };
      }

      // ── Delegation depth ────────────────────────────────────────────────
      const parentDepth = parent.taskConstraints?.maxDelegationDepth;
      if (parentDepth !== undefined) {
        if (parentDepth <= 0) {
          return {
            valid: false, depth: chain.length,
            reason: `Delegation depth exceeded at ${at}: parent forbids sub-delegation (maxDelegationDepth=0)`,
          };
        }
        const childDepth = mandate.taskConstraints?.maxDelegationDepth;
        if (childDepth === undefined || childDepth > parentDepth - 1) {
          return {
            valid: false, depth: chain.length,
            reason: `Delegation depth exceeded at ${at}: child must declare maxDelegationDepth ≤ ${parentDepth - 1}`,
          };
        }
      }
    }
  }

  const leaf = parsed[parsed.length - 1].mandate;
  if (options.expectedGrantee && leaf.grantee !== options.expectedGrantee) {
    return {
      valid: false, depth: chain.length,
      reason: `Leaf grantee ${leaf.grantee} does not match expected ${options.expectedGrantee}`,
    };
  }

  return {
    valid: true,
    mandate: leaf,
    mandates: parsed.map((p) => p.mandate),
    depth: chain.length,
  };
}

// ── Public-key resolvers ──────────────────────────────────────────────────────

/** Resolver backed by a static DID → key map. Keys may be base64 or raw bytes. */
export function staticResolver(
  keys: Record<string, Uint8Array | string>
): (did: string) => Promise<Uint8Array | null> {
  const normalised = new Map<string, Uint8Array>();
  for (const [did, key] of Object.entries(keys)) {
    normalised.set(did, typeof key === "string" ? new Uint8Array(Buffer.from(key, "base64")) : key);
  }
  return async (did) => normalised.get(did) ?? null;
}

/**
 * Resolver backed by the Aroha registry: DID → keccak256 didHash → record →
 * publicKeyB64. Defaults to the Aroha-managed registry (AROHA_REGISTRY_URL
 * overrides). Found keys are cached for `cacheTtlMs`; misses and errors are
 * never cached, so a newly registered or rotated key is picked up.
 */
export interface RegistryResolverOptions {
  /** How long a resolved key is reused, in ms. Default 5 minutes. */
  cacheTtlMs?: number;
  /** Per-lookup timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Bound on cached DIDs; the oldest entry is evicted past it. Default 1000. */
  maxEntries?: number;
}

export function registryResolver(
  registryUrl?: string,
  options: RegistryResolverOptions = {}
): (did: string) => Promise<Uint8Array | null> {
  const base = resolveRegistryUrl(registryUrl);
  const ttl = options.cacheTtlMs ?? 5 * 60_000;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxEntries = options.maxEntries ?? 1_000;
  // Positive results only, each with an expiry. WHY: the cache used to live
  // for the whole process and also remembered "not found" — so a key rotated
  // in the registry was never picked up, and one failed lookup (an agent not
  // yet registered, a registry 5xx) locked that DID out until restart.
  const cache = new Map<string, { key: Uint8Array; expires: number }>();
  return async (did) => {
    const hit = cache.get(did);
    if (hit && hit.expires > Date.now()) return hit.key;
    if (hit) cache.delete(did);
    try {
      const { keccak_256 } = await import("@noble/hashes/sha3");
      const hash = keccak_256(new TextEncoder().encode(did));
      const didHash = "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
      const res = await fetch(`${base}/v1/agents/${encodeURIComponent(didHash)}`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) return null;
      const record = (await res.json()) as { publicKeyB64?: string };
      if (typeof record.publicKeyB64 !== "string") return null;
      const key = new Uint8Array(Buffer.from(record.publicKeyB64, "base64"));
      if (key.length !== 32) return null;
      if (cache.size >= maxEntries) {
        const oldest = cache.keys().next().value;
        if (oldest !== undefined) cache.delete(oldest);
      }
      cache.set(did, { key, expires: Date.now() + ttl });
      return key;
    } catch {
      return null;
    }
  };
}

/** Extract a delegation envelope from a RunRequest context, if present and sane. */
export function extractEnvelope(
  context: Record<string, unknown> | undefined
): DelegationEnvelope | null {
  const raw = context?.[DELEGATION_CONTEXT_KEY] as Partial<DelegationEnvelope> | undefined;
  if (!raw || raw.v !== 1) return null;
  if (!Array.isArray(raw.chain) || raw.chain.length === 0) return null;
  if (typeof raw.rootKeyB64 !== "string" || typeof raw.correlationId !== "string") return null;
  return raw as DelegationEnvelope;
}

// The deprecated `verifyMandateChain` alias of verifyTaskMandateChain was
// REMOVED (breaking). WHY: @aroha-sdk/credentials exports a
// `verifyMandateChain` for SPENDING mandates with a different signature
// (token, resolveKey, opts) and different guarantees (it is the payee's money
// gate). A consumer importing both packages could reach for the credentials
// one and get the task-chain verifier instead — the compiler would only
// complain if the argument types happened not to line up, and a mistaken
// gate is exactly the kind of bug that passes every happy-path test. One name
// per guarantee: use verifyTaskMandateChain here, verifyMandateChain from
// @aroha-sdk/credentials for spending.

// ── Root-of-trust pinning ─────────────────────────────────────────────────────

/**
 * How a receiving agent decides that chain[0]'s grantor is someone it trusts.
 *
 * The envelope carries `rootKeyB64` — the key chain[0] is verified against.
 * Without pinning, that key is whatever the CALLER put there, so a chain that
 * "verifies" only proves it is self-consistent: anyone can mint a root
 * mandate with their own key and grant themselves anything. Pinning ties the
 * root grantor DID to a key the receiver already knows.
 */
export interface RootTrustOptions {
  /** Root issuers this agent trusts, DID → raw/base64 Ed25519 public key. */
  trustAnchors?: Record<string, Uint8Array | string>;
  /**
   * Resolves a root grantor DID to its Ed25519 public key (e.g. from a DID
   * document or the registry). Consulted for grantors not in trustAnchors.
   * Return null for unknown DIDs — the chain is then rejected.
   */
  resolveRootKey?: (grantorDid: string) => Promise<Uint8Array | null>;
  /**
   * DEVELOPMENT ONLY. Accept whatever root key the envelope carries. The
   * chain is then checked for internal consistency only, not for who issued
   * it. Required to run without trustAnchors or resolveRootKey; never set it
   * on an agent reachable by parties you do not control.
   */
  allowUnpinnedRoot?: boolean;
}

function rootKeyBytes(key: Uint8Array | string): Uint8Array {
  return typeof key === "string" ? new Uint8Array(Buffer.from(key, "base64")) : key;
}

function sameKey(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Throws unless a root of trust is configured. Called when a server is
 * CONSTRUCTED, so a missing trust anchor is a startup error instead of a
 * server that quietly accepts self-issued chains.
 */
export function assertRootTrustConfigured(options: RootTrustOptions, where: string): void {
  const hasAnchors = options.trustAnchors !== undefined && Object.keys(options.trustAnchors).length > 0;
  if (hasAnchors || options.resolveRootKey || options.allowUnpinnedRoot === true) return;
  throw new Error(
    `${where}: trustAnchors or resolveRootKey is required. Without one, any caller can sign its own ` +
      `root mandate. Pass allowUnpinnedRoot: true only for local development.`
  );
}

/**
 * Check the envelope's root key against the configured root of trust.
 * Returns null when trusted, or the reason it is not.
 */
export async function checkRootTrust(
  rootGrantor: string,
  rootKeyB64: string,
  options: RootTrustOptions
): Promise<string | null> {
  const envelopeKey = new Uint8Array(Buffer.from(rootKeyB64, "base64"));
  const anchor = options.trustAnchors?.[rootGrantor];
  if (anchor !== undefined) {
    return sameKey(rootKeyBytes(anchor), envelopeKey)
      ? null
      : `Envelope root key does not match trust anchor for ${rootGrantor}`;
  }
  if (options.resolveRootKey) {
    let resolved: Uint8Array | null;
    try {
      resolved = await options.resolveRootKey(rootGrantor);
    } catch {
      resolved = null;
    }
    if (!resolved) return `Untrusted root issuer: ${rootGrantor}`;
    return sameKey(resolved, envelopeKey)
      ? null
      : `Envelope root key does not match resolved key for ${rootGrantor}`;
  }
  if (options.allowUnpinnedRoot === true) return null;
  return `Untrusted root issuer: ${rootGrantor}`;
}
