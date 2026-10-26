// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// createDelegationMiddleware() — mandate-chain verification as an
// ArohaMiddleware, the same composability pattern @aroha-sdk/credentials'
// createRbacMiddleware() already uses.
//
// serveDelegated() (see serve-delegated.ts) wraps @aroha-sdk/run's serve()
// end to end — the right choice when you want its streaming/approval/
// receipt machinery too, but it means adopting delegation-based auth
// requires standing up a @aroha-sdk/run server specifically, not just adding
// a package to whatever ArohaServer-based host already exists. This is the
// other option: mandate-chain verification alone, as a middleware that
// mounts directly into ArohaServer's existing `middleware` array —
//
//   import { ArohaServer } from "@aroha-sdk/core";
//   import { createDelegationMiddleware, getVerifiedMandate } from "@aroha-sdk/delegation";
//
//   const server = new ArohaServer({
//     ...,
//     middleware: [createDelegationMiddleware({ identity, trustAnchors })],
//   });
//   // in onMessage:
//   const verified = getVerifiedMandate(envelope);   // undefined if require:false and none was sent
//
// No @aroha-sdk/run dependency in this path. You lose serveDelegated's
// automatic receipt stitching and ctx.delegate() convenience. What it does
// answer, before the handler runs: is there a valid mandate chain granting
// the caller access, AND is this request within the leaf mandate's
// constraints — allowed/blocked capability, actionLimits, dataAccess,
// reversibleOnly and humanGates. The second half is new: the middleware used
// to stop at the chain, so a verified mandate that excluded the requested
// capability (or the data it touched) still reached the handler.
// Attenuation/delegation calls remain the app's.

import { ArohaErrorCode, type ArohaEnvelope, type ArohaMiddleware } from "@aroha-sdk/core";
import type { KelSource, KelStore } from "@aroha-sdk/core/identity";
import type { MandateRevocationCheck } from "@aroha-sdk/credentials";
import {
  verifyTaskMandateChain, parseTaskMandateToken,
  assertRootTrustConfigured, checkRootTrust,
  DELEGATION_CONTEXT_KEY,
  type DelegationEnvelope, type ChainVerificationResult,
} from "./chain.js";
import { ActionCounter, enforceScope, type TaskRequestScope } from "./enforce.js";

export interface DelegationMiddlewareOptions {
  /** This server's own DID — incoming leaf mandates must be granted to it. */
  did: string;
  /**
   * Root issuers this server trusts, DID → raw/base64 Ed25519 public key.
   * One of trustAnchors / resolveRootKey is REQUIRED (construction throws
   * otherwise) unless allowUnpinnedRoot is set — see RootTrustOptions.
   */
  trustAnchors?: Record<string, Uint8Array | string>;
  /** Resolves a root grantor DID to its public key, for grantors not in trustAnchors. */
  resolveRootKey?: (grantorDid: string) => Promise<Uint8Array | null>;
  /** DEVELOPMENT ONLY: trust whatever root key the envelope carries. */
  allowUnpinnedRoot?: boolean;
  /** Resolves intermediate signer DIDs → public keys (chains longer than 1 hop). */
  resolvePublicKey?: (did: string) => Promise<Uint8Array | null>;
  /** Reject requests without a valid chain. Default: true. */
  require?: boolean;
  /** Task-mandate revocation hook, consulted for every link; a hook that throws rejects the request. */
  isRevoked?: MandateRevocationCheck;
  /** Key Event Log source: E-DID grantors are checked against their current key, revoked identities refused. */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. */
  kelStore?: KelStore;
  /** Maximum chain length accepted. Default 8. */
  maxDepth?: number;
  /**
   * Describe what an envelope does, so the leaf mandate's constraints are
   * enforced before the handler. Default: `{ capability: body.capability }`
   * — the capability the Aroha request names. Supply this to add the data a
   * capability touches (dataAccess), its reversibility, or a verified human
   * approval. Returning null rejects the envelope (403): a request whose
   * scope cannot be determined is not admitted.
   */
  requestScope?: (envelope: ArohaEnvelope) => TaskRequestScope | null | undefined | Promise<TaskRequestScope | null | undefined>;
}

/** Default scope: the capability named in the request body, nothing else. */
function defaultScope(envelope: ArohaEnvelope): TaskRequestScope | null {
  const cap = (envelope.body as unknown as Record<string, unknown> | undefined)?.capability;
  return typeof cap === "string" && cap.length > 0 ? { capability: cap } : null;
}

/** Reads `body.context.aroha` — same convention @aroha-sdk/run's RunRequest.context carries, so a DelegationEnvelope is wire-compatible with either hosting style. */
function extractFromEnvelope(envelope: ArohaEnvelope): DelegationEnvelope | null {
  const body = envelope.body as unknown as Record<string, unknown>;
  const context = body?.context as Record<string, unknown> | undefined;
  const raw = context?.[DELEGATION_CONTEXT_KEY] as Partial<DelegationEnvelope> | undefined;
  if (!raw || raw.v !== 1) return null;
  if (!Array.isArray(raw.chain) || raw.chain.length === 0) return null;
  if (typeof raw.rootKeyB64 !== "string" || typeof raw.correlationId !== "string") return null;
  return raw as DelegationEnvelope;
}

// Verified results are looked up by envelope identity, not stashed on the
// envelope object itself — keeps the wire shape untouched and avoids the
// TypeScript gymnastics of widening ArohaEnvelope's type just to carry an
// extra field only this middleware cares about.
const verifiedByEnvelope = new WeakMap<ArohaEnvelope, ChainVerificationResult>();

// Constraint violations go out as their spec Appendix A code (Aroha_*).
// Codes with no canonical counterpart keep their previous string.
const CANONICAL_CODES = new Set<string>(Object.values(ArohaErrorCode));
function violationCode(code: string): string {
  const canonical = `Aroha_${code}`;
  return CANONICAL_CODES.has(canonical) ? canonical : `ARHOA_${code}`;
}

/** Read the verified mandate chain result for an envelope, once createDelegationMiddleware has run. Undefined if no chain was sent and require:false. */
export function getVerifiedMandate(envelope: ArohaEnvelope): ChainVerificationResult | undefined {
  return verifiedByEnvelope.get(envelope);
}

export function createDelegationMiddleware(options: DelegationMiddlewareOptions): ArohaMiddleware {
  const { did, resolvePublicKey, require = true } = options;
  // Fail at construction, not per request: a server without a root of trust
  // would otherwise accept any self-issued chain.
  assertRootTrustConfigured(options, "createDelegationMiddleware");
  const counter = new ActionCounter();

  return async (envelope, reject) => {
    const delegationEnvelope = extractFromEnvelope(envelope);
    if (!delegationEnvelope) {
      if (require) {
        reject(400, "ARHOA_NO_MANDATE", "Missing delegation envelope (body.context.aroha) — this server requires a mandate chain");
      }
      return;
    }

    let rootGrantor: string;
    try {
      rootGrantor = parseTaskMandateToken(delegationEnvelope.chain[0]).mandate.grantor;
    } catch {
      reject(400, "ARHOA_CHAIN_INVALID", "Malformed root mandate token");
      return;
    }

    const untrusted = await checkRootTrust(rootGrantor, delegationEnvelope.rootKeyB64, options);
    if (untrusted) {
      const code = untrusted.startsWith("Untrusted") ? "ARHOA_UNTRUSTED_ROOT" : "ARHOA_ROOT_KEY_MISMATCH";
      reject(403, code, untrusted);
      return;
    }

    const result = await verifyTaskMandateChain(
      delegationEnvelope.chain,
      new Uint8Array(Buffer.from(delegationEnvelope.rootKeyB64, "base64")),
      {
        expectedGrantee: did, resolvePublicKey,
        isRevoked: options.isRevoked, kelSource: options.kelSource, kelStore: options.kelStore, maxDepth: options.maxDepth,
      },
    );
    if (!result.valid) {
      reject(403, "ARHOA_CHAIN_REJECTED", `Mandate chain rejected: ${result.reason}`);
      return;
    }

    let scope: TaskRequestScope | null | undefined;
    try {
      scope = options.requestScope ? await options.requestScope(envelope) : defaultScope(envelope);
    } catch (err) {
      reject(403, "ARHOA_SCOPE_UNKNOWN", `Could not determine the request scope: ${(err as Error).message}`);
      return;
    }
    if (!scope) {
      reject(403, "ARHOA_SCOPE_UNKNOWN", "Request scope could not be determined (no capability); refusing to run outside the mandate");
      return;
    }
    const violation = enforceScope(result.mandates!, scope, counter);
    if (violation) {
      reject(403, violationCode(violation.code), `Mandate constraint violated: ${violation.message}`);
      return;
    }

    verifiedByEnvelope.set(envelope, result);
  };
}
