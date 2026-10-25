// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Governed verifier profile — every protective mandate check ON, with no
 * way to leave one out by accident.
 *
 * WHY THIS EXISTS. Most of the strongest mandate guarantees are opt-in. With
 * default options a verifier proves only that a chain is internally
 * consistent back to SOME root key: no person root (an agent can mint its own
 * authority), no Key Event Log (a revoked identity's mandates keep working),
 * no revocation hook (a revoked mandate lives until expiry), no chain
 * requirement at the payment gate (a bare leaf can authorise a spend). Each
 * of those defaults is reasonable alone, for offline tests and audits; a
 * production gate that silently inherits all of them is not.
 *
 * governedVerification() builds the options object that turns all of them
 * on, and REFUSES to build it when a prerequisite is missing — a profile
 * without a revocation hook is not a weaker governed profile, it is not one
 * at all. The returned object carries `governed: true`, and the verifiers
 * (verifyMandateChain, verifyMandate, enforceSpendingConstraints) re-check
 * the prerequisites on every call, so a caller that spreads the profile and
 * drops or overrides a field gets a failed verification, not a quietly
 * weaker one.
 *
 * What the profile turns on:
 *   - requirePersonRoot  — the root must be a `did:aroha:E…` person whose KEL
 *                          verifies and is unrevoked;
 *   - kelSource          — every E-DID link is checked against its CURRENT
 *                          key, and a revoked identity or controller fails;
 *   - isRevoked          — consulted for every link; a hook that throws
 *                          fails the verification (fail closed);
 *   - requireChain       — enforceSpendingConstraints refuses a token that
 *                          does not verify back to a root;
 *   - a pinned root      — expectedRoot, expectedRootPerson or trustedRoots.
 *                          A person root alone is not enough: anyone can
 *                          incept a person identity, so the profile also
 *                          requires saying WHICH people (or roots) you trust.
 *
 * Fail-open revocation. The profile has no fail-open setting and never adds
 * one. It cannot inspect the hook it is given, so the operator remains
 * responsible for passing a hook that treats an unreachable revocation
 * source as a failure (the spec's MUST).
 */

import type { KelSource, KelStore } from "@aroha-sdk/core/identity";
import type { MandateRevocationCheck, VerifyMandateChainOptions } from "./mandate.js";

/** Inputs to governedVerification(). Every field the profile depends on is required by type AND checked at runtime. */
export interface GovernedVerificationInput {
  /** Key Event Log source (e.g. httpKelSource(registryUrl)). Required. */
  kelSource: KelSource;
  /** Highest-seen KEL memory. Recommended for long-lived verifiers. */
  kelStore?: KelStore;
  /** Revocation hook consulted for every link. Required; must fail closed. */
  isRevoked: MandateRevocationCheck;
  /** Root grantor must be exactly this DID. */
  expectedRoot?: string;
  /** Root grantor must be exactly this person DID. */
  expectedRootPerson?: string;
  /** Root grantor must be one of these DIDs (non-empty). */
  trustedRoots?: string[];
  /** Leaf grantee must be exactly this DID (normally the verifier's own). */
  expectedGrantee?: string;
  /** Maximum chain length, root and leaf included. Default 8. */
  maxDepth?: number;
  /** Not-before clock tolerance in ms. Default 30 000. */
  clockToleranceMs?: number;
}

/**
 * The options object governedVerification() returns. Assignable to
 * VerifyMandateChainOptions (pass it to verifyMandateChain as-is) and, with
 * `proposedAmountUsd` added, to EnforceSpendingConstraintsOptions.
 */
export type GovernedVerificationOptions = VerifyMandateChainOptions & {
  readonly governed: true;
  readonly requirePersonRoot: true;
  readonly requireChain: true;
  readonly kelSource: KelSource;
  readonly isRevoked: MandateRevocationCheck;
};

/** Thrown by governedVerification() when a prerequisite of the profile is missing. */
export class GovernedProfileError extends Error {
  readonly code = "GOVERNED_PREREQUISITE_MISSING";
  constructor(message: string) {
    super(message);
    this.name = "GovernedProfileError";
  }
}

/** The fixed switches of the governed profile; the inputs above supply the rest. */
export const GOVERNED_PROFILE = Object.freeze({
  governed: true,
  requirePersonRoot: true,
  requireChain: true,
} as const);

/**
 * Build verifier options with every protective check on. Throws
 * GovernedProfileError when kelSource, isRevoked or a root pin is missing.
 *
 *   const profile = governedVerification({ kelSource, isRevoked, trustedRoots: [aliceDid] });
 *   await verifyMandateChain(token, resolveKey, profile);
 *   await enforceSpendingConstraints(token, leafKey, { ...profile, proposedAmountUsd: 12 });
 */
export function governedVerification(input: GovernedVerificationInput): GovernedVerificationOptions {
  const options = {
    ...GOVERNED_PROFILE,
    kelSource: input.kelSource,
    kelStore: input.kelStore,
    isRevoked: input.isRevoked,
    expectedRoot: input.expectedRoot,
    expectedRootPerson: input.expectedRootPerson,
    trustedRoots: input.trustedRoots === undefined ? undefined : [...input.trustedRoots],
    expectedGrantee: input.expectedGrantee,
    maxDepth: input.maxDepth,
    clockToleranceMs: input.clockToleranceMs,
  };
  const gap = checkGovernedPrerequisites(options);
  if (gap) throw new GovernedProfileError(gap);
  return Object.freeze(options) as GovernedVerificationOptions;
}

/** The fields checkGovernedPrerequisites reads. */
interface GovernedFields {
  governed?: boolean;
  isRevoked?: unknown;
  kelSource?: unknown;
  requirePersonRoot?: boolean;
  expectedRoot?: string;
  expectedRootPerson?: string;
  trustedRoots?: string[];
}

/**
 * Returns null when `opts` is not governed or satisfies every prerequisite
 * of the governed profile, otherwise the first gap found. Used by the
 * profile builder and, on every call, by the mandate verifiers.
 */
export function checkGovernedPrerequisites(opts: GovernedFields): string | null {
  if (opts.governed !== true) return null;
  if (typeof opts.isRevoked !== "function") {
    return "governed profile: isRevoked is required (a revoked mandate would otherwise be accepted until it expires)";
  }
  if (!opts.kelSource) {
    return "governed profile: kelSource is required (identity revocation and person roots cannot be checked without it)";
  }
  if (opts.requirePersonRoot !== true && opts.expectedRootPerson === undefined) {
    return "governed profile: requirePersonRoot must stay on (otherwise an agent can mint its own root authority)";
  }
  const pinned = opts.expectedRoot !== undefined
    || opts.expectedRootPerson !== undefined
    || (Array.isArray(opts.trustedRoots) && opts.trustedRoots.length > 0);
  if (!pinned) {
    return "governed profile: a root pin is required — expectedRoot, expectedRootPerson or a non-empty trustedRoots";
  }
  return null;
}
