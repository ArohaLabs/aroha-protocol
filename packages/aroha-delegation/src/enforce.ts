// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Enforcing a verified task-mandate chain against what a request actually
// does — shared by serveDelegated() and createDelegationMiddleware().
//
// WHY THIS EXISTS. Verifying a chain proves who granted what. It does not,
// by itself, stop the request from doing something the grant excludes. The
// serving paths used to check only allowed/blocked capabilities (and only
// when the handler remembered to ask), so actionLimits, dataAccess,
// reversibleOnly and humanGates were signed declarations rather than
// enforced boundaries. Every serving path now runs the leaf's constraints
// (credentials' checkTaskConstraints, the same function enforceTaskConstraints
// uses) BEFORE the handler, against a TaskRequestScope that the server
// operator derives from the request.

import type { ArohaTaskMandateBody } from "@aroha-sdk/core";
import { checkTaskConstraints, TaskConstraintViolation } from "@aroha-sdk/credentials";

/**
 * What one request (or one action inside a handler) will do, as the SERVER
 * describes it — never as the caller claims it. The server operator's code
 * maps the request to the capability it invokes and the data it touches.
 */
export interface TaskRequestScope {
  /** Capability id the request invokes. Must be allowed (and not blocked) by the leaf mandate. */
  capability: string;
  /**
   * Data the request touches, resource key → access needed. Checked against
   * the leaf's taskConstraints.dataAccess (a resource missing from that map
   * is "none"). Declare everything the handler reads or writes; anything
   * left out is not checked.
   */
  dataAccess?: Record<string, "read" | "write" | "read-write">;
  /** Reversibility of the capability. Omitted = "irreversible" (fail closed under reversibleOnly). */
  reversibility?: "full" | "semi" | "irreversible";
  /** True only when a human has approved this action; required for capabilities in humanGates. */
  humanApproved?: boolean;
}

/**
 * Per-process invocation counts for actionLimits, keyed by (grantor,
 * mandateId) of EVERY link in the chain — so N sibling sub-delegations of
 * one parent cannot each spend the parent's full limit in this process.
 *
 * Limitation, stated plainly: the counts live in memory. They do not survive
 * a restart and are not shared between processes or servers; a mandate
 * presented to two servers gets each server's full limit. Bound the mandate's
 * lifetime accordingly.
 */
export class ActionCounter {
  private readonly counts = new Map<string, { expiresAt: number; byCap: Map<string, number> }>();

  constructor(private readonly maxEntries = 10_000) {}

  private key(m: ArohaTaskMandateBody): string {
    return `${m.grantor}\u0000${m.mandateId}`;
  }

  /** Current count of `capability` invocations under mandate `m`. */
  peek(m: ArohaTaskMandateBody, capability: string): number {
    return this.counts.get(this.key(m))?.byCap.get(capability) ?? 0;
  }

  /** Record one invocation of `capability` under mandate `m`. */
  record(m: ArohaTaskMandateBody, capability: string): void {
    const k = this.key(m);
    let entry = this.counts.get(k);
    if (!entry) {
      this.prune();
      entry = { expiresAt: Date.parse(m.expiresAt), byCap: new Map() };
      this.counts.set(k, entry);
    }
    entry.byCap.set(capability, (entry.byCap.get(capability) ?? 0) + 1);
  }

  /**
   * Drop entries for expired mandates — their limits no longer matter
   * because the mandate itself is refused. If still full, drop the oldest
   * entry rather than grow without bound.
   */
  private prune(): void {
    if (this.counts.size < this.maxEntries) return;
    const now = Date.now();
    for (const [k, v] of this.counts) if (!(v.expiresAt >= now)) this.counts.delete(k);
    if (this.counts.size >= this.maxEntries) {
      const oldest = this.counts.keys().next().value;
      if (oldest !== undefined) this.counts.delete(oldest);
    }
  }
}

/**
 * Check `scope` against a verified chain (root first, leaf last) and, when
 * it passes, record the invocation. Returns the violation or null.
 * Synchronous on purpose: check-then-record has no await between them, so
 * two concurrent requests cannot both pass a limit of 1.
 *
 * `prepaid`: the invocation was already counted (the request-level check
 * before the handler counted it), so every rule is re-checked EXCEPT the
 * action limits, and nothing is recorded. Without this, a handler that
 * asserts the capability its request was admitted for would be counted
 * twice — and refused at a limit of 1.
 */
export function enforceScope(
  chain: ArohaTaskMandateBody[],
  scope: TaskRequestScope,
  counter: ActionCounter,
  prepaid = false
): TaskConstraintViolation | null {
  const leaf = chain[chain.length - 1];
  const violation = checkTaskConstraints(leaf, {
    requestedCapability: scope.capability,
    currentActionCounts: prepaid ? {} : { [scope.capability]: counter.peek(leaf, scope.capability) },
    capabilityReversibility: scope.reversibility,
    dataAccess: scope.dataAccess,
    humanApproved: scope.humanApproved,
  });
  if (violation) return violation;
  if (prepaid) return null;

  // Ancestors' limits bind too: narrowing makes each child's limit ≤ its
  // parent's, but only the parent's own counter sees every sibling's use.
  for (const m of chain.slice(0, -1)) {
    const limit = m.taskConstraints?.actionLimits?.[scope.capability];
    if (limit === undefined) continue;
    const used = counter.peek(m, scope.capability);
    if (used >= limit) {
      return new TaskConstraintViolation(
        `Action limit exceeded for "${scope.capability}" under ancestor mandate ${m.mandateId}: ${used}/${limit}`,
        "ACTION_LIMIT_EXCEEDED"
      );
    }
  }

  for (const m of chain) counter.record(m, scope.capability);
  return null;
}
