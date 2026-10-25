// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consult loop prevention (design spec §3.2).
 *
 * Two independent limits, because neither alone is sufficient:
 *
 *   - A hop count bounds depth. Alone it cannot stop A→B→A→B, which stays
 *     under any limit for a while and burns two agents' budgets doing it.
 *   - A chain membership check stops cycles. Alone it cannot stop
 *     A→B→C→D→E→…, an unbounded line of distinct agents.
 *
 * Both checks are cheap and run on the RECEIVING side, before any model or
 * tool is touched. An agent that trusts a caller's self-reported hop count
 * is trusting the party with the motive to lie about it, so treat these as
 * a defence against accidents and misconfiguration; the peer allowlist is
 * what defends against a hostile caller.
 *
 * Refusal order is fixed and MUST match across implementations: malformed,
 * then hop limit, then cycle. The reason string lands in both parties' audit
 * logs, so two implementations disagreeing about which reason to report for
 * a request that violates several rules makes those logs unreconcilable.
 */

/** Consult depth allowed by default before an agent refuses (design spec §3.2). */
export const DEFAULT_MAX_CONSULT_HOPS = 3;

/** The subset of ConsultParams the guard needs. */
export interface ConsultLoopState {
  hopCount: number;
  consultChain: string[];
}

export type ConsultLoopVerdict =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Decide whether an inbound consult may be served.
 *
 * @param state     hop count and chain as received from the caller
 * @param ownDid    this agent's DID — presence in the chain means a cycle
 * @param maxHops   depth limit; defaults to DEFAULT_MAX_CONSULT_HOPS
 */
export function checkConsultLoop(
  state: ConsultLoopState,
  ownDid: string,
  maxHops: number = DEFAULT_MAX_CONSULT_HOPS,
): ConsultLoopVerdict {
  const { hopCount, consultChain } = state;

  if (!Number.isInteger(hopCount) || hopCount < 1) {
    return {
      ok: false,
      reason: `malformed consult: hopCount must be a positive integer, got ${hopCount}`,
    };
  }

  // A well-formed sender increments the count and appends to the chain
  // together (see nextConsultHop), so the chain can never be LONGER than the
  // hop count. When it is, the two disagree about how far this consult has
  // travelled, and the hop count is the smaller — i.e. the one that would
  // evade the depth limit.
  //
  // This does not make the guard safe against a determined liar: both fields
  // are self-reported, and a caller willing to trim the chain to match can
  // still under-report depth. It costs nothing, catches the inconsistent
  // case, and means evading the limit now also means destroying the very
  // evidence cycle detection runs on.
  if (consultChain.length > hopCount) {
    return {
      ok: false,
      reason:
        `malformed consult: the chain names ${consultChain.length} agents but hopCount is ` +
        `${hopCount} — a well-formed consult increments both together`,
    };
  }

  if (hopCount > maxHops) {
    return {
      ok: false,
      reason: `consult refused: hop ${hopCount} exceeds the limit of ${maxHops}`,
    };
  }

  if (consultChain.includes(ownDid)) {
    return {
      ok: false,
      reason: `consult refused: cycle — ${ownDid} is already in the consult chain`,
    };
  }

  return { ok: true };
}

/**
 * Build the hop count and chain to send on an OUTBOUND consult.
 *
 * Call this whether originating a consult (hopCount 0, empty chain) or
 * relaying one received from someone else — the arithmetic is the same, and
 * having one function for both is what keeps an originator from forgetting
 * to append itself and thereby erasing its own name from the cycle check.
 *
 * Returns a new array; the caller's chain is never mutated.
 */
export function nextConsultHop(
  hopCount: number,
  consultChain: string[],
  ownDid: string,
): { hopCount: number; consultChain: string[] } {
  return {
    hopCount: hopCount + 1,
    consultChain: [...consultChain, ownDid],
  };
}
