// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consult wire shapes (design spec §4).
 *
 * A consult travels as an ordinary ArohaRequest with capability "consult" —
 * no new message type and no protocol version bump. These are the `params`
 * and `result` payloads inside that envelope.
 *
 * These live in aroha-core rather than in any one consumer because two
 * implementations must agree on the field names to interoperate at all. The
 * Python SDK mirrors them in aroha/consult.py.
 */

/** What the consulted agent used to produce its answer (design spec §4.3). */
export interface ConsultSource {
  tool: string;
  summary: string;
}

export interface ConsultParams {
  /** A self-contained question. Never the caller's raw conversation history. */
  question: string;
  /** Optional subject-area hint, for the answering side's triage. */
  domainHint?: string;
  /** Consult hops already taken. A first-hop consult sends 1. */
  hopCount: number;
  /** DIDs already in this chain, in order. Used for cycle detection. */
  consultChain: string[];
}

export interface ConsultResult {
  answer: string;
  /** Tools consulted — makes an answer checkable rather than merely asserted. */
  sources: ConsultSource[];
  /**
   * Fingerprint of the answering agent's prompt/model (design spec §11.3 —
   * "behavioural versioning"). A department changing its agent's prompt or
   * model silently changes every consumer's results; this makes that change
   * DETECTABLE after the fact — not preventable, and not a contract that the
   * hash is stable across any particular change, only that an unchanged
   * agent produces an unchanged hash. Optional because not every answering
   * implementation computes one yet.
   */
  behaviourHash?: string;
}

/** The capability name a consult request carries. */
export const CONSULT_CAPABILITY = "consult";
