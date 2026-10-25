// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ArohaDisclosure — a per-hop statement of "I am an AI agent, and this is
 * the principal I act for".
 *
 * WHY THIS EXISTS. An envelope already names the sending agent (`from`) and,
 * for a KEL identity, the key event log names its controlling person. But
 * neither is something a counterparty — or a human guest in a shared room —
 * can read as a plain statement. Transparency rules for AI systems (EU AI Act
 * Art. 50 and the Commission's guidelines) ask each agent in a chain to
 * disclose its artificial nature and the principal it acts for at each new
 * interaction. This object is that statement in protocol data.
 *
 * WHERE IT LIVES. As an optional `disclosure` field on ArohaEnvelope. The
 * envelope signature covers the whole message minus `proof`, so a disclosure
 * carried in an envelope is signed by the sending agent's key: it cannot be
 * stripped or altered in transit without the signature failing. It is also
 * the `disclosure` field of a conversation Room (spec "Conversation and
 * Memory Profile"), shown to every guest on joining.
 *
 * WHAT IT PROVES, AND WHAT IT DOES NOT. The signature proves the agent made
 * this statement. It does not prove `principalDid` actually authorised the
 * agent — that is the job of a mandate chain rooted in that principal. A
 * verifier that needs both checks both.
 */

/** Wire version of the disclosure object. */
export const DISCLOSURE_VERSION = 1 as const;

export interface ArohaDisclosure {
  v: 1;
  /** The disclosing agent's DID. In an envelope, MUST equal `from`. */
  agentDid: string;
  /** The person or organisation the agent acts for. */
  principalDid: string;
  /** Whether the principal is a natural person or an organisation. */
  principalKind: "person" | "organization";
  /** Short human-readable statement of what the agent is doing on the principal's behalf. */
  purpose: string;
  /** Position in the agent chain: 0 = the agent the principal addressed directly; +1 per delegation hop. */
  hop: number;
  /** Always true. Present so the AI-generated nature is an explicit field, not an inference. */
  aiGenerated: true;
}

/** Input to buildDisclosure: everything but the constants. `hop` defaults to 0. */
export interface DisclosureInput {
  agentDid: string;
  principalDid: string;
  principalKind: "person" | "organization";
  purpose: string;
  hop?: number;
}

/** Upper bound on `purpose`, so a disclosure stays a statement and not a payload. */
export const MAX_DISCLOSURE_PURPOSE_LENGTH = 512;

const KNOWN_FIELDS = new Set(["v", "agentDid", "principalDid", "principalKind", "purpose", "hop", "aiGenerated"]);

export type DisclosureValidation =
  | { valid: true; disclosure: ArohaDisclosure }
  | { valid: false; reason: string };

/** Build a disclosure object. Throws on input that validateDisclosure would refuse. */
export function buildDisclosure(input: DisclosureInput): ArohaDisclosure {
  const disclosure: ArohaDisclosure = {
    v: DISCLOSURE_VERSION,
    agentDid: input.agentDid,
    principalDid: input.principalDid,
    principalKind: input.principalKind,
    purpose: input.purpose,
    hop: input.hop ?? 0,
    aiGenerated: true,
  };
  const checked = validateDisclosure(disclosure);
  if (!checked.valid) throw new Error(`Invalid disclosure: ${checked.reason}`);
  return disclosure;
}

/**
 * Structural check of an untrusted disclosure. With `expectedAgentDid`
 * (an envelope's `from`), also refuses a disclosure made in another agent's
 * name — an agent must not disclose on behalf of someone else.
 *
 * Unknown fields are refused rather than ignored, for the same reason as
 * action receipts: a signed claim this verifier never evaluated is a claim a
 * downstream reader may assume was checked.
 */
export function validateDisclosure(
  value: unknown,
  opts: { expectedAgentDid?: string } = {},
): DisclosureValidation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, reason: "disclosure is not an object" };
  }
  const d = value as Record<string, unknown>;
  if (d.v !== DISCLOSURE_VERSION) return { valid: false, reason: `unsupported disclosure version ${String(d.v)}` };
  for (const k of ["agentDid", "principalDid", "purpose"] as const) {
    if (typeof d[k] !== "string" || (d[k] as string).length === 0) {
      return { valid: false, reason: `${k} must be a non-empty string` };
    }
  }
  if (!(d.agentDid as string).startsWith("did:") || !(d.principalDid as string).startsWith("did:")) {
    return { valid: false, reason: "agentDid and principalDid must be DIDs" };
  }
  if ((d.purpose as string).length > MAX_DISCLOSURE_PURPOSE_LENGTH) {
    return { valid: false, reason: `purpose exceeds ${MAX_DISCLOSURE_PURPOSE_LENGTH} characters` };
  }
  if (d.principalKind !== "person" && d.principalKind !== "organization") {
    return { valid: false, reason: "principalKind must be \"person\" or \"organization\"" };
  }
  if (typeof d.hop !== "number" || !Number.isInteger(d.hop) || d.hop < 0) {
    return { valid: false, reason: "hop must be a non-negative integer" };
  }
  if (d.aiGenerated !== true) return { valid: false, reason: "aiGenerated must be true" };
  for (const k of Object.keys(d)) {
    if (!KNOWN_FIELDS.has(k)) return { valid: false, reason: `unknown field "${k}"` };
  }
  if (opts.expectedAgentDid !== undefined && d.agentDid !== opts.expectedAgentDid) {
    return { valid: false, reason: `disclosure names agent ${String(d.agentDid)}, not the sender ${opts.expectedAgentDid}` };
  }
  return { valid: true, disclosure: d as unknown as ArohaDisclosure };
}
