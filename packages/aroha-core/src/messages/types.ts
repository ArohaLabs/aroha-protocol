// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 3 Message Type Definitions
 *
 * All message types defined by the Aroha spec (aroha/1.0).
 * These are the ONLY valid values for the "type" field in a Aroha envelope.
 *
 * Applications may not invent new top-level message types — they extend
 * behavior through the "body" field only.
 */

// ─── Credential Token (Layer 1 extension — carried in message body) ──────────
//
// Human-triggered messages attach a base64url HumanCredential token here.
// Provider agents verify the token against the issuer's public key.
// Agent-to-agent messages omit this field; roles are resolved from the DID.

export interface WithCredential {
  /**
   * Registry-based auth: the credential ID returned on registration.
   * The receiving agent resolves the full credential from the registry.
   * Preferred over credentialToken for repeated calls — shorter and revocable.
   */
  credentialId?: string;
  /**
   * Inline auth: base64url-encoded signed HumanCredential.
   * Used when no shared registry is available (e.g. first call or direct peer).
   * If credentialId is also present, credentialId takes precedence.
   */
  credentialToken?: string;
}

// ─── Preference Context (Layer 5, carried in message body) ───────────────────

export interface PreferenceContext {
  budget?: { max: number; currency: string };
  quality?: { minRating?: number };
  accessibility?: Record<string, boolean | string>;
  constraints?: string[];
  /** Signed VC granting the recipient access to read this context */
  consentToken?: string;
}

// ─── Message Body Definitions ─────────────────────────────────────────────────

export interface ArohaRequestBody extends WithCredential {
  capability: string;
  params: Record<string, unknown>;
  preferenceContext?: PreferenceContext;
  /**
   * Idempotency key — if set, the receiving agent deduplicates requests with
   * the same key from the same sender within a 24-hour window.
   * Prevents duplicate side effects on retried requests (e.g. double-booking).
   * Use a UUID generated once per logical operation, not per retry attempt.
   */
  idempotencyKey?: string;
}

export interface ArohaResponseBody {
  capability: string;
  result: Record<string, unknown>;
}

export interface ArohaStreamBody {
  capability: string;
  progressPct: number; // 0–100
  event: string;
  data?: Record<string, unknown>;
}

// ─── Capability Schema Negotiation (CSN) ─────────────────────────────────────
// Extends the existing ArohaNegotiate flow with intent-based capability
// discovery. Structural JSON Schema matching is deterministic and preferred;
// an LLM matcher is used only when schema matching is ambiguous.
// Agreed mappings are SHA-256 cached for zero-round-trip reuse.

export interface CapabilitySchemaShape {
  /** JSON Schema for the capability's input body (params field). */
  input: Record<string, unknown>;
  /** JSON Schema for the capability's expected output (result field). */
  output?: Record<string, unknown>;
}

export interface CSNNegotiateExtension {
  /**
   * Natural-language description of what the requestor needs.
   * The provider uses this as a hint when structural schema matching is
   * ambiguous. Absent means "use schema-only matching".
   */
  capabilityIntent?: string;
  /**
   * JSON Schema of the requestor's expected interface.
   * The provider runs structural compatibility matching against its registry.
   * If a high-confidence match is found, no LLM call is needed.
   */
  desiredSchema?: CapabilitySchemaShape;
  /**
   * SHA-256 hex of the canonical desiredSchema JSON.
   * The provider checks its cache first — if a mapping exists for this hash
   * and this sender DID, the negotiation resolves in < 1ms without LLM.
   */
  schemaHash?: string;
  /**
   * If true, the provider returns its full signed capability manifest
   * in the ArohaAccept body. The requestor caches it for future calls.
   */
  requestCapabilityManifest?: boolean;
  /**
   * When true, the provider MUST NOT use LLM-based fuzzy matching.
   * If structural/cache match fails, return ArohaError with code CSN_NO_STRUCTURAL_MATCH.
   */
  disallowLLMFallback?: boolean;
}

export interface CapabilityManifestEntry {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  supportsSaga: boolean;
  defaultPricing?: { model: "per-call" | "subscription" | "negotiated"; amount?: number; currency?: string };
  defaultSLA?: { maxResponseMs: number; p99Ms?: number };
}

export interface SignedCapabilityManifest {
  agentDID: string;
  capabilities: CapabilityManifestEntry[];
  generatedAt: string;
  /**
   * Settlement rail identifiers this agent accepts (design spec §8.1) —
   * e.g. "stripe", "usdc-base", "ap2", "quota", "api-key". Mirrors the same
   * concept in aroha-registry's SAR (`UnsignedSar.settlementRails`); this is
   * the pre-registration form a provider serves directly during negotiation
   * (see CSNHandlerOptions.settlementRails / matchSettlementRail in
   * @aroha-sdk/orchestrator), while the SAR field is what a federated index
   * carries. Absent or empty means "not yet advertised" — treated as "any
   * rail acceptable" by matchSettlementRail so this stays backward
   * compatible with providers that haven't opted in.
   */
  settlementRails?: string[];
  /** Ed25519 signature over the canonical manifest JSON. */
  signature: string;
}

/**
 * A specific settlement rail proposed for a transaction (design spec §8.1).
 * `rail` is one of the adapter identifiers a provider might advertise via
 * SignedCapabilityManifest.settlementRails / SAR settlementRails — e.g.
 * "stripe", "usdc-base", "ap2", "quota", "api-key". `asset`/`destination`
 * are rail-specific (e.g. a token symbol + wallet address for a crypto
 * rail, or absent entirely for "quota").
 */
export interface ArohaSettlementTerm {
  rail: string;
  asset?: string;
  destination?: string;
}

export interface ArohaNegotiateBody {
  capability: string;
  proposedTerms: {
    price?: { amount: number; currency: string };
    sla?: { maxResponseMs: number; uptime: number };
    validForMs?: number;
    /** The settlement rail the requestor wants to pay on (design spec §8.1). */
    settlement?: ArohaSettlementTerm;
    /**
     * DID of a third party both sides agree to accept a binding decision
     * from if a dispute arises (design spec §8.3). Absent means no dispute
     * path is available for this transaction beyond ordinary compensation.
     */
    arbiterDid?: string;
    [key: string]: unknown;
  };
  /** CSN extension — omit for traditional price/SLA-only negotiation. */
  csn?: CSNNegotiateExtension;
}

export interface CSNAcceptExtension {
  /**
   * The actual registered capability name that matched the intent/schema.
   * May differ from the `capability` field when CSN resolves an alias.
   */
  resolvedCapability?: string;
  /** The schema the provider agreed to serve. Stored by requestor for caching. */
  agreedSchema?: CapabilitySchemaShape;
  /** Echo of the requestor's schemaHash — allows cache population. */
  schemaHash?: string;
  /** Returned when requestCapabilityManifest was true. */
  capabilityManifest?: SignedCapabilityManifest;
  /**
   * How the capability was matched:
   * "schema" — deterministic structural match (preferred, no LLM)
   * "intent" — LLM-assisted match (less certain, human approval recommended)
   * "cache"  — recovered from SHA-256 negotiation cache (zero-latency)
   */
  matchMethod?: "schema" | "intent" | "cache";
  /** Structural compatibility score (0–1) when matchMethod is "schema". */
  compatibilityScore?: number;
  /**
   * Audit trail of how the match was resolved.
   * Consumers can use this to tune caching or flag unexpected LLM usage.
   */
  matchAudit?: {
    structuralScore?: number;
    cacheHit?: boolean;
    llmUsed: boolean;
    llmModel?: string;
    fallbackReason?: string;
  };
}

export interface ArohaCounterOfferBody {
  capability: string;
  revisedTerms: ArohaNegotiateBody["proposedTerms"];
  csn?: Pick<CSNAcceptExtension, "resolvedCapability" | "agreedSchema" | "capabilityManifest">;
}

export interface ArohaAcceptBody {
  capability: string;
  acceptedTerms: ArohaNegotiateBody["proposedTerms"];
  /** CSN extension — present when the accept resolves a capability schema match. */
  csn?: CSNAcceptExtension;
}

export interface ArohaReserveBody extends WithCredential {
  capability: string;
  params: Record<string, unknown>;
  holdDurationMs: number;
  preferenceContext?: PreferenceContext;
}

export interface ArohaReserveAckBody {
  reservationToken: string;
  expiresAt: string; // ISO8601
}

export interface ArohaCommitBody {
  reservationToken: string;
}

/**
 * Structured evidence a provider attaches to a commit result (design spec
 * §8.2), so the buyer's release decision doesn't rest solely on the
 * provider's own unstructured `result` blob. Every field is optional
 * because not every capability can supply every kind — a flight booking
 * has a confirmation code; a data API call may only have its own signed
 * response. Absence of evidence is itself information a challenge-window
 * gate can act on (see @aroha-sdk/orchestrator's challenge.ts).
 */
export interface ArohaCommitEvidence {
  /** Provider-issued identifier a human or third party could look up independently (booking ref, order ID, tx hash). */
  confirmationId?: string;
  /** Base64 Ed25519 signature by the provider's own key over `result`, distinct from the envelope signature — proves the provider itself vouches for this specific payload, not just the transport. */
  providerSignature?: string;
  /** Claims from parties other than the provider (e.g. a payment processor's own confirmation), each independently attributable. */
  attestations?: Array<{ issuer: string; claim: string; signature?: string }>;
}

export interface ArohaCommitAckBody {
  reservationToken: string;
  result: Record<string, unknown>;
  /** Structured proof the committed action actually happened (design spec §8.2). Optional for backward compatibility with providers that only send `result`. */
  evidence?: ArohaCommitEvidence;
}

export interface ArohaCancelBody {
  reservationToken: string;
  reason: string;
}

export interface ArohaCancelAckBody {
  reservationToken: string;
}

/**
 * Raised by either party after a commit when they disagree the committed
 * result was actually delivered as claimed (design spec §8.3). Escrow can
 * `release()` or `refund()` but had no message type for "we disagree" — this
 * is that message. Sent to the `arbiterDid` agreed in the negotiate phase
 * (see `ArohaNegotiateBody.proposedTerms.arbiterDid`); a saga with no
 * arbiter has no dispute path beyond ordinary LIFO compensation.
 */
export interface ArohaDisputeBody {
  sagaId: string;
  reservationToken: string;
  /** DID of the party raising the dispute — must be one of the two transacting parties. */
  raisedBy: string;
  reason: string;
  /** The evidence (if any) the dispute is contesting — echoed for the arbiter's convenience, not re-verified by this type alone. */
  disputedEvidence?: ArohaCommitEvidence;
}

/**
 * The arbiter's binding decision on an `ArohaDispute` (design spec §8.3).
 * `release` and `refund` map directly onto `IArohaEscrowClient.release()` /
 * `refund()` in @aroha-sdk/settlement; `split` is for partial-fulfillment
 * cases where full release or full refund are both wrong.
 */
/**
 * Purpose tag inside every signed ArohaDisputeResolutionBody — domain
 * separation, so an arbiter signature over any other canonical object can
 * never be presented as a dispute resolution.
 */
export const DISPUTE_RESOLUTION_PURPOSE = "aroha-dispute-resolution/v1";

export interface ArohaDisputeResolutionBody {
  /** Always DISPUTE_RESOLUTION_PURPOSE. Signed. */
  purpose: typeof DISPUTE_RESOLUTION_PURPOSE;
  /** DID of the arbiter that decided. Signed. */
  arbiterDid: string;
  /** ISO 8601 time the decision was signed. Signed; bounds replay. */
  issuedAt: string;
  sagaId: string;
  reservationToken: string;
  resolution: "release" | "refund" | "split";
  /** Required when resolution is "split" — wei amount going to the provider; the remainder refunds to the payer. */
  splitAmountWei?: string;
  reason: string;
  /** Ed25519 signature by the arbiter's own key over the canonical form of this body (minus this field) — proves the resolution actually came from the agreed arbiterDid, not from either transacting party. */
  arbiterSignature: string;
}

export interface ArohaDelegateBody extends WithCredential {
  targetDID: string;
  capability: string;
  params: Record<string, unknown>;
  preferenceContext?: PreferenceContext;
}

export interface ArohaErrorBody {
  code: ArohaErrorCode;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
  /** Direct link to the error reference page for this code. */
  docsUrl?: string;
}

export interface ArohaSatisfactionSignalBody {
  sagaId: string;
  agentDID: string;
  /** The capability this signal applies to (e.g. "search-flights"). */
  capability: string;
  outcome: "satisfied" | "neutral" | "dissatisfied";
  dimensions: {
    price: "satisfied" | "neutral" | "dissatisfied";
    quality: "satisfied" | "neutral" | "dissatisfied";
    speed: "satisfied" | "neutral" | "dissatisfied";
  };
  /** Whether the saga completed within the provider's stated SLA. */
  withinSLA: boolean;
  /** Whether a compensation (ArohaCancel) was required to recover. */
  requiredCompensation: boolean;
}

/**
 * ArohaSpendingMandate — Layer 1 authorization token for agent payments.
 *
 * Enables agents to spend funds on behalf of a user without ever seeing
 * raw payment credentials. Each hop in the delegation chain can only
 * narrow constraints — never widen them.
 *
 * Mandate chain: User (intent) → Personal Agent (cart) → Provider (payment).
 *
 * References:
 *   AP2 Protocol (Google) — Intent/Cart/Payment Mandate pattern.
 *   IETF draft-niyikiza-oauth-attenuating-agent-tokens — monotonic scope narrowing.
 */
export interface ArohaSpendingMandateBody {
  mandateTier: "intent" | "cart" | "payment";
  constraints: SpendingConstraints;
  grantee: string;    // DID of the agent receiving this mandate
  grantor: string;    // DID of the agent issuing this mandate
  issuedAt: string;   // ISO8601 — set at signing time; compared against key_rotated_at to detect revoked-key tokens
  expiresAt: string;  // ISO8601
  parentMandateId: string | null;
  mandateId: string;
  /**
   * Which side of a payment this mandate's agent acts for (PSD3/PSR
   * "acting for the payer or the payee"). Optional; when a parent sets it,
   * every descendant must carry the same value, so an operator can show a
   * chain never acted for both sides. Absent = undeclared (legacy tokens).
   * Included in the signed v2 payload only when present, so tokens and
   * vectors issued before this field existed verify unchanged.
   */
  actingFor?: "payer" | "payee";
}

/**
 * Spending constraints carried inside a mandate token.
 *
 * **Enforcement model — two complementary layers:**
 *
 * 1. Monotonic narrowing (`assertNarrowing`, enforced synchronously at attenuation
 *    time): a child mandate's spendLimitUsd and all other constraints must be a
 *    subset of its parent's. This is a per-child check only — it does NOT prevent
 *    issuing multiple children that each claim the full parent limit.
 *
 * 2. Cumulative budget (`SpendingLedger`, enforced atomically at attenuation time):
 *    when a `ledger` is passed to issueIntentMandate / attenuateToCart /
 *    attenuateToPayment, issuing a child for $X atomically deducts $X from the
 *    parent's remaining pool. Attempting to over-allocate throws BudgetExhaustedError
 *    before the child token is signed. Released during saga compensation via
 *    releaseAllocation() so unused budget is returned to the parent pool.
 *
 * Both layers are needed for a complete protocol guarantee:
 *   - Narrowing alone: each child ≤ parent limit, but N children can each claim
 *     the full amount → effective grant = N × limit (the double-allocation gap).
 *   - Ledger alone: total ≤ limit, but without narrowing a child could re-widen
 *     a constraint the parent intentionally narrowed.
 *   - Both: total allocation ≤ limit AND every child is a strict subset.
 *
 * Runtime spend enforcement (the actual payment gate) remains the responsibility
 * of the receiving agent via enforceSpendingConstraints(). The settlement layer
 * (IArohaSettlement) handles post-fact financial settlement.
 */
export interface SpendingConstraints {
  spendLimitUsd: number;
  sessionLimitUsd?: number;
  currency?: string;                        // ISO 4217, default "USD"
  merchantCategory?: string | null;         // MCC allow-list; null = any
  requireHumanApprovalAboveUsd?: number;
  allowedMerchants?: string[] | null;       // DID allow-list; null = any
  validFrom?: string;                       // ISO8601
  validUntil?: string;                      // ISO8601
}

/**
 * TaskConstraints — non-monetary resource limits for task delegation.
 *
 * Carried inside an ArohaTaskMandateBody. Governs what a delegated agent may
 * do in terms of capabilities, compute, data access, and side effects —
 * independently of (or alongside) monetary spending constraints.
 *
 * All fields are optional; omitting a field means "no limit on this resource".
 * The SDK enforces non-null limits automatically before the handler runs.
 */
export interface TaskConstraints {
  /**
   * Maximum times each named capability may be invoked within this mandate.
   * Keys are exact capability IDs (e.g. "send-email", "post-social").
   * Omitting a capability ID means unlimited invocations of that capability.
   * { "send-email": 3, "post-social": 1 }
   */
  actionLimits?: Record<string, number>;

  /** Compute resource ceiling. All sub-fields are independent limits. */
  computeLimit?: {
    /** Max total LLM tokens across all calls in the delegation chain. */
    llmTokens?: number;
    /** Max outbound HTTP requests. */
    webRequests?: number;
    /** Wall-clock deadline in milliseconds from mandate issuance. */
    executionTimeMs?: number;
    /** CPU-seconds budget (for code-execution agents). */
    cpuSeconds?: number;
  };

  /**
   * Data access scope by resource key. Resource keys are agent-defined strings
   * (e.g. "calendar", "email", "customer-db", "files:/documents").
   * A missing key means "no access to this resource".
   * "none" explicitly blocks access (overrides a parent "read" grant on attenuation).
   */
  dataAccess?: Record<string, "none" | "read" | "read-write" | "write">;

  /** Where the agent is permitted to send task outputs. */
  outputHandling?: "internal-only" | "user-only" | "shareable";

  /**
   * When true, the SDK blocks any capability whose reversibility is "irreversible".
   * Use this to allow research and drafting while preventing sends and publishes.
   */
  reversibleOnly?: boolean;

  /**
   * Capabilities that require human approval before the SDK executes them.
   * The agent pauses at these gates and emits an approval_required event.
   * The user must approve via /v1/resume before execution continues.
   * e.g. ["send-email", "publish-post", "submit-form"]
   */
  humanGates?: string[];

  /**
   * For long-running tasks: the agent must emit a checkpoint event every N ms.
   * The personal agent receives these and may cancel or redirect the task.
   */
  checkpointIntervalMs?: number;

  /**
   * When true, any code-execution capability must run inside a sandbox.
   * The SDK rejects code-exec calls that don't declare sandboxed: true.
   */
  requireSandbox?: boolean;

  /**
   * Maximum delegation chain depth below this mandate.
   * 0 = sub-delegation is forbidden.
   * 1 = one level of sub-agents allowed.
   * Default: unlimited (undefined).
   */
  maxDelegationDepth?: number;

  /**
   * Conversation profile: the DID of the room member this grant acts for
   * (a guest grant). The grantor (the host person) lends a strict subset of
   * their own authority to their agent for requests from this member.
   * When a parent sets it, every child must carry the same value — dropping
   * it would turn a grant scoped to one person into a general one.
   */
  onBehalfOf?: string;

  /**
   * Conversation profile: the room this grant is bound to. When set,
   * enforceTaskConstraints refuses a request that does not come from this
   * room. Same narrowing rule as onBehalfOf.
   */
  roomId?: string;
}

/**
 * MandateInvariants — instance-level binding for one specific transaction
 * (design spec §9.1 Layer 1).
 *
 * `allowed`/`taskConstraints`/`spendingConstraints` above are CLASS-level:
 * which kinds of action, how much in total. "book-flights ≤ $500" is fully
 * satisfied by booking an attacker-redirected flight for $500 — attenuation
 * prevents escalation, not misuse within grant. Invariants bind the
 * specific instance instead: signed by the principal BEFORE untrusted
 * content (a tool result, a remote agent's response) enters the loop, then
 * checked again at commit against what actually happened. A redirected
 * payee or a mutated parameter fails that check regardless of how
 * persuasive the injected text was — the model can be steered, but the
 * bound outcome can't be altered without invalidating the signature.
 *
 * Every field is optional because not every mandate needs instance
 * binding — a mandate with no invariants is still valid and enforced at
 * the class level only, exactly as before this field existed.
 */
export interface MandateInvariants {
  /** DIDs the bound action may pay/target. Absent = not restricted by this invariant (class-level allowlists, if any, still apply). */
  payee?: string[];
  /**
   * Exact parameter values this specific transaction is bound to — e.g.
   * `{ destination: "JFK" }`, or a content hash for a value too large/
   * sensitive to embed directly (e.g. `{ passengerHash: "<sha256>" }`).
   * Checked for exact equality at commit, not compatibility — that's the
   * point: no wiggle room for an injected redirection to exploit.
   */
  parameters?: Record<string, string | number | boolean>;
  maxAmount?: { amount: number; currency: string };
  /**
   * ISO8601 — independent of (and typically tighter than) the mandate's own
   * `expiresAt`. This is when THIS specific bound plan goes stale, not when
   * the broader authority grant does.
   */
  expiry?: string;
}

/**
 * A `MandateInvariants` block signed by the principal (design spec §9.1
 * Layer 1) — the "binding artifact" the spec says intent-gate confirmation
 * should produce instead of just a yes/no. See
 * @aroha-sdk/credentials's signInvariants/verifyInvariants for how this is
 * produced and checked, and @aroha-sdk/orchestrator's intent-gate.ts for
 * where confirmation turns into one of these.
 */
export interface SignedInvariants {
  invariants: MandateInvariants;
  /** DID of the signer — must match the mandate's grantor/grantee chain the invariants are attached to. */
  signerDid: string;
  /** Hex Ed25519 signature over the canonical form of `invariants` (same sortKeys+JSON.stringify convention as mandate signing). */
  signature: string;
}

/**
 * ArohaTaskMandateBody — authorization token for task delegation.
 *
 * Used when delegating work that is non-monetary (pure task) or a combination
 * of task and spend (hybrid). Paired with ArohaSpendingMandateBody for the
 * monetary-only pattern.
 *
 * Mandate chain invariant: each hop can only narrow constraints, never widen.
 *
 * mandateType:
 *   "task"   — no monetary spend; taskConstraints only.
 *   "hybrid" — both task constraints and spending constraints apply.
 */
export interface ArohaTaskMandateBody {
  mandateType: "task" | "hybrid";
  mandateTier: "intent" | "cart" | "execution";
  /** Explicit list of permitted capability IDs. All others are denied. */
  allowed: string[];
  /** Explicit denials — override allowed when both match. */
  blocked?: string[];
  taskConstraints: TaskConstraints;
  /** Only present when mandateType is "hybrid". */
  spendingConstraints?: SpendingConstraints;
  /** Instance-level binding for one specific transaction (design spec §9.1 Layer 1). Absent = class-level enforcement only, as before this field existed. */
  invariants?: MandateInvariants;
  grantee: string;
  grantor: string;
  issuedAt: string;
  expiresAt: string;
  parentMandateId: string | null;
  mandateId: string;
}

/**
 * Reversibility classification for capabilities.
 *
 * "full"         — read-only; no persistent side effects. Always safe to delegate.
 * "semi"         — creates artefacts that can be deleted. Moderate risk.
 * "irreversible" — permanent side effects (send, publish, delete, pay).
 *                  Requires explicit humanGate or reversibleOnly=false in mandate.
 */
export type CapabilityReversibility = "full" | "semi" | "irreversible";

/**
 * Risk tier for capabilities — used by personal agents to decide gating policy.
 *
 * 1 — Read-only public data (web search, file read, summarise)
 * 2 — Creates artefacts (draft email, calendar event, write file)
 * 3 — Irreversible non-financial (send email, publish post, submit form)
 * 4 — Financial transactions (charge card, transfer funds, book non-refundable)
 * 5 — System-level meta-actions (deploy code, create agents, modify permissions)
 */
export type RiskTier = 1 | 2 | 3 | 4 | 5;

/**
 * TaskReceipt — structured record of what a delegated agent did.
 *
 * Generated by the vendor agent SDK at the end of every mandate execution.
 * Analogous to a payment receipt but for task delegation — proves exactly
 * what actions were taken, what resources were consumed, and whether the
 * execution stayed within mandate bounds.
 */
export interface TaskReceipt {
  receiptId: string;
  mandateId: string;
  correlationId: string;
  /** DID of the agent that executed the task. */
  executedByDid: string;
  /** DID of the personal agent that issued the mandate. */
  issuedByDid: string;
  startedAt: string;
  completedAt: string;
  status: "complete" | "partial" | "failed" | "cancelled";

  /** Ordered list of every capability invocation. */
  actions: TaskAction[];

  /** Aggregate resource consumption across all actions. */
  consumed: {
    llmTokens: number;
    webRequests: number;
    wallClockMs: number;
    actionCounts: Record<string, number>;
    moneySpentUsd?: number;
  };

  /** Whether the execution stayed within all mandate bounds. */
  mandateBoundsCheck: {
    withinBounds: boolean;
    /** Non-empty when withinBounds is false. */
    violations: string[];
  };

  /** Artefacts produced by the task. */
  outputs: TaskOutput[];
}

export interface TaskAction {
  sequence: number;
  capability: string;
  reversibility: CapabilityReversibility;
  startedAt: string;
  durationMs: number;
  status: "success" | "failed" | "skipped";
  /** True if a human gate paused execution before this action. */
  humanGateTriggered: boolean;
  /** Set when humanGateTriggered is true. */
  humanGateApproved?: boolean;
}

export interface TaskOutput {
  type: "file" | "email-sent" | "post-published" | "calendar-event" | "data" | "payment" | "other";
  summary: string;
  metadata?: Record<string, unknown>;
}

// ─── Error Codes ──────────────────────────────────────────────────────────────

const DOCS = "https://aroha-labs.com/docs/errors";

/**
 * Canonical wire-level error codes for the Aroha Protocol.
 * Every SDK uses the same strings — an `ArohaError` from a Go agent is parsed
 * identically by a Python consumer.
 *
 * Full reference with remediation steps: https://aroha-labs.com/docs/errors
 */
export enum ArohaErrorCode {
  /** Missing or invalid credential. @see {@link DOCS}#Aroha_UNAUTHORIZED */
  Unauthorized          = "Aroha_UNAUTHORIZED",
  /** Credential valid but role lacks permission. @see {@link DOCS}#Aroha_FORBIDDEN */
  Forbidden             = "Aroha_FORBIDDEN",

  /** Ed25519 proof verification failed. @see {@link DOCS}#Aroha_INVALID_SIGNATURE */
  InvalidSignature      = "Aroha_INVALID_SIGNATURE",
  /** `envelope.expires` is in the past. @see {@link DOCS}#Aroha_EXPIRED_MESSAGE */
  ExpiredMessage        = "Aroha_EXPIRED_MESSAGE",
  /** Nonce already seen in the rolling window. @see {@link DOCS}#Aroha_REPLAY_DETECTED */
  ReplayDetected        = "Aroha_REPLAY_DETECTED",
  /** Capability ID not recognised by this agent. @see {@link DOCS}#Aroha_UNKNOWN_CAPABILITY */
  UnknownCapability     = "Aroha_UNKNOWN_CAPABILITY",
  /** Sender trust level does not meet requirement. @see {@link DOCS}#Aroha_TRUST_LEVEL_INSUFFICIENT */
  TrustLevelInsufficient = "Aroha_TRUST_LEVEL_INSUFFICIENT",

  /** Reserve attempt failed (provider-side). @see {@link DOCS}#Aroha_RESERVATION_FAILED */
  ReservationFailed     = "Aroha_RESERVATION_FAILED",
  /** Hold duration elapsed before commit. @see {@link DOCS}#Aroha_RESERVATION_EXPIRED */
  ReservationExpired    = "Aroha_RESERVATION_EXPIRED",
  /** Commit could not be applied; idempotent retry safe. @see {@link DOCS}#Aroha_COMMIT_FAILED */
  CommitFailed          = "Aroha_COMMIT_FAILED",
  /** Compensation failed; manual intervention may be needed. @see {@link DOCS}#Aroha_CANCEL_FAILED */
  CancelFailed          = "Aroha_CANCEL_FAILED",
  /** `reservationToken` unknown or already cancelled. @see {@link DOCS}#Aroha_INVALID_TOKEN */
  InvalidToken          = "Aroha_INVALID_TOKEN",

  /** Capability temporarily unavailable. @see {@link DOCS}#Aroha_NO_INVENTORY */
  NoInventory           = "Aroha_NO_INVENTORY",
  /** Provider is at capacity; retry later. @see {@link DOCS}#Aroha_CAPACITY_EXCEEDED */
  CapacityExceeded      = "Aroha_CAPACITY_EXCEEDED",
  /** Provider dependency is down. @see {@link DOCS}#Aroha_SERVICE_UNAVAILABLE */
  ServiceUnavailable    = "Aroha_SERVICE_UNAVAILABLE",

  /** Unexpected internal error. @see {@link DOCS}#Aroha_INTERNAL_ERROR */
  InternalError         = "Aroha_INTERNAL_ERROR",
  /** Required body field missing or wrong type. @see {@link DOCS}#Aroha_INVALID_PARAMS */
  InvalidParams         = "Aroha_INVALID_PARAMS",

  /** No structural capability schema match found. @see {@link DOCS}#CSN_NO_STRUCTURAL_MATCH */
  CSN_NO_STRUCTURAL_MATCH = "CSN_NO_STRUCTURAL_MATCH",

  /** Action invocation count exceeds mandate's actionLimits. */
  ActionLimitExceeded      = "Aroha_ACTION_LIMIT_EXCEEDED",
  /** Compute resource (tokens/requests/time) budget exhausted. */
  ComputeLimitExceeded     = "Aroha_COMPUTE_LIMIT_EXCEEDED",
  /** Capability is irreversible but mandate requires reversibleOnly. */
  ReversibilityViolation   = "Aroha_REVERSIBILITY_VIOLATION",
  /** Capability requires human approval (humanGates) before execution. */
  HumanGateRequired        = "Aroha_HUMAN_GATE_REQUIRED",
  /** Agent attempted to access a data resource beyond its scope. */
  DataAccessViolation      = "Aroha_DATA_ACCESS_VIOLATION",
  /** Code execution attempted outside a declared sandbox. */
  SandboxRequired          = "Aroha_SANDBOX_REQUIRED",
  /** Delegation chain depth exceeds maxDelegationDepth. */
  DelegationDepthExceeded  = "Aroha_DELEGATION_DEPTH_EXCEEDED",
  /** Capability not in mandate's allowed list. */
  CapabilityNotPermitted   = "Aroha_CAPABILITY_NOT_PERMITTED",

  /** Requestor's and provider's settlement rails share no common value (design spec §8.1). @see {@link DOCS}#Aroha_SETTLEMENT_RAIL_MISMATCH */
  SettlementRailMismatch   = "Aroha_SETTLEMENT_RAIL_MISMATCH",
  /** Buyer disputed the commit result during the challenge window, or the arbiter resolved against the provider (design spec §8.2/§8.3). @see {@link DOCS}#Aroha_COMMIT_DISPUTED */
  CommitDisputed           = "Aroha_COMMIT_DISPUTED",
}

/** Returns the docs URL for a given error code. */
export function errorDocsUrl(code: ArohaErrorCode | string): string {
  return `${DOCS}#${code}`;
}

// ─── Message Type Union ───────────────────────────────────────────────────────

export type ArohaMessageType =
  | "ArohaRequest"
  | "ArohaResponse"
  | "ArohaStream"
  | "ArohaNegotiate"
  | "ArohaCounterOffer"
  | "ArohaAccept"
  | "ArohaReserve"
  | "ArohaReserveAck"
  | "ArohaCommit"
  | "ArohaCommitAck"
  | "ArohaCancel"
  | "ArohaCancelAck"
  | "ArohaDelegate"
  | "ArohaError"
  | "ArohaSatisfactionSignal"
  | "ArohaSpendingMandate"
  | "ArohaTaskMandate"
  | "ArohaDispute"
  | "ArohaDisputeResolution";

export type ArohaBodyByType = {
  ArohaRequest:           ArohaRequestBody;
  ArohaResponse:          ArohaResponseBody;
  ArohaStream:            ArohaStreamBody;
  ArohaNegotiate:         ArohaNegotiateBody;
  ArohaCounterOffer:      ArohaCounterOfferBody;
  ArohaAccept:            ArohaAcceptBody;
  ArohaReserve:           ArohaReserveBody;
  ArohaReserveAck:        ArohaReserveAckBody;
  ArohaCommit:            ArohaCommitBody;
  ArohaCommitAck:         ArohaCommitAckBody;
  ArohaCancel:            ArohaCancelBody;
  ArohaCancelAck:         ArohaCancelAckBody;
  ArohaDelegate:          ArohaDelegateBody;
  ArohaError:             ArohaErrorBody;
  ArohaSatisfactionSignal: ArohaSatisfactionSignalBody;
  ArohaSpendingMandate:   ArohaSpendingMandateBody;
  ArohaTaskMandate:       ArohaTaskMandateBody;
  ArohaDispute:           ArohaDisputeBody;
  ArohaDisputeResolution: ArohaDisputeResolutionBody;
};
