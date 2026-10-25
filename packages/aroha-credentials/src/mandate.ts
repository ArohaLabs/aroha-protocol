// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/credentials — ArohaMandateCredential
 *
 * Issues, attenuates, and verifies ArohaSpendingMandate tokens.
 *
 * The mandate chain enforces three orthogonal properties:
 *
 *   1. Provenance — every mandate traces back, link by link, to a root intent
 *      mandate signed by the human (or their personal agent). This is what
 *      verifyMandateChain() proves: each link is signed by its grantor, each
 *      grantor is the previous link's grantee, and each parentMandateId names
 *      the previous link. A v2 token CARRIES its ancestors so a verifier can
 *      check this offline; a bare parentMandateId (all a v1 token had) is just
 *      a UUID anyone can type.
 *
 *   2. Monotonic scope narrowing (checkNarrowing) — a child's constraints must
 *      be a subset of its parent's. Enforced twice: at attenuation time, so an
 *      honest caller gets an early error, and AGAIN by the verifier on every
 *      link, because the attenuation-time check runs on the delegating agent's
 *      own machine and a dishonest agent simply skips it. Only the
 *      verifier-side check is a security property.
 *
 *   3. Cumulative budget enforcement (SpendingLedger at issuance,
 *      RedemptionStore at redemption) — narrowing is per-child, so N children
 *      can each claim the full parent limit, and one payment mandate can be
 *      presented to N merchants. The ledger caps what a parent hands out; the
 *      redemption store caps what a payment mandate actually spends.
 *
 * Token versions:
 *   v1 (legacy) — { mandate, signature }, signed over JSON.stringify(sortKeys(mandate)).
 *                 No ancestry. Still accepted by verifyMandate() for backward
 *                 compatibility; accepted by verifyMandateChain() only as a
 *                 root (a v1 child cannot prove where it came from).
 *   v2          — { v: 2, mandate, signature, chain }, where `chain` is the
 *                 signed ancestry, root first, excluding this mandate. Each
 *                 v2 signature covers the RFC 8785 (JCS) canonical form of
 *                 { mandate, v: 2 } — the version is inside the signed bytes
 *                 so a v2 signature can never be replayed as a v1 one or
 *                 vice versa.
 *
 * Amounts: all *Usd fields are JSON numbers. They must be finite and
 * non-negative, and should be integers or decimals with at most cent
 * precision (e.g. 42 or 42.5 or 42.07). Non-finite values are rejected at
 * issuance and at verification. Amounts are compared, never re-serialised by
 * arithmetic, so JCS's ECMAScript number formatting round-trips them exactly
 * in every conformant SDK.
 *
 * References:
 *   AP2 Protocol (Google) Intent/Cart/Payment Mandate pattern.
 *   IETF draft-niyikiza-oauth-attenuating-agent-tokens (2024).
 *   RFC 8785 — JSON Canonicalization Scheme.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
// Runtime imports come from the ./identity subpath, never the @aroha-sdk/core
// barrel: the barrel re-exports the Node transport (ws, undici -> fs, http),
// which a Cloudflare Worker cannot bundle. Keeping this module (and
// redemption*, revocation, jcs) on subpaths is what lets the registry Worker
// import `@aroha-sdk/credentials/mandates` and verify chains with the SAME
// code every payee runs. The barrel import below is type-only (erased).
import type { ArohaSpendingMandateBody, SpendingConstraints, ArohaTaskMandateBody, TaskConstraints, TaskReceipt, TaskAction, TaskOutput, MandateInvariants, SignedInvariants } from "@aroha-sdk/core";
import { fromMultibase, generateDid, isInceptionDid, kelKeyResolver, resolveKelState, type KelSource, type KelStore, type KelState } from "@aroha-sdk/core/identity";
import { type ISpendingLedger, BudgetExhaustedError } from "./spending-ledger.js";
import { canonicalizeJcs } from "./jcs.js";
// governed.ts imports only TYPES from this module, so there is no runtime cycle.
import { checkGovernedPrerequisites } from "./governed.js";

// re-export so callers don't need a separate import
export { BudgetExhaustedError };

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── Public types ─────────────────────────────────────────────────────────────

/** Current mandate token version produced by every issuing function. */
export const MANDATE_TOKEN_VERSION = 2;

type MandateTier = ArohaSpendingMandateBody["mandateTier"];

/**
 * Breadth order of the tiers. A child may sit at the same tier as its parent
 * or a narrower one, never a broader one: a payment mandate cannot mint a
 * cart mandate, and nothing can mint an intent except the human root.
 */
const TIER_RANK: Record<MandateTier, number> = { intent: 0, cart: 1, payment: 2 };

/** One signed link of a mandate chain, as carried inside a v2 token. */
export interface MandateChainLink {
  /**
   * Which signing rule THIS link's signature follows: 1 = legacy
   * sortKeys/JSON.stringify over the body, 2 = JCS over { mandate, v: 2 }.
   * A v2 chain may start from a v1 root issued before the upgrade.
   */
  v: 1 | 2;
  mandate: ArohaSpendingMandateBody;
  signature: string;
}

export interface SignedMandate {
  mandate: ArohaSpendingMandateBody;
  /** base64url Ed25519 signature over the canonical mandate. */
  signature: string;
  /** base64url serialised token — embed in message body credentialToken. */
  token: string;
  /**
   * Set when the mandate was issued via a SpendingLedger.
   * Store this alongside the saga step so you can call releaseAllocation()
   * during compensation to return the unused budget to the parent.
   */
  allocationId?: string;
  /** Token version. 2 for everything this SDK issues now; absent on legacy v1 objects. */
  v?: 1 | 2;
  /**
   * Signed ancestry, root first, EXCLUDING this mandate. Empty for a root
   * intent mandate. Absent on legacy v1 objects. attenuateToCart /
   * attenuateToPayment append this mandate to it when they mint a child, so
   * every token carries everything a verifier needs to walk to the root.
   */
  chain?: MandateChainLink[];
}

export interface MandateVerificationResult {
  valid: boolean;
  mandate?: ArohaSpendingMandateBody;
  reason?: string;
  /**
   * True only when every link from a root intent mandate down to this one
   * was verified (signature against the grantor's key, linkage, tier order,
   * narrowing, time windows, revocation). False for a legacy v1 child token,
   * which carries no ancestry — such a token proves only that its immediate
   * grantor signed it, NOT that a human authorised the spend.
   */
  chainVerified?: boolean;
  /** The verified chain, root first, including this mandate (when chainVerified). */
  chain?: ArohaSpendingMandateBody[];
  /** grantor DID of the verified root mandate (when chainVerified). */
  rootGrantor?: string;
}

export interface LedgerOptions {
  /** Spending ledger for cumulative budget enforcement across children. */
  ledger?: ISpendingLedger;
}

/**
 * Resolve the Ed25519 public key that `did` signs with, or null when the DID
 * is unknown. Must NOT trust anything inside the token being verified — the
 * whole point of resolving is to get the key from somewhere the token's
 * author does not control (the DID itself, a registry, a pinned config).
 */
export type MandateKeyResolver = (did: string) => Promise<Uint8Array | null>;

/**
 * Revocation hook: return true if the mandate `mandateId` issued by `grantor`
 * has been revoked.
 *
 * A mandateId is chosen by whoever mints the mandate, so on its own it names
 * nothing: anyone can mint a valid mandate of their own that reuses someone
 * else's id. The grantor is what the signature binds, so (grantor, mandateId)
 * is the identity a shared revocation list must be keyed by.
 */
export type MandateRevocationCheck = (mandateId: string, grantor: string) => Promise<boolean>;

/**
 * Default resolver for content-addressed DIDs (`did:aroha:z<base58btc(pubkey)>`,
 * minted by aroha-core's generateDid / generateContentAddressedDID). The DID
 * commits to its own key, so no lookup is needed and nothing in the token can
 * influence the answer. Returns null for every other DID form — including
 * namespaced `did:aroha:<agentId>` ones, which are NOT self-certifying and
 * need a registry-backed resolver passed explicitly.
 *
 * The round-trip check (re-encode the decoded key, compare to the DID) is
 * what keeps a human-readable DID that merely happens to start with "z" and
 * use only base58 letters (e.g. "did:aroha:zoo") from decoding to a
 * zero-padded garbage key.
 *
 * Rotatable `did:aroha:E…` DIDs are NOT handled here: their key is not in
 * the DID but in a Key Event Log that must be fetched and verified. Use
 * `createMandateKeyResolver({ kelSource })`, or pass `kelSource` to
 * verifyMandateChain.
 */
export async function resolveContentAddressedKey(did: string): Promise<Uint8Array | null> {
  if (!did.startsWith("did:aroha:z")) return null;
  try {
    const key = fromMultibase(did.slice("did:aroha:".length));
    if (key.length !== 32) return null;
    return generateDid(key) === did ? key : null;
  } catch {
    return null;
  }
}

export interface MandateKeyResolverOptions {
  /**
   * Where to fetch Key Event Logs for rotatable `did:aroha:E…` DIDs (registry,
   * peer, logs carried with the request). Without it E-DIDs resolve to null.
   */
  kelSource?: KelSource;
  /** Highest-seen KEL memory (aroha-core KelStore) — rejects stale / forked logs. */
  kelStore?: KelStore;
  /** Resolver for every OTHER DID form (named, registry-trusted). */
  fallback?: MandateKeyResolver;
}

/**
 * Resolver covering all three `did:aroha:` forms:
 *   - `E…` (rotatable, self-certifying): the CURRENT key from the verified
 *     KEL via `kelSource`; null if the identity or its controller is revoked;
 *   - `z…` (legacy content-addressed): derived from the DID itself;
 *   - anything else: `fallback`, if given.
 *
 * The self-certifying forms NEVER fall through to `fallback`. That is the
 * point of them: a registry-backed resolver must not be able to answer for a
 * DID that carries its own proof, or the registry could substitute a key.
 */
export function createMandateKeyResolver(options: MandateKeyResolverOptions = {}): MandateKeyResolver {
  const kel = options.kelSource ? kelKeyResolver(options.kelSource, { store: options.kelStore }) : null;
  return async (did) => {
    if (isInceptionDid(did)) return kel ? kel(did) : null;
    const derived = await resolveContentAddressedKey(did);
    if (derived) return derived;
    return options.fallback ? options.fallback(did) : null;
  };
}

/** Options shared by verifyMandate and verifyMandateChain. */
export interface MandateCheckOptions {
  /**
   * Revocation hook, consulted for EVERY link in the chain — revoking the
   * human's intent mandate must kill every cart and payment beneath it.
   * A hook that throws fails the verification (fail closed).
   *
   * `null` states explicitly that this verifier does not check revocation (a
   * revoked mandate is then honoured until it expires). It behaves like
   * omitting the hook, except that verifyMandateChain does not print its
   * "ran without isRevoked" warning: the caller has already said so.
   */
  isRevoked?: MandateRevocationCheck | null;
  /**
   * Allowed clock skew in ms for NOT-BEFORE checks only (issuedAt,
   * constraints.validFrom). Default 30 000. Deliberately NOT applied to
   * expiresAt / validUntil: a tolerance there would extend spending
   * authority past the instant the human chose, and a verifier whose clock
   * runs slow is better off rejecting a just-expired mandate than honouring it.
   */
  clockToleranceMs?: number;
  /** Override "now" (Unix ms). For tests and replayed audits. */
  now?: number;
  /** If set, the chain's root grantor must be exactly this DID. */
  expectedRoot?: string;
  /**
   * If set, the chain's root grantor must be one of these DIDs. An EMPTY
   * list trusts no root at all (every chain fails) — an explicit "nobody",
   * never read as "anybody".
   */
  trustedRoots?: string[];
  /**
   * Set by governedVerification() (see governed.ts). When true the verifier
   * itself re-checks that every protective prerequisite is present —
   * isRevoked, kelSource, a person root and a pinned root — and fails the
   * verification when one is missing, instead of quietly running the weaker
   * check. WHY at verification time and not only when the profile is built:
   * the profile is a plain object, and a caller that spreads it and drops a
   * field (or overrides one with undefined) must not get a weaker check that
   * still reports itself as governed.
   */
  governed?: boolean;
}

/**
 * Key Event Log and person-root options. Shared by verifyMandateChain,
 * verifyMandate and enforceSpendingConstraints, so one governed profile (see
 * governedVerification) can be handed to any of them unchanged.
 */
export interface MandateKelOptions {
  /**
   * Key Event Log source for rotatable `did:aroha:E…` DIDs. When set, EVERY
   * E-DID in the chain — each link's grantor and grantee — is resolved
   * through its verified KEL (and its controller's), and:
   *   - a grantor's signature is checked against its CURRENT key (overriding
   *     `resolveKey` for E-DIDs: the log, not a resolver, is authoritative);
   *   - a link whose grantor or grantee is REVOKED, or whose controller person
   *     has revoked itself, fails — revoking a stolen agent must kill the
   *     mandates it holds and the ones it issued;
   *   - a missing, stale or forked log fails (fail closed), and so does an
   *     agent whose controller's KEL cannot be fetched: the controller's log
   *     is what proves the agent has not been revoked.
   * Consequence to plan for: mandates are checked against keys current at
   * VERIFICATION time, so after a rotation or recovery outstanding mandates
   * signed by the old key stop verifying and must be re-issued. That is the
   * desired outcome after a theft, and an accepted cost after a routine
   * rotation (mandates are short-lived).
   */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. Recommended for long-lived verifiers. */
  kelStore?: KelStore;
  /**
   * Require the root grantor to be a PERSON: a `did:aroha:E…` DID of kind
   * "person" whose KEL verifies and is not revoked, with the root mandate
   * signed by the person's current key. Requires `kelSource`. Without this a
   * root is "whatever DID signed first" — possibly an agent minting its own
   * authority.
   */
  requirePersonRoot?: boolean;
  /** Implies requirePersonRoot, and the root person must be exactly this DID. */
  expectedRootPerson?: string;
}

export interface VerifyMandateChainOptions extends MandateCheckOptions, MandateKelOptions {
  /** If set, the leaf mandate's grantee must be exactly this DID (normally your own). */
  expectedGrantee?: string;
  /** Maximum number of links accepted, root and leaf included. Default 8. */
  maxDepth?: number;
}

export interface VerifyMandateOptions extends MandateCheckOptions, MandateKelOptions {
  /** Maximum number of links accepted for a v2 token, root and leaf included. Default 8. */
  maxDepth?: number;
  /**
   * Unix ms timestamp of the grantor's most recent key rotation (agent_records.key_rotated_at).
   * When provided, mandates whose issuedAt precedes this timestamp are rejected — they were
   * signed with the now-revoked key even if the Ed25519 signature itself is well-formed.
   * Applies to the leaf mandate (the one whose key the caller supplied).
   */
  keyRotatedAt?: number;
  /**
   * Resolver for the ANCESTORS of a v2 token. The leaf is always checked
   * against the publicKey argument. Default: resolveContentAddressedKey.
   */
  resolveKey?: MandateKeyResolver;
}

const DEFAULT_CLOCK_TOLERANCE_MS = 30_000;
const DEFAULT_MAX_DEPTH = 8;

// ─── Issue ────────────────────────────────────────────────────────────────────

/**
 * Issue a root Intent Mandate from a user to their personal agent.
 *
 * When a ledger is provided, the mandate's budget is registered in the ledger
 * so that any children issued via attenuateToCart / attenuateToPayment are
 * deducted from the same pool.
 *
 * @param grantorDID   User's DID (or personal-agent acting on user's behalf)
 * @param granteeDID   Personal agent's DID
 * @param constraints  Maximum spend envelope — all downstream mandates must be ≤ these
 * @param privateKey   Grantor's Ed25519 private key (32 bytes)
 * @param ttlMs        Time-to-live in milliseconds (default: 1 hour)
 * @param options      Optional ledger for cumulative budget enforcement
 */
export async function issueIntentMandate(
  grantorDID: string,
  granteeDID: string,
  constraints: SpendingConstraints,
  privateKey: Uint8Array,
  ttlMs = 3_600_000,
  options?: LedgerOptions & {
    /**
     * PSD3/PSR acting-for side: whether this chain acts for the payer or the
     * payee. Inherited by every child (attenuation cannot change it).
     */
    actingFor?: "payer" | "payee";
  }
): Promise<SignedMandate> {
  if (options?.actingFor !== undefined && options.actingFor !== "payer" && options.actingFor !== "payee") {
    throw new Error(`Invalid actingFor "${String(options.actingFor)}": must be "payer" or "payee"`);
  }
  const signed = await issueMandateInternal(
    "intent", grantorDID, granteeDID, constraints, null, privateKey, Date.now() + ttlMs, [], options?.actingFor
  );
  if (options?.ledger) {
    await options.ledger.init(
      signed.mandate.mandateId,
      constraints.spendLimitUsd,
      new Date(signed.mandate.expiresAt).getTime(),
    );
  }
  return signed;
}

/**
 * Attenuate a mandate to a narrower Cart Mandate.
 *
 * Runs, in order:
 *   1. Inheritance — any of sessionLimitUsd, requireHumanApprovalAboveUsd,
 *      validFrom, validUntil, currency that the parent sets and the caller
 *      omits is copied from the parent. Omitting a field used to mean "no
 *      limit", which silently WIDENED the child; the verifier now rejects
 *      that, so the helper fills it in to keep honest callers working.
 *   2. checkNarrowing — throws if the child widens any constraint.
 *   3. ledger.allocate — atomic, throws BudgetExhaustedError if cumulative
 *      allocations to all children would exceed parent.spendLimitUsd.
 *
 * The returned token embeds the parent's signed chain plus the parent itself,
 * so a verifier can walk back to the root without any other input.
 *
 * The returned SignedMandate includes an allocationId when a ledger is used.
 * Persist this alongside the saga step to enable budget release on compensation.
 */
export async function attenuateToCart(
  parent: SignedMandate,
  granteeDID: string,
  narrowedConstraints: SpendingConstraints,
  grantorPrivateKey: Uint8Array,
  ttlMs?: number,
  options?: LedgerOptions
): Promise<SignedMandate> {
  const signed = await attenuateInternal("cart", parent, granteeDID, narrowedConstraints, grantorPrivateKey, ttlMs, options);

  // Register this child's own budget so it can sub-allocate to payment mandates
  if (options?.ledger) {
    await options.ledger.init(signed.mandate.mandateId, signed.mandate.constraints.spendLimitUsd);
  }

  return signed;
}

/**
 * Attenuate a Cart Mandate to a single-transaction Payment Mandate.
 *
 * Same inheritance, narrowing and ledger enforcement as attenuateToCart.
 * The payee still has to call redeemPaymentMandate() (see redemption.ts) at
 * settlement time — a payment mandate is a bearer-style authorisation for up
 * to spendLimitUsd, and without redemption tracking it could be presented to
 * any number of merchants.
 */
export async function attenuateToPayment(
  parent: SignedMandate,
  granteeDID: string,
  narrowedConstraints: SpendingConstraints,
  grantorPrivateKey: Uint8Array,
  ttlMs?: number,
  options?: LedgerOptions
): Promise<SignedMandate> {
  return attenuateInternal("payment", parent, granteeDID, narrowedConstraints, grantorPrivateKey, ttlMs, options);
}

async function attenuateInternal(
  tier: "cart" | "payment",
  parent: SignedMandate,
  granteeDID: string,
  narrowedConstraints: SpendingConstraints,
  grantorPrivateKey: Uint8Array,
  ttlMs: number | undefined,
  options: LedgerOptions | undefined
): Promise<SignedMandate> {
  const parentTier = parent.mandate.mandateTier;
  if (TIER_RANK[tier] < TIER_RANK[parentTier]) {
    throw new Error(`Cannot attenuate ${parentTier} → ${tier}: a child cannot be a broader tier than its parent`);
  }

  const constraints = inheritConstraints(parent.mandate.constraints, narrowedConstraints);
  assertNarrowing(parent.mandate.constraints, constraints, parentTier, tier);

  // Resolve the ancestry BEFORE touching the ledger, so a parent we cannot
  // build a chain from does not leave a dangling allocation behind.
  const chain = ancestryIncludingParent(parent);

  let allocationId: string | undefined;
  if (options?.ledger) {
    const result = await options.ledger.allocate(
      parent.mandate.mandateId,
      constraints.spendLimitUsd
    );
    allocationId = result.allocationId;
  }

  // A child may never outlive its parent. Pass the clamped expiry as an
  // ABSOLUTE instant: converting it back to a relative TTL means a second
  // Date.now() inside the issuer, and the milliseconds between the two reads
  // land the child one tick past the parent — which verifyMandateChain
  // rejects (same bug that was fixed for task mandates).
  const parentExpiry = new Date(parent.mandate.expiresAt).getTime();
  const expiry = ttlMs ? Math.min(parentExpiry, Date.now() + ttlMs) : parentExpiry;

  const signed = await issueMandateInternal(
    tier,
    parent.mandate.grantee,
    granteeDID,
    constraints,
    parent.mandate.mandateId,
    grantorPrivateKey,
    expiry,
    chain,
    // Inherited unconditionally: a child acting for the other side of the
    // payment than its parent is exactly what the field exists to rule out.
    parent.mandate.actingFor
  );

  return { ...signed, allocationId };
}

/**
 * The chain a child of `parent` must carry: the parent's own ancestry
 * followed by the parent. Prefers the structured `chain` field, falls back
 * to decoding `parent.token` (for SignedMandate objects that were rebuilt by
 * hand from a token), and finally accepts a legacy v1 parent only if it is a
 * root — a v1 child's ancestors were never transmitted, so there is nothing
 * to embed and any child we minted would fail verification downstream.
 */
function ancestryIncludingParent(parent: SignedMandate): MandateChainLink[] {
  let version = parent.v;
  let ancestors = parent.chain;
  if (ancestors === undefined && typeof parent.token === "string") {
    const decoded = parseMandateToken(parent.token);
    if (typeof decoded !== "string" && decoded.leaf.mandate.mandateId === parent.mandate.mandateId) {
      version = decoded.leaf.v;
      ancestors = decoded.ancestors;
    }
  }
  const v: 1 | 2 = version === 2 ? 2 : 1;
  if (ancestors === undefined) {
    if (parent.mandate.parentMandateId !== null) {
      throw new Error(
        "Cannot attenuate a legacy v1 mandate that is not a root: its ancestry was never embedded, " +
        "so the child could not be verified back to the human. Re-issue the chain from the root."
      );
    }
    ancestors = [];
  }
  return [...ancestors, { v, mandate: parent.mandate, signature: parent.signature }];
}

/**
 * Decode a mandate token into a SignedMandate (no verification — call
 * verifyMandateChain for that). Useful for an agent that received a token
 * and now wants to attenuate it further.
 */
export function decodeMandateToken(token: string): SignedMandate {
  const parsed = parseMandateToken(token);
  if (typeof parsed === "string") throw new Error(parsed);
  return {
    mandate: parsed.leaf.mandate,
    signature: parsed.leaf.signature,
    token,
    v: parsed.leaf.v,
    chain: parsed.leaf.v === 2 ? parsed.ancestors : undefined,
  };
}

// ─── Release ──────────────────────────────────────────────────────────────────

/**
 * Return an unused allocation to the parent mandate's budget.
 *
 * Call this during saga compensation after a step is cancelled, or when a
 * mandate expires before it is used. The released amount becomes available
 * for new child mandates.
 *
 * @param parentMandateId  mandate.mandateId of the mandate that issued the child
 * @param allocationId     the allocationId returned by attenuateToCart / attenuateToPayment
 * @param ledger           the same ledger instance used when attenuating
 */
export async function releaseAllocation(
  parentMandateId: string,
  allocationId: string,
  ledger: ISpendingLedger
): Promise<{ remainingUsd: number }> {
  return ledger.release(parentMandateId, allocationId);
}

// ─── Verify ───────────────────────────────────────────────────────────────────

/**
 * Verify a mandate token against ONE caller-supplied key.
 *
 * IMPORTANT — what this does and does not prove:
 *   - It proves the leaf mandate was signed by the holder of `publicKey`,
 *     is within its time window, is not revoked, and (optionally) names
 *     `expectedGrantee`.
 *   - For a v2 token it ALSO verifies the embedded chain back to a root
 *     (resolving ancestor keys with options.resolveKey, default
 *     content-addressed DIDs), and rejects the token if that fails. The
 *     result then has chainVerified: true.
 *   - For a legacy v1 token that is not itself a root, it CANNOT prove
 *     human authorisation: there is no ancestry to check, so anyone with a
 *     key can mint a "cart" naming any parentMandateId. Such results have
 *     chainVerified: false. Gate money on verifyMandateChain() (or on
 *     chainVerified === true plus expectedRoot), not on `valid` alone.
 *
 * @param token            base64url mandate token from credentialToken field
 * @param publicKey        Ed25519 public key of the LEAF mandate's grantor (32 bytes)
 * @param expectedGrantee  If set, validates the grantee DID matches
 */
export async function verifyMandate(
  token: string,
  publicKey: Uint8Array,
  expectedGrantee?: string,
  options?: VerifyMandateOptions
): Promise<MandateVerificationResult> {
  const governedGap = checkGovernedPrerequisites(options ?? {});
  if (governedGap) return { valid: false, reason: governedGap };

  const parsed = parseMandateToken(token);
  if (typeof parsed === "string") return { valid: false, reason: parsed };

  const { leaf } = parsed;
  const mandate = leaf.mandate;
  const now = options?.now ?? Date.now();
  const tolerance = options?.clockToleranceMs ?? DEFAULT_CLOCK_TOLERANCE_MS;

  const timeProblem = checkTimeWindow(mandate, now, tolerance);
  if (timeProblem) return { valid: false, reason: timeProblem };

  if (expectedGrantee && mandate.grantee !== expectedGrantee) {
    return { valid: false, reason: `Mandate grantee mismatch: expected ${expectedGrantee}` };
  }

  if (options?.keyRotatedAt !== undefined) {
    const issuedAtMs = mandate.issuedAt ? new Date(mandate.issuedAt).getTime() : 0;
    if (issuedAtMs <= options.keyRotatedAt) {
      return { valid: false, reason: "Mandate was signed with a since-rotated key" };
    }
  }

  const sigProblem = await checkLinkSignature(leaf, publicKey);
  if (sigProblem) return { valid: false, reason: sigProblem };

  const revokedProblem = await checkRevocation(mandate, options?.isRevoked);
  if (revokedProblem) return { valid: false, reason: revokedProblem };

  if (leaf.v === 1) {
    const isRoot = mandate.parentMandateId === null;
    if (!isRoot && options?.governed === true) {
      return { valid: false, reason: "Legacy v1 token carries no ancestry; the governed profile requires a verified chain" };
    }
    // A v1 ROOT is a one-link chain. When any root policy beyond expectedRoot
    // is asked for (KEL, person root, trustedRoots), run it through the same
    // link verifier as v2 so those checks cannot be skipped by presenting the
    // older token format.
    if (isRoot && (options?.kelSource || options?.requirePersonRoot || options?.expectedRootPerson !== undefined
      || options?.trustedRoots !== undefined || options?.governed === true)) {
      return verifyLinks([leaf], options?.resolveKey ?? resolveContentAddressedKey, {
        ...options,
        expectedGrantee,
      }, publicKey);
    }
    if (options?.expectedRoot !== undefined) {
      if (!isRoot) {
        return { valid: false, reason: "Legacy v1 token carries no ancestry; cannot prove the expected root" };
      }
      if (mandate.grantor !== options.expectedRoot) {
        return { valid: false, reason: `Chain root mismatch: expected ${options.expectedRoot}, got ${mandate.grantor}` };
      }
    }
    if (isRoot && mandate.mandateTier !== "intent") {
      return { valid: false, reason: `A root mandate must be an intent mandate, got ${mandate.mandateTier}` };
    }
    return isRoot
      ? { valid: true, mandate, chainVerified: true, chain: [mandate], rootGrantor: mandate.grantor }
      : { valid: true, mandate, chainVerified: false };
  }

  // v2: the token claims a chain, so the chain must verify. The leaf's key is
  // the one the caller vouched for; every ancestor is resolved independently.
  //
  // The caller's key applies to the LEAF LINK ONLY — by position, never by
  // DID. This used to be `did === mandate.grantor ? publicKey : resolve(did)`,
  // which handed the caller's key to any ANCESTOR whose grantor DID equalled
  // the leaf's: a forged root naming the leaf grantor as its own grantor, and
  // signed by the leaf grantor's key, verified as if the real root had signed
  // it. Self-delegation made that the normal shape, not an edge case.
  const ancestorResolver = options?.resolveKey ?? resolveContentAddressedKey;

  // A self-certifying leaf grantor carries its own key; a caller key that
  // disagrees with it is refused rather than trusted.
  const derived = await resolveContentAddressedKey(mandate.grantor).catch(() => null);
  if (derived && !bytesEqual(derived, publicKey)) {
    return { valid: false, reason: "Supplied key does not match the key derived from the grantor DID" };
  }

  return verifyLinks([...parsed.ancestors, leaf], ancestorResolver, {
    ...options,
    expectedGrantee,
  }, publicKey);
}

/**
 * Verify a mandate token all the way back to its human root.
 *
 * This is the check a payee must run before moving money. For every link,
 * root first:
 *   - the signature verifies against resolveKey(link.grantor)
 *   - root: parentMandateId is null, tier is "intent", grantor equals
 *     opts.expectedRoot when given
 *   - child: grantor === parent.grantee, parentMandateId === parent.mandateId,
 *     tier is not broader than the parent's (intent → cart → payment),
 *     constraints narrow the parent's (checkNarrowing — re-run here because
 *     the attenuation-time check is only advisory), expiresAt ≤ parent's
 *   - time window: expiresAt, issuedAt, validFrom, validUntil
 *   - opts.isRevoked(mandateId) is false
 *
 * A legacy v1 token is accepted only if it is itself a root.
 *
 * @param resolveKey  DID → Ed25519 public key. Defaults to deriving it from
 *                    content-addressed `did:aroha:z…` DIDs; pass a
 *                    registry-backed resolver for namespaced DIDs.
 */
export async function verifyMandateChain(
  token: string,
  resolveKey: MandateKeyResolver = resolveContentAddressedKey,
  opts: VerifyMandateChainOptions = {}
): Promise<MandateVerificationResult> {
  // Warn only when the hook was merely left out; `isRevoked: null` is the
  // caller's explicit, documented opt-out and must not be nagged about.
  if (opts.isRevoked === undefined) warnNoRevocationOnce();

  const parsed = parseMandateToken(token);
  if (typeof parsed === "string") return { valid: false, reason: parsed };

  if (parsed.leaf.v === 1 && parsed.leaf.mandate.parentMandateId !== null) {
    return {
      valid: false,
      reason: "Legacy v1 token carries no ancestry; it cannot be verified back to a root",
    };
  }
  return verifyLinks([...parsed.ancestors, parsed.leaf], resolveKey, opts);
}

let revocationWarningShown = false;

/**
 * One warning per process when a chain is verified with no revocation hook.
 * WHY a warning and not an error: the default stays non-breaking for callers
 * that verify offline (tests, audits, replays), but a production gate that
 * forgot the hook would otherwise honour a revoked mandate until it expires
 * and say nothing. Once per process so a busy verifier does not flood logs.
 */
function warnNoRevocationOnce(): void {
  if (revocationWarningShown) return;
  revocationWarningShown = true;
  console.warn(
    "[aroha-credentials] verifyMandateChain ran without isRevoked: a revoked mandate is accepted until it expires. " +
    "Pass a revocation hook (e.g. httpRevocationCheck), or use governedVerification() to require one."
  );
}

async function verifyLinks(
  links: MandateChainLink[],
  resolveKey: MandateKeyResolver,
  opts: VerifyMandateChainOptions,
  /** Key for the final link only (verifyMandate's caller-vouched key). Never used for ancestors. */
  leafKey?: Uint8Array,
): Promise<MandateVerificationResult> {
  const now = opts.now ?? Date.now();
  const tolerance = opts.clockToleranceMs ?? DEFAULT_CLOCK_TOLERANCE_MS;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  const governedGap = checkGovernedPrerequisites(opts);
  if (governedGap) return { valid: false, reason: governedGap };

  if (links.length === 0) return { valid: false, reason: "Empty mandate chain" };
  if (links.length > maxDepth) {
    return { valid: false, reason: `Mandate chain has ${links.length} links; maximum is ${maxDepth}` };
  }

  const requirePerson = opts.requirePersonRoot === true || opts.expectedRootPerson !== undefined;
  if (requirePerson && !opts.kelSource) {
    return { valid: false, reason: "requirePersonRoot needs a kelSource to verify the root person's KEL" };
  }
  const kelStateOf = opts.kelSource ? kelLookup(opts.kelSource, opts.kelStore) : null;

  const seen = new Set<string>();
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const m = link.mandate;
    const where = `chain link ${i} (${m.mandateTier} ${m.mandateId})`;
    const fail = (reason: string): MandateVerificationResult => ({ valid: false, reason: `${where}: ${reason}` });

    if (seen.has(m.mandateId)) return fail("mandateId repeats within the chain");
    seen.add(m.mandateId);

    // Signature first: everything else below reads fields of this link, and
    // none of them mean anything until we know who wrote them.
    let key: Uint8Array | null;
    let grantorKel: KelState | null = null;
    if (kelStateOf && isInceptionDid(m.grantor)) {
      const r = await kelStateOf(m.grantor);
      if ("error" in r) return fail(`grantor ${m.grantor}: ${r.error}`);
      grantorKel = r.state;
      key = r.state.currentKey;
    } else if (leafKey && i === links.length - 1) {
      key = leafKey;
    } else {
      try {
        key = await resolveKey(m.grantor);
      } catch {
        return fail(`Key resolution failed for grantor ${m.grantor}`);
      }
    }
    if (!key) return fail(`Cannot resolve public key for grantor ${m.grantor}`);
    const sigProblem = await checkLinkSignature(link, key);
    if (sigProblem) return fail(sigProblem);

    // The grantee holds this link's authority: if it was revoked, so was that.
    if (kelStateOf && isInceptionDid(m.grantee)) {
      const r = await kelStateOf(m.grantee);
      if ("error" in r) return fail(`grantee ${m.grantee}: ${r.error}`);
    }

    if (i === 0) {
      if (m.parentMandateId !== null) {
        return fail("first link has a parentMandateId — the token does not carry its full ancestry back to a root");
      }
      if (m.mandateTier !== "intent") {
        return fail(`a root mandate must be an intent mandate, got ${m.mandateTier}`);
      }
      if (opts.expectedRoot !== undefined && m.grantor !== opts.expectedRoot) {
        return fail(`Chain root mismatch: expected ${opts.expectedRoot}, got ${m.grantor}`);
      }
      if (opts.trustedRoots !== undefined && !opts.trustedRoots.includes(m.grantor)) {
        return fail(`root grantor ${m.grantor} is not a trusted root`);
      }
      if (requirePerson) {
        // grantorKel is set exactly when the root is an E-DID (kelSource is
        // guaranteed above), and kelLookup has already refused a revoked one.
        if (!grantorKel) return fail(`root grantor ${m.grantor} is not a person identity (did:aroha:E…)`);
        if (grantorKel.kind !== "person") return fail(`root grantor ${m.grantor} is an ${grantorKel.kind}, not a person`);
        if (opts.expectedRootPerson !== undefined && m.grantor !== opts.expectedRootPerson) {
          return fail(`Chain root mismatch: expected person ${opts.expectedRootPerson}, got ${m.grantor}`);
        }
      }
    } else {
      const p = links[i - 1].mandate;
      if (m.grantor !== p.grantee) {
        return fail(`grantor ${m.grantor} is not the parent's grantee ${p.grantee}`);
      }
      if (m.parentMandateId !== p.mandateId) {
        return fail(`parentMandateId ${String(m.parentMandateId)} does not match the parent's mandateId ${p.mandateId}`);
      }
      if (TIER_RANK[m.mandateTier] < TIER_RANK[p.mandateTier]) {
        return fail(`tier ${m.mandateTier} is broader than the parent's ${p.mandateTier}`);
      }
      const narrowing = checkNarrowing(p.constraints, m.constraints, p.mandateTier, m.mandateTier);
      if (narrowing) return fail(narrowing);
      // A declared acting-for side is part of the authority: a child that
      // drops it (undeclared) or flips it would let one chain act for both
      // the payer and the payee.
      if (p.actingFor !== undefined && m.actingFor !== p.actingFor) {
        return fail(`actingFor ${String(m.actingFor ?? "unset")} does not match the parent's ${p.actingFor}`);
      }
      if (Date.parse(m.expiresAt) > Date.parse(p.expiresAt)) {
        return fail(`expiresAt ${m.expiresAt} outlives the parent's ${p.expiresAt}`);
      }
    }

    const timeProblem = checkTimeWindow(m, now, tolerance);
    if (timeProblem) return fail(timeProblem);

    const revokedProblem = await checkRevocation(m, opts.isRevoked);
    if (revokedProblem) return fail(revokedProblem);
  }

  const leaf = links[links.length - 1].mandate;
  if (opts.expectedGrantee && leaf.grantee !== opts.expectedGrantee) {
    return { valid: false, reason: `Mandate grantee mismatch: expected ${opts.expectedGrantee}` };
  }

  return {
    valid: true,
    mandate: leaf,
    chainVerified: true,
    chain: links.map((l) => l.mandate),
    rootGrantor: links[0].mandate.grantor,
  };
}

/**
 * The KEL lookup verifyMandateChain uses, exported so other chain verifiers
 * (task-mandate chains in @aroha-sdk/delegation) apply the SAME rules —
 * controller required, revoked identity or controller is an error, a
 * missing or rejected log is an error — instead of a copy that could drift.
 * Create one per verification: results are memoised for its lifetime.
 */
export function createKelLookup(
  source: KelSource,
  store?: KelStore
): (did: string) => Promise<{ state: KelState } | { error: string }> {
  return kelLookup(source, store);
}

/**
 * Per-verification KEL lookup: resolves each E-DID once (with its controller,
 * which is REQUIRED here — the controller's log is what proves an agent has
 * not been revoked) and folds revocation into an error.
 */
function kelLookup(
  source: KelSource,
  store: KelStore | undefined
): (did: string) => Promise<{ state: KelState } | { error: string }> {
  const cache = new Map<string, Promise<{ state: KelState } | { error: string }>>();
  return (did) => {
    let p = cache.get(did);
    if (!p) {
      p = (async () => {
        try {
          const state = await resolveKelState(did, source, { store, requireController: true });
          if (!state) return { error: "no Key Event Log available" };
          if (state.revoked) return { error: "identity has been revoked" };
          if (state.controllerRevoked) return { error: `controller ${state.controller} has been revoked` };
          return { state };
        } catch (e) {
          return { error: `Key Event Log rejected: ${(e as Error).message}` };
        }
      })();
      cache.set(did, p);
    }
    return p;
  };
}

// ─── Enforcement ─────────────────────────────────────────────────────────────

export interface EnforceSpendingConstraintsOptions extends MandateCheckOptions, MandateKelOptions {
  /** Maximum number of links accepted for a v2 token, root and leaf included. Default 8. */
  maxDepth?: number;
  /** Your own DID — verified against mandate.grantee. Omit to skip grantee check. */
  expectedGrantee?: string;
  /** The merchant's DID — checked against constraints.allowedMerchants when not null. */
  merchantDID?: string;
  /** The proposed transaction amount in USD. Must not exceed mandate.spendLimitUsd. */
  proposedAmountUsd: number;
  /**
   * Unix ms timestamp of the grantor's most recent key rotation (agent_records.key_rotated_at).
   * Forwarded to verifyMandate to reject tokens signed with a since-rotated key.
   */
  keyRotatedAt?: number;
  /** Resolver for ancestor keys of a v2 token (see VerifyMandateOptions.resolveKey). */
  resolveKey?: MandateKeyResolver;
  /**
   * Require the token to be verified back to a root (chainVerified). Default
   * false for backward compatibility with legacy v1 child tokens — set it to
   * true at any gate that moves real money. Forced on when `governed` is set
   * (a governed profile cannot be weakened by passing requireChain: false).
   */
  requireChain?: boolean;
}

/**
 * Verify a mandate token AND assert the proposed spend is within its constraints.
 *
 * This is the function you must call at your payment gate before moving any funds.
 * Pair it with redeemPaymentMandate() so the same payment mandate cannot be
 * spent more than once (or beyond its limit cumulatively).
 *
 * Throws SpendingConstraintViolation if:
 *   - The mandate is expired, tampered with, revoked, or grantee-mismatched
 *   - requireChain is set and the token does not verify back to a root
 *   - proposedAmountUsd is not a finite, non-negative number
 *   - proposedAmountUsd exceeds spendLimitUsd
 *   - merchantDID is provided but not in constraints.allowedMerchants
 */
export async function enforceSpendingConstraints(
  token: string,
  grantorPublicKey: Uint8Array,
  options: EnforceSpendingConstraintsOptions
): Promise<ArohaSpendingMandateBody> {
  const result = await verifyMandate(token, grantorPublicKey, options.expectedGrantee, {
    keyRotatedAt: options.keyRotatedAt,
    resolveKey: options.resolveKey,
    isRevoked: options.isRevoked,
    clockToleranceMs: options.clockToleranceMs,
    now: options.now,
    expectedRoot: options.expectedRoot,
    trustedRoots: options.trustedRoots,
    governed: options.governed,
    kelSource: options.kelSource,
    kelStore: options.kelStore,
    requirePersonRoot: options.requirePersonRoot,
    expectedRootPerson: options.expectedRootPerson,
    maxDepth: options.maxDepth,
  });
  if (!result.valid) {
    throw new SpendingConstraintViolation(`Mandate invalid: ${result.reason}`, "MANDATE_INVALID");
  }
  if ((options.requireChain || options.governed === true) && !result.chainVerified) {
    throw new SpendingConstraintViolation(
      "Mandate invalid: token does not carry a chain verifiable back to a root mandate",
      "MANDATE_INVALID"
    );
  }

  const { constraints } = result.mandate!;

  // `NaN > limit` is false, so without this a NaN amount sailed through the
  // limit comparison below.
  if (typeof options.proposedAmountUsd !== "number" || !Number.isFinite(options.proposedAmountUsd) || options.proposedAmountUsd < 0) {
    throw new SpendingConstraintViolation(
      `Proposed amount ${String(options.proposedAmountUsd)} is not a finite, non-negative number`,
      "INVALID_AMOUNT"
    );
  }

  if (options.proposedAmountUsd > constraints.spendLimitUsd) {
    throw new SpendingConstraintViolation(
      `Proposed $${options.proposedAmountUsd} exceeds mandate limit $${constraints.spendLimitUsd}`,
      "LIMIT_EXCEEDED"
    );
  }

  // Fail-closed: if the mandate restricts merchants, a merchantDID is required.
  const merchantProblem = checkSpendMerchant(constraints, options.merchantDID);
  if (merchantProblem) throw new SpendingConstraintViolation(merchantProblem, "MERCHANT_NOT_ALLOWED");

  return result.mandate!;
}

// ─── Per-spend checks (shared by every spending gate) ────────────────────────
//
// One definition of what a single spend must satisfy against one mandate's
// constraints, used by enforceSpendingConstraints, redeemPaymentMandate and
// verifyHttpSpendRequest, so the gates cannot drift apart. They are pure: no
// signature or chain checks (run verifyMandateChain first) and no running
// totals (that is the ledger's or the redemption store's job).

const SPEND_MICROS_PER_USD = 1_000_000;

/**
 * The cumulative cap a mandate puts on everything spent under it: the
 * tighter of `spendLimitUsd` and `sessionLimitUsd`. The protocol carries no
 * session identifier, so a verifier treats a mandate's whole lifetime as one
 * session (the same rule payment-mandate redemption uses).
 */
export function mandateCumulativeLimitUsd(constraints: SpendingConstraints): number {
  return Math.min(constraints.spendLimitUsd, constraints.sessionLimitUsd ?? Infinity);
}

/** USD to integer micro-USD, the unit running totals are kept in. */
export function spendAmountMicros(amountUsd: number): number {
  return Math.round(amountUsd * SPEND_MICROS_PER_USD);
}

/**
 * Why `amountUsd` cannot be spent, or null. A spend must be a finite number
 * greater than zero, at least one micro-dollar (a smaller positive amount
 * rounds to nothing and could be repeated forever), and small enough to
 * account for exactly.
 */
export function checkSpendAmount(amountUsd: unknown): string | null {
  if (typeof amountUsd !== "number" || !Number.isFinite(amountUsd) || amountUsd <= 0) {
    return `Amount ${String(amountUsd)} must be a finite number greater than 0`;
  }
  const micros = spendAmountMicros(amountUsd);
  if (micros < 1) return `Amount ${String(amountUsd)} is below the smallest unit (1 micro-USD)`;
  if (!Number.isSafeInteger(micros)) return `Amount ${String(amountUsd)} is too large to account for exactly`;
  return null;
}

/**
 * Why paying `merchant` is outside the mandate's `allowedMerchants`, or null.
 * Fails closed: a mandate that restricts merchants refuses a spend whose
 * merchant was not given. An empty list allows no merchant at all.
 */
export function checkSpendMerchant(constraints: SpendingConstraints, merchant: string | undefined): string | null {
  if (constraints.allowedMerchants == null) return null;
  if (merchant === undefined) return "merchantDID is required when the mandate restricts allowedMerchants";
  if (!constraints.allowedMerchants.includes(merchant)) {
    return `Merchant ${merchant} is not in the mandate's allowed merchant list`;
  }
  return null;
}

/** What a server is about to spend, as checked by checkSpendAgainstConstraints. */
export interface SpendRequest {
  /** Amount of this one spend. Must already have passed checkSpendAmount. */
  amountUsd: number;
  /** ISO 4217 code of the amount. Default "USD", the same default a mandate's `currency` has. */
  currency?: string;
  /** The payee's DID. Required when any mandate restricts `allowedMerchants`. */
  merchant?: string;
  /** The payee's merchant category. Required when any mandate sets `merchantCategory`. */
  merchantCategory?: string;
  /**
   * True only when a human approved THIS spend out of band. Required for an
   * amount above `requireHumanApprovalAboveUsd`.
   */
  humanApproved?: boolean;
}

export type SpendConstraintCode =
  | "CURRENCY_MISMATCH"
  | "MERCHANT_NOT_ALLOWED"
  | "MERCHANT_CATEGORY_NOT_ALLOWED"
  | "HUMAN_APPROVAL_REQUIRED"
  | "OVER_LIMIT";

/**
 * Check one spend against ONE mandate's constraints, in this order:
 * currency, allowedMerchants, merchantCategory, requireHumanApprovalAboveUsd,
 * then the amount against mandateCumulativeLimitUsd (this spend alone; the
 * running total is the ledger's job). Every input a constraint needs must be
 * supplied: a missing one refuses (fail closed). The validity window
 * (validFrom / validUntil, expiresAt) belongs to the mandate, not the spend:
 * verifyMandateChain checks it on every link.
 */
export function checkSpendAgainstConstraints(
  constraints: SpendingConstraints,
  request: SpendRequest,
): { code: SpendConstraintCode; reason: string } | null {
  const want = constraints.currency ?? "USD";
  const got = request.currency ?? "USD";
  if (got !== want) return { code: "CURRENCY_MISMATCH", reason: `Spend is in ${got}; the mandate is in ${want}` };

  const merchant = checkSpendMerchant(constraints, request.merchant);
  if (merchant) return { code: "MERCHANT_NOT_ALLOWED", reason: merchant };

  if (constraints.merchantCategory != null) {
    if (request.merchantCategory === undefined) {
      return { code: "MERCHANT_CATEGORY_NOT_ALLOWED", reason: "merchantCategory is required when the mandate restricts merchantCategory" };
    }
    if (request.merchantCategory !== constraints.merchantCategory) {
      return {
        code: "MERCHANT_CATEGORY_NOT_ALLOWED",
        reason: `Merchant category ${request.merchantCategory} is not the mandate's ${constraints.merchantCategory}`,
      };
    }
  }

  if (constraints.requireHumanApprovalAboveUsd !== undefined
    && request.amountUsd > constraints.requireHumanApprovalAboveUsd && request.humanApproved !== true) {
    return {
      code: "HUMAN_APPROVAL_REQUIRED",
      reason: `$${request.amountUsd} is above the mandate's human-approval threshold of $${constraints.requireHumanApprovalAboveUsd}`,
    };
  }

  const limit = mandateCumulativeLimitUsd(constraints);
  if (spendAmountMicros(request.amountUsd) > spendAmountMicros(limit)) {
    return { code: "OVER_LIMIT", reason: `$${request.amountUsd} exceeds the mandate's limit of $${limit}` };
  }
  return null;
}

export class SpendingConstraintViolation extends Error {
  constructor(
    message: string,
    public readonly code:
      | "MANDATE_INVALID"
      | "LIMIT_EXCEEDED"
      | "MERCHANT_NOT_ALLOWED"
      | "INVALID_AMOUNT"
      | "REDEMPTION_LIMIT_EXCEEDED"
  ) {
    super(message);
    this.name = "SpendingConstraintViolation";
  }
}

// ─── Canonicalisation & signing ───────────────────────────────────────────────

/**
 * The exact string a v2 mandate signature covers: RFC 8785 JCS of
 * { "mandate": <body>, "v": 2 }. Exported so other SDKs' conformance tests
 * (and test-vectors/mandate-v2.json) can pin it byte for byte.
 */
export function mandateSigningPayloadV2(mandate: ArohaSpendingMandateBody): string {
  return canonicalizeJcs({ mandate, v: 2 });
}

/**
 * Legacy v1 canonical form. Kept ONLY to verify tokens issued before v2 —
 * it is JavaScript's JSON.stringify after key sorting, which is not a
 * specified format and is not guaranteed to match other languages.
 */
function canonicalizeMandateV1(mandate: ArohaSpendingMandateBody): string {
  return JSON.stringify(sortKeys(mandate));
}

function signingBytes(v: 1 | 2, mandate: ArohaSpendingMandateBody): Uint8Array {
  const s = v === 2 ? mandateSigningPayloadV2(mandate) : canonicalizeMandateV1(mandate);
  return new TextEncoder().encode(s);
}

async function checkLinkSignature(link: MandateChainLink, publicKey: Uint8Array): Promise<string | null> {
  try {
    const sigBytes = Buffer.from(link.signature, "base64url");
    const valid = await ed.verifyAsync(sigBytes, signingBytes(link.v, link.mandate), publicKey);
    return valid ? null : "Invalid signature";
  } catch {
    return "Signature verification error";
  }
}

async function checkRevocation(
  mandate: ArohaSpendingMandateBody,
  isRevoked: MandateRevocationCheck | null | undefined
): Promise<string | null> {
  if (!isRevoked) return null;
  try {
    return (await isRevoked(mandate.mandateId, mandate.grantor)) ? `Mandate ${mandate.mandateId} has been revoked` : null;
  } catch {
    // A revocation service we cannot reach is not evidence of non-revocation.
    return `Revocation check failed for mandate ${mandate.mandateId}`;
  }
}

/**
 * Time checks for one mandate. Expiry-side checks are strict; not-before
 * checks get `tolerance` ms of slack for issuer/verifier clock skew (see
 * MandateCheckOptions.clockToleranceMs for why the asymmetry).
 */
function checkTimeWindow(m: ArohaSpendingMandateBody, now: number, tolerance: number): string | null {
  if (Date.parse(m.expiresAt) < now) return "Mandate expired";
  // A body that expires before it was issued is either corrupt or built to
  // confuse the time-window checks; neither is a mandate anyone signed on
  // purpose. Checked after "expired" so an ordinary stale token keeps its
  // ordinary reason.
  if (Date.parse(m.expiresAt) < Date.parse(m.issuedAt)) return "Mandate expires before it was issued";
  if (Date.parse(m.issuedAt) > now + tolerance) return `Mandate issuedAt ${m.issuedAt} is in the future`;
  const { validFrom, validUntil } = m.constraints;
  if (validFrom !== undefined && Date.parse(validFrom) > now + tolerance) {
    return `Mandate not yet valid (validFrom ${validFrom})`;
  }
  if (validUntil !== undefined && Date.parse(validUntil) < now) {
    return `Mandate validity window has ended (validUntil ${validUntil})`;
  }
  return null;
}

// ─── Token parsing & shape validation ─────────────────────────────────────────

interface ParsedMandateToken {
  leaf: MandateChainLink;
  /** Root first, excluding the leaf. Always empty for v1. */
  ancestors: MandateChainLink[];
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Returns the parsed token or a human-readable reason it was rejected. */
function parseMandateToken(token: string): ParsedMandateToken | string {
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    return "Malformed token";
  }
  if (!isRecord(raw)) return "Malformed token";

  const v = raw.v === undefined ? 1 : raw.v;
  if (v !== 1 && v !== 2) return `Unsupported mandate token version: ${String(raw.v)}`;
  // A v1 token never had a chain; one that does is either corrupt or an
  // attempt to make a chain look optional by dropping the version marker.
  if (v === 1 && raw.chain !== undefined) return "Malformed token: chain present without v: 2";

  const leaf = toLink(v, raw);
  if (typeof leaf === "string") return `Malformed token: ${leaf}`;

  const ancestors: MandateChainLink[] = [];
  if (v === 2) {
    if (!Array.isArray(raw.chain)) return "Malformed token: v2 token requires a chain array";
    for (let i = 0; i < raw.chain.length; i++) {
      const entry = raw.chain[i];
      if (!isRecord(entry) || (entry.v !== 1 && entry.v !== 2)) {
        return `Malformed token: chain[${i}] is not a versioned link`;
      }
      const link = toLink(entry.v, entry);
      if (typeof link === "string") return `Malformed token: chain[${i}]: ${link}`;
      ancestors.push(link);
    }
  }
  return { leaf, ancestors };
}

function toLink(v: 1 | 2, raw: Record<string, unknown>): MandateChainLink | string {
  if (typeof raw.signature !== "string") return "signature missing";
  const shape = checkMandateShape(raw.mandate);
  if (shape) return shape;
  return { v, mandate: raw.mandate as ArohaSpendingMandateBody, signature: raw.signature };
}

function isIsoDate(x: unknown): x is string {
  return typeof x === "string" && !Number.isNaN(Date.parse(x));
}

function isAmount(x: unknown): x is number {
  return typeof x === "number" && Number.isFinite(x) && x >= 0;
}

/**
 * Structural validation of a decoded mandate body. Everything downstream
 * compares these fields; a missing or mistyped one must not be allowed to
 * turn a comparison into a silent pass (`undefined > 5` is false, and so is
 * `NaN > 5`).
 */
function checkMandateShape(m: unknown): string | null {
  if (!isRecord(m)) return "mandate is not an object";
  // A task mandate is not a spending mandate, whatever else it carries. Its
  // tiers overlap ("intent", "cart") and a v1 task signature covers the same
  // sortKeys bytes as a v1 spending one, so refuse the type marker outright
  // rather than rely on the other fields happening to differ.
  if (m.mandateType !== undefined) return "mandateType present: this is a task mandate, not a spending mandate";
  if (m.mandateTier !== "intent" && m.mandateTier !== "cart" && m.mandateTier !== "payment") {
    return "mandateTier is invalid";
  }
  for (const f of ["grantor", "grantee", "mandateId"] as const) {
    if (typeof m[f] !== "string" || (m[f] as string).length === 0) return `${f} is missing`;
  }
  if (!isIsoDate(m.issuedAt)) return "issuedAt is not a date";
  if (!isIsoDate(m.expiresAt)) return "expiresAt is not a date";
  if (m.parentMandateId !== null && typeof m.parentMandateId !== "string") return "parentMandateId is invalid";
  if (m.actingFor !== undefined && m.actingFor !== "payer" && m.actingFor !== "payee") return "actingFor is invalid";
  return checkConstraintsShape(m.constraints);
}

function checkConstraintsShape(c: unknown): string | null {
  if (!isRecord(c)) return "constraints is not an object";
  if (!isAmount(c.spendLimitUsd)) return "constraints.spendLimitUsd must be a finite, non-negative number";
  for (const f of ["sessionLimitUsd", "requireHumanApprovalAboveUsd"] as const) {
    if (c[f] !== undefined && !isAmount(c[f])) return `constraints.${f} must be a finite, non-negative number`;
  }
  if (c.currency !== undefined && typeof c.currency !== "string") return "constraints.currency must be a string";
  if (c.merchantCategory !== undefined && c.merchantCategory !== null && typeof c.merchantCategory !== "string") {
    return "constraints.merchantCategory must be a string or null";
  }
  if (c.allowedMerchants !== undefined && c.allowedMerchants !== null) {
    if (!Array.isArray(c.allowedMerchants) || !c.allowedMerchants.every((x) => typeof x === "string")) {
      return "constraints.allowedMerchants must be an array of DIDs or null";
    }
  }
  for (const f of ["validFrom", "validUntil"] as const) {
    if (c[f] !== undefined && !isIsoDate(c[f])) return `constraints.${f} must be an ISO 8601 date`;
  }
  return null;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function issueMandateInternal(
  tier: MandateTier,
  grantorDID: string,
  granteeDID: string,
  constraints: SpendingConstraints,
  parentMandateId: string | null,
  privateKey: Uint8Array,
  expiresAtMs: number,
  chain: MandateChainLink[],
  actingFor?: "payer" | "payee"
): Promise<SignedMandate> {
  const shapeProblem = checkConstraintsShape(constraints);
  if (shapeProblem) throw new Error(`Invalid spending constraints: ${shapeProblem}`);

  const mandate: ArohaSpendingMandateBody = {
    mandateTier: tier,
    // JSON round-trip: the body we sign must be exactly the body the verifier
    // will decode — no undefined-valued keys, no prototype, no toJSON surprises.
    constraints: JSON.parse(JSON.stringify(constraints)) as SpendingConstraints,
    grantee: granteeDID,
    grantor: grantorDID,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    parentMandateId,
    mandateId: crypto.randomUUID(),
    // Only when declared: an absent field leaves the JCS payload byte-identical
    // to tokens issued before actingFor existed.
    ...(actingFor !== undefined ? { actingFor } : {}),
  };

  const sig = await ed.signAsync(signingBytes(2, mandate), privateKey);
  const signature = Buffer.from(sig).toString("base64url");
  const token = Buffer.from(
    JSON.stringify({ v: MANDATE_TOKEN_VERSION, mandate, signature, chain })
  ).toString("base64url");

  return { v: 2, mandate, signature, token, chain };
}

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj as Record<string, unknown>)
      .sort()
      .reduce((acc, k) => {
        (acc as Record<string, unknown>)[k] = sortKeys((obj as Record<string, unknown>)[k]);
        return acc;
      }, {} as Record<string, unknown>);
  }
  return obj;
}

/**
 * Optional constraint fields a child inherits from its parent when the
 * caller leaves them out. allowedMerchants and merchantCategory are NOT on
 * this list: the attenuation API has always required callers to restate a
 * merchant restriction explicitly (omitting it is an error, not an
 * inheritance), and that stricter behaviour is kept.
 */
const INHERITED_FIELDS = [
  "sessionLimitUsd",
  "requireHumanApprovalAboveUsd",
  "validFrom",
  "validUntil",
  "currency",
] as const;

function inheritConstraints(parent: SpendingConstraints, child: SpendingConstraints): SpendingConstraints {
  const out: SpendingConstraints = { ...child };
  for (const f of INHERITED_FIELDS) {
    if (out[f] === undefined && parent[f] !== undefined) {
      (out as unknown as Record<string, unknown>)[f] = parent[f];
    }
  }
  return out;
}

/**
 * Check that `child` is a subset of `parent`. Returns null when it is, or
 * the reason it is not.
 *
 * The rule for every optional field: if the PARENT sets it, the child must
 * set it too, to an equal or narrower value. Previously each comparison only
 * ran when both sides set the field, so a child that simply omitted
 * sessionLimitUsd or requireHumanApprovalAboveUsd had no session cap and no
 * approval threshold at all — a widening that passed every check.
 *
 * Used both at attenuation time (assertNarrowing, so honest callers get an
 * early error) and by verifyMandateChain on every link (the only place it is
 * a security control, since the attenuating agent can skip its own check).
 */
export function checkNarrowing(
  parent: SpendingConstraints,
  child: SpendingConstraints,
  parentTier: string,
  childTier: string
): string | null {
  const prefix = `Cannot attenuate ${parentTier} → ${childTier}`;

  if (!isAmount(child.spendLimitUsd)) {
    return `${prefix}: child spendLimitUsd must be a finite, non-negative number`;
  }
  if (child.spendLimitUsd > parent.spendLimitUsd) {
    return `${prefix}: child spendLimitUsd (${child.spendLimitUsd}) exceeds parent (${parent.spendLimitUsd})`;
  }

  if (parent.sessionLimitUsd !== undefined) {
    if (child.sessionLimitUsd === undefined) {
      return `${prefix}: parent sets sessionLimitUsd (${parent.sessionLimitUsd}) but child omits it`;
    }
    if (!isAmount(child.sessionLimitUsd) || child.sessionLimitUsd > parent.sessionLimitUsd) {
      return `${prefix}: child sessionLimitUsd exceeds parent`;
    }
  }

  if (parent.requireHumanApprovalAboveUsd !== undefined) {
    if (child.requireHumanApprovalAboveUsd === undefined) {
      return `${prefix}: parent sets an approval threshold (requireHumanApprovalAboveUsd ${parent.requireHumanApprovalAboveUsd}) but child omits it`;
    }
    if (!isAmount(child.requireHumanApprovalAboveUsd) || child.requireHumanApprovalAboveUsd > parent.requireHumanApprovalAboveUsd) {
      return `${prefix}: child approval threshold exceeds parent`;
    }
  }

  // Currency defaults to USD on both sides; a child may not switch it.
  if ((child.currency ?? "USD") !== (parent.currency ?? "USD")) {
    return `${prefix}: child currency "${child.currency ?? "USD"}" differs from parent "${parent.currency ?? "USD"}"`;
  }

  if (parent.allowedMerchants != null) {
    if (child.allowedMerchants == null) {
      return `${prefix}: parent restricts allowedMerchants but child sets none`;
    }
    // A non-empty parent list keeps the long-standing rule that the child
    // must name at least one merchant (an empty list is almost certainly a
    // caller bug). An EMPTY parent list means "no merchant at all" — which
    // enforceSpendingConstraints honours — so the child must stay empty.
    if (parent.allowedMerchants.length > 0 && child.allowedMerchants.length === 0) {
      return `${prefix}: parent restricts allowedMerchants but child sets none`;
    }
    const parentSet = new Set(parent.allowedMerchants);
    for (const m of child.allowedMerchants) {
      if (!parentSet.has(m)) {
        return `${prefix}: child allowedMerchants contains "${m}" not in parent`;
      }
    }
  }

  if (parent.merchantCategory !== undefined && parent.merchantCategory !== null) {
    if (child.merchantCategory === null || child.merchantCategory === undefined) {
      return `${prefix}: child merchantCategory must not widen parent's "${parent.merchantCategory}" restriction`;
    }
    if (child.merchantCategory !== parent.merchantCategory) {
      return `${prefix}: child merchantCategory "${child.merchantCategory}" does not match parent "${parent.merchantCategory}"`;
    }
  }

  if (parent.validUntil !== undefined) {
    if (child.validUntil === undefined) {
      return `${prefix}: parent sets validUntil (${parent.validUntil}) but child omits it`;
    }
    const c = Date.parse(child.validUntil);
    if (Number.isNaN(c) || c > Date.parse(parent.validUntil)) {
      return `${prefix}: child validUntil (${child.validUntil}) extends beyond parent (${parent.validUntil})`;
    }
  }

  if (parent.validFrom !== undefined) {
    if (child.validFrom === undefined) {
      return `${prefix}: parent sets validFrom (${parent.validFrom}) but child omits it`;
    }
    const c = Date.parse(child.validFrom);
    if (Number.isNaN(c) || c < Date.parse(parent.validFrom)) {
      return `${prefix}: child validFrom (${child.validFrom}) precedes parent (${parent.validFrom})`;
    }
  }

  return null;
}

/** Throwing form of checkNarrowing, used at attenuation time. */
function assertNarrowing(
  parent: SpendingConstraints,
  child: SpendingConstraints,
  parentTier: string,
  childTier: string
): void {
  const reason = checkNarrowing(parent, child, parentTier, childTier);
  if (reason) throw new Error(reason);
}

// ─── Task Mandate ─────────────────────────────────────────────────────────────

export interface SignedTaskMandate {
  mandate: ArohaTaskMandateBody;
  signature: string;
  token: string;
  /**
   * Which signing rule `signature` follows: 2 (everything issued now) = JCS
   * over { mandate, purpose: "aroha.task-mandate/v2", v: 2 }; 1 (legacy,
   * absent on old objects) = sortKeys/JSON.stringify over the body.
   */
  v?: 1 | 2;
}

/** Task-mandate token version produced by issueTaskMandate / attenuateTaskMandate. */
export const TASK_MANDATE_TOKEN_VERSION = 2;

/**
 * Domain-separation tag inside every v2 task-mandate signature.
 *
 * WHY a purpose tag: a v1 task-mandate signature covered only the sorted
 * body, the same shape of bytes signInvariants and other sortKeys signers in
 * this file produce. A signature made for one kind of object could then, in
 * principle, be presented as another whose JSON happened to serialise the
 * same. Naming the purpose inside the signed bytes means a v2 task-mandate
 * signature verifies as nothing else, and nothing else verifies as it — not
 * a spending mandate (whose v2 payload has no purpose field), not a v1 token.
 */
export const TASK_MANDATE_PURPOSE = "aroha.task-mandate/v2";

/**
 * The exact string a v2 task-mandate signature covers: RFC 8785 JCS of
 * { "mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2 }.
 * Exported so conformance tests can pin it byte for byte.
 */
export function taskMandateSigningPayloadV2(mandate: ArohaTaskMandateBody): string {
  return canonicalizeJcs({ mandate, purpose: TASK_MANDATE_PURPOSE, v: 2 });
}

function taskSigningBytes(v: 1 | 2, mandate: ArohaTaskMandateBody): Uint8Array {
  const s = v === 2
    ? taskMandateSigningPayloadV2(mandate)
    : JSON.stringify(sortKeys(mandate as unknown as Record<string, unknown>));
  return new TextEncoder().encode(s);
}

/**
 * Verify one task-mandate link's signature under the rule its version names.
 * Never throws; false on any error. Shared with @aroha-sdk/delegation's
 * chain verifier so both read the version marker the same way.
 */
export async function verifyTaskMandateSignature(
  signed: { mandate: ArohaTaskMandateBody; signature: string; v?: 1 | 2 },
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const v: 1 | 2 = signed.v === 2 ? 2 : 1;
    return await ed.verifyAsync(Buffer.from(signed.signature, "base64url"), taskSigningBytes(v, signed.mandate), publicKey);
  } catch {
    return false;
  }
}

/**
 * Decode the version marker of a raw task-mandate token object. Absent = v1
 * (every token issued before v2). Anything else is refused rather than
 * guessed, so a token cannot pick a signing rule by sending garbage.
 */
export function taskMandateTokenVersion(raw: Record<string, unknown>): 1 | 2 | null {
  if (raw.v === undefined || raw.v === 1) return 1;
  if (raw.v === 2) return 2;
  return null;
}

export interface TaskMandateVerificationResult {
  valid: boolean;
  mandate?: ArohaTaskMandateBody;
  reason?: string;
}

/**
 * Issue a root Task Mandate from a user (or personal agent) to a vendor agent.
 *
 * Use this for non-monetary task delegation — research, email drafting,
 * scheduling, data analysis, etc. For tasks that also involve spending money,
 * set mandateType to "hybrid" and provide spendingConstraints.
 *
 * @param grantorDID         Issuer's DID
 * @param granteeDID         Receiving agent's DID
 * @param allowed            Explicit list of permitted capability IDs
 * @param taskConstraints    Resource limits and safety controls
 * @param privateKey         Issuer's Ed25519 private key (32 bytes)
 * @param ttlMs              Time-to-live in ms (default: 1 hour)
 * @param options            Optional: blocked caps, spending constraints, parent ID
 */
export async function issueTaskMandate(
  grantorDID: string,
  granteeDID: string,
  allowed: string[],
  taskConstraints: TaskConstraints,
  privateKey: Uint8Array,
  ttlMs = 3_600_000,
  options?: {
    blocked?: string[];
    spendingConstraints?: SpendingConstraints;
    parentMandateId?: string;
    tier?: "intent" | "cart" | "execution";
    /** Instance-level binding for this specific transaction (design spec §9.1 Layer 1). */
    invariants?: MandateInvariants;
    /**
     * Absolute expiry, overriding ttlMs.
     *
     * Attenuation needs this. Clamping a child to its parent's expiry and then
     * expressing the result as a relative TTL means calling Date.now() twice —
     * once to compute the TTL, once inside this function — and the elapsed
     * milliseconds push the child's expiry PAST the parent's. The chain
     * verifier then rejects a mandate that was correct when it was built.
     */
    expiresAtMs?: number;
  }
): Promise<SignedTaskMandate> {
  const mandateType = options?.spendingConstraints ? "hybrid" : "task";
  const draft: ArohaTaskMandateBody = {
    mandateType,
    mandateTier: options?.tier ?? "intent",
    allowed,
    blocked: options?.blocked,
    taskConstraints,
    spendingConstraints: options?.spendingConstraints,
    invariants: options?.invariants,
    grantee: granteeDID,
    grantor: grantorDID,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(options?.expiresAtMs ?? Date.now() + ttlMs).toISOString(),
    parentMandateId: options?.parentMandateId ?? null,
    mandateId: crypto.randomUUID(),
  };
  // JSON round-trip: the body we sign must be exactly the body the verifier
  // will decode — no undefined-valued optional keys (JCS has no "undefined").
  const mandate = JSON.parse(JSON.stringify(draft)) as ArohaTaskMandateBody;

  const sig = await ed.signAsync(taskSigningBytes(2, mandate), privateKey);
  const signature = Buffer.from(sig).toString("base64url");
  const token = Buffer.from(JSON.stringify({ v: TASK_MANDATE_TOKEN_VERSION, mandate, signature })).toString("base64url");
  return { mandate, signature, token, v: 2 };
}

/**
 * Attenuate a task mandate to a narrower child mandate.
 *
 * Enforces monotonic narrowing with checkTaskNarrowing — the same function
 * the chain verifier runs on every link. Every constraint the parent sets
 * must be restated equal-or-narrower; omitting one is widening. The parent's
 * blocked list and spendingConstraints are inherited when the caller does not
 * pass them; invariants must be restated explicitly.
 */
export async function attenuateTaskMandate(
  parent: SignedTaskMandate,
  granteeDID: string,
  narrowedAllowed: string[],
  narrowedConstraints: TaskConstraints,
  grantorPrivateKey: Uint8Array,
  ttlMs?: number,
  options?: { blocked?: string[]; spendingConstraints?: SpendingConstraints; invariants?: MandateInvariants }
): Promise<SignedTaskMandate> {
  // Inherit the parent's blocked list and spending constraints when the
  // caller leaves them out, instead of silently dropping them. Inheriting is
  // equal-or-narrower by construction; dropping would be a widening that the
  // chain verifier rejects on the receiving agent. Invariants are NOT
  // inherited: binding a specific transaction is a deliberate act, so a
  // parent's invariants must be restated (the long-standing contract).
  const blocked = mergeLists(parent.mandate.blocked, options?.blocked);
  const spendingConstraints = options?.spendingConstraints ?? parent.mandate.spendingConstraints;
  const invariants = options?.invariants;
  // A parent's room / on-behalf-of binding is inherited when the caller
  // leaves it out (it can never be changed, so restating it adds nothing);
  // a caller that names a DIFFERENT value still gets the narrowing error.
  const pTc = parent.mandate.taskConstraints ?? {};
  narrowedConstraints = {
    ...narrowedConstraints,
    ...(pTc.onBehalfOf !== undefined && narrowedConstraints.onBehalfOf === undefined ? { onBehalfOf: pTc.onBehalfOf } : {}),
    ...(pTc.roomId !== undefined && narrowedConstraints.roomId === undefined ? { roomId: pTc.roomId } : {}),
  };

  assertTaskNarrowing(parent.mandate, {
    allowed: narrowedAllowed,
    blocked,
    taskConstraints: narrowedConstraints,
    spendingConstraints,
    invariants,
  });

  // A child may never outlive its parent. Pass the clamped expiry as an
  // ABSOLUTE instant: converting it back to a relative TTL would require a
  // second Date.now() inside issueTaskMandate, and the milliseconds between
  // the two reads land the child one tick past the parent — which the chain
  // verifier rejects, intermittently, on the receiving agent.
  const expiry = ttlMs
    ? Math.min(new Date(parent.mandate.expiresAt).getTime(), Date.now() + ttlMs)
    : new Date(parent.mandate.expiresAt).getTime();

  return issueTaskMandate(
    parent.mandate.grantee,
    granteeDID,
    narrowedAllowed,
    narrowedConstraints,
    grantorPrivateKey,
    undefined,
    {
      expiresAtMs: expiry,
      blocked,
      spendingConstraints,
      parentMandateId: parent.mandate.mandateId,
      tier: parent.mandate.mandateTier === "intent" ? "cart" : "execution",
      invariants,
    }
  );
}

/** Union of two optional capability lists, order-preserving; undefined when both are. */
function mergeLists(a: string[] | undefined, b: string[] | undefined): string[] | undefined {
  if (!a && !b) return undefined;
  return [...new Set([...(a ?? []), ...(b ?? [])])];
}

export interface VerifyTaskMandateOptions {
  /** Override "now" (Unix ms). For tests and replayed audits. */
  now?: number;
  /**
   * Allowed clock skew for the NOT-BEFORE check on issuedAt, in ms. Default
   * 30 000 — the same asymmetry as spending mandates: slack on not-before,
   * none on expiry (see MandateCheckOptions.clockToleranceMs).
   */
  clockToleranceMs?: number;
  /**
   * Revocation hook keyed by (mandateId, grantor) — the same contract as
   * spending mandates. A hook that throws fails the verification (fail
   * closed): an unreachable revocation source is not evidence of
   * non-revocation.
   */
  isRevoked?: MandateRevocationCheck;
}

/**
 * Verify a task mandate token (shape + signature + time window + grantee +
 * revocation when a hook is given).
 *
 * Token formats:
 *   v2 — { v: 2, mandate, signature }, signature over JCS of
 *        { mandate, purpose: "aroha.task-mandate/v2", v: 2 }. Issued now.
 *   v1 — { mandate, signature } over sortKeys/JSON.stringify. Still
 *        verifiable, so tokens issued before v2 keep working until they
 *        expire. The version is inside the v2 signed bytes, so neither form
 *        can be replayed as the other.
 * Multi-hop task chains are verified by @aroha-sdk/delegation's
 * verifyTaskMandateChain.
 *
 * Hardening (why each check exists):
 *   - The token is attacker-supplied bytes. It used to be cast straight to
 *     SignedTaskMandate, so a token whose JSON was `null`, a number, or an
 *     object without `mandate` threw a TypeError out of a function whose
 *     contract is to RETURN { valid: false } — callers that only handled
 *     the result crashed (or, behind a catch-all, logged and moved on).
 *   - `new Date("garbage") < new Date()` is false, so an unparseable
 *     expiresAt used to pass the expiry check: a mandate that never expires.
 *     Dates are now parsed and NaN rejected.
 *   - issuedAt in the future (beyond clock tolerance) is rejected, matching
 *     spending mandates: a far-future issuedAt is how a pre-signed token
 *     hides its real age.
 *   - Structural checks on every field the enforcement code later compares
 *     (allowed/blocked lists, limits, constraints), because `undefined > n`
 *     and `NaN > n` are both false — a missing limit must not read as "no
 *     limit exceeded".
 */
export async function verifyTaskMandate(
  token: string,
  publicKey: Uint8Array,
  expectedGrantee?: string,
  options: VerifyTaskMandateOptions = {}
): Promise<TaskMandateVerificationResult> {
  if (typeof token !== "string" || token.length === 0) return { valid: false, reason: "Malformed token" };
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "Malformed token" };
  }
  if (!isRecord(raw)) return { valid: false, reason: "Malformed token" };
  if (typeof raw.signature !== "string" || raw.signature.length === 0) {
    return { valid: false, reason: "Malformed token: signature missing" };
  }
  const version = taskMandateTokenVersion(raw);
  if (version === null) return { valid: false, reason: `Unsupported task mandate token version: ${String(raw.v)}` };
  const shape = checkTaskMandateShape(raw.mandate);
  if (shape) return { valid: false, reason: `Malformed token: ${shape}` };
  const mandate = raw.mandate as ArohaTaskMandateBody;
  const signature = raw.signature;

  const now = options.now ?? Date.now();
  const tolerance = options.clockToleranceMs ?? DEFAULT_CLOCK_TOLERANCE_MS;
  if (Date.parse(mandate.expiresAt) < now) {
    return { valid: false, reason: "Task mandate expired" };
  }
  if (Date.parse(mandate.issuedAt) > now + tolerance) {
    return { valid: false, reason: `Task mandate issuedAt ${mandate.issuedAt} is in the future` };
  }
  if (Date.parse(mandate.expiresAt) < Date.parse(mandate.issuedAt)) {
    return { valid: false, reason: "Task mandate expires before it was issued" };
  }

  if (expectedGrantee && mandate.grantee !== expectedGrantee) {
    return { valid: false, reason: `Grantee mismatch: expected ${expectedGrantee}` };
  }

  if (!(await verifyTaskMandateSignature({ mandate, signature, v: version }, publicKey))) {
    return { valid: false, reason: "Invalid signature" };
  }

  const revoked = await checkTaskRevocation(mandate, options.isRevoked);
  if (revoked) return { valid: false, reason: revoked };

  return { valid: true, mandate };
}

/**
 * Task-mandate revocation, same contract as checkRevocation for spending
 * mandates: keyed by (mandateId, grantor), and a hook that throws is a
 * failure, never a pass. Exported for @aroha-sdk/delegation's chain verifier.
 */
export async function checkTaskRevocation(
  mandate: { mandateId: string; grantor: string },
  isRevoked: MandateRevocationCheck | undefined
): Promise<string | null> {
  if (!isRevoked) return null;
  try {
    return (await isRevoked(mandate.mandateId, mandate.grantor)) ? `Task mandate ${mandate.mandateId} has been revoked` : null;
  } catch {
    return `Revocation check failed for task mandate ${mandate.mandateId}`;
  }
}

function isStringArray(x: unknown): x is string[] {
  return Array.isArray(x) && x.every((v) => typeof v === "string");
}

function isCount(x: unknown): x is number {
  return typeof x === "number" && Number.isFinite(x) && x >= 0;
}

/**
 * Structural validation of a decoded task-mandate body (see verifyTaskMandate).
 * Exported so @aroha-sdk/delegation parses chain links with the same rules
 * the single-link verifier applies. Returns null when the shape is valid.
 */
export function checkTaskMandateShape(m: unknown): string | null {
  if (!isRecord(m)) return "mandate is not an object";
  if (m.mandateType !== "task" && m.mandateType !== "hybrid") return "mandateType is invalid";
  if (m.mandateTier !== "intent" && m.mandateTier !== "cart" && m.mandateTier !== "execution") {
    return "mandateTier is invalid";
  }
  for (const f of ["grantor", "grantee", "mandateId"] as const) {
    if (typeof m[f] !== "string" || (m[f] as string).length === 0) return `${f} is missing`;
  }
  if (!isIsoDate(m.issuedAt)) return "issuedAt is not a date";
  if (!isIsoDate(m.expiresAt)) return "expiresAt is not a date";
  if (m.parentMandateId !== null && typeof m.parentMandateId !== "string") return "parentMandateId is invalid";
  if (!isStringArray(m.allowed)) return "allowed must be an array of capability ids";
  if (m.blocked !== undefined && !isStringArray(m.blocked)) return "blocked must be an array of capability ids";

  const tc = m.taskConstraints;
  if (!isRecord(tc)) return "taskConstraints is not an object";
  if (tc.actionLimits !== undefined) {
    if (!isRecord(tc.actionLimits)) return "taskConstraints.actionLimits must be an object";
    for (const [cap, n] of Object.entries(tc.actionLimits)) {
      if (!isCount(n)) return `taskConstraints.actionLimits["${cap}"] must be a finite, non-negative number`;
    }
  }
  if (tc.computeLimit !== undefined) {
    if (!isRecord(tc.computeLimit)) return "taskConstraints.computeLimit must be an object";
    for (const f of ["llmTokens", "webRequests", "executionTimeMs", "cpuSeconds"] as const) {
      const v = tc.computeLimit[f];
      if (v !== undefined && !isCount(v)) return `taskConstraints.computeLimit.${f} must be a finite, non-negative number`;
    }
  }
  if (tc.dataAccess !== undefined) {
    if (!isRecord(tc.dataAccess)) return "taskConstraints.dataAccess must be an object";
    for (const [res, a] of Object.entries(tc.dataAccess)) {
      if (a !== "none" && a !== "read" && a !== "read-write" && a !== "write") {
        return `taskConstraints.dataAccess["${res}"] is invalid`;
      }
    }
  }
  if (tc.reversibleOnly !== undefined && typeof tc.reversibleOnly !== "boolean") {
    return "taskConstraints.reversibleOnly must be a boolean";
  }
  for (const f of ["onBehalfOf", "roomId"] as const) {
    if (tc[f] !== undefined && (typeof tc[f] !== "string" || (tc[f] as string).length === 0)) {
      return `taskConstraints.${f} must be a non-empty string`;
    }
  }

  if (m.mandateType === "hybrid" || m.spendingConstraints !== undefined) {
    const sc = checkConstraintsShape(m.spendingConstraints);
    if (sc) return `spendingConstraints: ${sc}`;
  }
  if (m.invariants !== undefined && !isRecord(m.invariants)) return "invariants must be an object";
  return null;
}

/**
 * Sign a MandateInvariants block (design spec §9.1 Layer 1).
 *
 * Called by the principal (or an intent-gate confirmation step, see
 * @aroha-sdk/orchestrator's intent-gate.ts) BEFORE any untrusted content
 * — a tool result, a remote agent's response — enters the agent loop.
 * Reuses the same sortKeys+JSON.stringify canonicalization and Ed25519
 * signing convention as every other mandate primitive in this file.
 */
export async function signInvariants(
  invariants: MandateInvariants,
  signerDid: string,
  privateKey: Uint8Array
): Promise<SignedInvariants> {
  const canonical = JSON.stringify(sortKeys(invariants as unknown as Record<string, unknown>));
  const bytes = new TextEncoder().encode(canonical);
  const sig = await ed.signAsync(bytes, privateKey);
  const signature = Buffer.from(sig).toString("base64url");
  return { invariants, signerDid, signature };
}

/**
 * Verify a SignedInvariants block's signature against the claimed signer's public key.
 * Does not check expiry or contents — call verifyInvariants for that, at commit time.
 */
export async function verifySignedInvariants(
  signed: SignedInvariants,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const canonical = JSON.stringify(sortKeys(signed.invariants as unknown as Record<string, unknown>));
    const bytes = new TextEncoder().encode(canonical);
    const sigBytes = Buffer.from(signed.signature, "base64url");
    return await ed.verifyAsync(sigBytes, bytes, publicKey);
  } catch {
    return false;
  }
}

export interface InvariantCheckActual {
  /** The DID the bound action is about to pay/target. */
  payee?: string;
  /** Actual parameter values the bound action is about to execute with. */
  parameters?: Record<string, string | number | boolean>;
  /** Actual amount the bound action is about to commit. */
  amount?: { amount: number; currency: string };
}

/**
 * Check a live, about-to-commit action against previously-signed instance
 * invariants (design spec §9.1 Layer 1) — call this at the saga's commit
 * phase, after untrusted content has already influenced the plan, to catch
 * any redirected payee, mutated parameter, or budget overrun regardless of
 * how the model was steered to get there.
 *
 * Fails closed: a field present in `invariants` but absent from `actual`
 * is treated as a violation, not a pass.
 */
export function verifyInvariants(
  actual: InvariantCheckActual,
  invariants: MandateInvariants,
  now: number = Date.now()
): { ok: true } | { ok: false; reason: string } {
  if (invariants.expiry && now > new Date(invariants.expiry).getTime()) {
    return { ok: false, reason: `Invariants expired at ${invariants.expiry}` };
  }

  if (invariants.payee) {
    if (!actual.payee || !invariants.payee.includes(actual.payee)) {
      return { ok: false, reason: `Payee "${actual.payee ?? "(none)"}" is not in the bound payee list [${invariants.payee.join(", ")}]` };
    }
  }

  if (invariants.maxAmount) {
    if (!actual.amount) {
      return { ok: false, reason: "Invariants bind a maxAmount but the actual action has no amount" };
    }
    if (actual.amount.currency !== invariants.maxAmount.currency) {
      return { ok: false, reason: `Currency mismatch: actual ${actual.amount.currency} vs bound ${invariants.maxAmount.currency}` };
    }
    if (actual.amount.amount > invariants.maxAmount.amount) {
      return { ok: false, reason: `Amount ${actual.amount.amount} exceeds bound maxAmount ${invariants.maxAmount.amount}` };
    }
  }

  if (invariants.parameters) {
    const actualParams = actual.parameters ?? {};
    for (const [key, boundValue] of Object.entries(invariants.parameters)) {
      if (!(key in actualParams) || actualParams[key] !== boundValue) {
        return { ok: false, reason: `Parameter "${key}" is ${JSON.stringify(actualParams[key])}, bound to ${JSON.stringify(boundValue)}` };
      }
    }
  }

  return { ok: true };
}

/**
 * One requested action, checked against a VERIFIED task mandate by
 * checkTaskConstraints / assertTaskConstraints. The serving paths in
 * @aroha-sdk/delegation build one of these per request and per action.
 */
export interface TaskActionRequest {
  /** The capability being requested. Checked against allowed/blocked lists. */
  requestedCapability: string;
  /** Current action counts for this execution session (used for limit checking). */
  currentActionCounts?: Record<string, number>;
  /** Current compute consumption for this session. */
  currentCompute?: {
    llmTokens?: number;
    webRequests?: number;
    wallClockMs?: number;
  };
  /** Reversibility of the requested capability. Omitted = "irreversible" (fail closed under reversibleOnly). */
  capabilityReversibility?: "full" | "semi" | "irreversible";
  /**
   * Data the action will touch, resource key → access it needs. Checked
   * against taskConstraints.dataAccess: when the mandate sets that map, every
   * requested resource must be granted with at least the rights asked for (a
   * resource missing from the map is "none"). When the mandate sets no
   * dataAccess map there is no data-access limit, as TaskConstraints
   * documents. Omitting this field means the action touches no data — so a
   * caller must declare what it reads and writes for the check to bind.
   */
  dataAccess?: Record<string, "read" | "write" | "read-write">;
  /**
   * Set ONLY after a human approved this action (e.g. an "approve" decision
   * from requestApproval). A capability listed in humanGates is refused
   * without it. Default false.
   */
  humanApproved?: boolean;
  /**
   * Conversation profile: the room the request came from. Required to match
   * when the mandate's taskConstraints.roomId is set. The runtime supplies it
   * from its own room record, never from the request body.
   */
  roomId?: string;
  /**
   * Conversation profile: the room member the request is made for. Required
   * to match when the mandate's taskConstraints.onBehalfOf is set.
   */
  onBehalfOf?: string;
}

export interface EnforceTaskConstraintsOptions extends TaskActionRequest {
  /** Your own DID — verified against mandate.grantee. Omit to skip. */
  expectedGrantee?: string;
  /** Revocation hook (mandateId, grantor); fails closed when it throws. */
  isRevoked?: MandateRevocationCheck;
}

/**
 * Check a requested action against an ALREADY-VERIFIED task mandate.
 * Returns null when the action is within the mandate, otherwise the
 * violation (not thrown). Use assertTaskConstraints for the throwing form,
 * enforceTaskConstraints to verify a token and check in one call.
 *
 * Checks: allowed / blocked capability, reversibleOnly, humanGates,
 * actionLimits, computeLimit (when the caller reports consumption) and
 * dataAccess.
 */
export function checkTaskConstraints(
  mandate: ArohaTaskMandateBody,
  request: TaskActionRequest
): TaskConstraintViolation | null {
  const taskConstraints: TaskConstraints = mandate.taskConstraints ?? {};
  const { allowed, blocked } = mandate;
  const cap = request.requestedCapability;

  // Room / on-behalf-of binding (conversation profile guest grants). A grant
  // bound to one room and one member is refused for any other, including a
  // request that names no room or member at all: that must fail closed.
  if (taskConstraints.roomId !== undefined && request.roomId !== taskConstraints.roomId) {
    return new TaskConstraintViolation(
      `The mandate is bound to room ${taskConstraints.roomId}; the request is from ${request.roomId ?? "no room"}`,
      "CONTEXT_MISMATCH"
    );
  }
  if (taskConstraints.onBehalfOf !== undefined && request.onBehalfOf !== taskConstraints.onBehalfOf) {
    return new TaskConstraintViolation(
      `The mandate acts on behalf of ${taskConstraints.onBehalfOf}; the request is for ${request.onBehalfOf ?? "nobody named"}`,
      "CONTEXT_MISMATCH"
    );
  }

  // Capability permission check
  if (!allowed.includes(cap)) {
    return new TaskConstraintViolation(`Capability "${cap}" is not in the mandate's allowed list`, "CAPABILITY_NOT_PERMITTED");
  }
  if (blocked?.includes(cap)) {
    return new TaskConstraintViolation(`Capability "${cap}" is explicitly blocked by the mandate`, "CAPABILITY_NOT_PERMITTED");
  }

  // Reversibility check
  if (taskConstraints.reversibleOnly) {
    const rev = request.capabilityReversibility ?? "irreversible";
    if (rev === "irreversible") {
      return new TaskConstraintViolation(
        `Capability "${cap}" is irreversible but mandate requires reversibleOnly`,
        "REVERSIBILITY_VIOLATION"
      );
    }
  }

  // Human gate check — the caller obtains approval upstream and says so.
  if (taskConstraints.humanGates?.includes(cap) && request.humanApproved !== true) {
    return new TaskConstraintViolation(`Capability "${cap}" requires human approval (humanGate)`, "HUMAN_GATE_REQUIRED");
  }

  // Action limit check
  if (taskConstraints.actionLimits) {
    const limit = taskConstraints.actionLimits[cap];
    if (limit !== undefined) {
      const current = request.currentActionCounts?.[cap] ?? 0;
      if (current >= limit) {
        return new TaskConstraintViolation(`Action limit exceeded for "${cap}": ${current}/${limit}`, "ACTION_LIMIT_EXCEEDED");
      }
    }
  }

  // Compute limit check
  if (taskConstraints.computeLimit && request.currentCompute) {
    const { llmTokens, webRequests, executionTimeMs } = taskConstraints.computeLimit;
    if (llmTokens !== undefined && (request.currentCompute.llmTokens ?? 0) >= llmTokens) {
      return new TaskConstraintViolation(`LLM token budget exhausted (${llmTokens} max)`, "COMPUTE_LIMIT_EXCEEDED");
    }
    if (webRequests !== undefined && (request.currentCompute.webRequests ?? 0) >= webRequests) {
      return new TaskConstraintViolation(`Web request budget exhausted (${webRequests} max)`, "COMPUTE_LIMIT_EXCEEDED");
    }
    if (executionTimeMs !== undefined && (request.currentCompute.wallClockMs ?? 0) >= executionTimeMs) {
      return new TaskConstraintViolation(`Execution time budget exhausted (${executionTimeMs}ms max)`, "COMPUTE_LIMIT_EXCEEDED");
    }
  }

  // Data access check. This used to be missing entirely: dataAccess was
  // signed, narrowed on every link, and then never compared with what an
  // action actually touched — a declaration, not a boundary. Rights are
  // compared as sets (read, write), the same model checkTaskNarrowing uses,
  // so a write-only grant never admits a read.
  return checkTaskDataAccess(taskConstraints, request.dataAccess);
}

/**
 * The dataAccess rule of checkTaskConstraints on its own, for callers that
 * check a data touch that is not a capability invocation. Returns null when
 * every requested resource is granted with the rights asked for, or when the
 * mandate sets no dataAccess map (no limit, as TaskConstraints documents).
 */
export function checkTaskDataAccess(
  taskConstraints: TaskConstraints | undefined,
  requested: Record<string, "read" | "write" | "read-write"> | undefined
): TaskConstraintViolation | null {
  const grants = taskConstraints?.dataAccess;
  if (!grants || !requested) return null;
  for (const [resource, wanted] of Object.entries(requested)) {
    const granted = grants[resource] ?? "none";
    const g = DATA_ACCESS_RIGHTS[granted as DataAccessLevel];
    const w = DATA_ACCESS_RIGHTS[wanted as DataAccessLevel];
    // An unknown requested level fails closed rather than reading as "none".
    if (!g || !w || (w.read && !g.read) || (w.write && !g.write)) {
      return new TaskConstraintViolation(
        `Data access "${wanted}" on "${resource}" exceeds the mandate's grant (${granted})`,
        "DATA_ACCESS_VIOLATION"
      );
    }
  }
  return null;
}

/** Throwing form of checkTaskConstraints. */
export function assertTaskConstraints(mandate: ArohaTaskMandateBody, request: TaskActionRequest): void {
  const violation = checkTaskConstraints(mandate, request);
  if (violation) throw violation;
}

/**
 * Verify a task mandate AND assert the requested action is within its constraints.
 *
 * Call this at your capability gate before executing any side-effecting operation.
 * Throws TaskConstraintViolation if any constraint is breached — including
 * dataAccess, when the caller declares the data the action touches.
 */
export async function enforceTaskConstraints(
  token: string,
  grantorPublicKey: Uint8Array,
  options: EnforceTaskConstraintsOptions
): Promise<ArohaTaskMandateBody> {
  const result = await verifyTaskMandate(token, grantorPublicKey, options.expectedGrantee, { isRevoked: options.isRevoked });
  if (!result.valid) {
    throw new TaskConstraintViolation(`Task mandate invalid: ${result.reason}`, "MANDATE_INVALID");
  }
  const mandate = result.mandate!;
  assertTaskConstraints(mandate, options);
  return mandate;
}

export class TaskConstraintViolation extends Error {
  constructor(
    message: string,
    public readonly code:
      | "MANDATE_INVALID"
      | "CAPABILITY_NOT_PERMITTED"
      | "REVERSIBILITY_VIOLATION"
      | "HUMAN_GATE_REQUIRED"
      | "ACTION_LIMIT_EXCEEDED"
      | "COMPUTE_LIMIT_EXCEEDED"
      | "DATA_ACCESS_VIOLATION"
      | "SANDBOX_REQUIRED"
      | "DELEGATION_DEPTH_EXCEEDED"
      | "CONTEXT_MISMATCH"
  ) {
    super(message);
    this.name = "TaskConstraintViolation";
  }
}

// ─── Task Receipt Builder ─────────────────────────────────────────────────────

/**
 * Builds a TaskReceipt incrementally as a task executes.
 *
 * Usage:
 *   const receipt = new TaskReceiptBuilder(mandateId, correlationId, agentDid, issuedByDid);
 *   receipt.addAction({ capability: "web-search", ... });
 *   receipt.addOutput({ type: "data", summary: "Research complete" });
 *   const final = receipt.complete("complete");
 */
export class TaskReceiptBuilder {
  private actions: TaskAction[] = [];
  private outputs: TaskOutput[] = [];
  private consumed = { llmTokens: 0, webRequests: 0, wallClockMs: 0, actionCounts: {} as Record<string, number> };
  private violations: string[] = [];
  private startedAt: string;

  constructor(
    private readonly mandateId: string,
    private readonly correlationId: string,
    private readonly executedByDid: string,
    private readonly issuedByDid: string
  ) {
    this.startedAt = new Date().toISOString();
  }

  addAction(action: Omit<TaskAction, "sequence">): this {
    this.actions.push({ ...action, sequence: this.actions.length + 1 });
    this.consumed.actionCounts[action.capability] = (this.consumed.actionCounts[action.capability] ?? 0) + 1;
    return this;
  }

  addOutput(output: TaskOutput): this {
    this.outputs.push(output);
    return this;
  }

  recordLlmTokens(tokens: number): this { this.consumed.llmTokens += tokens; return this; }
  recordWebRequest(): this { this.consumed.webRequests += 1; return this; }
  recordViolation(v: string): this { this.violations.push(v); return this; }

  complete(status: TaskReceipt["status"]): TaskReceipt {
    const completedAt = new Date().toISOString();
    this.consumed.wallClockMs = Date.now() - new Date(this.startedAt).getTime();
    return {
      receiptId: crypto.randomUUID(),
      mandateId: this.mandateId,
      correlationId: this.correlationId,
      executedByDid: this.executedByDid,
      issuedByDid: this.issuedByDid,
      startedAt: this.startedAt,
      completedAt,
      status,
      actions: this.actions,
      consumed: this.consumed,
      mandateBoundsCheck: {
        withinBounds: this.violations.length === 0,
        violations: this.violations,
      },
      outputs: this.outputs,
    };
  }
}

// ─── Task narrowing enforcement ───────────────────────────────────────────────

/**
 * The child-side fields checkTaskNarrowing compares. A full
 * ArohaTaskMandateBody satisfies it; attenuateTaskMandate passes the body it
 * is ABOUT to sign, so the issuer and the verifier run the same rule.
 */
export interface TaskNarrowingChild {
  allowed: string[];
  blocked?: string[];
  taskConstraints: TaskConstraints;
  spendingConstraints?: SpendingConstraints;
  invariants?: MandateInvariants;
  /** ISO 8601. Omitted only at issuance time, before the expiry is chosen. */
  expiresAt?: string;
}

type DataAccessLevel = "none" | "read" | "read-write" | "write";

// "write" is not "more than read-write" — it is write WITHOUT read. Model each
// level as the set of rights it grants and require child ⊆ parent; the old
// linear order let a child turn a parent's write-only grant into read-write.
const DATA_ACCESS_RIGHTS: Record<DataAccessLevel, { read: boolean; write: boolean }> = {
  none: { read: false, write: false },
  read: { read: true, write: false },
  write: { read: false, write: true },
  "read-write": { read: true, write: true },
};

// Ordered narrowest first: internal-only is the tightest output policy.
const OUTPUT_HANDLING_RANK: Record<string, number> = { "internal-only": 0, "user-only": 1, shareable: 2 };

const COMPUTE_FIELDS = ["llmTokens", "webRequests", "executionTimeMs", "cpuSeconds"] as const;

/**
 * Check that a child task mandate is equal to or narrower than its parent.
 * Returns null when it is, or the reason it is not.
 *
 * The rule, for every constraint: if the PARENT sets it, the child must set it
 * too, to an equal or narrower value. Omission is widening — TaskConstraints
 * documents "omitting a field means no limit", so a child that simply leaves
 * out actionLimits / computeLimit / dataAccess / reversibleOnly / humanGates /
 * spendingConstraints / invariants would otherwise carry MORE authority than
 * its parent while every pairwise "both set" comparison passed.
 *
 * Shared by the issuer (attenuateTaskMandate, so an honest caller gets an
 * early error) and the verifier (@aroha-sdk/delegation's
 * verifyTaskMandateChain, on every link). Only the verifier-side call is a
 * security control — a dishonest delegating agent skips its own check — and
 * keeping one function is what stops the two from drifting apart.
 *
 * Not checked here: maxDelegationDepth (owned by the chain verifier, which
 * sees the whole path) and grantor/grantee/parentMandateId linkage.
 */
export function checkTaskNarrowing(parent: ArohaTaskMandateBody, child: TaskNarrowingChild): string | null {
  const prefix = "Cannot attenuate task mandate";
  const ptc: TaskConstraints = parent.taskConstraints ?? {};
  const ctc: TaskConstraints = child.taskConstraints ?? {};

  // ── allowed ⊆ parent.allowed ────────────────────────────────────────────
  const parentAllowed = new Set(parent.allowed);
  for (const cap of child.allowed) {
    if (!parentAllowed.has(cap)) {
      return `${prefix}: child allowed includes "${cap}" which is not in parent's allowed list`;
    }
  }
  const childAllowed = new Set(child.allowed);

  // ── blocked ⊇ parent.blocked ────────────────────────────────────────────
  const childBlocked = new Set(child.blocked ?? []);
  for (const cap of parent.blocked ?? []) {
    if (!childBlocked.has(cap)) return `${prefix}: child drops parent's blocked capability "${cap}"`;
  }

  // ── actionLimits ────────────────────────────────────────────────────────
  // A parent limit binds every capability the child can still invoke. A
  // capability the child no longer allows cannot be invoked at all, so its
  // limit may be left out without widening anything.
  if (ptc.actionLimits) {
    for (const [cap, parentLimit] of Object.entries(ptc.actionLimits)) {
      if (!childAllowed.has(cap)) continue;
      const childLimit = ctc.actionLimits?.[cap];
      if (childLimit === undefined) {
        return `${prefix}: parent sets actionLimits["${cap}"] (${parentLimit}) but child omits it`;
      }
      if (!isCount(childLimit) || childLimit > parentLimit) {
        return `${prefix}: child actionLimits["${cap}"] (${childLimit}) exceeds parent (${parentLimit})`;
      }
    }
  }

  // ── computeLimit ────────────────────────────────────────────────────────
  if (ptc.computeLimit) {
    for (const f of COMPUTE_FIELDS) {
      const p = ptc.computeLimit[f];
      if (p === undefined) continue;
      const c = ctc.computeLimit?.[f];
      if (c === undefined) return `${prefix}: parent sets computeLimit.${f} (${p}) but child omits it`;
      if (!isCount(c) || c > p) return `${prefix}: child ${f} (${c}) exceeds parent (${p})`;
    }
  }

  // ── dataAccess ──────────────────────────────────────────────────────────
  // Inside a dataAccess map a missing key means "no access", so a child that
  // sets the map but leaves a resource out is narrowing. Leaving the WHOLE
  // map out means "no data-access limit", which is widening.
  if (ptc.dataAccess) {
    if (!ctc.dataAccess) return `${prefix}: parent restricts dataAccess but child omits it`;
    for (const [resource, childAccess] of Object.entries(ctc.dataAccess)) {
      const parentAccess = ptc.dataAccess[resource] ?? "none";
      const c = DATA_ACCESS_RIGHTS[childAccess as DataAccessLevel];
      const p = DATA_ACCESS_RIGHTS[parentAccess as DataAccessLevel];
      if (!c || !p || (c.read && !p.read) || (c.write && !p.write)) {
        return `${prefix}: child dataAccess["${resource}"] (${childAccess}) exceeds parent (${parentAccess})`;
      }
    }
  }

  // ── boolean restrictions: parent true ⇒ child true ──────────────────────
  if (ptc.reversibleOnly === true && ctc.reversibleOnly !== true) {
    return `${prefix}: parent requires reversibleOnly but child does not`;
  }
  if (ptc.requireSandbox === true && ctc.requireSandbox !== true) {
    return `${prefix}: parent requires requireSandbox but child does not`;
  }

  // ── onBehalfOf / roomId: a parent's binding is kept verbatim ────────────
  // Omission is widening here too: a child without the parent's room or
  // member binding would be usable from any room, for anyone.
  for (const f of ["onBehalfOf", "roomId"] as const) {
    if (ptc[f] !== undefined && ctc[f] !== ptc[f]) {
      return `${prefix}: child ${f} (${ctc[f] ?? "unset"}) does not keep the parent's ${f} (${ptc[f]})`;
    }
  }

  // ── humanGates ⊇ parent.humanGates ──────────────────────────────────────
  // Only gates on capabilities the child can still invoke matter.
  if (ptc.humanGates) {
    const childGates = new Set(ctc.humanGates ?? []);
    for (const cap of ptc.humanGates) {
      if (childAllowed.has(cap) && !childGates.has(cap)) {
        return `${prefix}: child drops parent's human gate on "${cap}"`;
      }
    }
  }

  // ── outputHandling ──────────────────────────────────────────────────────
  if (ptc.outputHandling !== undefined) {
    const p = OUTPUT_HANDLING_RANK[ptc.outputHandling];
    const c = ctc.outputHandling === undefined ? undefined : OUTPUT_HANDLING_RANK[ctc.outputHandling];
    if (c === undefined || p === undefined || c > p) {
      return `${prefix}: child outputHandling (${ctc.outputHandling ?? "unset"}) is wider than parent (${ptc.outputHandling})`;
    }
  }

  // ── checkpointIntervalMs: the child may check in more often, never less ─
  if (ptc.checkpointIntervalMs !== undefined) {
    const c = ctc.checkpointIntervalMs;
    if (c === undefined || !isCount(c) || c > ptc.checkpointIntervalMs) {
      return `${prefix}: child checkpointIntervalMs (${c ?? "unset"}) is longer than parent (${ptc.checkpointIntervalMs})`;
    }
  }

  // ── spendingConstraints (same rule as spending-mandate attenuation) ─────
  if (parent.spendingConstraints) {
    if (!child.spendingConstraints) return `${prefix}: parent sets spendingConstraints but child omits them`;
    const reason = checkNarrowing(parent.spendingConstraints, child.spendingConstraints, "task", "task");
    if (reason) return `${prefix}: spendingConstraints: ${reason}`;
  }

  // ── invariants (design spec §9.1 Layer 1) ───────────────────────────────
  // A parent's instance binding can never be loosened downstream, only
  // tightened or left unchanged.
  const pi = parent.invariants;
  if (pi) {
    const ci = child.invariants;
    if (!ci) return `${prefix}: parent has invariants but child drops them entirely`;

    if (pi.payee) {
      if (!ci.payee) return `${prefix}: parent restricts payee but child has no payee invariant`;
      const parentPayees = new Set(pi.payee);
      for (const p of ci.payee) {
        if (!parentPayees.has(p)) return `${prefix}: child payee "${p}" is not in parent's payee list`;
      }
    }

    if (pi.maxAmount) {
      if (!ci.maxAmount) return `${prefix}: parent has maxAmount invariant but child has none`;
      if (ci.maxAmount.currency !== pi.maxAmount.currency) {
        return `${prefix}: child maxAmount currency (${ci.maxAmount.currency}) differs from parent (${pi.maxAmount.currency})`;
      }
      if (!isAmount(ci.maxAmount.amount) || ci.maxAmount.amount > pi.maxAmount.amount) {
        return `${prefix}: child maxAmount (${ci.maxAmount.amount}) exceeds parent (${pi.maxAmount.amount})`;
      }
    }

    if (pi.parameters) {
      const childParams = ci.parameters ?? {};
      for (const [key, parentValue] of Object.entries(pi.parameters)) {
        // A fixed parent value can't be loosened (dropped or changed) by the child.
        if (!(key in childParams) || childParams[key] !== parentValue) {
          return `${prefix}: child parameter "${key}" does not match parent's fixed value`;
        }
      }
    }

    if (pi.expiry) {
      if (!ci.expiry) return `${prefix}: parent has expiry invariant but child has none`;
      const c = Date.parse(ci.expiry);
      if (Number.isNaN(c) || c > Date.parse(pi.expiry)) {
        return `${prefix}: child expiry (${ci.expiry}) exceeds parent (${pi.expiry})`;
      }
    }
  }

  // ── expiry ≤ parent ─────────────────────────────────────────────────────
  if (child.expiresAt !== undefined) {
    const c = Date.parse(child.expiresAt);
    const p = Date.parse(parent.expiresAt);
    // NaN on either side fails closed: an unparseable date is not "no expiry".
    if (Number.isNaN(c) || Number.isNaN(p) || c > p) {
      return `${prefix}: child expiry (${child.expiresAt}) extends beyond parent (${parent.expiresAt})`;
    }
  }

  return null;
}

/** Throwing form of checkTaskNarrowing, used at attenuation time. */
function assertTaskNarrowing(parent: ArohaTaskMandateBody, child: TaskNarrowingChild): void {
  const reason = checkTaskNarrowing(parent, child);
  if (reason) throw new Error(reason);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
