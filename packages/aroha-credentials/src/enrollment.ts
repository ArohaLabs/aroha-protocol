// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Enrollment — how a server learns, with proof, which DID speaks for which
 * of its customer accounts.
 *
 * WHY. verifyHttpSpendRequest pins one root DID per request, and that DID
 * comes from a table the server keeps: account → DID. Whatever fills that
 * table decides whose mandates the server honours, so it must prove two
 * things together:
 *
 *   - the ACCOUNT: the customer is signed in to THIS account with the
 *     server's own login. This stops anyone from enrolling a DID into
 *     someone else's account. The library cannot check a login; the server
 *     passes the account id it authenticated, as `authenticatedAccountId`.
 *   - the KEY: the DID's private key signed a fresh, single-use, expiring
 *     challenge the server issued to that same account, for this service.
 *     This stops anyone from enrolling a DID whose key they do not hold, and
 *     a proof made for one account, challenge or service from being used for
 *     another.
 *
 * ── Protocol ─────────────────────────────────────────────────────────────────
 *
 *   1. Signed-in customer asks for a challenge:
 *        server: issueEnrollmentChallenge(store, { authenticatedAccountId }) → { challenge, expiresAt, accountId }
 *   2. On the customer's device, with the DID's key:
 *        client: signEnrollment({ accountId, did, challenge, audience, privateKey }) → proof
 *   3. Signed-in customer sends { did, challenge, proof }:
 *        server: completeEnrollment(store, { authenticatedAccountId, did, challenge, proof, audience })
 *      The challenge is consumed first, whatever the outcome. Then: it must
 *      have been issued to this account and be unexpired; the DID must be
 *      content-addressed (`did:aroha:z…`) or resolvable through a KEL source
 *      (`did:aroha:E…`); the proof must verify. Then account → DID is
 *      recorded. A later enrollment for the same account replaces it (key
 *      rotation); a lost key goes through the server's account recovery.
 *   4. Per request: expectedRoot: await enrolledDid(store, customerId)
 *      (undefined for an unknown customer → ROOT_NOT_PINNED, not a crash).
 *
 * `proof` is an Ed25519 signature (base64url, no padding) by the DID's key
 * over the UTF-8 bytes of the RFC 8785 JCS canonicalisation of
 *
 *   { purpose: "aroha.enrollment/v1", audience, accountId, did, challenge }
 *
 * Shared vectors: test-vectors/enrollment-v1.json (TypeScript and Python).
 *
 * This module imports only @noble/*, core's crypto/identity subpaths and the
 * mandate key resolvers, so it is exported from the Worker-safe
 * `@aroha-sdk/credentials/mandates` entry too.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import type { KelSource, KelStore } from "@aroha-sdk/core/identity";
import { canonicalizeJcs } from "./jcs.js";
import { createMandateKeyResolver, resolveContentAddressedKey, type MandateKeyResolver } from "./mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** Domain-separation string inside every enrollment proof. */
export const ENROLLMENT_PURPOSE = "aroha.enrollment/v1";
/** Default challenge lifetime (5 minutes). */
export const ENROLLMENT_CHALLENGE_DEFAULT_TTL_MS = 5 * 60_000;
/** Longest challenge lifetime issueEnrollmentChallenge accepts (1 hour). */
export const ENROLLMENT_CHALLENGE_MAX_TTL_MS = 60 * 60_000;

const CHALLENGE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const MAX_DID_LENGTH = 512;

/** What a store keeps for an issued, unused challenge. */
export interface EnrollmentChallengeRecord {
  /** The account the challenge was issued to (from the server's own login). */
  accountId: string;
  /** Unix ms after which the challenge is refused. */
  expiresAtMs: number;
}

/**
 * Where challenges and account → DID bindings live. In-memory for one
 * process (InMemoryEnrollmentStore); a server with more than one process, or
 * one that restarts, backs it with its database.
 *
 * `consumeChallenge` MUST be atomic: return the record AND delete it in one
 * step (`DELETE … RETURNING`, Redis `GETDEL`), so two concurrent enrollments
 * cannot both use one challenge. A throw from any method refuses the
 * enrollment (STORE_UNAVAILABLE).
 */
export interface EnrollmentStore {
  /** Record a newly issued challenge. */
  putChallenge(challenge: string, record: EnrollmentChallengeRecord, nowMs: number): void | Promise<void>;
  /** Atomically remove and return the challenge's record; null / undefined if unknown or already used. */
  consumeChallenge(challenge: string): EnrollmentChallengeRecord | null | undefined | Promise<EnrollmentChallengeRecord | null | undefined>;
  /** The DID enrolled for an account, or null / undefined. */
  getBinding(accountId: string): string | null | undefined | Promise<string | null | undefined>;
  /** Record (or replace) the DID enrolled for an account. */
  setBinding(accountId: string, did: string): void | Promise<void>;
}

/**
 * Enrollment store for a single-process server and for tests. Challenges are
 * dropped once expired; when full (default 100 000 live challenges) it
 * refuses to issue more rather than forgetting live ones.
 */
export class InMemoryEnrollmentStore implements EnrollmentStore {
  private readonly challenges = new Map<string, EnrollmentChallengeRecord>();
  private readonly bindings = new Map<string, string>();
  private readonly maxChallenges: number;
  private puts = 0;

  constructor(options: { maxChallenges?: number } = {}) {
    this.maxChallenges = options.maxChallenges ?? 100_000;
  }

  putChallenge(challenge: string, record: EnrollmentChallengeRecord, nowMs: number): void {
    if (++this.puts % 64 === 0 || this.challenges.size >= this.maxChallenges) {
      for (const [c, r] of this.challenges) if (r.expiresAtMs <= nowMs) this.challenges.delete(c);
    }
    if (this.challenges.has(challenge)) throw new Error("InMemoryEnrollmentStore: challenge already issued");
    if (this.challenges.size >= this.maxChallenges) throw new Error("InMemoryEnrollmentStore: too many outstanding challenges");
    this.challenges.set(challenge, { accountId: record.accountId, expiresAtMs: record.expiresAtMs });
  }

  consumeChallenge(challenge: string): EnrollmentChallengeRecord | null {
    const r = this.challenges.get(challenge);
    if (!r) return null;
    this.challenges.delete(challenge);
    return { ...r };
  }

  getBinding(accountId: string): string | null {
    return this.bindings.get(accountId) ?? null;
  }

  setBinding(accountId: string, did: string): void {
    this.bindings.set(accountId, did);
  }

  /** Number of outstanding challenges (for tests and metrics). */
  get pendingChallenges(): number {
    return this.challenges.size;
  }
}

/** The exact string an enrollment proof signs (JCS of the five fields). */
export function enrollmentSigningPayload(fields: { audience: string; accountId: string; did: string; challenge: string }): string {
  return canonicalizeJcs({
    purpose: ENROLLMENT_PURPOSE,
    audience: fields.audience,
    accountId: fields.accountId,
    did: fields.did,
    challenge: fields.challenge,
  });
}

function requireString(fn: string, name: string, v: unknown): asserts v is string {
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${fn}: ${name} must be a non-empty string`);
}

function requireStore(fn: string, store: unknown): asserts store is EnrollmentStore {
  const s = store as Partial<EnrollmentStore> | null | undefined;
  if (!s || typeof s.putChallenge !== "function" || typeof s.consumeChallenge !== "function"
    || typeof s.getBinding !== "function" || typeof s.setBinding !== "function") {
    throw new TypeError(`${fn}: an EnrollmentStore is required`);
  }
}

function requireNow(fn: string, now: unknown): number {
  if (now === undefined) return Date.now();
  if (typeof now !== "number" || !Number.isFinite(now)) throw new TypeError(`${fn}: now must be a finite number (Unix ms)`);
  return now;
}

// ─── Server ──────────────────────────────────────────────────────────────────

export interface IssueEnrollmentChallengeInput {
  /**
   * The account the CURRENT REQUEST is signed in to, from YOUR authentication
   * (session, OAuth token, API key) — never a value the client sends in the
   * body or query. This is the whole defence against enrolling a DID into
   * someone else's account.
   */
  authenticatedAccountId: string;
  /** Challenge lifetime, default 5 minutes, at most 1 hour. */
  ttlMs?: number;
  /** Override "now" (Unix ms). */
  now?: number;
}

export interface EnrollmentChallenge {
  /** 32 random bytes, base64url. Single use. */
  challenge: string;
  /** When it stops being accepted (ISO 8601 UTC). */
  expiresAt: string;
  /** The account it was issued to — the value the client signs as `accountId`. */
  accountId: string;
}

/** Issue a fresh, single-use, expiring challenge bound to the signed-in account. */
export async function issueEnrollmentChallenge(store: EnrollmentStore, input: IssueEnrollmentChallengeInput): Promise<EnrollmentChallenge> {
  const fn = "issueEnrollmentChallenge";
  requireStore(fn, store);
  requireString(fn, "authenticatedAccountId", input?.authenticatedAccountId);
  const ttl = input.ttlMs ?? ENROLLMENT_CHALLENGE_DEFAULT_TTL_MS;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0 || ttl > ENROLLMENT_CHALLENGE_MAX_TTL_MS) {
    throw new TypeError(`${fn}: ttlMs must be a positive number of milliseconds, at most ${ENROLLMENT_CHALLENGE_MAX_TTL_MS}`);
  }
  const now = requireNow(fn, input.now);
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const challenge = Buffer.from(bytes).toString("base64url");
  const expiresAtMs = Math.floor(now + ttl);
  await store.putChallenge(challenge, { accountId: input.authenticatedAccountId, expiresAtMs }, now);
  return { challenge, expiresAt: new Date(expiresAtMs).toISOString(), accountId: input.authenticatedAccountId };
}

export interface CompleteEnrollmentInput {
  /**
   * The account the CURRENT REQUEST is signed in to, from YOUR authentication
   * — never a value from the request body. The challenge must have been
   * issued to this account, and the proof must name it.
   */
  authenticatedAccountId: string;
  /** This service's identifier (its origin or DID), from your configuration — the value clients sign as `audience`. */
  audience: string;
  /** From the request body (untrusted): the DID being enrolled. */
  did: unknown;
  /** From the request body (untrusted): the challenge issued earlier. */
  challenge: unknown;
  /** From the request body (untrusted): signEnrollment's output. */
  proof: unknown;
  /** Override "now" (Unix ms). */
  now?: number;
  /**
   * DID → Ed25519 key. Default: content-addressed `did:aroha:z…` only (and
   * `did:aroha:E…` through `kelSource`). A custom resolver takes over all
   * DID forms: return null for any DID you cannot vouch for.
   */
  resolvePublicKey?: MandateKeyResolver;
  /** Key Event Log source, so rotatable `did:aroha:E…` DIDs can enroll (current key). */
  kelSource?: KelSource;
  kelStore?: KelStore;
}

/** Why an enrollment was refused. Stable across SDKs (enrollment-v1.json pins them). */
export type EnrollmentFailureCode =
  | "MALFORMED"                   // challenge is not a string of 16-128 base64url characters
  | "CHALLENGE_UNKNOWN"           // never issued, or already used (challenges are single-use)
  | "CHALLENGE_ACCOUNT_MISMATCH"  // issued to a different account than the one signed in
  | "CHALLENGE_EXPIRED"
  | "BAD_DID"                     // not a DID whose key can be resolved without trusting the client
  | "BAD_PROOF"                   // the DID's key did not sign this audience, account, DID and challenge
  | "STORE_UNAVAILABLE";          // the store threw

export type EnrollmentResult =
  | {
      ok: true;
      accountId: string;
      did: string;
      /** The DID this enrollment replaced (key rotation), when there was a different one. */
      replaced?: string;
    }
  | {
      ok: false;
      code: EnrollmentFailureCode;
      reason: string;
      /** Suggested HTTP status: 400 bad or stale input, 403 the account or key does not match, 503 store down. */
      status: 400 | 403 | 503;
    };

const refuse = (code: EnrollmentFailureCode, reason: string, status: 400 | 403 | 503): EnrollmentResult => ({ ok: false, code, reason, status });

/**
 * Verify an enrollment and record account → DID, or refuse it. Throws
 * TypeError only for a server misconfiguration (no store, no
 * authenticatedAccountId, no audience); every client-side problem is a
 * refusal. The challenge is consumed before anything else is checked.
 */
export async function completeEnrollment(store: EnrollmentStore, input: CompleteEnrollmentInput): Promise<EnrollmentResult> {
  const fn = "completeEnrollment";
  requireStore(fn, store);
  requireString(fn, "authenticatedAccountId", input?.authenticatedAccountId);
  requireString(fn, "audience", input.audience);
  const now = requireNow(fn, input.now);
  const accountId = input.authenticatedAccountId;
  const { challenge, did, proof } = input;

  if (typeof challenge !== "string" || !CHALLENGE_RE.test(challenge)) {
    return refuse("MALFORMED", "challenge must be the string issued by issueEnrollmentChallenge", 400);
  }

  // First: spend the challenge, whatever happens next.
  let record: EnrollmentChallengeRecord | null | undefined;
  try {
    record = await store.consumeChallenge(challenge);
  } catch {
    return refuse("STORE_UNAVAILABLE", "Enrollment store unavailable", 503);
  }
  if (!record) return refuse("CHALLENGE_UNKNOWN", "Challenge unknown or already used", 400);
  if (record.accountId !== accountId) {
    return refuse("CHALLENGE_ACCOUNT_MISMATCH", "Challenge was issued to a different account", 403);
  }
  if (!(typeof record.expiresAtMs === "number" && record.expiresAtMs > now)) {
    return refuse("CHALLENGE_EXPIRED", "Challenge expired", 400);
  }

  if (typeof did !== "string" || did.length === 0 || did.length > MAX_DID_LENGTH) {
    return refuse("BAD_DID", "did must be a DID string", 400);
  }
  const resolver = input.resolvePublicKey
    ?? (input.kelSource ? createMandateKeyResolver({ kelSource: input.kelSource, kelStore: input.kelStore }) : resolveContentAddressedKey);
  let key: Uint8Array | null;
  try {
    key = await resolver(did);
  } catch {
    key = null;
  }
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    return refuse("BAD_DID", `Cannot resolve a key for ${did}: enroll a content-addressed did:aroha:z… DID (or a did:aroha:E… DID with a KEL source)`, 400);
  }

  let valid = false;
  try {
    const sig = typeof proof === "string" && BASE64URL_RE.test(proof) ? new Uint8Array(Buffer.from(proof, "base64url")) : new Uint8Array(0);
    valid = sig.length === 64 && await ed.verifyAsync(
      sig, new TextEncoder().encode(enrollmentSigningPayload({ audience: input.audience, accountId, did, challenge })), key,
    );
  } catch {
    valid = false;
  }
  if (!valid) return refuse("BAD_PROOF", "Proof does not verify: the DID's key did not sign this service, account and challenge", 403);

  let previous: string | null | undefined;
  try {
    previous = await store.getBinding(accountId);
    await store.setBinding(accountId, did);
  } catch {
    return refuse("STORE_UNAVAILABLE", "Enrollment store unavailable", 503);
  }
  return typeof previous === "string" && previous.length > 0 && previous !== did
    ? { ok: true, accountId, did, replaced: previous }
    : { ok: true, accountId, did };
}

/**
 * The DID enrolled for `accountId`, or undefined when there is none. Pass it
 * straight to `expectedRoot`: undefined refuses with ROOT_NOT_PINNED (403).
 */
export async function enrolledDid(store: EnrollmentStore, accountId: string): Promise<string | undefined> {
  requireStore("enrolledDid", store);
  requireString("enrolledDid", "accountId", accountId);
  const did = await store.getBinding(accountId);
  return typeof did === "string" && did.length > 0 ? did : undefined;
}

// ─── Client ──────────────────────────────────────────────────────────────────

export interface SignEnrollmentInput {
  /** Your account id at the service, as returned with the challenge. */
  accountId: string;
  /** The DID to enroll; `privateKey` must be its key. */
  did: string;
  /** The challenge the service issued. */
  challenge: string;
  /** The service's identifier, exactly as it configures `audience` (its origin or DID). */
  audience: string;
  /** The DID's Ed25519 private key (32 bytes). Stays on the customer's device. */
  privateKey: Uint8Array;
}

/** Sign an enrollment on the customer's device. Returns the proof (base64url). */
export async function signEnrollment(input: SignEnrollmentInput): Promise<string> {
  const fn = "signEnrollment";
  for (const k of ["accountId", "did", "challenge", "audience"] as const) requireString(fn, k, input?.[k]);
  if (!CHALLENGE_RE.test(input.challenge)) throw new TypeError(`${fn}: challenge must be 16-128 base64url characters`);
  if (!(input.privateKey instanceof Uint8Array) || input.privateKey.length !== 32) {
    throw new TypeError(`${fn}: privateKey must be a 32-byte Ed25519 private key`);
  }
  // A content-addressed DID names its key: refuse to sign for the wrong one.
  const named = await resolveContentAddressedKey(input.did);
  if (named) {
    const pub = await ed.getPublicKeyAsync(input.privateKey);
    if (Buffer.compare(Buffer.from(pub), Buffer.from(named)) !== 0) {
      throw new TypeError(`${fn}: privateKey is not the key of ${input.did}`);
    }
  }
  const payload = enrollmentSigningPayload(input);
  return Buffer.from(await ed.signAsync(new TextEncoder().encode(payload), input.privateKey)).toString("base64url");
}
