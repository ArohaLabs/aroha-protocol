// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Layer 3 Message Envelope
 *
 * Implements the spec's message envelope format.
 * Every Aroha message, regardless of type, uses this envelope.
 *
 * Responsibilities:
 *   - Build outbound envelopes (build + sign)
 *   - Validate inbound envelopes (schema + signature + nonce + expiry + recipient)
 *
 * This module is pure protocol. It does not route messages or apply
 * business logic — that belongs to the application tier.
 */

import { randomBytes } from "@noble/hashes/utils";
import { signMessage, verifyMessageSignature, type MessageProof } from "../crypto/signing.js";
import { NonceRegistry } from "./nonce.js";
import { extractPublicKey, type DIDDocument } from "../identity/did.js";
import { type ArohaMessageType, type ArohaBodyByType } from "./types.js";
import { type ArohaDisclosure, validateDisclosure } from "./disclosure.js";

/** Longest nonce validateEnvelope accepts (SDK nonces are 64 hex chars). */
export const MAX_NONCE_LENGTH = 128;

// ─── Envelope Type ────────────────────────────────────────────────────────────

export interface ArohaEnvelope<T extends ArohaMessageType = ArohaMessageType> {
  "@context": string[];
  id: string;           // urn:uuid:<uuid-v4>
  type: T;
  from: string;         // did:aroha:<sender>
  to: string;           // did:aroha:<recipient>
  created: string;      // ISO8601
  expires: string;      // ISO8601
  nonce: string;        // random hex-32, replay prevention
  correlationId: string; // links messages in a saga or session
  body: T extends keyof ArohaBodyByType ? ArohaBodyByType[T] : Record<string, unknown>;
  proof?: MessageProof;
  /** W3C Trace Context traceparent header — injected by @aroha-sdk/telemetry for distributed tracing. */
  traceparent?: string;
  /**
   * Model routing hint — set by @aroha-sdk/orchestrator ModelRouter.
   * Informational only: tells the receiving agent which model tier to use
   * for processing this request. Never enforced by the transport layer.
   */
  routingHint?: {
    complexity: "trivial" | "standard" | "complex";
    suggestedModel?: string;
  };
  /**
   * Per-hop AI and principal disclosure (see disclosure.ts). Optional.
   * Covered by `proof`: the signature is over the whole message minus
   * `proof`, so a disclosure cannot be stripped or edited in transit.
   * validateEnvelope refuses a malformed one, or one naming an agent other
   * than `from`.
   */
  disclosure?: ArohaDisclosure;
}

// ─── Build ────────────────────────────────────────────────────────────────────

const Aroha_CONTEXT = [
  "https://aroha-labs.com/contexts/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1",
];

/**
 * Build and sign an outbound Aroha message envelope.
 *
 * @param type             One of the 15 Aroha message types
 * @param from             Sender DID (did:aroha:<id>)
 * @param to               Recipient DID (did:aroha:<id>)
 * @param body             Message body — typed per message type
 * @param correlationId    Saga or session ID linking related messages
 * @param privateKey       Sender's Ed25519 private key
 * @param ttlSeconds       How long the message is valid (default: 300s / 5min).
 *                         Receivers reject envelopes whose `expires - created`
 *                         exceeds their `maxTtlMs` (default also 5 min), so a
 *                         longer TTL only works against receivers configured
 *                         to accept it.
 */
export interface BuildEnvelopeOptions {
  ttlSeconds?: number;
  /** W3C Trace Context traceparent — propagated by @aroha-sdk/telemetry. */
  traceparent?: string;
  /** Model routing hint — set by @aroha-sdk/orchestrator ModelRouter. */
  routingHint?: ArohaEnvelope["routingHint"];
  /**
   * Verification method id to stamp into `proof.verificationMethod`
   * (absolute `did#frag`). Default `${from}#key-1`. Set it when the DID
   * document lists several keys (e.g. one per device) so the receiver
   * verifies against the key that actually signed.
   */
  keyId?: string;
  /** Per-hop disclosure to carry (signed with the rest of the envelope). */
  disclosure?: ArohaDisclosure;
}

export async function buildEnvelope<T extends ArohaMessageType>(
  type: T,
  from: string,
  to: string,
  body: T extends keyof ArohaBodyByType ? ArohaBodyByType[T] : Record<string, unknown>,
  correlationId: string,
  privateKey: Uint8Array,
  ttlSecondsOrOptions: number | BuildEnvelopeOptions = 300
): Promise<ArohaEnvelope<T>> {
  const opts: BuildEnvelopeOptions =
    typeof ttlSecondsOrOptions === "number"
      ? { ttlSeconds: ttlSecondsOrOptions }
      : ttlSecondsOrOptions;
  const ttlSeconds = opts.ttlSeconds ?? 300;

  const now = new Date();
  const expires = new Date(now.getTime() + ttlSeconds * 1000);

  const envelope: ArohaEnvelope<T> = {
    "@context": Aroha_CONTEXT,
    id: `urn:uuid:${crypto.randomUUID()}`,
    type,
    from,
    to,
    created: now.toISOString(),
    expires: expires.toISOString(),
    nonce: Buffer.from(randomBytes(32)).toString("hex"),
    correlationId,
    body,
    ...(opts.traceparent ? { traceparent: opts.traceparent } : {}),
    ...(opts.routingHint ? { routingHint: opts.routingHint } : {}),
    ...(opts.disclosure ? { disclosure: opts.disclosure } : {}),
  };

  const keyId = opts.keyId ?? `${from}#key-1`;
  const proof = await signMessage(
    envelope as unknown as Record<string, unknown>,
    privateKey,
    keyId
  );

  return { ...envelope, proof };
}

/**
 * Build an unsigned Aroha envelope for use within a trusted network mesh
 * (VPC, mTLS service mesh). The receiving server must be configured with
 * bypassSignatureFor to accept envelopes from this sender DID.
 */
export async function buildUnsignedEnvelope<T extends ArohaMessageType>(
  type: T,
  from: string,
  to: string,
  body: T extends keyof ArohaBodyByType ? ArohaBodyByType[T] : Record<string, unknown>,
  correlationId: string,
  opts: BuildEnvelopeOptions = {}
): Promise<ArohaEnvelope<T>> {
  const ttlSeconds = opts.ttlSeconds ?? 300;
  const now = new Date();
  const expires = new Date(now.getTime() + ttlSeconds * 1000);

  return {
    "@context": Aroha_CONTEXT,
    id: `urn:uuid:${crypto.randomUUID()}`,
    type,
    from,
    to,
    created: now.toISOString(),
    expires: expires.toISOString(),
    nonce: Buffer.from(randomBytes(32)).toString("hex"),
    correlationId,
    body,
    ...(opts.traceparent ? { traceparent: opts.traceparent } : {}),
    ...(opts.disclosure ? { disclosure: opts.disclosure } : {}),
  };
}

// ─── Validate ─────────────────────────────────────────────────────────────────

export type ValidationResult =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Default ceiling on an envelope's declared lifetime (`expires - created`).
 *
 * WHY 5 minutes: it equals `buildEnvelope`'s default `ttlSeconds` (300), so
 * every envelope built with defaults passes, while a sender can no longer
 * pick a 30-day TTL. The TTL is the replay window that a nonce store must
 * cover; with the default in-memory store a restart forgets every nonce, so
 * an uncapped TTL meant a captured envelope could be replayed after any
 * restart for as long as the sender liked. Capping it bounds that window to
 * minutes (and `FileNonceStore` closes it for single-instance deployments).
 */
export const DEFAULT_MAX_ENVELOPE_TTL_MS = 300_000;

/**
 * Default allowance for a sender's clock running AHEAD of ours when checking
 * `created`. Kept separate from `clockToleranceMs` (whose default is 0,
 * strict) because a strict "created must not be in the future" check would
 * reject ordinary traffic from any host whose clock is a few ms ahead.
 */
export const DEFAULT_MAX_FUTURE_SKEW_MS = 30_000;

/**
 * Validate an inbound Aroha message envelope.
 *
 * Order of checks (CHANGED — security fix):
 *   1. Recipient match (`to` must equal this agent's DID)
 *   2. Timestamp sanity: `created`/`expires` parse; not expired (with
 *      `clockToleranceMs`); `created` not too far in the future; declared
 *      lifetime `expires - created` ≤ `maxTtlMs`
 *   3. Signature verification (unless `skipSignature`)
 *   4. Nonce freshness — recorded ONLY NOW, keyed per sender
 *
 * WHY signature before nonce: the nonce used to be recorded before the
 * signature was checked. Any unauthenticated client could therefore (a)
 * fill the nonce store with junk, and (b) "pre-burn" a legitimate sender's
 * nonce by sending a forged envelope carrying it first, so the real message
 * was later rejected as a replay. Only state-free checks run before the
 * signature now; the store is written only for authenticated envelopes.
 *
 * WHY per-sender keys (`<from>:<nonce>`): the nonce namespace was global, so
 * one sender's envelope could collide with (and consume) another sender's
 * nonce. Scoping by the authenticated sender removes cross-sender
 * interference.
 *
 * `skipSignature`: the nonce is still recorded (keyed by the CLAIMED
 * `from`), but because nothing authenticates `from` in that mode, anyone
 * who can reach the listener can burn any nonce for any sender. Replay
 * protection in skip mode is only as good as the network control that
 * justified skipping signatures.
 *
 * @param envelope      The received message envelope
 * @param senderKey     Either the claimed sender's Ed25519 public key, or
 *                      the sender's DID Document — in which case the key is
 *                      chosen by `proof.verificationMethod` (multi-device
 *                      keys) and rotation cool-downs/revocations are applied
 *                      via `extractPublicKey`.
 * @param myDID         This agent's DID (to verify the "to" field)
 * @param nonceRegistry Shared nonce registry for this agent
 */
export interface ValidateEnvelopeOptions {
  /**
   * Skip Ed25519 signature check — use only within trusted mesh / VPC
   * environments. See the replay caveat in validateEnvelope's doc comment.
   */
  skipSignature?: boolean;
  /**
   * Clock skew tolerance in milliseconds applied to the expires check.
   * Accepts messages that expired up to this many ms ago.
   * Recommended: 5000 (5s) for cross-region deployments.
   * Default: 0 (strict).
   */
  clockToleranceMs?: number;
  /**
   * Maximum accepted `expires - created`, in ms. Default
   * DEFAULT_MAX_ENVELOPE_TTL_MS (5 min, = buildEnvelope's default TTL).
   * Raise it only together with a persistent/shared NonceStore.
   */
  maxTtlMs?: number;
  /**
   * How far `created` may be in the future, in ms. Default
   * max(clockToleranceMs, DEFAULT_MAX_FUTURE_SKEW_MS).
   */
  maxFutureSkewMs?: number;
}

function didOfVerificationMethod(vmId: string): string | null {
  if (vmId.startsWith("#")) return null; // relative — belongs to whichever DID resolves it
  const hash = vmId.indexOf("#");
  return hash >= 0 ? vmId.slice(0, hash) : vmId;
}

export async function validateEnvelope(
  envelope: ArohaEnvelope,
  senderKey: Uint8Array | DIDDocument,
  myDID: string,
  nonceRegistry: NonceRegistry,
  options?: ValidateEnvelopeOptions
): Promise<ValidationResult> {
  // 1. Recipient check — must be addressed to us
  if (envelope.to !== myDID) {
    return { valid: false, reason: `Message addressed to ${envelope.to}, not ${myDID}` };
  }

  // 2. Timestamp checks — pure functions of the envelope, no state touched.
  const tolerance = options?.clockToleranceMs ?? 0;
  if (tolerance < 0) {
    return { valid: false, reason: "Invalid clockToleranceMs: must be non-negative" };
  }
  const createdMs = Date.parse(envelope.created);
  const expiresMs = Date.parse(envelope.expires);
  if (Number.isNaN(createdMs) || Number.isNaN(expiresMs)) {
    // NaN compares false against everything, so an unparseable `expires`
    // used to sail through the expiry check below.
    return { valid: false, reason: "Malformed created/expires timestamp" };
  }
  const now = Date.now();
  if (expiresMs + tolerance < now) {
    return { valid: false, reason: `Message expired at ${envelope.expires} (outside tolerance window)` };
  }
  const futureSkew = options?.maxFutureSkewMs ?? Math.max(tolerance, DEFAULT_MAX_FUTURE_SKEW_MS);
  if (createdMs > now + futureSkew) {
    return { valid: false, reason: `Message created at ${envelope.created} is in the future (beyond allowed clock skew)` };
  }
  const maxTtl = options?.maxTtlMs ?? DEFAULT_MAX_ENVELOPE_TTL_MS;
  if (expiresMs - createdMs > maxTtl) {
    return {
      valid: false,
      reason: `Message lifetime ${expiresMs - createdMs}ms exceeds maximum ${maxTtl}ms`,
    };
  }
  if (typeof envelope.nonce !== "string" || envelope.nonce.length === 0) {
    return { valid: false, reason: "Missing nonce" };
  }
  // SDK nonces are 64 hex chars. The cap bounds what one envelope can make
  // the nonce store hold — every accepted nonce is kept until expiry.
  if (envelope.nonce.length > MAX_NONCE_LENGTH) {
    return { valid: false, reason: `Nonce longer than ${MAX_NONCE_LENGTH} characters` };
  }

  // A disclosure is optional, but one that is present must be well-formed
  // and made in the sender's own name: an agent disclosing "on behalf of"
  // another agent's DID would mislead exactly the reader it exists for.
  if (envelope.disclosure !== undefined) {
    const d = validateDisclosure(envelope.disclosure, { expectedAgentDid: envelope.from });
    if (!d.valid) return { valid: false, reason: `Invalid disclosure: ${d.reason}` };
  }

  // 3. Signature verification (skip in trusted mesh mode) — BEFORE the nonce.
  if (!options?.skipSignature) {
    const vmId = envelope.proof?.verificationMethod;
    if (vmId) {
      const vmDid = didOfVerificationMethod(vmId);
      if (vmDid !== null && vmDid !== envelope.from) {
        return { valid: false, reason: "Signature verification failed: proof key belongs to a different DID than `from`" };
      }
    }

    let publicKey: Uint8Array;
    if (senderKey instanceof Uint8Array) {
      publicKey = senderKey;
    } else {
      if (senderKey.id !== envelope.from) {
        return { valid: false, reason: "Signature verification failed: sender DID document does not match `from`" };
      }
      try {
        publicKey = extractPublicKey(senderKey, vmId);
      } catch (e) {
        return { valid: false, reason: `Signature verification failed: ${(e as Error).message}` };
      }
    }

    const isValid = await verifyMessageSignature(
      envelope as unknown as Record<string, unknown>,
      publicKey
    );
    if (!isValid) {
      return { valid: false, reason: "Signature verification failed" };
    }
  }

  // 4. Nonce check (replay prevention) — only authenticated envelopes reach
  // here. Retained until expires + tolerance: the expiry check above keeps
  // accepting the envelope for `tolerance` ms past `expires`, so evicting
  // the nonce at `expires` would reopen a replay window of that length.
  const nonceFresh = await nonceRegistry.checkAsync(
    `${envelope.from}:${envelope.nonce}`,
    new Date(expiresMs + tolerance).toISOString()
  );
  if (!nonceFresh) {
    return { valid: false, reason: "Nonce replay detected" };
  }

  return { valid: true };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Create a new correlationId for a new saga or session. */
export function newCorrelationId(): string {
  return `saga-${crypto.randomUUID()}`;
}

/** Extract the sender's DID from an envelope. */
export function senderDID(envelope: ArohaEnvelope): string {
  return envelope.from;
}
