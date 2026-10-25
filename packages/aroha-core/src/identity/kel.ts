// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Rotatable, self-certifying identifiers — `did:aroha:E…` — and the Key Event
 * Log (KEL) that carries their key history. KERI-style inception + pre-rotation.
 *
 * WHY this exists. `did:aroha:` already had two forms, and neither can survive
 * a lost or stolen device:
 *   - content-addressed `did:aroha:z<base58btc(pubkey)>`: the DID IS the key.
 *     Anyone can verify it with no network, but the key can never change —
 *     a verifier who derives the key from the DID string ignores every
 *     rotation record, so a stolen key is the identity forever, and a lost
 *     one takes the personal name, reputation and grants with it.
 *   - named `did:aroha:<label>`: rotatable, but only because some registry
 *     says which key is current. Whoever runs the registry can substitute a
 *     key.
 * The `E` form keeps the first property (no registry trust) and adds the
 * second (rotation):
 *
 *   did:aroha:E<base58btc(sha256(JCS(inception event without `sig`)))>
 *
 * The identifier commits to the INCEPTION EVENT, not to a key. The inception
 * names the current key AND a digest of the NEXT key (pre-rotation). Every
 * later key change is an event in an append-only log, hash-chained to its
 * predecessor, and authorised by a key the previous state committed to. A
 * verifier replays the log from the inception it can hash back to the DID, so
 * a registry, cache or peer serving the log can withhold events or serve an
 * old prefix, but cannot forge one.
 *
 * Who may do what (the security story, in one table):
 *
 *   event     | authorised by                        | a thief holding only the CURRENT key…
 *   ----------+--------------------------------------+--------------------------------------
 *   inception | the current key (proof of possession)| —
 *   rotate    | the pre-committed NEXT key, revealed | cannot rotate: the next key is not on
 *             |   (its sha256 must equal the         |   the device (kept offline / passkey
 *             |   commitment)                        |   store), and its digest pins it
 *   recover   | the CONTROLLER person, by anchoring  | cannot recover: needs the person's key
 *   (agents)  |   the event's digest in the person's |
 *             |   own KEL (see "anchors" below)      |
 *   revoke    | the controller (anchored), OR the    | cannot revoke: needs either of those
 *             |   identity's own pre-committed next  |
 *             |   key, revealed                      |
 *   anchor    | the current key (persons only)       | for a PERSON key: can anchor until the
 *   (persons) |                                      |   person rotates — person keys are the
 *             |                                      |   high-value secret, see "person keys"
 *
 * The stolen-device path for an agent is therefore: the person, from another
 * device, appends `recover` to the agent's KEL (new current key + new next
 * commitment) and anchors it in the person's KEL. From that point verifiers
 * resolving the agent see the new key; the thief's key verifies nothing.
 *
 * Anchors, not signatures, for controller authority. A controller-authorised
 * agent event carries no signature of its own; instead the person appends an
 * `anchor` event to THEIR KEL listing a seal {did, seq, digest} of the agent
 * event. WHY not just "signed by the controller's key": signatures carry no
 * ordering. If a person's old key K1 leaked and they rotated to K2, a thief
 * holding K1 could still sign a "recover" that names K1 as the controller key
 * of the time, and a verifier holding the person's full, honest KEL would have
 * no way to say it came after the rotation. An anchor is an event IN the
 * person's hash-chained log, at a sequence number, signed by whatever key was
 * current at that position — so after the person rotates, K1 can no longer
 * produce an anchor that fits into the honest log. (It can produce a FORK of
 * the person's log; forks are what the duplicity check in `acceptKel` exists
 * for — see the stale/duplicity section.) Seals have a second benefit: a
 * verifier holding the person's KEL learns that agent X has a controller event
 * at seq N, so an agent log served without it is detectably STALE. That is
 * what makes "revoked by its controller" hard to hide.
 *
 * Person keys. A person is an `E` DID of kind "person" with no controller.
 * Persons rotate only by pre-rotation: their recovery story is the next key,
 * generated at inception and kept somewhere the current key is not — offline
 * paper/QR backup, or a passkey/secure-enclave-backed store on a second
 * device. Losing BOTH the current and the next key of a person is
 * unrecoverable by design (there is nobody above a person to vouch for a new
 * key); migrating to a fresh person identity with a signed linkage
 * (migration.ts) is the fallback, and relationships must re-trust the link.
 *
 * Stale logs and duplicity — the honest limitation. A KEL is verifiable
 * offline but its FRESHNESS is not: whoever serves it can omit the newest
 * events (a rotation, a revocation) and the shorter log still verifies. And
 * anyone holding a superseded key can fork the log from the point that key
 * was current (the "dead key" problem KERI solves with witnesses). Mitigations
 * here:
 *   1. Verifiers keep the longest log they have verified per DID (`KelStore`,
 *      `acceptKel`). A shorter log is rejected as stale (or answered from the
 *      stored, longer log); a log that disagrees with a stored one at any
 *      sequence is a DUPLICITY alarm, recorded, and the DID is refused from
 *      then on until a human looks at it.
 *   2. Controller seals (above) let a person's KEL vouch for the minimum length
 *      of each of their agents' KELs.
 *   3. Pre-rotation itself: after a rotation the superseded key cannot extend
 *      the honest log, so the only thing it can do is fork — which (1) catches
 *      for any verifier that has seen the honest log.
 * What this does NOT give you: a first-contact verifier fed only a forked or
 * stale log, with no other source, will accept it. Witnesses/watchers (KERI's
 * answer) are future work; the registry and peers acting as log mirrors are
 * the near-term mitigation.
 *
 * Canonical form: every event is signed over RFC 8785 JCS of the event with
 * its `sig` field removed, and its digest is sha256 of the same bytes. That
 * makes the digest (and therefore the DID, and every `prior` link) the same in
 * every conformant SDK.
 *
 * Mutual exclusion with the other `did:aroha:` forms: an `E` DID's suffix is
 * "E" followed by the base58btc encoding of exactly 32 bytes (and must
 * re-encode to itself). Content-addressed DIDs start with "z"; named DIDs are
 * lowercase per the method spec, and `generateDID` refuses any name that
 * parses as either self-certifying form. See `isInceptionDid`.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "../crypto/jcs.js";
import { toMultibase, fromMultibase } from "./did.js";
import type { PublicKeyResolver } from "./did-cache.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const DID_PREFIX = "did:aroha:";

/** Current KEL event format version. Every event carries `v: 1`. */
export const KEL_VERSION = 1 as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export type KelIdentityKind = "person" | "agent";

/**
 * A seal a person places in their own KEL (inside an `anchor` event) to
 * authorise — and to vouch for the existence of — one event in one of their
 * agents' KELs.
 */
export interface KelSeal {
  /** The agent DID whose KEL holds the sealed event. */
  did: string;
  /** Sequence number of the sealed event in that KEL. */
  seq: number;
  /** `eventDigest` of the sealed event. */
  digest: string;
}

/**
 * Event 0. The DID is `did:aroha:` + `eventDigest(inception)`.
 * Signed by `keys[0]` — proof that the creator holds the key it names.
 */
export interface InceptionEvent {
  v: 1;
  type: "inception";
  kind: KelIdentityKind;
  /** Current signing key(s), multibase (`z…`) Ed25519. Exactly one in v1. */
  keys: string[];
  /** `keyDigest` of the NEXT public key — the pre-rotation commitment. */
  nextKeyDigest: string;
  /** Agents only: the person `E` DID that may recover or revoke this agent. */
  controller?: string;
  /** ISO 8601. Informational — part of the digest, so it makes DIDs unique. */
  createdAt: string;
  /** base64url Ed25519 signature by keys[0] over JCS(event without sig). */
  sig: string;
}

interface KelEventCommon {
  v: 1;
  /** The DID this event belongs to (binds the event to one log). */
  did: string;
  /** Position in the log; inception is 0, each event is prior + 1. */
  seq: number;
  /** `eventDigest` of the event at seq - 1. */
  prior: string;
  /** ISO 8601, informational. */
  at: string;
}

/**
 * Pre-rotation. `keys[0]` must be the key whose digest the previous state
 * committed to, and this event must be signed by it. Installs a new
 * commitment for the following rotation.
 */
export interface RotateEvent extends KelEventCommon {
  type: "rotate";
  keys: string[];
  nextKeyDigest: string;
  sig: string;
}

/**
 * Controller recovery (agents with a controller only). Installs a fresh key
 * and commitment WITHOUT any key the agent held — the stolen-device path.
 * Carries no signature; it is authorised by a seal in the controller's KEL.
 */
export interface RecoverEvent extends KelEventCommon {
  type: "recover";
  auth: "controller";
  keys: string[];
  nextKeyDigest: string;
}

/** Revocation authorised by the controller (anchored, unsigned). */
export interface ControllerRevokeEvent extends KelEventCommon {
  type: "revoke";
  auth: "controller";
  reason?: string;
}

/** Revocation authorised by the identity's own pre-committed next key. */
export interface SelfRevokeEvent extends KelEventCommon {
  type: "revoke";
  auth: "next-key";
  /** The next public key, revealed; its digest must equal the commitment. */
  revealedKey: string;
  reason?: string;
  sig: string;
}

export type RevokeEvent = ControllerRevokeEvent | SelfRevokeEvent;

/** Persons only: seal agent events, signed by the person's current key. */
export interface AnchorEvent extends KelEventCommon {
  type: "anchor";
  seals: KelSeal[];
  sig: string;
}

export type KelEvent = InceptionEvent | RotateEvent | RecoverEvent | RevokeEvent | AnchorEvent;

/** One key-establishing point in a log: from `seq` on, `keys` were current. */
export interface KelKeyEstablishment {
  seq: number;
  keys: string[];
}

/** The result of replaying a verified KEL. */
export interface KelState {
  did: string;
  kind: KelIdentityKind;
  controller?: string;
  /** Multibase keys valid right now. Empty once revoked. */
  currentKeys: string[];
  /** Raw bytes of currentKeys[0], or null once revoked. */
  currentKey: Uint8Array | null;
  /** The outstanding pre-rotation commitment, or null once revoked. */
  nextKeyDigest: string | null;
  /** True after a `revoke` event: no key of this identity is valid any more. */
  revoked: boolean;
  /** Sequence number of the last event. */
  sequence: number;
  /** eventDigest of the last event. */
  lastDigest: string;
  /** eventDigest of every event, by sequence number. */
  digests: string[];
  /** Every key-establishing event (inception, rotate, recover), in order. */
  keyHistory: KelKeyEstablishment[];
  /** Seals this identity has anchored (persons). */
  seals: KelSeal[];
  /** The verified events. */
  events: KelEvent[];
  /** The controller's verified state, when it was resolved. */
  controllerState?: KelState;
  /**
   * True when the controller's KEL was resolved and the controller has revoked
   * ITSELF. Its agents act for an abandoned principal, so callers deciding
   * authority (mandates) treat this like `revoked`.
   */
  controllerRevoked: boolean;
}

export type KelErrorCode =
  /** The log is malformed, mis-signed, mis-chained, or breaks a rule. */
  | "invalid"
  /** Verifiably shorter than a log already seen (or than the controller's seals say). */
  | "stale"
  /** Two different events at the same sequence: someone forked the log. */
  | "duplicity"
  /** The log needs its controller's KEL and none could be obtained. */
  | "controller-unavailable";

export class KelError extends Error {
  constructor(public readonly code: KelErrorCode, message: string) {
    super(message);
    this.name = "KelError";
  }
}

/** Fetch the KEL for a DID from wherever it lives (registry, peer, cache, the first message). */
export type KelSource = (did: string) => Promise<KelEvent[] | null | undefined>;

export interface VerifyKelOptions {
  /** Source of the CONTROLLER's KEL. Required to verify recover / controller-revoke events. */
  resolveControllerKel?: KelSource;
  /**
   * Fail with "controller-unavailable" if an agent names a controller whose
   * KEL cannot be obtained, even when no event in the agent's log needs it.
   * Set it where the controller's own revocation and its seals (freshness)
   * matter — e.g. authorising money. Default false, which keeps an
   * inception-only agent verifiable with nothing but its inception.
   */
  requireController?: boolean;
}

// ─── Digests and identifiers ─────────────────────────────────────────────────

const utf8 = (s: string) => new TextEncoder().encode(s);

/** `E` + base58btc(sha256(bytes)) — the digest encoding used throughout KELs. */
export function sha256Digest(bytes: Uint8Array): string {
  return "E" + toMultibase(sha256(bytes)).slice(1);
}

/** Decode an `E…` digest to its 32 bytes, or null if it is not one (canonically encoded). */
function decodeDigest(digest: unknown): Uint8Array | null {
  if (typeof digest !== "string" || !digest.startsWith("E")) return null;
  try {
    const bytes = fromMultibase("z" + digest.slice(1));
    if (bytes.length !== 32) return null;
    // Re-encode to reject non-canonical spellings of the same bytes.
    return "E" + toMultibase(bytes).slice(1) === digest ? bytes : null;
  } catch {
    return null;
  }
}

/** The pre-rotation commitment for a public key: sha256 of its raw 32 bytes. */
export function keyDigest(publicKey: Uint8Array): string {
  return sha256Digest(publicKey);
}

/** Digest of an event: sha256 over JCS of the event with `sig` removed. */
export function eventDigest(event: KelEvent): string {
  return sha256Digest(utf8(canonicalizeJcs(signingBody(event))));
}

function signingBody(event: KelEvent): Record<string, unknown> {
  const { sig: _sig, ...body } = event as KelEvent & { sig?: string };
  return body as Record<string, unknown>;
}

/** The DID an inception event creates. */
export function didFromInception(inception: InceptionEvent): string {
  return DID_PREFIX + eventDigest(inception);
}

/**
 * True for the rotatable, self-certifying form `did:aroha:E<base58btc(32-byte
 * sha256)>`. Strict: the suffix must decode to exactly 32 bytes and re-encode
 * to itself, so a named DID such as `did:aroha:Echo` is never mistaken for one.
 */
export function isInceptionDid(did: string): boolean {
  return inceptionDigestFromDid(did) !== null;
}

/**
 * The 32-byte inception digest an `E` DID commits to, or null for any other
 * DID. This is the stable, key-independent identity material — personal
 * names derive from it, so they survive rotation.
 */
export function inceptionDigestFromDid(did: string): Uint8Array | null {
  if (typeof did !== "string" || !did.startsWith(DID_PREFIX)) return null;
  const suffix = did.slice(DID_PREFIX.length);
  if (suffix.includes(".") || suffix.includes(":")) return null;
  return decodeDigest(suffix);
}

// ─── Shape checks (logs arrive from the network: trust nothing) ──────────────

function decodeKey(k: unknown): Uint8Array | null {
  if (typeof k !== "string" || !k.startsWith("z")) return null;
  try {
    const bytes = fromMultibase(k);
    return bytes.length === 32 && toMultibase(bytes) === k ? bytes : null;
  } catch {
    return null;
  }
}

function singleKey(keys: unknown, where: string): { multibase: string; bytes: Uint8Array } {
  // v1 is single-key. Multi-key thresholds (KERI's weighted multisig) are a
  // future version; accepting arrays now keeps the wire format ready for it.
  if (!Array.isArray(keys) || keys.length !== 1) {
    throw new KelError("invalid", `${where}: keys must be an array of exactly one Ed25519 key in KEL v1`);
  }
  const bytes = decodeKey(keys[0]);
  if (!bytes) throw new KelError("invalid", `${where}: keys[0] is not a multibase Ed25519 public key`);
  return { multibase: keys[0] as string, bytes };
}

function requireDigest(d: unknown, where: string, field: string): string {
  if (!decodeDigest(d)) throw new KelError("invalid", `${where}: ${field} is not an E-digest`);
  return d as string;
}

function requireTime(t: unknown, where: string, field: string): void {
  if (typeof t !== "string" || Number.isNaN(Date.parse(t))) {
    throw new KelError("invalid", `${where}: ${field} is not an ISO 8601 timestamp`);
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function verifySig(event: KelEvent, publicKey: Uint8Array): Promise<boolean> {
  const sig = (event as { sig?: unknown }).sig;
  if (typeof sig !== "string") return false;
  try {
    return await ed.verifyAsync(
      Buffer.from(sig, "base64url"),
      utf8(canonicalizeJcs(signingBody(event))),
      publicKey
    );
  } catch {
    return false;
  }
}

async function signEvent<T extends KelEvent>(unsigned: Omit<T, "sig">, privateKey: Uint8Array): Promise<T> {
  const sig = await ed.signAsync(utf8(canonicalizeJcs(unsigned as Record<string, unknown>)), privateKey);
  return { ...unsigned, sig: Buffer.from(sig).toString("base64url") } as T;
}

function safeDigest(event: unknown, where: string): string {
  try {
    return eventDigest(event as KelEvent);
  } catch (e) {
    throw new KelError("invalid", `${where}: event cannot be canonicalised (${(e as Error).message})`);
  }
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Replay a KEL and return the identity's current state. Pure and offline
 * except for the optional controller-KEL source; trusts nothing about where
 * the events came from.
 *
 * Checks, in order:
 *   - `did` is an `E` DID and equals `did:aroha:` + eventDigest(events[0])
 *     (any edit to the inception — key, commitment, controller, kind — changes
 *     the digest and is caught here);
 *   - the inception is signed by its own key and its next-key commitment is
 *     not the current key's digest (which would let the current key rotate);
 *   - every later event names this DID, has seq = index, `prior` = digest of
 *     the previous event, and follows its type's authorisation rule (table at
 *     the top of this file); nothing follows a `revoke`;
 *   - for agents with a controller: every controller-authorised event is
 *     sealed in the controller's verified KEL, and every seal the controller
 *     placed for this agent matches the log (a seal past the end of the log
 *     means the log is STALE; a seal with a different digest means DUPLICITY).
 *
 * Throws `KelError` (with a `code`) on any failure.
 */
export async function verifyKel(
  did: string,
  events: KelEvent[],
  options: VerifyKelOptions = {}
): Promise<KelState> {
  if (!isInceptionDid(did)) throw new KelError("invalid", `${did} is not an inception (E-form) DID`);
  if (!Array.isArray(events) || events.length === 0) throw new KelError("invalid", "empty KEL");

  // ── Inception ──
  const inc = events[0] as unknown;
  if (!isRecord(inc) || inc.v !== KEL_VERSION || inc.type !== "inception") {
    throw new KelError("invalid", "event 0 is not a v1 inception event");
  }
  const inception = inc as unknown as InceptionEvent;
  if (inception.kind !== "person" && inception.kind !== "agent") {
    throw new KelError("invalid", "inception: kind must be \"person\" or \"agent\"");
  }
  const where0 = "inception";
  const k0 = singleKey(inception.keys, where0);
  requireDigest(inception.nextKeyDigest, where0, "nextKeyDigest");
  requireTime(inception.createdAt, where0, "createdAt");
  if (inception.controller !== undefined) {
    if (inception.kind === "person") {
      throw new KelError("invalid", "inception: a person has no controller");
    }
    if (typeof inception.controller !== "string" || !isInceptionDid(inception.controller)) {
      // A controller we cannot verify offline (a named or z DID) would make
      // recovery registry-trusted again — exactly what this form removes.
      throw new KelError("invalid", "inception: controller must be a person E-DID");
    }
  }

  const incDigest = safeDigest(inception, where0);
  if (DID_PREFIX + incDigest !== did) {
    throw new KelError("invalid", `inception digest does not match ${did} — the inception event was altered or belongs to another DID`);
  }
  if (!(await verifySig(inception, k0.bytes))) {
    throw new KelError("invalid", "inception: signature does not verify against its own key");
  }
  if (inception.nextKeyDigest === keyDigest(k0.bytes)) {
    throw new KelError("invalid", "inception: next-key commitment equals the current key — pre-rotation would protect nothing");
  }

  const state: KelState = {
    did,
    kind: inception.kind,
    ...(inception.controller ? { controller: inception.controller } : {}),
    currentKeys: [k0.multibase],
    currentKey: k0.bytes,
    nextKeyDigest: inception.nextKeyDigest,
    revoked: false,
    sequence: 0,
    lastDigest: incDigest,
    digests: [incDigest],
    keyHistory: [{ seq: 0, keys: [k0.multibase] }],
    seals: [],
    events: [inception],
    controllerRevoked: false,
  };

  // Controller-authorised events, checked against the controller's KEL below.
  const needsSeal: Array<{ seq: number; digest: string }> = [];

  // ── Subsequent events ──
  for (let i = 1; i < events.length; i++) {
    const raw = events[i] as unknown;
    const where = `event ${i}`;
    if (!isRecord(raw) || raw.v !== KEL_VERSION) throw new KelError("invalid", `${where}: not a v1 KEL event`);
    const e = raw as unknown as KelEvent;
    if (e.type === "inception") throw new KelError("invalid", `${where}: a second inception`);
    if (state.revoked) throw new KelError("invalid", `${where}: event after revocation`);
    const ev = e as Exclude<KelEvent, InceptionEvent>;
    if (ev.did !== did) throw new KelError("invalid", `${where}: names DID ${String(ev.did)}, not ${did}`);
    if (ev.seq !== i) throw new KelError("invalid", `${where}: seq ${String(ev.seq)} out of order`);
    if (ev.prior !== state.lastDigest) {
      throw new KelError("invalid", `${where}: prior digest does not chain to event ${i - 1}`);
    }
    requireTime(ev.at, where, "at");
    const digest = safeDigest(ev, where);

    switch (ev.type) {
      case "rotate": {
        const k = singleKey(ev.keys, where);
        requireDigest(ev.nextKeyDigest, where, "nextKeyDigest");
        if (keyDigest(k.bytes) !== state.nextKeyDigest) {
          throw new KelError("invalid", `${where}: rotation key does not match the pre-rotation commitment`);
        }
        // Signed by the revealed key: a thief holding only the CURRENT key
        // fails here, because the commitment pins a key they do not have.
        if (!(await verifySig(ev, k.bytes))) {
          throw new KelError("invalid", `${where}: rotation is not signed by the pre-committed next key`);
        }
        if (ev.nextKeyDigest === keyDigest(k.bytes)) {
          throw new KelError("invalid", `${where}: next-key commitment equals the new current key`);
        }
        setKeys(state, k, ev.nextKeyDigest, i);
        break;
      }
      case "recover": {
        if (state.kind !== "agent" || !state.controller) {
          throw new KelError("invalid", `${where}: recover is only defined for agents with a controller`);
        }
        if (ev.auth !== "controller") throw new KelError("invalid", `${where}: recover must be controller-authorised`);
        if ("sig" in ev) throw new KelError("invalid", `${where}: recover carries no signature (it is anchored)`);
        const k = singleKey(ev.keys, where);
        requireDigest(ev.nextKeyDigest, where, "nextKeyDigest");
        if (ev.nextKeyDigest === keyDigest(k.bytes)) {
          throw new KelError("invalid", `${where}: next-key commitment equals the new current key`);
        }
        setKeys(state, k, ev.nextKeyDigest, i);
        needsSeal.push({ seq: i, digest });
        break;
      }
      case "revoke": {
        if (ev.reason !== undefined && typeof ev.reason !== "string") {
          throw new KelError("invalid", `${where}: reason must be a string`);
        }
        if (ev.auth === "next-key") {
          const revealed = decodeKey(ev.revealedKey);
          if (!revealed) throw new KelError("invalid", `${where}: revealedKey is not an Ed25519 key`);
          if (keyDigest(revealed) !== state.nextKeyDigest) {
            throw new KelError("invalid", `${where}: revealed key does not match the pre-rotation commitment`);
          }
          if (!(await verifySig(ev, revealed))) {
            throw new KelError("invalid", `${where}: revocation is not signed by the pre-committed next key`);
          }
        } else if (ev.auth === "controller") {
          if (state.kind !== "agent" || !state.controller) {
            throw new KelError("invalid", `${where}: controller revocation on an identity with no controller`);
          }
          if ("sig" in ev) throw new KelError("invalid", `${where}: a controller revocation carries no signature (it is anchored)`);
          needsSeal.push({ seq: i, digest });
        } else {
          throw new KelError("invalid", `${where}: unknown revoke auth`);
        }
        state.revoked = true;
        state.currentKeys = [];
        state.currentKey = null;
        state.nextKeyDigest = null;
        break;
      }
      case "anchor": {
        if (state.kind !== "person") throw new KelError("invalid", `${where}: only persons anchor`);
        if (!Array.isArray(ev.seals)) throw new KelError("invalid", `${where}: seals must be an array`);
        for (const s of ev.seals as unknown[]) {
          if (
            !isRecord(s) || typeof s.did !== "string" || !isInceptionDid(s.did) ||
            !Number.isInteger(s.seq) || (s.seq as number) < 1 || !decodeDigest(s.digest)
          ) {
            throw new KelError("invalid", `${where}: malformed seal`);
          }
        }
        if (!state.currentKey || !(await verifySig(ev, state.currentKey))) {
          throw new KelError("invalid", `${where}: anchor is not signed by the current key`);
        }
        state.seals.push(...ev.seals.map((s) => ({ did: s.did, seq: s.seq, digest: s.digest })));
        break;
      }
      default:
        throw new KelError("invalid", `${where}: unknown event type ${String((ev as { type?: unknown }).type)}`);
    }

    state.sequence = i;
    state.lastDigest = digest;
    state.digests.push(digest);
    state.events.push(ev);
  }

  // ── Controller ──
  if (state.controller) {
    const needController = needsSeal.length > 0 || options.requireController === true;
    let controllerEvents: KelEvent[] | null | undefined = null;
    if (options.resolveControllerKel) {
      try {
        controllerEvents = await options.resolveControllerKel(state.controller);
      } catch (e) {
        if (e instanceof KelError && e.code !== "controller-unavailable") throw e;
        controllerEvents = null;
      }
    }
    if (!controllerEvents || controllerEvents.length === 0) {
      if (needController) {
        throw new KelError(
          "controller-unavailable",
          needsSeal.length > 0
            ? `${did} has controller-authorised events but the controller ${state.controller}'s KEL is unavailable`
            : `controller ${state.controller}'s KEL is unavailable`
        );
      }
    } else {
      // Persons have no controller, so this recursion is at most one level.
      const ctl = await verifyKel(state.controller, controllerEvents);
      if (ctl.kind !== "person") {
        throw new KelError("invalid", `controller ${state.controller} is not a person`);
      }
      const mine = ctl.seals.filter((s) => s.did === did);
      // Authorisation BEFORE comparison. An event that claims controller
      // authority but is not anchored is simply invalid — it is junk, not
      // evidence of a fork. Checking the seals first reported it as
      // "duplicity", and a caller that records duplicity on that code alone
      // would let anyone disable an agent by submitting an unsigned recover
      // at a position the controller had sealed. Only after every claimed
      // controller event is proven anchored does a digest mismatch mean the
      // log genuinely forks.
      for (const need of needsSeal) {
        if (!mine.some((s) => s.seq === need.seq && s.digest === need.digest)) {
          throw new KelError(
            "invalid",
            `event ${need.seq} claims controller authority but is not anchored in ${state.controller}'s KEL`
          );
        }
      }
      for (const seal of mine) {
        if (seal.seq > state.sequence) {
          throw new KelError(
            "stale",
            `controller anchored ${did} event ${seal.seq}, but the log provided ends at ${state.sequence}`
          );
        }
        if (state.digests[seal.seq] !== seal.digest) {
          throw new KelError(
            "duplicity",
            `controller anchored a different event at ${did} seq ${seal.seq} than the log provided`
          );
        }
      }
      state.controllerState = ctl;
      state.controllerRevoked = ctl.revoked;
    }
  }

  return state;
}

function setKeys(state: KelState, k: { multibase: string; bytes: Uint8Array }, next: string, seq: number): void {
  state.currentKeys = [k.multibase];
  state.currentKey = k.bytes;
  state.nextKeyDigest = next;
  state.keyHistory.push({ seq, keys: [k.multibase] });
}

/**
 * The key(s) that were current at sequence `seq` of a verified log — for
 * checking something signed at a known point in the past (e.g. a migration
 * linkage). Throws if `seq` is outside the log.
 */
export function keysAtSequence(state: KelState, seq: number): string[] {
  if (!Number.isInteger(seq) || seq < 0 || seq > state.sequence) {
    throw new KelError("invalid", `seq ${seq} is outside ${state.did}'s log (0..${state.sequence})`);
  }
  let keys = state.keyHistory[0].keys;
  for (const est of state.keyHistory) {
    if (est.seq > seq) break;
    keys = est.keys;
  }
  return keys;
}

/**
 * Does `personDid` control `agentDid`, right now, per both verified logs?
 * True only if the agent's inception names the person as controller, both
 * logs verify (the agent's against the person's seals), the person is a
 * person, and neither is revoked.
 */
export async function verifyAgentControlledBy(
  agentDid: string,
  agentKel: KelEvent[],
  personDid: string,
  personKel: KelEvent[]
): Promise<{ controlled: true; agent: KelState; person: KelState } | { controlled: false; reason: string }> {
  try {
    const person = await verifyKel(personDid, personKel);
    if (person.kind !== "person") return { controlled: false, reason: `${personDid} is not a person` };
    if (person.revoked) return { controlled: false, reason: `${personDid} is revoked` };
    const agent = await verifyKel(agentDid, agentKel, {
      resolveControllerKel: async (d) => (d === personDid ? personKel : null),
      requireController: true,
    });
    if (agent.kind !== "agent") return { controlled: false, reason: `${agentDid} is not an agent` };
    if (agent.controller !== personDid) {
      return { controlled: false, reason: `${agentDid} names ${agent.controller ?? "no controller"}, not ${personDid}` };
    }
    if (agent.revoked) return { controlled: false, reason: `${agentDid} has been revoked` };
    return { controlled: true, agent, person };
  } catch (e) {
    return { controlled: false, reason: (e as Error).message };
  }
}

// ─── Creating and extending logs ─────────────────────────────────────────────

/**
 * Everything the holder of a KEL identity keeps. `privateKey` signs day to
 * day; `nextPrivateKey` is the pre-committed rotation key and SHOULD NOT live
 * on the same device — for a person, an offline backup or a passkey-backed
 * store; for an agent, the controller's device or the runtime's keystore
 * (never the agent process's memory if the threat is a stolen agent host).
 */
export interface KelIdentity {
  did: string;
  kind: KelIdentityKind;
  controller?: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  nextPrivateKey: Uint8Array;
  nextPublicKey: Uint8Array;
  kel: KelEvent[];
}

export interface InceptOptions {
  kind: KelIdentityKind;
  /** Agents only: the person E-DID allowed to recover / revoke this agent. */
  controller?: string;
  /** Use this current private key instead of generating one (migration keeps the device key). */
  privateKey?: Uint8Array;
  /** Use this next private key instead of generating one. */
  nextPrivateKey?: Uint8Array;
  now?: Date;
}

/** Fresh key material for a replacement device: current key + next key + its commitment. */
export interface KelKeyMaterial {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  nextPrivateKey: Uint8Array;
  nextPublicKey: Uint8Array;
  nextKeyDigest: string;
}

async function keypair(priv?: Uint8Array): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  const privateKey = priv ?? ed.utils.randomPrivateKey();
  return { privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
}

/** Generate a current/next key pair-of-pairs, e.g. on the new device during agent recovery. */
export async function generateKelKeyMaterial(): Promise<KelKeyMaterial> {
  const cur = await keypair();
  const next = await keypair();
  return {
    privateKey: cur.privateKey,
    publicKey: cur.publicKey,
    nextPrivateKey: next.privateKey,
    nextPublicKey: next.publicKey,
    nextKeyDigest: keyDigest(next.publicKey),
  };
}

/** Create a new identity: generate (or take) keys, build and sign the inception. */
export async function incept(options: InceptOptions): Promise<KelIdentity> {
  if (options.kind === "person" && options.controller) throw new Error("a person has no controller");
  if (options.controller !== undefined && !isInceptionDid(options.controller)) {
    throw new Error("controller must be a person E-DID (did:aroha:E…)");
  }
  const cur = await keypair(options.privateKey);
  const next = await keypair(options.nextPrivateKey);
  if (keyDigest(next.publicKey) === keyDigest(cur.publicKey)) throw new Error("next key must differ from the current key");

  const unsigned: Omit<InceptionEvent, "sig"> = {
    v: KEL_VERSION,
    type: "inception",
    kind: options.kind,
    keys: [toMultibase(cur.publicKey)],
    nextKeyDigest: keyDigest(next.publicKey),
    ...(options.controller ? { controller: options.controller } : {}),
    createdAt: (options.now ?? new Date()).toISOString(),
  };
  const inception = await signEvent<InceptionEvent>(unsigned, cur.privateKey);
  return {
    did: didFromInception(inception),
    kind: options.kind,
    ...(options.controller ? { controller: options.controller } : {}),
    privateKey: cur.privateKey,
    publicKey: cur.publicKey,
    nextPrivateKey: next.privateKey,
    nextPublicKey: next.publicKey,
    kel: [inception],
  };
}

function nextPosition(kel: KelEvent[], did: string): { seq: number; prior: string } {
  const last = kel[kel.length - 1];
  if (!last) throw new Error("empty KEL");
  if (last.type === "revoke") throw new Error(`${did} is revoked; its log is closed`);
  return { seq: kel.length, prior: eventDigest(last) };
}

/**
 * Pre-rotate: the committed next key becomes current, and a new next key
 * (generated, or `options.nextPrivateKey`) is committed. Signed by the key
 * being revealed.
 */
export async function rotateKel(
  identity: KelIdentity,
  options: { nextPrivateKey?: Uint8Array; now?: Date } = {}
): Promise<KelIdentity> {
  const newNext = await keypair(options.nextPrivateKey);
  if (keyDigest(newNext.publicKey) === keyDigest(identity.nextPublicKey)) {
    throw new Error("the new next key must differ from the key being rotated in");
  }
  const event = await signEvent<RotateEvent>(
    {
      v: KEL_VERSION,
      type: "rotate",
      did: identity.did,
      ...nextPosition(identity.kel, identity.did),
      at: (options.now ?? new Date()).toISOString(),
      keys: [toMultibase(identity.nextPublicKey)],
      nextKeyDigest: keyDigest(newNext.publicKey),
    },
    identity.nextPrivateKey
  );
  return {
    ...identity,
    privateKey: identity.nextPrivateKey,
    publicKey: identity.nextPublicKey,
    nextPrivateKey: newNext.privateKey,
    nextPublicKey: newNext.publicKey,
    kel: [...identity.kel, event],
  };
}

/**
 * Abandon an identity with its own pre-committed next key. After this no key
 * of the identity verifies anything. Returns the extended log.
 */
export async function revokeKelSelf(
  identity: KelIdentity,
  options: { reason?: string; now?: Date } = {}
): Promise<KelEvent[]> {
  const event = await signEvent<SelfRevokeEvent>(
    {
      v: KEL_VERSION,
      type: "revoke",
      did: identity.did,
      ...nextPosition(identity.kel, identity.did),
      at: (options.now ?? new Date()).toISOString(),
      auth: "next-key",
      revealedKey: toMultibase(identity.nextPublicKey),
      ...(options.reason !== undefined ? { reason: options.reason } : {}),
    },
    identity.nextPrivateKey
  );
  return [...identity.kel, event];
}

/** Append an `anchor` event to a person's log sealing the given agent events. */
export async function anchorInKel(
  person: KelIdentity,
  seals: KelSeal[],
  options: { now?: Date } = {}
): Promise<KelIdentity> {
  if (person.kind !== "person") throw new Error("only persons anchor");
  const event = await signEvent<AnchorEvent>(
    {
      v: KEL_VERSION,
      type: "anchor",
      did: person.did,
      ...nextPosition(person.kel, person.did),
      at: (options.now ?? new Date()).toISOString(),
      seals,
    },
    person.privateKey
  );
  return { ...person, kel: [...person.kel, event] };
}

function controlledAgent(person: KelIdentity, agentKel: KelEvent[]): string {
  const inception = agentKel[0];
  if (!inception || inception.type !== "inception") throw new Error("agent KEL has no inception");
  if (inception.controller !== person.did) {
    throw new Error(`agent's controller is ${inception.controller ?? "none"}, not ${person.did}`);
  }
  return didFromInception(inception);
}

/**
 * The stolen/lost-device path. The controlling person installs a fresh key
 * and next-key commitment on one of their agents, without any key the agent
 * held. `replacement` comes from the NEW device (`generateKelKeyMaterial()` —
 * only its public halves need to reach the person).
 *
 * Returns both extended logs: the agent's (with `recover`) and the person's
 * (with the `anchor` that authorises it). Publish both; a verifier needs the
 * person's log to accept the recovery.
 */
export async function recoverAgent(
  person: KelIdentity,
  agentKel: KelEvent[],
  replacement: { publicKey: Uint8Array; nextKeyDigest: string },
  options: { now?: Date } = {}
): Promise<{ person: KelIdentity; agentKel: KelEvent[] }> {
  const agentDid = controlledAgent(person, agentKel);
  if (replacement.nextKeyDigest === keyDigest(replacement.publicKey)) {
    throw new Error("next-key commitment must differ from the new current key");
  }
  const now = options.now ?? new Date();
  const event: RecoverEvent = {
    v: KEL_VERSION,
    type: "recover",
    did: agentDid,
    ...nextPosition(agentKel, agentDid),
    at: now.toISOString(),
    auth: "controller",
    keys: [toMultibase(replacement.publicKey)],
    nextKeyDigest: replacement.nextKeyDigest,
  };
  const updatedPerson = await anchorInKel(person, [{ did: agentDid, seq: event.seq, digest: eventDigest(event) }], { now });
  return { person: updatedPerson, agentKel: [...agentKel, event] };
}

/**
 * The controlling person revokes one of their agents (abandoned, compromised
 * beyond recovery, decommissioned). Same two-log shape as `recoverAgent`.
 */
export async function revokeAgent(
  person: KelIdentity,
  agentKel: KelEvent[],
  options: { reason?: string; now?: Date } = {}
): Promise<{ person: KelIdentity; agentKel: KelEvent[] }> {
  const agentDid = controlledAgent(person, agentKel);
  const now = options.now ?? new Date();
  const event: ControllerRevokeEvent = {
    v: KEL_VERSION,
    type: "revoke",
    did: agentDid,
    ...nextPosition(agentKel, agentDid),
    at: now.toISOString(),
    auth: "controller",
    ...(options.reason !== undefined ? { reason: options.reason } : {}),
  };
  const updatedPerson = await anchorInKel(person, [{ did: agentDid, seq: event.seq, digest: eventDigest(event) }], { now });
  return { person: updatedPerson, agentKel: [...agentKel, event] };
}

// ─── Freshness: KelStore, duplicity, stale logs ──────────────────────────────

export interface DuplicityEvidence {
  did: string;
  seq: number;
  /** [digest already seen, conflicting digest offered]. */
  digests: [string, string];
  detectedAt: string;
}

/**
 * What a verifier remembers per DID: the longest log it has VERIFIED, and any
 * duplicity it has detected. Implementations: `InMemoryKelStore` here; the
 * runtime/registry should back it with durable storage (a forgotten log
 * re-opens the stale-log window).
 */
export interface KelStore {
  get(did: string): Promise<KelEvent[] | null>;
  /** Called only with logs that verified and extend (or equal) what is stored. */
  put(did: string, events: KelEvent[]): Promise<void>;
  recordDuplicity(evidence: DuplicityEvidence): Promise<void>;
  getDuplicity(did: string): Promise<DuplicityEvidence | null>;
}

export class InMemoryKelStore implements KelStore {
  private readonly logs = new Map<string, KelEvent[]>();
  private readonly alarms = new Map<string, DuplicityEvidence>();

  async get(did: string): Promise<KelEvent[] | null> {
    return this.logs.get(did) ?? null;
  }
  async put(did: string, events: KelEvent[]): Promise<void> {
    this.logs.set(did, [...events]);
  }
  async recordDuplicity(evidence: DuplicityEvidence): Promise<void> {
    if (!this.alarms.has(evidence.did)) this.alarms.set(evidence.did, evidence);
  }
  async getDuplicity(did: string): Promise<DuplicityEvidence | null> {
    return this.alarms.get(did) ?? null;
  }
}

export interface AcceptKelOptions extends VerifyKelOptions {
  /**
   * What to do with a log shorter than the one already stored. "reject"
   * (default) throws KelError("stale") so the caller knows the source is
   * behind; "use-stored" answers from the longer stored log instead — the
   * right choice for key resolution, where the newest verified state is what
   * matters, not which source was lagging.
   */
  onStale?: "reject" | "use-stored";
}

/**
 * Verify `events` and reconcile them with what `store` has seen for `did`:
 *   - a DID with a recorded duplicity alarm is refused outright;
 *   - the log must verify (`verifyKel`) — BEFORE it is compared, so an
 *     unauthenticated party cannot raise a false duplicity alarm with junk;
 *   - if it disagrees with the stored log at any common sequence: duplicity
 *     is recorded and KelError("duplicity") thrown — two validly-authorised
 *     different events at one position means a key was used to fork the log;
 *   - if it is shorter: stale (see `onStale`);
 *   - otherwise it is stored if it is longer, and its state returned.
 */
export async function acceptKel(
  did: string,
  events: KelEvent[],
  store: KelStore,
  options: AcceptKelOptions = {}
): Promise<KelState> {
  const alarm = await store.getDuplicity(did);
  if (alarm) {
    throw new KelError("duplicity", `${did} has a recorded duplicity alarm at seq ${alarm.seq} (since ${alarm.detectedAt})`);
  }
  const stored = await store.get(did);
  const useStored = options.onStale === "use-stored" && stored !== null && stored.length > 0;

  let state: KelState;
  try {
    state = await verifyKel(did, events, options);
  } catch (e) {
    // A log the controller's seals prove is behind: answer from the stored
    // one if allowed and it is genuinely longer.
    if (e instanceof KelError && e.code === "stale" && useStored && stored!.length > events.length) {
      return verifyKel(did, stored!, options);
    }
    throw e;
  }

  if (stored && stored.length > 0) {
    const common = Math.min(stored.length, state.digests.length);
    for (let i = 0; i < common; i++) {
      const seen = eventDigest(stored[i]);
      if (seen !== state.digests[i]) {
        const evidence: DuplicityEvidence = {
          did,
          seq: i,
          digests: [seen, state.digests[i]],
          detectedAt: new Date().toISOString(),
        };
        await store.recordDuplicity(evidence);
        throw new KelError("duplicity", `${did}: two different events at seq ${i} — the log was forked`);
      }
    }
    if (state.digests.length < stored.length) {
      if (useStored) return verifyKel(did, stored, options);
      throw new KelError(
        "stale",
        `${did}: offered log ends at seq ${state.sequence}, but seq ${stored.length - 1} has already been seen`
      );
    }
  }
  if (!stored || state.events.length > stored.length) await store.put(did, state.events);
  return state;
}

/**
 * A `KelSource` over logs you already hold — the inception that arrived with
 * a first contact, logs attached to a record, test fixtures. Indexed by the
 * DID each log's inception hashes to; if two logs share a DID the longer wins.
 */
export function kelSourceFromLogs(...logs: KelEvent[][]): KelSource {
  const byDid = new Map<string, KelEvent[]>();
  for (const log of logs) {
    const inception = log?.[0];
    if (!inception || inception.type !== "inception") continue;
    let did: string;
    try {
      did = didFromInception(inception);
    } catch {
      continue;
    }
    const existing = byDid.get(did);
    if (!existing || log.length > existing.length) byDid.set(did, log);
  }
  return async (did) => byDid.get(did) ?? null;
}

export interface ResolveKelStateOptions {
  /** Highest-seen memory. Strongly recommended for any long-lived verifier. */
  store?: KelStore;
  /** See VerifyKelOptions.requireController. */
  requireController?: boolean;
}

/**
 * Fetch, verify and (with a store) reconcile the KEL for an `E` DID, including
 * its controller's KEL when it has one. Returns null when `did` is not an
 * `E` DID or no log for it can be found; throws KelError when a log is found
 * but does not verify, is stale with nothing better stored, or is duplicitous.
 */
export async function resolveKelState(
  did: string,
  source: KelSource,
  options: ResolveKelStateOptions = {}
): Promise<KelState | null> {
  if (!isInceptionDid(did)) return null;
  const { store } = options;

  const fetchLog = async (d: string): Promise<KelEvent[] | null> => {
    let log: KelEvent[] | null | undefined = null;
    try {
      log = await source(d);
    } catch {
      log = null;
    }
    if ((!log || log.length === 0) && store) log = await store.get(d);
    return log && log.length > 0 ? log : null;
  };

  const events = await fetchLog(did);
  if (!events) return null;

  const resolveControllerKel: KelSource = async (cdid) => {
    const log = await fetchLog(cdid);
    if (!log) return null;
    if (!store) return log;
    // Reconcile the controller's log too: its seals are what make agent
    // revocations visible, so a stale controller log must not win either.
    const ctl = await acceptKel(cdid, log, store, { onStale: "use-stored" });
    return ctl.events;
  };

  const verifyOptions: VerifyKelOptions = {
    resolveControllerKel,
    requireController: options.requireController,
  };
  return store
    ? acceptKel(did, events, store, { ...verifyOptions, onStale: "use-stored" })
    : verifyKel(did, events, verifyOptions);
}

/**
 * A `PublicKeyResolver` (validateEnvelope callers, mandate verification, SAR
 * checks…) for `E` DIDs: the CURRENT key from the verified KEL. Returns null
 * for every other DID form — compose it with a z-DID or registry resolver —
 * and null (fail closed) when the identity is revoked, its controller is
 * revoked, or its log fails verification / reconciliation.
 *
 * The verification method id is accepted for interface compatibility; v1
 * KEL identities have exactly one key, so any `#fragment` on the DID maps to
 * it.
 */
export function kelKeyResolver(source: KelSource, options: ResolveKelStateOptions = {}): PublicKeyResolver {
  return async (did: string): Promise<Uint8Array | null> => {
    try {
      const state = await resolveKelState(did, source, options);
      if (!state || state.revoked || state.controllerRevoked || !state.currentKey) return null;
      return state.currentKey;
    } catch {
      return null;
    }
  };
}
