// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Conversation and Memory Profile — signed rooms, consent records, authored
 * turns and the memory-record shape (spec "Conversation and Memory Profile").
 *
 * WHY THIS EXISTS. A shared chat is the smallest setting in which "whose
 * instruction is this?" cannot be answered by the model: a guest's message
 * enters the model with the same role as the host's. The profile carries
 * authority and attribution as signed metadata instead, so enforcement can
 * happen outside the model:
 *   - a Room record, signed by its owner's PERSON key, says who is a member,
 *     in which role, from which membership epoch;
 *   - a consent record, signed by the person it is about, says which uses of
 *     their messages they agreed to (ISO/IEC TS 27560-shaped);
 *   - a turn signature binds an author's key to one message's content hash,
 *     room, epoch and addressees;
 *   - a MemoryFact records who asserted a fact, about whom, in which scope,
 *     and from which signed origin.
 *
 * No new wire message type is introduced: these objects are carried inside
 * existing bodies (room/invitation data, `capability: "invite"` requests) and
 * stored by the runtime.
 *
 * WHAT A SIGNATURE HERE PROVES. Possession of a key the signer's Key Event
 * Log names. It does not prove a person was present when the runtime used a
 * person key it holds for them — the same limit as UserApproval.
 *
 * Every signature is Ed25519 over the UTF-8 bytes of the RFC 8785 JCS form of
 * the object with its `signature` field removed. Each object carries its own
 * `purpose` tag inside the signed bytes, so a signature for one kind of
 * object never verifies as another.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "../crypto/jcs.js";
import { validateDisclosure, type ArohaDisclosure } from "../messages/disclosure.js";
import { verifyKel, type KelIdentityKind, type KelSource } from "../identity/kel.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

export const ROOM_PURPOSE = "aroha.room/v1" as const;
export const CONSENT_PURPOSE = "aroha.consent/v1" as const;
export const TURN_PURPOSE = "aroha.turn/v1" as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export type RoomMemberKind = "person" | "agent";
export type RoomRole = "host" | "guest" | "own" | "invited" | "delegated";

export interface RoomMember {
  did: string;
  kind: RoomMemberKind;
  /** The runtime's local principal id for this member, when it has one. */
  principalId?: string;
  displayName: string;
  role: RoomRole;
  /** Room epoch at which the member joined. */
  joinedEpoch: number;
  /** Room epoch at which the member left; absent while a member. Membership is [joinedEpoch, leftEpoch). */
  leftEpoch?: number;
  /** recordId of the member's consent record. REQUIRED for a person with role "guest". */
  consentRef?: string;
}

export interface RoomMemoryPolicy {
  /** Whether the agent may read the host's personal memory in this room. */
  personalRead: boolean;
  /** Whether anything said in this room may be written to any personal memory. */
  personalWrite: boolean;
  /** Room-scoped memory: off, or on only for members whose consent grants memory_write. */
  roomMemory: "off" | "consented";
  /** What an invited or delegated agent member may be shown. Default "none". */
  agentRead?: "none" | "members";
}

export interface RoomRecord {
  v: 1;
  purpose: typeof ROOM_PURPOSE;
  roomId: string;
  threadId: string;
  /** The host person's DID. Its key signs the record. */
  ownerDid: string;
  /** Incremented on every membership change. */
  epoch: number;
  members: RoomMember[];
  historyVisibility: "joined" | "shared";
  invocation: "explicit" | "implicit";
  memoryPolicy: RoomMemoryPolicy;
  /** The room agent's disclosure, shown to every member on joining. */
  disclosure: ArohaDisclosure;
  /** ISO 8601. */
  updatedAt: string;
  /** base64url Ed25519 by ownerDid's current key over JCS(record minus signature). */
  signature: string;
}

export const CONSENT_PURPOSES = ["transcript_retention", "agent_use_of_messages", "memory_write", "provider_processing"] as const;
export type ConsentPurpose = (typeof CONSENT_PURPOSES)[number];

export interface ConsentEvent {
  event: "given" | "withdrawn";
  purposes: ConsentPurpose[];
  /** ISO 8601. */
  at: string;
  /** Who recorded the event: the subject, or (withdrawal only) a room member at `epoch`. */
  actorDid: string;
  /** Room epoch at which the event was recorded. */
  epoch: number;
  /**
   * base64url Ed25519 by actorDid over consentEventSigningBytes(record, index):
   * JCS of { purpose: "aroha.consent-event/v1", recordId, subjectDid, roomId,
   * purposes, withdrawalRoute, index, prevHash, entry: <this event minus sig> }.
   */
  sig: string;
}

/**
 * A consent record: an append-only, hash-chained list of signed events.
 *
 * WHY EVERY EVENT IS SIGNED BY ITS OWN ACTOR. A record re-signed whole by
 * whoever appended last would let that signer rewrite earlier events —
 * including inventing a "given" event in the subject's name. Each event is
 * instead signed by its actor and chained to the previous one (prevHash), so
 * an earlier event cannot be altered, inserted or removed without breaking a
 * signature the appender does not hold.
 */
export interface ConsentRecord {
  v: 1;
  purpose: typeof CONSENT_PURPOSE;
  recordId: string;
  /** The person the consent is about. */
  subjectDid: string;
  roomId: string;
  /** Purposes the subject was asked about. */
  purposes: ConsentPurpose[];
  /** Where and how consent can be withdrawn (a URL or a short instruction). */
  withdrawalRoute: string;
  /** Append-only. The first event is "given" by the subject. */
  events: ConsentEvent[];
}

/** The object a turn signature covers. */
export interface TurnSignaturePayload {
  purpose: typeof TURN_PURPOSE;
  threadId: string;
  roomId: string;
  epoch: number;
  /** ISO 8601. */
  at: string;
  /** SHA-256 hex of the UTF-8 bytes of the turn's content (turnContentHash). */
  contentHash: string;
  /** DIDs the turn is addressed to (people or agents). Empty = nobody in particular. */
  addressedTo: string[];
}

/** An authored turn as stored or carried: the payload fields plus author and signature. */
export interface SignedTurn extends Omit<TurnSignaturePayload, "purpose"> {
  authorDid: string;
  content: string;
  /** base64url Ed25519 by authorDid over JCS(TurnSignaturePayload). */
  authorSignature: string;
}

/** The memory record (schema only; storage and enforcement belong to the runtime). */
export interface MemoryFact {
  v: 1;
  factId: string;
  text: string;
  /** Whoever asserted it. */
  speakerDid: string;
  /** Resolved from the speaker's KEL, never declared by the message (resolveSpeakerKind). */
  speakerKind: RoomMemberKind;
  /** "self", "room", or the DID of the member (person or agent) the fact is about. */
  subjectDid: string;
  /** "private" or "room:<roomId>". */
  scope: string;
  audience: "host" | "persons" | "members";
  epoch: number;
  /** Hash of the signed turn or envelope the fact was extracted from. */
  origin: string;
  derivedFrom: string[];
  /** Agent-asserted facts are claims until a person adopts them. */
  status: "fact" | "claim";
  consentRef?: string;
  createdAt: string;
}

/** What a resolver returns for a DID: its current key and identity kind. */
export interface ResolvedSigner {
  publicKey: Uint8Array;
  kind: RoomMemberKind;
}
export type ConversationKeyResolver = (did: string) => Promise<ResolvedSigner | null> | ResolvedSigner | null;

export type ConversationVerification<T> = { ok: true; value: T; signer: ResolvedSigner } | { ok: false; reason: string };

// ─── Shared helpers ───────────────────────────────────────────────────────────

const utf8 = (s: string) => new TextEncoder().encode(s);
const SHA256_HEX = /^[0-9a-f]{64}$/;

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
function isNonEmpty(x: unknown): x is string {
  return typeof x === "string" && x.length > 0;
}
function isDid(x: unknown): x is string {
  return isNonEmpty(x) && x.startsWith("did:");
}
function isEpoch(x: unknown): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 0;
}
function isIso(x: unknown): x is string {
  return typeof x === "string" && !Number.isNaN(Date.parse(x));
}
function unknownField(obj: Record<string, unknown>, known: readonly string[]): string | null {
  const set = new Set(known);
  for (const k of Object.keys(obj)) if (!set.has(k)) return k;
  return null;
}

/** JCS bytes of an object with its `signature` field removed. */
export function conversationSigningBytes(obj: Record<string, unknown>): Uint8Array {
  const { signature: _s, ...rest } = obj;
  return utf8(canonicalizeJcs(rest));
}

async function signBytes(bytes: Uint8Array, privateKey: Uint8Array): Promise<string> {
  return Buffer.from(await ed.signAsync(bytes, privateKey)).toString("base64url");
}

async function verifyBytes(sigB64: string, bytes: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  try {
    const sig = Uint8Array.from(Buffer.from(sigB64, "base64url"));
    if (sig.length !== 64) return false;
    return await ed.verifyAsync(sig, bytes, publicKey);
  } catch {
    return false;
  }
}

async function resolveSigner(resolve: ConversationKeyResolver, did: string): Promise<ResolvedSigner | null> {
  try {
    return (await resolve(did)) ?? null;
  } catch {
    return null;
  }
}

/**
 * A resolver backed by Key Event Logs: verifies the DID's KEL and returns its
 * current key and its `kind`. A DID without a verifiable, unrevoked KEL
 * resolves to null — the profile never takes a signer's kind from the
 * message itself.
 */
export function kelConversationResolver(source: KelSource): ConversationKeyResolver {
  return async (did: string) => {
    const events = await source(did);
    if (!events) return null;
    const state = await verifyKel(did, events);
    if (state.revoked || state.controllerRevoked || !state.currentKey) return null;
    return { publicKey: state.currentKey, kind: state.kind };
  };
}

/**
 * speakerKind resolution rule: the kind recorded in the DID's verified KEL
 * inception. Anything that cannot be resolved that way — a z-form or named
 * DID, an unverifiable log — is an "agent". WHY default to agent: a person's
 * word carries more authority in a room (approvals, consent, fact adoption),
 * so the unproven case must get the lesser authority, never the greater.
 */
export function resolveSpeakerKind(kelKind: KelIdentityKind | null | undefined): RoomMemberKind {
  return kelKind === "person" ? "person" : "agent";
}

// ─── Room ─────────────────────────────────────────────────────────────────────

const ROOM_FIELDS = [
  "v", "purpose", "roomId", "threadId", "ownerDid", "epoch", "members", "historyVisibility",
  "invocation", "memoryPolicy", "disclosure", "updatedAt", "signature",
] as const;
const MEMBER_FIELDS = ["did", "kind", "principalId", "displayName", "role", "joinedEpoch", "leftEpoch", "consentRef"] as const;
const ROLES = new Set<RoomRole>(["host", "guest", "own", "invited", "delegated"]);

/** Structural rules for a room record. Returns null when it is well-formed. */
export function checkRoomShape(value: unknown, opts: { requireSignature?: boolean } = {}): string | null {
  if (!isRecord(value)) return "room is not an object";
  const r = value;
  if (r.v !== 1 || r.purpose !== ROOM_PURPOSE) return "not an aroha.room/v1 record";
  const extra = unknownField(r, ROOM_FIELDS);
  if (extra) return `unknown field "${extra}"`;
  for (const k of ["roomId", "threadId"] as const) if (!isNonEmpty(r[k])) return `${k} must be a non-empty string`;
  if (!isDid(r.ownerDid)) return "ownerDid must be a DID";
  if (!isEpoch(r.epoch)) return "epoch must be a non-negative integer";
  if (r.historyVisibility !== "joined" && r.historyVisibility !== "shared") return "historyVisibility is invalid";
  if (r.invocation !== "explicit" && r.invocation !== "implicit") return "invocation is invalid";
  if (!isIso(r.updatedAt)) return "updatedAt must be an ISO 8601 date";
  const mp = r.memoryPolicy;
  if (!isRecord(mp)) return "memoryPolicy must be an object";
  if (unknownField(mp, ["personalRead", "personalWrite", "roomMemory", "agentRead"])) return "memoryPolicy has an unknown field";
  if (typeof mp.personalRead !== "boolean" || typeof mp.personalWrite !== "boolean") return "memoryPolicy.personalRead/personalWrite must be booleans";
  if (mp.roomMemory !== "off" && mp.roomMemory !== "consented") return "memoryPolicy.roomMemory is invalid";
  if (mp.agentRead !== undefined && mp.agentRead !== "none" && mp.agentRead !== "members") return "memoryPolicy.agentRead is invalid";
  const d = validateDisclosure(r.disclosure);
  if (!d.valid) return `disclosure: ${d.reason}`;
  if (!Array.isArray(r.members) || r.members.length === 0) return "members must be a non-empty array";
  const seen = new Set<string>();
  let hosts = 0;
  for (const [i, m] of r.members.entries()) {
    const where = `members[${i}]`;
    if (!isRecord(m)) return `${where} is not an object`;
    const mx = unknownField(m, MEMBER_FIELDS);
    if (mx) return `${where} has unknown field "${mx}"`;
    if (!isDid(m.did)) return `${where}.did must be a DID`;
    if (seen.has(m.did)) return `${where}.did appears twice`;
    seen.add(m.did);
    if (m.kind !== "person" && m.kind !== "agent") return `${where}.kind is invalid`;
    if (!ROLES.has(m.role as RoomRole)) return `${where}.role is invalid`;
    if (typeof m.displayName !== "string") return `${where}.displayName must be a string`;
    if (m.principalId !== undefined && !isNonEmpty(m.principalId)) return `${where}.principalId must be a non-empty string`;
    if (!isEpoch(m.joinedEpoch) || m.joinedEpoch > (r.epoch as number)) return `${where}.joinedEpoch must be an integer ≤ epoch`;
    if (m.leftEpoch !== undefined && (!isEpoch(m.leftEpoch) || m.leftEpoch <= m.joinedEpoch || m.leftEpoch > (r.epoch as number))) {
      return `${where}.leftEpoch must be an integer in (joinedEpoch, epoch]`;
    }
    if (m.consentRef !== undefined && !isNonEmpty(m.consentRef)) return `${where}.consentRef must be a non-empty string`;
    if (m.role === "guest" && m.kind === "person" && m.consentRef === undefined) return `${where}: a person guest requires a consentRef`;
    if (m.role === "host") {
      hosts++;
      if (m.did !== r.ownerDid || m.kind !== "person") return `${where}: the host must be the owner, a person`;
    }
  }
  if (hosts !== 1) return "exactly one member must have role host";
  if (opts.requireSignature !== false && !isNonEmpty(r.signature)) return "signature is missing";
  return null;
}

/** Sign a room record with the owner's person key. */
export async function signRoom(room: Omit<RoomRecord, "signature" | "v" | "purpose">, ownerPrivateKey: Uint8Array): Promise<RoomRecord> {
  const unsigned = { v: 1 as const, purpose: ROOM_PURPOSE, ...room };
  const problem = checkRoomShape(unsigned, { requireSignature: false });
  if (problem) throw new Error(`Invalid room: ${problem}`);
  const body = JSON.parse(JSON.stringify(unsigned)) as Omit<RoomRecord, "signature">;
  return { ...body, signature: await signBytes(conversationSigningBytes(body), ownerPrivateKey) };
}

/**
 * Verify a room record: shape, owner resolves to a PERSON, signature by the
 * owner's current key. A room signed by an agent key is refused — rooms are
 * the host person's statement of who may speak.
 */
export async function verifyRoom(room: unknown, resolve: ConversationKeyResolver): Promise<ConversationVerification<RoomRecord>> {
  const problem = checkRoomShape(room);
  if (problem) return { ok: false, reason: `malformed room: ${problem}` };
  const r = room as RoomRecord;
  const signer = await resolveSigner(resolve, r.ownerDid);
  if (!signer) return { ok: false, reason: `room owner ${r.ownerDid} has no resolvable key` };
  if (signer.kind !== "person") return { ok: false, reason: `room owner ${r.ownerDid} is not a person` };
  if (!(await verifyBytes(r.signature, conversationSigningBytes(r as unknown as Record<string, unknown>), signer.publicKey))) {
    return { ok: false, reason: "room signature does not verify" };
  }
  return { ok: true, value: r, signer };
}

/** The members of a room at a given epoch: joinedEpoch ≤ epoch < leftEpoch. */
export function roomMembersAt(room: RoomRecord, epoch: number): RoomMember[] {
  return room.members.filter((m) => m.joinedEpoch <= epoch && (m.leftEpoch === undefined || epoch < m.leftEpoch));
}

// ─── Consent ──────────────────────────────────────────────────────────────────

export const CONSENT_EVENT_PURPOSE = "aroha.consent-event/v1" as const;

const CONSENT_FIELDS = ["v", "purpose", "recordId", "subjectDid", "roomId", "purposes", "withdrawalRoute", "events"] as const;
const EVENT_FIELDS = ["event", "purposes", "at", "actorDid", "epoch", "sig"] as const;
const PURPOSE_SET = new Set<string>(CONSENT_PURPOSES);

function isPurposeList(x: unknown): x is ConsentPurpose[] {
  return Array.isArray(x) && x.length > 0 && x.every((p) => typeof p === "string" && PURPOSE_SET.has(p)) && new Set(x).size === x.length;
}

/** SHA-256 hex of JCS of a whole event (sig included) — the next event's prevHash. */
export function consentEventHash(event: ConsentEvent): string {
  return Buffer.from(sha256(utf8(canonicalizeJcs(event)))).toString("hex");
}

/**
 * The exact bytes event `index` of a record is signed over. Binds the event
 * to the record's identity and terms (recordId, subject, room, purposes,
 * withdrawalRoute), to its position, and to the previous event's hash.
 */
export function consentEventSigningBytes(
  record: Pick<ConsentRecord, "recordId" | "subjectDid" | "roomId" | "purposes" | "withdrawalRoute" | "events">,
  index: number,
): Uint8Array {
  const { sig: _s, ...entry } = record.events[index];
  return utf8(canonicalizeJcs({
    purpose: CONSENT_EVENT_PURPOSE,
    recordId: record.recordId,
    subjectDid: record.subjectDid,
    roomId: record.roomId,
    purposes: record.purposes,
    withdrawalRoute: record.withdrawalRoute,
    index,
    prevHash: index === 0 ? null : consentEventHash(record.events[index - 1]),
    entry,
  }));
}

/** Structural and event-order rules for a consent record (signatures not checked). */
export function checkConsentShape(value: unknown): string | null {
  if (!isRecord(value)) return "consent record is not an object";
  const c = value;
  if (c.v !== 1 || c.purpose !== CONSENT_PURPOSE) return "not an aroha.consent/v1 record";
  const extra = unknownField(c, CONSENT_FIELDS);
  if (extra) return `unknown field "${extra}"`;
  if (!isNonEmpty(c.recordId) || !isNonEmpty(c.roomId)) return "recordId and roomId must be non-empty strings";
  if (!isDid(c.subjectDid)) return "subjectDid must be a DID";
  if (!isPurposeList(c.purposes)) return "purposes must be a non-empty list of known purposes without repeats";
  if (!isNonEmpty(c.withdrawalRoute)) return "withdrawalRoute must be a non-empty string";
  if (!Array.isArray(c.events) || c.events.length === 0) return "events must be a non-empty array";
  let last = -Infinity;
  let lastEpoch = -1;
  for (const [i, e] of c.events.entries()) {
    const where = `events[${i}]`;
    if (!isRecord(e)) return `${where} is not an object`;
    const ex = unknownField(e, EVENT_FIELDS);
    if (ex) return `${where} has unknown field "${ex}"`;
    if (e.event !== "given" && e.event !== "withdrawn") return `${where}.event is invalid`;
    if (!isPurposeList(e.purposes)) return `${where}.purposes is invalid`;
    for (const p of e.purposes as string[]) if (!(c.purposes as string[]).includes(p)) return `${where} names a purpose the record does not ask about`;
    if (!isIso(e.at)) return `${where}.at must be an ISO 8601 date`;
    const t = Date.parse(e.at as string);
    if (t < last) return `${where} is earlier than the event before it`;
    last = t;
    if (!isEpoch(e.epoch) || e.epoch < lastEpoch) return `${where}.epoch must be a non-negative integer, not decreasing`;
    lastEpoch = e.epoch;
    if (!isDid(e.actorDid)) return `${where}.actorDid must be a DID`;
    if (!isNonEmpty(e.sig)) return `${where}.sig is missing`;
    // Only the subject can GIVE consent; a room member may withdraw it.
    if (e.event === "given" && e.actorDid !== c.subjectDid) return `${where}: only the subject can give consent`;
  }
  if ((c.events[0] as ConsentEvent).event !== "given") return "the first event must be \"given\"";
  return null;
}

/** Create a consent record with its first ("given") event, signed by the subject. */
export async function createConsent(
  input: Omit<ConsentRecord, "v" | "purpose" | "events"> & { given: { purposes: ConsentPurpose[]; at: string; epoch: number } },
  subjectPrivateKey: Uint8Array,
): Promise<ConsentRecord> {
  const { given, ...rest } = input;
  return appendSigned(
    { v: 1, purpose: CONSENT_PURPOSE, ...rest, events: [] },
    { event: "given", purposes: given.purposes, at: given.at, epoch: given.epoch, actorDid: input.subjectDid },
    subjectPrivateKey,
  );
}

/** Append an event (given by the subject, or withdrawn by the subject or a room member), signed by its actor. */
export async function appendConsentEvent(
  record: ConsentRecord,
  event: Omit<ConsentEvent, "sig">,
  actorPrivateKey: Uint8Array,
): Promise<ConsentRecord> {
  return appendSigned(record, event, actorPrivateKey);
}

async function appendSigned(record: ConsentRecord, event: Omit<ConsentEvent, "sig">, priv: Uint8Array): Promise<ConsentRecord> {
  const draft: ConsentRecord = JSON.parse(JSON.stringify({ ...record, events: [...record.events, { ...event, sig: "pending" }] }));
  const problem = checkConsentShape(draft);
  if (problem) throw new Error(`Invalid consent record: ${problem}`);
  const i = draft.events.length - 1;
  draft.events[i].sig = await signBytes(consentEventSigningBytes(draft, i), priv);
  return draft;
}

/**
 * Verify a consent record: shape, then EVERY event's signature against its
 * own actor's key (each actor must resolve to a person). A "given" event
 * must be signed by the subject. When any event's actor is not the subject,
 * the room record is REQUIRED, and that actor must have been a member of
 * the room at the event's epoch — a member who has left cannot withdraw on
 * someone's behalf.
 */
export async function verifyConsent(
  record: unknown,
  resolve: ConversationKeyResolver,
  opts: { room?: RoomRecord } = {},
): Promise<ConversationVerification<ConsentRecord>> {
  const problem = checkConsentShape(record);
  if (problem) return { ok: false, reason: `malformed consent record: ${problem}` };
  const c = record as ConsentRecord;
  if (opts.room && opts.room.roomId !== c.roomId) return { ok: false, reason: "consent record is for a different room" };
  let subjectSigner: ResolvedSigner | null = null;
  for (const [i, e] of c.events.entries()) {
    if (e.actorDid !== c.subjectDid) {
      if (!opts.room) return { ok: false, reason: `events[${i}] is by ${e.actorDid}, not the subject; the room record is required to check membership` };
      if (e.epoch > opts.room.epoch || !roomMembersAt(opts.room, e.epoch).some((m) => m.did === e.actorDid)) {
        return { ok: false, reason: `events[${i}]: ${e.actorDid} was not a room member at epoch ${e.epoch}` };
      }
    }
    const signer = await resolveSigner(resolve, e.actorDid);
    if (!signer) return { ok: false, reason: `events[${i}]: actor ${e.actorDid} has no resolvable key` };
    if (signer.kind !== "person") return { ok: false, reason: `events[${i}]: actor ${e.actorDid} is not a person` };
    if (!(await verifyBytes(e.sig, consentEventSigningBytes(c, i), signer.publicKey))) {
      return { ok: false, reason: `events[${i}]: signature does not verify` };
    }
    if (e.actorDid === c.subjectDid) subjectSigner = signer;
  }
  return { ok: true, value: c, signer: subjectSigner! };
}

/** The purposes currently granted: given minus later withdrawn, replayed in order. Call on a VERIFIED record. */
export function effectiveConsent(record: Pick<ConsentRecord, "events">): Set<ConsentPurpose> {
  const granted = new Set<ConsentPurpose>();
  for (const e of record.events) {
    for (const p of e.purposes) {
      if (e.event === "given") granted.add(p);
      else granted.delete(p);
    }
  }
  return granted;
}

// ─── Turns ────────────────────────────────────────────────────────────────────

/** SHA-256 hex of the UTF-8 bytes of a turn's content. */
export function turnContentHash(content: string): string {
  return Buffer.from(sha256(utf8(content))).toString("hex");
}

/** The exact bytes a turn signature covers. */
export function turnSigningBytes(p: Omit<TurnSignaturePayload, "purpose">): Uint8Array {
  return utf8(canonicalizeJcs({
    purpose: TURN_PURPOSE,
    threadId: p.threadId,
    roomId: p.roomId,
    epoch: p.epoch,
    at: p.at,
    contentHash: p.contentHash,
    addressedTo: p.addressedTo,
  }));
}

function checkTurnShape(t: unknown): string | null {
  if (!isRecord(t)) return "turn is not an object";
  const extra = unknownField(t, ["threadId", "roomId", "epoch", "at", "contentHash", "addressedTo", "authorDid", "content", "authorSignature"]);
  if (extra) return `unknown field "${extra}"`;
  if (!isNonEmpty(t.threadId) || !isNonEmpty(t.roomId)) return "threadId and roomId must be non-empty strings";
  if (!isEpoch(t.epoch)) return "epoch must be a non-negative integer";
  if (!isIso(t.at)) return "at must be an ISO 8601 date";
  if (typeof t.contentHash !== "string" || !SHA256_HEX.test(t.contentHash)) return "contentHash must be SHA-256 hex";
  if (!Array.isArray(t.addressedTo) || !t.addressedTo.every(isDid)) return "addressedTo must be an array of DIDs";
  if (!isDid(t.authorDid)) return "authorDid must be a DID";
  if (typeof t.content !== "string") return "content must be a string";
  if (!isNonEmpty(t.authorSignature)) return "authorSignature is missing";
  return null;
}

/** Sign a turn with its author's key. `contentHash` is computed from `content`. */
export async function signTurn(
  turn: Omit<SignedTurn, "contentHash" | "authorSignature">,
  authorPrivateKey: Uint8Array,
): Promise<SignedTurn> {
  const contentHash = turnContentHash(turn.content);
  const payload = { ...turn, contentHash };
  return { ...payload, authorSignature: await signBytes(turnSigningBytes(payload), authorPrivateKey) };
}

/**
 * Verify an authored turn: shape, contentHash matches content, signature by
 * the author's current key, and (when a room is given) the author was a
 * member at the turn's epoch. The result's `signer.kind` is the speaker kind
 * — from the resolver (the KEL), never from the turn.
 */
export async function verifyTurn(
  turn: unknown,
  resolve: ConversationKeyResolver,
  opts: { room?: RoomRecord } = {},
): Promise<ConversationVerification<SignedTurn>> {
  const problem = checkTurnShape(turn);
  if (problem) return { ok: false, reason: `malformed turn: ${problem}` };
  const t = turn as SignedTurn;
  if (turnContentHash(t.content) !== t.contentHash) return { ok: false, reason: "turn content does not match contentHash" };
  if (opts.room) {
    if (opts.room.roomId !== t.roomId || opts.room.threadId !== t.threadId) return { ok: false, reason: "turn is for a different room or thread" };
    if (!roomMembersAt(opts.room, t.epoch).some((m) => m.did === t.authorDid)) {
      return { ok: false, reason: `${t.authorDid} was not a room member at epoch ${t.epoch}` };
    }
  }
  const signer = await resolveSigner(resolve, t.authorDid);
  if (!signer) return { ok: false, reason: `turn author ${t.authorDid} has no resolvable key` };
  if (!(await verifyBytes(t.authorSignature, turnSigningBytes(t), signer.publicKey))) {
    return { ok: false, reason: "turn signature does not verify" };
  }
  return { ok: true, value: t, signer };
}
