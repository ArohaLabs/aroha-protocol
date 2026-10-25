// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Signed action receipts — taint, approver and mandate, carried across a
 * process boundary.
 *
 * WHY THIS EXISTS. A runtime already knows, at the moment it acts, whether
 * the turn that chose the action had read untrusted content (its taint
 * flag), which human approved the call, and under which mandate. All three
 * stopped at the process boundary: a downstream party received the action
 * and nothing that would let it ask "did this come from untrusted input, and
 * if so, did a person approve it?". A receipt is that statement, signed by
 * the acting agent's own key, so a verifier anywhere can check it without
 * trusting the transport that carried it.
 *
 * WHAT IT PROVES, AND WHAT IT DOES NOT. The signature proves the acting
 * agent's key made these claims about this action and these arguments. It
 * does not prove the claims are TRUE — an agent that lies about its own
 * taint state can sign the lie. What it gives a verifier is accountability
 * (the claim is attributable and non-repudiable) and a policy hook: a
 * verifier that requires untainted-or-approved can refuse on the agent's own
 * signed word, and an agent caught signing a false "untainted" has produced
 * the evidence against itself.
 *
 * FORMAT. The body is canonicalised with RFC 8785 JCS (canonicalizeJcs) and
 * signed with Ed25519; the signature is base64url over the UTF-8 bytes of
 * that canonical form. `purpose` is inside the signed body, so a signature
 * made for any other Aroha object can never be replayed as a receipt.
 *
 * VERSIONS. v2 ("aroha.action-receipt/v2", issued by signActionReceipt)
 * adds the requester, principal and executor identities, the hash of what
 * the approver was shown, a traceparent, a room binding, and an `outcome`
 * so that DENIED actions are receipted too. v1 receipts still verify. Each
 * version refuses fields it does not define.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "../crypto/jcs.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** Domain tag of a v1 receipt, carried in the signed body. */
export const ACTION_RECEIPT_PURPOSE = "aroha.action-receipt/v1" as const;

/**
 * Domain tag of a v2 receipt. A different tag, not just a different `v`,
 * so a v2 signature can never verify as a v1 receipt or the reverse even if
 * a verifier only compared one of the two fields.
 */
export const ACTION_RECEIPT_PURPOSE_V2 = "aroha.action-receipt/v2" as const;

/**
 * Where the content that shaped an action came from. Free-form strings are
 * accepted so a newer sender is not refused by an older verifier, but these
 * are the values this package and the runtime emit.
 */
export type ReceiptProvenance = "user" | "tool" | "retrieval" | "memory" | "peer" | "delegated" | (string & {});

/** Who approved the action, when a human did. */
export interface ReceiptApproval {
  /** The approving person's DID (or principal id when they have no DID). */
  approverDid: string;
  /** ISO 8601. */
  approvedAt: string;
  /** Identifies the approval itself, so the receipt can be joined to the approval record. */
  approvalId: string;
  /**
   * v2 only. SHA-256 hex of the JCS form of exactly what the approver was
   * shown (UserApproval.presentedHash). Lets a verifier holding the
   * presented content check the approval was for THIS content.
   */
  presentedHash?: string;
  /**
   * v2 only. The approver's own signature from the approval record
   * (UserApproval.userSignature), base64url. The receipt carries it as
   * evidence; checking it needs the approval record it was made over, which
   * `approvalId` references. The receipt alone does not contain that record,
   * so verifyActionReceipt does not check this field.
   */
  approverSignature?: string;
}

/** Whether the action ran or was refused. v2 only; a v1 receipt always means "executed". */
export type ReceiptOutcome = "executed" | "denied";

/** Fields every receipt version carries. */
interface ReceiptCommon {
  /** The acting agent — the key that signs the receipt. */
  agentDid: string;
  /** The capability or tool name the action invokes. */
  action: string;
  /** SHA-256 hex of the JCS canonical form of the action's arguments (hashReceiptArgs). */
  argsSha256: string;
  /** When the action was taken, or refused (ISO 8601). */
  at: string;
  /** Whether untrusted content had entered the turn that chose this action. */
  tainted: boolean;
  /** Where that content came from, when known. */
  provenance?: ReceiptProvenance[];
  /** The human approval behind the action, when there was one. */
  approval?: ReceiptApproval;
  /** The mandate the action was taken under, when there was one. */
  mandateId?: string;
  /** Who granted that mandate (a DID). */
  mandateGrantor?: string;
  /** Joins the receipt to the request and audit entries it belongs to. */
  correlationId?: string;
}

/** A v1 receipt body (still verifiable, no longer issued by signActionReceipt). */
export interface ArohaActionReceiptBodyV1 extends ReceiptCommon {
  v: 1;
  purpose: typeof ACTION_RECEIPT_PURPOSE;
}

/**
 * A v2 receipt body: v1 plus the four identities (requester, principal,
 * approver, executor), the hash of what the approver was shown, a trace
 * link, and an outcome, so that a refusal is receipted as well as an action.
 */
export interface ArohaActionReceiptBodyV2 extends ReceiptCommon {
  v: 2;
  purpose: typeof ACTION_RECEIPT_PURPOSE_V2;
  /** Who asked for the action (a person or agent DID). */
  requesterDid?: string;
  /** Whose authority the action ran under (the mandate root's person or organisation). */
  principalDid?: string;
  /** The agent that executed (or refused) it. Usually equals agentDid. */
  executorDid?: string;
  /** SHA-256 hex of the JCS form of what was presented for approval (hashPresentedContent). */
  presentedHash?: string;
  /** W3C Trace Context traceparent of the span that took the action. */
  traceparent?: string;
  outcome: ReceiptOutcome;
  /** Required when outcome is "denied"; absent otherwise. */
  denialReason?: string;
  /** The conversation room the action was requested from, if any. */
  roomId?: string;
  /** The room member the action was taken for, under a guest grant (task mandate onBehalfOf). */
  onBehalfOf?: string;
}

/** Everything a receipt says, before it is signed. */
export type ArohaActionReceiptBody = ArohaActionReceiptBodyV1 | ArohaActionReceiptBodyV2;

/** A signed receipt: the body plus a base64url Ed25519 signature over JCS(body). */
export type ArohaActionReceipt = ArohaActionReceiptBody & { signature: string };
export type ArohaActionReceiptV1 = ArohaActionReceiptBodyV1 & { signature: string };
export type ArohaActionReceiptV2 = ArohaActionReceiptBodyV2 & { signature: string };

/**
 * Input to signActionReceipt: a v2 body without the constant fields.
 * `outcome` defaults to "executed".
 */
export type ActionReceiptInput = Omit<ArohaActionReceiptBodyV2, "v" | "purpose" | "at" | "outcome"> & {
  at?: string;
  outcome?: ReceiptOutcome;
};

/** Input to the legacy v1 signer. */
export type ActionReceiptInputV1 = Omit<ArohaActionReceiptBodyV1, "v" | "purpose" | "at"> & { at?: string };

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * The argument digest a receipt carries: SHA-256 over the JCS canonical form.
 * Canonical, so a sender and a verifier that build the same arguments in a
 * different key order agree on the digest.
 */
export function hashReceiptArgs(args: unknown): string {
  return hex(sha256(new TextEncoder().encode(canonicalizeJcs(args ?? {}))));
}

/**
 * The presented-content digest (`presentedHash`): SHA-256 hex over the JCS
 * form of exactly what the approver was shown. Same construction as
 * hashReceiptArgs, named separately because it hashes a different thing
 * (the decision context, not the call) and the two must not be confused.
 *
 * WHY: an approval that binds only the call's parameters says nothing about
 * what the person was told. A surface that showed one thing and submitted
 * another still produced a valid approval. Hashing what was shown, inside the
 * signed approval and the receipt, makes that divergence detectable.
 */
export function hashPresentedContent(content: unknown): string {
  return hex(sha256(new TextEncoder().encode(canonicalizeJcs(content ?? {}))));
}

/** The exact bytes that are signed: JCS of the body, signature excluded. */
export function actionReceiptSigningBytes(body: ArohaActionReceiptBody): Uint8Array {
  const { signature: _ignored, ...rest } = body as ArohaActionReceiptBody & { signature?: string };
  return new TextEncoder().encode(canonicalizeJcs(stripUndefined(rest)));
}

/** JCS refuses `undefined`; optional fields that are absent are simply omitted (one level deep, for `approval`). */
function stripUndefined<T extends Record<string, unknown>>(obj: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    out[k] = v !== null && typeof v === "object" && !Array.isArray(v) ? stripUndefined(v as Record<string, unknown>) : v;
  }
  return out as T;
}

/** The outcome / denialReason rule, shared by the signer and the parser. */
function outcomeProblem(outcome: unknown, denialReason: unknown): string | null {
  if (outcome !== "executed" && outcome !== "denied") return "outcome must be \"executed\" or \"denied\"";
  if (outcome === "denied" && (typeof denialReason !== "string" || denialReason.length === 0)) {
    return "a denied receipt requires a denialReason";
  }
  if (outcome === "executed" && denialReason !== undefined) return "an executed receipt must not carry a denialReason";
  return null;
}

/**
 * Build and sign a v2 receipt with the acting agent's Ed25519 private key.
 *
 * Denied actions are receipted too (outcome "denied" with a denialReason):
 * a record of what an agent was stopped from doing is evidence a verifier
 * and an incident responder need as much as a record of what it did.
 */
export async function signActionReceipt(input: ActionReceiptInput, privateKey: Uint8Array): Promise<ArohaActionReceiptV2> {
  const outcome = input.outcome ?? "executed";
  const problem = outcomeProblem(outcome, input.denialReason);
  if (problem) throw new Error(`Invalid action receipt: ${problem}`);
  const body = stripUndefined({
    ...input,
    outcome,
    v: 2 as const,
    purpose: ACTION_RECEIPT_PURPOSE_V2,
    at: input.at ?? new Date().toISOString(),
  }) as ArohaActionReceiptBodyV2;
  const signature = await ed.signAsync(actionReceiptSigningBytes(body), privateKey);
  return { ...body, signature: Buffer.from(signature).toString("base64url") };
}

/**
 * Sign a legacy v1 receipt. Kept for test vectors and for interop with a
 * verifier that predates v2; new code calls signActionReceipt.
 * @deprecated v1 carries no outcome, identities or presentedHash.
 */
export async function signActionReceiptV1(input: ActionReceiptInputV1, privateKey: Uint8Array): Promise<ArohaActionReceiptV1> {
  const body = stripUndefined({
    ...input,
    v: 1 as const,
    purpose: ACTION_RECEIPT_PURPOSE,
    at: input.at ?? new Date().toISOString(),
  }) as ArohaActionReceiptBodyV1;
  const signature = await ed.signAsync(actionReceiptSigningBytes(body), privateKey);
  return { ...body, signature: Buffer.from(signature).toString("base64url") };
}

/** SHA-256 hex of the whole signed receipt (JCS), for an audit trail to reference. */
export function actionReceiptHash(receipt: ArohaActionReceipt): string {
  return hex(sha256(new TextEncoder().encode(canonicalizeJcs(stripUndefined({ ...receipt })))));
}

export type ReceiptKeyResolver = (did: string) => Uint8Array | null | undefined | Promise<Uint8Array | null | undefined>;

export type ReceiptVerification =
  | { ok: true; receipt: ArohaActionReceipt }
  | { ok: false; reason: string };

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((s) => typeof s === "string");
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

const COMMON_FIELDS = [
  "v", "purpose", "agentDid", "action", "argsSha256", "at", "tainted", "provenance",
  "approval", "mandateId", "mandateGrantor", "correlationId", "signature",
] as const;
const KNOWN_V1 = new Set<string>(COMMON_FIELDS);
const KNOWN_V2 = new Set<string>([
  ...COMMON_FIELDS,
  "requesterDid", "principalDid", "executorDid", "presentedHash", "traceparent",
  "outcome", "denialReason", "roomId", "onBehalfOf",
]);
const APPROVAL_V1 = new Set(["approverDid", "approvedAt", "approvalId"]);
const APPROVAL_V2 = new Set([...APPROVAL_V1, "presentedHash", "approverSignature"]);

/**
 * Structural check of an untrusted value. Every field is type-checked so a
 * verifier never reads a property of the wrong type from a peer's object.
 * Accepts v1 and v2; each version refuses fields it does not define.
 */
export function parseActionReceipt(value: unknown): ArohaActionReceipt | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  const isV1 = r.v === 1 && r.purpose === ACTION_RECEIPT_PURPOSE;
  const isV2 = r.v === 2 && r.purpose === ACTION_RECEIPT_PURPOSE_V2;
  if (!isV1 && !isV2) return null;
  for (const k of ["agentDid", "action", "argsSha256", "at", "signature"] as const) {
    if (typeof r[k] !== "string" || (r[k] as string).length === 0) return null;
  }
  if (typeof r.tainted !== "boolean") return null;
  if (r.provenance !== undefined && !isStringArray(r.provenance)) return null;
  for (const k of ["mandateId", "mandateGrantor", "correlationId"] as const) {
    if (r[k] !== undefined && typeof r[k] !== "string") return null;
  }
  if (r.approval !== undefined) {
    const a = r.approval as Record<string, unknown> | null;
    if (typeof a !== "object" || a === null || Array.isArray(a)) return null;
    if (typeof a.approverDid !== "string" || typeof a.approvedAt !== "string" || typeof a.approvalId !== "string") return null;
    const allowed = isV2 ? APPROVAL_V2 : APPROVAL_V1;
    for (const k of Object.keys(a)) if (!allowed.has(k)) return null;
    if (a.presentedHash !== undefined && (typeof a.presentedHash !== "string" || !SHA256_HEX.test(a.presentedHash))) return null;
    if (a.approverSignature !== undefined && typeof a.approverSignature !== "string") return null;
  }
  if (isV2) {
    for (const k of ["requesterDid", "principalDid", "executorDid", "traceparent", "roomId", "onBehalfOf"] as const) {
      if (r[k] !== undefined && (typeof r[k] !== "string" || (r[k] as string).length === 0)) return null;
    }
    if (r.presentedHash !== undefined && (typeof r.presentedHash !== "string" || !SHA256_HEX.test(r.presentedHash))) return null;
    if (outcomeProblem(r.outcome, r.denialReason)) return null;
  }
  // Unknown fields are refused rather than ignored: they would be covered by
  // the signature but invisible to this verifier's policy, so a receipt could
  // carry a claim the verifier silently never evaluated. Per version: a v1
  // receipt carrying a v2-only field is malformed, not "v1 plus extras".
  const known = isV2 ? KNOWN_V2 : KNOWN_V1;
  for (const k of Object.keys(r)) if (!known.has(k)) return null;
  return r as unknown as ArohaActionReceipt;
}

/**
 * Verify a receipt's signature against its agent's key (v1 or v2).
 *
 * `resolvePublicKey` is the verifier's own resolver (a content-addressed DID
 * resolves from the DID itself; a rotatable one from its verified key event
 * log). A receipt whose agent cannot be resolved is refused — never accepted
 * on its own say-so.
 */
export async function verifyActionReceipt(
  receipt: unknown,
  resolvePublicKey: ReceiptKeyResolver,
): Promise<ReceiptVerification> {
  const parsed = parseActionReceipt(receipt);
  if (!parsed) return { ok: false, reason: "the action receipt is malformed" };
  let key: Uint8Array | null | undefined;
  try {
    key = await resolvePublicKey(parsed.agentDid);
  } catch {
    key = null;
  }
  if (!key) return { ok: false, reason: `the action receipt's agent ${parsed.agentDid} has no resolvable key` };
  let sig: Uint8Array;
  try {
    sig = Uint8Array.from(Buffer.from(parsed.signature, "base64url"));
  } catch {
    return { ok: false, reason: "the action receipt's signature is not base64url" };
  }
  if (sig.length !== 64) return { ok: false, reason: "the action receipt's signature has the wrong length" };
  let valid = false;
  try {
    valid = await ed.verifyAsync(sig, actionReceiptSigningBytes(parsed), key);
  } catch {
    valid = false;
  }
  return valid ? { ok: true, receipt: parsed } : { ok: false, reason: "the action receipt's signature does not verify" };
}

/**
 * Check a VERIFIED receipt against the content a party says was presented
 * for approval. Returns null when every presentedHash the receipt carries
 * (top level and inside `approval`) equals hashPresentedContent(content),
 * otherwise the reason. A receipt with no presentedHash is refused: it makes
 * no statement about what was shown, so it cannot confirm one.
 */
export function verifyPresentedHash(receipt: ArohaActionReceiptBody, presentedContent: unknown): string | null {
  if (receipt.v !== 2) return "a v1 action receipt carries no presentedHash";
  const hashes = [receipt.presentedHash, receipt.approval?.presentedHash].filter((h): h is string => h !== undefined);
  if (hashes.length === 0) return "the action receipt carries no presentedHash";
  const actual = hashPresentedContent(presentedContent);
  for (const h of hashes) {
    if (h !== actual) return "the content presented for approval differs from what the receipt records";
  }
  return null;
}

/**
 * The policy a downstream verifier applies: an action derived from untrusted
 * input must carry a human approval. Returns the refusal reason, or null when
 * the receipt satisfies the policy. Call it on a VERIFIED receipt — this
 * reads claims, it does not check who made them.
 */
export function requireApprovalIfTainted(receipt: ArohaActionReceiptBody): string | null {
  if (!receipt.tainted) return null;
  if (receipt.approval && receipt.approval.approverDid && receipt.approval.approvalId) return null;
  return "The action was derived from untrusted input and carries no human approval.";
}

/**
 * Check that a verified receipt describes THIS action: the same agent, the
 * same action name and the same arguments. A valid receipt for a different
 * call proves nothing about this one.
 */
export function receiptMatches(
  receipt: ArohaActionReceiptBody,
  expected: { agentDid: string; action: string; args: unknown },
): string | null {
  if (receipt.agentDid !== expected.agentDid) return `the action receipt is for ${receipt.agentDid}, not ${expected.agentDid}`;
  if (receipt.action !== expected.action) return `the action receipt is for "${receipt.action}", not "${expected.action}"`;
  if (receipt.argsSha256 !== hashReceiptArgs(expected.args)) return "the action receipt does not match the action's arguments";
  return null;
}
