// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The JWT form of a mandate (spec §6.10): the same mandate, written so that
 * a stock JSON Web Token library can read and verify it.
 *
 * WHY. The native token (§6.5, §6.6) is signed over RFC 8785 canonical JSON.
 * That is exact and compact, but nothing outside an Aroha SDK can verify it.
 * Services that already accept OAuth access tokens have a JWT library, a key
 * set URL for each issuer, and code that reads `iss`, `sub` and `exp`. In the
 * JWT form each link of a mandate chain is one such token:
 *
 *   header   { "alg": "EdDSA", "typ": "aroha-mandate+jwt", "kid": <key id> }
 *   claims   { "iss": <grantor>, "sub": <grantee>, "jti": <mandateId>,
 *              "iat": <issuedAt, seconds>, "exp": <expiresAt, seconds>,
 *              "authorization_details": [ { "type": <the mandate's type URI>,
 *                                           …the rest of the mandate body… } ] }
 *
 * `authorization_details` is the member OAuth Rich Authorization Requests
 * (RFC 9396) uses to say what a token is good for. A spending chain is its
 * link JWTs joined by "~", root first; a single link is a plain JWT.
 *
 * WHAT STAYS THE SAME. The body a verifier acts on, and every rule applied to
 * it: narrowing on every link, expiry, revocation, the expected root and
 * grantee. This module only maps between claims and the body, and signs and
 * checks the JWS. The chain rules live in mandate.ts and run on both forms.
 *
 * WHAT A STOCK LIBRARY DOES AND DOES NOT CHECK. It checks the signature,
 * `iss` and `exp` of one link. It does not check that a child narrows its
 * parent, or that the chain reaches the root you trust. Use
 * verifyMandateChain for that.
 *
 * STRICTNESS. A mandate JWT may carry only the header members and claims
 * listed above. An unknown claim is refused, not ignored: a claim such as
 * `nbf` or `aud` that a stock library enforces and this verifier does not
 * would let the two disagree about one token. `typ` is required and checked
 * (RFC 8725), so a token of another kind signed by the same key is never read
 * as a mandate. Times are whole seconds, the form every JWT library accepts,
 * so the claims and the body are the same mandate with nothing rounded away.
 *
 * A mandate is issued in one form. Its signature covers different bytes in
 * each, so a token cannot be converted. A spending token holds one form. A
 * task chain is a list of tokens, and the verifier takes each on its own.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { verifyEd25519 } from "./ed25519-strict.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** The `typ` header of a mandate JWT. */
export const MANDATE_JWT_TYP = "aroha-mandate+jwt";
/** `authorization_details[0].type` of a spending mandate link. */
export const SPENDING_MANDATE_DETAIL_TYPE = "https://aroha-labs.com/mandates/spending";
/** `authorization_details[0].type` of a task mandate. */
export const TASK_MANDATE_DETAIL_TYPE = "https://aroha-labs.com/mandates/task";
/** Joins the link JWTs of a spending chain, root first. */
export const MANDATE_JWT_SEPARATOR = "~";
/** Longest single mandate JWT accepted, in characters. */
export const MANDATE_JWT_MAX_LENGTH = 16 * 1024;

export type MandateJwtKind = "spending" | "task";

const DETAIL_TYPES: Record<MandateJwtKind, string> = { spending: SPENDING_MANDATE_DETAIL_TYPE, task: TASK_MANDATE_DETAIL_TYPE };
const HEADER_MEMBERS = new Set(["alg", "typ", "kid"]);
const CLAIMS = new Set(["iss", "sub", "jti", "iat", "exp", "authorization_details"]);
/** Body members that live in registered claims, never inside authorization_details. */
const CLAIM_BACKED = ["grantor", "grantee", "mandateId", "issuedAt", "expiresAt"] as const;
const SEGMENT = /^[A-Za-z0-9_-]+$/;
/** A 64-byte Ed25519 signature is exactly 86 base64url characters. */
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
/** 9999-12-31T23:59:59Z: the last instant the body's date form can write. */
const MAX_SECONDS = 253_402_300_799;
/** Deepest nesting a claims set may have. Every SDK must stop at the same depth. */
const MAX_DEPTH = 32;
/** Largest magnitude every JSON parser reads exactly (RFC 8259 §6, I-JSON). */
const MAX_NUMBER = Number.MAX_SAFE_INTEGER;
/** RFC 7519 StringOrURI, ASCII only so every SDK reads it alike. */
const STRING_OR_URI = /^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$/;

/** Members allowed in a detail, by kind, and in the objects it holds (spec §6.10 rule 4). */
const DETAIL_MEMBERS: Record<MandateJwtKind, ReadonlySet<string>> = {
  spending: new Set(["mandateTier", "constraints", "parentMandateId", "actingFor"]),
  task: new Set(["mandateType", "mandateTier", "allowed", "blocked", "taskConstraints", "spendingConstraints", "invariants", "parentMandateId"]),
};
const SPENDING_CONSTRAINTS = new Set(["spendLimitUsd", "sessionLimitUsd", "currency", "merchantCategory", "requireHumanApprovalAboveUsd", "allowedMerchants", "validFrom", "validUntil"]);
const TASK_CONSTRAINTS = new Set(["actionLimits", "computeLimit", "dataAccess", "outputHandling", "reversibleOnly", "humanGates", "checkpointIntervalMs", "requireSandbox", "maxDelegationDepth", "onBehalfOf", "roomId"]);

export interface MandateJwtHeader {
  alg: "EdDSA" | "Ed25519";
  typ: string;
  kid?: string;
}

export interface DecodedMandateJwt {
  kind: MandateJwtKind;
  header: MandateJwtHeader;
  /** The mandate body the claims decode to. NOT shape-checked here; callers run their own check. */
  body: Record<string, unknown>;
  /** The ASCII text the signature covers: `<header>.<payload>` as received. */
  signingInput: string;
  /** base64url Ed25519 signature. */
  signature: string;
}

/** True for a token in the JWT form: only a JWT contains a ".". */
export function looksLikeMandateJwt(token: unknown): token is string {
  return typeof token === "string" && token.includes(".");
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * True when an object in valid JSON text repeats a member name. JSON.parse keeps
 * the last, so a token could show one value to this verifier and another to a
 * parser that keeps the first. Scans the text, because the parsed value has
 * already lost the repeat. Iterative, so deep nesting cannot exhaust the stack.
 */
function hasDuplicateMember(text: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let expectName = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      if (expectName) {
        const name = JSON.parse(text.slice(i, end + 1)) as string;
        const seen = stack[stack.length - 1] as Set<string>;
        if (seen.has(name)) return true;
        seen.add(name);
        expectName = false;
      }
      i = end;
    } else if (ch === "{") {
      stack.push(new Set());
      expectName = true;
    } else if (ch === "[") {
      stack.push(null);
    } else if (ch === "}" || ch === "]") {
      stack.pop();
      expectName = false;
    } else if (ch === ",") {
      expectName = stack.length > 0 && stack[stack.length - 1] !== null;
    }
  }
  return false;
}

/** Decode one base64url JSON segment, or null. The encoding must be canonical and the text valid UTF-8. */
function decodeJsonSegment(segment: string): unknown {
  if (!SEGMENT.test(segment)) return null;
  const bytes = Buffer.from(segment, "base64url");
  if (b64u(bytes) !== segment) return null;
  try {
    // ignoreBOM keeps a byte order mark in the text, so JSON.parse refuses it as
    // every other SDK does, instead of silently removing it.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const value = JSON.parse(text) as unknown;
    return hasDuplicateMember(text) ? null : value;
  } catch {
    return null;
  }
}

/** Why a parsed JSON value could read differently in another SDK, or null. */
function checkPortable(value: unknown, depth = 1): string | null {
  if (depth > MAX_DEPTH) return `nested deeper than ${MAX_DEPTH} levels`;
  if (typeof value === "string") return /[\uD800-\uDFFF]/u.test(value) ? "a string is not well-formed Unicode" : null;
  if (typeof value === "number") return Number.isFinite(value) && Math.abs(value) <= MAX_NUMBER ? null : "a number is outside the exact range";
  if (Array.isArray(value)) {
    for (const v of value) {
      const why = checkPortable(v, depth + 1);
      if (why) return why;
    }
  } else if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) {
      const why = checkPortable(k, depth) ?? checkPortable(v, depth + 1);
      if (why) return why;
    }
  }
  return null;
}

/** The first member of `value` outside `allowed`, or null. Leaves type checks to the shape check. */
function unknownMember(value: unknown, allowed: ReadonlySet<string>): string | null {
  return isRecord(value) ? Object.keys(value).find((k) => !allowed.has(k)) ?? null : null;
}

/**
 * Date parsers disagree on nearly everything else: some forms are local time,
 * so a verdict could depend on the verifier's time zone. Exactly one form.
 */
function isExactInstant(x: unknown): boolean {
  if (typeof x !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)) return false;
  const ms = Date.parse(x);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === x;
}

function isSeconds(x: unknown): x is number {
  return typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= MAX_SECONDS;
}

/**
 * The instant a mandate JWT may carry for `ms`: the whole second at or
 * before it. Rounding down keeps a child's expiry at or before its parent's.
 */
export function mandateJwtInstant(ms: number): number {
  return Math.floor(ms / 1000) * 1000;
}

/**
 * The claims of a mandate body. Throws when the body cannot be written as a
 * JWT without loss: `issuedAt` and `expiresAt` must fall on whole seconds.
 */
export function mandateBodyToJwtClaims(kind: MandateJwtKind, body: Record<string, unknown>): Record<string, unknown> {
  const seconds = (field: "issuedAt" | "expiresAt"): number => {
    const ms = Date.parse(String(body[field]));
    if (Number.isNaN(ms) || ms % 1000 !== 0 || ms < 0) throw new Error(`A mandate JWT needs ${field} on a whole second`);
    return ms / 1000;
  };
  const detail: Record<string, unknown> = { type: DETAIL_TYPES[kind] };
  for (const [k, v] of Object.entries(body)) {
    if ((CLAIM_BACKED as readonly string[]).includes(k) || v === undefined) continue;
    if (k === "type") throw new Error('A mandate body may not have a member named "type"');
    detail[k] = v;
  }
  return {
    iss: body.grantor,
    sub: body.grantee,
    jti: body.mandateId,
    iat: seconds("issuedAt"),
    exp: seconds("expiresAt"),
    authorization_details: [detail],
  };
}

/** The mandate body a set of claims decodes to, or the reason they are not a mandate. */
export function jwtClaimsToMandateBody(claims: unknown): { kind: MandateJwtKind; body: Record<string, unknown> } | string {
  if (!isRecord(claims)) return "claims are not an object";
  for (const k of Object.keys(claims)) if (!CLAIMS.has(k)) return `unknown claim "${k}"`;
  const portable = checkPortable(claims);
  if (portable) return portable;
  for (const k of ["iss", "sub", "jti"] as const) {
    if (typeof claims[k] !== "string" || (claims[k] as string).length === 0) return `${k} must be a non-empty string`;
  }
  // RFC 7519 StringOrURI: a value with a colon must be a URI.
  for (const k of ["iss", "sub"] as const) {
    const v = claims[k] as string;
    if (v.includes(":") && !STRING_OR_URI.test(v)) return `${k} contains a colon and is not a URI`;
  }
  if (!isSeconds(claims.iat)) return "iat must be a whole number of seconds";
  if (!isSeconds(claims.exp)) return "exp must be a whole number of seconds";
  const details = claims.authorization_details;
  if (!Array.isArray(details) || details.length !== 1 || !isRecord(details[0])) {
    return "authorization_details must hold exactly one object";
  }
  const detail = details[0];
  const kind = (Object.keys(DETAIL_TYPES) as MandateJwtKind[]).find((k) => DETAIL_TYPES[k] === detail.type);
  if (!kind) return `authorization_details type ${JSON.stringify(detail.type)} is not a mandate`;
  for (const k of CLAIM_BACKED) {
    if (k in detail) return `authorization_details must not carry ${k}; it is a registered claim`;
  }
  const { type: _type, ...rest } = detail;
  // Nothing here may be ignored: a member this verifier skips is one a
  // RAR-aware consumer may enforce, or a limit an older verifier would drop.
  const stray = unknownMember(rest, DETAIL_MEMBERS[kind]);
  if (stray) return `authorization_details has an unknown member "${stray}"`;
  const constraints = kind === "spending" ? [detail.constraints] : [detail.spendingConstraints];
  for (const c of constraints) {
    const k = unknownMember(c, SPENDING_CONSTRAINTS);
    if (k) return `constraints has an unknown member "${k}"`;
    if (isRecord(c)) {
      for (const f of ["validFrom", "validUntil"] as const) {
        if (c[f] !== undefined && !isExactInstant(c[f])) return `constraints.${f} is not in the form YYYY-MM-DDTHH:mm:ss.sssZ`;
      }
    }
  }
  const taskStray = kind === "task" ? unknownMember(detail.taskConstraints, TASK_CONSTRAINTS) : null;
  if (taskStray) return `taskConstraints has an unknown member "${taskStray}"`;
  return {
    kind,
    body: {
      ...rest,
      grantee: claims.sub,
      grantor: claims.iss,
      issuedAt: new Date(claims.iat * 1000).toISOString(),
      expiresAt: new Date(claims.exp * 1000).toISOString(),
      mandateId: claims.jti,
    },
  };
}

/**
 * Decode one mandate JWT without verifying its signature. Returns the decoded
 * token, or the reason it is not a mandate JWT. The body is not shape-checked.
 */
export function decodeMandateJwt(jwt: unknown): DecodedMandateJwt | string {
  if (typeof jwt !== "string") return "not a string";
  if (jwt.length > MANDATE_JWT_MAX_LENGTH) return `longer than ${MANDATE_JWT_MAX_LENGTH} characters`;
  const parts = jwt.split(".");
  if (parts.length !== 3) return "not a compact JWS (three dot-separated parts)";
  const header = decodeJsonSegment(parts[0]);
  if (!isRecord(header)) return "header is not base64url JSON";
  for (const k of Object.keys(header)) if (!HEADER_MEMBERS.has(k)) return `unknown header member "${k}"`;
  // An allowlist, not "anything but none": the key is Ed25519, so no other
  // algorithm can be right, and naming one must not be a way to pick the check.
  if (header.alg !== "EdDSA" && header.alg !== "Ed25519") return `alg ${JSON.stringify(header.alg)} is not EdDSA`;
  if (header.typ !== MANDATE_JWT_TYP && header.typ !== `application/${MANDATE_JWT_TYP}`) {
    return `typ ${JSON.stringify(header.typ)} is not ${MANDATE_JWT_TYP}`;
  }
  if (header.kid !== undefined && (typeof header.kid !== "string" || header.kid.length === 0)) return "kid must be a non-empty string";
  const mapped = jwtClaimsToMandateBody(decodeJsonSegment(parts[1]));
  if (typeof mapped === "string") return parts[1].length === 0 ? "payload is empty" : mapped;
  if (!SIGNATURE.test(parts[2]) || b64u(Buffer.from(parts[2], "base64url")) !== parts[2]) return "signature is not a base64url Ed25519 signature";
  return {
    kind: mapped.kind,
    header: header as unknown as MandateJwtHeader,
    body: mapped.body,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: parts[2],
  };
}

/** Sign a mandate body as a JWT. `kid` is the signer's key id, normally the key's RFC 7638 thumbprint. */
export async function signMandateJwt(kind: MandateJwtKind, body: Record<string, unknown>, privateKey: Uint8Array, kid?: string): Promise<string> {
  const header = { alg: "EdDSA", typ: MANDATE_JWT_TYP, ...(kid !== undefined ? { kid } : {}) };
  const encode = (value: unknown) => b64u(new TextEncoder().encode(JSON.stringify(value)));
  const claims = mandateBodyToJwtClaims(kind, body);
  // Refused here so an issuer never mints what every verifier would reject.
  const mapped = jwtClaimsToMandateBody(claims);
  if (typeof mapped === "string") throw new Error(`Cannot issue this mandate as a JWT: ${mapped}`);
  const signingInput = `${encode(header)}.${encode(claims)}`;
  // 87 = "." plus an 86-character signature. Refused here so that an issuer
  // never mints a mandate that every verifier would then reject.
  if (signingInput.length + 87 > MANDATE_JWT_MAX_LENGTH) {
    throw new Error(`A mandate JWT cannot be longer than ${MANDATE_JWT_MAX_LENGTH} characters`);
  }
  const signature = await ed.signAsync(new TextEncoder().encode(signingInput), privateKey);
  return `${signingInput}.${b64u(signature)}`;
}

/** True when the JWT's signature verifies under `publicKey`. Never throws. Says nothing about the claims. */
export async function verifyMandateJwtSignature(jwt: string, publicKey: Uint8Array): Promise<boolean> {
  const decoded = decodeMandateJwt(jwt);
  if (typeof decoded === "string") return false;
  try {
    return await verifyEd25519(Buffer.from(decoded.signature, "base64url"), new TextEncoder().encode(decoded.signingInput), publicKey);
  } catch {
    return false;
  }
}

/** Split a JWT-form token into its link JWTs, root first, or the reason it cannot be split. */
export function splitMandateJwtChain(token: string): string[] | string {
  const links = token.split(MANDATE_JWT_SEPARATOR);
  if (links.some((l) => l.length === 0)) return "empty link in the chain";
  return links;
}

export interface MandateTokenSummary {
  kind: MandateJwtKind;
  /** "jwt" for the JWT form, "native" for the Aroha v1 / v2 token. */
  format: "jwt" | "native";
  mandateId: string;
  grantor: string;
  grantee: string;
}

/**
 * Read a token's leaf without verifying anything: which kind of mandate it
 * is, its id, grantor and grantee, in either form. Null when it is not a
 * mandate token. For routing and error messages only — every field is
 * unauthenticated until the token is verified.
 */
export function peekMandateToken(token: unknown): MandateTokenSummary | null {
  if (typeof token !== "string" || token.length === 0) return null;
  const strings = (kind: MandateJwtKind, format: "jwt" | "native", m: Record<string, unknown>): MandateTokenSummary | null =>
    typeof m.mandateId === "string" && typeof m.grantor === "string" && typeof m.grantee === "string"
      ? { kind, format, mandateId: m.mandateId, grantor: m.grantor, grantee: m.grantee }
      : null;
  if (looksLikeMandateJwt(token)) {
    const links = token.split(MANDATE_JWT_SEPARATOR);
    const decoded = decodeMandateJwt(links[links.length - 1]);
    return typeof decoded === "string" ? null : strings(decoded.kind, "jwt", decoded.body);
  }
  try {
    const raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as unknown;
    if (!isRecord(raw) || !isRecord(raw.mandate)) return null;
    return strings(raw.mandate.mandateType !== undefined ? "task" : "spending", "native", raw.mandate);
  } catch {
    return null;
  }
}
