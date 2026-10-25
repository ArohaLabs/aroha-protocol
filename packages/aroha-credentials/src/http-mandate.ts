// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mandate presentation over plain HTTP — the REST counterpart of the MCP
 * binding in @aroha-sdk/mcp-bridge (`_meta["aroha/mandate"]`).
 *
 * WHY. A mandate token on its own is a bearer credential: whoever copies it
 * out of a log, a proxy or a browser tab can spend it. A REST server must
 * therefore never accept the token alone. The holder (the mandate's grantee)
 * signs each request — this server, this method, this path and query, these
 * body bytes, a single-use nonce, a short expiry — and the server checks that
 * signature against the holder's DID before it looks at the mandate.
 *
 * ── Wire format (spec §6.9.2) ───────────────────────────────────────────────
 *
 *   Aroha-Mandate: base64url( UTF-8( JCS({ token, holder, nonce, expires, proof }) ) )
 *
 * `proof` is the holder's Ed25519 signature (base64url, no padding) over the
 * UTF-8 bytes of the RFC 8785 JCS canonicalisation of
 *
 *   { purpose:    "aroha.http-mandate-presentation/v1",
 *     audience:   <the server's identifier, as the server configures it>,
 *     method:     <HTTP method, ASCII upper-case>,
 *     target:     <path + query exactly as sent; see httpRequestTarget()>,
 *     bodySha256: <lower-case hex SHA-256 of the exact body bytes; empty body = SHA-256("")>,
 *     mandateId:  <the presented token's leaf mandateId>,
 *     holder, nonce, expires }
 *
 * Client:  headers = await presentMandateHttp({ token, holderDid, holderPrivateKey, audience, method, url, body })
 * Server:  await verifyHttpMandateRequest(req.headers["aroha-mandate"], { audience, method, url, body, nonces, expectedRoot, isRevoked })
 *
 * This module imports only @noble/* and core's crypto subpath, so it is
 * exported from the Worker-safe `@aroha-sdk/credentials/mandates` entry too.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalizeJcs } from "./jcs.js";
import {
  createMandateKeyResolver,
  resolveContentAddressedKey,
  verifyMandateChain,
  type MandateKeyResolver,
  type MandateRevocationCheck,
  type VerifyMandateChainOptions,
} from "./mandate.js";
import type { ArohaSpendingMandateBody } from "@aroha-sdk/core";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

/** The request header that carries a mandate presentation. */
export const HTTP_MANDATE_HEADER = "Aroha-Mandate";
/** Domain-separation string inside every HTTP presentation proof. */
export const HTTP_MANDATE_PRESENTATION_PURPOSE = "aroha.http-mandate-presentation/v1";
/** Longest lifetime a presentation may have (5 minutes). */
export const HTTP_PRESENTATION_MAX_TTL_MS = 5 * 60_000;
/** Clock-skew allowance a verifier adds to the maximum lifetime. */
export const HTTP_PRESENTATION_CLOCK_SKEW_MS = 30_000;
/** Longest header value a verifier will decode. Tokens carry their chain, so allow a few KB per link. */
export const HTTP_PRESENTATION_MAX_HEADER_LENGTH = 32_768;

const DEFAULT_TTL_MS = 60_000;
const PRESENTATION_KEYS = ["expires", "holder", "nonce", "proof", "token"] as const;
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const EXPIRES_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const METHOD_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** RFC 3986 characters allowed in a path or query, unencoded. */
const TARGET_CHARS_RE = /^[A-Za-z0-9\-._~:/?[\]@!$&'()*+,;=%]*$/;
const ABSOLUTE_HTTP_RE = /^[Hh][Tt][Tt][Pp][Ss]?:\/\/[^/?#]*/;

export type HttpRequestBody = string | Uint8Array | ArrayBuffer | null | undefined;

/** The decoded `Aroha-Mandate` header. */
export interface HttpMandatePresentation {
  token: string;
  holder: string;
  nonce: string;
  expires: string;
  proof: string;
}

/**
 * Why a presentation was refused. Stable across SDKs (the shared vectors
 * pin them); the human-readable `reason` is not.
 */
export type HttpPresentationFailureCode =
  | "MISSING"                  // no header
  | "MALFORMED"                // not base64url JCS JSON with exactly the five string members, bad nonce or expires format
  | "EXPIRED"
  | "LIFETIME_TOO_LONG"
  | "MALFORMED_TOKEN"          // token is not a decodable mandate token
  | "HOLDER_NOT_GRANTEE"       // the presenter is not the mandate's grantee
  | "BAD_REQUEST"              // the server's own method or URL cannot be normalised
  | "UNKNOWN_HOLDER"           // the holder's key cannot be resolved
  | "BAD_PROOF"                // signature does not verify for this audience, method, target and body
  | "REPLAYED"                 // nonce already used
  | "NONCE_STORE_UNAVAILABLE"; // the nonce store threw — treated as a refusal

export type HttpPresentationResult =
  | { ok: true; holder: string; token: string; mandateId: string }
  | { ok: false; code: HttpPresentationFailureCode; reason: string };

/**
 * Single-use nonce memory. A server with more than one process MUST back
 * this with shared storage (Redis `SET key 1 NX PXAT expiresAtMs`, a unique
 * index in a database), and `claim` MUST be atomic: two concurrent claims of
 * the same key cannot both return true.
 */
export interface HttpPresentationNonceStore {
  /**
   * Record `key` until `expiresAtMs`. Returns true if the key was new, false
   * if it was already recorded. A throw (or rejected promise) refuses the request.
   */
  claim(key: string, expiresAtMs: number, nowMs: number): boolean | Promise<boolean>;
}

/**
 * In-memory nonce store for a single-process server. Entries are dropped once
 * their presentation has expired. When full (default 100 000 live entries) it
 * refuses new claims rather than forgetting old ones: forgetting would let a
 * captured request be replayed.
 */
export class InMemoryHttpPresentationNonces implements HttpPresentationNonceStore {
  private readonly seen = new Map<string, number>();
  private readonly maxEntries: number;
  private claims = 0;

  constructor(options: { maxEntries?: number } = {}) {
    this.maxEntries = options.maxEntries ?? 100_000;
  }

  claim(key: string, expiresAtMs: number, nowMs: number): boolean {
    if (++this.claims % 64 === 0 || this.seen.size >= this.maxEntries) this.prune(nowMs);
    if (this.seen.has(key)) {
      // An expired entry can no longer be replayed (the presentation itself is
      // refused as expired before it gets here), but keep the answer exact.
      if (this.seen.get(key)! >= nowMs) return false;
      this.seen.delete(key);
    }
    if (this.seen.size >= this.maxEntries) return false;
    this.seen.set(key, expiresAtMs);
    return true;
  }

  /** Number of live entries (for tests and metrics). */
  get size(): number {
    return this.seen.size;
  }

  private prune(nowMs: number): void {
    for (const [k, exp] of this.seen) if (exp < nowMs) this.seen.delete(k);
  }
}

// ─── Normalisation ───────────────────────────────────────────────────────────

/**
 * The request target the proof covers: the path and query of the request
 * exactly as sent on the wire (origin-form, RFC 9112 §3.2.1), with no
 * decoding and no re-encoding.
 *
 *   - "https://api.example.com/v1/pay?x=1#frag" → "/v1/pay?x=1"
 *   - "https://api.example.com"                 → "/"
 *   - "https://api.example.com?x=1"             → "/?x=1"
 *   - "/v1/pay?x=1"                             → "/v1/pay?x=1"   (origin-form, as a server sees req.url)
 *
 * Refused (throws): anything that is not http(s) absolute-form or
 * origin-form; characters outside RFC 3986's unreserved / reserved / "%"
 * set (a client would percent-encode them, so the signed bytes would not be
 * the sent bytes); a "%" not followed by two hex digits; "." or ".."
 * path segments, in any percent-encoded spelling (a client or proxy would
 * collapse them).
 */
export function httpRequestTarget(url: string): string {
  if (typeof url !== "string" || url.length === 0) throw new TypeError("URL must be a non-empty string");
  const hash = url.indexOf("#");
  const noFragment = hash === -1 ? url : url.slice(0, hash);
  let target: string;
  if (noFragment.startsWith("/") && !noFragment.startsWith("//")) {
    target = noFragment;
  } else {
    const m = ABSOLUTE_HTTP_RE.exec(noFragment);
    if (!m) throw new TypeError(`URL must be absolute http(s) or an origin-form path: ${url}`);
    const authority = m[0].slice(m[0].indexOf("//") + 2);
    if (authority.length === 0 || authority.includes("@")) throw new TypeError(`URL has no host, or carries user info: ${url}`);
    const rest = noFragment.slice(m[0].length);
    target = rest.length === 0 ? "/" : rest.startsWith("?") ? `/${rest}` : rest;
  }
  if (!TARGET_CHARS_RE.test(target)) {
    throw new TypeError(`URL target contains characters an HTTP client would re-encode; percent-encode them first: ${target}`);
  }
  if (/%(?![0-9A-Fa-f]{2})/.test(target)) throw new TypeError(`URL target has a malformed percent-escape: ${target}`);
  const q = target.indexOf("?");
  const path = q === -1 ? target : target.slice(0, q);
  for (const seg of path.split("/")) {
    if (/^(?:\.|%2e){1,2}$/i.test(seg)) throw new TypeError(`URL target has a "." or ".." segment: ${target}`);
  }
  return target;
}

/** HTTP method as signed: an RFC 9110 token, ASCII upper-cased. */
export function httpMethodForProof(method: string): string {
  if (typeof method !== "string" || !METHOD_RE.test(method)) throw new TypeError(`Invalid HTTP method: ${String(method)}`);
  return method.replace(/[a-z]/g, (c) => c.toUpperCase());
}

/** Lower-case hex SHA-256 of the exact body bytes (null / undefined / "" = the empty body). */
export function httpBodySha256(body: HttpRequestBody): string {
  return Buffer.from(sha256(bodyBytes(body))).toString("hex");
}

function bodyBytes(body: HttpRequestBody): Uint8Array {
  if (body === null || body === undefined) return new Uint8Array(0);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  throw new TypeError("Request body must be a string, Uint8Array, ArrayBuffer, null or undefined (the raw bytes, not a parsed object)");
}

/**
 * The exact string the proof signs: JCS of the nine fields. Exported so other
 * SDKs' tests (and test-vectors/http-presentation-v1.json) can pin it.
 */
export function httpPresentationSigningPayload(fields: {
  audience: string;
  method: string;
  target: string;
  bodySha256: string;
  mandateId: string;
  holder: string;
  nonce: string;
  expires: string;
}): string {
  return canonicalizeJcs({
    purpose: HTTP_MANDATE_PRESENTATION_PURPOSE,
    audience: fields.audience,
    method: fields.method,
    target: fields.target,
    bodySha256: fields.bodySha256,
    mandateId: fields.mandateId,
    holder: fields.holder,
    nonce: fields.nonce,
    expires: fields.expires,
  });
}

/** Leaf mandateId and grantee of a token, spending or task. Null when undecodable. */
function tokenLeaf(token: string): { mandateId: string; grantee: string } | null {
  if (!BASE64URL_RE.test(token)) return null;
  try {
    const raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as { mandate?: { mandateId?: unknown; grantee?: unknown } };
    const m = raw?.mandate;
    if (!m || typeof m !== "object" || Array.isArray(m)) return null;
    if (typeof m.mandateId !== "string" || m.mandateId.length === 0) return null;
    if (typeof m.grantee !== "string" || m.grantee.length === 0) return null;
    return { mandateId: m.mandateId, grantee: m.grantee };
  } catch {
    return null;
  }
}

function randomNonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Buffer.from(b).toString("base64url");
}

// ─── Client ──────────────────────────────────────────────────────────────────

export interface PresentMandateHttpInput {
  /** The mandate token whose grantee is `holderDid`. */
  token: string;
  /** Your DID — must be the token's leaf grantee. */
  holderDid: string;
  /** Your Ed25519 private key (32 bytes). */
  holderPrivateKey: Uint8Array;
  /** The server's identifier, exactly as the server configures `audience` (its DID or its origin). */
  audience: string;
  method: string;
  /** The URL you will send, already percent-encoded (see httpRequestTarget). */
  url: string;
  /** The exact body bytes you will send. Omit for an empty body. */
  body?: HttpRequestBody;
  /** Presentation lifetime, default 60 s, capped at 5 min. */
  ttlMs?: number;
  /** Override the random nonce (test vectors only). */
  nonce?: string;
  /** Override "now" in Unix ms (test vectors only). */
  now?: number;
}

/**
 * Build the header that presents `token` for exactly one HTTP request.
 * Returns `{ "Aroha-Mandate": value }` to merge into the request headers.
 * Sign the bytes you send: if a client library re-serialises the body or
 * rewrites the URL afterwards, the server will refuse the request.
 */
export async function presentMandateHttp(input: PresentMandateHttpInput): Promise<{ [HTTP_MANDATE_HEADER]: string }> {
  for (const k of ["token", "holderDid", "audience"] as const) {
    if (typeof input[k] !== "string" || input[k].length === 0) throw new TypeError(`presentMandateHttp: ${k} is required`);
  }
  if (!(input.holderPrivateKey instanceof Uint8Array) || input.holderPrivateKey.length !== 32) {
    throw new TypeError("presentMandateHttp: holderPrivateKey must be a 32-byte Ed25519 private key");
  }
  const leaf = tokenLeaf(input.token);
  if (!leaf) throw new TypeError("presentMandateHttp: token is not a mandate token");
  if (leaf.grantee !== input.holderDid) {
    throw new TypeError(`presentMandateHttp: the token's grantee is ${leaf.grantee}, not ${input.holderDid}`);
  }
  const method = httpMethodForProof(input.method);
  const target = httpRequestTarget(input.url);
  // An http(s) client sends what the WHATWG URL parser makes of the string;
  // refuse rather than sign bytes that will not be the bytes sent.
  if (!input.url.startsWith("/")) {
    const u = new URL(input.url);
    const sent = u.href.slice(u.origin.length).split("#")[0];
    if ((sent.length === 0 ? "/" : sent) !== target) {
      throw new TypeError(`presentMandateHttp: an HTTP client would send ${sent} for ${input.url}; pass the normalised URL`);
    }
  }
  const ttl = input.ttlMs ?? DEFAULT_TTL_MS;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0) throw new TypeError("presentMandateHttp: ttlMs must be a positive number");
  const nonce = input.nonce ?? randomNonce();
  if (!NONCE_RE.test(nonce)) throw new TypeError("presentMandateHttp: nonce must be 16-128 base64url characters");
  const now = input.now ?? Date.now();
  const expires = new Date(now + Math.min(ttl, HTTP_PRESENTATION_MAX_TTL_MS)).toISOString();

  const payload = httpPresentationSigningPayload({
    audience: input.audience, method, target, bodySha256: httpBodySha256(input.body),
    mandateId: leaf.mandateId, holder: input.holderDid, nonce, expires,
  });
  const proof = Buffer.from(await ed.signAsync(new TextEncoder().encode(payload), input.holderPrivateKey)).toString("base64url");
  const value = Buffer.from(canonicalizeJcs({ token: input.token, holder: input.holderDid, nonce, expires, proof }), "utf8").toString("base64url");
  return { [HTTP_MANDATE_HEADER]: value };
}

// ─── Server ──────────────────────────────────────────────────────────────────

export interface VerifyHttpPresentationOptions {
  /** This server's identifier — the value clients put in `audience`. */
  audience: string;
  /** The request method as received. */
  method: string;
  /** The request URL as received: origin-form `req.url` (Node), or the full URL (fetch Request.url). */
  url: string;
  /** The raw body bytes as received, BEFORE any JSON parsing. */
  body: HttpRequestBody;
  /** Single-use nonce memory. */
  nonces: HttpPresentationNonceStore;
  /** Holder DID → Ed25519 key. Default: content-addressed `did:aroha:z…` DIDs only. */
  resolvePublicKey?: MandateKeyResolver;
  /**
   * Override "now" (Unix ms). One clock governs everything: the presentation's
   * expiry, the nonce store's expiry, and — in verifyHttpMandateRequest and
   * verifyHttpSpendRequest — every mandate's validity window. Tests can
   * therefore exercise mandate expiry without sleeping.
   */
  now?: number;
}

const fail = (code: HttpPresentationFailureCode, reason: string): HttpPresentationResult => ({ ok: false, code, reason });

/**
 * Check every part of the presentation except the nonce, then run `gate`
 * (further checks that must pass before the nonce is consumed), then claim
 * the nonce last — so a request that fails for any reason does not burn it.
 */
async function checkPresentation(
  headerValue: unknown,
  opts: VerifyHttpPresentationOptions,
  gate?: (p: { holder: string; token: string; mandateId: string }) => Promise<HttpPresentationResult | null>,
): Promise<HttpPresentationResult> {
  if (typeof opts?.audience !== "string" || opts.audience.length === 0) throw new TypeError("verifyHttpPresentation: audience is required");
  if (!opts.nonces || typeof opts.nonces.claim !== "function") throw new TypeError("verifyHttpPresentation: a nonce store is required");

  if (headerValue === undefined || headerValue === null || headerValue === "") {
    return fail("MISSING", `No mandate presented (${HTTP_MANDATE_HEADER} header missing)`);
  }
  if (typeof headerValue !== "string") return fail("MALFORMED", `${HTTP_MANDATE_HEADER} must be a single header value`);
  if (headerValue.length > HTTP_PRESENTATION_MAX_HEADER_LENGTH) return fail("MALFORMED", `${HTTP_MANDATE_HEADER} is too long`);
  if (!BASE64URL_RE.test(headerValue)) return fail("MALFORMED", `${HTTP_MANDATE_HEADER} is not base64url`);

  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(headerValue, "base64url").toString("utf8"));
  } catch {
    return fail("MALFORMED", `${HTTP_MANDATE_HEADER} is not JSON`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return fail("MALFORMED", "Mandate presentation is not an object");
  const keys = Object.keys(raw).sort();
  if (keys.length !== PRESENTATION_KEYS.length || keys.some((k, i) => k !== PRESENTATION_KEYS[i])) {
    return fail("MALFORMED", `Mandate presentation must have exactly the members ${PRESENTATION_KEYS.join(", ")}`);
  }
  const p = raw as Record<string, unknown>;
  for (const k of PRESENTATION_KEYS) {
    if (typeof p[k] !== "string" || (p[k] as string).length === 0) return fail("MALFORMED", `Mandate presentation ${k} must be a non-empty string`);
  }
  const { token, holder, nonce, expires, proof } = p as unknown as HttpMandatePresentation;
  if (!NONCE_RE.test(nonce)) return fail("MALFORMED", "Mandate presentation nonce must be 16-128 base64url characters");
  const expiresMs = Date.parse(expires);
  if (!EXPIRES_RE.test(expires) || Number.isNaN(expiresMs) || new Date(expiresMs).toISOString() !== expires) {
    return fail("MALFORMED", "Mandate presentation expires must be an ISO 8601 UTC instant (YYYY-MM-DDTHH:mm:ss.sssZ)");
  }

  const now = opts.now ?? Date.now();
  if (expiresMs <= now) return fail("EXPIRED", "Mandate presentation expired");
  if (expiresMs - now > HTTP_PRESENTATION_MAX_TTL_MS + HTTP_PRESENTATION_CLOCK_SKEW_MS) {
    return fail("LIFETIME_TOO_LONG", "Mandate presentation lifetime too long (maximum 5 minutes)");
  }

  const leaf = tokenLeaf(token);
  if (!leaf) return fail("MALFORMED_TOKEN", "Malformed mandate token");
  if (leaf.grantee !== holder) return fail("HOLDER_NOT_GRANTEE", `Presenter ${holder} is not the mandate's grantee`);

  let method: string, target: string, bodySha256: string;
  try {
    method = httpMethodForProof(opts.method);
    target = httpRequestTarget(opts.url);
    bodySha256 = httpBodySha256(opts.body);
  } catch (e) {
    return fail("BAD_REQUEST", `Cannot normalise the request: ${(e as Error).message}`);
  }

  let key: Uint8Array | null;
  try {
    key = await (opts.resolvePublicKey ?? resolveContentAddressedKey)(holder);
  } catch {
    key = null;
  }
  if (!(key instanceof Uint8Array) || key.length !== 32) return fail("UNKNOWN_HOLDER", `Cannot resolve public key for holder ${holder}`);

  let valid = false;
  try {
    const sig = BASE64URL_RE.test(proof) ? new Uint8Array(Buffer.from(proof, "base64url")) : new Uint8Array(0);
    valid = sig.length === 64 && await ed.verifyAsync(sig, new TextEncoder().encode(httpPresentationSigningPayload({
      audience: opts.audience, method, target, bodySha256, mandateId: leaf.mandateId, holder, nonce, expires,
    })), key);
  } catch {
    valid = false;
  }
  if (!valid) return fail("BAD_PROOF", "Mandate presentation proof does not verify for this server, method, target and body");

  if (gate) {
    const refused = await gate({ holder, token, mandateId: leaf.mandateId });
    if (refused) return refused;
  }

  // Last: only a request that is otherwise fully valid consumes its nonce.
  let fresh: boolean;
  try {
    fresh = (await opts.nonces.claim(`${holder} ${nonce}`, expiresMs, now)) === true;
  } catch {
    return fail("NONCE_STORE_UNAVAILABLE", "Nonce store unavailable");
  }
  if (!fresh) return fail("REPLAYED", "Mandate presentation already used");
  return { ok: true, holder, token, mandateId: leaf.mandateId };
}

/**
 * Verify an `Aroha-Mandate` header for this request. On success returns the
 * holder DID and token; the holder has proven possession of its key for this
 * exact request and is the token's leaf grantee.
 *
 * Does NOT verify the mandate itself. Prefer verifyHttpMandateRequest(), which
 * does both; if you call this directly, verify the token next with
 * `expectedGrantee: result.holder` and a pinned root.
 */
export async function verifyHttpPresentation(
  headerValue: string | readonly string[] | null | undefined,
  options: VerifyHttpPresentationOptions,
): Promise<HttpPresentationResult> {
  return checkPresentation(headerValue, options);
}

export interface VerifyHttpMandateRequestOptions
  extends VerifyHttpPresentationOptions,
    Omit<VerifyMandateChainOptions, "expectedGrantee" | "isRevoked" | "now" | "expectedRoot" | "trustedRoots"> {
  /**
   * The one root grantor (normally the human's DID) the chain must start at.
   * Supply this or `trustedRoots`; supplying neither throws. A supplied but
   * empty value (undefined, null, "") — such as an enrollment lookup for an
   * account with no enrolled DID — refuses the request with ROOT_NOT_PINNED
   * (403) instead of throwing, and does not consume the nonce.
   */
  expectedRoot?: string | null;
  /** Accept any of these root grantors. Supplied but empty (undefined, null, []) refuses with ROOT_NOT_PINNED. */
  trustedRoots?: readonly string[] | null;
  /**
   * Revocation hook for every link of the chain. REQUIRED: pass `null` to
   * state explicitly that this server does not check revocation (a revoked
   * mandate is then honoured until it expires). The explicit `null` prints no
   * warning; the result reports it as `revocationChecked: false`.
   */
  isRevoked: MandateRevocationCheck | null;
  /** Resolver for the chain's grantor keys. Default: content-addressed DIDs (and kelSource for E-DIDs). */
  resolveKey?: MandateKeyResolver;
}

/**
 * The root pin of a request, or null when the pin options were supplied but
 * are all empty (a refusal, ROOT_NOT_PINNED). Throws for a misconfiguration:
 * neither option supplied at all, or a value of the wrong type.
 *
 *   expectedRoot: a non-empty string pins; undefined / null / "" is empty.
 *   trustedRoots: a non-empty array of non-empty strings pins; undefined /
 *                 null / [] is empty; anything else (a non-array, an entry
 *                 that is not a non-empty string) throws.
 *
 * When both are given, every non-empty one applies (the chain must satisfy
 * both); an empty one is ignored if the other pins.
 */
function rootPin(options: { expectedRoot?: unknown; trustedRoots?: unknown } | undefined):
  { expectedRoot?: string; trustedRoots?: string[] } | null {
  if (!options || typeof options !== "object") throw new TypeError("verifyHttpMandateRequest: options are required");
  const hasExpectedKey = "expectedRoot" in options;
  const hasTrustedKey = "trustedRoots" in options;
  if (!hasExpectedKey && !hasTrustedKey) {
    throw new TypeError("verifyHttpMandateRequest: pin the root you trust with expectedRoot or trustedRoots");
  }
  const { expectedRoot: er, trustedRoots: tr } = options;
  if (er !== undefined && er !== null && typeof er !== "string") {
    throw new TypeError("verifyHttpMandateRequest: expectedRoot must be a DID string");
  }
  if (tr !== undefined && tr !== null
    && (!Array.isArray(tr) || !tr.every((r) => typeof r === "string" && r.length > 0))) {
    throw new TypeError("verifyHttpMandateRequest: trustedRoots must be a list of DIDs");
  }
  const pin: { expectedRoot?: string; trustedRoots?: string[] } = {};
  if (typeof er === "string" && er.length > 0) pin.expectedRoot = er;
  if (Array.isArray(tr) && tr.length > 0) pin.trustedRoots = [...(tr as string[])];
  return pin.expectedRoot !== undefined || pin.trustedRoots !== undefined ? pin : null;
}

export type HttpMandateRequestResult =
  | {
      ok: true;
      holder: string;
      token: string;
      /** The verified leaf mandate — read its constraints before acting. */
      mandate: ArohaSpendingMandateBody;
      /** The verified chain, root first, including the leaf. */
      chain: ArohaSpendingMandateBody[];
      rootGrantor: string;
      /**
       * False when the server passed `isRevoked: null`: no link was checked
       * for revocation, so a revoked mandate is honoured until it expires.
       */
      revocationChecked: boolean;
    }
  | {
      ok: false;
      /**
       * ROOT_NOT_PINNED: the pin option was supplied but is empty (see
       * verifyHttpMandateRequest) — e.g. an account with no enrolled DID.
       */
      code: HttpPresentationFailureCode | "MANDATE_INVALID" | "ROOT_NOT_PINNED";
      reason: string;
      /** Suggested HTTP status: 401 for a missing or bad presentation, 403 for a mandate that does not authorise (or no pinned root). */
      status: 401 | 403;
    };

/**
 * The one call a REST server needs: verify the holder's presentation for this
 * request AND verify the spending mandate chain back to a root you trust,
 * with the presenter as the required grantee. The nonce is consumed only
 * when both pass.
 *
 * You must pin the root: `expectedRoot` (one DID) or `trustedRoots`
 * (a list). Without a pinned root, anyone can mint a valid chain of their
 * own; when neither option is supplied this function throws instead of
 * running that weaker check. When the option is supplied but its value is
 * empty — `enrolledDid(store, customerId)` for a customer who never enrolled —
 * the request is refused with ROOT_NOT_PINNED (403), not thrown, and its
 * nonce is not consumed. You must also pass `isRevoked` (a hook, or `null`
 * to opt out explicitly).
 *
 * `now` (one injectable clock) governs the presentation expiry, the nonce
 * expiry and every mandate's validity window.
 *
 * For task mandates, call verifyHttpPresentation() and then the task-mandate
 * verifier with `expectedGrantee: holder`.
 */
export async function verifyHttpMandateRequest(
  headerValue: string | readonly string[] | null | undefined,
  options: VerifyHttpMandateRequestOptions,
): Promise<HttpMandateRequestResult> {
  const pinned = rootPin(options);
  if (!("isRevoked" in options) || (options.isRevoked !== null && typeof options.isRevoked !== "function")) {
    throw new TypeError("verifyHttpMandateRequest: isRevoked is required (a revocation hook, or null to opt out explicitly)");
  }

  const { audience, method, url, body, nonces, resolvePublicKey, now, isRevoked, resolveKey, expectedRoot, trustedRoots, ...chainOptions } = options;
  const holderResolver = resolvePublicKey ?? (options.kelSource
    ? createMandateKeyResolver({ kelSource: options.kelSource, kelStore: options.kelStore })
    : resolveContentAddressedKey);

  let verified: { mandate: ArohaSpendingMandateBody; chain: ArohaSpendingMandateBody[]; rootGrantor: string } | null = null;
  const result = await checkPresentation(headerValue, { audience, method, url, body, nonces, resolvePublicKey: holderResolver, now }, async ({ holder, token }) => {
    // An empty pin (say, an account with no enrolled DID) is a refusal,
    // decided here: after the presentation checks, so a bad presentation still
    // reads 401, and before the nonce is claimed, so the nonce is not used up.
    if (!pinned) {
      return {
        ok: false, code: "ROOT_NOT_PINNED" as HttpPresentationFailureCode,
        reason: "No trusted root for this request: expectedRoot / trustedRoots is empty (no enrolled DID for this account?)",
      };
    }
    const r = await verifyMandateChain(token, resolveKey ?? resolveContentAddressedKey, {
      ...chainOptions,
      ...(pinned.expectedRoot !== undefined ? { expectedRoot: pinned.expectedRoot } : {}),
      ...(pinned.trustedRoots !== undefined ? { trustedRoots: pinned.trustedRoots } : {}),
      // Passed through as given: null is the explicit opt-out, which
      // verifyMandateChain honours without printing its missing-hook warning.
      isRevoked,
      now,
      expectedGrantee: holder,
    });
    if (!r.valid || !r.chainVerified || !r.mandate || !r.chain || !r.rootGrantor) {
      return { ok: false, code: "MANDATE_INVALID" as HttpPresentationFailureCode, reason: `Mandate invalid: ${r.reason ?? "chain not verified"}` };
    }
    verified = { mandate: r.mandate, chain: r.chain, rootGrantor: r.rootGrantor };
    return null;
  });
  if (!result.ok) {
    const code = result.code as HttpPresentationFailureCode | "MANDATE_INVALID" | "ROOT_NOT_PINNED";
    return { ok: false, code, reason: result.reason, status: code === "MANDATE_INVALID" || code === "ROOT_NOT_PINNED" ? 403 : 401 };
  }
  const v = verified as unknown as { mandate: ArohaSpendingMandateBody; chain: ArohaSpendingMandateBody[]; rootGrantor: string };
  return {
    ok: true, holder: result.holder, token: result.token, mandate: v.mandate, chain: v.chain, rootGrantor: v.rootGrantor,
    revocationChecked: typeof isRevoked === "function",
  };
}
