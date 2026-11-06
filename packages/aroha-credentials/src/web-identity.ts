// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Web identities — naming a mandate's grantor, grantee or holder with an
 * HTTPS URL instead of a `did:aroha:` identifier (spec §4.7).
 *
 * WHY. A mandate says "this key may do that, within these limits". How the
 * key's owner is NAMED is a separate question. `did:aroha:` identifiers
 * answer it without any lookup (the identifier commits to the key), which is
 * their strength, but a verifier has to learn a new identifier scheme to use
 * them. Most agent platforms already name an agent by an HTTPS URL that
 * serves a small JSON document with the agent's public keys — the OAuth
 * Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document).
 * A web identity is exactly that URL, so an agent that already publishes one
 * can sign and hold mandates under the name it already has.
 *
 * WHAT IT IS NOT. The OAuth draft defines the document for OAuth clients; it
 * says nothing about mandates. Reusing the document as an Aroha identity is
 * this profile's choice. No OAuth flow runs here: the verifier fetches the
 * document, reads the key, and checks the mandate signature with it.
 *
 * TRUST MODEL — different from did:aroha, on purpose and worth knowing:
 *   - A `did:aroha:z…` / `E…` identifier is self-certifying: the verifier
 *     needs no network and trusts no third party to learn the key.
 *   - A web identity is as trustworthy as HTTPS to that origin: whoever
 *     controls the host, its DNS or a certificate for it can publish a key.
 *     The key is the one published at VERIFICATION time, so replacing it stops
 *     outstanding mandates verifying (the same rule as an E-form rotation).
 *   - The governed profile (§6.8) still requires a `did:aroha:E…` person
 *     root. A web identity cannot be a governed root.
 *
 * The token format does not change. Only the resolver does: pass
 * `createMandateKeyResolver({ web: true })` (or the resolver made here) where
 * a key resolver is accepted.
 *
 * FETCH RULES (from the OAuth draft, §"Client ID Metadata Document" and its
 * security considerations, applied here to both the document and a
 * `jwks_uri`): HTTPS only, no redirects followed, HTTP 200 only, a size cap,
 * a timeout, successful results cached for a bounded time, failures
 * remembered for 30 seconds at most. Before each request the host name is resolved and the request is
 * refused if any of its addresses is special-use (loopback, private,
 * link-local, …) — on Node.js by default, elsewhere when the caller supplies
 * `lookup`. That check does not pin the connection, and a Cloudflare Worker
 * or browser has no resolver to ask; see `refusal()` for exactly what is and
 * is not covered, and use `allowHost`, a pinning `fetch` or an egress policy
 * where it matters.
 *
 * This module imports only @noble/hashes, so it is exported from the
 * Worker-safe `@aroha-sdk/credentials/mandates` entry too.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { isWeakEd25519Key } from "./ed25519-strict.js";
import type { MandateKeyResolver } from "./mandate.js";

// ─── Identifier ───────────────────────────────────────────────────────────────

/** Longest web identity accepted, in characters. */
export const WEB_IDENTITY_MAX_LENGTH = 2048;

export interface WebIdentityCheckOptions {
  /**
   * Also accept `http://localhost[:port]/…` and `http://127.0.0.1[:port]/…`.
   * For local development only: such an identity proves nothing to anyone
   * else, and the OAuth draft forbids the loopback exception in production.
   */
  allowLoopbackHttp?: boolean;
}

/** True for anything a web-identity resolver should claim: an http(s) URL string. */
export function looksLikeWebIdentity(id: unknown): id is string {
  return typeof id === "string" && (id.startsWith("https://") || id.startsWith("http://"));
}

/*
 * The grammar (spec §4.7). It is written out, not left to a URL parser,
 * because identifiers are compared as plain strings and every SDK must agree
 * on which strings are identifiers. Only one spelling of a URL is accepted.
 *
 *   identity = "https://" host [ ":" port ] path
 *   host     = label 1*( "." label )         ; lower case, the last label a TLD
 *   label    = 1–63 of a-z 0-9 "-", not starting or ending with "-"
 *   tld      = 2–63 letters a-z, or an "xn--" label; never "localhost"
 *   xn--     = a valid A-label: decoding and re-encoding gives the same label
 *   port     = 1–65535 without leading zeros, and not the scheme's default
 *   path     = 1*( "/" segment ) [ "/" ]     ; so never just "/"
 *   segment  = 1*( unreserved / sub-delims / ":" / "@" / "%" HEX HEX )
 *              and not "." or "..", also when a dot is written "%2e"
 */
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const TLD = "(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})";
const HOST = `(?:${LABEL}\\.)+${TLD}`;
const PCHAR = "(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})";
const URL_RE = new RegExp(`^(https|http)://(${HOST}|localhost|127\\.0\\.0\\.1)(?::([1-9][0-9]{0,4}))?((?:/${PCHAR}+)*/?)(\\?(?:${PCHAR}|[/?])*)?$`);

interface UrlRules {
  loopbackHttp: boolean;
  /** A web identity needs a path other than "/" and no query; a jwks_uri needs neither. */
  identity: boolean;
}

function checkUrl(value: unknown, rules: UrlRules): string | null {
  if (typeof value !== "string" || value.length === 0) return "is not a string";
  if (value.length > WEB_IDENTITY_MAX_LENGTH) return `is longer than ${WEB_IDENTITY_MAX_LENGTH} characters`;
  if (!value.startsWith("https://") && !(rules.loopbackHttp && value.startsWith("http://"))) return "must use the https scheme";
  if (value.includes("#")) return "must not contain a fragment";
  if (/^https?:\/\/[^/?]*@/.test(value)) return "must not contain user information";
  const m = URL_RE.exec(value);
  if (!m) return "is not a URL in the accepted form";
  const [, scheme, host, port, path, query] = m;
  const loopback = host === "localhost" || host === "127.0.0.1";
  // An IP literal never matches HOST: an IP has no name to anchor trust in,
  // and accepting one turns the resolver into a fetcher of arbitrary
  // addresses. The two loopback names are for development only.
  if (loopback !== (scheme === "http")) return loopback ? "loopback hosts are accepted over http only" : "must use the https scheme";
  if (loopback && !rules.loopbackHttp) return "must not name a loopback host";
  if (host.length > 253) return "host is too long";
  // RFC 6761: every name under "localhost" is loopback, whatever DNS says.
  if (host.endsWith(".localhost")) return "must not name a loopback host";
  if (port !== undefined && (Number(port) > 65535 || Number(port) === (scheme === "https" ? 443 : 80))) {
    return "port is out of range or is the default port, which must be omitted";
  }
  if (path === "") return "must have a path";
  for (const segment of path.split("/")) {
    const dots = segment.replace(/%2e/gi, ".");
    if (dots === "." || dots === "..") return "must not contain dot segments";
  }
  if (rules.identity && path === "/") return "must have a path other than /";
  if (rules.identity && query !== undefined) return "must not contain a query";
  // Belt and braces: the platform's URL parser must read the string the same
  // way the grammar does, or `fetch` would go somewhere the checks did not
  // look. Also rejects a malformed "xn--" label.
  try {
    if (new URL(value).href !== value) return "is not in normalised form";
  } catch {
    return "is not a URL";
  }
  return null;
}

/**
 * Why `id` is not a valid web identity, or null when it is one.
 *
 * Rules (the OAuth Client ID Metadata Document draft's, made stricter so
 * that one agent has exactly one name): the https scheme; a lower-case DNS
 * hostname ending in a top-level domain (no IP literal, no localhost); an
 * optional non-default port; a path other than "/" with no empty or dot
 * segments; no user information, fragment or query (the draft says a query
 * SHOULD NOT be present). See the grammar above.
 */
export function checkWebIdentity(id: unknown, options: WebIdentityCheckOptions = {}): string | null {
  const why = checkUrl(id, { loopbackHttp: options.allowLoopbackHttp === true, identity: true });
  return why ? `Web identity ${why}` : null;
}

/** True when `id` is a valid web identity (see checkWebIdentity). */
export function isWebIdentity(id: unknown, options: WebIdentityCheckOptions = {}): id is string {
  return checkWebIdentity(id, options) === null;
}

// ─── Keys ─────────────────────────────────────────────────────────────────────

/** An Ed25519 public key as a JSON Web Key (RFC 8037). */
export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url (no padding) of the 32-byte public key. */
  x: string;
  kid?: string;
  use?: "sig";
  alg?: "EdDSA";
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url) of an Ed25519 public key: the
 * hash of `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`. Used as the default
 * `kid`, so the same key always gets the same key id.
 */
export function ed25519JwkThumbprint(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new TypeError("An Ed25519 public key is 32 bytes");
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${b64u(publicKey)}"}`;
  return b64u(sha256(new TextEncoder().encode(canonical)));
}

/** Encode an Ed25519 public key as a signing JWK. `kid` defaults to its RFC 7638 thumbprint. */
export function ed25519PublicKeyToJwk(publicKey: Uint8Array, kid?: string): Ed25519Jwk {
  return { kty: "OKP", crv: "Ed25519", x: b64u(publicKey), kid: kid ?? ed25519JwkThumbprint(publicKey), use: "sig", alg: "EdDSA" };
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Members that carry private or symmetric key material in a JWK (RFC 7518 §6). */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/**
 * Decode a JWK to a raw Ed25519 public key, or null when it is not an
 * Ed25519 key usable for verifying signatures: `kty` "OKP", `crv` "Ed25519",
 * `x` exactly 32 bytes in canonical base64url, `use` absent or "sig",
 * `key_ops` absent or containing "verify", `alg` absent or "EdDSA" / "Ed25519".
 */
export function jwkToEd25519PublicKey(jwk: unknown): Uint8Array | null {
  if (!isRecord(jwk)) return null;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  if (jwk.use !== undefined && jwk.use !== "sig") return null;
  if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes("verify"))) return null;
  if (jwk.alg !== undefined && jwk.alg !== "EdDSA" && jwk.alg !== "Ed25519") return null;
  if (!/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) return null;
  const key = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  // Round-trip: 43 base64url characters can spell 32 bytes more than one way
  // (the last character carries two unused bits). Only the canonical spelling
  // is a key, so two documents never name one key by different strings.
  return key.length === 32 && b64u(key) === jwk.x && !isWeakEd25519Key(key) ? key : null;
}

export type WebIdentityKeySelection =
  | { ok: true; key: Uint8Array; kid?: string }
  | { ok: false; reason: string };

/**
 * Choose the signing key from a JWK Set: the FIRST key that
 * jwkToEd25519PublicKey accepts.
 *
 * WHY the first and not "any": a native mandate token carries no key id, the
 * JWT form's `kid` must not choose the key (spec §6.10), and the resolver
 * contract returns one key. One rule that every implementation
 * applies the same way matters more than flexibility. To rotate, publish the
 * new key first; mandates signed by the old key then stop verifying and are
 * re-issued, which is the rule a `did:aroha:E…` rotation already follows.
 *
 * A set that contains ANY private or symmetric key material is refused
 * outright: the document is public, so that key is burnt, and a publisher
 * that leaks one key cannot be assumed to have kept the others.
 */
export function selectWebIdentityKey(jwks: unknown): WebIdentityKeySelection {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) return { ok: false, reason: "key set has no keys array" };
  for (const k of jwks.keys) {
    if (isRecord(k) && PRIVATE_JWK_MEMBERS.some((m) => m in k)) {
      return { ok: false, reason: "key set contains private key material" };
    }
  }
  for (const k of jwks.keys) {
    const key = jwkToEd25519PublicKey(k);
    if (key) return { ok: true, key, ...(typeof (k as Record<string, unknown>).kid === "string" ? { kid: (k as Record<string, unknown>).kid as string } : {}) };
  }
  return { ok: false, reason: "key set has no Ed25519 signing key" };
}

// ─── Document ─────────────────────────────────────────────────────────────────

/** The members of a Client ID Metadata Document this profile reads. Others are ignored. */
export interface WebIdentityDocument {
  /** MUST equal the URL the document is served from, compared as a plain string. */
  client_id: string;
  client_name?: string;
  client_uri?: string;
  /** Inline key set. Exactly one of `jwks` and `jwks_uri` must be present. */
  jwks?: { keys: unknown[] };
  /** HTTPS URL of the key set. */
  jwks_uri?: string;
  [member: string]: unknown;
}

export interface BuildWebIdentityDocumentInput {
  /** The web identity: the HTTPS URL this document will be served from. */
  identity: string;
  /** The Ed25519 public key (32 bytes) the identity signs mandates with. */
  publicKey: Uint8Array;
  /** Key id. Default: the key's RFC 7638 thumbprint. */
  kid?: string;
  /** Human-readable name (OAuth `client_name`). */
  name?: string;
  /** Home page (OAuth `client_uri`). */
  uri?: string;
  /**
   * Further members to publish, e.g. the OAuth client metadata an agent that
   * also signs in with this URL needs. May not override `client_id` or the
   * key members, and may not carry a client secret.
   */
  extra?: Record<string, unknown>;
  /** Accept an `http://localhost` identity (development only). */
  allowLoopbackHttp?: boolean;
}

const RESERVED_DOCUMENT_MEMBERS = ["client_id", "jwks", "jwks_uri", "client_secret", "client_secret_expires_at"] as const;

/**
 * Build the JSON document to serve at a web identity's URL (as
 * `application/json`, HTTP 200, no redirect). Throws on an invalid identity
 * or key, so a document that no verifier would accept is never produced.
 */
export function buildWebIdentityDocument(input: BuildWebIdentityDocumentInput): WebIdentityDocument {
  const why = checkWebIdentity(input.identity, { allowLoopbackHttp: input.allowLoopbackHttp });
  if (why) throw new Error(why);
  for (const m of RESERVED_DOCUMENT_MEMBERS) {
    if (input.extra && m in input.extra) throw new Error(`buildWebIdentityDocument: extra must not set ${m}`);
  }
  return {
    ...(input.extra ?? {}),
    client_id: input.identity,
    ...(input.name !== undefined ? { client_name: input.name } : {}),
    ...(input.uri !== undefined ? { client_uri: input.uri } : {}),
    jwks: { keys: [ed25519PublicKeyToJwk(input.publicKey, input.kid)] },
  };
}

// ─── Resolution ───────────────────────────────────────────────────────────────

/** Default size cap for the identity document: the OAuth draft's recommended 5 kilobytes. */
export const WEB_IDENTITY_MAX_DOCUMENT_BYTES = 5 * 1024;
/** Default size cap for a key set fetched from `jwks_uri`. */
export const WEB_IDENTITY_MAX_JWKS_BYTES = 16 * 1024;
/** Default (and longest default) time a resolved key is reused: 5 minutes. */
export const WEB_IDENTITY_MAX_CACHE_MS = 5 * 60_000;
/** Default timeout for each HTTPS request. */
export const WEB_IDENTITY_FETCH_TIMEOUT_MS = 5_000;
/** Default time a failed resolution is remembered: 30 seconds. */
export const WEB_IDENTITY_FAILURE_CACHE_MS = 30_000;
const CACHE_MAX_ENTRIES = 500;

export interface WebIdentityResolverOptions extends WebIdentityCheckOptions {
  /** Replaces the global `fetch` (tests, runtimes with their own client). */
  fetch?: typeof fetch;
  /** Timeout for each request, ms. Default 5 000. */
  timeoutMs?: number;
  /** Size cap for the identity document, bytes. Default 5 120. */
  maxDocumentBytes?: number;
  /** Size cap for a `jwks_uri` response, bytes. Default 16 384. */
  maxJwksBytes?: number;
  /**
   * Longest time a successfully resolved key is reused, ms. A shorter
   * `Cache-Control: max-age` on the document is honoured; `no-store` and
   * `no-cache` disable reuse. 0 disables the cache. Default 300 000.
   *
   * This is also how long a key removed from the document keeps verifying.
   */
  maxCacheMs?: number;
  /**
   * Decide whether a host may be fetched. Called with the lower-case hostname
   * of the identity and of any `jwks_uri` before each request; return false
   * to refuse. Use it to pin the identities a verifier accepts, or to keep a
   * verifier that can reach internal services away from them.
   */
  allowHost?: (hostname: string) => boolean;
  /**
   * Resolve a host name to its addresses, so a request to a special-use
   * address (loopback, private, link-local, …; see isSpecialUseAddress) can be
   * refused before it is made. Default: the platform resolver on Node.js when
   * the global `fetch` makes the request; none when `fetch` is replaced or
   * the runtime has no resolver. `false` turns the check off, for a verifier
   * whose network already denies those ranges.
   */
  lookup?: WebIdentityAddressLookup | false;
  /**
   * How long a failed resolution is remembered, ms, so a token naming a dead or
   * slow host cannot force a request per verification. Default 30 000, never
   * more than `maxCacheMs`.
   */
  failureCacheMs?: number;
  /** Most requests in flight to one host at a time; more are refused. Default 8. */
  maxConcurrentPerHost?: number;
  /** Told why a resolution failed (the resolver itself only returns null). Never told keys. */
  onFailure?: (identity: string, reason: string) => void;
  /** Override "now" (Unix ms) for cache expiry. For tests. */
  now?: () => number;
}

export type WebIdentityResolution =
  | { ok: true; key: Uint8Array; kid?: string; document: WebIdentityDocument }
  | { ok: false; reason: string };

interface CacheEntry {
  expires: number;
  value: Extract<WebIdentityResolution, { ok: true }>;
}

/**
 * Read a response body as UTF-8, refusing anything over `maxBytes`. Streams
 * when the runtime exposes a body stream so an oversized response is dropped
 * without being buffered.
 */
async function readCapped(res: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(res.headers?.get?.("content-length") ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return new TextEncoder().encode(text).length > maxBytes ? null : text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(all);
}

type FetchedJson = { ok: true; json: unknown; cacheControl: string | null } | { ok: false; reason: string };

async function fetchJson(url: string, maxBytes: number, options: WebIdentityResolverOptions): Promise<FetchedJson> {
  const doFetch = options.fetch ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? WEB_IDENTITY_FETCH_TIMEOUT_MS);
  try {
    // redirect: "manual" — a 3xx comes back as itself and fails the 200
    // check below. The document must come from the URL the identity names;
    // following a redirect would let that host point the verifier anywhere.
    const res = await doFetch(url, { method: "GET", headers: { accept: "application/json" }, redirect: "manual", signal: ctrl.signal });
    if (res.redirected === true || res.status !== 200) return { ok: false, reason: `GET ${url} did not return HTTP 200` };
    let text: string | null;
    try {
      text = await readCapped(res, maxBytes);
    } catch {
      return { ok: false, reason: `GET ${url} returned a body that is not UTF-8` };
    }
    if (text === null) return { ok: false, reason: `GET ${url} returned more than ${maxBytes} bytes` };
    try {
      return { ok: true, json: JSON.parse(text) as unknown, cacheControl: res.headers?.get?.("cache-control") ?? null };
    } catch {
      return { ok: false, reason: `GET ${url} did not return JSON` };
    }
  } catch {
    return { ok: false, reason: `GET ${url} failed` };
  } finally {
    clearTimeout(timer);
  }
}

/** How long a response may be reused, ms, from its Cache-Control header and the configured ceiling. */
function cacheLifetime(cacheControl: string | null, ceilingMs: number): number {
  if (ceilingMs <= 0) return 0;
  if (!cacheControl) return ceilingMs;
  const directives = cacheControl.toLowerCase().split(",").map((d) => d.trim());
  if (directives.includes("no-store") || directives.includes("no-cache")) return 0;
  const maxAge = directives.map((d) => /^max-age=(\d+)$/.exec(d)).find((m) => m !== null);
  return maxAge ? Math.min(ceilingMs, Number(maxAge[1]) * 1000) : ceilingMs;
}

// ─── Address check ────────────────────────────────────────────────────────────

/** Parse a dotted-quad IPv4 address to its four octets, or null. */
function parseIpv4(s: string): number[] | null {
  // No leading zeros: some resolvers read "010" as octal, so it is not one address.
  const m = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(s);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : null;
}

/** Parse an IPv6 address (any textual form, zone id ignored) to eight 16-bit groups, or null. */
function parseIpv6(input: string): number[] | null {
  let s = input.split("%")[0];
  if (s.includes(".")) {
    // An IPv4 tail ("::ffff:10.0.0.1") is two groups written in decimal.
    const lastColon = s.lastIndexOf(":");
    const v4 = lastColon < 0 ? null : parseIpv4(s.slice(lastColon + 1));
    if (!v4) return null;
    s = `${s.slice(0, lastColon + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !rest) return null;
  const known = head.length + rest.length;
  if (halves.length === 2 ? known > 7 : known !== 8) return null;
  return [...head, ...new Array<number>(8 - known).fill(0), ...rest];
}

function isSpecialUseIpv4(o: number[]): boolean {
  const [a, b, c] = o;
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||            // this network, private, loopback, multicast and reserved
    (a === 100 && b >= 64 && b <= 127) ||                      // shared address space (carrier-grade NAT)
    (a === 169 && b === 254) ||                                // link-local, including cloud metadata services
    (a === 172 && b >= 16 && b <= 31) ||                       // private
    (a === 192 && b === 168) ||                                // private
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||          // IETF protocol assignments, documentation
    (a === 192 && b === 88 && c === 99) ||                     // deprecated 6to4 relay anycast
    (a === 198 && (b === 18 || b === 19)) ||                   // benchmarking
    (a === 198 && b === 51 && c === 100) ||                    // documentation
    (a === 203 && b === 0 && c === 113)                        // documentation
  );
}

/**
 * True when `address` (an IPv4 or IPv6 address as text) is a special-use
 * address a verifier must not fetch from (RFC 6890 and its registry):
 * loopback, private, link-local, shared, documentation, benchmarking,
 * multicast, reserved and unspecified ranges, IPv6 unique-local and
 * transition ranges, and IPv4-mapped or NAT64 forms of a special-use IPv4
 * address. Anything that does not parse as an address is treated as
 * special-use, so an unexpected resolver answer is refused, not fetched.
 *
 * The same list is in every SDK and pinned by `addresses` in
 * test-vectors/web-identity-v1.json.
 */
export function isSpecialUseAddress(address: string): boolean {
  if (typeof address !== "string") return true;
  const v4 = parseIpv4(address);
  if (v4) return isSpecialUseIpv4(v4);
  const g = parseIpv6(address);
  if (!g) return true;
  const embedded = [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
  const zeroTo = (n: number) => g.slice(0, n).every((x) => x === 0);
  if (zeroTo(5) && g[5] === 0xffff) return isSpecialUseIpv4(embedded);                     // ::ffff:0:0/96, IPv4-mapped
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return isSpecialUseIpv4(embedded); // 64:ff9b::/96, NAT64
  return (
    zeroTo(6) ||                                   // ::/96: unspecified, loopback, deprecated IPv4-compatible
    (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) || // 64:ff9b:1::/48, local-use NAT64
    (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) || // 100::/64, discard only
    (g[0] === 0x2001 && g[1] < 0x200) ||           // 2001::/23, IETF protocol assignments (Teredo, ORCHID, …)
    (g[0] === 0x2001 && g[1] === 0xdb8) ||         // 2001:db8::/32, documentation
    g[0] === 0x2002 ||                             // 2002::/16, 6to4
    (g[0] & 0xfe00) === 0xfc00 ||                  // fc00::/7, unique local
    (g[0] & 0xffc0) === 0xfe80 ||                  // fe80::/10, link-local
    (g[0] & 0xffc0) === 0xfec0 ||                  // fec0::/10, deprecated site-local
    (zeroTo(4) && g[4] === 0xffff && g[5] === 0) || // ::ffff:0:0:0/96, IPv4-translated
    (g[0] === 0x3fff && g[1] < 0x1000) ||          // 3fff::/20, documentation
    g[0] === 0x5f00 ||                             // 5f00::/16, segment routing
    (g[0] & 0xff00) === 0xff00                     // ff00::/8, multicast
  );
}

/** Resolve a host name to every address it has. */
export type WebIdentityAddressLookup = (hostname: string) => Promise<string[]>;

let nodeLookup: WebIdentityAddressLookup | null | undefined;

/**
 * The platform's resolver, where there is one this module can reach: Node.js
 * (and runtimes that implement `node:dns`). Null elsewhere — a Cloudflare
 * Worker or a browser cannot see what a name resolves to.
 *
 * The module name is held in a variable so bundlers for those runtimes do
 * not try to resolve it; this file stays importable everywhere.
 */
async function platformLookup(): Promise<WebIdentityAddressLookup | null> {
  if (nodeLookup !== undefined) return nodeLookup;
  const g = globalThis as { process?: { versions?: { node?: string } }; navigator?: { userAgent?: string } };
  if (!g.process?.versions?.node || g.navigator?.userAgent === "Cloudflare-Workers") return (nodeLookup = null);
  try {
    const name = "node:dns/promises";
    type Dns = { lookup(hostname: string, options: { all: true }): Promise<{ address: string }[]> };
    const mod = (await import(/* @vite-ignore */ name)) as Dns & { default?: Dns };
    const dns = mod.default ?? mod;
    nodeLookup = async (hostname) => (await dns.lookup(hostname, { all: true })).map((a) => a.address);
  } catch {
    nodeLookup = null;
  }
  return nodeLookup;
}

/**
 * Why `url` must not be fetched, or null. Two checks, in this order: the
 * verifier's own `allowHost`, then the addresses the host name resolves to.
 *
 * The address check is what keeps a hostile token from pointing a verifier
 * at its own network: `https://intranet.example.com/x` is a well-formed
 * identity, and only its DNS answer shows that it is 10.0.0.5. It runs
 *   - with `options.lookup` when one is given;
 *   - with the platform resolver when the request will be made by the global
 *     `fetch` (a custom `options.fetch` owns its own network policy, as the
 *     reference MCP server's address-pinning fetch does);
 *   - not at all when `options.lookup` is false, or when the runtime has no
 *     resolver this module can reach.
 * It refuses the request if ANY address is special-use, and if the lookup
 * fails. It does not pin the connection to the vetted address: the request
 * resolves the name again, so a resolver that changes its answer between the
 * two can still get through. Deployments that need that closed use a pinning
 * client (`options.fetch`) or an egress policy.
 */
async function refusal(url: string, options: WebIdentityResolverOptions): Promise<string | null> {
  const { hostname } = new URL(url);
  if (options.allowHost && options.allowHost(hostname) !== true) return `Host of ${url} is not allowed by this verifier`;
  if (options.lookup === false) return null;
  if (options.allowLoopbackHttp === true && (hostname === "localhost" || hostname === "127.0.0.1")) return null;
  const lookup = options.lookup ?? (options.fetch ? null : await platformLookup());
  if (!lookup) return null;
  let addresses: string[];
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    addresses = await Promise.race([
      lookup(hostname),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("lookup timed out")), options.timeoutMs ?? WEB_IDENTITY_FETCH_TIMEOUT_MS);
      }),
    ]);
  } catch {
    return `Host of ${url} could not be resolved`;
  } finally {
    clearTimeout(timer);
  }
  if (!Array.isArray(addresses) || addresses.length === 0) return `Host of ${url} could not be resolved`;
  return addresses.some((a) => isSpecialUseAddress(a)) ? `Host of ${url} resolves to a special-use address` : null;
}

async function resolveUncached(identity: string, options: WebIdentityResolverOptions): Promise<{ result: WebIdentityResolution; lifetimeMs: number }> {
  const fail = (reason: string) => ({ result: { ok: false as const, reason }, lifetimeMs: 0 });

  const why = checkWebIdentity(identity, options);
  if (why) return fail(why);
  const refused = await refusal(identity, options);
  if (refused) return fail(refused);

  const fetched = await fetchJson(identity, options.maxDocumentBytes ?? WEB_IDENTITY_MAX_DOCUMENT_BYTES, options);
  if (!fetched.ok) return fail(fetched.reason);
  const doc = fetched.json;
  if (!isRecord(doc)) return fail("Identity document is not a JSON object");
  // Simple string comparison, as the OAuth draft requires: the document must
  // name the URL it was fetched from, or one host could serve another's.
  if (doc.client_id !== identity) return fail("Identity document client_id does not equal the identity");
  if ("client_secret" in doc || "client_secret_expires_at" in doc) return fail("Identity document carries a client secret");

  const hasJwks = doc.jwks !== undefined;
  const hasJwksUri = doc.jwks_uri !== undefined;
  if (hasJwks && hasJwksUri) return fail("Identity document has both jwks and jwks_uri");
  if (!hasJwks && !hasJwksUri) return fail("Identity document publishes no keys (jwks or jwks_uri)");

  let jwks: unknown = doc.jwks;
  let lifetimeMs = cacheLifetime(fetched.cacheControl, options.maxCacheMs ?? WEB_IDENTITY_MAX_CACHE_MS);
  if (hasJwksUri) {
    const uriWhy = checkUrl(doc.jwks_uri, { loopbackHttp: options.allowLoopbackHttp === true, identity: false });
    if (uriWhy) return fail(`Identity document jwks_uri ${uriWhy}`);
    const jwksUri = doc.jwks_uri as string;
    const keysRefused = await refusal(jwksUri, options);
    if (keysRefused) return fail(keysRefused);
    const keySet = await fetchJson(jwksUri, options.maxJwksBytes ?? WEB_IDENTITY_MAX_JWKS_BYTES, options);
    if (!keySet.ok) return fail(keySet.reason);
    jwks = keySet.json;
    lifetimeMs = Math.min(lifetimeMs, cacheLifetime(keySet.cacheControl, options.maxCacheMs ?? WEB_IDENTITY_MAX_CACHE_MS));
  }

  const selected = selectWebIdentityKey(jwks);
  if (!selected.ok) return fail(`Identity document ${selected.reason}`);
  return {
    result: { ok: true, key: selected.key, ...(selected.kid !== undefined ? { kid: selected.kid } : {}), document: doc as WebIdentityDocument },
    lifetimeMs,
  };
}

/**
 * Resolve a web identity to its current Ed25519 public key, with the reason
 * when it cannot be resolved. Does not cache; use createWebIdentityResolver
 * for a caching resolver. Never throws.
 */
export async function resolveWebIdentity(identity: string, options: WebIdentityResolverOptions = {}): Promise<WebIdentityResolution> {
  try {
    return (await resolveUncached(identity, options)).result;
  } catch (e) {
    return { ok: false, reason: `Web identity resolution failed: ${(e as Error).message}` };
  }
}

/**
 * A MandateKeyResolver for web identities, with a bounded in-memory cache.
 * Returns null for anything that is not an http(s) URL, and null (after
 * calling `onFailure`) for a web identity that cannot be resolved — a
 * verifier then rejects the mandate (fail closed).
 *
 *   const resolveKey = createMandateKeyResolver({ web: true });          // did:aroha AND web identities
 *   const result = await verifyMandateChain(token, resolveKey, { expectedRoot: "https://agents.example.com/shopper" });
 */
export function createWebIdentityResolver(options: WebIdentityResolverOptions = {}): MandateKeyResolver {
  const cache = new Map<string, CacheEntry>();
  // Separate from `cache`, so junk identities cannot push out good keys.
  const failures = new Map<string, number>();
  const inFlight = new Map<string, Promise<Uint8Array | null>>();
  const perHost = new Map<string, number>();
  const now = options.now ?? Date.now;
  const failureMs = Math.min(options.failureCacheMs ?? WEB_IDENTITY_FAILURE_CACHE_MS, options.maxCacheMs ?? WEB_IDENTITY_MAX_CACHE_MS);
  const maxPerHost = options.maxConcurrentPerHost ?? 8;

  const report = (identity: string, reason: string) => {
    try {
      options.onFailure?.(identity, reason);
    } catch {
      // A logging hook that throws must not change the outcome.
    }
  };

  const fetchKey = async (identity: string): Promise<Uint8Array | null> => {
    let resolved: { result: WebIdentityResolution; lifetimeMs: number };
    try {
      resolved = await resolveUncached(identity, options);
    } catch (e) {
      resolved = { result: { ok: false, reason: `Web identity resolution failed: ${(e as Error).message}` }, lifetimeMs: 0 };
    }
    if (!resolved.result.ok) {
      if (failureMs > 0) {
        if (failures.size >= CACHE_MAX_ENTRIES) failures.delete(failures.keys().next().value as string);
        failures.set(identity, now() + failureMs);
      }
      report(identity, resolved.result.reason);
      return null;
    }
    if (resolved.lifetimeMs > 0) {
      if (cache.size >= CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value as string);
      cache.set(identity, { expires: now() + resolved.lifetimeMs, value: resolved.result });
    }
    return resolved.result.key;
  };

  return async (identity) => {
    if (!looksLikeWebIdentity(identity)) return null;
    const hit = cache.get(identity);
    if (hit) {
      if (hit.expires > now()) return hit.value.key;
      cache.delete(identity);
    }
    const failedUntil = failures.get(identity);
    if (failedUntil !== undefined) {
      if (failedUntil > now()) return null;
      failures.delete(identity);
    }
    // Concurrent verifications of one identity share one request.
    const pending = inFlight.get(identity);
    if (pending) return pending;
    let host: string;
    try {
      host = new URL(identity).hostname;
    } catch {
      host = identity;
    }
    const count = perHost.get(host) ?? 0;
    if (count >= maxPerHost) {
      report(identity, `Too many requests in flight to ${host}`);
      return null;
    }
    perHost.set(host, count + 1);
    const request = fetchKey(identity).finally(() => {
      inFlight.delete(identity);
      const left = (perHost.get(host) ?? 1) - 1;
      if (left > 0) perHost.set(host, left);
      else perHost.delete(host);
    });
    inFlight.set(identity, request);
    return request;
  };
}
