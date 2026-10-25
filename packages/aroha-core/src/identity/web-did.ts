// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Web-Native Identity — did:aroha-web:
 *
 * A DNS-anchored DID method that requires NO central Aroha registry.
 * Identity is verified by TWO independent channels simultaneously:
 *
 *   1. HTTPS — DID Document served at:
 *      https://{domain}/.well-known/aroha/agents/{path}/did.json
 *
 *   2. DNS TXT — Key-commitment record at:
 *      _aroha.{domain} IN TXT "v=aroha1; path={path}; keyhash={sha256 of pubkey}"
 *
 * Both channels must agree. Domain hijacking via HTTPS alone is insufficient —
 * the attacker would also need to control DNS to forge the key-commitment.
 * This is a meaningful security upgrade over single-channel HTTPS identity
 * (did:wba, did:web).
 *
 * Key rotation:
 *   Rotations are cryptographically chained — each record is signed by the
 *   key it replaces, commits to the hash of the key that replaces it, and (v2)
 *   names the DID and its own trustAfter in the signed bytes. The chain must
 *   link the current key back to a key DNS commits to; a 24-hour (default)
 *   cool-down applies before a key DNS has not yet endorsed is trusted.
 *   Records are embedded in the DID Document under `arohaWeb.keyHistory`,
 *   newest first. See resolveWebDID for the exact rules, and
 *   spec-public/spec/web-did.md for the normative text.
 *
 * DID format:
 *   did:aroha-web:{domain}[:{path}]
 *   e.g. did:aroha-web:stripe.com:payments-agent
 *        did:aroha-web:internal.example.corp:invoicing
 *
 * Resolution produces the same DIDDocument format as did:aroha: — full
 * interoperability with the rest of the Aroha stack.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, randomBytes } from "@noble/hashes/utils";
import {
  type DIDDocument,
  type AgentKeyPair,
  type VerificationMethod,
  type KeyRotationRecord,
  toMultibase,
  fromMultibase,
  buildRotationRecord,
  rotationSigningPayload,
} from "./did.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── Types ────────────────────────────────────────────────────────────────────

export interface WebDIDDocument extends DIDDocument {
  /** Two-factor verification metadata. */
  arohaWeb: {
    domain: string;
    path: string;
    /** SHA-256 hex of the active public key — must match DNS TXT. */
    keyCommitmentHash: string;
    /** Rotation chain (newest-first). Null if this is the genesis key. */
    keyHistory: KeyRotationRecord[];
  };
}

export { type KeyRotationRecord } from "./did.js";

export interface WebAgentKeyPair extends AgentKeyPair {
  /** The DNS TXT record value to publish at _aroha.{domain}. */
  dnsTXTRecord: string;
  /** The URL where the DID Document should be served. */
  wellKnownUrl: string;
  /** The full typed document (superset of DIDDocument). */
  webDocument: WebDIDDocument;
}

export interface WebDIDResolutionResult {
  document: WebDIDDocument;
  /**
   * True if a DNS TXT key-commitment matched a key in the document's verified
   * rotation chain (the current key, or an earlier one it rotated from).
   */
  dnsVerified: boolean;
  /** True if the CURRENT primary key is accepted and past its rotation cool-down. */
  keyTrusted: boolean;
  /** Reason if keyTrusted is false. */
  trustReason?: string;
  /**
   * Every key a verifier may accept right now, newest first. Empty when
   * nothing is accepted (fail closed). See resolveWebDID for the rules.
   */
  acceptedKeys: WebDIDAcceptedKey[];
  /** True when keyHistory holds legacy v1 (not DID-bound) rotation records. */
  deprecatedRotations: boolean;
}

// ─── DID parsing ──────────────────────────────────────────────────────────────

export interface WebDIDParseOptions {
  /**
   * Accept an IPv4 literal as the domain. Off by default: a did:aroha-web
   * identity is anchored in DNS (the TXT key-commitment), and an IP literal
   * has no DNS name to anchor — it also turns the resolver into a fetcher of
   * arbitrary internal addresses. For closed test networks only.
   */
  allowIpLiteral?: boolean;
}

// One DNS label: 1–63 of [a-z0-9-], not starting or ending with "-".
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
/** The path grammar: lowercase segments of [a-z0-9-], "/"-separated. */
export const WEB_DID_PATH_PATTERN = /^[a-z0-9-]+(\/[a-z0-9-]+)*$/;

/**
 * Validate the domain of a did:aroha-web identifier as a DNS hostname.
 *
 * WHY: the domain is interpolated into `https://{domain}/...` and fetched.
 * Unvalidated, a DID like `did:aroha-web:evil.com@10.0.0.5` or one carrying a
 * port, userinfo, percent-escapes or an IP literal points the resolver at a
 * host the DID's text does not obviously name — the textbook request-forgery
 * shape. Only plain hostnames (and, opted in, IPv4 literals) are accepted.
 */
export function assertWebDIDDomain(domain: string, options: WebDIDParseOptions = {}): void {
  const d = domain.toLowerCase();
  if (d.length === 0 || d.length > 253) throw new Error(`did:aroha-web domain has an invalid length: ${domain}`);
  if (IPV4.test(d)) {
    if (options.allowIpLiteral === true && d.split(".").every((o) => Number(o) <= 255)) return;
    throw new Error(`did:aroha-web domain must be a hostname, not an IP literal: ${domain}`);
  }
  const labels = d.split(".");
  if (!labels.every((l) => LABEL.test(l))) {
    throw new Error(`did:aroha-web domain is not a valid hostname: ${domain}`);
  }
  // A final all-numeric label is not a hostname (and smells of an obfuscated IP).
  if (/^\d+$/.test(labels[labels.length - 1])) {
    throw new Error(`did:aroha-web domain is not a valid hostname: ${domain}`);
  }
}

/**
 * Parse `did:aroha-web:domain[:path]` into its components. Throws on a domain
 * that is not a hostname or a path outside WEB_DID_PATH_PATTERN.
 */
export function parseWebDID(did: string, options: WebDIDParseOptions = {}): { domain: string; path: string } {
  const prefix = "did:aroha-web:";
  if (!did.startsWith(prefix)) {
    throw new Error(`Not a did:aroha-web: identifier: ${did}`);
  }
  const rest = did.slice(prefix.length);
  const colonIdx = rest.indexOf(":");
  const domain = colonIdx === -1 ? rest : rest.slice(0, colonIdx);
  const path = colonIdx === -1 ? "agent" : rest.slice(colonIdx + 1).replace(/:/g, "/");
  assertWebDIDDomain(domain, options);
  // The path is interpolated into the well-known URL; "..", "%2e", "?" or
  // "#" would let a DID point at a document other than its own.
  if (!WEB_DID_PATH_PATTERN.test(path)) {
    throw new Error(`did:aroha-web path must match ${WEB_DID_PATH_PATTERN}: ${path}`);
  }
  return { domain, path };
}

export function buildWebDID(domain: string, path: string): string {
  const normalised = path.replace(/\//g, ":");
  return `did:aroha-web:${domain}:${normalised}`;
}

export function isWebDID(did: string): boolean {
  return did.startsWith("did:aroha-web:");
}

// ─── Well-known path ──────────────────────────────────────────────────────────

/**
 * The HTTP path at which the DID Document should be served.
 * e.g. `did:aroha-web:stripe.com:payments` → `/.well-known/aroha/agents/payments/did.json`
 */
export function wellKnownPath(did: string, options: WebDIDParseOptions = {}): string {
  const { path } = parseWebDID(did, options);
  return `/.well-known/aroha/agents/${path}/did.json`;
}

/**
 * The full HTTPS URL for a given did:aroha-web: identifier.
 */
export function wellKnownUrl(did: string, options: WebDIDParseOptions = {}): string {
  const { domain, path } = parseWebDID(did, options);
  return `https://${domain}/.well-known/aroha/agents/${path}/did.json`;
}

// ─── DNS TXT record ───────────────────────────────────────────────────────────

/**
 * Returns the DNS TXT record VALUE (not the full DNS record) for the
 * key-commitment. Publish at: `_aroha.{domain} IN TXT "{this value}"`
 *
 * Format: `v=aroha1; path={path}; keyhash={sha256hex}`
 */
export function dnsTXTValue(did: string, publicKey: Uint8Array): string {
  const { path } = parseWebDID(did);
  const keyhash  = bytesToHex(sha256(publicKey));
  return `v=aroha1; path=${path}; keyhash=${keyhash}`;
}

/** Parse a DNS TXT value back to its fields. Returns null if invalid. */
export function parseDNSTXT(txt: string): { path: string; keyhash: string } | null {
  if (!txt.includes("v=aroha1")) return null;
  const fields: Record<string, string> = {};
  for (const part of txt.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    fields[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  if (!fields.path || !fields.keyhash) return null;
  return { path: fields.path, keyhash: fields.keyhash };
}

// ─── Key commitment hash ──────────────────────────────────────────────────────

export function keyCommitmentHash(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}

// ─── Generate ─────────────────────────────────────────────────────────────────

/**
 * Generate a new did:aroha-web: identity.
 *
 * Returns the key pair, the DID Document to serve at the well-known path,
 * the DNS TXT value to publish, and the well-known URL.
 *
 * @param domain    The company domain (e.g. "stripe.com")
 * @param path      Agent identifier within the domain (e.g. "payments-agent")
 * @param endpoint  The Aroha HTTP endpoint URL (e.g. "https://agents.stripe.com/aroha/v1")
 */
export async function generateWebAgent(
  domain: string,
  path: string,
  endpoint?: string
): Promise<WebAgentKeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey  = await ed.getPublicKeyAsync(privateKey);

  const did    = buildWebDID(domain, path);
  const keyId  = `${did}#key-1`;
  const now    = new Date().toISOString();
  const agentEndpoint = endpoint ?? `https://${domain}/aroha/v1`;

  const webDoc: WebDIDDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://aroha-labs.com/contexts/aroha-web/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id:                 keyId,
        type:               "Ed25519VerificationKey2020",
        controller:         did,
        publicKeyMultibase: toMultibase(publicKey),
      },
    ],
    authentication:   [keyId],
    assertionMethod:  [keyId],
    keyAgreement:     [keyId],
    service: [
      {
        id:              `${did}#aroha`,
        type:            "ArohaEndpoint",
        serviceEndpoint: agentEndpoint,
      },
    ],
    created: now,
    updated: now,
    arohaWeb: {
      domain,
      path,
      keyCommitmentHash: keyCommitmentHash(publicKey),
      keyHistory: [],
    },
  };

  const txt = dnsTXTValue(did, publicKey);
  const url = wellKnownUrl(did);

  return {
    did,
    privateKey,
    publicKey,
    document:      webDoc,
    webDocument:   webDoc,
    dnsTXTRecord:  txt,
    wellKnownUrl:  url,
  };
}

// ─── Key rotation ──────────────────────────────────────────────────────────────

/**
 * Rotate to a new key pair. The old key signs a (v2, DID-bound) rotation
 * record that is embedded in the new DID Document. The new key is not
 * trusted until `coolDownHours` (default 24h) after the rotation is announced.
 *
 * Publish the returned `webDocument` at the well-known URL and update the
 * DNS TXT record with `dnsTXTRecord` to complete the rotation. Until DNS is
 * updated, resolvers anchored on the OLD DNS commitment accept the new key
 * only once its cool-down has passed (see resolveWebDID).
 */
export async function rotateKey(
  current: WebAgentKeyPair,
  coolDownHours = 24
): Promise<WebAgentKeyPair> {
  const newPrivateKey = ed.utils.randomPrivateKey();
  const newPublicKey  = await ed.getPublicKeyAsync(newPrivateKey);

  const { domain, path } = current.webDocument.arohaWeb;
  const did   = buildWebDID(domain, path);
  const now   = new Date();

  const rotation = await buildRotationRecord(
    did, current.privateKey, toMultibase(current.publicKey), newPublicKey, now, coolDownHours
  );

  // Keep the primary verification method's id (e.g. `#key-1`) and any
  // additional (device) methods: a rotation replaces the PRIMARY key only.
  const [primary, ...others] = current.webDocument.verificationMethod;
  const keyId = primary?.id ?? `${did}#key-1`;
  const ts    = now.toISOString();

  const newDoc: WebDIDDocument = {
    ...current.webDocument,
    verificationMethod: [
      {
        id:                 keyId,
        type:               "Ed25519VerificationKey2020",
        controller:         did,
        publicKeyMultibase: toMultibase(newPublicKey),
      },
      ...others,
    ],
    updated: ts,
    arohaWeb: {
      ...current.webDocument.arohaWeb,
      keyCommitmentHash: keyCommitmentHash(newPublicKey),
      keyHistory:        [rotation, ...current.webDocument.arohaWeb.keyHistory],
    },
  };

  return {
    did,
    privateKey:   newPrivateKey,
    publicKey:    newPublicKey,
    document:     newDoc,
    webDocument:  newDoc,
    dnsTXTRecord: dnsTXTValue(did, newPublicKey),
    wellKnownUrl: wellKnownUrl(did),
  };
}

// ─── Resolve ──────────────────────────────────────────────────────────────────

export interface ResolveWebDIDOptions {
  /**
   * Check the DNS TXT key-commitment (default true). Setting this to false is
   * the same as `allowNoDns: true`: resolution proceeds HTTPS-only, logged,
   * and the result has `dnsVerified: false`.
   */
  verifyDNS?: boolean;
  /**
   * DNS TXT lookup for `_aroha.{domain}` — receives the bare domain. When
   * omitted: Deno's built-in resolver, else Node's node:dns/promises
   * resolveTxt (loaded lazily, so Worker bundles are unaffected), else —
   * no resolver at all — resolution throws unless allowNoDns.
   */
  dnsResolver?: (domain: string) => Promise<string[]>;
  /**
   * Use the platform resolver (Deno.resolveDns / node:dns) when no
   * dnsResolver is passed. Default true. Set false to require an injected
   * resolver — e.g. in tests, so they never touch real DNS.
   */
  useSystemDns?: boolean;
  /** See WebDIDParseOptions.allowIpLiteral. Default false. */
  allowIpLiteral?: boolean;
  /**
   * Maximum DID-document size in bytes. Default 65 536. The body is read as
   * a stream and abandoned past the cap, so a hostile server cannot make the
   * resolver buffer an unbounded response.
   */
  maxDocumentBytes?: number;
  /**
   * Allow resolution to proceed HTTPS-only when NO DNS resolver is available.
   *
   * WHY the default is to throw: DNS is the second factor — the only thing an
   * attacker who controls the web server does not also control. Silently
   * skipping it when no resolver happens to be wired up (the old behaviour in
   * Node) downgraded every resolution to single-channel without anyone
   * choosing that. For tests and local development only; logged when used.
   */
  allowNoDns?: boolean;
  /** HTTPS fetch timeout. Default 10 000 ms. */
  fetchTimeoutMs?: number;
  /** Clock override (tests, replayed audits). */
  now?: Date;
  /**
   * Floor applied to a LEGACY (v1) rotation record's cool-down, whose
   * `trustAfter` is unsigned and could have been shortened by whoever serves
   * the document. Default 24 (the protocol default). v2 records sign
   * `trustAfter` and are honoured as signed.
   */
  legacyMinCoolDownHours?: number;
  /** Where warnings go (HTTPS-only mode, deprecated v1 records). Default console.warn. */
  logger?: (message: string) => void;
}

/** One key a verifier may accept for this DID right now. */
export interface WebDIDAcceptedKey {
  /** The verification method id this key answers for (absolute). */
  verificationMethodId: string;
  publicKeyMultibase: string;
  /**
   * "current"     — the document's primary key, trusted;
   * "predecessor" — the previous primary key, accepted only during the
   *                 latest rotation's cool-down while DNS already commits
   *                 to the new key (graceful cutover);
   * "anchored"    — a key earlier in the chain that DNS still commits to,
   *                 while newer keys wait out their cool-down;
   * "additional"  — a non-primary (device) method whose hash DNS commits to.
   */
  role: "current" | "predecessor" | "anchored" | "additional";
}

const DEFAULT_LEGACY_COOLDOWN_HOURS = 24;

function absoluteVmId(did: string, id: string): string {
  return id.startsWith("#") ? `${did}${id}` : id;
}

function txtHashesForPath(records: string[], path: string): Set<string> {
  const out = new Set<string>();
  for (const txt of records) {
    const parsed = parseDNSTXT(txt);
    if (parsed && parsed.path === path) out.add(parsed.keyhash);
  }
  return out;
}

/**
 * Resolve a did:aroha-web: identifier.
 *
 * Steps:
 *   1. Fetch the DID Document over HTTPS; its `id` must equal `did`.
 *   2. Verify the rotation chain in `arohaWeb.keyHistory` (newest first):
 *        keyHistory[0].newKeyHash   = hash(current primary key)
 *        keyHistory[i].newKeyHash   = hash(keyHistory[i-1].predecessorKey)
 *        each record signed by its predecessorKey, v2 records bound to `did`,
 *        rotatedAt non-increasing down the list.
 *      Any break throws — a document whose history does not chain is not a
 *      rotated identity, it is two unrelated keys.
 *   3. DNS: find the NEWEST key in the chain whose hash `_aroha.{domain}`
 *      commits to (the anchor). No anchor → `dnsVerified: false` and NO
 *      accepted keys (fail closed). This is what stops "strip keyHistory":
 *      a stripped document's only key is the new one, which DNS (still
 *      naming the old key) does not commit to, so nothing is accepted.
 *   4. Accepted keys:
 *        - anchor = current key (DNS updated): the current key, plus — while
 *          the latest rotation is inside its cool-down — the predecessor
 *          (graceful cutover, as the spec describes).
 *        - anchor = an older key: walk forward from it; each newer key is
 *          accepted only once ITS rotation's cool-down has passed. Until
 *          then the anchored key is the one accepted. A key DNS has not
 *          endorsed never gets the early, during-cool-down acceptance: that
 *          window is exactly the owner's chance to react to a rotation made
 *          with a stolen key (by publishing a fresh DNS commitment).
 *
 * `keyTrusted` keeps its old meaning — the CURRENT primary key is accepted
 * and past cool-down — so existing callers (commerce org-identity) keep
 * working. Use `webDIDPublicKeys` / `selectWebDIDKey` to verify a signature
 * against the key its proof names.
 *
 * Legacy call form `resolveWebDID(did, verifyDNS, dnsResolver, fetchTimeoutMs)`
 * is still accepted.
 */
export async function resolveWebDID(
  did: string,
  verifyDNSOrOptions: boolean | ResolveWebDIDOptions = true,
  dnsResolver?: (domain: string) => Promise<string[]>,
  fetchTimeoutMs = 10_000
): Promise<WebDIDResolutionResult> {
  const opts: ResolveWebDIDOptions =
    typeof verifyDNSOrOptions === "object"
      ? verifyDNSOrOptions
      : { verifyDNS: verifyDNSOrOptions, dnsResolver, fetchTimeoutMs };
  const log = opts.logger ?? ((m: string) => console.warn(m));
  const now = opts.now ?? new Date();
  const url = wellKnownUrl(did, { allowIpLiteral: opts.allowIpLiteral });

  // ── Step 1: Fetch DID Document over HTTPS ─────────────────────────────────
  // redirect: "error" — the document must come from the host the DID names.
  // Following a redirect would let that host bounce the resolver to any
  // other address (including internal ones) with the DID's authority.
  //
  // NOT covered here: a hostname whose DNS answer is a private/loopback
  // address. fetch() exposes no hook between name resolution and connect, so
  // the resolved address cannot be checked from this layer. Deployments that
  // resolve DIDs from untrusted input should egress through a proxy or
  // network policy that denies private ranges.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.fetchTimeoutMs ?? 10_000);
  let doc: WebDIDDocument;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: ctrl.signal,
      redirect: "error",
    });
    if (!res.ok) {
      throw new Error(`Failed to resolve ${did}: HTTP ${res.status} from ${url}`);
    }
    const text = await readCappedText(res, opts.maxDocumentBytes ?? MAX_WEB_DID_DOCUMENT_BYTES, url);
    try {
      doc = JSON.parse(text) as WebDIDDocument;
    } catch {
      throw new Error(`Failed to resolve ${did}: document at ${url} is not JSON`);
    }
  } finally {
    clearTimeout(timer);
  }
  if (typeof doc !== "object" || doc === null) {
    throw new Error(`Failed to resolve ${did}: document at ${url} is not an object`);
  }

  if (doc.id !== did) {
    throw new Error(`DID mismatch: document claims ${doc.id}, expected ${did}`);
  }
  const primary = doc.verificationMethod?.[0];
  if (!primary) throw new Error(`DID ${did}: document has no verification methods`);
  const currentKey = primary.publicKeyMultibase;
  const currentHash = keyCommitmentHash(fromMultibase(currentKey));
  if (doc.arohaWeb?.keyCommitmentHash !== undefined && doc.arohaWeb.keyCommitmentHash !== currentHash) {
    throw new Error(`DID ${did}: arohaWeb.keyCommitmentHash does not match the primary key`);
  }

  // ── Step 2: Verify the rotation chain ─────────────────────────────────────
  const history: KeyRotationRecord[] = doc.arohaWeb?.keyHistory ?? [];
  let deprecatedRotations = false;
  for (let i = 0; i < history.length; i++) {
    const r = history[i];
    const check = await checkKeyRotation(r, did);
    if (!check.valid) {
      throw new Error(`DID ${did}: key rotation record (rotatedAt ${r.rotatedAt}) ${check.reason}`);
    }
    if (check.deprecated) deprecatedRotations = true;
    const successorKey = i === 0 ? currentKey : history[i - 1].predecessorKey;
    if (r.newKeyHash !== keyCommitmentHash(fromMultibase(successorKey))) {
      throw new Error(
        i === 0
          ? `DID ${did}: keyHistory[0] does not commit to the current primary key`
          : `DID ${did}: keyHistory[${i}] does not commit to keyHistory[${i - 1}].predecessorKey — the rotation chain is broken`
      );
    }
    if (i > 0 && Date.parse(r.rotatedAt) > Date.parse(history[i - 1].rotatedAt)) {
      throw new Error(`DID ${did}: keyHistory is not newest-first at index ${i}`);
    }
  }
  if (deprecatedRotations) {
    log(`[aroha] ${did}: keyHistory contains legacy v1 rotation records (not DID-bound); re-rotate to upgrade`);
  }

  // Chain keys oldest → newest; chain[j] (j ≥ 1) was introduced by history[n - j].
  const n = history.length;
  const chain: string[] = [...history.map((r) => r.predecessorKey).reverse(), currentKey];
  const legacyFloorMs = (opts.legacyMinCoolDownHours ?? DEFAULT_LEGACY_COOLDOWN_HOURS) * 3_600_000;
  const effectiveTrustAfter = (r: KeyRotationRecord): number => {
    const signed = Date.parse(r.trustAfter);
    if (r.v === 2) return signed;
    // v1: trustAfter is unsigned — never let it shorten the default cool-down.
    return Math.max(Number.isNaN(signed) ? 0 : signed, Date.parse(r.rotatedAt) + legacyFloorMs);
  };
  const introducedBy = (j: number): KeyRotationRecord => history[n - j];

  // ── Step 3: DNS TXT key-commitment ────────────────────────────────────────
  const { domain, path } = parseWebDID(did, { allowIpLiteral: opts.allowIpLiteral });
  let txtRecords: string[] | null = null;
  if (opts.verifyDNS !== false) {
    const systemDns = opts.useSystemDns !== false;
    const nodeResolver = opts.dnsResolver || !systemDns ? null : await loadNodeTxtResolver();
    if (opts.dnsResolver) {
      txtRecords = await opts.dnsResolver(domain).catch(() => []);
    } else if (nodeResolver) {
      txtRecords = await nodeResolver(domain).catch(() => []); // lookup failed → fail closed below
    } else if (systemDns && typeof (globalThis as Record<string, unknown>)["Deno"] !== "undefined") {
      try {
        const denoGlobal = (globalThis as unknown as { Deno: { resolveDns(n: string, t: string): Promise<string[][]> } }).Deno;
        txtRecords = (await denoGlobal.resolveDns(`_aroha.${domain}`, "TXT")).flat();
      } catch {
        txtRecords = []; // lookup failed — no commitment found, fail closed below
      }
    } else if (!opts.allowNoDns) {
      throw new Error(
        `Cannot verify ${did}: no DNS resolver available for the _aroha.${domain} TXT key-commitment. ` +
        `Pass dnsResolver (e.g. node:dns/promises resolveTxt), or allowNoDns: true for tests/dev only.`
      );
    }
  }
  if (txtRecords === null) {
    log(`[aroha] ${did}: resolved HTTPS-only — DNS key-commitment NOT checked (allowNoDns / verifyDNS:false)`);
  }

  const acceptedKeys: WebDIDAcceptedKey[] = [];
  const primaryId = absoluteVmId(did, primary.id);
  let dnsVerified = false;
  let anchor: number;
  if (txtRecords === null) {
    // HTTPS-only: the document is all we have; treat it as self-anchored.
    anchor = chain.length - 1;
  } else {
    const hashes = txtHashesForPath(txtRecords, path);
    anchor = -1;
    for (let j = chain.length - 1; j >= 0; j--) {
      if (hashes.has(keyCommitmentHash(fromMultibase(chain[j])))) { anchor = j; break; }
    }
    dnsVerified = anchor >= 0;
    // Non-primary (device) methods are accepted only when DNS commits to each.
    if (dnsVerified) {
      for (const vm of doc.verificationMethod.slice(1)) {
        if (hashes.has(keyCommitmentHash(fromMultibase(vm.publicKeyMultibase)))) {
          acceptedKeys.push({ verificationMethodId: absoluteVmId(did, vm.id), publicKeyMultibase: vm.publicKeyMultibase, role: "additional" });
        }
      }
    }
  }
  if (txtRecords === null) {
    for (const vm of doc.verificationMethod.slice(1)) {
      acceptedKeys.push({ verificationMethodId: absoluteVmId(did, vm.id), publicKeyMultibase: vm.publicKeyMultibase, role: "additional" });
    }
  }

  // ── Step 4: which primary-slot keys are accepted now ─────────────────────
  let keyTrusted = false;
  let trustReason: string | undefined;
  const nowMs = now.getTime();
  const last = chain.length - 1;
  if (anchor < 0) {
    trustReason = `No DNS TXT key-commitment at _aroha.${domain} matches any key in the document's rotation chain`;
  } else if (anchor === last) {
    acceptedKeys.unshift({ verificationMethodId: primaryId, publicKeyMultibase: currentKey, role: "current" });
    if (n > 0 && nowMs < effectiveTrustAfter(history[0])) {
      acceptedKeys.splice(1, 0, { verificationMethodId: primaryId, publicKeyMultibase: chain[last - 1], role: "predecessor" });
      trustReason = `Key rotation cool-down active until ${new Date(effectiveTrustAfter(history[0])).toISOString()}`;
    } else {
      keyTrusted = true;
    }
  } else {
    let cur = anchor;
    while (cur < last && nowMs >= effectiveTrustAfter(introducedBy(cur + 1))) cur++;
    acceptedKeys.unshift({
      verificationMethodId: primaryId,
      publicKeyMultibase: chain[cur],
      role: cur === last ? "current" : "anchored",
    });
    if (cur === last) {
      keyTrusted = true;
    } else {
      trustReason =
        `DNS commits to an earlier key; the newer key is not trusted until its rotation cool-down ends ` +
        `(${new Date(effectiveTrustAfter(introducedBy(cur + 1))).toISOString()}) or DNS is updated`;
    }
  }

  return { document: doc, dnsVerified, keyTrusted, trustReason, acceptedKeys, deprecatedRotations };
}

/**
 * The keys that may verify a signature whose proof names
 * `verificationMethodId` (default: the primary method), newest first.
 * During a graceful cutover this has TWO entries for the primary id — a
 * verifier should accept a signature that verifies under either. Empty when
 * nothing is accepted (DNS mismatch, unknown method).
 */
export function webDIDPublicKeys(result: WebDIDResolutionResult, verificationMethodId?: string): Uint8Array[] {
  const did = result.document.id;
  const primaryId = absoluteVmId(did, result.document.verificationMethod[0]?.id ?? `${did}#key-1`);
  const wanted = verificationMethodId ? absoluteVmId(did, verificationMethodId) : primaryId;
  return result.acceptedKeys
    .filter((k) => k.verificationMethodId === wanted)
    .map((k) => fromMultibase(k.publicKeyMultibase));
}

/**
 * The newest accepted key for `verificationMethodId` (default primary).
 * Throws when none is accepted — callers building a PublicKeyResolver should
 * map that to "unknown sender" (null), never fall back to another key.
 */
export function selectWebDIDKey(result: WebDIDResolutionResult, verificationMethodId?: string): Uint8Array {
  const keys = webDIDPublicKeys(result, verificationMethodId);
  if (keys.length === 0) {
    throw new Error(
      `DID ${result.document.id}: no accepted key for ${verificationMethodId ?? "the primary verification method"}` +
      (result.trustReason ? ` (${result.trustReason})` : "")
    );
  }
  return keys[0];
}

/**
 * Verify a key rotation record's predecessor signature, and — for a v2
 * record when `expectedDid` is given — that it was signed for that DID.
 * Accepts legacy v1 records (see checkKeyRotation for the deprecation flag).
 */
export async function verifyKeyRotation(rotation: KeyRotationRecord, expectedDid?: string): Promise<boolean> {
  return (await checkKeyRotation(rotation, expectedDid)).valid;
}

/** Detailed form of verifyKeyRotation: `deprecated` is true for a v1 (not DID-bound) record. */
export async function checkKeyRotation(
  rotation: KeyRotationRecord,
  expectedDid?: string
): Promise<{ valid: boolean; deprecated: boolean; reason?: string }> {
  const deprecated = rotation.v !== 2;
  if (rotation.v !== undefined && rotation.v !== 2) {
    return { valid: false, deprecated, reason: `has unsupported version ${String(rotation.v)}` };
  }
  if (rotation.v === 2 && expectedDid !== undefined && rotation.did !== expectedDid) {
    return { valid: false, deprecated, reason: `was signed for ${String(rotation.did)}, not ${expectedDid}` };
  }
  try {
    const ok = await ed.verifyAsync(
      Buffer.from(rotation.predecessorSignature, "base64url"),
      rotationSigningPayload(rotation),
      fromMultibase(rotation.predecessorKey)
    );
    return ok ? { valid: true, deprecated } : { valid: false, deprecated, reason: "has invalid predecessor signature" };
  } catch {
    return { valid: false, deprecated, reason: "has invalid predecessor signature" };
  }
}

// ─── Fetch / DNS helpers ──────────────────────────────────────────────────────

/** Default cap on a DID document's size (64 KiB). */
export const MAX_WEB_DID_DOCUMENT_BYTES = 64 * 1024;

/**
 * Read a response body as UTF-8, refusing anything over `maxBytes`. Reads
 * the stream incrementally and cancels it at the cap instead of buffering
 * the whole body first (which is what res.json() does).
 */
async function readCappedText(res: Response, maxBytes: number, url: string): Promise<string> {
  const declared = Number(res.headers?.get?.("content-length") ?? NaN);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`DID document at ${url} is too large (${declared} bytes > ${maxBytes})`);
  }
  if (!res.body) throw new Error(`DID document at ${url} has no body`);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(`DID document at ${url} is too large (> ${maxBytes} bytes)`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(all);
}

type TxtResolver = (domain: string) => Promise<string[]>;
let nodeTxtResolver: TxtResolver | null | undefined;

/**
 * Node's resolveTxt for `_aroha.{domain}`, or null outside Node. Loaded with
 * a computed specifier so Worker/browser bundlers do not try to resolve
 * node:dns; there, this returns null and the caller fails closed.
 */
async function loadNodeTxtResolver(): Promise<TxtResolver | null> {
  if (nodeTxtResolver !== undefined) return nodeTxtResolver;
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  if (!proc?.versions?.node || typeof (globalThis as Record<string, unknown>)["Deno"] !== "undefined") {
    nodeTxtResolver = null;
    return null;
  }
  try {
    const spec = "node:dns/promises";
    const dns = (await import(/* @vite-ignore */ spec)) as { resolveTxt(name: string): Promise<string[][]> };
    // A TXT record may arrive split into ≤255-byte strings; rejoin each one.
    nodeTxtResolver = async (domain) => (await dns.resolveTxt(`_aroha.${domain}`)).map((parts) => parts.join(""));
  } catch {
    nodeTxtResolver = null;
  }
  return nodeTxtResolver;
}
