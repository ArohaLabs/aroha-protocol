// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Registry-backed mandate revocation and redemption — the client half of
 * the Aroha registry's /v1/mandates endpoints.
 *
 * WHY THIS EXISTS. verifyMandateChain has always consulted an `isRevoked`
 * hook on every link, and redeemPaymentMandate has always taken a
 * RedemptionStore — but nothing in the SDK PROVIDED either outside tests. A
 * human could not actually revoke the intent mandate they gave their agent,
 * and two payees could not share a cumulative cap, unless each integrator
 * built that infrastructure. These functions connect the existing hooks to
 * the registry:
 *
 *   revokeMandate(registryUrl, token, grantorPrivateKey)
 *     → POST /v1/mandates/:mandateId/revoke
 *   httpRevocationCheck(registryUrl, { cacheMs })   (a MandateRevocationCheck)
 *     → GET  /v1/mandates/:mandateId/revoked
 *   httpRedemptionStore(registryUrl, apiKey)        (a RedemptionStore)
 *     → POST /v1/mandates/:mandateId/redeem, GET …/redemptions
 *
 * WHO MAY REVOKE. The registry accepts a revocation only when it is signed by
 * the mandate's grantor or by the grantor of ANY ancestor link — authority
 * flows down a chain, so anyone above a mandate may withdraw it. The signed
 * bytes are mandateRevocationPayload(mandateId, revokedAt); the registry
 * verifies the whole chain first (so a forged "ancestor" cannot be smuggled
 * in) and the revoker's key the same way it resolves every chain key.
 *
 * Revocation is permanent: once the registry says revoked, it stays revoked.
 * That is why httpRevocationCheck caches a "revoked" answer forever but a
 * "not revoked" answer only for `cacheMs`.
 *
 * SIGNED STATUS (recommended). The registry signs every revocation answer
 * with its own key (published at /.well-known/aroha-registry-keys.json) over
 * revocationStatusPayload(…), which includes `checkedAt`. Pass the pinned
 * keys as `registryKeys` and httpRevocationCheck verifies the signature, the
 * (mandateId, grantor) it names, and its freshness — an unsigned, altered,
 * mis-addressed or stale answer is a failure, never "not revoked". Without
 * `registryKeys` the answer is trusted as transported (the pre-signing
 * behaviour, kept for compatibility) — only as trustworthy as TLS and every
 * cache or proxy in between.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex } from "@noble/hashes/utils";
import { canonicalizeJcs } from "./jcs.js";
// Subpath, not the barrel: this module is part of the Worker-safe
// @aroha-sdk/credentials/mandates entry point.
import { assertSecureEndpoint } from "@aroha-sdk/core/endpoints";
import {
  decodeMandateToken,
  resolveContentAddressedKey,
  type MandateRevocationCheck,
} from "./mandate.js";
import { mandateRedemptionKey, parseMandateRedemptionKey, type RedemptionRecord, type RedemptionStore } from "./redemption.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

type FetchLike = typeof fetch;

/** Domain-separation tag inside the signed revocation bytes. */
export const MANDATE_REVOCATION_PURPOSE = "aroha.mandate.revoke/v1";

/**
 * The exact string a revocation signature covers: RFC 8785 JCS of
 * { mandateId, purpose: MANDATE_REVOCATION_PURPOSE, revokedAt }.
 *
 * `purpose` is there so these bytes can never be confused with any other
 * small JSON object a grantor key signs — a signature over {mandateId,
 * revokedAt} alone would be a valid signature over whatever else happens to
 * canonicalise identically.
 */
export function mandateRevocationPayload(mandateId: string, revokedAt: string): string {
  return canonicalizeJcs({ mandateId, purpose: MANDATE_REVOCATION_PURPOSE, revokedAt });
}

/** Domain-separation tag inside the registry's signed revocation-status bytes. */
export const REVOCATION_STATUS_PURPOSE = "aroha.revocation-status/v1";

/** The fields of a revocation answer the registry signs. */
export interface RevocationStatusFields {
  mandateId: string;
  grantor: string;
  revoked: boolean;
  /** Present only when revoked. */
  revokedAt?: string;
  /** Registry time the status was read (ISO 8601). */
  checkedAt: string;
}

/**
 * The exact string a revocation-status signature covers: RFC 8785 JCS of
 * { purpose: REVOCATION_STATUS_PURPOSE, mandateId, grantor, revoked,
 * revokedAt?, checkedAt }. Mirrors GET /v1/mandates/:id/revoked in the
 * registry (apps/registry-server/src/routes/mandates.ts).
 */
export function revocationStatusPayload(s: RevocationStatusFields): string {
  return canonicalizeJcs({
    purpose: REVOCATION_STATUS_PURPOSE,
    mandateId: s.mandateId,
    grantor: s.grantor,
    revoked: s.revoked,
    ...(s.revokedAt !== undefined ? { revokedAt: s.revokedAt } : {}),
    checkedAt: s.checkedAt,
  });
}

/**
 * A registry signing key, in the shape /.well-known/aroha-registry-keys.json
 * publishes it (`publicKeyB64`, base64url) or as raw bytes. `keyId`, when
 * omitted, is computed as the first 16 hex chars of SHA-256(publicKey).
 */
export interface RegistryStatusKey {
  keyId?: string;
  publicKeyB64?: string;
  publicKey?: Uint8Array;
  purpose?: string[];
  /** Retired keys are never accepted for revocation status (it is short-lived). */
  retired?: boolean;
}

/** Look up a registry signing key by keyId — return null for an unknown key. */
export type RegistryStatusKeyResolver = (keyId: string) => Uint8Array | null | Promise<Uint8Array | null>;

/** First 16 hex chars of SHA-256(publicKey) — the registry's keyId. */
export function registryKeyId(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey)).slice(0, 16);
}

function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

function statusKeyResolver(keys: RegistryStatusKey[] | RegistryStatusKeyResolver): RegistryStatusKeyResolver {
  if (typeof keys === "function") return keys;
  const byId = new Map<string, Uint8Array>();
  for (const k of keys) {
    if (k.retired) continue;
    if (k.purpose && !k.purpose.includes("revocation-status")) continue;
    const pub = k.publicKey ?? (k.publicKeyB64 ? b64urlDecode(k.publicKeyB64) : null);
    if (!pub || pub.length !== 32) throw new Error("registryKeys: every key needs a 32-byte publicKey or publicKeyB64");
    byId.set(k.keyId ?? registryKeyId(pub), pub);
  }
  if (byId.size === 0) throw new Error("registryKeys: no usable (non-retired, revocation-status) key");
  return (keyId) => byId.get(keyId) ?? null;
}

/**
 * A revocation answer that failed signature or freshness verification. Never
 * softened by `failOpen`: it is evidence the answer was altered or replayed,
 * not that the registry was unreachable.
 */
export class RevocationStatusVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevocationStatusVerificationError";
  }
}

/**
 * Normalise and vet the registry URL. Revocation answers and redemption
 * records decide whether money moves; over cleartext an on-path party could
 * forge "not revoked" or "redeemed". https:// is required except to a
 * loopback host, unless the caller opts out with allowInsecureHttp.
 */
function base(registryUrl: string, allowInsecureHttp?: boolean): string {
  assertSecureEndpoint(registryUrl, { allowInsecureHttp, label: "registryUrl" });
  return registryUrl.replace(/\/+$/, "");
}

async function withTimeout<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await run(ctrl.signal);
  } finally {
    clearTimeout(timer);
  }
}

// ─── Revocation check ─────────────────────────────────────────────────────────

export interface HttpRevocationCheckOptions {
  /** DEVELOPMENT ONLY: allow an http:// registryUrl on a non-loopback host. */
  allowInsecureHttp?: boolean;
  /**
   * How long a "not revoked" answer is reused, in ms. Default 30 000. A
   * "revoked" answer is cached for the life of the checker (revocation is
   * permanent). 0 disables the negative cache.
   */
  cacheMs?: number;
  /**
   * When the registry cannot be reached (network error, timeout, non-2xx),
   * treat the mandate as NOT revoked instead of failing. Default false:
   * the checker throws, which verifyMandateChain turns into a rejection —
   * "we could not ask" is not evidence of "not revoked". Opt in only where
   * availability matters more than honouring a revocation promptly.
   */
  failOpen?: boolean;
  /** Called on every lookup failure (both modes) — for logging/metrics. */
  onError?: (mandateId: string, error: unknown) => void;
  /** Per-request timeout in ms. Default 5 000. */
  timeoutMs?: number;
  /** fetch implementation (tests, custom agents). Default globalThis.fetch. */
  fetch?: FetchLike;
  /**
   * RECOMMENDED. The registry's signing keys, pinned out of band (e.g. copied
   * from its /.well-known/aroha-registry-keys.json `keys` array), or a
   * resolver from keyId to public key. When set, every answer must carry a
   * valid `statusSignature` by a non-retired key over
   * revocationStatusPayload(…), name the (mandateId, grantor) asked about,
   * and be fresh (`checkedAt` within `maxStatusAgeMs`); anything else throws
   * a RevocationStatusVerificationError — even with `failOpen`. When unset,
   * the answer is trusted as transported (backward compatible).
   */
  registryKeys?: RegistryStatusKey[] | RegistryStatusKeyResolver;
  /** Oldest acceptable signed `checkedAt`, in ms. Default 60 000. Only with registryKeys. */
  maxStatusAgeMs?: number;
  /** How far a signed `checkedAt` may lie in the future (clock skew), in ms. Default 30 000. */
  maxStatusFutureSkewMs?: number;
}

/**
 * A MandateRevocationCheck backed by the registry's
 * GET /v1/mandates/:mandateId/revoked. Pass it as `isRevoked` to
 * verifyMandateChain / verifyMandate / enforceSpendingConstraints.
 *
 * Pass `registryKeys` to verify the registry's signature on every answer
 * (recommended; see HttpRevocationCheckOptions.registryKeys).
 */
export function httpRevocationCheck(
  registryUrl: string,
  options: HttpRevocationCheckOptions = {}
): MandateRevocationCheck {
  const root = base(registryUrl, options.allowInsecureHttp);
  const cacheMs = options.cacheMs ?? 30_000;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const doFetch = options.fetch ?? fetch;
  const revoked = new Set<string>();
  const notRevokedUntil = new Map<string, number>();
  // Built once, so a malformed key list fails at construction, not per lookup.
  const resolveStatusKey = options.registryKeys ? statusKeyResolver(options.registryKeys) : null;
  const maxAgeMs = options.maxStatusAgeMs ?? 60_000;
  const maxFutureSkewMs = options.maxStatusFutureSkewMs ?? 30_000;

  /** Throws RevocationStatusVerificationError unless the answer is signed, addressed to us, and fresh. */
  async function verifySigned(
    resolve: RegistryStatusKeyResolver,
    body: Record<string, unknown>,
    mandateId: string,
    grantor: string,
    revokedAnswer: boolean,
  ): Promise<void> {
    const fail = (why: string): never => {
      throw new RevocationStatusVerificationError(`revocation status rejected: ${why}`);
    };
    const { statusSignature, statusKeyId, checkedAt, revokedAt } = body;
    if (typeof statusSignature !== "string" || typeof statusKeyId !== "string" || typeof checkedAt !== "string") {
      return fail("unsigned answer (no statusSignature / statusKeyId / checkedAt)");
    }
    if (body.mandateId !== mandateId || body.grantor !== grantor) fail("the answer names a different mandate");
    if (revokedAnswer && typeof revokedAt !== "string") fail("a revoked answer without revokedAt");
    const checkedMs = Date.parse(checkedAt);
    const now = Date.now();
    if (Number.isNaN(checkedMs)) fail("checkedAt is not a date");
    if (now - checkedMs > maxAgeMs) fail(`stale answer (checkedAt older than ${maxAgeMs} ms)`);
    if (checkedMs - now > maxFutureSkewMs) fail("checkedAt is in the future");
    const pub = await resolve(statusKeyId);
    if (!pub) return fail(`unknown registry key ${statusKeyId}`);
    const sig = b64urlDecode(statusSignature);
    let ok = false;
    try {
      ok = sig !== null && sig.length === 64 && (await ed.verifyAsync(
        sig,
        new TextEncoder().encode(revocationStatusPayload({
          mandateId,
          grantor,
          revoked: revokedAnswer,
          ...(revokedAnswer ? { revokedAt: revokedAt as string } : {}),
          checkedAt,
        })),
        pub,
      ));
    } catch {
      ok = false;
    }
    if (!ok) fail("statusSignature does not verify under the registry key");
  }

  return async (mandateId: string, grantor: string): Promise<boolean> => {
    if (typeof grantor !== "string" || grantor.length === 0) {
      // The registry answers per (grantor, mandateId); a bare id is ambiguous.
      throw new Error("httpRevocationCheck needs the mandate's grantor (verifyMandateChain passes it)");
    }
    const key = mandateRedemptionKey({ grantor, mandateId });
    if (revoked.has(key)) return true;
    const until = notRevokedUntil.get(key);
    if (until !== undefined && Date.now() < until) return false;

    try {
      const res = await withTimeout(timeoutMs, (signal) =>
        doFetch(`${root}/v1/mandates/${encodeURIComponent(mandateId)}/revoked?grantor=${encodeURIComponent(grantor)}`, {
          headers: { Accept: "application/json" },
          signal,
        })
      );
      if (!res.ok) throw new Error(`revocation lookup returned HTTP ${res.status}`);
      const body = (await res.json()) as Record<string, unknown>;
      if (typeof body.revoked !== "boolean") throw new Error("revocation lookup returned no `revoked` boolean");
      if (resolveStatusKey) await verifySigned(resolveStatusKey, body, mandateId, grantor, body.revoked);
      if (body.revoked) {
        revoked.add(key);
        notRevokedUntil.delete(key);
        return true;
      }
      if (cacheMs > 0) notRevokedUntil.set(key, Date.now() + cacheMs);
      return false;
    } catch (err) {
      options.onError?.(mandateId, err);
      // failOpen covers "could not ask", never "the answer was forged".
      if (options.failOpen && !(err instanceof RevocationStatusVerificationError)) return false;
      throw err;
    }
  };
}

// ─── Revoke ───────────────────────────────────────────────────────────────────

export interface RevokeMandateOptions {
  /** DEVELOPMENT ONLY: allow an http:// registryUrl on a non-loopback host. */
  allowInsecureHttp?: boolean;
  /**
   * DID of the revoker — the grantor of the mandate or of one of its
   * ancestors. Default: the chain link whose grantor is the content-addressed
   * DID of `grantorPrivateKey`'s public key, else the leaf's grantor. Set it
   * explicitly for E-DID or named grantors.
   */
  revokerDid?: string;
  /** Revocation instant. Default now. */
  revokedAt?: Date;
  fetch?: FetchLike;
  timeoutMs?: number;
}

export interface RevokeMandateResult {
  mandateId: string;
  revoked: true;
  revokedAt: string;
  revokedBy: string;
}

/**
 * Revoke the mandate a token names (its leaf), signing as its grantor or an
 * ancestor grantor. Revoking a mandate kills everything beneath it: verifiers
 * consult the revocation hook for every link of a chain.
 *
 * Throws on any non-2xx answer (the registry's error message included).
 */
export async function revokeMandate(
  registryUrl: string,
  token: string,
  grantorPrivateKey: Uint8Array,
  options: RevokeMandateOptions = {}
): Promise<RevokeMandateResult> {
  const decoded = decodeMandateToken(token); // throws on a malformed token
  const mandateId = decoded.mandate.mandateId;
  const revokedAt = (options.revokedAt ?? new Date()).toISOString();

  let revokerDid = options.revokerDid;
  if (!revokerDid) {
    const pub = await ed.getPublicKeyAsync(grantorPrivateKey);
    const links = [...(decoded.chain ?? []).map((l) => l.mandate), decoded.mandate];
    for (const m of links) {
      const k = await resolveContentAddressedKey(m.grantor);
      if (k && k.length === pub.length && k.every((b, i) => b === pub[i])) {
        revokerDid = m.grantor;
        break;
      }
    }
    revokerDid ??= decoded.mandate.grantor;
  }

  const sig = await ed.signAsync(new TextEncoder().encode(mandateRevocationPayload(mandateId, revokedAt)), grantorPrivateKey);
  const doFetch = options.fetch ?? fetch;
  const res = await withTimeout(options.timeoutMs ?? 10_000, (signal) =>
    doFetch(`${base(registryUrl, options.allowInsecureHttp)}/v1/mandates/${encodeURIComponent(mandateId)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ token, revokedAt, revoker: revokerDid, signature: Buffer.from(sig).toString("base64url") }),
      signal,
    })
  );
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new Error(`revokeMandate: HTTP ${res.status}: ${typeof body.error === "string" ? body.error : "request failed"}`);
  }
  return {
    mandateId,
    revoked: true,
    revokedAt: typeof body.revokedAt === "string" ? body.revokedAt : revokedAt,
    revokedBy: typeof body.revokedBy === "string" ? body.revokedBy : revokerDid,
  };
}

// ─── Redemption store ─────────────────────────────────────────────────────────

export interface HttpRedemptionStoreOptions {
  /** DEVELOPMENT ONLY: allow an http:// registryUrl on a non-loopback host. */
  allowInsecureHttp?: boolean;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * A RedemptionStore backed by the registry's
 * POST /v1/mandates/:mandateId/redeem — one cumulative cap shared by every
 * payee that uses the same registry, enforced atomically server-side.
 *
 * The registry does NOT take the caller's `limitMicros`: it re-verifies the
 * token (chain, revocation, tier, merchant allow-list) and derives the limit
 * from the verified payment mandate. So the token must reach it — call
 * `redeemPaymentMandate(store, mandate, amountUsd, merchant, { token })`.
 * A call without a token throws rather than redeeming unverified.
 *
 * Network and server errors throw (the redemption did not happen, or its
 * outcome is unknown — never report it as accepted).
 */
export function httpRedemptionStore(
  registryUrl: string,
  apiKey: string,
  options: HttpRedemptionStoreOptions = {}
): RedemptionStore {
  const root = base(registryUrl, options.allowInsecureHttp);
  const doFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    Authorization: `Bearer ${apiKey}`,
  };

  return {
    // `_key` is mandateRedemptionKey(mandate). The registry derives the same
    // key from the verified token, so only the mandateId is sent, in the path.
    async tryRedeem(_key: string, amountMicros: number, _limitMicros: number, record: RedemptionRecord) {
      if (!record.token) {
        throw new Error(
          "httpRedemptionStore needs the mandate token: call redeemPaymentMandate(store, mandate, amountUsd, merchant, { token })"
        );
      }
      const res = await withTimeout(timeoutMs, (signal) =>
        doFetch(`${root}/v1/mandates/${encodeURIComponent(record.mandateId)}/redeem`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            token: record.token,
            amountMicros,
            merchant: record.merchant,
            redemptionId: record.redemptionId,
          }),
          signal,
        })
      );
      const body = (await res.json().catch(() => ({}))) as {
        accepted?: unknown; redeemedMicros?: unknown; error?: unknown;
      };
      // 200 = accepted, 409 = would exceed the cap. Anything else is an error.
      if ((res.status === 200 || res.status === 409) && typeof body.accepted === "boolean" && typeof body.redeemedMicros === "number") {
        return { accepted: body.accepted, redeemedMicros: body.redeemedMicros };
      }
      throw new Error(`redeem: HTTP ${res.status}: ${typeof body.error === "string" ? body.error : "unexpected response"}`);
    },

    async redeemedMicros(key: string): Promise<number> {
      const parts = parseMandateRedemptionKey(key);
      if (!parts) {
        throw new Error("httpRedemptionStore.redeemedMicros takes mandateRedemptionKey(mandate), not a bare mandateId");
      }
      const res = await withTimeout(timeoutMs, (signal) =>
        doFetch(
          `${root}/v1/mandates/${encodeURIComponent(parts.mandateId)}/redemptions?grantor=${encodeURIComponent(parts.grantor)}`,
          { headers, signal }
        )
      );
      const body = (await res.json().catch(() => ({}))) as { redeemedMicros?: unknown; error?: unknown };
      if (!res.ok || typeof body.redeemedMicros !== "number") {
        throw new Error(`redemptions: HTTP ${res.status}: ${typeof body.error === "string" ? body.error : "unexpected response"}`);
      }
      return body.redeemedMicros;
    },
  };
}
