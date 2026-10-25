// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `@aroha-sdk/credentials/testing` — TEST-ONLY builders for HTTP mandate
 * presentations that a correct client would never send.
 *
 * DO NOT IMPORT THIS IN PRODUCTION CODE. Nothing here is needed to present or
 * verify a mandate; it exists so a server's own test suite can check that
 * verifyHttpMandateRequest / verifyHttpSpendRequest refuse what they must
 * (a presenter who is not the grantee, a proof by the wrong key, a tampered
 * member, an over-long lifetime) without reverse-engineering the header
 * format or importing an Ed25519 library. It is a separate entry point, not
 * re-exported from the package root or `/mandates`.
 *
 *   import { presentMandateHttpUnchecked, buildHttpPresentationHeader } from "@aroha-sdk/credentials/testing";
 */

import * as ed from "@noble/ed25519";
import { canonicalizeJcs } from "./jcs.js";
import {
  HTTP_MANDATE_HEADER,
  HTTP_PRESENTATION_MAX_TTL_MS,
  httpBodySha256,
  httpMethodForProof,
  httpPresentationSigningPayload,
  httpRequestTarget,
  type HttpRequestBody,
  type PresentMandateHttpInput,
} from "./http-mandate.js";

const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString("base64url");

/** base64url(JCS(members)) — any object, including ones with missing, extra or mistyped members. */
export function encodeHttpPresentation(members: unknown): string {
  return b64u(canonicalizeJcs(members));
}

/** The leaf mandateId of a token, or null when it is not decodable. No verification. */
function leafMandateId(token: string): string | null {
  try {
    const raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as { mandate?: { mandateId?: unknown } };
    return typeof raw?.mandate?.mandateId === "string" ? raw.mandate.mandateId : null;
  } catch {
    return null;
  }
}

export interface BuildHttpPresentationInput {
  /** Any string — need not be a valid token. */
  token: string;
  /** The `holder` member. Need not be the token's grantee, nor the signer. */
  holder: string;
  /** Ed25519 private key (32 bytes) that signs the proof. Any key. */
  signerPrivateKey: Uint8Array;
  audience: string;
  /** Signed verbatim (not upper-cased) — pass "POST", or something wrong on purpose. */
  method: string;
  /** Request URL; its target is computed with httpRequestTarget. Ignored when `target` is given. */
  url?: string;
  /** Request target signed verbatim. */
  target?: string;
  /** Body whose hash is signed. Ignored when `bodySha256` is given. */
  body?: HttpRequestBody;
  /** Body hash signed verbatim. */
  bodySha256?: string;
  /** mandateId signed. Default: the token's leaf mandateId (required if the token is not decodable). */
  mandateId?: string;
  /** Default: a fixed-length random base64url nonce. */
  nonce?: string;
  /** `expires` member, verbatim. Default: now + ttlMs. */
  expires?: string;
  /** Default Date.now(). */
  now?: number;
  /** Default 60 s. NOT capped — use it to build an over-long lifetime. */
  ttlMs?: number;
  /** Replace the proof with this string after signing. */
  proof?: string;
  /** Members added to (or overriding) the five header members after signing. */
  extraMembers?: Record<string, unknown>;
  /** Members removed from the header after signing. */
  omitMembers?: ("token" | "holder" | "nonce" | "expires" | "proof")[];
}

/**
 * Build an `Aroha-Mandate` header from arbitrary fields, signed with an
 * arbitrary key. Every field a verifier checks can be set to a wrong value;
 * the proof is a real Ed25519 signature over whatever was supplied, so a test
 * isolates exactly the field it changed. Returns `{ "Aroha-Mandate": value }`.
 */
export async function buildHttpPresentationHeader(input: BuildHttpPresentationInput): Promise<{ [HTTP_MANDATE_HEADER]: string }> {
  const now = input.now ?? Date.now();
  const nonce = input.nonce ?? b64u(crypto.getRandomValues(new Uint8Array(16)));
  const expires = input.expires ?? new Date(now + (input.ttlMs ?? 60_000)).toISOString();
  const target = input.target ?? httpRequestTarget(input.url ?? "/");
  const bodySha256 = input.bodySha256 ?? httpBodySha256(input.body);
  const mandateId = input.mandateId ?? leafMandateId(input.token);
  if (mandateId === null) throw new TypeError("buildHttpPresentationHeader: the token is not decodable; pass mandateId");

  const payload = httpPresentationSigningPayload({
    audience: input.audience, method: input.method, target, bodySha256, mandateId, holder: input.holder, nonce, expires,
  });
  const proof = input.proof ?? b64u(await ed.signAsync(new TextEncoder().encode(payload), input.signerPrivateKey));
  const members: Record<string, unknown> = { token: input.token, holder: input.holder, nonce, expires, proof, ...input.extraMembers };
  for (const k of input.omitMembers ?? []) delete members[k];
  return { [HTTP_MANDATE_HEADER]: encodeHttpPresentation(members) };
}

/**
 * presentMandateHttp without the client-side guard that `holderDid` is the
 * token's grantee (and without requiring a decodable token when `mandateId`
 * can be read from it). Everything else — method upper-casing, target
 * normalisation, TTL cap — is as presentMandateHttp does it, so the header
 * differs from an honest one only in who presents it.
 */
export async function presentMandateHttpUnchecked(
  input: PresentMandateHttpInput & { mandateId?: string },
): Promise<{ [HTTP_MANDATE_HEADER]: string }> {
  const now = input.now ?? Date.now();
  const ttl = Math.min(input.ttlMs ?? 60_000, HTTP_PRESENTATION_MAX_TTL_MS);
  return buildHttpPresentationHeader({
    token: input.token, holder: input.holderDid, signerPrivateKey: input.holderPrivateKey,
    audience: input.audience, method: httpMethodForProof(input.method), target: httpRequestTarget(input.url),
    body: input.body, mandateId: input.mandateId, nonce: input.nonce, now, ttlMs: ttl,
  });
}
