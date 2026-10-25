// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * MCP on the wire for wrapMcp(): a Streamable HTTP MCP endpoint (protocol
 * revision 2026-07-28, with the SDK's stateless fallback for 2025-era
 * clients) that exposes the wrapped tools behind the same mandate gate as the
 * Aroha-envelope endpoint.
 *
 * ── Mandate carriage convention ─────────────────────────────────────────────
 * A tools/call carries its mandate in the request `_meta` under the key
 * `"aroha/mandate"` (MCP reserves un-prefixed and `io.modelcontextprotocol/`
 * keys; `aroha/` is this project's prefix):
 *
 *   "_meta": {
 *     "aroha/mandate": {
 *       "token":   "<mandate token>",
 *       "holder":  "did:aroha:…",        // the mandate's grantee, presenting it
 *       "nonce":   "<random, single use>",
 *       "expires": "<ISO 8601, ≤ 5 min ahead>",
 *       "proof":   "<base64url Ed25519 signature by the holder>"
 *     }
 *   }
 *
 * `proof` signs RFC 8785 JCS of
 *   { purpose: "aroha.mcp-mandate-presentation/v1", audience: <this agent's DID>,
 *     tool, argsSha256, mandateId, holder, nonce, expires }
 * so a token seen on the wire cannot be replayed for another tool, other
 * arguments, another server, or a second time. Build it with
 * `presentMandate()`. A mandate token on its own is never accepted: without
 * the holder's proof it would be a bearer credential.
 */

import { createHash, randomUUID } from "node:crypto";
import * as ed from "@noble/ed25519";
import { canonicalizeJcs, type PublicKeyResolver } from "@aroha-sdk/core";

export const MANDATE_META_KEY = "aroha/mandate";
export const MANDATE_PRESENTATION_PURPOSE = "aroha.mcp-mandate-presentation/v1";
const MAX_PRESENTATION_TTL_MS = 5 * 60_000;

export interface MandatePresentation {
  token: string;
  holder: string;
  nonce: string;
  expires: string;
  proof: string;
}

/** SHA-256 hex of the JCS canonical arguments. */
export function argsDigest(args: unknown): string {
  return createHash("sha256").update(canonicalizeJcs(args ?? {}), "utf8").digest("hex");
}

function mandateIdOf(token: string): string {
  const raw = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as { mandate?: { mandateId?: unknown } };
  if (typeof raw?.mandate?.mandateId !== "string") throw new Error("malformed mandate token");
  return raw.mandate.mandateId;
}

function presentationBytes(p: Omit<MandatePresentation, "proof" | "token"> & { audience: string; tool: string; argsSha256: string; mandateId: string }): Uint8Array {
  return new TextEncoder().encode(canonicalizeJcs({
    purpose: MANDATE_PRESENTATION_PURPOSE,
    audience: p.audience,
    tool: p.tool,
    argsSha256: p.argsSha256,
    mandateId: p.mandateId,
    holder: p.holder,
    nonce: p.nonce,
    expires: p.expires,
  }));
}

/**
 * Build the `_meta` for a tools/call that presents `token` as `holderDid`
 * to the agent `audience` (its DID) for exactly this tool and arguments.
 */
export async function presentMandate(input: {
  token: string;
  holderDid: string;
  holderPrivateKey: Uint8Array;
  audience: string;
  tool: string;
  args: Record<string, unknown>;
  ttlMs?: number;
}): Promise<{ [MANDATE_META_KEY]: MandatePresentation }> {
  const nonce = randomUUID();
  const expires = new Date(Date.now() + Math.min(input.ttlMs ?? 60_000, MAX_PRESENTATION_TTL_MS)).toISOString();
  const bytes = presentationBytes({
    audience: input.audience, tool: input.tool, argsSha256: argsDigest(input.args),
    mandateId: mandateIdOf(input.token), holder: input.holderDid, nonce, expires,
  });
  const proof = Buffer.from(await ed.signAsync(bytes, input.holderPrivateKey)).toString("base64url");
  return { [MANDATE_META_KEY]: { token: input.token, holder: input.holderDid, nonce, expires, proof } };
}

/** Single-use nonce memory, pruned by expiry. */
export class PresentationNonces {
  private readonly seen = new Map<string, number>();
  claim(nonce: string, expiresMs: number): boolean {
    const now = Date.now();
    for (const [n, exp] of this.seen) if (exp < now) this.seen.delete(n);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiresMs);
    return true;
  }
}

/**
 * Verify a presentation for (audience, tool, args). Returns the holder DID and
 * token on success. Does NOT verify the mandate itself — the caller runs the
 * mandate gate with the returned holder as the expected grantee.
 */
export async function verifyPresentation(
  value: unknown,
  ctx: { audience: string; tool: string; args: unknown; resolvePublicKey: PublicKeyResolver; nonces: PresentationNonces },
): Promise<{ ok: true; holder: string; token: string } | { ok: false; reason: string }> {
  if (!value || typeof value !== "object") return { ok: false, reason: `No mandate presented (_meta["${MANDATE_META_KEY}"] missing)` };
  const p = value as Partial<MandatePresentation>;
  for (const k of ["token", "holder", "nonce", "expires", "proof"] as const) {
    if (typeof p[k] !== "string" || p[k]!.length === 0) return { ok: false, reason: `Mandate presentation is missing ${k}` };
  }
  const expiresMs = Date.parse(p.expires!);
  const now = Date.now();
  if (Number.isNaN(expiresMs) || expiresMs < now) return { ok: false, reason: "Mandate presentation expired" };
  if (expiresMs - now > MAX_PRESENTATION_TTL_MS + 30_000) return { ok: false, reason: "Mandate presentation lifetime too long" };
  let mandateId: string;
  try {
    mandateId = mandateIdOf(p.token!);
  } catch {
    return { ok: false, reason: "Malformed mandate token" };
  }
  let key: Uint8Array | null = null;
  try {
    key = await ctx.resolvePublicKey(p.holder!);
  } catch {
    key = null;
  }
  if (!key) return { ok: false, reason: `Cannot resolve public key for holder ${p.holder}` };
  let valid = false;
  try {
    const sig = new Uint8Array(Buffer.from(p.proof!, "base64url"));
    valid = sig.length === 64 && await ed.verifyAsync(sig, presentationBytes({
      audience: ctx.audience, tool: ctx.tool, argsSha256: argsDigest(ctx.args),
      mandateId, holder: p.holder!, nonce: p.nonce!, expires: p.expires!,
    }), key);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "Mandate presentation proof does not verify for this agent, tool and arguments" };
  // Claim the nonce only after the proof verifies, so an unauthenticated
  // request cannot burn someone else's nonce.
  if (!ctx.nonces.claim(p.nonce!, expiresMs)) return { ok: false, reason: "Mandate presentation already used" };
  return { ok: true, holder: p.holder!, token: p.token! };
}
