// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — HTTP Registry Implementation (Layer 2)
 *
 * Implements IArohaRegistry against a REST API endpoint — either:
 *   1. Aroha Managed Registry  (AROHA_MANAGED_REGISTRY_URL from @aroha-sdk/core) — the commercial SaaS
 *   2. Self-hosted registry   — any server running the ArohaRegistryServer
 *
 * Enterprises interact with this client. They never need to touch a blockchain,
 * hold cryptocurrency, or pay gas fees.  Authentication is via API key (Bearer
 * token).  Staking / Sybil resistance is handled by the registry operator
 * through subscription tiers and org-level verification.
 *
 * API surface exposed by any conformant Aroha HTTP Registry server:
 *
 *   POST   /v1/agents                       — register
 *   DELETE /v1/agents/:didHash              — deactivate
 *   PUT    /v1/agents/:didHash/manifest     — update manifest
 *   GET    /v1/agents/:didHash              — resolve by DID
 *   GET    /v1/agents?capabilities=a,b,c   — query by capability
 *   GET    /v1/kel/:did                     — Key Event Log (httpKelSource)
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import type { KelEvent, KelSource } from "@aroha-sdk/core/identity";
import { AROHA_MANAGED_REGISTRY_URL, assertSecureEndpoint, resolveRegistryUrl } from "@aroha-sdk/core/endpoints";
import {
  assertRegistrationKey,
  registrationNeedsProof,
  signRegistrationChallenge,
} from "./registration-proof.js";
import {
  type IArohaRegistry,
  type AgentRecord,
  type RegisterOptions,
} from "./types.js";

// ─── Client ───────────────────────────────────────────────────────────────────

export interface ArohaHttpRegistryOptions {
  /**
   * Base URL of the registry API.
   * Defaults to the Aroha managed registry.
   * Self-hosted: set to e.g. "https://registry.acme.internal"
   */
  baseUrl?: string;
  /**
   * Ordered list of fallback registry URLs tried when the primary is
   * unreachable or returns a 5xx error. Client errors (4xx) are never
   * retried — they indicate a caller mistake.
   *
   * Example: use a self-hosted mirror as backup for the managed registry.
   */
  fallbackUrls?: string[];
  /**
   * API key (Bearer token).  Issued by the registry operator.
   * For the managed registry, obtain from the registry operator's dashboard.
   */
  apiKey: string;
  /**
   * DEVELOPMENT ONLY: allow http:// registry URLs on non-loopback hosts. The
   * API key rides every request, and resolved records decide which public
   * key an agent is trusted under — neither may cross the network in clear.
   */
  allowInsecureHttp?: boolean;
  /**
   * Optional fetch implementation.  Defaults to the global fetch (Node 22+).
   * Inject a custom implementation in test environments.
   */
  fetch?: typeof globalThis.fetch;
}

// Re-exported from @aroha-sdk/core so every package names the SAME host. The
// value used to be the registry.aroha-labs.com alias, which does not resolve;
// it is now the deployed workers.dev host (see core's endpoints module).
export { AROHA_MANAGED_REGISTRY_URL };
/** @deprecated Use AROHA_MANAGED_REGISTRY_URL */
export const Aroha_MANAGED_REGISTRY_URL = AROHA_MANAGED_REGISTRY_URL;

export class ArohaHttpRegistry implements IArohaRegistry {
  private readonly urls: readonly string[];
  private readonly apiKey: string;
  private readonly fetch: typeof globalThis.fetch;

  constructor(opts: ArohaHttpRegistryOptions) {
    const primary = resolveRegistryUrl(opts.baseUrl);
    const fallbacks = (opts.fallbackUrls ?? []).map(u => u.replace(/\/$/, ""));
    for (const u of [primary, ...fallbacks]) {
      assertSecureEndpoint(u, { allowInsecureHttp: opts.allowInsecureHttp, label: "registry URL" });
    }
    this.urls   = [primary, ...fallbacks];
    this.apiKey = opts.apiKey;
    this.fetch  = opts.fetch ?? globalThis.fetch;
  }

  // ─── IArohaRegistry ──────────────────────────────────────────────────────────

  async register(
    did: string,
    manifestCID: string,
    publicKey: Uint8Array,
    options?: RegisterOptions
  ): Promise<void> {
    const needsProof = registrationNeedsProof(did);
    const signer = options?.signer;
    if (needsProof && !signer) {
      throw new Error(
        `ArohaHttpRegistry.register(${did}): options.signer is required — the registry only registers a DID ` +
        `whose key the caller proves it holds (POST /v1/agents/challenge). Pass { signer: { privateKey } } ` +
        `or { signer: { sign } }.`
      );
    }
    await assertRegistrationKey(did, publicKey, signer);

    // The challenge is issued by — and only redeemable at — the server that
    // issued it, so each fallback attempt runs the whole exchange itself.
    // capabilityIds are no longer sent: the server indexes capabilities only
    // from the CID-verified manifest.
    await this.withFallback(async url => {
      const body: Record<string, unknown> = {
        did,
        manifestCID,
        publicKeyB64: Buffer.from(publicKey).toString("base64url"),
      };
      if (options?.endpointUrl) body.endpointUrl = options.endpointUrl;
      if (needsProof) {
        const challengeRes = await this.postTo(url, "/v1/agents/challenge", { did });
        const { nonce } = (await challengeRes.json()) as { nonce?: unknown };
        if (typeof nonce !== "string" || nonce.length === 0) {
          throw new RegistryHttpError(502, "registry returned no challenge nonce");
        }
        const sig = await signRegistrationChallenge(signer!, did, nonce);
        body.challengeNonce = nonce;
        body.challengeSignature = Buffer.from(sig).toString("base64url");
      }
      return this.postTo(url, "/v1/agents", body);
    });
  }

  async deactivate(did: string): Promise<void> {
    const didHash = hashDID(did);
    await this.withFallback(url => this.deleteTo(url, `/v1/agents/${didHash}`));
  }

  async updateManifest(did: string, newCID: string): Promise<void> {
    const didHash = hashDID(did);
    await this.withFallback(url => this.putTo(url, `/v1/agents/${didHash}/manifest`, { manifestCID: newCID }));
  }

  async resolveByDID(did: string): Promise<AgentRecord | null> {
    const didHash = hashDID(did);
    return this.withFallback(async url => {
      const res = await this.getFrom(url, `/v1/agents/${didHash}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
      return (await res.json()) as AgentRecord;
    });
  }

  async queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]> {
    const param = capabilityIds.map(encodeURIComponent).join(",");
    return this.withFallback(async url => {
      const res = await this.getFrom(url, `/v1/agents?capabilities=${param}`);
      if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
      return (await res.json()) as AgentRecord[];
    });
  }

  // ─── Fallback orchestration ───────────────────────────────────────────────────

  /**
   * Try each URL in order. Retries on network errors and 5xx responses.
   * Throws immediately on 4xx — those are caller errors, not infrastructure failures.
   */
  private async withFallback<T>(fn: (baseUrl: string) => Promise<T>): Promise<T> {
    let lastError: unknown;
    for (const url of this.urls) {
      try {
        return await fn(url);
      } catch (err) {
        if (err instanceof RegistryHttpError && err.statusCode >= 400 && err.statusCode < 500) {
          throw err;
        }
        lastError = err;
      }
    }
    throw lastError;
  }

  // ─── HTTP primitives ─────────────────────────────────────────────────────────

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
    };
  }

  private async postTo(base: string, path: string, body: unknown): Promise<Response> {
    const res = await this.fetch(`${base}${path}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
    return res;
  }

  private async putTo(base: string, path: string, body: unknown): Promise<Response> {
    const res = await this.fetch(`${base}${path}`, {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
    return res;
  }

  private async deleteTo(base: string, path: string): Promise<Response> {
    const res = await this.fetch(`${base}${path}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
    return res;
  }

  private getFrom(base: string, path: string): Promise<Response> {
    return this.fetch(`${base}${path}`, { headers: this.headers() });
  }
}

// ─── KEL source ───────────────────────────────────────────────────────────────

export interface HttpKelSourceOptions {
  /** DEVELOPMENT ONLY: allow http:// registry URLs on non-loopback hosts. */
  allowInsecureHttp?: boolean;
  /** Mirrors tried in order on a network error or 5xx (never on 4xx/409). */
  fallbackUrls?: string[];
  /** fetch implementation (tests). Default globalThis.fetch. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in ms. Default 10 000. */
  timeoutMs?: number;
}

/**
 * A core `KelSource` backed by a registry's GET /v1/kel/:did.
 *
 * WHY: every KEL-aware verifier (verifyMandateChain's kelSource, the
 * mcp-bridge person-root gate, kelKeyResolver) takes a KelSource, but the
 * SDK shipped no way to fetch one from the registry that stores them, so each
 * integrator hand-wrote the fetch. This is that fetch, with the answers that
 * matter for safety kept distinct:
 *   - 200 → the stored events. The CALLER re-verifies them (resolveKelState):
 *     a registry cannot forge a log, only withhold one, so nothing here
 *     trusts it;
 *   - 404 → null (no log known);
 *   - 409 → THROWS: the registry has recorded duplicity for the DID, or knows
 *     its stored log is stale behind the controller's seals. Returning null
 *     or the stale events would let a verifier act on a log the registry
 *     itself says could hide a revocation; throwing makes it fail closed;
 *   - other 4xx → throws; network error / 5xx → next fallback, then throws.
 * Pair it with a KelStore (highest-seen memory) in long-lived verifiers so a
 * registry that later serves a SHORTER log cannot roll you back.
 */
export function httpKelSource(
  registryUrl?: string,
  options: HttpKelSourceOptions = {}
): KelSource {
  const urls = [resolveRegistryUrl(registryUrl), ...(options.fallbackUrls ?? [])].map((u) => u.replace(/\/+$/, ""));
  // A KEL decides which key a DID currently has; a tampered one over
  // cleartext would let an on-path party substitute a key.
  for (const u of urls) assertSecureEndpoint(u, { allowInsecureHttp: options.allowInsecureHttp, label: "registry URL" });
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

  return async (did: string): Promise<KelEvent[] | null> => {
    let lastError: unknown;
    for (const base of urls) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      let res: Response;
      try {
        res = await doFetch(`${base}/v1/kel/${encodeURIComponent(did)}`, {
          headers: { Accept: "application/json" },
          signal: ctrl.signal,
        });
      } catch (err) {
        lastError = err;
        continue;
      } finally {
        clearTimeout(timer);
      }
      if (res.status === 404) return null;
      if (res.status >= 500) {
        lastError = new RegistryHttpError(res.status, await res.text());
        continue;
      }
      if (!res.ok) throw new RegistryHttpError(res.status, await res.text());
      const body = (await res.json()) as { did?: unknown; events?: unknown };
      if (body.did !== undefined && body.did !== did) {
        throw new Error(`registry answered GET /v1/kel for ${String(body.did)}, not ${did}`);
      }
      if (!Array.isArray(body.events)) throw new Error(`registry returned no events array for ${did}`);
      return body.events as KelEvent[];
    }
    throw lastError ?? new Error("httpKelSource: no registry URL");
  };
}

// ─── Error ────────────────────────────────────────────────────────────────────

export class RegistryHttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: string
  ) {
    super(`Aroha Registry HTTP ${statusCode}: ${body}`);
    this.name = "RegistryHttpError";
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/** Compute keccak256(did) as a 0x-prefixed hex string — matches on-chain logic. */
function hashDID(did: string): string {
  return "0x" + bytesToHex(keccak_256(new TextEncoder().encode(did)));
}
