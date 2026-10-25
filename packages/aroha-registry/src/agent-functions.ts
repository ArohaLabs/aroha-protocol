// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Thin functional wrappers around ArohaHttpRegistry / ArohaIpfsClient — the
 * simple registerAgent/resolveAgent/listAgents/resolveManifest shape this
 * package's README has described since its first version, which was never
 * actually implemented. `export * from` never surfaced them because they
 * didn't exist anywhere in src/ — every call site following the README threw
 * an import error.
 *
 * These are deliberately thin: no new behaviour, just the friendlier call
 * shape wrapped around the classes that already do the real work
 * (ArohaHttpRegistry, ArohaIpfsClient). Reach for those directly — via
 * ArohaDiscovery, for the on-chain contract backend — for anything these
 * don't cover.
 */

import { ArohaHttpRegistry } from "./http-registry.js";
import { ArohaIpfsClient } from "./ipfs.js";
import { canonicalizeMessage } from "@aroha-sdk/core";
import { resolveIpfsGateway } from "@aroha-sdk/core/endpoints";
import { verifyAsync } from "@noble/ed25519";
import { type AgentRecord, type CapabilityManifest, type DiscoveredAgent } from "./types.js";
import type { RegistrationSigner } from "./registration-proof.js";

/**
 * IPFS gateway used when no gatewayUrl is supplied — reads only, no pinning
 * credentials needed. Read at call time so AROHA_IPFS_GATEWAY can override it.
 */
const defaultGateway = (): string => resolveIpfsGateway();

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

// ─── registerAgent ──────────────────────────────────────────────────────────

export interface RegisterAgentOptions {
  did: string;
  manifestCID: string;
  /** Base64url-encoded Ed25519 public key (32 bytes). */
  publicKeyB64: string;
  /**
   * Registry API key. Required — registering a DID is a write, and the
   * registry rejects unauthenticated writes. (The version of this example
   * that shipped in the README before this fix omitted it; it was never
   * actually callable as written.)
   */
  apiKey: string;
  /** Registry base URL. Defaults to the managed Aroha registry. */
  registryUrl?: string;
  stakeWei?: bigint;
  /** @deprecated Ignored by the HTTP registry, which indexes capabilities from the verified manifest. */
  capabilityIds?: string[];
  /**
   * Proves possession of the agent key (required for every DID except a
   * rotatable did:aroha:E…): the raw 32-byte seed, or a signing callback.
   */
  signer?: RegistrationSigner;
  /** The agent's public endpoint URL. */
  endpointUrl?: string;
  /** Override the HTTP client — inject a test double, or add tracing/retry. */
  fetch?: typeof globalThis.fetch;
}

/** Register an agent so it can be discovered by DID or capability. */
export async function registerAgent(opts: RegisterAgentOptions): Promise<void> {
  const registry = new ArohaHttpRegistry({
    ...(opts.registryUrl ? { baseUrl: opts.registryUrl } : {}),
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    apiKey: opts.apiKey,
  });
  await registry.register(opts.did, opts.manifestCID, b64urlToBytes(opts.publicKeyB64), {
    stakeWei: opts.stakeWei,
    capabilityIds: opts.capabilityIds,
    ...(opts.signer ? { signer: opts.signer } : {}),
    ...(opts.endpointUrl ? { endpointUrl: opts.endpointUrl } : {}),
  });
}

// ─── resolveAgent / listAgents ──────────────────────────────────────────────
//
// Both return DiscoveredAgent (record + manifest + endpoint + publicKey), not
// the bare AgentRecord resolveByDID() gives you — AgentRecord alone has no
// endpointUrl or capabilities field, so it can't satisfy what the README's
// example actually does with the result (agent.endpointUrl). Getting there
// means fetching and verifying the IPFS manifest, same as ArohaDiscovery
// already does for the on-chain contract backend; this is that same
// fetch-verify-shape step, against an HTTP-resolved record instead.

interface ResolveOptions {
  registryUrl?: string;
  apiKey?: string;
  /** IPFS gateway to fetch manifests from. Defaults to a public read-only gateway. */
  gatewayUrl?: string;
  /** Override the HTTP client for the registry lookup — inject a test double, or add tracing/retry. */
  fetch?: typeof globalThis.fetch;
}

/**
 * Same check ArohaDiscovery.resolveAgent() runs for the on-chain contract
 * backend (its own private, unexported copy of this) — canonicalize the
 * manifest with its signature field excluded, verify against the record's
 * public key. Reimplemented here rather than imported because that copy is
 * private to ArohaDiscovery and coupled to the contract backend; the check
 * itself has nothing backend-specific about it.
 */
async function verifyManifestSignature(manifest: CapabilityManifest, publicKey: Uint8Array): Promise<boolean> {
  const { signature, ...body } = manifest;
  const canonical = canonicalizeMessage(body as unknown as Record<string, unknown>);
  const bytes = new TextEncoder().encode(canonical);
  try {
    const sigBytes = Buffer.from(signature, "base64url");
    return await verifyAsync(sigBytes, bytes, publicKey);
  } catch {
    return false;
  }
}

async function toDiscoveredAgent(
  record: AgentRecord,
  ipfs: ArohaIpfsClient,
  requiredCapabilities?: string[]
): Promise<DiscoveredAgent> {
  const manifest = await ipfs.fetchManifest(record.manifestCID);
  const publicKey = b64urlToBytes(record.publicKeyB64);

  const validSignature = await verifyManifestSignature(manifest, publicKey);
  if (!validSignature) {
    throw new Error(`Manifest signature verification failed for agent ${manifest.did}`);
  }

  if (requiredCapabilities?.length) {
    const have = new Set(manifest.capabilities.map((c) => c.id));
    const missing = requiredCapabilities.filter((id) => !have.has(id));
    if (missing.length > 0) {
      throw new Error(`Agent ${manifest.did} is missing capabilities: ${missing.join(", ")}`);
    }
  }

  return { record, manifest, endpoint: manifest.endpoint, publicKey };
}

/** Resolve a single agent by DID, including its manifest (endpoint, capabilities). Returns null if not found or deactivated. */
export async function resolveAgent(did: string, opts: ResolveOptions = {}): Promise<DiscoveredAgent | null> {
  const registry = new ArohaHttpRegistry({
    ...(opts.registryUrl ? { baseUrl: opts.registryUrl } : {}),
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    apiKey: opts.apiKey ?? "",
  });
  const record = await registry.resolveByDID(did);
  if (!record) return null;

  const ipfs = new ArohaIpfsClient({ type: "gateway", gatewayUrl: opts.gatewayUrl ?? defaultGateway() });
  return toDiscoveredAgent(record, ipfs);
}

export interface ListAgentsOptions extends ResolveOptions {
  /** Capability ID(s) the agent must expose. */
  capability: string | string[];
}

/**
 * List agents exposing the given capability. Each result's manifest is
 * fetched and signature-verified — an agent whose manifest fails to fetch or
 * verify is dropped from the results rather than surfaced as a partial or
 * untrusted record.
 */
export async function listAgents(opts: ListAgentsOptions): Promise<DiscoveredAgent[]> {
  const registry = new ArohaHttpRegistry({
    ...(opts.registryUrl ? { baseUrl: opts.registryUrl } : {}),
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    apiKey: opts.apiKey ?? "",
  });
  const capabilityIds = Array.isArray(opts.capability) ? opts.capability : [opts.capability];
  const records = await registry.queryByCapability(capabilityIds);

  const ipfs = new ArohaIpfsClient({ type: "gateway", gatewayUrl: opts.gatewayUrl ?? defaultGateway() });
  const settled = await Promise.allSettled(
    records.map((r) => toDiscoveredAgent(r, ipfs, capabilityIds))
  );
  return settled
    .filter((r): r is PromiseFulfilledResult<DiscoveredAgent> => r.status === "fulfilled")
    .map((r) => r.value);
}

// ─── resolveManifest ────────────────────────────────────────────────────────

/** Fetch a capability manifest directly from IPFS by CID. No signature verification — use resolveAgent()/listAgents() when you need a trusted, verified manifest. */
export async function resolveManifest(cid: string, opts: { gatewayUrl?: string } = {}): Promise<CapabilityManifest> {
  const ipfs = new ArohaIpfsClient({ type: "gateway", gatewayUrl: opts.gatewayUrl ?? defaultGateway() });
  return ipfs.fetchManifest(cid);
}
