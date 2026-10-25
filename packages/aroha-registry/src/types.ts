// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — Shared Types
 *
 * Types that mirror the on-chain AgentRecord struct and the off-chain
 * Capability Manifest format defined in the protocol spec.
 */

// ─── On-chain record (mirrors ArohaRegistry.sol AgentRecord struct) ────────────

export interface AgentRecord {
  /** keccak256 hash of the DID string */
  didHash: string;
  /** Ethereum address of the operator who registered the agent */
  ownerAddress: string;
  /** IPFS CID of the full capability manifest */
  manifestCID: string;
  /** Base64url-encoded Ed25519 public key (32 bytes) */
  publicKeyB64: string;
  /** Economic stake in wei */
  stakedWei: bigint;
  /** Reputation score 0–10000 */
  reputationScore: number;
  /** Whether the agent is currently active */
  active: boolean;
  /** Unix timestamp of registration */
  registeredAt: number;
  /** Unix timestamp of last manifest update */
  lastUpdatedAt: number;
}

// ─── Off-chain Capability Manifest (stored on IPFS) ──────────────────────────

export interface CapabilityDefinition {
  id: string;
  version: string;
  description?: string;
  /** JSON Schema for input parameters */
  inputSchema: Record<string, unknown>;
  /** JSON Schema for output result */
  outputSchema: Record<string, unknown>;
  /** Whether the capability is async (uses WebSocket streaming) */
  async: boolean;
  /** Maximum response time in ms */
  maxResponseMs: number;
  /** Trust level required to invoke this capability (0–4) */
  requiredTrustLevel: 0 | 1 | 2 | 3 | 4;
  pricing: {
    model: "free" | "per-transaction" | "subscription";
    fee?: string;
    currency?: string;
  };
  /**
   * Whether this capability participates in sagas.
   * "participant" = implements ArohaReserve/Commit/Cancel.
   * "none" = read-only, no reservation needed.
   */
  sagaRole: "none" | "participant";
  /** ID of the reserve capability (required if sagaRole = "participant") */
  reserveCapabilityId?: string;
  /** ID of the cancel/compensate capability (required if sagaRole = "participant") */
  cancelCapabilityId?: string;
}

export interface CapabilityManifest {
  /** Protocol version */
  aroha: "1.0";
  /** Agent DID */
  did: string;
  /** Human-readable name */
  name: string;
  description?: string;
  /** Semantic version of this manifest */
  version: string;
  /** Aroha endpoint URL where this agent receives messages (e.g. https://agent.acme.com/aroha/v1) */
  endpoint: string;
  /** All capabilities this agent exposes */
  capabilities: CapabilityDefinition[];
  /** Supported protocols (e.g. ["aroha/1.0", "mcp/2024-11", "a2a/1.0"]) */
  protocols: string[];
  /** DIDs of organizations that have issued VCs for this agent */
  trustAnchors?: string[];
  /** Uptime SLA (0–1) */
  uptime?: number;
  /** ISO8601 timestamp of manifest creation */
  createdAt: string;
  /** JWS signature of the manifest body (signed by agent's key) */
  signature: string;
}

// ─── Pluggable registry interface ────────────────────────────────────────────
//
// Any conformant registry implementation (blockchain, HTTP managed, self-hosted)
// MUST satisfy this interface.  The rest of the SDK depends only on this type —
// not on any specific backend.

export interface IArohaRegistry {
  /**
   * Register a new agent.
   * @param did        Full DID string (e.g. "did:aroha:my-agent")
   * @param manifestCID IPFS CID of the signed capability manifest
   * @param publicKey  Raw Ed25519 public key bytes (32 bytes) or PQ key bytes
   * @param options    Backend-specific options (stake amount, API key, etc.)
   */
  register(
    did: string,
    manifestCID: string,
    publicKey: Uint8Array,
    options?: RegisterOptions
  ): Promise<void>;

  /** Permanently deactivate a DID. Irreversible. */
  deactivate(did: string): Promise<void>;

  /** Replace the on-record manifest CID (after uploading a new manifest to IPFS). */
  updateManifest(did: string, newCID: string): Promise<void>;

  /**
   * Resolve a DID to its AgentRecord.
   * Returns null if not found or deactivated.
   */
  resolveByDID(did: string): Promise<AgentRecord | null>;

  /**
   * Find agents that expose ALL of the requested capabilities.
   * @param capabilityIds  Array of capability ID strings (e.g. ["book-flight"])
   */
  queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]>;
}

/** Options accepted by registry implementations at registration time. */
export interface RegisterOptions {
  /** Blockchain registries: amount to stake in wei (defaults to minimum). */
  stakeWei?: bigint;
  /** HTTP registries: subscription tier or API key for the managed service. */
  apiKey?: string;
  /**
   * Capability IDs extracted from the manifest at pin time. Used by the
   * in-memory and contract registries. NOT sent by ArohaHttpRegistry: the
   * Aroha registry server no longer accepts capabilityIds in the body — it
   * indexes capabilities only from the CID-verified manifest.
   */
  capabilityIds?: string[];
  /**
   * HTTP registries: proves possession of the agent key (POST
   * /v1/agents/challenge → sign → register). Required for every DID except
   * a rotatable did:aroha:E…; ArohaHttpRegistry.register throws without it.
   * See registration-proof.ts.
   */
  signer?: import("./registration-proof.js").RegistrationSigner;
  /** HTTP registries: the agent's public endpoint (http/https). */
  endpointUrl?: string;
  /** Any extra backend-specific fields. */
  [key: string]: unknown;
}

// ─── Discovery result ─────────────────────────────────────────────────────────

export interface DiscoveredAgent {
  record: AgentRecord;
  manifest: CapabilityManifest;
  /** Resolved Aroha endpoint URL from the DID Document */
  endpoint: string;
  /** Ed25519 public key bytes (decoded from record) */
  publicKey: Uint8Array;
}
