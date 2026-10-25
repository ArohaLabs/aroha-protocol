// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — Blockchain Registry Implementation (Layer 2)
 *
 * Wraps the ArohaRegistry Solidity contract using ethers.js v6.
 * Implements IArohaRegistry against an EVM-compatible blockchain.
 *
 * This is ONE of three conformant registry implementations:
 *   - ArohaRegistryContract  ← this file (blockchain — trustless, permissionless)
 *   - ArohaHttpRegistry      ← http-registry.ts (managed SaaS or self-hosted)
 *   - (self-hosted HTTP server implementing the same REST API)
 *
 * Use ArohaHttpRegistry for enterprise deployments where blockchain is not
 * required or desired. Use this class when trustless, on-chain guarantees
 * are specifically needed (e.g. permissionless public registries).
 */

import { ethers } from "ethers";
import { type AgentRecord, type IArohaRegistry, type RegisterOptions } from "./types.js";

// ─── ABI (matches ArohaRegistry.sol interface) ─────────────────────────────────

const REGISTRY_ABI = [
  // Registration
  "function register(bytes32 didHash, string calldata manifestCID, bytes calldata publicKey) external payable",
  "function deactivate(bytes32 didHash) external",
  "function updateManifest(bytes32 didHash, string calldata newCID) external",

  // Queries
  "function resolveByDID(bytes32 didHash) external view returns (tuple(bytes32 didHash, address ownerAddress, string manifestCID, bytes publicKey, uint256 stakedWei, uint32 reputationScore, bool active, uint256 registeredAt, uint256 lastUpdatedAt))",
  "function queryByCapability(bytes32[] calldata capabilityHashes) external view returns (tuple(bytes32 didHash, address ownerAddress, string manifestCID, bytes publicKey, uint256 stakedWei, uint32 reputationScore, bool active, uint256 registeredAt, uint256 lastUpdatedAt)[])",
  "function getMinStake() external view returns (uint256)",

  // Events
  "event AgentRegistered(bytes32 indexed didHash, address indexed owner, string manifestCID)",
  "event AgentDeactivated(bytes32 indexed didHash)",
  "event ManifestUpdated(bytes32 indexed didHash, string newCID)",
  "event ReputationUpdated(bytes32 indexed didHash, uint32 newScore)",
];

// ─── Contract wrapper ─────────────────────────────────────────────────────────

export class ArohaRegistryContract implements IArohaRegistry {
  private readonly contract: ethers.Contract;
  private readonly provider: ethers.JsonRpcProvider;

  constructor(
    /** RPC endpoint URL (e.g. Polygon PoS mainnet or testnet) */
    rpcUrl: string,
    /** Deployed ArohaRegistry contract address */
    contractAddress: string,
    /** Optional signer for write operations (registration, deactivation) */
    private readonly signer?: ethers.Wallet
  ) {
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
    const runner = signer?.connect(this.provider) ?? this.provider;
    this.contract = new ethers.Contract(contractAddress, REGISTRY_ABI, runner);
  }

  // ─── Write operations (require signer) ───────────────────────────────────────

  /**
   * Register a new agent on-chain.
   * Implements IArohaRegistry.register — stakeWei is read from options.stakeWei.
   * If omitted, the contract's minimum stake is fetched and used automatically.
   *
   * @param did        Agent DID string (will be hashed to bytes32)
   * @param manifestCID  IPFS CID of the signed capability manifest
   * @param publicKey  Ed25519 or PQ public key bytes
   * @param options    { stakeWei?: bigint } — defaults to on-chain minimum
   */
  async register(
    did: string,
    manifestCID: string,
    publicKey: Uint8Array,
    options?: RegisterOptions
  ): Promise<void> {
    this.requireSigner();
    const stakeWei = options?.stakeWei ?? (await this.getMinStake());
    const didHash = hashDID(did);
    const tx = await this.contract["register"](
      didHash,
      manifestCID,
      publicKey,
      { value: stakeWei }
    );
    await tx.wait();
  }

  /** Deactivate an agent on-chain, returning its stake. */
  async deactivate(did: string): Promise<void> {
    this.requireSigner();
    const tx = await this.contract["deactivate"](hashDID(did));
    await tx.wait();
  }

  /** Update the manifest CID for an existing agent. */
  async updateManifest(did: string, newManifestCID: string): Promise<void> {
    this.requireSigner();
    const tx = await this.contract["updateManifest"](hashDID(did), newManifestCID);
    await tx.wait();
  }

  // ─── Read operations ──────────────────────────────────────────────────────────

  /**
   * Resolve an agent record by DID.
   * Returns null if the agent is not registered.
   */
  async resolveByDID(did: string): Promise<AgentRecord | null> {
    const didHash = hashDID(did);
    try {
      const raw = await this.contract["resolveByDID"](didHash);
      return decodeRecord(raw);
    } catch {
      return null;
    }
  }

  /**
   * Query agents by capability IDs.
   * Returns all active agents that declare at least one of the given capabilities.
   *
   * @param capabilityIds  Array of capability ID strings (e.g. ["book-flight", "search-hotels"])
   */
  async queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]> {
    const hashes = capabilityIds.map(hashCapability);
    const raw: unknown[] = await this.contract["queryByCapability"](hashes);
    return (raw as unknown[])
      .map((r) => decodeRecord(r))
      .filter((r) => r.active);
  }

  /**
   * Get the minimum stake required for registration.
   */
  async getMinStake(): Promise<bigint> {
    return this.contract["getMinStake"]() as Promise<bigint>;
  }

  // ─── Event listeners ──────────────────────────────────────────────────────────

  /**
   * Subscribe to AgentRegistered events.
   */
  onAgentRegistered(
    callback: (didHash: string, owner: string, manifestCID: string) => void
  ): void {
    this.contract.on(
      "AgentRegistered",
      (didHash: string, owner: string, manifestCID: string) =>
        callback(didHash, owner, manifestCID)
    );
  }

  removeAllListeners(): void {
    this.contract.removeAllListeners();
  }

  // ─── Private ──────────────────────────────────────────────────────────────────

  private requireSigner(): void {
    if (!this.signer) throw new Error("ArohaRegistryContract: signer required for write operations");
  }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/** Produce the bytes32 didHash used on-chain from a DID string. */
export function hashDID(did: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(did));
}

/** Produce the bytes32 capability hash used for on-chain indexing. */
export function hashCapability(capabilityId: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(capabilityId));
}

function decodeRecord(raw: unknown): AgentRecord {
  const r = raw as {
    didHash: string;
    ownerAddress: string;
    manifestCID: string;
    publicKey: Uint8Array;
    stakedWei: bigint;
    reputationScore: number;
    active: boolean;
    registeredAt: bigint;
    lastUpdatedAt: bigint;
  };
  return {
    didHash: r.didHash,
    ownerAddress: r.ownerAddress,
    manifestCID: r.manifestCID,
    publicKeyB64: Buffer.from(r.publicKey).toString("base64url"),
    stakedWei: r.stakedWei,
    reputationScore: Number(r.reputationScore),
    active: r.active,
    registeredAt: Number(r.registeredAt),
    lastUpdatedAt: Number(r.lastUpdatedAt),
  };
}
