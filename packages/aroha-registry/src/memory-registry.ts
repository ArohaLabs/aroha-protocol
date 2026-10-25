// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * InMemoryRegistry — Private enterprise registry (no blockchain required)
 *
 * A fully conformant IArohaRegistry implementation backed by in-process Maps.
 * Designed for:
 *
 *   • Internal enterprise deployments (HR agent ↔ IT agent, same company)
 *   • Local development and integration testing
 *   • Private agent networks where a public blockchain is unnecessary
 *
 * Agents register directly — no IPFS CID required (pass any opaque string).
 * Pass capabilityIds in RegisterOptions so the registry can route discovery.
 *
 * Usage:
 *   const registry = new InMemoryRegistry();
 *
 *   await registry.register("did:aroha:jira-agent", "manifest-v1", pubKey, {
 *     capabilityIds: ["search-issues", "create-issue", "transition-issue"],
 *   });
 *
 *   const agents = await registry.queryByCapability(["create-issue"]);
 */

import { createHash } from "node:crypto";
import type { IArohaRegistry, AgentRecord, RegisterOptions } from "./types.js";

export interface InMemoryRegisterOptions extends RegisterOptions {
  /** Capability IDs this agent exposes — used to populate the capability index. */
  capabilityIds?: string[];
  /** Human-readable display name for the agent (optional; stored in record metadata). */
  displayName?: string;
  /** Initial reputation score (0–10000). Default: 5000 */
  initialReputationScore?: number;
  /** Override the auto-generated ownerAddress. Default: zero address */
  ownerAddress?: string;
}

export class InMemoryRegistry implements IArohaRegistry {
  /** didHash → AgentRecord */
  private readonly records = new Map<string, AgentRecord>();
  /** did (full string) → didHash */
  private readonly didToHash = new Map<string, string>();
  /** capabilityHash → Set of didHashes */
  private readonly capabilityIndex = new Map<string, Set<string>>();
  /** didHash → capability IDs (for deactivation cleanup) */
  private readonly didCapabilities = new Map<string, string[]>();

  private hashDID(did: string): string {
    return "0x" + createHash("sha256").update(did).digest("hex").slice(0, 40);
  }

  private hashCapability(capId: string): string {
    return "0x" + createHash("sha256").update(capId).digest("hex").slice(0, 40);
  }

  async register(
    did: string,
    manifestCID: string,
    publicKey: Uint8Array,
    options: InMemoryRegisterOptions = {}
  ): Promise<void> {
    const didHash = this.hashDID(did);
    const existing = this.records.get(didHash);

    const record: AgentRecord = {
      didHash,
      ownerAddress: options.ownerAddress ?? "0x0000000000000000000000000000000000000000",
      manifestCID,
      publicKeyB64: Buffer.from(publicKey).toString("base64url"),
      stakedWei: options.stakeWei ?? 0n,
      reputationScore: options.initialReputationScore ?? existing?.reputationScore ?? 5000,
      active: true,
      registeredAt: existing?.registeredAt ?? Date.now(),
      lastUpdatedAt: Date.now(),
    };

    this.records.set(didHash, record);
    this.didToHash.set(did, didHash);

    // Update capability index
    const capIds = options.capabilityIds ?? this.didCapabilities.get(didHash) ?? [];
    if (capIds.length > 0) {
      // Remove from old index entries first (re-register case)
      const old = this.didCapabilities.get(didHash) ?? [];
      for (const capId of old) {
        this.capabilityIndex.get(this.hashCapability(capId))?.delete(didHash);
      }
      // Add to new index entries
      for (const capId of capIds) {
        const capHash = this.hashCapability(capId);
        if (!this.capabilityIndex.has(capHash)) {
          this.capabilityIndex.set(capHash, new Set());
        }
        this.capabilityIndex.get(capHash)!.add(didHash);
      }
      this.didCapabilities.set(didHash, capIds);
    }
  }

  async deactivate(did: string): Promise<void> {
    const didHash = this.didToHash.get(did) ?? this.hashDID(did);
    const record = this.records.get(didHash);
    if (!record) return;

    record.active = false;
    record.lastUpdatedAt = Date.now();

    // Remove from capability index so it won't appear in discovery
    const caps = this.didCapabilities.get(didHash) ?? [];
    for (const capId of caps) {
      this.capabilityIndex.get(this.hashCapability(capId))?.delete(didHash);
    }
  }

  async updateManifest(did: string, newCID: string): Promise<void> {
    const didHash = this.didToHash.get(did) ?? this.hashDID(did);
    const record = this.records.get(didHash);
    if (!record) throw new Error(`Agent not found: ${did}`);
    record.manifestCID = newCID;
    record.lastUpdatedAt = Date.now();
  }

  async resolveByDID(did: string): Promise<AgentRecord | null> {
    const didHash = this.didToHash.get(did) ?? this.hashDID(did);
    const record = this.records.get(didHash);
    return record?.active ? record : null;
  }

  async queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]> {
    // Return agents that expose ANY of the requested capabilities
    const matched = new Set<string>();
    for (const capId of capabilityIds) {
      const capHash = this.hashCapability(capId);
      const agents = this.capabilityIndex.get(capHash);
      if (agents) for (const didHash of agents) matched.add(didHash);
    }

    return Array.from(matched)
      .map((didHash) => this.records.get(didHash)!)
      .filter((r) => r?.active);
  }

  /** List all active agents. Useful for admin tooling and debugging. */
  listAll(): AgentRecord[] {
    return Array.from(this.records.values()).filter((r) => r.active);
  }

  /** Total count of registered agents (active + inactive). */
  get size(): number {
    return this.records.size;
  }
}
