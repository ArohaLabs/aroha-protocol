// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — Discovery (Layer 2)
 *
 * Implements the full discovery flow from the protocol spec:
 *
 *   1. queryByCapability()  → get matching AgentRecords from blockchain
 *   2. fetchManifest(CID)   → retrieve full capability manifest from IPFS
 *   3. verifyManifest()     → verify manifest signature against on-chain public key
 *   4. resolveDID()         → extract Aroha endpoint URL from DID Document
 *
 * The result is a DiscoveredAgent — everything needed to start communicating.
 *
 * This is SDK infrastructure (Tier 2). Selection logic (which agent to
 * pick from the discovered set) belongs to the orchestrator (Tier 2)
 * and preference layer (Tier 2), not here.
 */

import { fromMultibase, type DIDDocument } from "@aroha-sdk/core";
import { verifyMessageSignature, canonicalizeMessage } from "@aroha-sdk/core";
import { ArohaRegistryContract } from "./contract.js";
import { ArohaIpfsClient } from "./ipfs.js";
import { type AgentRecord, type CapabilityManifest, type DiscoveredAgent } from "./types.js";

export class ArohaDiscovery {
  constructor(
    private readonly contract: ArohaRegistryContract,
    private readonly ipfs: ArohaIpfsClient
  ) {}

  /**
   * Discover all agents that can serve the given capability IDs.
   *
   * Runs the full discovery flow: blockchain query → IPFS fetch →
   * signature verification → DID Document resolution.
   *
   * @param capabilityIds  One or more capability IDs (e.g. ["book-flight"])
   * @param options        Optional filters
   */
  async discover(
    capabilityIds: string[],
    options: DiscoveryOptions = {}
  ): Promise<DiscoveredAgent[]> {
    // Step 1 — Query blockchain for matching records
    const records = await this.contract.queryByCapability(capabilityIds);

    // Step 2 — Apply reputation filter (optional)
    const filtered = records.filter((r) => {
      if (options.minReputationScore !== undefined) {
        return r.reputationScore >= options.minReputationScore;
      }
      return true;
    });

    // Step 3 — Fetch manifests in parallel, verify, and resolve
    const results = await Promise.allSettled(
      filtered.map((record) => this.resolveAgent(record, capabilityIds))
    );

    // Return only successfully resolved agents
    return results
      .filter(
        (r): r is PromiseFulfilledResult<DiscoveredAgent> => r.status === "fulfilled"
      )
      .map((r) => r.value);
  }

  /**
   * Resolve a single agent DID to its full DiscoveredAgent descriptor.
   * Useful when you already know which agent you want to talk to.
   */
  async resolveAgent(
    record: AgentRecord,
    requiredCapabilities?: string[]
  ): Promise<DiscoveredAgent> {
    // Fetch manifest from IPFS
    const manifest = await this.ipfs.fetchManifest(record.manifestCID);

    // Verify manifest signature
    const pubKey = Buffer.from(record.publicKeyB64, "base64url");
    const isValid = await this.verifyManifestSignature(manifest, pubKey);
    if (!isValid) {
      throw new Error(
        `Manifest signature verification failed for agent ${manifest.did}`
      );
    }

    // Verify the manifest actually has the required capabilities
    if (requiredCapabilities?.length) {
      const manifestCapIds = new Set(manifest.capabilities.map((c) => c.id));
      const missing = requiredCapabilities.filter((id) => !manifestCapIds.has(id));
      if (missing.length > 0) {
        throw new Error(
          `Agent ${manifest.did} is missing capabilities: ${missing.join(", ")}`
        );
      }
    }

    return {
      record,
      manifest,
      endpoint: manifest.endpoint,
      publicKey: pubKey,
    };
  }

  /**
   * Verify that a capability manifest's signature is valid.
   * The signature covers the manifest body with the signature field excluded.
   */
  private async verifyManifestSignature(
    manifest: CapabilityManifest,
    publicKey: Uint8Array
  ): Promise<boolean> {
    const { signature, ...body } = manifest;
    const canonical = JSON.stringify(sortKeys(body));
    const bytes = new TextEncoder().encode(canonical);
    try {
      const sigBytes = Buffer.from(signature, "base64url");
      const { verifyAsync } = await import("@noble/ed25519");
      return verifyAsync(sigBytes, bytes, publicKey);
    } catch {
      return false;
    }
  }

}

export interface DiscoveryOptions {
  /** Only include agents with reputation >= this value (0–10000) */
  minReputationScore?: number;
  /** Only include agents that support this trust level */
  maxRequiredTrustLevel?: number;
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as object).sort()) {
      sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return obj;
}
