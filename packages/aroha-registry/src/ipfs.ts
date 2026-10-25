// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — IPFS Manifest Storage (Layer 2)
 *
 * Capability manifests are stored on IPFS — content-addressed and immutable.
 * Only the CID (content hash) is stored on-chain.
 *
 * This module supports two backends:
 *   - Pinata API (cloud pinning, easiest to get started)
 *   - Public IPFS gateway (read-only, no pinning)
 *
 * The protocol does not mandate which pinning service to use — only that
 * the manifest is retrievable by its CID.
 */

import { type CapabilityManifest } from "./types.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type IpfsBackend = PinataBackend | GatewayBackend;

export interface PinataBackend {
  type: "pinata";
  /** Pinata JWT API token */
  jwt: string;
}

export interface GatewayBackend {
  type: "gateway";
  /** IPFS gateway base URL (e.g. "https://ipfs.io/ipfs") */
  gatewayUrl: string;
}

// ─── IPFS client ──────────────────────────────────────────────────────────────

export class ArohaIpfsClient {
  constructor(private readonly backend: IpfsBackend) {}

  /**
   * Upload a capability manifest to IPFS.
   * Returns the CID and the capability IDs extracted from the manifest.
   *
   * Pass capabilityIds to RegisterOptions when registering so the registry
   * can store them immediately, independent of IPFS propagation timing.
   *
   * @param manifest  The signed capability manifest object
   */
  async uploadManifest(manifest: CapabilityManifest): Promise<{ cid: string; capabilityIds: string[] }> {
    if (this.backend.type !== "pinata") {
      throw new Error("Manifest upload requires a pinning backend (pinata)");
    }

    const response = await fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.backend.jwt}`,
      },
      body: JSON.stringify({
        pinataContent: manifest,
        pinataMetadata: {
          name: `aroha-manifest-${manifest.did}-${manifest.version}`,
        },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`IPFS upload failed: ${error}`);
    }

    const result = (await response.json()) as { IpfsHash: string };
    const capabilityIds = manifest.capabilities.map((cap) => cap.id).filter(Boolean);
    return { cid: result.IpfsHash, capabilityIds };
  }

  /**
   * Fetch a capability manifest from IPFS by its CID.
   *
   * @param cid  The IPFS content hash (stored on-chain in the AgentRecord)
   */
  async fetchManifest(cid: string): Promise<CapabilityManifest> {
    const url = this.resolveUrl(cid);
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`IPFS fetch failed for CID ${cid}: ${response.statusText}`);
    }

    return response.json() as Promise<CapabilityManifest>;
  }

  private resolveUrl(cid: string): string {
    if (this.backend.type === "pinata") {
      return `https://gateway.pinata.cloud/ipfs/${cid}`;
    }
    return `${this.backend.gatewayUrl}/${cid}`;
  }
}
