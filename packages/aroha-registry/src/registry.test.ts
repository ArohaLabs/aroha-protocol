// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { ArohaDiscovery } from "./discover.js";
import type { AgentRecord, CapabilityManifest } from "./types.js";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function signManifest(manifest: Omit<CapabilityManifest, "signature">, priv: Uint8Array): Promise<CapabilityManifest> {
  const { signature: _, ...body } = manifest as CapabilityManifest;
  const sortKeys = (obj: unknown): unknown => {
    if (Array.isArray(obj)) return obj.map(sortKeys);
    if (obj !== null && typeof obj === "object") {
      const sorted: Record<string, unknown> = {};
      for (const key of Object.keys(obj as object).sort()) {
        sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
      }
      return sorted;
    }
    return obj;
  };
  const canonical = JSON.stringify(sortKeys(body));
  const bytes = new TextEncoder().encode(canonical);
  const sig = await ed.signAsync(bytes, priv);
  return { ...manifest, signature: Buffer.from(sig).toString("base64url") } as CapabilityManifest;
}

async function makeAgentFixture() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);

  const manifestBody: Omit<CapabilityManifest, "signature"> = {
    aroha: "1.0",
    did: "did:aroha:provider-agent",
    name: "Test Provider",
    version: "1.0.0",
    endpoint: "https://provider.example.com/aroha",
    capabilities: [
      {
        id: "search-flights",
        version: "1.0.0",
        description: "Search for available flights",
        inputSchema: { type: "object", properties: { origin: { type: "string" } } },
        outputSchema: { type: "object", properties: { flights: { type: "array" } } },
        async: false,
        maxResponseMs: 5000,
        requiredTrustLevel: 1,
        pricing: { model: "free" },
        sagaRole: "none",
      },
    ],
    protocols: ["aroha/1.0"],
    createdAt: new Date().toISOString(),
  };

  const manifest = await signManifest(manifestBody, priv);

  const record: AgentRecord = {
    didHash: "0xhash",
    ownerAddress: "0xOwner",
    manifestCID: "QmTestCID",
    publicKeyB64: Buffer.from(pub).toString("base64url"),
    stakedWei: 1_000_000_000_000_000_000n,
    reputationScore: 8500,
    active: true,
    registeredAt: Date.now() - 86400_000,
    lastUpdatedAt: Date.now(),
  };

  return { priv, pub, manifest, record };
}

describe("ArohaDiscovery", () => {
  it("discovers agents and returns DiscoveredAgent array", async () => {
    const { record, manifest, pub } = await makeAgentFixture();

    const mockContract = {
      queryByCapability: vi.fn().mockResolvedValue([record]),
    };
    const mockIpfs = {
      fetchManifest: vi.fn().mockResolvedValue(manifest),
    };

    const discovery = new ArohaDiscovery(mockContract as any, mockIpfs as any);
    const agents = await discovery.discover(["search-flights"]);

    expect(agents).toHaveLength(1);
    expect(agents[0].manifest.did).toBe("did:aroha:provider-agent");
    expect(agents[0].endpoint).toBe("https://provider.example.com/aroha");
  });

  it("filters by minReputationScore", async () => {
    const { record, manifest } = await makeAgentFixture();
    const lowRepRecord = { ...record, reputationScore: 3000 };

    const mockContract = {
      queryByCapability: vi.fn().mockResolvedValue([record, lowRepRecord]),
    };
    const mockIpfs = {
      fetchManifest: vi.fn().mockResolvedValue(manifest),
    };

    const discovery = new ArohaDiscovery(mockContract as any, mockIpfs as any);
    const agents = await discovery.discover(["search-flights"], { minReputationScore: 5000 });

    expect(agents).toHaveLength(1);
    expect(agents[0].record.reputationScore).toBe(8500);
  });

  it("skips agents whose manifests fail signature verification", async () => {
    const { record, manifest } = await makeAgentFixture();
    const badManifest = { ...manifest, signature: "invalidsig" };

    const mockContract = {
      queryByCapability: vi.fn().mockResolvedValue([record]),
    };
    const mockIpfs = {
      fetchManifest: vi.fn().mockResolvedValue(badManifest),
    };

    const discovery = new ArohaDiscovery(mockContract as any, mockIpfs as any);
    const agents = await discovery.discover(["search-flights"]);

    expect(agents).toHaveLength(0);
  });

  it("skips agents missing required capabilities", async () => {
    const { record, manifest } = await makeAgentFixture();

    const mockContract = {
      queryByCapability: vi.fn().mockResolvedValue([record]),
    };
    const mockIpfs = {
      fetchManifest: vi.fn().mockResolvedValue(manifest),
    };

    const discovery = new ArohaDiscovery(mockContract as any, mockIpfs as any);
    const agents = await discovery.discover(["book-hotel"]); // not in manifest

    expect(agents).toHaveLength(0);
  });

  it("returns empty array when no agents are found", async () => {
    const mockContract = {
      queryByCapability: vi.fn().mockResolvedValue([]),
    };
    const mockIpfs = {
      fetchManifest: vi.fn(),
    };

    const discovery = new ArohaDiscovery(mockContract as any, mockIpfs as any);
    const agents = await discovery.discover(["any-capability"]);
    expect(agents).toHaveLength(0);
  });
});
