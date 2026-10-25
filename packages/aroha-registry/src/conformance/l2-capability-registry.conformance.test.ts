// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol Conformance Suite — Layer 2: Capability Registry
 *
 * Tests the MUST requirements from docs/conformance/test-matrix.md rows L2-01 to L2-04.
 * Uses InMemoryRegistry as the reference implementation under test.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { InMemoryRegistry } from "../memory-registry.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makePublicKey(): Promise<Uint8Array> {
  const priv = ed.utils.randomPrivateKey();
  return ed.getPublicKeyAsync(priv);
}

// ─── L2-01: Agent publishes capability manifest on startup ───────────────────

describe("L2-01 [MUST] Agent publishes capability manifest to registry on startup", () => {
  it("registered agent is retrievable by DID", async () => {
    const registry = new InMemoryRegistry();
    const did = "did:aroha:l2-01-agent";
    const pubKey = await makePublicKey();

    await registry.register(did, "manifest-cid-v1", pubKey, {
      capabilityIds: ["search-flights"],
    });

    const record = await registry.resolveByDID(did);
    expect(record).not.toBeNull();
    expect(record!.active).toBe(true);
  });

  it("registration stores the manifest CID", async () => {
    const registry = new InMemoryRegistry();
    const did = "did:aroha:l2-01-cid-agent";
    const pubKey = await makePublicKey();

    await registry.register(did, "ipfs://Qm12345", pubKey, {
      capabilityIds: ["book-hotel"],
    });

    const record = await registry.resolveByDID(did);
    expect(record!.manifestCID).toBe("ipfs://Qm12345");
  });
});

// ─── L2-02: Capability manifest includes required fields ──────────────────────

describe("L2-02 [MUST] Capability manifest includes: DID, capabilities[], endpoint, version", () => {
  it("agent record includes public key bytes", async () => {
    const registry = new InMemoryRegistry();
    const did = "did:aroha:l2-02-fields";
    const pubKey = await makePublicKey();

    await registry.register(did, "manifest-v1", pubKey, {
      capabilityIds: ["process-payment"],
    });

    const record = await registry.resolveByDID(did);
    expect(record).not.toBeNull();
    // publicKeyB64 is the encoded form of the provided public key
    const decoded = Buffer.from(record!.publicKeyB64, "base64url");
    expect(decoded).toEqual(Buffer.from(pubKey));
  });

  it("agent record includes active status and registration timestamps", async () => {
    const registry = new InMemoryRegistry();
    const pubKey = await makePublicKey();
    const before = Date.now();

    await registry.register("did:aroha:l2-02-ts", "cid-ts", pubKey);

    const record = await registry.resolveByDID("did:aroha:l2-02-ts");
    expect(record!.active).toBe(true);
    expect(record!.registeredAt).toBeGreaterThanOrEqual(before);
    expect(record!.lastUpdatedAt).toBeGreaterThanOrEqual(before);
  });
});

// ─── L2-03: Registry supports capability discovery by name ────────────────────

describe("L2-03 [MUST] Registry supports capability discovery by name and tag", () => {
  it("queryByCapability returns agents that expose the requested capability", async () => {
    const registry = new InMemoryRegistry();
    const pub1 = await makePublicKey();
    const pub2 = await makePublicKey();

    await registry.register("did:aroha:l2-03-flight", "cid-1", pub1, {
      capabilityIds: ["search-flights", "book-flight"],
    });
    await registry.register("did:aroha:l2-03-hotel", "cid-2", pub2, {
      capabilityIds: ["book-hotel"],
    });

    const flightAgents = await registry.queryByCapability(["search-flights"]);
    expect(flightAgents.map((a) => a.publicKeyB64)).toContain(
      Buffer.from(pub1).toString("base64url")
    );
    expect(flightAgents.length).toBe(1);
  });

  it("queryByCapability returns multiple matching agents", async () => {
    const registry = new InMemoryRegistry();
    const pub1 = await makePublicKey();
    const pub2 = await makePublicKey();

    await registry.register("did:aroha:l2-03-provider-a", "cid-a", pub1, {
      capabilityIds: ["currency-conversion"],
    });
    await registry.register("did:aroha:l2-03-provider-b", "cid-b", pub2, {
      capabilityIds: ["currency-conversion"],
    });

    const agents = await registry.queryByCapability(["currency-conversion"]);
    expect(agents.length).toBe(2);
  });

  it("queryByCapability returns empty array when no agent has the capability", async () => {
    const registry = new InMemoryRegistry();
    const agents = await registry.queryByCapability(["nonexistent-capability"]);
    expect(agents).toHaveLength(0);
  });

  it("queryByCapability matches any one of multiple requested capabilities (OR semantics)", async () => {
    const registry = new InMemoryRegistry();
    const pub = await makePublicKey();

    await registry.register("did:aroha:l2-03-or-test", "cid-or", pub, {
      capabilityIds: ["send-email"],
    });

    const agents = await registry.queryByCapability(["send-email", "send-sms"]);
    expect(agents.length).toBe(1);
  });
});

// ─── L2-04: Agent deregisters from registry on graceful shutdown ──────────────

describe("L2-04 [SHOULD] Agent deregisters from registry on graceful shutdown", () => {
  it("deactivated agent no longer appears in capability queries", async () => {
    const registry = new InMemoryRegistry();
    const pub = await makePublicKey();

    await registry.register("did:aroha:l2-04-deactivate", "cid-deact", pub, {
      capabilityIds: ["process-refund"],
    });

    // Confirm registered
    const before = await registry.queryByCapability(["process-refund"]);
    expect(before.length).toBe(1);

    // Graceful shutdown — deregister
    await registry.deactivate("did:aroha:l2-04-deactivate");

    const after = await registry.queryByCapability(["process-refund"]);
    expect(after.length).toBe(0);
  });

  it("resolveByDID returns null for a deactivated agent", async () => {
    const registry = new InMemoryRegistry();
    const pub = await makePublicKey();

    await registry.register("did:aroha:l2-04-null", "cid-null", pub);
    await registry.deactivate("did:aroha:l2-04-null");

    const record = await registry.resolveByDID("did:aroha:l2-04-null");
    expect(record).toBeNull();
  });
});
