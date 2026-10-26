<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/registry

Layer 2 — registry clients, IPFS manifest publishing, and capability discovery.

```bash
npm install @aroha-sdk/registry
```

---

## IArohaRegistry

All registry implementations share this interface:

```typescript
interface IArohaRegistry {
  register(did, manifestCID, publicKey, options?): Promise<void>;
  deactivate(did): Promise<void>;
  updateManifest(did, newCID): Promise<void>;
  resolveByDID(did): Promise<AgentRecord | null>;
  queryByCapability(capabilityIds: string[]): Promise<AgentRecord[]>;
}
```

Four concrete implementations are provided — including `InMemoryRegistry` for enterprise deployments that need no blockchain at all.

---

## ArohaHttpRegistry

HTTP registry client, for a self-hosted registry (`createArohaRegistryServer()` from `@aroha-sdk/registry/server`). A reference deployment answers at `aroha-registry.aroha-labs.workers.dev`, but a hosted registry service with API keys is not currently offered, so registering needs a registry you run (or an API key from its operator).

```typescript
import { ArohaHttpRegistry } from "@aroha-sdk/registry";

const registry = new ArohaHttpRegistry({
  baseUrl: "https://registry.example.internal",   // your self-hosted registry
  apiKey: process.env.AROHA_API_KEY!,              // issued by the registry operator
});

// Register
await registry.register(identity.did, manifestCID, identity.publicKey);

// Discover agents with a capability
const agents = await registry.queryByCapability(["book-flight"]);

// Resolve by DID
const record = await registry.resolveByDID("did:aroha:my-agent");
```

---

## ArohaRegistryContract

On-chain registry backed by `ArohaRegistry.sol` (EVM). Adds staking and trustless capability indexing.

```typescript
import { ethers } from "ethers";
import { ArohaRegistryContract } from "@aroha-sdk/registry/contract";

const registry = new ArohaRegistryContract(
  "http://127.0.0.1:8545",       // rpcUrl
  "0x...",                       // contractAddress
  new ethers.Wallet("0x..."),    // optional signer, needed for writes
);

await registry.register(identity.did, manifestCID, identity.publicKey, {
  stakeWei: BigInt("1000000000000000"),  // optional; defaults to the contract's minimum stake
});
```

---

## InMemoryRegistry

A fully conformant `IArohaRegistry` backed by in-process Maps. Zero external dependencies. Designed for:

- **Intra-enterprise deployments** — HR agent ↔ IT agent within the same company, no public blockchain needed
- **Local development and integration tests** — spin up a registry in one line
- **Private agent networks** — air-gapped environments, zero-trust internal topologies

```typescript
import { InMemoryRegistry } from "@aroha-sdk/registry";

const registry = new InMemoryRegistry();

await registry.register("did:aroha:jira-agent", "manifest-v1", publicKey, {
  capabilityIds: ["search-issues", "create-issue", "transition-issue"],
  initialReputationScore: 8000,
});

await registry.register("did:aroha:github-agent", "manifest-v2", pubKey2, {
  capabilityIds: ["list-issues", "create-issue", "merge-pull-request"],
});

// Discovery works exactly the same as blockchain/HTTP registries
const agents = await registry.queryByCapability(["create-issue"]);
// → returns both jira-agent and github-agent

// Admin listing
console.log(registry.listAll());   // all active agents
console.log(registry.size);        // total count including inactive
```

The `InMemoryRegistry` returns the same `AgentRecord` shape as the other implementations, so you can swap implementations without changing discovery or saga code. Its `didHash` is a truncated SHA-256 of the DID, not the contract's keccak-256, so hash values differ between backends.

---

## ArohaIpfsClient

Publish and fetch capability manifests on IPFS.

```typescript
import { ArohaIpfsClient } from "@aroha-sdk/registry/ipfs";

// Pinning backend (Pinata JWT) for uploads, or { type: "gateway", gatewayUrl } for reads only
const ipfs = new ArohaIpfsClient({ type: "pinata", jwt: process.env.PINATA_JWT! });

// Publish manifest
const { cid, capabilityIds } = await ipfs.uploadManifest(manifest);

// Fetch manifest by CID
const fetched = await ipfs.fetchManifest(cid);
```

---

## ArohaDiscovery

High-level discovery engine for the on-chain backend — wraps `ArohaRegistryContract` + IPFS + manifest signature verification. For the HTTP registry, use `resolveAgent` / `listAgents` (see the package README).

```typescript
import { ArohaDiscovery } from "@aroha-sdk/registry";

const discovery = new ArohaDiscovery(contractRegistry, ipfs);   // ArohaRegistryContract, ArohaIpfsClient

// Discover all agents with a capability
const agents = await discovery.discover(
  ["book-flight"],
  { minReputationScore: 4000, maxRequiredTrustLevel: 2 }
);

// agents: DiscoveredAgent[]
// Each has: .record (AgentRecord) + .manifest (CapabilityManifest) + .endpoint (string)
```

`ArohaDiscovery` verifies manifest signatures against the on-chain public key before returning results.
An agent with an invalid manifest signature is silently excluded.

---

## Building a capability manifest

```typescript
import * as ed from "@noble/ed25519";

const manifest = {
  aroha: "1.0" as const,
  did: identity.did,
  name: "My Agent",
  version: "1.0.0",
  endpoint: "https://my-agent.example.com/aroha/v1",
  protocols: ["aroha/1.0" as const],
  capabilities: [
    {
      id: "search-flights",
      version: "1.0.0",
      inputSchema: { type: "object", properties: { origin: { type: "string" } } },
      outputSchema: { type: "object" },
      async: false,
      maxResponseMs: 5000,
      requiredTrustLevel: 1 as const,
      pricing: { model: "free" as const },
      sagaRole: "none" as const,
    },
    {
      id: "book-flight",
      version: "1.0.0",
      sagaRole: "participant" as const,
      reserveCapabilityId: "book-flight",
      cancelCapabilityId: "book-flight",
      requiredTrustLevel: 2 as const,
      pricing: { model: "per-transaction" as const, fee: 2.50, currency: "USD" },
    },
  ],
  signature: "",
};

// Sign (keys sorted, `signature` field left out)
const { signature: _omit, ...body } = manifest;
const input = JSON.stringify(sortKeys(body));
const sig = await ed.signAsync(new TextEncoder().encode(input), identity.privateKey);
manifest.signature = Buffer.from(sig).toString("base64url");
```

---

## CapabilityDefinition fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✓ | Kebab-case capability ID |
| `version` | string | ✓ | Semver |
| `inputSchema` | JSON Schema | ✓ | Input parameters |
| `outputSchema` | JSON Schema | ✓ | Result shape |
| `async` | boolean | ✓ | Uses WebSocket streaming |
| `maxResponseMs` | number | ✓ | Response timeout hint |
| `requiredTrustLevel` | 0–4 | ✓ | Minimum caller trust level |
| `pricing` | object | ✓ | `"free"` / `"per-transaction"` / `"subscription"` |
| `sagaRole` | `"none"` / `"participant"` | ✓ | Whether the capability implements reserve/commit/cancel |
| `reserveCapabilityId` | string | if saga | Capability ID for `ArohaReserve` |
| `cancelCapabilityId` | string | if saga | Capability ID for `ArohaCancel` |
