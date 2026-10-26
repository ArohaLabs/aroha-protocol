# @aroha-sdk/registry

![Stable](https://img.shields.io/badge/status-stable-brightgreen) ![npm](https://img.shields.io/npm/v/@aroha-sdk/registry)
> `createArohaRegistryServer()` (self-hosted HTTP registry): ![Beta](https://img.shields.io/badge/status-beta-blue)

Discover and register agents on the Aroha network — find agents you can issue mandates to.

## Install

```bash
npm install @aroha-sdk/registry
```

## Quick example

```typescript
import { registerAgent, resolveAgent, listAgents } from "@aroha-sdk/registry";

// Register an agent so others can discover it and issue mandates to it
await registerAgent({
  did: "did:aroha:flight-agent",
  manifestCID: "QmXxx…",
  publicKeyB64: "MFkwEw…",
  apiKey: process.env.AROHA_API_KEY!, // registering is a write — requires auth
});

// Resolve an agent by DID before issuing a mandate. Fetches the record,
// then fetches and signature-verifies its IPFS manifest — throws if the
// manifest doesn't verify against the record's public key.
const agent = await resolveAgent("did:aroha:flight-agent");
// agent.endpoint, agent.manifest.capabilities, agent.publicKey, agent.record

// Find agents by capability — same fetch-and-verify per result; an agent
// whose manifest fails to fetch or verify is silently dropped, not returned
// as an untrusted partial record.
const flightAgents = await listAgents({ capability: "book-flights" });
// Issue a mandate to flightAgents[0].record.didHash's owner, then call flightAgents[0].endpoint
```

## Why this exists in the mandate chain

A mandate is issued to a specific DID. The registry is how you find the DID (and public key) of the agent you want to delegate to — so you can issue a correctly targeted, verifiable mandate before making any call.

## API

These are thin wrappers over `ArohaHttpRegistry` / `ArohaIpfsClient` — reach
for those classes directly (or `ArohaDiscovery`, for the on-chain contract
backend) for anything not covered here.

- `registerAgent(opts)` — register an agent. Requires `did`, `manifestCID`, `publicKeyB64`, `apiKey`. Optional: `registryUrl`, `stakeWei`, `capabilityIds`, `fetch` (inject a test double).
- `resolveAgent(did, opts?)` — resolve a DID to a verified `DiscoveredAgent` (`{ record, manifest, endpoint, publicKey }`), or `null` if not found. Throws if the manifest's signature doesn't verify. Optional: `registryUrl`, `apiKey`, `gatewayUrl`, `fetch`.
- `listAgents({ capability, ... })` — list agents exposing a capability (string or array), each resolved and verified the same way as `resolveAgent`. Agents that fail verification are dropped, not returned.
- `resolveManifest(cid, opts?)` — fetch a manifest directly from IPFS by CID, **unverified**. Use `resolveAgent`/`listAgents` when you need a signature-checked manifest.

Read operations (`resolveAgent`, `listAgents`) don't require `apiKey` — the
registry's reads are public. Registering does. Without `registryUrl` the
functions use `AROHA_REGISTRY_URL`, else the reference registry deployment;
a hosted registry service with API keys is not currently offered, so to
register agents run your own registry (`createArohaRegistryServer()` from
`@aroha-sdk/registry/server`) and pass its URL.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).