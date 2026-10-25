<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/trusted-mesh

Skip Ed25519 signature verification for agents communicating within a trusted network boundary — a VPC, Kubernetes pod network, or mTLS service mesh. Reduces per-message overhead from ~1ms (Ed25519 verify) to ~0 without sacrificing the rest of Aroha's protocol guarantees.

---

## Security model

Aroha's cryptographic identity exists to answer: *"can I trust a message I received over an untrusted network?"* Inside a VPC or an Istio/Linkerd mesh with mutual TLS, the network itself already answers that question. Ed25519 verification adds latency with no incremental security benefit.

`@aroha-sdk/trusted-mesh` implements a **perimeter trust model**:

- **Outside the perimeter**: every agent verifies every signature. No change.
- **Inside the perimeter**: agents on the allowlist skip Ed25519 verification. Nonce replay prevention and message expiry are still enforced on every message.
- **The allowlist is on the receiving side**: even if an attacker reaches the internal endpoint, only DIDs explicitly allowlisted bypass verification.

---

## Installation

```bash
npm install @aroha-sdk/trusted-mesh
```

---

## Quickstart

### Server side — accept unsigned envelopes from trusted peers

```typescript
import { createTrustedMeshOptions } from "@aroha-sdk/trusted-mesh";

const server = new ArohaServer({
  agentDID: "did:aroha:hotel-agent",
  // ...other options...
  ...createTrustedMeshOptions({
    trustedDIDs: [
      "did:aroha:personal-agent",
      "did:aroha:orchestrator",
    ],
    // Or by prefix (trust all agents with a common namespace):
    trustedPrefixes: ["did:aroha:internal:"],
  }),
});
```

### Client side — send unsigned envelopes

```typescript
import { TrustedMeshClient } from "@aroha-sdk/trusted-mesh";

const client = new TrustedMeshClient(
  "did:aroha:personal-agent",  // senderDID
  "did:aroha:hotel-agent"      // recipientDID
);

// Sends an unsigned ArohaRequest — no Ed25519 signing overhead
const response = await client.sendUnsigned(
  "http://hotel-agent.internal/aroha/v1",
  "ArohaRequest",
  { capability: "book-hotel", params: { city: "Tokyo" } }
);
```

### Using a trust zone helper

```typescript
import { createTrustedZone } from "@aroha-sdk/trusted-mesh";

const zone = createTrustedZone([
  "did:aroha:personal-agent",
  "did:aroha:flight-agent",
  "did:aroha:hotel-agent",
]);

// On each server:
const server = new ArohaServer({
  // ...
  ...zone.serverOptions,
});

// Unsigned client for personal-agent → flight-agent:
const client = zone.createClient("did:aroha:personal-agent", "did:aroha:flight-agent");
```

---

## API

### `createTrustedMeshOptions(opts): Partial<ArohaServerOptions>`

Returns `{ bypassSignatureFor }` to spread into `ArohaServerOptions`.

```typescript
createTrustedMeshOptions({
  trustedDIDs: string[];       // exact DID allowlist
  trustedPrefixes?: string[];  // prefix-match allowlist
})
```

### `TrustedMeshClient`

Extends `ArohaClient`. All standard methods are available. Adds:

```typescript
sendUnsigned<T extends ArohaMessageType>(
  endpoint: string,
  type: T,
  body: ArohaBodyByType[T],
  correlationId?: string,
  opts?: SendOptions
): Promise<ArohaEnvelope | null>
```

### `createTrustedZone(trustedDIDs, prefixes?)`

Convenience helper that creates shared server options and a client factory for a group of mutually-trusting agents.

```typescript
const zone = createTrustedZone(dids);
zone.serverOptions    // spread into ArohaServerOptions
zone.createClient(senderDID, recipientDID)  // TrustedMeshClient
```

### `ipInCidr(ip, cidr)` / `ipInAnyRange(ip, ranges)`

IPv4 CIDR matching utilities for building IP-based allowlists alongside DID-based ones.

```typescript
ipInCidr("10.0.1.5", "10.0.0.0/8")       // true
ipInAnyRange("192.168.1.10", ["10.0.0.0/8", "192.168.0.0/16"])  // true
```

---

## What's still verified in mesh mode

| Check | Mesh mode |
|-------|-----------|
| Ed25519 signature | **Skipped** for allowlisted DIDs |
| Message expiry (`expires` field) | Always checked |
| Nonce replay prevention | Always checked |
| Recipient DID match (`to` field) | Always checked |
| RBAC middleware | Still runs if configured |

---

## Deployment patterns

**Kubernetes**: Use `trustedPrefixes: ["did:aroha:internal:"]` and ensure your internal agents register with that prefix. Combine with a NetworkPolicy that blocks external traffic to agent ports.

**Istio / Linkerd**: The mTLS peer certificate already verifies the caller's identity at the network layer. Use `trustedDIDs` to allowlist the service account DIDs, or `trustedPrefixes` for the entire mesh namespace.

**Docker Compose / single host**: Use `trustedDIDs` with explicit DID lists. All agents share the same Docker network — external traffic can't reach the agent ports.
