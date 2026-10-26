<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/trusted-mesh

Skip Ed25519 signature verification for agents communicating within a trusted network boundary — a VPC, Kubernetes pod network, or mTLS service mesh. Reduces per-message overhead from ~1ms (Ed25519 verify) to ~0 without sacrificing the rest of Aroha's protocol guarantees.

---

## Security model

Aroha's cryptographic identity exists to answer: *"can I trust a message I received over an untrusted network?"* Inside a VPC or an Istio/Linkerd mesh with mutual TLS, the network itself already answers that question. Ed25519 verification adds latency with no incremental security benefit.

`@aroha-sdk/trusted-mesh` implements a **perimeter trust model**:

- **Outside the perimeter**: every agent verifies every signature. No change.
- **Inside the perimeter**: a request skips Ed25519 verification only when it arrives from a trusted network (`trustedNetworks`, default loopback only, plus your optional `isTrustedTransport` check such as an mTLS peer certificate) **and** claims an allowlisted DID. Nonce replay prevention and message expiry are still enforced on every message.
- **The DID allowlist alone is not a control**: with signatures skipped, `envelope.from` is unauthenticated, so anything that reaches the listener could claim an allowlisted DID. The network/transport check is what makes the DID meaningful — only use this where only mesh peers can reach the listener.

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
    // Networks requests must arrive from (default: loopback only)
    trustedNetworks: ["10.0.0.0/8"],
    // Optional extra transport check, e.g. an mTLS peer certificate
    isTrustedTransport: (req) => hasMeshPeerCertificate(req),
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
  "https://hotel-agent.internal/aroha/v1",
  "ArohaRequest",
  { capability: "book-hotel", params: { city: "Tokyo" } }
);
```

The client refuses a plain `http://` endpoint unless the host is loopback (`localhost`, `127.0.0.0/8`, `::1`), so use an `https://` endpoint for any other host. For development only, pass `{ allowInsecureHttp: true }` as the third constructor argument to allow `http://` to other hosts; it has the same meaning and default (off) as on `ArohaClient`. Envelopes, which are unsigned in mesh mode, then cross the network in clear.

### Using a trust zone helper

```typescript
import { createTrustedZone } from "@aroha-sdk/trusted-mesh";

const zone = createTrustedZone([
  "did:aroha:personal-agent",
  "did:aroha:flight-agent",
  "did:aroha:hotel-agent",
], undefined, { trustedNetworks: ["10.0.0.0/8"] });

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

Returns `{ bypassSignatureForRequest }` to spread into `ArohaServerOptions`.

```typescript
createTrustedMeshOptions({
  trustedDIDs: string[];          // exact DID allowlist
  trustedPrefixes?: string[];     // prefix-match allowlist
  trustedNetworks?: string[];     // CIDR ranges or addresses; default loopback only
  isTrustedTransport?: (req: IncomingMessage) => boolean;  // extra transport check
})
```

### `TrustedMeshClient`

Extends `ArohaClient`. All standard methods are available.

```typescript
new TrustedMeshClient(
  senderDID: string,
  recipientDID: string,
  opts?: ArohaClientOptions   // { pool?, allowInsecureHttp? } — passed to ArohaClient unchanged
)
```

Adds:

```typescript
sendUnsigned<T extends ArohaMessageType>(
  endpoint: string,
  type: T,
  body: ArohaBodyByType[T],
  correlationId?: string,
  opts?: SendOptions
): Promise<ArohaEnvelope | null>
```

### `createTrustedZone(trustedDIDs, prefixes?, network?)`

Convenience helper that creates shared server options and a client factory for a group of mutually-trusting agents.

```typescript
const zone = createTrustedZone(dids);
zone.serverOptions    // spread into ArohaServerOptions
zone.createClient(senderDID, recipientDID, opts?)  // TrustedMeshClient
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
| Ed25519 signature | **Skipped** for allowlisted DIDs arriving over a trusted network/transport |
| Message expiry (`expires` field) | Always checked |
| Nonce replay prevention | Always checked |
| Recipient DID match (`to` field) | Always checked |
| RBAC middleware | Still runs if configured |

---

## Deployment patterns

**Kubernetes**: Use `trustedPrefixes: ["did:aroha:internal:"]` with `trustedNetworks` set to the pod CIDR, and ensure your internal agents register with that prefix. Combine with a NetworkPolicy that blocks external traffic to agent ports.

**Istio / Linkerd**: The mTLS peer certificate already verifies the caller's identity at the network layer. Check it in `isTrustedTransport`, and use `trustedDIDs` to allowlist the service account DIDs, or `trustedPrefixes` for the entire mesh namespace.

**Docker Compose / single host**: Use `trustedDIDs` with explicit DID lists and `trustedNetworks` set to the Docker network's range. All agents share the same Docker network — external traffic can't reach the agent ports.
