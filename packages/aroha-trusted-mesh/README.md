# @aroha-sdk/trusted-mesh

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/trusted-mesh)

Skip per-message envelope signing between agents inside a network boundary you control (VPC,
Kubernetes pod network, mTLS mesh).

## Install

```bash
npm install @aroha-sdk/trusted-mesh
```

## Quick example

```typescript
import { createTrustedMeshOptions, TrustedMeshClient, createTrustedZone } from "@aroha-sdk/trusted-mesh";
import { ArohaServer } from "@aroha-sdk/core";

// Server: skip the signature check ONLY when the request arrives from a trusted network
// AND claims an allow-listed DID. Everything else still needs a valid Ed25519 signature;
// nonce and expiry checks always apply.
const server = new ArohaServer({
  agentDID, didDocument, port: 3001, resolvePublicKey, onMessage,
  ...createTrustedMeshOptions({
    trustedDIDs: ["did:aroha:flight-agent", "did:aroha:hotel-agent"],
    trustedPrefixes: ["did:aroha:internal:"],
    trustedNetworks: ["10.0.0.0/8"],                      // default: loopback only
    isTrustedTransport: (req) => hasMeshPeerCertificate(req), // optional extra check, e.g. mTLS
  }),
});

// Client inside the mesh: send unsigned envelopes. Plain http:// is refused for any
// non-loopback host unless you pass { allowInsecureHttp: true } (development only), so use https://.
const client = new TrustedMeshClient("did:aroha:flight-agent", "did:aroha:hotel-agent");
const reply = await client.sendUnsigned("https://hotel-agent.internal:3001/aroha/v1", "ArohaRequest", {
  capability: "check-availability",
  params: { city: "Tokyo", nights: 5 },
});

// Or both halves at once
const zone = createTrustedZone(["did:aroha:a", "did:aroha:b"], undefined, { trustedNetworks: ["10.0.0.0/8"] });
```

## Security model

The DID allow-list alone is not a control: with signatures skipped, `envelope.from` is
unauthenticated. The network (and optional transport) check is what makes the DID meaningful,
so only use this where only mesh peers can reach the listener. Spending mandates are
unaffected — a mandate is still verified by whoever acts on it.

## API

- `createTrustedMeshOptions({ trustedDIDs, trustedPrefixes?, trustedNetworks?, isTrustedTransport? })` → `{ bypassSignatureForRequest }` to spread into `ArohaServerOptions`.
- `TrustedMeshClient(senderDID, recipientDID, opts?)` — `sendUnsigned(endpoint, type, body, correlationId?, opts?)`. `opts` are `ArohaClientOptions` (`pool`, `allowInsecureHttp`), passed to `ArohaClient` unchanged; `allowInsecureHttp` defaults to off.
- `createTrustedZone(dids, prefixes?, network?)` → `{ serverOptions, createClient(sender, recipient, opts?) }`.
- `ipInCidr(ip, cidr)`, `ipInAnyRange(ip, ranges)`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
