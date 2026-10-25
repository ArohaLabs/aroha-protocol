<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/core

The foundational package. Implements Protocol Layers 0–3: transport, identity, crypto, and messaging.

```bash
npm install @aroha-sdk/core
```

---

## ArohaServer

Starts an HTTP server that validates inbound Aroha messages before handing them to your code.

```typescript
import { ArohaServer } from "@aroha-sdk/core";

const server = new ArohaServer({
  agentDID: "did:aroha:my-agent",
  didDocument: identity.document,       // served at /.well-known/aroha-agent.json
  port: 3001,

  resolvePublicKey: async (senderDID) =>
    knownPublicKeys.get(senderDID) ?? null,

  middleware: [
    // Mount RBAC, B2B agreements, or consent middleware here (from @aroha-sdk/credentials and @aroha-sdk/commerce)
  ],

  httpRoutes: [
    // Mount additional HTTP handlers here, e.g. from @aroha-sdk/credentials
  ],

  onMessage: async (envelope, respond, stream) => {
    // `envelope` is already verified (sig, nonce, expiry, recipient)
    // All middleware has passed successfully
    const reply = await handleMessage(envelope);
    respond(reply);           // sync reply
    // stream(event);         // async WebSocket event
  },
});

await server.start();
```

**What `ArohaServer` handles automatically:**

- Ed25519 signature verification (`proof.proofValue`)
- Nonce replay detection (5-minute rolling window)
- Message expiry enforcement
- Recipient DID check
- Executes `middleware` chain before `onMessage` is called
- `GET /.well-known/aroha-agent.json` endpoint
- Additional raw `httpRoutes` evaluation

---

## ArohaClient

Sends Aroha envelopes to a remote agent.

```typescript
import { ArohaClient } from "@aroha-sdk/core";

const client = new ArohaClient();

// Synchronous request/response
const reply = await client.send(
  "https://provider.example.com/aroha/v1",
  signedEnvelope,
  { timeoutMs: 30_000 }
);

// Streaming
for await (const event of client.stream("wss://provider.example.com/aroha/stream", correlationId)) {
  console.log(event.body);
}

// Fetch DID Document
const didDoc = await client.fetchDIDDocument("https://provider.example.com");
```

---

## did:aroha-web: — Two-Factor Web Identity

`generateWebAgent` creates a domain-anchored agent identity verified by **both** HTTPS and DNS — not just HTTPS. See the [did:aroha-web: spec](../spec/web-did.md) for the full design rationale.

```typescript
import { generateWebAgent, rotateKey, resolveWebDID, dnsTxtValue, wellKnownPath } from "@aroha-sdk/core";

// ── Create ────────────────────────────────────────────────────────────────────
const agent = await generateWebAgent("stripe.com", "payments-agent");
// agent.did === "did:aroha-web:stripe.com:payments-agent"

// 1. Serve DID document at the well-known path
//    GET https://stripe.com/.well-known/aroha/agents/payments-agent/did.json
serveJson(wellKnownPath(agent.did), agent.document);

// 2. Publish DNS TXT: _aroha.stripe.com IN TXT "v=aroha1; path=payments-agent; keyhash=..."
console.log(dnsTxtValue(agent.document));

// ── Mount in ArohaServer ───────────────────────────────────────────────────────
const server = new ArohaServer({
  agentDID:       agent.did,
  didDocument:    agent.document,
  webDIDDocument: agent.document,    // enables /.well-known/aroha/agents/{path}/did.json
  port:           3000,
  // ...
});

// ── Rotate key (24-hour cool-down, predecessor-signed) ────────────────────────
const rotated = await rotateKey(agent, 24);
// Update DID document and DNS TXT with new keyhash

// ── Resolve and verify ────────────────────────────────────────────────────────
const result = await resolveWebDID("did:aroha-web:stripe.com:payments-agent");
if (result.fullyVerified) {
  // HTTPS + DNS + key cool-down all passed
}
```

| Check | `did:web:` | `did:wba:` (ANP) | **`did:aroha-web:`** |
|-------|-----------|-----------------|---------------------|
| HTTPS | ✓ | ✓ | ✓ |
| DNS TXT | ✗ | ✗ | **✓** |
| Key rotation cool-down | ✗ | ✗ | **✓** |
| Predecessor-signature chain | ✗ | ✗ | **✓** |

---

## generateDID

Creates an Ed25519 keypair and a `did:aroha:` DID. Call once and persist the private key.

```typescript
import { generateDID } from "@aroha-sdk/core";

const identity = await generateDID(
  "my-agent",                                    // globally unique, URL-safe ID
  "https://my-agent.example.com/aroha/v1"         // Aroha endpoint URL
);

identity.did         // "did:aroha:my-agent"
identity.privateKey  // Uint8Array (32 bytes) — keep secret
identity.publicKey   // Uint8Array (32 bytes) — share freely
identity.document    // DID Document JSON — serve at /.well-known/
```

!!! warning "Persist the private key"
    Calling `generateDID` again creates a new key. All pending reservations and peer
    public-key mappings become invalid. In production, save `identity.privateKey` to a
    secrets manager and reload it on restart.

---

## buildEnvelope

Builds and signs a Aroha envelope.

```typescript
import { buildEnvelope } from "@aroha-sdk/core";

const envelope = await buildEnvelope(
  "ArohaRequest",       // message type
  senderDID,           // from
  recipientDID,        // to
  {                    // body (type-specific)
    capability: "search-flights",
    params: { origin: "LHR", destination: "NRT", date: "2026-06-01" },
  },
  correlationId,       // string — links saga steps
  privateKey           // Uint8Array — Ed25519 private key
);
```

The envelope is signed using Ed25519 over the canonical body (keys sorted, `proof` omitted).

---

## Crypto utilities

```typescript
import { signMessage, verifyMessageSignature, encryptBody, decryptBody } from "@aroha-sdk/core";

const sig = await signMessage(data, privateKey);
const ok = await verifyMessageSignature(data, sig, publicKey);

// Body encryption: X25519 ECDH key agreement + AES-256-GCM
// Uses the correct Ed25519 → X25519 birational map (edwardsToMontgomery*)
const encrypted = await encryptBody(body, recipientPublicKey);
const decrypted = await decryptBody(encrypted, privateKey);
```

---

## WalletService

`WalletService` (ephemeral session keys, paymaster, escrow) lives in **`@aroha-sdk/settlement`**, not `@aroha-sdk/core`. The protocol kernel is settlement-free by design.

```typescript
import { createWallet } from "@aroha-sdk/settlement/payments";

const wallet = createWallet({ budget: 5 });
const receipt = await wallet.buyData("did:aroha:provider", {
  budget: 0.05,
  capability: "sentiment-score",
  params: { ticker: "BTC" },
});
```

See [@aroha-sdk/settlement →](settlement.md)

---

## ArohaErrorCode enum

See [Error Codes →](../reference/errors.md)
