# @aroha-sdk/core

![Stable](https://img.shields.io/badge/status-stable-brightgreen) ![npm](https://img.shields.io/npm/v/@aroha-sdk/core)

Transport, identity, and cryptographic primitives for the Aroha Protocol — the foundation every agent and mandate is built on.

## Install

```bash
npm install @aroha-sdk/core
```

## Quick example

```typescript
import { generateDID, buildEnvelope, validateEnvelope, NonceRegistry } from "@aroha-sdk/core";

// Mint an agent's DID, keypair, and DID document in one call
const agent = await generateDID("my-flight-agent", "https://flights.example.com/aroha/v1");
// agent.did → "did:aroha:my-flight-agent"
// agent.privateKey / agent.publicKey / agent.document

// Sign a JSON body and wrap it in a transport envelope
const envelope = await buildEnvelope(
  "ArohaRequest",
  agent.did,
  "did:aroha:orchestrator",
  { capability: "book-flight", params: { origin: "SFO", destination: "JFK" } },
  "corr-1",
  agent.privateKey,
);

// Recipient validates the envelope: signature, recipient match, nonce replay, and expiry
const nonceRegistry = new NonceRegistry();
const result = await validateEnvelope(envelope, agent.publicKey, "did:aroha:orchestrator", nonceRegistry);
// result.valid === true, or { valid: false, reason } — envelope.body is already
// on hand from receiving it; validateEnvelope only confirms it's trustworthy
```

## Why this exists in the mandate chain

Agents need cryptographic identity to hold and present mandates. A mandate is issued to a specific DID — without a verifiable DID backed by an Ed25519 keypair, there is no way to prove that the mandate recipient is the legitimate grantee. `@aroha-sdk/core` provides that identity layer.

## API

### Identity

- `generateDID(agentId, endpoint, options?)` — mint a fresh Ed25519 keypair, DID, and DID document. `options.namespace` produces `did:aroha:<namespace>.<agentId>`.
- `generateDid(publicKey)` — derive a `did:aroha:` DID string from an *existing* public key (content-addressed, no document). Note the lowercase `Did` — different function from `generateDID` above.
- `mintLocalIdentity(agentId, endpoint, options?)` / `preparePublish(identity)` — same generation as `generateDID`, but structurally separated into a `LocalIdentity` (carries the private key) and a `PublishableIdentity` (does not — no `privateKey` field exists on the type at all). Use this when an app needs to guarantee a locally-minted identity can't be handed to a registry-publish call by accident.
- `rotateDIDKey`, `revokeKey`, `verifyRevocation` — key lifecycle management.

### Credentials

- `issueCredential(credential, issuerPrivateKey, issuerKeyId)` / `verifyCredential(credential, issuerPublicKey)` — W3C Verifiable Credentials (`CorporateIdentityCredential`, `ComplianceCertificationCredential`, `CapabilityAuthorizationCredential` types included).

### Messaging (transport envelopes)

- `buildEnvelope(type, from, to, body, correlationId, privateKey, ttlSecondsOrOptions?)` — sign a JSON body and wrap it in a transport envelope. `type` is one of the `ArohaMessageType` union (`"ArohaRequest"`, `"ArohaResponse"`, `"ArohaTaskMandate"`, etc.).
- `validateEnvelope(envelope, senderPubKey, myDID, nonceRegistry, options?)` — verify signature, recipient match, nonce replay, and expiry. Returns `{ valid: true }` or `{ valid: false, reason }` — it confirms the envelope is trustworthy, it doesn't hand the body back (you already have `envelope.body`).

### Crypto

- `signMessage(message, privateKey, verificationMethodId)` / `verifyMessageSignature(message, publicKey)` — sign/verify with a full `MessageProof` (DID-document-shaped) object attached.
- `signCanonical(payload, privateKey)` / `verifyCanonicalSignature(payload, signature, publicKey)` — the bare-signature counterpart: a hex Ed25519 signature over canonical JSON, no proof wrapper. Use this when you need to prove control of a DID's key over a flat payload that isn't itself a Aroha message envelope (e.g. an out-of-band API request).
- `canonicalizeMessage(message)` — the deterministic JSON form both signing functions above sign over (sorted keys, `proof` field excluded).

### Manifest builders

- `buildAgentManifest(did, opts)` / `buildMcpManifest(did, opts)` / `buildSkillManifest(did, opts)` — construct a manifest for the three common entity kinds, defaulting to `visibility: "private"`, `published: false`, `deployTarget: "local"`.
- `validateManifest(manifest)` — structural check against the shape above (not a full JSON-Schema validator) — catches a missing `did`, an invalid `kind`, or `published:true` combined with `visibility:"private"`.

### Skills

- `defineSkill(definition)` / `new SkillRegistry()` — register a named, independently-invocable unit of behavior (`{ id, name, skillType, inputSchema?, handler }`) and call it by id via `registry.invoke(id, input)`. No fixed `skillType` vocabulary — that's app/domain-specific.

### Scheduling

- `new LocalScheduler()` — register a `ScheduledTask` against a `TriggerConfig` (`"manual"` | `"interval"` | `"cron"`). Natively runs `"manual"` (call `scheduler.trigger(id)` yourself) and `"interval"` triggers in-process; `"cron"` is a config shape for wiring your own cron library or host-level scheduler — no cron parser is bundled here.

### Transport server/client

- `ArohaServer` — HTTP + WebSocket server implementing the Aroha Protocol `/aroha/v1` contract. Supports a `middleware: ArohaMiddleware[]` chain (mount RBAC via `@aroha-sdk/credentials`'s `createRbacMiddleware()`, or mandate-chain auth via `@aroha-sdk/delegation`'s `createDelegationMiddleware()`) and additional `httpRoutes`.
- `ArohaClient` — HTTP client for calling compliant agents.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).