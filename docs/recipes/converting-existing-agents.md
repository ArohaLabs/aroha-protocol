<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Recipe: Converting an Existing Agent to Aroha Protocol

This recipe walks through converting an agent that already has business logic (e.g., a REST service that books flights, searches hotels, or processes payments) into a fully Aroha-compliant agent. Work through the six phases in order — each phase is independently testable.

---

## Prerequisites

- Node.js ≥ 22, TypeScript ≥ 5.4
- Existing service with at least one HTTP endpoint that performs a query or transaction
- `@aroha-sdk/core` and `@aroha-sdk/registry` (published on npm; `@aroha-sdk/credentials` for Phase 5)

```bash
npm install @aroha-sdk/core @aroha-sdk/registry
```

---

## Phase 1 — Identity & Transport

Replace your existing HTTP server entry point with a `ArohaServer`. Your existing business logic stays untouched — you are only wrapping it.

### 1.1 Generate a DID

Every agent owns an Ed25519 keypair. Generate once, persist the private key securely.

```typescript
import { generateDID } from "@aroha-sdk/core";

// Run once; save identity.privateKey somewhere secure (env var, secrets manager, HSM)
const identity = await generateDID(
  "my-booking-agent",               // globally unique, URL-safe ID
  "https://my-agent.example.com/aroha/v1"  // your public Aroha endpoint
);

console.log(identity.did);           // "did:aroha:my-booking-agent"
console.log(identity.document);      // DID Document — serve this at /.well-known/
```

> If your agent restarts, reload the same private key bytes rather than calling `generateDID` again.  
> Changing the keypair invalidates all pending reservations and breaks peers' signature verification.

### 1.2 Start ArohaServer

```typescript
import { ArohaServer } from "@aroha-sdk/core";
import { ArohaRole } from "@aroha-sdk/credentials";
import { handleMessage } from "./handlers.js";  // your business logic (Phase 2)

// Seed peers whose messages you will accept (expand as you integrate peers)
const knownPublicKeys = new Map<string, Uint8Array>();
knownPublicKeys.set(identity.did, identity.publicKey);

// Assign roles to known peers
const agentRoles = new Map<string, ArohaRole[]>();
// e.g., agentRoles.set("did:aroha:orchestrator-alice", [ArohaRole.AgentOrchestrator]);

import { createRbacMiddleware } from "@aroha-sdk/credentials";

const server = new ArohaServer({
  agentDID: identity.did,
  didDocument: identity.document,  // served automatically at /.well-known/aroha-agent.json
  port: 3001,

  resolvePublicKey: async (senderDID) => knownPublicKeys.get(senderDID) ?? null,

  middleware: [
    createRbacMiddleware({
      resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
      resolveIssuerPublicKey: async (did) => knownPublicKeys.get(did) ?? null,
    })
  ],

  onMessage: async (envelope, respond, _stream) => {
    // `envelope` is already verified: signature, nonce, expiry, and recipient DID
    const reply = await handleMessage(envelope, identity.did, identity.privateKey);
    respond(reply);
  },
});

await server.start();
console.log(`Agent live at https://my-agent.example.com/aroha/v1`);
```

**What you get for free** from `ArohaServer`:

| Automatic | Your responsibility |
|-----------|---------------------|
| Ed25519 signature verification | Business logic in `onMessage` |
| Nonce replay protection | Generating signed reply envelopes |
| Message expiry enforcement | Saga state (reservations) |
| `/.well-known/aroha-agent.json` endpoint | Keeping `resolvePublicKey` up to date |
| HTTPS routing | TLS termination (reverse proxy or cert) |

**Checkpoint:** `curl https://my-agent.example.com/.well-known/aroha-agent.json` should return the DID Document.

---

## Phase 2 — Message Handler

Map your existing API surface to Aroha message types. Create `src/handlers.ts`:

```typescript
import { buildEnvelope, ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";

export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {

  const { type, body, from, correlationId } = envelope;

  switch (type) {

    // ── READ-ONLY QUERY ────────────────────────────────────────────────────
    case "ArohaRequest": {
      const { capability, params } = body;
      switch (capability) {

        case "search-flights": {
          // BEFORE: your existing search logic
          //   const results = await flightService.search(params);
          const results = await flightService.search(params);

          return buildEnvelope("ArohaResponse", agentDID, from,
            { capability, result: results },
            correlationId, privateKey);
        }

        default:
          return errorEnvelope(envelope, agentDID, privateKey,
            ArohaErrorCode.UnknownCapability, `Unknown capability: ${capability}`);
      }
    }

    // ── TRANSACTIONAL (saga) — see Phase 3 ────────────────────────────────
    case "ArohaReserve":
      return handleReserve(envelope, agentDID, privateKey);

    case "ArohaCommit":
      return handleCommit(envelope, agentDID, privateKey);

    case "ArohaCancel":
      return handleCancel(envelope, agentDID, privateKey);

    // ── FALLBACK ──────────────────────────────────────────────────────────
    default:
      return errorEnvelope(envelope, agentDID, privateKey,
        ArohaErrorCode.UnknownCapability, `Unsupported message type: ${type}`);
  }
}

function errorEnvelope(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array,
  code: ArohaErrorCode,
  message: string
): Promise<ArohaEnvelope> {
  return buildEnvelope("ArohaError", agentDID, envelope.from,
    { code, message, retryable: false },
    envelope.correlationId, privateKey);
}
```

### Mapping your existing API

| Your existing surface | Aroha message type |
|-----------------------|-------------------|
| `GET /search` (read-only) | `ArohaRequest` → `ArohaResponse` |
| `POST /hold` (hold inventory) | `ArohaReserve` → `ArohaReserveAck` |
| `POST /confirm` (finalize booking) | `ArohaCommit` → `ArohaCommitAck` |
| `DELETE /cancel` (refund/rollback) | `ArohaCancel` → `ArohaCancelAck` |
| Streaming progress events | `ArohaStream` (via WebSocket) |
| Price negotiation | `ArohaNegotiate` → `ArohaCounterOffer` → `ArohaAccept` |

**Checkpoint:** Send a manual `ArohaRequest` using `ArohaClient` and verify you get back a `ArohaResponse`.

```typescript
import { ArohaClient, buildEnvelope } from "@aroha-sdk/core";
const client = new ArohaClient();

const req = await buildEnvelope("ArohaRequest", myDID, agentDID,
  { capability: "search-flights", params: { origin: "LHR", destination: "NRT", date: "2026-06-01" } },
  crypto.randomUUID(), myPrivateKey);

const reply = await client.send("https://my-agent.example.com/aroha/v1", req);
console.log(reply.type, reply.body);  // "ArohaResponse" { result: [...] }
```

---

## Phase 3 — Saga Pattern (Transactional Capabilities)

Skip this phase if all your capabilities are read-only (e.g., search, lookup).

Implement reserve / commit / cancel. The three rules are:

1. **`ArohaReserve`** — hold inventory, return a `reservationToken`
2. **`ArohaCommit`** — finalize; **must be idempotent** (same token → same result)
3. **`ArohaCancel`** — compensating transaction; must always succeed even if commit already ran

```typescript
// In-process store — replace with your DB / cache in production
const reservations = new Map<string, {
  params: unknown;
  expiresAt: Date;
  committed: boolean;
  result?: unknown;
}>();

async function handleReserve(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { capability, params, holdDurationMs } = envelope.body;

  if (capability !== "book-flight") {
    return errorEnvelope(envelope, agentDID, privateKey,
      ArohaErrorCode.UnknownCapability, `Cannot reserve: ${capability}`);
  }

  // Check inventory before issuing token
  const available = await flightService.checkAvailability(params);
  if (!available) {
    return errorEnvelope(envelope, agentDID, privateKey,
      ArohaErrorCode.NoInventory, "No seats available");
  }

  const reservationToken = `RES-${crypto.randomUUID()}`;
  const expiresAt = new Date(Date.now() + holdDurationMs);

  reservations.set(reservationToken, { params, expiresAt, committed: false });
  // In production: persist to DB here and schedule expiry cleanup

  return buildEnvelope("ArohaReserveAck", agentDID, envelope.from,
    { reservationToken, expiresAt: expiresAt.toISOString() },
    envelope.correlationId, privateKey);
}

async function handleCommit(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { reservationToken } = envelope.body;
  const res = reservations.get(reservationToken);

  if (!res) {
    return errorEnvelope(envelope, agentDID, privateKey,
      ArohaErrorCode.InvalidToken, "Unknown or expired reservation token");
  }

  if (new Date() > res.expiresAt) {
    return errorEnvelope(envelope, agentDID, privateKey,
      ArohaErrorCode.ReservationExpired, "Reservation has expired");
  }

  // IDEMPOTENCY: if already committed, return the same result
  if (!res.committed) {
    res.committed = true;
    res.result = await flightService.confirm(res.params);  // your existing confirm logic
  }

  return buildEnvelope("ArohaCommitAck", agentDID, envelope.from,
    { reservationToken, result: res.result },
    envelope.correlationId, privateKey);
}

async function handleCancel(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { reservationToken, reason } = envelope.body;
  const res = reservations.get(reservationToken);

  if (res?.committed) {
    // Post-commit compensation — refund or void the booking
    await flightService.refund(res.result);
  }

  reservations.delete(reservationToken);

  return buildEnvelope("ArohaCancelAck", agentDID, envelope.from,
    { reservationToken },
    envelope.correlationId, privateKey);
}
```

### Idempotency checklist

- [ ] Calling `ArohaCommit` twice with the same `reservationToken` returns the **same `result`** both times
- [ ] Calling `ArohaCancel` on an already-cancelled token returns `ArohaCancelAck` (not an error)
- [ ] `reservationToken`s are persisted to durable storage, not in-process memory

**Checkpoint:** run a reserve, commit and cancel round trip against your agent and check
that each returns its acknowledgement (`ArohaReserveAck`, `ArohaCommitAck`, `ArohaCancelAck`).
Sagas are an extension ([extensions](../spec/extensions.md)); the saga coordinator `@aroha-sdk/orchestrator` is published on npm (1.4.0) and its source is no longer in this repository.

---

## Phase 4 — Registry & Discovery

Register your agent so orchestrators can find it dynamically.

### 4.1 Build and sign the capability manifest

```typescript
import { ArohaHttpRegistry, type CapabilityManifest } from "@aroha-sdk/registry";
import * as ed from "@noble/ed25519";

const manifest: CapabilityManifest = {
  aroha: "1.0",
  did: identity.did,
  name: "My Booking Agent",
  version: "1.0.0",
  endpoint: "https://my-agent.example.com/aroha/v1",
  protocols: ["aroha/1.0"],
  capabilities: [
    {
      id: "search-flights",           // matches capability field in ArohaRequest
      version: "1.0",
      inputSchema: {
        type: "object",
        properties: {
          origin: { type: "string" },
          destination: { type: "string" },
          date: { type: "string", format: "date" },
        },
        required: ["origin", "destination", "date"],
      },
      outputSchema: { type: "object" },
      async: false,
      maxResponseMs: 5000,
      requiredTrustLevel: 1,          // 0=public, 1=authenticated, 2=verified, 3=trusted, 4=privileged
      pricing: { model: "free" },
      sagaRole: "none",               // read-only, no reservation needed
    },
    {
      id: "book-flight",
      version: "1.0",
      inputSchema: { /* ... */ },
      outputSchema: { /* ... */ },
      async: false,
      maxResponseMs: 30000,
      requiredTrustLevel: 2,
      pricing: { model: "per-transaction", fee: 2.50, currency: "USD" },
      sagaRole: "participant",        // implements reserve/commit/cancel
      reserveCapabilityId: "book-flight",
      cancelCapabilityId: "book-flight",
    },
  ],
  signature: "",  // filled in below
};

// Sign the manifest (keys must be sorted deterministically)
const signingInput = JSON.stringify(sortKeysDeep({ ...manifest, signature: undefined }));
const sigBytes = await ed.signAsync(new TextEncoder().encode(signingInput), identity.privateKey);
manifest.signature = Buffer.from(sigBytes).toString("base64url");
```

### 4.2 Publish and register

```typescript
// Publish manifest to IPFS (optional; can also host it yourself)
import { ArohaIpfsClient } from "@aroha-sdk/registry/ipfs";
const ipfs = new ArohaIpfsClient({ endpoint: "https://aroha-ipfs-gateway.aroha-labs.workers.dev" });
const manifestCID = await ipfs.add(JSON.stringify(manifest));

// Register with an HTTP registry: the reference deployment or your own (apps/registry-server)
const registry = new ArohaHttpRegistry({
  baseUrl: "https://aroha-registry.aroha-labs.workers.dev",  // or your self-hosted URL
  apiKey: process.env.Aroha_REGISTRY_API_KEY!,              // org key issued by that registry's operator
});

await registry.register(identity.did, manifestCID, identity.publicKey);
console.log("Agent registered:", identity.did);
```

After registration, orchestrators calling `registry.queryByCapability(["search-flights"])` will find your agent, fetch the manifest, verify your signature, and begin sending you Aroha messages.

**Checkpoint:** `registry.resolveByDID(identity.did)` should return your `AgentRecord`.

---

## Phase 5 — Credentials & RBAC

If your agent needs to authenticate callers (e.g., only paying customers can book), enable credential verification.

### 5.1 Accept human credentials

Callers include credentials in the `ArohaRequest` or `ArohaReserve` body:

```typescript
// Option A: inline token (first call)
{ capability: "book-flight", params: {...}, credentialToken: "<base64url>" }

// Option B: registry reference (repeated calls, revocable)
{ capability: "book-flight", params: {...}, credentialId: "<uuid>" }
```

### 5.2 Verify in your handler

```typescript
import { verifyHumanCredential, CredentialRegistry } from "@aroha-sdk/credentials";

const credentialRegistry = new CredentialRegistry();

async function checkCredential(body: ArohaRequestBody): Promise<ArohaRole[] | null> {
  if (body.credentialToken) {
    // Inline token — verify signature against issuer public key
    const issuerPublicKey = await resolveIssuerKey(body);  // you must know the issuer DID
    const result = await verifyHumanCredential(body.credentialToken, issuerPublicKey);
    return result.valid ? result.credential!.roles : null;
  }

  if (body.credentialId) {
    // Registry reference
    const cred = await credentialRegistry.resolve(body.credentialId);
    if (!cred) return null;
    const issuerPublicKey = await resolveIssuerKey({ issuerDID: cred.issuerDID });
    const result = await verifyHumanCredential(serializeCredential(cred), issuerPublicKey);
    return result.valid ? cred.roles : null;
  }

  return null;  // unauthenticated
}
```

### 5.3 Configure RBAC in ArohaServer

Mount `createRbacMiddleware` from `@aroha-sdk/credentials` to enforce the standard role permission matrix automatically:

```typescript
import { createRbacMiddleware, ArohaRole } from "@aroha-sdk/credentials";

const server = new ArohaServer({
  // ...
  middleware: [
    createRbacMiddleware({
      // Standard matrix: AgentOrchestrator can query/reserve/commit/cancel
      // AgentObserver can only query
      // Override specific roles if needed:
      permissions: {
        [ArohaRole.HumanUser]: ["query", "reserve", "commit", "cancel"],
        [ArohaRole.AgentOrchestrator]: ["query", "reserve", "commit", "cancel", "delegate"],
      },
      resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
      resolveIssuerPublicKey: async (issuerDID) => knownPublicKeys.get(issuerDID) ?? null,
    })
  ]
  // ...
});
```

`ArohaServer` will reject messages from unauthorized senders before `onMessage` is called — you do not need to check roles inside your handler.

---

## Phase 6 — Testing

Run the full compliance test suite:

Work through the MUST rows in the [conformance test matrix](../conformance/test-matrix.md)
against your running agent, then the interoperability test in the
[implementer packet](../conformance/implementer-packet.md).

Manual checks to verify:

```bash
# 1. DID Document is accessible
curl http://localhost:3001/.well-known/aroha-agent.json | jq .id

# 2. Unknown capability returns ArohaError (not a 500)
#    Build a ArohaRequest for "nonexistent-capability" and check reply.type === "ArohaError"

# 3. Expired envelope is rejected
#    Send a ArohaRequest with `expires` set to the past; server must return 400/ArohaError

# 4. Idempotent commit
#    Reserve → Commit → Commit again with same token; both commits must return identical result

# 5. Cancellation after commit (compensation)
#    Reserve → Commit → Cancel; must return ArohaCancelAck and trigger your refund logic
```

---

## Quick-Reference Checklist

### Phase 1 — Identity & Transport
- [ ] Call `generateDID()` once; persist private key securely
- [ ] Wrap existing server in `ArohaServer`
- [ ] `/.well-known/aroha-agent.json` returns valid DID Document
- [ ] `resolvePublicKey` returns peers' public keys
- [ ] RBAC policy configured with at least `resolveAgentRoles`

### Phase 2 — Message Handler
- [ ] `onMessage` dispatches on `envelope.type`
- [ ] Read-only queries handled via `ArohaRequest` → `ArohaResponse`
- [ ] Unknown capabilities return `ArohaError` with `ArohaErrorCode.UnknownCapability`
- [ ] All replies built with `buildEnvelope()` (auto-signs with `privateKey`)

### Phase 3 — Saga (transactional only)
- [ ] `ArohaReserve` issues a unique `reservationToken`
- [ ] `ArohaCommit` is **idempotent** (same token → same result)
- [ ] `ArohaCancel` always succeeds and triggers compensation logic
- [ ] Reservation state persisted to durable storage

### Phase 4 — Registry
- [ ] Capability manifest built and signed with agent private key
- [ ] Manifest published to IPFS or HTTP registry
- [ ] `sagaRole: "participant"` set for transactional capabilities
- [ ] `registry.register()` called with DID, manifestCID, publicKey

### Phase 5 — Credentials & RBAC
- [ ] `credentialToken` / `credentialId` extracted from message body
- [ ] `verifyHumanCredential()` called before privileged actions
- [ ] `middleware: [createRbacMiddleware(...)]` passed to `ArohaServer` for automatic enforcement

### Phase 6 — Testing
- [ ] Every MUST row in the [conformance test matrix](../conformance/test-matrix.md) passes
- [ ] Idempotent commit verified
- [ ] Compensation flow (cancel after commit) verified
- [ ] DID Document endpoint validated externally

---

## Common Pitfalls

| Mistake | Fix |
|---------|-----|
| Re-generating DID on every restart | Persist `privateKey` bytes; reload and call `generateDID` only once |
| `ArohaCommit` not idempotent | Store `result` in reservation record; return stored value on duplicate commits |
| Forgetting `ArohaCancel` after commit | Always handle cancel even if committed — trigger your refund/void logic |
| Sending raw HTTP errors (4xx/5xx) | Always return a `ArohaError` envelope; raw HTTP errors break saga engines |
| Manifest signature with unsorted keys | Sort keys deterministically before signing: `JSON.stringify(sortKeysDeep(manifest))` |
| `resolvePublicKey` returns `null` for all peers | Seed the map at startup from registry or static config |
| Not setting `sagaRole: "participant"` in manifest | Orchestrators will not include your agent in sagas without this flag |

---

## See Also

- [Aroha Protocol Specification](../spec/aroha-1.0.md)
- [Conformance test matrix](../conformance/test-matrix.md)
- [Mock provider agent](../../agents/mock-provider-agent/src/) — reference provider agent used by the interoperability test
- [Implementer packet](../conformance/implementer-packet.md)
