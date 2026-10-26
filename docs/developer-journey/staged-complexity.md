<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Staged Complexity Guide

This guide is honest about the gap between the 35-second demo and a production deployment.
Follow each stage independently. Each stage is fully functional and testable on its own.

---

## Stage 1 — Localhost Development (Zero Infrastructure)

**What you need:** Node.js 22+. Nothing else.

**What you get:** Two agents talking to each other locally with full saga support.
No blockchain. No Redis. No TLS. No credentials.

> `@aroha-sdk/orchestrator` (sagas) and `@aroha-sdk/settlement` are optional extensions, published on npm; their source is not in this repository. The core protocol (identity, signed envelopes, mandates) does not need them — see the [extensions document](../spec/extensions.md).

```bash
npm install @aroha-sdk/core @aroha-sdk/orchestrator
```

```typescript
import { ArohaServer, generateDID, buildEnvelope } from "@aroha-sdk/core";
import { SagaEngine } from "@aroha-sdk/orchestrator";

// 1. Generate identities (in-memory, ephemeral)
const provider = await generateDID("my-service", "http://localhost:3040");
const client   = await generateDID("my-client",  "http://localhost:3030");

// 2. Start provider server — devMode skips all crypto validation
const server = new ArohaServer({
  agentDID: provider.did, didDocument: provider.document, port: 3040,
  devMode: true,  // <-- localhost only, never in production
  onMessage: async (env, respond) => {
    if (env.body.capability === "say-hello") {
      respond(await buildEnvelope("ArohaResponse", provider.did, env.from,
        { capability: "say-hello", result: { message: "Hello from Aroha!" } },
        env.correlationId, provider.privateKey));
    }
  },
  resolvePublicKey: async () => client.publicKey,
});
await server.start();
```

**Stage 1 checklist:**
- [x] NullSettlement (no payment tracking needed)
- [x] MapNonceStore (in-process, single instance)
- [x] `devMode: true` (skip crypto, no TLS)
- [x] No registry — hardcode endpoint URLs
- [x] No credentials or RBAC

---

## Stage 2 — Staging / Pre-Production

**What you add:** Real crypto validation, Postgres nonce store, HTTP registry, Postgres settlement.

```bash
npm install @aroha-sdk/core @aroha-sdk/orchestrator @aroha-sdk/settlement
```

Key changes from Stage 1:

```typescript
import { PostgresNonceStore } from "@aroha-sdk/core/nonce/postgres";
import { PostgresSettlement } from "@aroha-sdk/settlement";

const server = new ArohaServer({
  devMode: false,            // <-- real crypto now
  clockToleranceMs: 5_000,   // <-- 5s NTP tolerance
  maxBodyBytes: 1_048_576,   // <-- 1MB limit
  nonceStore: new PostgresNonceStore(process.env.DATABASE_URL),
  // ...
});
```

**Stage 2 checklist:**
- [x] `devMode: false` — real Ed25519 signature validation
- [x] Persistent nonce store (Postgres or Redis via `PostgresNonceStore`)
- [x] HTTP registry for capability discovery (no EVM needed)
- [x] Postgres or Stripe settlement backend
- [x] TLS 1.3 via reverse proxy (nginx, Caddy, or cloud load balancer)
- [x] `clockToleranceMs: 5_000` for cross-region deployments

---

## Stage 3 — Production

**What you add:** RBAC credentials, telemetry, mTLS; optionally on-chain registry staking and EVM escrow settlement (optional extensions; the `contracts/` are not part of the core).

**Stage 3 checklist:**
- [x] Optional: EVM registry (`ArohaRegistry.sol`) + ETH staking
- [x] Optional: `EscrowSettlement` for on-chain atomic payments
- [x] `@aroha-sdk/credentials` RBAC middleware
- [x] `@aroha-sdk/telemetry` W3C Trace Context + Grafana dashboard
- [x] mTLS between internal agents (use `@aroha-sdk/trusted-mesh`)
- [x] Redis nonce store for multi-instance deployments
- [x] `CompensationDLQ` wired to `SagaEngine` for rollback recovery
- [x] Emergency key revocation plan documented
- [x] Conformance tier declared in capability manifest

---

## Common Mistakes

| Mistake | Consequence | Fix |
|---|---|---|
| `devMode: true` in production | Zero security | Set `NODE_ENV=production`, remove `devMode` |
| MapNonceStore in multi-instance | Replay attacks succeed cross-instance | Inject `RedisNonceStore` |
| Missing `clockToleranceMs` cross-region | Valid messages silently dropped | Set `clockToleranceMs: 5_000` |
| EVM escrow for internal agents | Unnecessary gas costs | Use `NullSettlement` or `PostgresSettlement` internally |
