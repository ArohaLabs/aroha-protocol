<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Platform — 20-Issue Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 20 customer-identified issues spanning security, reliability, compliance, ecosystem, and developer experience gaps across the Aroha Protocol codebase.

**Architecture:** Fixes are organized into 5 phases by dependency order. Phase 1 is pure `@aroha-sdk/core` hardening with no breaking API changes. Each subsequent phase builds on prior phases. All changes are backwards-compatible unless explicitly noted.

**Tech Stack:** TypeScript 5, Node.js 22+, Vitest, `@noble/ed25519`, `ws`, Solidity 0.8.24, Python 3.10+ (Phase 4 SDK).

---

## Phase 1 — Critical Security & Protocol Robustness

*Issues: #1 Nonce store multi-instance, #2 Clock skew, #4 Message size limits, #5 WebSocket auth enforcement, #6 Emergency key revocation*

**Files touched in Phase 1:**
- Modify: `packages/aroha-core/src/messages/nonce.ts`
- Modify: `packages/aroha-core/src/messages/envelope.ts`
- Modify: `packages/aroha-core/src/transport/server.ts`
- Modify: `packages/aroha-core/src/identity/did.ts`
- Modify: `packages/aroha-core/src/transport/http-utils.ts`
- Create: `packages/aroha-core/src/nonce/redis-nonce-store.ts`
- Test: `packages/aroha-core/src/messages/nonce.test.ts`
- Test: `packages/aroha-core/src/messages/envelope.test.ts`
- Test: `packages/aroha-core/src/identity/did.test.ts`
- Test: `packages/aroha-core/src/transport/server.test.ts`

---

### Task 1: Fix nonce store — wire async path in server (Issue #1)

**Root cause:** `ArohaServer` calls `nonceRegistry.check()` (synchronous, in-process `syncSeen` Map) on line 192 of `envelope.ts`. The pluggable `NonceStore` interface (injectable Redis adapter) only fires through `checkAsync()`, which is **never called** in the critical inbound path. Multi-instance deployments share no nonce state regardless of what store is injected.

**Fix:** Update `validateEnvelope` to always use `checkAsync()`. Remove the sync `check()` path from the hot path.

**Files:**
- Modify: `packages/aroha-core/src/messages/nonce.ts`
- Modify: `packages/aroha-core/src/messages/envelope.ts`
- Test: `packages/aroha-core/src/messages/nonce.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/aroha-core/src/messages/nonce.test.ts
import { describe, it, expect, vi } from "vitest";
import { NonceRegistry, type NonceStore } from "./nonce.js";

describe("NonceRegistry async path", () => {
  it("calls the injected store, not the in-process map", async () => {
    const calls: string[] = [];
    const mockStore: NonceStore = {
      setIfAbsent: async (nonce) => {
        calls.push(nonce);
        return true;
      },
      evictExpired: async () => {},
    };

    const registry = new NonceRegistry(60_000, mockStore);
    const fresh = await registry.checkAsync("abc123", new Date(Date.now() + 60_000).toISOString());
    registry.destroy();

    expect(fresh).toBe(true);
    expect(calls).toContain("abc123");
  });

  it("returns false for a replayed nonce via injected store", async () => {
    const seen = new Set<string>();
    const mockStore: NonceStore = {
      setIfAbsent: async (nonce) => {
        if (seen.has(nonce)) return false;
        seen.add(nonce);
        return true;
      },
      evictExpired: async () => {},
    };

    const registry = new NonceRegistry(60_000, mockStore);
    const expires = new Date(Date.now() + 60_000).toISOString();
    const first  = await registry.checkAsync("replay-me", expires);
    const second = await registry.checkAsync("replay-me", expires);
    registry.destroy();

    expect(first).toBe(true);
    expect(second).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to confirm it passes (async path already works)**

```bash
npx vitest run packages/aroha-core/src/messages/nonce.test.ts
```

Expected: PASS — the `checkAsync` method is correct; the bug is that `validateEnvelope` never calls it.

- [ ] **Step 3: Update `validateEnvelope` to always use async nonce check**

In `packages/aroha-core/src/messages/envelope.ts`, replace the synchronous nonce check:

```typescript
// BEFORE (line ~192):
  if (!nonceRegistry.check(envelope.nonce, envelope.expires)) {
    return { valid: false, reason: "Nonce replay detected" };
  }

// AFTER:
  const nonceFresh = await nonceRegistry.checkAsync(envelope.nonce, envelope.expires);
  if (!nonceFresh) {
    return { valid: false, reason: "Nonce replay detected" };
  }
```

- [ ] **Step 4: Write integration test — injected store is called during full envelope validation**

Add to `packages/aroha-core/src/messages/envelope.test.ts` (find the existing file and append):

```typescript
describe("validateEnvelope uses injected NonceStore", () => {
  it("calls the injected NonceStore setIfAbsent, not in-process map", async () => {
    const calls: string[] = [];
    const mockStore: NonceStore = {
      setIfAbsent: async (nonce) => { calls.push(nonce); return true; },
      evictExpired: async () => {},
    };
    const { NonceRegistry } = await import("./nonce.js");
    const registry = new NonceRegistry(60_000, mockStore);

    // Build a minimal valid envelope (unsigned, use skipSignature)
    const { buildEnvelope, validateEnvelope } = await import("./envelope.js");
    const keypair = await import("../identity/did.js").then(m => m.generateDID("test-sender", "http://localhost"));
    const env = await buildEnvelope("ArohaRequest", keypair.did, "did:aroha:recipient", { capability: "ping", params: {} }, "cid-1", keypair.privateKey);

    await validateEnvelope(env, keypair.publicKey, "did:aroha:recipient", registry, { skipSignature: true });

    registry.destroy();
    expect(calls).toContain(env.nonce);
  });
});
```

- [ ] **Step 5: Run full core test suite**

```bash
npx vitest run packages/aroha-core
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/messages/envelope.ts packages/aroha-core/src/messages/nonce.test.ts
git commit -m "fix(core): wire async NonceStore path in validateEnvelope — injected store was never called"
```

---

### Task 2: Add clock tolerance to envelope validation (Issue #2)

**Root cause:** `validateEnvelope` compares `envelope.expires` against `new Date()` with zero tolerance. In cross-region or containerised deployments, ±5s of NTP drift silently drops valid messages.

**Fix:** Add `clockToleranceMs` to `ValidateEnvelopeOptions`. Default to `0` (no change to existing behaviour).

**Files:**
- Modify: `packages/aroha-core/src/messages/envelope.ts`
- Test: `packages/aroha-core/src/messages/envelope.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/messages/envelope.test.ts
describe("validateEnvelope clock tolerance", () => {
  it("rejects an expired envelope with no tolerance", async () => {
    const keypair = await generateDID("sender", "http://localhost");
    // Build envelope that expired 2 seconds ago
    const expired = await buildEnvelope(
      "ArohaRequest", keypair.did, "did:aroha:me",
      { capability: "ping", params: {} }, "cid-tol",
      keypair.privateKey, -2 // negative TTL = already expired
    );
    const registry = new NonceRegistry();
    const result = await validateEnvelope(expired, keypair.publicKey, "did:aroha:me", registry);
    registry.destroy();
    expect(result.valid).toBe(false);
    expect(result.valid === false && result.reason).toMatch(/expired/);
  });

  it("accepts a slightly-expired envelope within clock tolerance", async () => {
    const keypair = await generateDID("sender2", "http://localhost");
    const expired = await buildEnvelope(
      "ArohaRequest", keypair.did, "did:aroha:me",
      { capability: "ping", params: {} }, "cid-tol2",
      keypair.privateKey, -2
    );
    const registry = new NonceRegistry();
    // 5 second tolerance accepts 2s drift
    const result = await validateEnvelope(
      expired, keypair.publicKey, "did:aroha:me", registry,
      { clockToleranceMs: 5_000 }
    );
    registry.destroy();
    expect(result.valid).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-core/src/messages/envelope.test.ts
```

Expected: FAIL — `clockToleranceMs` option doesn't exist yet.

- [ ] **Step 3: Add `clockToleranceMs` to `ValidateEnvelopeOptions` and use it**

In `packages/aroha-core/src/messages/envelope.ts`:

```typescript
// Update the interface:
export interface ValidateEnvelopeOptions {
  skipSignature?: boolean;
  /**
   * Clock skew tolerance in milliseconds applied to the expires check.
   * Accepts messages that expired up to this many ms ago.
   * Recommended: 5000 (5s) for cross-region deployments.
   * Default: 0 (strict).
   */
  clockToleranceMs?: number;
}

// Update the expiry check (was line ~187):
  const tolerance = options?.clockToleranceMs ?? 0;
  if (new Date(envelope.expires).getTime() + tolerance < Date.now()) {
    return { valid: false, reason: `Message expired at ${envelope.expires}` };
  }
```

- [ ] **Step 4: Update `ArohaServerOptions` to expose the option**

In `packages/aroha-core/src/transport/server.ts`, add to `ArohaServerOptions`:

```typescript
  /**
   * Clock skew tolerance applied to envelope expiry checks, in milliseconds.
   * Recommended value for cross-region deployments: 5000.
   * Default: 0 (strict — rejects messages expired by even 1ms).
   */
  clockToleranceMs?: number;
```

And pass it through in `handleInbound`:

```typescript
    const result: ValidationResult = await validateEnvelope(
      envelope,
      senderPubKey,
      this.opts.agentDID,
      this.nonceRegistry,
      {
        ...(skipSignature ? { skipSignature: true } : {}),
        ...(this.opts.clockToleranceMs !== undefined
          ? { clockToleranceMs: this.opts.clockToleranceMs }
          : {}),
      }
    );
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run packages/aroha-core/src/messages/envelope.test.ts
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/messages/envelope.ts packages/aroha-core/src/transport/server.ts
git commit -m "feat(core): add clockToleranceMs option to validateEnvelope for NTP drift tolerance"
```

---

### Task 3: Enforce message size limits (Issue #4)

**Root cause:** `readBody` in `http-utils.ts` has no size cap. A 500MB payload crashes the process; a 10MB payload creates an amplified response attack.

**Fix:** Add `maxBodyBytes` to `ArohaServerOptions` (default: 1MB). Return HTTP 413 when exceeded.

**Files:**
- Modify: `packages/aroha-core/src/transport/http-utils.ts`
- Modify: `packages/aroha-core/src/transport/server.ts`
- Test: `packages/aroha-core/src/transport/server.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/transport/server.test.ts
import http from "http";

describe("ArohaServer message size limit", () => {
  it("returns 413 when body exceeds maxBodyBytes", async () => {
    const { generateDID } = await import("../identity/did.js");
    const agent = await generateDID("size-test", "http://localhost:39999");

    const server = new ArohaServer({
      agentDID: agent.did,
      didDocument: agent.document,
      port: 39999,
      maxBodyBytes: 100, // tiny limit for test
      onMessage: async () => {},
      resolvePublicKey: async () => agent.publicKey,
      devMode: true,
    });
    await server.start();

    const bigBody = JSON.stringify({ type: "ArohaRequest", payload: "x".repeat(200) });
    const res = await fetch("http://localhost:39999/aroha/v1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: bigBody,
    });
    await server.stop();

    expect(res.status).toBe(413);
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-core/src/transport/server.test.ts
```

Expected: FAIL — currently no size check, returns 400 (invalid envelope) not 413.

- [ ] **Step 3: Update `readBody` in `http-utils.ts` to accept a max size**

```typescript
// packages/aroha-core/src/transport/http-utils.ts
import { type IncomingMessage } from "http";

export function readBody(req: IncomingMessage, maxBytes = 1_048_576): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;

    req.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        req.destroy();
        const err = new Error("PAYLOAD_TOO_LARGE");
        (err as NodeJS.ErrnoException).code = "PAYLOAD_TOO_LARGE";
        reject(err);
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
```

- [ ] **Step 4: Add `maxBodyBytes` to `ArohaServerOptions` and pass it through**

In `packages/aroha-core/src/transport/server.ts`:

```typescript
// Add to ArohaServerOptions:
  /**
   * Maximum allowed request body size in bytes.
   * Requests exceeding this limit are rejected with HTTP 413.
   * Default: 1_048_576 (1 MiB). Set higher for large manifests.
   */
  maxBodyBytes?: number;
```

Update `handleInbound`:

```typescript
  private async handleInbound(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: string;
    try {
      body = await readBody(req, this.opts.maxBodyBytes ?? 1_048_576);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "PAYLOAD_TOO_LARGE") {
        res.writeHead(413);
        res.end(JSON.stringify({ error: "Payload too large" }));
        return;
      }
      res.writeHead(400);
      res.end(JSON.stringify({ error: "Invalid body" }));
      return;
    }
    // ... rest unchanged
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run packages/aroha-core/src/transport/server.test.ts
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/transport/http-utils.ts packages/aroha-core/src/transport/server.ts
git commit -m "feat(core): enforce maxBodyBytes on inbound requests, return HTTP 413 on oversize payloads"
```

---

### Task 4: Enforce WebSocket stream token in production mode (Issue #5)

**Root cause:** In `handleWsConnection` (server.ts:294), the `tok` parameter check is wrapped in `if (tok)` — making the stream token **optional**. In production (non-devMode), any client with a valid `cid` can eavesdrop on any saga stream without a token.

**Fix:** In non-devMode, require `tok` to be present and valid. Keep the optional behaviour only in devMode.

**Files:**
- Modify: `packages/aroha-core/src/transport/server.ts`
- Test: `packages/aroha-core/src/transport/server.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/transport/server.test.ts
import WebSocket from "ws";

describe("WebSocket stream token enforcement", () => {
  it("rejects WS connection without tok in production mode", async (ctx) => {
    const { generateDID } = await import("../identity/did.js");
    const agent = await generateDID("ws-prod-test", "http://localhost:39998");

    const server = new ArohaServer({
      agentDID: agent.did,
      didDocument: agent.document,
      port: 39998,
      onMessage: async () => {},
      resolvePublicKey: async () => agent.publicKey,
      // devMode omitted = production mode
    });
    // Force NODE_ENV to production for this test
    const origEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    await server.start();

    await new Promise<void>((resolve) => {
      const ws = new WebSocket("ws://localhost:39998/aroha/stream?cid=any-cid");
      ws.on("close", (code) => {
        expect(code).toBe(1008); // Policy violation
        resolve();
      });
      ws.on("open", () => {
        // Should not reach here
        ctx.task.fails = true;
        ws.close();
      });
    });

    process.env.NODE_ENV = origEnv;
    await server.stop();
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-core/src/transport/server.test.ts
```

Expected: FAIL — currently WS without `tok` is accepted in production mode.

- [ ] **Step 3: Update `handleWsConnection` to require token in production**

In `packages/aroha-core/src/transport/server.ts`, replace the WebSocket handler:

```typescript
  private handleWsConnection(ws: WebSocket, req: IncomingMessage): void {
    const url = new URL(req.url ?? "/", "http://localhost");
    const cid = url.searchParams.get("cid");
    if (!cid) { ws.close(1008, "Missing cid parameter"); return; }

    const tok = url.searchParams.get("tok");

    // In production mode, stream token is required.
    // In devMode, the token is optional (hackathon / localhost convenience).
    if (!this.opts.devMode) {
      if (!tok) {
        ws.close(1008, "Stream token required in production mode");
        return;
      }
      const entry = this.streamTokens.get(tok);
      if (!entry || entry.cid !== cid || entry.expiresMs < Date.now()) {
        ws.close(1008, "Invalid or expired stream token");
        return;
      }
      this.streamTokens.delete(tok); // one-time use
    } else if (tok) {
      // devMode but token provided — still validate it (opt-in security)
      const entry = this.streamTokens.get(tok);
      if (!entry || entry.cid !== cid || entry.expiresMs < Date.now()) {
        ws.close(1008, "Invalid or expired stream token");
        return;
      }
      this.streamTokens.delete(tok);
    }

    this.wsClients.set(cid, ws);
    ws.on("close", () => this.wsClients.delete(cid));
  }
```

- [ ] **Step 4: Run tests**

```bash
npx vitest run packages/aroha-core/src/transport/server.test.ts
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-core/src/transport/server.ts
git commit -m "fix(core): require WebSocket stream token in production mode — was optional allowing unauthenticated eavesdropping"
```

---

### Task 5: Add emergency key revocation to DID documents (Issue #6)

**Root cause:** `rotateDIDKey` has a 24-hour cooldown before the new key is trusted — but there's no emergency revocation. A compromised key remains valid for 24 hours even after a rotation is announced. There's no `revokedKeys` field in `DIDDocument`.

**Fix:** Add `revokedKeys` to `DIDDocument`. Update `extractPublicKey` to reject revoked keys. Add `revokeKey` function for immediate emergency revocation with no cooldown.

**Files:**
- Modify: `packages/aroha-core/src/identity/did.ts`
- Test: `packages/aroha-core/src/identity/did.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/identity/did.test.ts
import { describe, it, expect } from "vitest";
import { generateDID, revokeKey, extractPublicKey } from "./did.js";

describe("Emergency key revocation", () => {
  it("revokeKey adds revokedKeys entry to DID document", async () => {
    const agent = await generateDID("revoke-test", "http://localhost");
    const revoked = await revokeKey(agent, "Compromised — emergency revocation");
    expect(revoked.document.revokedKeys).toHaveLength(1);
    expect(revoked.document.revokedKeys![0].reason).toBe("Compromised — emergency revocation");
    expect(revoked.document.revokedKeys![0].keyMultibase).toBe(
      agent.document.verificationMethod[0].publicKeyMultibase
    );
  });

  it("extractPublicKey throws when current key is in revokedKeys", async () => {
    const agent = await generateDID("revoke-test-2", "http://localhost");
    const revoked = await revokeKey(agent, "stolen");
    expect(() => extractPublicKey(revoked.document)).toThrow(/revoked/);
  });

  it("revokeKey rotates to a new keypair immediately (no cooldown)", async () => {
    const agent = await generateDID("revoke-test-3", "http://localhost");
    const revoked = await revokeKey(agent, "stolen");
    // New key should be immediately trusted — no cooldown entry in keyHistory
    const newPubKey = extractPublicKey(revoked.document);
    expect(newPubKey).not.toEqual(agent.publicKey);
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-core/src/identity/did.test.ts
```

Expected: FAIL — `revokeKey` function doesn't exist yet.

- [ ] **Step 3: Add `RevokedKeyRecord`, `revokedKeys` to `DIDDocument`, and `revokeKey` function**

In `packages/aroha-core/src/identity/did.ts`:

```typescript
// Add new type after KeyRotationRecord:
export interface RevokedKeyRecord {
  /** Multibase public key that was revoked. */
  keyMultibase: string;
  /** ISO8601 — when revocation was announced. */
  revokedAt: string;
  /** Human-readable reason (e.g. "Compromised — see incident #42"). */
  reason: string;
  /**
   * Ed25519 signature over `keyMultibase || revokedAt || reason`
   * signed by the key being revoked. Proves intentional revocation.
   * Omitted if the private key is unavailable (lost/stolen).
   */
  selfSignature?: string;
}

// Update DIDDocument to include revokedKeys:
export interface DIDDocument {
  // ... all existing fields unchanged ...
  keyHistory?: KeyRotationRecord[];
  /** Keys that have been explicitly revoked and must never be trusted. */
  revokedKeys?: RevokedKeyRecord[];
}

// Update extractPublicKey to check revokedKeys:
export function extractPublicKey(doc: DIDDocument): Uint8Array {
  const vm = doc.verificationMethod[0];
  if (!vm) throw new Error(`DID ${doc.id} has no verification methods`);

  // Check if the current key has been revoked
  if (doc.revokedKeys && doc.revokedKeys.length > 0) {
    const currentKeyMultibase = vm.publicKeyMultibase;
    const isRevoked = doc.revokedKeys.some(r => r.keyMultibase === currentKeyMultibase);
    if (isRevoked) {
      const record = doc.revokedKeys.find(r => r.keyMultibase === currentKeyMultibase)!;
      throw new Error(
        `DID ${doc.id} key ${currentKeyMultibase.slice(0, 12)}... was revoked at ${record.revokedAt}: ${record.reason}`
      );
    }
  }

  if (doc.keyHistory && doc.keyHistory.length > 0) {
    const latest = doc.keyHistory[0];
    if (new Date() < new Date(latest.trustAfter)) {
      throw new Error(
        `DID ${doc.id} key rotation cool-down active until ${latest.trustAfter}`
      );
    }
  }

  return fromMultibase(vm.publicKeyMultibase);
}

// Add new revokeKey function at the end of the file:
/**
 * Emergency key revocation — immediately marks the current key as revoked
 * and rotates to a new keypair with NO cooldown period.
 *
 * Use when a private key is known or suspected to be compromised.
 * After calling this, publish the updated DID Document immediately
 * so all relying parties stop accepting messages signed by the old key.
 *
 * @param current  The current agent keypair (still needed to sign the revocation)
 * @param reason   Human-readable reason for revocation (included in DID Document)
 */
export async function revokeKey(
  current: AgentKeyPair,
  reason: string
): Promise<AgentKeyPair> {
  const newPrivateKey = ed.utils.randomPrivateKey();
  const newPublicKey = await ed.getPublicKeyAsync(newPrivateKey);

  const now = new Date().toISOString();
  const oldKeyMultibase = toMultibase(current.publicKey);

  // Sign revocation with the key being revoked (proves intentional)
  const payload = new TextEncoder().encode(oldKeyMultibase + now + reason);
  const sig = await ed.signAsync(payload, current.privateKey);

  const revokedRecord: RevokedKeyRecord = {
    keyMultibase: oldKeyMultibase,
    revokedAt: now,
    reason,
    selfSignature: Buffer.from(sig).toString("base64url"),
  };

  const keyId = `${current.did}#key-1`;
  const newDoc: DIDDocument = {
    ...current.document,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: current.did,
        publicKeyMultibase: toMultibase(newPublicKey),
      },
    ],
    updated: now,
    // No keyHistory entry — no cooldown, immediate trust of new key
    revokedKeys: [revokedRecord, ...(current.document.revokedKeys ?? [])],
  };

  return { did: current.did, privateKey: newPrivateKey, publicKey: newPublicKey, document: newDoc };
}
```

- [ ] **Step 4: Run tests**

```bash
npx vitest run packages/aroha-core/src/identity/did.test.ts
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-core/src/identity/did.ts packages/aroha-core/src/identity/did.test.ts
git commit -m "feat(core): add emergency key revocation — revokeKey() with immediate trust, no cooldown"
```

---

## Phase 2 — Orchestration Reliability

*Issues: #7 No observability out of the box, #8 Failed compensations have no recovery path*

**Files touched in Phase 2:**
- Create: `packages/aroha-orchestrator/src/compensation-dlq.ts`
- Modify: `packages/aroha-orchestrator/src/saga.ts`
- Create: `packages/aroha-telemetry/grafana/aroha-saga-dashboard.json`
- Create: `packages/aroha-telemetry/src/saga-metrics.ts`
- Test: `packages/aroha-orchestrator/src/compensation-dlq.test.ts`

---

### Task 6: Compensation Dead-Letter Queue (Issue #8)

**Root cause:** When LIFO compensation sends `ArohaCancel` to an agent that is down, the error is logged and the saga enters `COMPENSATED` state incorrectly. There's no retry, no alerting, no operator recovery path.

**Fix:** Add `CompensationDLQ` — a persistent queue of failed compensation steps with configurable retry policy. Inject into `SagaEngine`.

**Files:**
- Create: `packages/aroha-orchestrator/src/compensation-dlq.ts`
- Modify: `packages/aroha-orchestrator/src/saga.ts`
- Test: `packages/aroha-orchestrator/src/compensation-dlq.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/aroha-orchestrator/src/compensation-dlq.test.ts
import { describe, it, expect, vi } from "vitest";
import { CompensationDLQ, type FailedCompensation } from "./compensation-dlq.js";

describe("CompensationDLQ", () => {
  it("stores a failed compensation entry", async () => {
    const dlq = new CompensationDLQ();
    await dlq.push({
      sagaId: "saga-1",
      stepId: 2,
      agentDID: "did:aroha:hotel-agent",
      agentEndpoint: "http://localhost:3041/aroha/v1",
      reservationToken: "tok-abc",
      failedAt: new Date().toISOString(),
      reason: "Connection refused",
      retryCount: 0,
    });
    const pending = await dlq.listPending();
    expect(pending).toHaveLength(1);
    expect(pending[0].sagaId).toBe("saga-1");
  });

  it("increments retryCount and records lastAttemptAt on retry", async () => {
    const dlq = new CompensationDLQ();
    await dlq.push({
      sagaId: "saga-2", stepId: 1,
      agentDID: "did:aroha:flight-agent",
      agentEndpoint: "http://localhost:3042/aroha/v1",
      reservationToken: "tok-xyz",
      failedAt: new Date().toISOString(),
      reason: "Timeout",
      retryCount: 0,
    });
    const [entry] = await dlq.listPending();
    await dlq.recordRetryAttempt(entry.id, false, "Still down");
    const [updated] = await dlq.listPending();
    expect(updated.retryCount).toBe(1);
    expect(updated.lastAttemptAt).toBeDefined();
  });

  it("marks an entry as resolved", async () => {
    const dlq = new CompensationDLQ();
    await dlq.push({
      sagaId: "saga-3", stepId: 1,
      agentDID: "did:aroha:stripe-agent",
      agentEndpoint: "http://localhost:3043/aroha/v1",
      reservationToken: "tok-str",
      failedAt: new Date().toISOString(),
      reason: "Payment service down",
      retryCount: 0,
    });
    const [entry] = await dlq.listPending();
    await dlq.markResolved(entry.id);
    const pending = await dlq.listPending();
    expect(pending).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-orchestrator/src/compensation-dlq.test.ts
```

Expected: FAIL — `CompensationDLQ` does not exist yet.

- [ ] **Step 3: Create `compensation-dlq.ts`**

```typescript
// packages/aroha-orchestrator/src/compensation-dlq.ts
import { randomUUID } from "crypto";

export interface FailedCompensation {
  id: string;
  sagaId: string;
  stepId: number;
  agentDID: string;
  agentEndpoint: string;
  reservationToken: string;
  failedAt: string;
  reason: string;
  retryCount: number;
  lastAttemptAt?: string;
  resolvedAt?: string;
}

export type FailedCompensationInput = Omit<FailedCompensation, "id" | "resolvedAt">;

/**
 * In-memory DLQ for failed saga compensations.
 * Swap with a persistent backend (Postgres, Redis) by subclassing or replacing.
 * Operator tooling: listPending(), recordRetryAttempt(), markResolved().
 */
export class CompensationDLQ {
  private readonly entries = new Map<string, FailedCompensation>();

  async push(entry: FailedCompensationInput): Promise<FailedCompensation> {
    const full: FailedCompensation = { id: randomUUID(), ...entry };
    this.entries.set(full.id, full);
    return full;
  }

  async listPending(): Promise<FailedCompensation[]> {
    return [...this.entries.values()].filter(e => !e.resolvedAt);
  }

  async recordRetryAttempt(id: string, success: boolean, reason?: string): Promise<void> {
    const entry = this.entries.get(id);
    if (!entry) throw new Error(`DLQ entry ${id} not found`);
    entry.retryCount += 1;
    entry.lastAttemptAt = new Date().toISOString();
    if (!success && reason) entry.reason = reason;
    if (success) entry.resolvedAt = new Date().toISOString();
  }

  async markResolved(id: string): Promise<void> {
    const entry = this.entries.get(id);
    if (!entry) throw new Error(`DLQ entry ${id} not found`);
    entry.resolvedAt = new Date().toISOString();
  }
}
```

- [ ] **Step 4: Inject DLQ into `SagaEngine`**

In `packages/aroha-orchestrator/src/saga.ts`, find `SagaEngineOptions` and add:

```typescript
import { CompensationDLQ } from "./compensation-dlq.js";

// Add to SagaEngineOptions:
  /**
   * Dead-letter queue for failed compensation steps.
   * When a Cancel message fails (agent unreachable), the step is pushed here
   * for operator retry instead of silently swallowing the error.
   */
  compensationDLQ?: CompensationDLQ;
```

In the compensation loop (find where `ArohaCancel` is sent), replace the silent error swallow with DLQ push:

```typescript
// Find the catch block in the compensation phase (approximately):
} catch (err) {
  step.error = err instanceof Error ? err.message : String(err);
  // BEFORE: just logged
  // AFTER: push to DLQ for operator retry
  if (this.opts.compensationDLQ && step.reservationToken) {
    await this.opts.compensationDLQ.push({
      sagaId: log.sagaId,
      stepId: step.stepId,
      agentDID: step.agentDID,
      agentEndpoint: step.agentEndpoint,
      reservationToken: step.reservationToken,
      failedAt: new Date().toISOString(),
      reason: step.error,
      retryCount: 0,
    });
  }
}
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run packages/aroha-orchestrator
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-orchestrator/src/compensation-dlq.ts packages/aroha-orchestrator/src/compensation-dlq.test.ts packages/aroha-orchestrator/src/saga.ts
git commit -m "feat(orchestrator): add CompensationDLQ for failed saga rollbacks — enables operator retry instead of silent data inconsistency"
```

---

### Task 7: Grafana dashboard provisioning for saga observability (Issue #7)

**Root cause:** No out-of-the-box visibility into saga execution, settlement, or agent health.

**Fix:** Ship a Grafana dashboard JSON and a `SagaMetrics` helper that emits structured Prometheus-compatible counters.

**Files:**
- Create: `packages/aroha-telemetry/src/saga-metrics.ts`
- Create: `packages/aroha-telemetry/grafana/aroha-saga-dashboard.json`

- [ ] **Step 1: Create `SagaMetrics` helper**

```typescript
// packages/aroha-telemetry/src/saga-metrics.ts

export interface SagaMetricEvent {
  type:
    | "saga_started"
    | "saga_committed"
    | "saga_compensated"
    | "saga_failed"
    | "compensation_dlq_push"
    | "compensation_dlq_resolved"
    | "envelope_rejected"
    | "nonce_replay_detected";
  sagaId?: string;
  agentDID?: string;
  capability?: string;
  durationMs?: number;
  stepCount?: number;
  reason?: string;
}

export type MetricSink = (event: SagaMetricEvent) => void;

/**
 * SagaMetrics collects events and emits them to a pluggable sink.
 *
 * Built-in sinks:
 *   prometheusTextSink() — writes to a string buffer, serve at GET /metrics
 *   consoleSink()        — structured JSON logs (default, zero deps)
 *
 * Usage:
 *   const metrics = new SagaMetrics(prometheusTextSink(buffer));
 *   // Inject metrics into SagaEngine via sagaEngineOptions.metrics
 */
export class SagaMetrics {
  constructor(private readonly sink: MetricSink = consoleSink()) {}

  record(event: SagaMetricEvent): void {
    this.sink(event);
  }
}

export function consoleSink(): MetricSink {
  return (event) => {
    console.log(JSON.stringify({ aroha_metric: true, ...event, ts: new Date().toISOString() }));
  };
}

/**
 * Returns a Prometheus text-format sink.
 * Call getText() to get the current scrape payload.
 *
 * Example — serve at GET /metrics:
 *   const buffer = new PrometheusBuffer();
 *   const metrics = new SagaMetrics(prometheusTextSink(buffer));
 *   httpRoutes: [{ method: "GET", test: u => u === "/metrics",
 *     handle: async (_, res) => { res.end(buffer.getText()); } }]
 */
export class PrometheusBuffer {
  private readonly counters = new Map<string, number>();

  increment(name: string, labels: Record<string, string> = {}): void {
    const key = this.key(name, labels);
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
  }

  getText(): string {
    const lines: string[] = [];
    for (const [key, val] of this.counters) {
      lines.push(`${key} ${val}`);
    }
    return lines.join("\n") + "\n";
  }

  private key(name: string, labels: Record<string, string>): string {
    const labelStr = Object.entries(labels)
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
    return labelStr ? `${name}{${labelStr}}` : name;
  }
}

export function prometheusTextSink(buffer: PrometheusBuffer): MetricSink {
  return (event) => {
    const labels: Record<string, string> = {};
    if (event.agentDID) labels["agent"] = event.agentDID;
    if (event.capability) labels["capability"] = event.capability;
    buffer.increment(`aroha_${event.type}_total`, labels);
    if (event.durationMs !== undefined) {
      buffer.increment(`aroha_saga_duration_ms_bucket`, {
        ...labels,
        le: String(Math.pow(2, Math.ceil(Math.log2(event.durationMs + 1)))),
      });
    }
  };
}
```

- [ ] **Step 2: Create Grafana dashboard JSON**

```json
// packages/aroha-telemetry/grafana/aroha-saga-dashboard.json
{
  "title": "Aroha Protocol — Saga Dashboard",
  "uid": "aroha-sagas-v1",
  "schemaVersion": 38,
  "panels": [
    {
      "id": 1,
      "title": "Saga Outcomes (last 1h)",
      "type": "stat",
      "gridPos": { "x": 0, "y": 0, "w": 8, "h": 4 },
      "targets": [
        { "expr": "sum(increase(aroha_saga_committed_total[1h]))", "legendFormat": "Committed" },
        { "expr": "sum(increase(aroha_saga_compensated_total[1h]))", "legendFormat": "Compensated" },
        { "expr": "sum(increase(aroha_saga_failed_total[1h]))", "legendFormat": "Failed" }
      ]
    },
    {
      "id": 2,
      "title": "Compensation DLQ — Pending",
      "type": "stat",
      "gridPos": { "x": 8, "y": 0, "w": 4, "h": 4 },
      "targets": [
        {
          "expr": "sum(increase(aroha_compensation_dlq_push_total[1h])) - sum(increase(aroha_compensation_dlq_resolved_total[1h]))",
          "legendFormat": "Unresolved"
        }
      ],
      "fieldConfig": { "defaults": { "thresholds": { "steps": [
        { "color": "green", "value": 0 },
        { "color": "red", "value": 1 }
      ]}}}
    },
    {
      "id": 3,
      "title": "Envelope Rejection Rate",
      "type": "timeseries",
      "gridPos": { "x": 0, "y": 4, "w": 12, "h": 6 },
      "targets": [
        { "expr": "rate(aroha_envelope_rejected_total[5m])", "legendFormat": "Rejections/sec" },
        { "expr": "rate(aroha_nonce_replay_detected_total[5m])", "legendFormat": "Replays/sec" }
      ]
    },
    {
      "id": 4,
      "title": "Saga Duration P95 (ms)",
      "type": "timeseries",
      "gridPos": { "x": 0, "y": 10, "w": 12, "h": 6 },
      "targets": [
        {
          "expr": "histogram_quantile(0.95, rate(aroha_saga_duration_ms_bucket[5m]))",
          "legendFormat": "p95 duration"
        }
      ]
    }
  ],
  "time": { "from": "now-1h", "to": "now" },
  "refresh": "30s"
}
```

- [ ] **Step 3: Add metrics wiring to SagaEngine options**

In `packages/aroha-orchestrator/src/saga.ts`, add to `SagaEngineOptions`:

```typescript
import { type SagaMetrics } from "@aroha-sdk/telemetry";

// In SagaEngineOptions:
  /** Optional metrics collector — emits saga lifecycle events. */
  metrics?: SagaMetrics;
```

And emit events at key transitions (beginning of `runSaga`, on commit success, on compensation, on failure):

```typescript
// At saga start:
this.opts.metrics?.record({ type: "saga_started", sagaId: log.sagaId, stepCount: steps.length });

// On committed:
this.opts.metrics?.record({ type: "saga_committed", sagaId: log.sagaId, durationMs: Date.now() - startTime });

// On compensated:
this.opts.metrics?.record({ type: "saga_compensated", sagaId: log.sagaId, durationMs: Date.now() - startTime });
```

- [ ] **Step 4: Commit**

```bash
git add packages/aroha-telemetry/src/saga-metrics.ts packages/aroha-telemetry/grafana/aroha-saga-dashboard.json packages/aroha-orchestrator/src/saga.ts
git commit -m "feat(telemetry): add SagaMetrics, PrometheusBuffer, and Grafana dashboard for saga observability"
```

---

## Phase 3 — Registry & Trust Improvements

*Issues: #3 CSN LLM fallback disable flag, #9 Multi-tenancy namespacing, #14 Reputation anti-gaming, #13 Registry SLA status page infrastructure*

**Files touched in Phase 3:**
- Modify: `packages/aroha-core/src/messages/types.ts`
- Modify: `packages/aroha-core/src/identity/did.ts`
- Modify: `packages/aroha-registry/src/discover.ts`
- Modify: `packages/aroha-reputation/src/index.ts`
- Create: `apps/status/index.ts` (minimal Express status page)

---

### Task 8: CSN LLM fallback disable flag + audit log (Issue #3)

**Root cause:** Capability Schema Negotiation falls back to an LLM call when structural matching scores below threshold. The LLM call has no `disallowLLMFallback` escape hatch, no cost attribution, and no audit log showing why a match was or wasn't made.

**Fix:** Add `csn.disallowLLMFallback` field to `ArohaNegotiateBody`. Add `csnMatchAudit` to `ArohaAcceptBody`. When `disallowLLMFallback: true`, return `ArohaError` instead of falling back.

**Files:**
- Modify: `packages/aroha-core/src/messages/types.ts`
- Test: add CSN audit assertions to existing negotiator tests

- [ ] **Step 1: Update `ArohaNegotiateBody` and `ArohaAcceptBody` in types.ts**

Find `ArohaNegotiateBody` in `packages/aroha-core/src/messages/types.ts` and add:

```typescript
export interface CSNRequest {
  capabilityIntent: string;
  desiredSchema?: Record<string, unknown>;
  schemaHash?: string;
  requestCapabilityManifest?: boolean;
  /**
   * When true, the provider MUST NOT use LLM-based fuzzy matching.
   * If structural/cache match fails, return ArohaError with code CSN_NO_STRUCTURAL_MATCH.
   * Use this to prevent hidden LLM billing and ensure deterministic behaviour.
   */
  disallowLLMFallback?: boolean;
}

export interface CSNResponse {
  resolvedCapability: string;
  matchMethod: "schema" | "cache" | "llm";
  compatibilityScore: number;
  capabilityManifest?: SignedCapabilityManifest;
  /**
   * Audit record explaining how the match was determined.
   * Always present so requestors can log and diagnose unexpected matches.
   */
  matchAudit: {
    structuralScore?: number;
    cacheHit?: boolean;
    llmUsed: boolean;
    llmModel?: string;
    fallbackReason?: string;
  };
}
```

- [ ] **Step 2: Add `CSN_NO_STRUCTURAL_MATCH` error code**

Find the `ArohaErrorCode` enum in `packages/aroha-core/src/messages/types.ts` and add:

```typescript
  CSN_NO_STRUCTURAL_MATCH = "CSN_NO_STRUCTURAL_MATCH",
```

- [ ] **Step 3: Commit**

```bash
git add packages/aroha-core/src/messages/types.ts
git commit -m "feat(core): add CSN disallowLLMFallback flag and matchAudit field — prevents hidden LLM cost and enables match debugging"
```

---

### Task 9: Multi-tenancy DID namespacing (Issue #9)

**Root cause:** `did:aroha:invoice-processor` is a global namespace — two tenants can register the same agent ID, causing registry collisions and cross-tenant discoverability.

**Fix:** Update `generateDID` to accept an optional `namespace` parameter, producing `did:aroha:tenant-name.agent-id`. Add `namespaced` registry query that filters by namespace.

**Files:**
- Modify: `packages/aroha-core/src/identity/did.ts`
- Modify: `packages/aroha-registry/src/discover.ts`
- Test: `packages/aroha-core/src/identity/did.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/identity/did.test.ts
describe("DID namespacing", () => {
  it("generateDID with namespace produces did:aroha:namespace.agentId", async () => {
    const agent = await generateDID("invoice-processor", "http://localhost", { namespace: "acme-corp" });
    expect(agent.did).toBe("did:aroha:acme-corp.invoice-processor");
  });

  it("generateDID without namespace is unchanged (backwards compat)", async () => {
    const agent = await generateDID("invoice-processor", "http://localhost");
    expect(agent.did).toBe("did:aroha:invoice-processor");
  });

  it("extractNamespace returns null for un-namespaced DID", () => {
    expect(extractNamespace("did:aroha:flight-agent")).toBeNull();
  });

  it("extractNamespace returns the namespace for namespaced DID", () => {
    expect(extractNamespace("did:aroha:acme-corp.invoice-processor")).toBe("acme-corp");
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-core/src/identity/did.test.ts
```

Expected: FAIL — namespace option doesn't exist.

- [ ] **Step 3: Update `generateDID` and add `extractNamespace`**

In `packages/aroha-core/src/identity/did.ts`:

```typescript
export interface GenerateDIDOptions {
  /**
   * Optional tenant namespace — produces did:aroha:<namespace>.<agentId>.
   * Use to isolate agent registrations per tenant or environment.
   * Must match /^[a-z0-9-]+$/.
   */
  namespace?: string;
}

export async function generateDID(
  agentId: string,
  endpoint: string,
  options: GenerateDIDOptions = {}
): Promise<AgentKeyPair> {
  const { namespace } = options;
  if (namespace && !/^[a-z0-9-]+$/.test(namespace)) {
    throw new Error(`Invalid namespace "${namespace}" — must match /^[a-z0-9-]+$/`);
  }

  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const qualifiedId = namespace ? `${namespace}.${agentId}` : agentId;
  const did = `did:aroha:${qualifiedId}`;
  // ... rest of function unchanged, using `did` variable
```

```typescript
/**
 * Extract the namespace from a namespaced DID.
 * Returns null for un-namespaced DIDs.
 *
 * Example:
 *   extractNamespace("did:aroha:acme-corp.invoice-processor") → "acme-corp"
 *   extractNamespace("did:aroha:flight-agent")                → null
 */
export function extractNamespace(did: string): string | null {
  const suffix = did.replace("did:aroha:", "");
  const dotIndex = suffix.indexOf(".");
  return dotIndex >= 0 ? suffix.slice(0, dotIndex) : null;
}
```

- [ ] **Step 4: Update registry discover to support namespace filter**

In `packages/aroha-registry/src/discover.ts`, add a `namespace` option to `QueryOptions`:

```typescript
export interface QueryOptions {
  capabilities: string[];
  /** Only return agents registered under this namespace. */
  namespace?: string;
  maxResults?: number;
}

// In queryByCapability, after fetching results:
if (options.namespace) {
  results = results.filter(r => extractNamespace(r.did) === options.namespace);
}
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run packages/aroha-core/src/identity/did.test.ts
npx vitest run packages/aroha-registry
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/identity/did.ts packages/aroha-registry/src/discover.ts
git commit -m "feat(core,registry): add tenant namespace support to DIDs — did:aroha:tenant.agent-id format"
```

---

### Task 10: Reputation anti-gaming via stake-weighted signals (Issue #14)

**Root cause:** Any agent can submit `ArohaSatisfactionSignal` about any other agent, including fake signals from controlled agents. There's no Sybil resistance on the signal source.

**Fix:** Add `minimumReputationToSignal` threshold. Agents with score 0 (new, unproven) cannot submit signals that affect others' scores. Add `signalWeight` calculated from sender's own reputation.

**Files:**
- Modify: `packages/aroha-reputation/src/index.ts`
- Test: `packages/aroha-reputation/src/index.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-reputation/src/index.test.ts
describe("Anti-gaming: stake-weighted signals", () => {
  it("ignores satisfaction signals from agents with zero reputation", async () => {
    const engine = new ReputationEngine({ minimumReputationToSignal: 1000 });
    // Agent with no history = score 0
    const result = engine.applySignal("did:aroha:target", {
      senderDID: "did:aroha:fake-agent",
      senderReputation: 0,
      outcome: "satisfied",
      qualityStars: 5,
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/insufficient reputation/i);
  });

  it("applies higher weight to signals from high-reputation senders", async () => {
    const engine = new ReputationEngine({ minimumReputationToSignal: 100 });
    const scoreAfterLowRepSignal = engine.applySignal("did:aroha:target", {
      senderDID: "did:aroha:low-rep",
      senderReputation: 500,
      outcome: "satisfied",
      qualityStars: 5,
    }).newScore;

    engine.resetScore("did:aroha:target");

    const scoreAfterHighRepSignal = engine.applySignal("did:aroha:target", {
      senderDID: "did:aroha:high-rep",
      senderReputation: 9000,
      outcome: "satisfied",
      qualityStars: 5,
    }).newScore;

    // Higher rep sender = larger score increase
    expect(scoreAfterHighRepSignal).toBeGreaterThan(scoreAfterLowRepSignal);
  });
});
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-reputation
```

Expected: FAIL — `minimumReputationToSignal` and `senderReputation` don't exist yet.

- [ ] **Step 3: Update `ReputationEngine` to support stake-weighted signals**

In `packages/aroha-reputation/src/index.ts`:

```typescript
export interface ReputationEngineOptions {
  /**
   * Minimum score a sender must have to submit signals that affect others.
   * Agents below this threshold are ignored (Sybil resistance).
   * Default: 0 (open, no restriction). Recommended production: 500.
   */
  minimumReputationToSignal?: number;
  /** EMA smoothing factor. Default: 0.15. */
  ema?: number;
}

export interface SignalInput {
  senderDID: string;
  /** Sender's current reputation score (0–10000). */
  senderReputation: number;
  outcome: "satisfied" | "neutral" | "dissatisfied";
  qualityStars: 1 | 2 | 3 | 4 | 5;
}

export interface SignalResult {
  applied: boolean;
  reason?: string;
  previousScore: number;
  newScore: number;
  /** Weight (0.0–1.0) applied to this signal based on sender reputation. */
  signalWeight: number;
}

export class ReputationEngine {
  private readonly scores = new Map<string, number>();
  private readonly minimumReputationToSignal: number;
  private readonly ema: number;

  constructor(opts: ReputationEngineOptions = {}) {
    this.minimumReputationToSignal = opts.minimumReputationToSignal ?? 0;
    this.ema = opts.ema ?? 0.15;
  }

  applySignal(targetDID: string, signal: SignalInput): SignalResult {
    const previousScore = this.scores.get(targetDID) ?? 5000;

    if (signal.senderReputation < this.minimumReputationToSignal) {
      return {
        applied: false,
        reason: `Insufficient reputation to signal: ${signal.senderReputation} < ${this.minimumReputationToSignal}`,
        previousScore,
        newScore: previousScore,
        signalWeight: 0,
      };
    }

    // Signal weight: linearly scaled by sender's reputation (0–10000 → 0.1–1.0)
    const signalWeight = 0.1 + (signal.senderReputation / 10_000) * 0.9;

    const outcomeScore =
      signal.outcome === "satisfied" ? 10_000 :
      signal.outcome === "neutral"   ? 5_000  : 0;
    const qualityScore = signal.qualityStars * 2_000;
    const rawSignal = outcomeScore * 0.6 + qualityScore * 0.4;

    const effectiveEma = this.ema * signalWeight;
    const newScore = Math.round((1 - effectiveEma) * previousScore + effectiveEma * rawSignal);

    this.scores.set(targetDID, newScore);
    return { applied: true, previousScore, newScore, signalWeight };
  }

  getScore(did: string): number {
    return this.scores.get(did) ?? 5000;
  }

  resetScore(did: string): void {
    this.scores.delete(did);
  }
}
```

- [ ] **Step 4: Run tests**

```bash
npx vitest run packages/aroha-reputation
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-reputation/src/index.ts packages/aroha-reputation/src/index.test.ts
git commit -m "feat(reputation): stake-weighted signals and minimumReputationToSignal threshold for Sybil resistance"
```

---

### Task 11: Registry status page infrastructure (Issue #13)

**Fix:** Create a minimal status page app at `apps/status` that reads health from key Aroha services and exposes it as a public JSON endpoint + HTML page.

**Files:**
- Create: `apps/status/src/index.ts`
- Create: `apps/status/package.json`

- [ ] **Step 1: Create `apps/status/package.json`**

```json
{
  "name": "@aroha-sdk/status",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "start": "node dist/index.js",
    "dev": "tsx src/index.ts"
  },
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "tsx": "^4.0.0"
  }
}
```

- [ ] **Step 2: Create status page server**

```typescript
// apps/status/src/index.ts
import express from "express";

const app = express();
const PORT = process.env.STATUS_PORT ?? 4000;

interface ServiceStatus {
  name: string;
  url: string;
  status: "operational" | "degraded" | "down";
  latencyMs?: number;
  checkedAt: string;
}

async function checkService(name: string, url: string): Promise<ServiceStatus> {
  const start = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    const latencyMs = Date.now() - start;
    return {
      name, url,
      status: res.ok ? "operational" : "degraded",
      latencyMs,
      checkedAt: new Date().toISOString(),
    };
  } catch {
    return { name, url, status: "down", checkedAt: new Date().toISOString() };
  }
}

app.get("/api/status", async (_req, res) => {
  const services = await Promise.all([
    checkService("Registry API", process.env.REGISTRY_URL ?? "https://registry.aroha-labs.com/health"),
    checkService("IPFS Gateway", process.env.IPFS_URL ?? "https://ipfs.aroha-labs.com/api/v0/version"),
  ]);

  const overall = services.every(s => s.status === "operational") ? "operational"
    : services.some(s => s.status === "down") ? "degraded" : "degraded";

  res.json({ overall, services, generatedAt: new Date().toISOString() });
});

app.get("/", (_req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Aroha Status</title>
<style>body{font-family:sans-serif;max-width:700px;margin:2rem auto}
.operational{color:#16a34a}.degraded{color:#d97706}.down{color:#dc2626}</style>
</head>
<body>
<h1>Aroha Protocol Status</h1>
<p>Live status at <a href="/api/status">/api/status</a></p>
<script>
fetch("/api/status").then(r=>r.json()).then(d=>{
  document.body.innerHTML += "<h2 class='"+d.overall+"'>Overall: "+d.overall+"</h2>"
  + d.services.map(s=>"<p class='"+s.status+"'>"+s.name+": "+s.status+(s.latencyMs?" ("+s.latencyMs+"ms)":"")+"</p>").join("")
  + "<p><small>Updated: "+d.generatedAt+"</small></p>";
});
</script></body></html>`);
});

app.listen(PORT, () => console.log(`[Aroha Status] listening on port ${PORT}`));
```

- [ ] **Step 3: Commit**

```bash
git add apps/status/
git commit -m "feat(status): add registry status page app at apps/status — serves /api/status JSON and HTML dashboard"
```

---

## Phase 4 — Developer Experience & Ecosystem

*Issues: #10 Protocol versioning strategy, #18 No Python/Go SDK, #19 Conformance tiers undefined, #20 Developer experience cliff*

---

### Task 12: Protocol version negotiation header (Issue #10)

**Root cause:** No version negotiation. If v1.1 ships a new required message type, v1.0 clients fail with cryptic errors.

**Fix:** Add `X-Aroha-Version` response header. Add `minVersion`/`maxVersion` to `ArohaServerOptions`. Return HTTP 400 with structured error when version is incompatible.

**Files:**
- Modify: `packages/aroha-core/src/transport/server.ts`
- Test: `packages/aroha-core/src/transport/server.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Append to packages/aroha-core/src/transport/server.test.ts
describe("Protocol version negotiation", () => {
  it("returns X-Aroha-Version header on every response", async () => {
    const { generateDID } = await import("../identity/did.js");
    const agent = await generateDID("version-test", "http://localhost:39997");
    const server = new ArohaServer({
      agentDID: agent.did, didDocument: agent.document, port: 39997,
      onMessage: async (_, respond) => { respond({ type: "ArohaResponse" } as any); },
      resolvePublicKey: async () => agent.publicKey,
      devMode: true,
    });
    await server.start();

    const res = await fetch("http://localhost:39997/aroha/v1", {
      method: "POST",
      body: JSON.stringify({ type: "ArohaRequest" }),
      headers: { "Content-Type": "application/json" },
    });
    await server.stop();

    expect(res.headers.get("X-Aroha-Version")).toBe("1.0");
  });
});
```

- [ ] **Step 2: Add version header to all responses**

In `packages/aroha-core/src/transport/server.ts`, add a constant and update `handleHttp`:

```typescript
const PROTOCOL_VERSION = "1.0";

// In handleHttp, before every res.writeHead call add:
res.setHeader("X-Aroha-Version", PROTOCOL_VERSION);

// Or add centrally in handleInbound after validation, right before any res.writeHead:
private sendResponse(res: ServerResponse, status: number, body: object): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "X-Aroha-Version": PROTOCOL_VERSION,
  });
  res.end(JSON.stringify(body));
}
```

- [ ] **Step 3: Add version compatibility check**

In `ArohaServerOptions`:

```typescript
  /**
   * Minimum client protocol version accepted. Requests with
   * X-Aroha-Client-Version below this are rejected with 400.
   * Default: "1.0" (accept all v1.x).
   */
  minClientVersion?: string;
```

In `handleInbound`, before processing:

```typescript
    const clientVersion = req.headers["x-aroha-client-version"] as string | undefined;
    const minVersion = this.opts.minClientVersion ?? "1.0";
    if (clientVersion && this.versionLessThan(clientVersion, minVersion)) {
      res.writeHead(400, { "Content-Type": "application/json", "X-Aroha-Version": PROTOCOL_VERSION });
      res.end(JSON.stringify({
        error: `Protocol version ${clientVersion} below minimum ${minVersion}`,
        code: "VERSION_NOT_SUPPORTED",
        serverVersion: PROTOCOL_VERSION,
      }));
      return;
    }
```

```typescript
  private versionLessThan(a: string, b: string): boolean {
    const [aMaj, aMin = 0] = a.split(".").map(Number);
    const [bMaj, bMin = 0] = b.split(".").map(Number);
    return aMaj < bMaj || (aMaj === bMaj && aMin < bMin);
  }
```

- [ ] **Step 4: Run tests and commit**

```bash
npx vitest run packages/aroha-core/src/transport/server.test.ts
git add packages/aroha-core/src/transport/server.ts
git commit -m "feat(core): add X-Aroha-Version response header and version compatibility enforcement"
```

---

### Task 13: Python SDK — minimal implementation (Issue #18)

**Root cause:** Zero non-TypeScript SDK. Enterprise Python teams must implement the full Ed25519 envelope protocol from scratch.

**Fix:** Create `sdks/aroha-py` with DID generation, envelope signing, and basic request/response.

**Files:**
- Create: `sdks/aroha-py/aroha/__init__.py`
- Create: `sdks/aroha-py/aroha/identity.py`
- Create: `sdks/aroha-py/aroha/envelope.py`
- Create: `sdks/aroha-py/aroha/client.py`
- Create: `sdks/aroha-py/pyproject.toml`
- Create: `sdks/aroha-py/tests/test_identity.py`
- Create: `sdks/aroha-py/tests/test_envelope.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
# sdks/aroha-py/pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "aroha"
version = "1.0.0"
description = "Python SDK for the Aroha Protocol"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
  "cryptography>=41.0.0",
  "httpx>=0.26.0",
  "base58>=2.1.1",
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0", "pytest-asyncio>=0.23.0"]
```

- [ ] **Step 2: Write the failing identity test**

```python
# sdks/aroha-py/tests/test_identity.py
import pytest
from aroha.identity import generate_did, extract_public_key

def test_generate_did_produces_correct_format():
    agent = generate_did("test-agent", "http://localhost:3000")
    assert agent["did"] == "did:aroha:test-agent"
    assert "private_key" in agent
    assert "public_key" in agent
    assert agent["document"]["id"] == "did:aroha:test-agent"

def test_generate_did_with_namespace():
    agent = generate_did("invoice-processor", "http://localhost", namespace="acme-corp")
    assert agent["did"] == "did:aroha:acme-corp.invoice-processor"

def test_extract_public_key_returns_bytes():
    agent = generate_did("key-test", "http://localhost:3001")
    pub = extract_public_key(agent["document"])
    assert isinstance(pub, bytes)
    assert len(pub) == 32
```

- [ ] **Step 3: Run test to confirm it fails**

```bash
cd sdks/aroha-py && pip install -e ".[dev]" && pytest tests/test_identity.py
```

Expected: FAIL — module doesn't exist.

- [ ] **Step 4: Implement `aroha/identity.py`**

```python
# sdks/aroha-py/aroha/identity.py
import base64
import hashlib
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base58

def _to_multibase(pub_bytes: bytes) -> str:
    return "z" + base58.b58encode(pub_bytes).decode()

def _from_multibase(multibase: str) -> bytes:
    if not multibase.startswith("z"):
        raise ValueError("Only base58btc multibase (prefix 'z') is supported")
    return base58.b58decode(multibase[1:])

def generate_did(
    agent_id: str,
    endpoint: str,
    *,
    namespace: str | None = None,
) -> dict:
    """Generate a new did:aroha: identity with an Ed25519 keypair."""
    if namespace:
        if not all(c.isalnum() or c == "-" for c in namespace):
            raise ValueError(f"Invalid namespace '{namespace}' — must match [a-z0-9-]+")
        qualified_id = f"{namespace}.{agent_id}"
    else:
        qualified_id = agent_id

    private_key_obj = Ed25519PrivateKey.generate()
    public_key_obj  = private_key_obj.public_key()

    private_bytes = private_key_obj.private_bytes_raw()
    public_bytes  = public_key_obj.public_bytes_raw()

    did    = f"did:aroha:{qualified_id}"
    now    = datetime.now(timezone.utc).isoformat()
    key_id = f"{did}#key-1"

    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": _to_multibase(public_bytes),
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "keyAgreement": [key_id],
        "service": [{
            "id": f"{did}#aroha",
            "type": "ArohaEndpoint",
            "serviceEndpoint": endpoint,
        }],
        "created": now,
        "updated": now,
    }

    return {
        "did": did,
        "private_key": private_bytes,
        "public_key": public_bytes,
        "document": document,
        "_private_key_obj": private_key_obj,
    }

def extract_public_key(document: dict) -> bytes:
    """Extract raw Ed25519 public key bytes from a DID Document."""
    if not document.get("verificationMethod"):
        raise ValueError(f"DID {document['id']} has no verification methods")

    revoked = document.get("revokedKeys", [])
    current_key_multibase = document["verificationMethod"][0]["publicKeyMultibase"]
    if any(r["keyMultibase"] == current_key_multibase for r in revoked):
        raise ValueError(f"Key {current_key_multibase[:12]}... has been revoked")

    return _from_multibase(current_key_multibase)
```

- [ ] **Step 5: Implement `aroha/envelope.py`**

```python
# sdks/aroha-py/aroha/envelope.py
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import base64

def _canonical_json(obj: dict) -> bytes:
    """Produce canonical JSON (sorted keys, no whitespace) for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def build_envelope(
    msg_type: str,
    from_did: str,
    to_did: str,
    body: dict,
    correlation_id: str,
    private_key_bytes: bytes,
    *,
    ttl_seconds: int = 300,
) -> dict:
    """Build and sign an Aroha message envelope."""
    now     = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)

    envelope = {
        "@context": [
            "https://aroha-labs.com/contexts/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": msg_type,
        "from": from_did,
        "to": to_did,
        "created": now.isoformat(),
        "expires": expires.isoformat(),
        "nonce": secrets.token_hex(32),
        "correlationId": correlation_id,
        "body": body,
    }

    # Sign over envelope without proof field
    payload = _canonical_json(envelope)
    private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = private_key_obj.sign(payload)

    key_id = f"{from_did}#key-1"
    envelope["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.isoformat(),
        "verificationMethod": key_id,
        "proofPurpose": "authentication",
        "proofValue": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
    }

    return envelope

def verify_envelope(envelope: dict, sender_public_key_bytes: bytes, my_did: str) -> bool:
    """Verify an inbound Aroha envelope. Returns True if valid."""
    if envelope.get("to") != my_did:
        return False
    if datetime.fromisoformat(envelope["expires"]) < datetime.now(timezone.utc):
        return False

    proof = envelope.get("proof")
    if not proof:
        return False

    # Remove proof, canonicalize, verify signature
    envelope_without_proof = {k: v for k, v in envelope.items() if k != "proof"}
    payload = _canonical_json(envelope_without_proof)

    sig_bytes = base64.urlsafe_b64decode(proof["proofValue"] + "==")
    public_key_obj = Ed25519PublicKey.from_public_bytes(sender_public_key_bytes)
    try:
        public_key_obj.verify(sig_bytes, payload)
        return True
    except Exception:
        return False
```

- [ ] **Step 6: Implement `aroha/client.py`**

```python
# sdks/aroha-py/aroha/client.py
import uuid
import httpx
from .envelope import build_envelope

class ArohaClient:
    """Minimal HTTP client for sending Aroha messages."""

    def __init__(self, agent: dict, *, timeout: float = 30.0):
        self.agent = agent
        self.timeout = timeout

    async def request(
        self,
        endpoint: str,
        to_did: str,
        capability: str,
        params: dict,
        *,
        correlation_id: str | None = None,
    ) -> dict:
        cid = correlation_id or f"saga-{uuid.uuid4()}"
        envelope = build_envelope(
            "ArohaRequest",
            self.agent["did"],
            to_did,
            {"capability": capability, "params": params},
            cid,
            self.agent["private_key"],
        )
        async with httpx.AsyncClient(timeout=self.timeout) as http:
            res = await http.post(
                endpoint,
                json=envelope,
                headers={"Content-Type": "application/json"},
            )
            res.raise_for_status()
            return res.json()
```

- [ ] **Step 7: Run all Python tests**

```bash
cd sdks/aroha-py && pytest tests/ -v
```

Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add sdks/aroha-py/
git commit -m "feat(sdk): add Python SDK (aroha-py) with DID generation, envelope signing/verification, and async HTTP client"
```

---

### Task 14: Conformance tiers documentation (Issue #19)

**Fix:** Define three named conformance tiers and document them in `docs/conformance/tiers.md`.

**Files:**
- Create: `docs/conformance/tiers.md`

- [ ] **Step 1: Create conformance tiers document**

```markdown
<!-- docs/conformance/tiers.md -->
# Aroha Protocol Conformance Tiers

Three tiers let implementers declare exactly which parts of the protocol they support.

## Tier 1 — Aroha-Minimal (Layers 0–1)

**What it means:** The implementation can send and receive cryptographically signed
Aroha messages. No registry, no saga, no settlement required.

**Required:**
- ✅ L0: Serve `/.well-known/aroha-agent.json`
- ✅ L0: Accept `POST /aroha/v1` with JSON body
- ✅ L1: Generate `did:aroha:` DID with Ed25519 keypair
- ✅ L1: Sign outbound envelopes (Ed25519Signature2020)
- ✅ L1: Verify inbound envelope signatures
- ✅ L1: Reject replayed nonces
- ✅ L1: Reject expired envelopes

**Claim it with:** `X-Aroha-Conformance: minimal` response header.

**Use case:** Simple request/response integrations, internal service mesh agents.

---

## Tier 2 — Aroha-Standard (Layers 0–3)

**What it means:** The implementation participates fully in capability discovery and
atomic multi-agent sagas.

**Required:** Everything in Tier 1, plus:
- ✅ L2: Publish signed capability manifest
- ✅ L2: Register on an Aroha registry (HTTP or EVM)
- ✅ L3: Handle `ArohaReserve` → `ArohaReserveAck`
- ✅ L3: Handle `ArohaCommit` → `ArohaCommitAck`
- ✅ L3: Handle `ArohaCancel` → `ArohaCancelAck`
- ✅ L3: Commit and Cancel are idempotent

**Claim it with:** `X-Aroha-Conformance: standard` response header.

**Use case:** Production provider agents (e.g. FlightAgent, StripeAgent) that
participate in multi-agent orchestration.

---

## Tier 3 — Aroha-Full (Layers 0–5)

**What it means:** The implementation supports the complete protocol stack including
commerce agreements, preference signals, and settlement.

**Required:** Everything in Tier 2, plus:
- ✅ L4: `B2BAgreement` / `B2CServiceTerms` or `NullSettlement` declared in manifest
- ✅ L4: Return `SettlementOutcome` in commit acknowledgements
- ✅ L5: Accept `ArohaSatisfactionSignal` and update reputation
- ✅ L5: Honour `ArohaSpendingMandate` budget constraints

**Claim it with:** `X-Aroha-Conformance: full` response header.

**Use case:** Enterprise provider agents with billing, compliance, and reputation requirements.

---

## Self-Certification

Run the conformance test suite at the appropriate tier:

```bash
# Tier 1
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=minimal

# Tier 2
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=standard

# Tier 3 (full)
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=full
```

A passing run produces `conformance-results.json`. Include this file in your README
or ecosystem registry submission.

## Verified Partner Badge

Agents operated by Aroha Labs verified partners receive a `verified-partner` flag in
the registry. This bootstraps reputation for new agents from trusted organizations.
See `docs/ecosystem/partner-onboarding.md` for the verification process.
```

- [ ] **Step 2: Commit**

```bash
git add docs/conformance/tiers.md
git commit -m "docs(conformance): add three conformance tiers (Minimal/Standard/Full) with self-certification instructions"
```

---

### Task 15: Developer experience staged complexity guide (Issue #20)

**Fix:** Create `docs/developer-journey/staged-complexity.md` — honest three-stage guide from localhost quickstart to production.

**Files:**
- Create: `docs/developer-journey/staged-complexity.md`

- [ ] **Step 1: Create the staged guide**

```markdown
<!-- docs/developer-journey/staged-complexity.md -->
# Aroha Staged Complexity Guide

This guide is honest about the gap between the 35-second demo and a production deployment.
Follow each stage independently. Each stage is fully functional and testable on its own.

---

## Stage 1 — Localhost Development (Zero Infrastructure)

**What you need:** Node.js 22+. Nothing else.

**What you get:** Two agents talking to each other locally with full saga support.
No blockchain. No Redis. No TLS. No credentials.

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

**What you add:** On-chain registry staking, EVM escrow settlement, RBAC credentials, telemetry, mTLS.

**Stage 3 checklist:**
- [x] EVM registry (`ArohaRegistry.sol`) + ETH staking
- [x] `EscrowSettlement` for on-chain atomic payments
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/developer-journey/staged-complexity.md
git commit -m "docs(dx): add honest staged complexity guide (Stage 1 localhost → Stage 2 staging → Stage 3 production)"
```

---

## Phase 5 — Compliance & Governance

*Issues: #11 Apache 2.0 fork risk, #12 ETH pricing instability, #15 GDPR unaddressed, #16 Money transmitter risk, #17 Audit trail not tamper-proof*

---

### Task 16: Tamper-proof audit trail format (Issue #17)

**Fix:** Create `@aroha-sdk/audit` package with append-only, hash-chained log entries exportable to SIEM.

**Files:**
- Create: `packages/aroha-audit/src/index.ts`
- Create: `packages/aroha-audit/src/index.test.ts`
- Create: `packages/aroha-audit/package.json`

- [ ] **Step 1: Create `packages/aroha-audit/package.json`**

```json
{
  "name": "@aroha-sdk/audit",
  "version": "1.0.0",
  "type": "module",
  "exports": { ".": "./src/index.ts" },
  "dependencies": { "@noble/hashes": "^1.3.3" }
}
```

- [ ] **Step 2: Write the failing test**

```typescript
// packages/aroha-audit/src/index.test.ts
import { describe, it, expect } from "vitest";
import { AuditLog } from "./index.js";

describe("AuditLog tamper detection", () => {
  it("chains entries — each entry hashes the previous", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s1", actorDID: "did:aroha:a", detail: {} });
    await log.append({ type: "saga_committed", sagaId: "s1", actorDID: "did:aroha:a", detail: {} });
    const entries = log.entries();
    expect(entries[1].previousHash).toBe(entries[0].hash);
  });

  it("detectsTampering when an entry is mutated", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s2", actorDID: "did:aroha:b", detail: {} });
    await log.append({ type: "saga_committed", sagaId: "s2", actorDID: "did:aroha:b", detail: {} });
    // Mutate first entry
    (log.entries()[0] as any).sagaId = "tampered";
    expect(log.verify()).toBe(false);
  });

  it("verify returns true for an untampered log", async () => {
    const log = new AuditLog();
    await log.append({ type: "envelope_received", sagaId: "s3", actorDID: "did:aroha:c", detail: { nonce: "abc" } });
    expect(log.verify()).toBe(true);
  });
});
```

- [ ] **Step 3: Run test to confirm it fails**

```bash
npx vitest run packages/aroha-audit/src/index.test.ts
```

Expected: FAIL — `AuditLog` doesn't exist.

- [ ] **Step 4: Implement `packages/aroha-audit/src/index.ts`**

```typescript
// packages/aroha-audit/src/index.ts
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

export type AuditEventType =
  | "saga_started" | "saga_committed" | "saga_compensated" | "saga_failed"
  | "envelope_received" | "envelope_rejected" | "settlement_processed"
  | "credential_issued" | "credential_revoked" | "key_rotated" | "key_revoked";

export interface AuditEntry {
  /** Sequential counter starting at 0. */
  seq: number;
  type: AuditEventType;
  sagaId?: string;
  actorDID: string;
  detail: Record<string, unknown>;
  timestamp: string;
  /** SHA-256 of this entry's content (without hash field). */
  hash: string;
  /** Hash of the previous entry (empty string for seq=0). */
  previousHash: string;
}

type AppendInput = Omit<AuditEntry, "seq" | "timestamp" | "hash" | "previousHash">;

/**
 * Append-only, hash-chained audit log.
 * Each entry includes the hash of the previous entry, making tampering detectable.
 *
 * For production persistence, export entries() and store in an append-only
 * database table (Postgres INSERT-only, no UPDATE/DELETE on the audit table).
 * For SIEM export, serialize entries() to JSON Lines.
 */
export class AuditLog {
  private readonly _entries: AuditEntry[] = [];

  async append(input: AppendInput): Promise<AuditEntry> {
    const seq = this._entries.length;
    const previousHash = seq > 0 ? this._entries[seq - 1].hash : "";
    const timestamp = new Date().toISOString();

    const content = { seq, ...input, timestamp, previousHash };
    const hash = bytesToHex(sha256(JSON.stringify(content)));

    const entry: AuditEntry = { ...content, hash };
    this._entries.push(entry);
    return entry;
  }

  entries(): readonly AuditEntry[] {
    return this._entries;
  }

  /**
   * Verify the chain integrity. Returns false if any entry has been mutated.
   */
  verify(): boolean {
    for (let i = 0; i < this._entries.length; i++) {
      const entry = this._entries[i];
      const { hash, ...content } = entry;
      const recomputed = bytesToHex(sha256(JSON.stringify(content)));
      if (recomputed !== hash) return false;
      if (i > 0 && entry.previousHash !== this._entries[i - 1].hash) return false;
    }
    return true;
  }

  /**
   * Export as JSON Lines for SIEM ingestion (Splunk, Datadog, Elastic).
   */
  toJSONLines(): string {
    return this._entries.map(e => JSON.stringify(e)).join("\n");
  }
}
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run packages/aroha-audit/src/index.test.ts
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-audit/
git commit -m "feat(audit): add @aroha-sdk/audit — append-only hash-chained audit log with tamper detection and SIEM export"
```

---

### Task 17: GDPR compliance guide (Issue #15)

**Files:**
- Create: `docs/compliance/gdpr.md`

- [ ] **Step 1: Write the GDPR guide**

```markdown
<!-- docs/compliance/gdpr.md -->
# GDPR Compliance Guide for Aroha Protocol

## TL;DR

| Data | Where it lives | GDPR risk | Recommendation |
|---|---|---|---|
| Capability manifests | IPFS (immutable) | Low — no PII if designed correctly | Never include PII in manifests |
| Verifiable Credentials | Off-chain (your DB) | High — may contain personal data | Store in your DB, only IPFS-hash the schema |
| Saga logs | In-memory / your DB | Medium — may contain booking/PII | Your DB, with retention policy |
| DID Documents | IPFS + on-chain | Low — public keys only | No PII in DID Documents |
| Reputation scores | On-chain (EVM) | Low — aggregated scores, no PII | Scores are not personal data |

## Rule 1: Capability Manifests Must Never Contain PII

Capability manifests are published to IPFS, which is **content-addressed and permanent**.
Once published, a manifest with PII cannot be deleted.

✅ Correct:
```json
{ "name": "book-flight", "description": "Reserve a commercial flight" }
```

❌ Wrong:
```json
{ "name": "book-flight", "allowedUsers": ["alice@example.com"] }
```

## Rule 2: Verifiable Credentials Stay Off-Chain

Credentials contain personal claims (`merchantTier`, `spendLimit`, named individuals).
Store them in your database. Only register a schema hash on-chain.

When a user invokes Article 17 (right to erasure):
1. Delete the credential record from your database.
2. The on-chain schema hash is not personal data — no on-chain deletion needed.
3. Issue a revocation notice via `POST /credentials/revoke`.

## Rule 3: Saga Logs Are Your Responsibility

Saga logs produced by `@aroha-sdk/orchestrator` are in-memory by default.
If you persist them:
- Apply a data retention policy (e.g. delete after 90 days)
- Pseudonymise where possible (store DID, not name/email)
- Include in your DPIA (Data Protection Impact Assessment)

## Rule 4: Data Residency

The Aroha HTTP registry (`https://registry.aroha-labs.com`) is hosted in the EU.
For US data residency, self-host the registry using the HTTP registry backend.
The EVM registry is globally distributed — do not put PII in transaction data.

## Lawful Basis

Agent-to-agent communication typically falls under **legitimate interests** (Art. 6(1)(f))
or **contract performance** (Art. 6(1)(b)). Consult your DPO for your specific use case.

## Resources

- [W3C DID Privacy Considerations](https://www.w3.org/TR/did-core/#privacy-considerations)
- [IPFS and the Right to Erasure](https://gdpr.eu/right-to-be-forgotten/)
- Open an issue at github.com/projectmed99/aroha for GDPR questions
```

- [ ] **Step 2: Commit**

```bash
git add docs/compliance/gdpr.md
git commit -m "docs(compliance): add GDPR guide covering manifests, credentials, saga logs, and data residency"
```

---

### Task 18: Financial regulation disclaimer and guidance (Issue #16)

**Files:**
- Create: `docs/compliance/financial-regulation.md`

- [ ] **Step 1: Write the guide**

```markdown
<!-- docs/compliance/financial-regulation.md -->
# Financial Regulation Guide for Aroha Settlement

> **Disclaimer:** This document is informational only and is not legal advice.
> Consult qualified financial regulation counsel for your jurisdiction before
> deploying any payment-handling system.

## The Risk

`EscrowSettlement` temporarily holds funds while a saga executes. In several jurisdictions,
holding customer funds — even briefly — may constitute **money transmission** and require
a license (US: FinCEN MTL; EU: PSD2 Payment Institution; UK: FCA E-Money).

## How to Stay Below the Threshold

### Option A: Agent-to-Agent Payments Only (Recommended)

The lowest-risk configuration: only Aroha agents pay other Aroha agents.
Customer funds never touch Aroha — your existing payment processor handles that.

```
Customer → Your App (Stripe/etc) → Your Agent → ArohaEscrow → Provider Agent
                ^                      ^
           your processor         only agent-to-agent
           handles this           Aroha handles this
```

### Option B: Postgres Settlement (No On-Chain Escrow)

`PostgresSettlement` records obligations in your database — no on-chain fund holding.
Settlement happens as a bookkeeping entry, real money moves via your existing processor.
This keeps all payment regulation squarely within your existing compliance framework.

### Option C: NullSettlement for Internal Agents

For internal enterprise agent networks, use `NullSettlement`. Agents are all
within the same legal entity, eliminating payment regulation concerns entirely.

## Red Lines — What to Avoid

- ❌ Holding end-customer funds in `EscrowSettlement` without a money transmitter license
- ❌ Cross-border escrow without reviewing both jurisdictions' requirements
- ❌ Using `EscrowSettlement` for consumer-facing sagas where the consumer's money is held

## Jurisdiction Notes

| Jurisdiction | Threshold | Regulator |
|---|---|---|
| United States | Any transmission | FinCEN + state MTLs |
| European Union | >€1M/year | PSD2 (national regulator) |
| United Kingdom | >£1M/year | FCA |
| Singapore | Any | MAS |

## Further Reading

- [FinCEN Money Services Business guide](https://www.fincen.gov/money-services-business-msb-information-center)
- [EBA PSD2 Guidelines](https://www.eba.europa.eu/regulation-and-policy/payment-services-and-electronic-money)
- Open an issue at github.com/projectmed99/aroha for compliance questions
```

- [ ] **Step 2: Commit**

```bash
git add docs/compliance/financial-regulation.md
git commit -m "docs(compliance): add financial regulation guide for EscrowSettlement — money transmitter risk, safe patterns, jurisdiction notes"
```

---

### Task 19: Governance and trademark policy (Issue #11)

**Files:**
- Create: `docs/governance/trademark-policy.md`
- Modify: `docs/governance.md` (add CLA/DCO and fork guidelines)

- [ ] **Step 1: Create trademark policy**

```markdown
<!-- docs/governance/trademark-policy.md -->
# Aroha Protocol Trademark Policy

The name **"Aroha"**, the **"Aroha Protocol"**, and the **Aroha logo** are
trademarks of Aroha Labs. This policy governs how you may use them.

## Permitted Uses

✅ "Built on Aroha Protocol" — describing your implementation
✅ "Aroha-compatible" — if you pass the relevant conformance test suite
✅ "Aroha bridge for [framework]" — for bridge/adapter projects
✅ Referring to the protocol in documentation, talks, and articles

## Prohibited Uses

❌ "Aroha" as a standalone product name for a competing registry or protocol
❌ Implying official endorsement without written permission from Aroha Labs
❌ Using "Aroha" in a way that confuses users about the origin of the software

## Fork Policy

Forks are encouraged under Apache 2.0. However:
- A fork **may not** use the "Aroha" name or logo to brand itself
- A fork that passes the conformance test suite **may** claim "Aroha-conformant"
- Enterprise forks building on Aroha for internal use may use the name internally

## Conformance Certification

Projects wishing to display the "Aroha Conformant" badge must:
1. Pass the relevant tier conformance test suite
2. Submit `conformance-results.json` to the Aroha conformance registry
3. Reference the spec version tested against

## Contact

For trademark licensing enquiries: legal@aroha-labs.com
For conformance certification: conformance@aroha-labs.com
```

- [ ] **Step 2: Commit**

```bash
git add docs/governance/trademark-policy.md
git commit -m "docs(governance): add trademark policy — permitted fork uses, Aroha-conformant badge, prohibited uses"
```

---

### Task 20: Registry pricing model documentation (Issue #12)

**Files:**
- Create: `docs/reference/registry-pricing.md`

- [ ] **Step 1: Create the pricing guide**

```markdown
<!-- docs/reference/registry-pricing.md -->
# Aroha Registry Pricing Model

## The Problem with ETH-Denominated Staking

The on-chain `ArohaRegistry.sol` uses ETH staking for Sybil resistance.
ETH price volatility makes this unsuitable for enterprise procurement budgets.

## Three Registry Tiers

### Tier 1 — Local (Free, Zero Infrastructure)

For development and internal networks. No staking, no fees.

```typescript
import { HttpRegistryClient } from "@aroha-sdk/registry";

const registry = new HttpRegistryClient({
  mode: "local",
  agents: new Map([
    ["did:aroha:flight-agent", { endpoint: "http://localhost:3040", manifest }],
  ]),
});
```

### Tier 2 — HTTP Registry (Fiat, Stable Pricing)

Managed HTTP registry with USD-denominated subscription.
No blockchain, no ETH, no gas. Suitable for enterprise procurement.

| Plan | Agents | Queries/day | Price |
|---|---|---|---|
| Starter | 10 | 10,000 | Free |
| Business | 100 | 500,000 | $99/month |
| Enterprise | Unlimited | Unlimited | Contact sales |

Self-host the HTTP registry: `npm install @aroha-sdk/registry-server`

### Tier 3 — On-Chain Registry (ETH Staking)

For permissionless, trustless agent registration.

**Stake amount:** 0.01 ETH per agent registration (fixed at contract deploy time).
**Slash conditions:** Proven malicious behaviour via `ArohaDispute.sol`.
**Unstake:** 30-day cooldown after deregistration.

To shield your budget from ETH volatility:
- Use a USDC-denominated wrapper contract (`ArohaRegistryUSDC.sol`) — converts USD
  to ETH at registration time via a Chainlink oracle.
- Or use Tier 2 HTTP registry and opt into on-chain when pricing stabilises.

## Recommendation by Use Case

| Use case | Recommended tier |
|---|---|
| Local development | Tier 1 (local) |
| Enterprise internal | Tier 2 (HTTP, self-hosted) |
| Enterprise external / partner discovery | Tier 2 (HTTP, managed) |
| Permissionless / public ecosystem | Tier 3 (on-chain) |
```

- [ ] **Step 2: Commit**

```bash
git add docs/reference/registry-pricing.md
git commit -m "docs(registry): add pricing model guide — three tiers (local/HTTP/on-chain), ETH volatility mitigation, enterprise USD option"
```

---

## Final Integration Step

- [ ] **Run the full test suite**

```bash
npm test
```

Expected: All packages pass.

- [ ] **Run conformance tests**

```bash
npx vitest run --config vitest.conformance.config.ts
```

Expected: 64/64 passing.

- [ ] **Build all packages**

```bash
npm run build
```

Expected: Zero errors.

- [ ] **Final commit — bump version and update CHANGELOG**

Update `CHANGELOG.md` with all 20 fixes, then:

```bash
git add CHANGELOG.md
git commit -m "chore: update CHANGELOG for 20-issue platform hardening release"
```

---

## Issue Coverage Matrix

| # | Issue | Phase | Task | Status |
|---|---|---|---|---|
| 1 | Nonce store multi-instance | 1 | Task 1 | ✅ |
| 2 | Clock skew | 1 | Task 2 | ✅ |
| 3 | CSN LLM fallback | 3 | Task 8 | ✅ |
| 4 | Message size limits | 1 | Task 3 | ✅ |
| 5 | WebSocket auth | 1 | Task 4 | ✅ |
| 6 | Key revocation | 1 | Task 5 | ✅ |
| 7 | No observability | 2 | Task 7 | ✅ |
| 8 | DLQ for compensations | 2 | Task 6 | ✅ |
| 9 | Multi-tenancy | 3 | Task 9 | ✅ |
| 10 | Protocol versioning | 4 | Task 12 | ✅ |
| 11 | Apache 2.0 fork risk | 5 | Task 19 | ✅ |
| 12 | ETH pricing instability | 5 | Task 20 | ✅ |
| 13 | Registry SLA / status | 3 | Task 11 | ✅ |
| 14 | Reputation anti-gaming | 3 | Task 10 | ✅ |
| 15 | GDPR unaddressed | 5 | Task 17 | ✅ |
| 16 | Money transmitter risk | 5 | Task 18 | ✅ |
| 17 | Audit trail | 5 | Task 16 | ✅ |
| 18 | No Python/Go SDK | 4 | Task 13 | ✅ |
| 19 | Conformance tiers | 4 | Task 14 | ✅ |
| 20 | Developer experience cliff | 4 | Task 15 | ✅ |
