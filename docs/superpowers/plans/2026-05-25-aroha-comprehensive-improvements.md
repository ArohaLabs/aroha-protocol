<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol — Comprehensive Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 22 security, correctness, operational, scoring, and code-quality issues across `@aroha-sdk/core`, `@aroha-sdk/credentials`, and `@aroha-sdk/preferences`.

**Architecture:** Work package-by-package in dependency order: credentials RBAC and mandate first (security-critical), then core transport/identity changes, then preferences scoring. Each task is independently committable and tested.

**Tech Stack:** TypeScript, `@noble/ed25519`, `@noble/hashes`, `vitest`, Node.js `http`/`ws`

---

## File Map

| File | Change |
|------|--------|
| `packages/aroha-credentials/package.json` | Add `vitest` devDep + `test` script |
| `packages/aroha-credentials/src/rbac.ts` | Add `mandate` action; map `ArohaSpendingMandate` |
| `packages/aroha-credentials/src/rbac.test.ts` | Tests for mandate action |
| `packages/aroha-credentials/src/mandate.ts` | Fix `assertNarrowing` (merchantCategory, time windows, typo) |
| `packages/aroha-credentials/src/mandate.test.ts` | Tests for new narrowing rules |
| `packages/aroha-credentials/src/middleware.ts` | Unknown-issuer → 401; extract `readBody`; fix route ordering |
| `packages/aroha-credentials/src/registry.ts` | `CredentialStore` interface + `MapCredentialStore` |
| `packages/aroha-credentials/src/registry.test.ts` | Tests via `MapCredentialStore` |
| `packages/aroha-core/src/messages/nonce.ts` | `NonceStore` interface + `MapNonceStore` |
| `packages/aroha-core/src/messages/nonce.test.ts` | Tests via `MapNonceStore` |
| `packages/aroha-core/src/transport/server.ts` | `devMode` guard; WS stream token; accept `nonceStore` option |
| `packages/aroha-core/src/transport/client.ts` | Stream token param; WS URL via `URL`; error propagation |
| `packages/aroha-core/src/transport/http-utils.ts` | **New** — shared `readBody` |
| `packages/aroha-core/src/messages/types.ts` | Add `capability`, `withinSLA`, `requiredCompensation` to `ArohaSatisfactionSignalBody` |
| `packages/aroha-core/src/identity/credentials.ts` | Fix trust level 3 description |
| `packages/aroha-core/src/identity/did.ts` | Extract `KeyRotationRecord`; add `keyHistory?` to `DIDDocument`; add `rotateDIDKey()` |
| `packages/aroha-core/src/identity/did.test.ts` | Tests for `rotateDIDKey` |
| `packages/aroha-core/src/identity/web-did.ts` | Call `verifyKeyRotation` in `resolveWebDID`; add `fetchTimeoutMs` |
| `packages/aroha-preferences/src/profile.ts` | `CapabilityPreference` booleans → float weights |
| `packages/aroha-preferences/src/satisfaction.ts` | EMA on dimension weights |
| `packages/aroha-preferences/src/filter.ts` | Time decay; trust-level prior; apply dimension weights |
| `packages/aroha-preferences/src/preferences.test.ts` | Tests for all three scoring changes |

---

## Task 0: Enable Tests in @aroha-sdk/credentials

**Files:**
- Modify: `packages/aroha-credentials/package.json`

`@aroha-sdk/credentials` has test files but no test runner configured.

- [ ] **Step 1: Add vitest to package.json**

Replace the `package.json` `scripts` and `devDependencies` sections:

```json
{
  "name": "@aroha-sdk/credentials",
  "version": "1.0.0",
  "description": "Human credentials, RBAC, and credential registry for the Aroha Protocol",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "clean": "rm -rf dist",
    "test": "vitest run"
  },
  "dependencies": {
    "@aroha-sdk/core": "^1.0.0",
    "@noble/ed25519": "^2.1.0",
    "@noble/hashes": "^1.4.0",
    "uuid": "^10.0.0"
  },
  "devDependencies": {
    "@types/node": "^20.14.0",
    "@types/uuid": "^10.0.0",
    "typescript": "^5.4.0",
    "vitest": "^1.6.0"
  }
}
```

- [ ] **Step 2: Verify existing tests run**

```bash
cd packages/aroha-credentials && npx vitest run
```

Expected: all existing tests pass (rbac, mandate, credentials, registry).

- [ ] **Step 3: Commit**

```bash
git add packages/aroha-credentials/package.json
git commit -m "chore(credentials): add vitest test runner"
```

---

## Task 1: RBAC — Map ArohaSpendingMandate to mandate action

**Files:**
- Modify: `packages/aroha-credentials/src/rbac.ts`
- Modify: `packages/aroha-credentials/src/rbac.test.ts`

`ArohaSpendingMandate` currently falls through `actionForMessageType` to `null`, bypassing all RBAC checks.

- [ ] **Step 1: Write failing tests**

Add to the bottom of `packages/aroha-credentials/src/rbac.test.ts`:

```ts
describe("ArohaSpendingMandate action mapping", () => {
  it("maps ArohaSpendingMandate to mandate", () => {
    expect(actionForMessageType("ArohaSpendingMandate")).toBe("mandate");
  });

  it("ArohaSatisfactionSignal returns null (private signal, no RBAC)", () => {
    expect(actionForMessageType("ArohaSatisfactionSignal")).toBeNull();
  });
});

describe("mandate action permissions", () => {
  it("allows HumanAdmin to issue mandates", () => {
    expect(checkPermission([ArohaRole.HumanAdmin], "mandate").allowed).toBe(true);
  });

  it("allows HumanUser to issue mandates", () => {
    expect(checkPermission([ArohaRole.HumanUser], "mandate").allowed).toBe(true);
  });

  it("allows AgentOrchestrator to issue mandates", () => {
    expect(checkPermission([ArohaRole.AgentOrchestrator], "mandate").allowed).toBe(true);
  });

  it("denies HumanReadonly from issuing mandates", () => {
    expect(checkPermission([ArohaRole.HumanReadonly], "mandate").allowed).toBe(false);
  });

  it("denies AgentObserver from issuing mandates", () => {
    expect(checkPermission([ArohaRole.AgentObserver], "mandate").allowed).toBe(false);
  });

  it("denies AgentProvider from issuing mandates", () => {
    expect(checkPermission([ArohaRole.AgentProvider], "mandate").allowed).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-credentials && npx vitest run --reporter=verbose
```

Expected: "mandate" tests fail with "received null" / "received false".

- [ ] **Step 3: Update rbac.ts**

Replace the full contents of `packages/aroha-credentials/src/rbac.ts`:

```ts
import { type ArohaMessageType } from "@aroha-sdk/core";
import { ArohaRole, type HumanCredential } from "./types.js";

export { ArohaRole } from "./types.js";

// ─── Actions ──────────────────────────────────────────────────────────────────

export type ArohaAction =
  | "query"
  | "reserve"
  | "commit"
  | "cancel"
  | "delegate"
  | "negotiate"
  | "mandate"
  | "admin";

export function actionForMessageType(type: ArohaMessageType): ArohaAction | null {
  switch (type) {
    case "ArohaRequest":
    case "ArohaStream":
      return "query";
    case "ArohaReserve":
      return "reserve";
    case "ArohaCommit":
      return "commit";
    case "ArohaCancel":
      return "cancel";
    case "ArohaDelegate":
      return "delegate";
    case "ArohaNegotiate":
    case "ArohaCounterOffer":
    case "ArohaAccept":
      return "negotiate";
    case "ArohaSpendingMandate":
      return "mandate";
    // Responses, acks, and private signals skip RBAC
    default:
      return null;
  }
}

// ─── Policy ───────────────────────────────────────────────────────────────────

export type RolePermissions = Partial<Record<ArohaRole, ArohaAction[]>>;

export interface RbacPolicy {
  permissions?: RolePermissions;
  resolveAgentRoles: (agentDID: string) => Promise<ArohaRole[]> | ArohaRole[];
  resolveIssuerPublicKey?: (issuerDID: string) => Promise<Uint8Array | null> | Uint8Array | null;
  credentialRegistry?: {
    resolve(credentialId: string): HumanCredential | null | Promise<HumanCredential | null>;
  };
}

export const DEFAULT_RBAC_PERMISSIONS: RolePermissions = {
  [ArohaRole.HumanAdmin]:        ["query", "reserve", "commit", "cancel", "delegate", "negotiate", "mandate", "admin"],
  [ArohaRole.HumanUser]:         ["query", "reserve", "commit", "cancel", "negotiate", "mandate"],
  [ArohaRole.HumanReadonly]:     ["query"],
  [ArohaRole.AgentOrchestrator]: ["query", "reserve", "commit", "cancel", "delegate", "negotiate", "mandate"],
  [ArohaRole.AgentProvider]:     [],
  [ArohaRole.AgentObserver]:     ["query"],
};

// ─── Permission check ─────────────────────────────────────────────────────────

export interface RbacCheckResult {
  allowed: boolean;
  roles: ArohaRole[];
  reason?: string;
}

export function checkPermission(
  roles: ArohaRole[],
  action: ArohaAction,
  permissions: RolePermissions = DEFAULT_RBAC_PERMISSIONS
): RbacCheckResult {
  if (roles.length === 0) {
    return { allowed: false, roles, reason: "No roles assigned" };
  }
  for (const role of roles) {
    const allowed = permissions[role] ?? [];
    if (allowed.includes("admin") || allowed.includes(action)) {
      return { allowed: true, roles };
    }
  }
  return {
    allowed: false,
    roles,
    reason: `Roles [${roles.join(", ")}] do not permit action "${action}"`,
  };
}
```

- [ ] **Step 4: Run tests — confirm pass**

```bash
cd packages/aroha-credentials && npx vitest run --reporter=verbose
```

Expected: all tests pass including the new mandate tests.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-credentials/src/rbac.ts packages/aroha-credentials/src/rbac.test.ts
git commit -m "fix(credentials): map ArohaSpendingMandate to mandate RBAC action"
```

---

## Task 2: Mandate — Complete assertNarrowing + fix typos

**Files:**
- Modify: `packages/aroha-credentials/src/mandate.ts`
- Modify: `packages/aroha-credentials/src/mandate.test.ts`

`assertNarrowing` doesn't check `merchantCategory` or `validUntil`/`validFrom` time windows. Error messages also have a typo ("attentuate").

- [ ] **Step 1: Write failing tests**

Add to the bottom of `packages/aroha-credentials/src/mandate.test.ts`:

```ts
describe("assertNarrowing — merchantCategory", () => {
  it("allows child to keep same merchantCategory", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: "travel" }, k.priv)
    ).resolves.toBeDefined();
  });

  it("rejects child setting merchantCategory to null when parent restricts it", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: null }, k.priv)
    ).rejects.toThrow(/merchantCategory/i);
  });

  it("rejects child setting different merchantCategory", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      merchantCategory: "travel",
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", { spendLimitUsd: 100, merchantCategory: "food" }, k.priv)
    ).rejects.toThrow(/merchantCategory/i);
  });
});

describe("assertNarrowing — validUntil / validFrom", () => {
  const future = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

  it("rejects child validUntil beyond parent validUntil", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validUntil: future(3_600_000), // 1 hour
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validUntil: future(7_200_000), // 2 hours — wider
      }, k.priv)
    ).rejects.toThrow(/validUntil/i);
  });

  it("allows child validUntil within parent window", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validUntil: future(3_600_000),
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validUntil: future(1_800_000), // 30 min — narrower
      }, k.priv)
    ).resolves.toBeDefined();
  });

  it("rejects child validFrom before parent validFrom", async () => {
    const k = await makeKey();
    const parent = await issueIntentMandate("did:aroha:g", "did:aroha:e", {
      spendLimitUsd: 500,
      validFrom: future(3_600_000),
    }, k.priv);
    await expect(
      attenuateToCart(parent, "did:aroha:p", {
        spendLimitUsd: 100,
        validFrom: future(1_800_000), // starts earlier than parent — wider
      }, k.priv)
    ).rejects.toThrow(/validFrom/i);
  });
});
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-credentials && npx vitest run mandate
```

Expected: new tests fail.

- [ ] **Step 3: Update assertNarrowing in mandate.ts**

Replace the `assertNarrowing` function (lines 212–256) with:

```ts
function assertNarrowing(
  parent: SpendingConstraints,
  child: SpendingConstraints,
  parentTier: string,
  childTier: string
): void {
  const prefix = `Cannot attenuate ${parentTier} → ${childTier}`;

  if (child.spendLimitUsd > parent.spendLimitUsd) {
    throw new Error(`${prefix}: child spendLimitUsd (${child.spendLimitUsd}) exceeds parent (${parent.spendLimitUsd})`);
  }

  if (
    parent.sessionLimitUsd !== undefined &&
    child.sessionLimitUsd !== undefined &&
    child.sessionLimitUsd > parent.sessionLimitUsd
  ) {
    throw new Error(`${prefix}: child sessionLimitUsd exceeds parent`);
  }

  if (
    parent.requireHumanApprovalAboveUsd !== undefined &&
    child.requireHumanApprovalAboveUsd !== undefined &&
    child.requireHumanApprovalAboveUsd > parent.requireHumanApprovalAboveUsd
  ) {
    throw new Error(`${prefix}: child approval threshold exceeds parent`);
  }

  if (parent.allowedMerchants !== undefined && parent.allowedMerchants.length > 0) {
    const parentSet = new Set(parent.allowedMerchants);
    if (!child.allowedMerchants || child.allowedMerchants.length === 0) {
      throw new Error(`${prefix}: parent restricts allowedMerchants but child sets none`);
    }
    for (const m of child.allowedMerchants) {
      if (!parentSet.has(m)) {
        throw new Error(`${prefix}: child allowedMerchants contains "${m}" not in parent`);
      }
    }
  }

  if (parent.merchantCategory !== undefined && parent.merchantCategory !== null) {
    if (child.merchantCategory === null || child.merchantCategory === undefined) {
      throw new Error(`${prefix}: child merchantCategory must not widen parent's "${parent.merchantCategory}" restriction`);
    }
    if (child.merchantCategory !== parent.merchantCategory) {
      throw new Error(`${prefix}: child merchantCategory "${child.merchantCategory}" does not match parent "${parent.merchantCategory}"`);
    }
  }

  if (parent.validUntil !== undefined && child.validUntil !== undefined) {
    if (new Date(child.validUntil) > new Date(parent.validUntil)) {
      throw new Error(`${prefix}: child validUntil (${child.validUntil}) extends beyond parent (${parent.validUntil})`);
    }
  }

  if (parent.validFrom !== undefined && child.validFrom !== undefined) {
    if (new Date(child.validFrom) < new Date(parent.validFrom)) {
      throw new Error(`${prefix}: child validFrom (${child.validFrom}) precedes parent (${parent.validFrom})`);
    }
  }
}
```

- [ ] **Step 4: Run tests — confirm pass**

```bash
cd packages/aroha-credentials && npx vitest run mandate
```

Expected: all mandate tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-credentials/src/mandate.ts packages/aroha-credentials/src/mandate.test.ts
git commit -m "fix(credentials): complete assertNarrowing with merchantCategory and time window checks"
```

---

## Task 3: Security — handleRegister unknown-issuer fallthrough + devMode guard

**Files:**
- Modify: `packages/aroha-credentials/src/middleware.ts`
- Modify: `packages/aroha-core/src/transport/server.ts`

Two issues: (1) `handleRegister` stores credentials from unknown issuers when `resolveIssuerPublicKey` returns `null`. (2) `devMode` guard throws only when `NODE_ENV === "production"` — fail-open.

- [ ] **Step 1: Fix handleRegister in middleware.ts**

In `packages/aroha-credentials/src/middleware.ts`, replace the `handleRegister` function:

```ts
async function handleRegister(
  req: IncomingMessage,
  res: ServerResponse,
  registry: CredentialRegistry,
  opts: CredentialRegistryRouteOptions
): Promise<void> {
  const body = await readBody(req).catch(() => null);
  if (!body) { res.writeHead(400); res.end(JSON.stringify({ error: "Invalid body" })); return; }

  let cred: HumanCredential;
  try { cred = JSON.parse(body) as HumanCredential; }
  catch { res.writeHead(400); res.end(JSON.stringify({ error: "Invalid JSON" })); return; }

  if (opts.resolveIssuerPublicKey) {
    const pubKey = await opts.resolveIssuerPublicKey(cred.issuerDID);
    if (!pubKey) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: `Unknown credential issuer: ${cred.issuerDID}` }));
      return;
    }
    const ok = await registry.register(cred, pubKey);
    if (!ok) { res.writeHead(400); res.end(JSON.stringify({ error: "Credential signature invalid" })); return; }
  } else {
    registry.registerTrusted(cred);
  }

  res.writeHead(201, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ credentialId: cred.credentialId, stored: true }));
}
```

- [ ] **Step 2: Fix devMode guard in server.ts**

In `packages/aroha-core/src/transport/server.ts`, replace lines 114–125 (the `devMode` check at the top of `start()`):

```ts
start(): Promise<void> {
  if (this.opts.devMode) {
    if (process.env.NODE_ENV !== "development") {
      throw new Error(
        `[Aroha] devMode can only be enabled when NODE_ENV=development. ` +
        `Current NODE_ENV: "${process.env.NODE_ENV ?? "(unset)"}". ` +
        `Remove devMode: true before deploying.`
      );
    }
    console.warn(
      "[Aroha] WARNING: devMode is ENABLED — ALL cryptographic validation is bypassed. " +
      "Never use devMode in production."
    );
  }
```

- [ ] **Step 3: Run all credentials tests**

```bash
cd packages/aroha-credentials && npx vitest run
```

Expected: all tests pass.

- [ ] **Step 4: Run all core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-credentials/src/middleware.ts packages/aroha-core/src/transport/server.ts
git commit -m "fix(security): unknown issuer returns 401; devMode guard is now fail-closed"
```

---

## Task 4: Mandate — Fix credentialRegistryRoutes route ordering

**Files:**
- Modify: `packages/aroha-credentials/src/middleware.ts`

The GET list route (`startsWith`) is broader than the GET by-ID route (regex). Currently safe but fragile. Make the list route more specific.

- [ ] **Step 1: Fix the list route test predicate**

In `packages/aroha-credentials/src/middleware.ts`, in the `credentialRegistryRoutes` function, replace the last route:

```ts
// Before:
{
  method: "GET",
  test: (url) => url.startsWith("/aroha/credentials"),
  handle: (req, res) => handleList(req, res, registry),
},

// After:
{
  method: "GET",
  test: (url) => url === "/aroha/credentials" || url.startsWith("/aroha/credentials?"),
  handle: (req, res) => handleList(req, res, registry),
},
```

- [ ] **Step 2: Run credentials tests**

```bash
cd packages/aroha-credentials && npx vitest run
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add packages/aroha-credentials/src/middleware.ts
git commit -m "fix(credentials): tighten credential list route URL matching"
```

---

## Task 5: Ops — Pluggable NonceStore

**Files:**
- Modify: `packages/aroha-core/src/messages/nonce.ts`
- Modify: `packages/aroha-core/src/messages/nonce.test.ts`
- Modify: `packages/aroha-core/src/transport/server.ts`

In-memory `NonceRegistry` breaks replay protection in multi-instance deployments.

- [ ] **Step 1: Write failing tests**

Replace `packages/aroha-core/src/messages/nonce.test.ts` with:

```ts
import { describe, it, expect, vi } from "vitest";
import { NonceRegistry, MapNonceStore, type NonceStore } from "./nonce.js";

describe("MapNonceStore (default)", () => {
  it("accepts a fresh nonce", () => {
    const r = new NonceRegistry();
    const exp = new Date(Date.now() + 60_000).toISOString();
    expect(r.check("abc", exp)).toBe(true);
  });

  it("rejects a replayed nonce", () => {
    const r = new NonceRegistry();
    const exp = new Date(Date.now() + 60_000).toISOString();
    r.check("abc", exp);
    expect(r.check("abc", exp)).toBe(false);
  });

  it("evicts expired nonces", async () => {
    const r = new NonceRegistry(100);
    const exp = new Date(Date.now() - 1).toISOString(); // already expired
    r.check("stale", exp);
    await new Promise((res) => setTimeout(res, 150));
    expect(r.size).toBe(0);
  });

  it("accepts a fresh nonce after expired one is evicted", async () => {
    const r = new NonceRegistry(100);
    const expiredAt = new Date(Date.now() - 1).toISOString();
    r.check("stale", expiredAt);
    await new Promise((res) => setTimeout(res, 150));
    const freshExp = new Date(Date.now() + 60_000).toISOString();
    expect(r.check("stale", freshExp)).toBe(true); // evicted, so fresh again
  });
});

describe("custom NonceStore injection", () => {
  it("delegates check to custom store", async () => {
    const calls: string[] = [];
    const store: NonceStore = {
      async setIfAbsent(nonce, _expiryMs) {
        calls.push(nonce);
        return !calls.slice(0, -1).includes(nonce);
      },
      async evictExpired() {},
    };
    const r = new NonceRegistry(60_000, store);
    const exp = new Date(Date.now() + 60_000).toISOString();
    expect(await r.checkAsync("n1", exp)).toBe(true);
    expect(await r.checkAsync("n1", exp)).toBe(false);
    expect(calls).toEqual(["n1", "n1"]);
  });
});
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-core && npx vitest run nonce
```

Expected: `NonceStore`, `MapNonceStore`, `checkAsync` not found.

- [ ] **Step 3: Rewrite nonce.ts**

Replace `packages/aroha-core/src/messages/nonce.ts` with:

```ts
// ─── NonceStore interface ─────────────────────────────────────────────────────

/**
 * Pluggable nonce deduplication backend.
 * Default: MapNonceStore (in-process). Production: inject a Redis adapter.
 */
export interface NonceStore {
  /**
   * Record a nonce and return true if it is fresh (first seen).
   * Returns false if the nonce was already recorded (replay).
   * expiryMs is the absolute expiry timestamp in milliseconds.
   */
  setIfAbsent(nonce: string, expiryMs: number): Promise<boolean>;
  evictExpired(): Promise<void>;
}

// ─── Default in-process store ─────────────────────────────────────────────────

export class MapNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();

  async setIfAbsent(nonce: string, expiryMs: number): Promise<boolean> {
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiryMs);
    return true;
  }

  async evictExpired(): Promise<void> {
    const now = Date.now();
    for (const [nonce, expiryMs] of this.seen) {
      if (expiryMs < now) this.seen.delete(nonce);
    }
  }

  get size(): number { return this.seen.size; }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

export class NonceRegistry {
  private readonly store: NonceStore;
  private readonly cleanupTimer: ReturnType<typeof setInterval>;
  // Synchronous fallback store for backward-compat sync check()
  private readonly syncStore = new MapNonceStore();

  constructor(cleanupIntervalMs = 60_000, store?: NonceStore) {
    this.store = store ?? this.syncStore;
    this.cleanupTimer = setInterval(() => {
      this.store.evictExpired().catch(() => {});
    }, cleanupIntervalMs);
    if (typeof this.cleanupTimer.unref === "function") this.cleanupTimer.unref();
  }

  /**
   * Synchronous check — only works with the default MapNonceStore.
   * Use checkAsync when injecting a custom store.
   */
  check(nonce: string, expiresAt: string): boolean {
    this.syncStore.evictExpired().catch(() => {});
    if (this.syncStore["seen"].has(nonce)) return false;
    const expiryMs = new Date(expiresAt).getTime();
    this.syncStore["seen"].set(nonce, expiryMs);
    return true;
  }

  /**
   * Async check — works with any NonceStore, including custom backends.
   */
  async checkAsync(nonce: string, expiresAt: string): Promise<boolean> {
    const expiryMs = new Date(expiresAt).getTime();
    return this.store.setIfAbsent(nonce, expiryMs);
  }

  get size(): number {
    return this.syncStore.size;
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}
```

- [ ] **Step 4: Add `nonceStore` option to ArohaServerOptions**

In `packages/aroha-core/src/transport/server.ts`, add to the `ArohaServerOptions` interface (after `bypassSignatureFor`):

```ts
/**
 * Custom nonce store for distributed deployments.
 * Defaults to in-process MapNonceStore (not safe for multi-instance).
 * Inject a Redis-backed NonceStore for multi-replica deployments.
 */
nonceStore?: import("../messages/nonce.js").NonceStore;
```

And update the `ArohaServer` class field:

```ts
// Replace:
private readonly nonceRegistry = new NonceRegistry();

// With:
private readonly nonceRegistry: NonceRegistry;

constructor(private readonly opts: ArohaServerOptions) {
  this.nonceRegistry = new NonceRegistry(60_000, opts.nonceStore);
}
```

- [ ] **Step 5: Run core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/messages/nonce.ts packages/aroha-core/src/messages/nonce.test.ts packages/aroha-core/src/transport/server.ts
git commit -m "feat(core): pluggable NonceStore interface for distributed replay protection"
```

---

## Task 6: Ops — Pluggable CredentialStore

**Files:**
- Modify: `packages/aroha-credentials/src/registry.ts`
- Modify: `packages/aroha-credentials/src/registry.test.ts`

`CredentialRegistry` uses an in-process `Map` — same horizontal scale gap as NonceRegistry.

- [ ] **Step 1: Write failing tests**

In `packages/aroha-credentials/src/registry.test.ts`, add at the bottom:

```ts
describe("CredentialStore interface", () => {
  it("MapCredentialStore is exported and usable", async () => {
    const { MapCredentialStore } = await import("./registry.js");
    const store = new MapCredentialStore();
    const cred: HumanCredential = {
      credentialId: "test-id",
      userId: "user-1",
      roles: [ArohaRole.HumanUser],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      issuerDID: "did:aroha:issuer",
      signature: "dummy",
    };
    await store.set(cred.credentialId, cred);
    expect(await store.get(cred.credentialId)).toEqual(cred);
    await store.delete(cred.credentialId);
    expect(await store.get(cred.credentialId)).toBeUndefined();
  });

  it("CredentialRegistry accepts a custom store", async () => {
    const { MapCredentialStore, CredentialRegistry } = await import("./registry.js");
    const store = new MapCredentialStore();
    const reg = new CredentialRegistry(store);
    const cred: HumanCredential = {
      credentialId: "custom-store-id",
      userId: "user-2",
      roles: [ArohaRole.HumanUser],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      issuerDID: "did:aroha:issuer",
      signature: "dummy",
    };
    reg.registerTrusted(cred);
    expect(reg.resolve("custom-store-id")).toEqual(cred);
  });
});
```

Also add the missing imports to the top of `registry.test.ts` if not present:

```ts
import { ArohaRole } from "./types.js";
import type { HumanCredential } from "./types.js";
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-credentials && npx vitest run registry
```

Expected: `MapCredentialStore` not found.

- [ ] **Step 3: Rewrite registry.ts**

Replace `packages/aroha-credentials/src/registry.ts` with:

```ts
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { type HumanCredential } from "./types.js";
import { verifyHumanCredential } from "./credentials.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── CredentialStore interface ────────────────────────────────────────────────

/**
 * Pluggable credential storage backend.
 * Default: MapCredentialStore (in-process). Production: inject Redis/Postgres.
 */
export interface CredentialStore {
  set(id: string, credential: HumanCredential): Promise<void> | void;
  get(id: string): Promise<HumanCredential | undefined> | HumanCredential | undefined;
  delete(id: string): Promise<boolean> | boolean;
  values(): AsyncIterable<HumanCredential> | Iterable<HumanCredential>;
}

// ─── Default in-process store ─────────────────────────────────────────────────

export class MapCredentialStore implements CredentialStore {
  private readonly store = new Map<string, HumanCredential>();

  set(id: string, credential: HumanCredential): void {
    this.store.set(id, credential);
  }

  get(id: string): HumanCredential | undefined {
    return this.store.get(id);
  }

  delete(id: string): boolean {
    return this.store.delete(id);
  }

  values(): Iterable<HumanCredential> {
    return this.store.values();
  }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

export class CredentialRegistry {
  private readonly store: CredentialStore;

  constructor(store: CredentialStore = new MapCredentialStore()) {
    this.store = store;
  }

  async register(credential: HumanCredential, issuerPublicKey: Uint8Array): Promise<boolean> {
    const { serializeCredential } = await import("./credentials.js");
    const token = serializeCredential(credential);
    const result = await verifyHumanCredential(token, issuerPublicKey);
    if (!result.valid) return false;
    await this.store.set(credential.credentialId, credential);
    return true;
  }

  registerTrusted(credential: HumanCredential): void {
    this.store.set(credential.credentialId, credential);
  }

  resolve(credentialId: string): HumanCredential | null {
    const cred = this.store.get(credentialId);
    if (!cred) return null;
    // Handle async store — synchronous resolve can only work with sync stores
    if (cred instanceof Promise) return null;
    if (new Date((cred as HumanCredential).expiresAt) < new Date()) {
      this.store.delete(credentialId);
      return null;
    }
    return cred as HumanCredential;
  }

  revoke(credentialId: string): boolean {
    const result = this.store.delete(credentialId);
    if (result instanceof Promise) return false;
    return result as boolean;
  }

  listForUser(userId: string): HumanCredential[] {
    const now = new Date();
    const results: HumanCredential[] = [];
    const vals = this.store.values();
    for (const cred of vals as Iterable<HumanCredential>) {
      if (cred.userId === userId && new Date(cred.expiresAt) >= now) {
        results.push(cred);
      }
    }
    return results;
  }

  get size(): number {
    // Only works with MapCredentialStore
    const store = this.store as MapCredentialStore;
    return store["store"]?.size ?? 0;
  }

  evictExpired(): number {
    const now = new Date();
    let count = 0;
    const vals = this.store.values();
    for (const cred of vals as Iterable<HumanCredential>) {
      if (new Date(cred.expiresAt) < now) {
        this.store.delete(cred.credentialId);
        count++;
      }
    }
    return count;
  }
}

// ─── HTTP Client ──────────────────────────────────────────────────────────────

export class CredentialRegistryClient {
  constructor(private readonly baseUrl: string) {}

  async register(credential: HumanCredential): Promise<{ ok: boolean; reason?: string }> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential),
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    return { ok: false, reason: String(body.error ?? res.statusText) };
  }

  async resolve(credentialId: string): Promise<HumanCredential | null> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials/${encodeURIComponent(credentialId)}`);
    if (!res.ok) return null;
    return res.json() as Promise<HumanCredential>;
  }

  async revoke(credentialId: string, revokeProof: string): Promise<{ ok: boolean; reason?: string }> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials/${encodeURIComponent(credentialId)}`, {
      method: "DELETE",
      headers: { "X-Revoke-Proof": revokeProof },
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    return { ok: false, reason: String(body.error ?? res.statusText) };
  }

  async listForUser(userId: string): Promise<HumanCredential[]> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials?userId=${encodeURIComponent(userId)}`);
    if (!res.ok) return [];
    return res.json() as Promise<HumanCredential[]>;
  }
}

// ─── Revoke proof helpers ─────────────────────────────────────────────────────

export async function buildRevokeProof(credentialId: string, issuerPrivateKey: Uint8Array): Promise<string> {
  const payload = JSON.stringify({ action: "revoke", credentialId });
  const bytes = new TextEncoder().encode(payload);
  const sig = await ed.signAsync(bytes, issuerPrivateKey);
  return Buffer.from(sig).toString("base64url");
}

export async function verifyRevokeProof(
  credentialId: string,
  proof: string,
  issuerPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const payload = JSON.stringify({ action: "revoke", credentialId });
    const bytes = new TextEncoder().encode(payload);
    const sig = Buffer.from(proof, "base64url");
    return await ed.verifyAsync(sig, bytes, issuerPublicKey);
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run credentials tests**

```bash
cd packages/aroha-credentials && npx vitest run
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-credentials/src/registry.ts packages/aroha-credentials/src/registry.test.ts
git commit -m "feat(credentials): pluggable CredentialStore interface for distributed deployments"
```

---

## Task 7: Data Model — ArohaSatisfactionSignalBody + trust level description

**Files:**
- Modify: `packages/aroha-core/src/messages/types.ts`
- Modify: `packages/aroha-core/src/identity/credentials.ts`

The wire format for satisfaction signals is missing fields the scoring engine uses. Trust level 3 description is wrong.

- [ ] **Step 1: Update ArohaSatisfactionSignalBody in types.ts**

In `packages/aroha-core/src/messages/types.ts`, replace the `ArohaSatisfactionSignalBody` interface:

```ts
export interface ArohaSatisfactionSignalBody {
  sagaId: string;
  agentDID: string;
  /** The capability this signal applies to (e.g. "search-flights"). */
  capability: string;
  outcome: "satisfied" | "neutral" | "dissatisfied";
  dimensions: {
    price: "satisfied" | "neutral" | "dissatisfied";
    quality: "satisfied" | "neutral" | "dissatisfied";
    speed: "satisfied" | "neutral" | "dissatisfied";
  };
  /** Whether the saga completed within the provider's stated SLA. */
  withinSLA: boolean;
  /** Whether a compensation (ArohaCancel) was required to recover. */
  requiredCompensation: boolean;
}
```

- [ ] **Step 2: Fix trust level 3 description in credentials.ts**

In `packages/aroha-core/src/identity/credentials.ts`, replace the `TRUST_LEVEL_DESCRIPTIONS` entry for level 3:

```ts
// Before:
3: "Reputable — reputation score >= 8000",

// After:
3: "Reputable — reputation score >= 0.8",
```

- [ ] **Step 3: Run core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/aroha-core/src/messages/types.ts packages/aroha-core/src/identity/credentials.ts
git commit -m "fix(core): align ArohaSatisfactionSignalBody with scoring engine; fix trust level 3 threshold"
```

---

## Task 8: Scoring — Time decay, trust-level prior, dimension preference EMA

**Files:**
- Modify: `packages/aroha-preferences/src/profile.ts`
- Modify: `packages/aroha-preferences/src/satisfaction.ts`
- Modify: `packages/aroha-preferences/src/filter.ts`
- Modify: `packages/aroha-preferences/src/preferences.test.ts`

Three scoring improvements: stale scores decay toward neutral, new agents start based on trust level, dimension preferences accumulate via EMA instead of being overwritten.

- [ ] **Step 1: Write failing tests**

Add to the bottom of `packages/aroha-preferences/src/preferences.test.ts`:

```ts
// ─── Time-decay scoring ───────────────────────────────────────────────────────

describe("scoreAgents — time decay", () => {
  it("decays a stale high score toward neutral over time", () => {
    const agents = [makeAgent("stale-agent")];
    const twoYearsAgo = new Date(Date.now() - 730 * 86400_000).toISOString();
    const profile: PreferenceProfile = {
      ...createDefaultProfile("owner"),
      dynamic: {
        agentScores: {
          "did:aroha:stale-agent": { score: 0.95, transactions: 50, lastUsed: twoYearsAgo },
        },
        capabilityPreferences: {},
        preferBundled: false,
        trustedBundlers: [],
      },
    };
    const scores = scoreAgents(agents, profile, "search-flights");
    // After 2 years, score should have decayed significantly toward 0.5
    expect(scores["did:aroha:stale-agent"]).toBeLessThan(0.75);
  });

  it("does not decay a recently-used high score much", () => {
    const agents = [makeAgent("recent-agent")];
    const yesterday = new Date(Date.now() - 86400_000).toISOString();
    const profile: PreferenceProfile = {
      ...createDefaultProfile("owner"),
      dynamic: {
        agentScores: {
          "did:aroha:recent-agent": { score: 0.9, transactions: 10, lastUsed: yesterday },
        },
        capabilityPreferences: {},
        preferBundled: false,
        trustedBundlers: [],
      },
    };
    const scores = scoreAgents(agents, profile, "search-flights");
    expect(scores["did:aroha:recent-agent"]).toBeGreaterThan(0.88);
  });
});

// ─── Trust-level cold-start priors ───────────────────────────────────────────

describe("scoreAgents — trust-level prior", () => {
  it("gives a higher starting score to a trust-level-2 agent vs trust-level-0", () => {
    const highTrust = makeAgent("high-trust", { requiredTrustLevel: 2 });
    const lowTrust  = makeAgent("low-trust",  { requiredTrustLevel: 0 });
    const profile = createDefaultProfile("owner");
    const scores = scoreAgents([highTrust, lowTrust], profile, "search-flights");
    expect(scores["did:aroha:high-trust"]).toBeGreaterThan(scores["did:aroha:low-trust"]);
  });

  it("trust-level-4 agent starts above 0.8", () => {
    const trusted = makeAgent("user-trusted", { requiredTrustLevel: 4 });
    const profile = createDefaultProfile("owner");
    const scores = scoreAgents([trusted], profile, "search-flights");
    expect(scores["did:aroha:user-trusted"]).toBeGreaterThan(0.8);
  });
});

// ─── Dimension preference EMA ─────────────────────────────────────────────────

describe("applySatisfactionSignal — dimension weight EMA", () => {
  it("increases priceWeight when price is dissatisfied", () => {
    const profile = createDefaultProfile("owner");
    const signal: SatisfactionSignal = {
      sagaId: "s1",
      agentDID: "did:aroha:p",
      capability: "book-flight",
      outcome: "neutral",
      dimensions: { price: "dissatisfied", quality: "satisfied", speed: "satisfied" },
      withinSLA: true,
      requiredCompensation: false,
    };
    const updated = applySatisfactionSignal(profile, signal);
    const pref = updated.dynamic.capabilityPreferences["book-flight"];
    expect(pref.priceWeight).toBeGreaterThan(0);
    expect(pref.qualityWeight).toBe(0);
    expect(pref.speedWeight).toBe(0);
  });

  it("accumulates priceWeight over multiple signals (does not overwrite)", () => {
    let profile = createDefaultProfile("owner");
    const signal: SatisfactionSignal = {
      sagaId: "s1",
      agentDID: "did:aroha:p",
      capability: "book-flight",
      outcome: "neutral",
      dimensions: { price: "dissatisfied", quality: "satisfied", speed: "satisfied" },
      withinSLA: true,
      requiredCompensation: false,
    };
    profile = applySatisfactionSignal(profile, signal);
    const afterOne = profile.dynamic.capabilityPreferences["book-flight"].priceWeight;
    profile = applySatisfactionSignal(profile, signal);
    const afterTwo = profile.dynamic.capabilityPreferences["book-flight"].priceWeight;
    expect(afterTwo).toBeGreaterThan(afterOne); // accumulated, not overwritten
  });

  it("starts at zero weights for a new capability", () => {
    const profile = createDefaultProfile("owner");
    const pref = profile.dynamic.capabilityPreferences["new-capability"];
    expect(pref).toBeUndefined(); // no entry yet
  });
});
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-preferences && npm test
```

Expected: new tests fail — `priceWeight` not found, scoring ignores trust level.

- [ ] **Step 3: Update CapabilityPreference in profile.ts**

In `packages/aroha-preferences/src/profile.ts`, replace the `CapabilityPreference` interface:

```ts
export interface CapabilityPreference {
  /** 0–1 EMA weight. Higher = user more strongly needs better price. */
  priceWeight:   number;
  /** 0–1 EMA weight. Higher = user more strongly needs better quality. */
  qualityWeight: number;
  /** 0–1 EMA weight. Higher = user more strongly needs better speed. */
  speedWeight:   number;
}
```

Update `createDefaultProfile` — `capabilityPreferences` stays `{}`, so no per-preference default is needed. The `CapabilityPreference` default object used as fallback in `satisfaction.ts` will need updating in step 5.

- [ ] **Step 4: Update updateCapabilityPreference in satisfaction.ts**

In `packages/aroha-preferences/src/satisfaction.ts`, replace the `updateCapabilityPreference` function and the `CapabilityPreference` fallback:

```ts
// EMA constants for dimension preferences (slower to change than agent scores)
const PREF_DECAY = 0.9;
const PREF_NEW   = 0.1;

function updateCapabilityPreference(
  current: CapabilityPreference,
  signal: SatisfactionSignal
): CapabilityPreference {
  // A dissatisfied dimension signals the user wants improvement there — weight increases.
  const priceSignal   = signal.dimensions.price   === "dissatisfied" ? 1 : 0;
  const qualitySignal = signal.dimensions.quality === "dissatisfied" ? 1 : 0;
  const speedSignal   = signal.dimensions.speed   === "dissatisfied" ? 1 : 0;

  return {
    priceWeight:   Math.min(1, current.priceWeight   * PREF_DECAY + priceSignal   * PREF_NEW),
    qualityWeight: Math.min(1, current.qualityWeight * PREF_DECAY + qualitySignal * PREF_NEW),
    speedWeight:   Math.min(1, current.speedWeight   * PREF_DECAY + speedSignal   * PREF_NEW),
  };
}
```

Also update the fallback inside `applySatisfactionSignal` where `capPref` is initialized:

```ts
// Replace:
const capPref: CapabilityPreference = profile.dynamic.capabilityPreferences[
  signal.capability
] ?? { preferPrice: false, preferQuality: false, preferSpeed: false };

// With:
const capPref: CapabilityPreference = profile.dynamic.capabilityPreferences[
  signal.capability
] ?? { priceWeight: 0, qualityWeight: 0, speedWeight: 0 };
```

- [ ] **Step 5: Update scoreAgents in filter.ts**

Replace `packages/aroha-preferences/src/filter.ts` with:

```ts
import { type PreferenceProfile } from "./profile.js";
import { type DiscoveredAgent } from "@aroha-sdk/registry";

// ─── Hard Filter ──────────────────────────────────────────────────────────────

export function filterAgents(
  agents: DiscoveredAgent[],
  profile: PreferenceProfile,
  capabilityId: string,
  options: FilterOptions = {}
): DiscoveredAgent[] {
  const { userTrustLevel = 1, domain } = options;
  const blocked = new Set(profile.static.brands.blocked);
  const budget = domain ? profile.static.budget[domain] : undefined;

  return agents.filter((agent) => {
    if (blocked.has(agent.manifest.did)) return false;

    const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
    if (cap && cap.requiredTrustLevel > userTrustLevel) return false;

    if (budget && cap?.pricing.model === "per-transaction" && cap.pricing.fee) {
      const fee = parseFloat(cap.pricing.fee);
      if (!isNaN(fee) && fee > budget.max) return false;
    }

    return true;
  });
}

export interface FilterOptions {
  userTrustLevel?: 0 | 1 | 2 | 3 | 4;
  domain?: string;
}

// ─── Scoring constants ────────────────────────────────────────────────────────

/** Exponential decay half-life in days. Score drifts toward 0.5 when unused. */
const DECAY_HALF_LIFE_DAYS = 180;

/** Starting score for agents with no history, keyed by required trust level. */
const TRUST_LEVEL_PRIORS: Record<0 | 1 | 2 | 3 | 4, number> = {
  0: 0.30,
  1: 0.45,
  2: 0.55,
  3: 0.70,
  4: 0.85,
};

// ─── Soft Scorer ─────────────────────────────────────────────────────────────

export function scoreAgents(
  agents: DiscoveredAgent[],
  profile: PreferenceProfile,
  capabilityId: string
): Record<string, number> {
  const scores: Record<string, number> = {};
  const preferred = new Set(profile.static.brands.preferred);
  const capPref = profile.dynamic.capabilityPreferences[capabilityId];

  for (const agent of agents) {
    const did = agent.manifest.did;
    const dynamic = profile.dynamic.agentScores[did];

    // Base score: time-decayed EMA or trust-level prior for unknown agents
    let score: number;
    if (dynamic) {
      score = decayScore(dynamic.score, dynamic.lastUsed);
    } else {
      const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
      const trustLevel = ((cap?.requiredTrustLevel ?? 1) as 0 | 1 | 2 | 3 | 4);
      score = TRUST_LEVEL_PRIORS[trustLevel];
    }

    // Preferred brand boost
    if (preferred.has(did)) score = Math.min(1, score + 0.15);

    // Trusted bundler boost
    if (profile.dynamic.preferBundled && profile.dynamic.trustedBundlers.includes(did)) {
      score = Math.min(1, score + 0.12);
    }

    // Dimension preference boost — small signal toward agents matching what the user needs
    if (capPref) {
      const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
      if (cap) {
        // Price preference: boost free/low-fee agents
        if (capPref.priceWeight > 0.3 && cap.pricing.model === "free") {
          score = Math.min(1, score + capPref.priceWeight * 0.08);
        }
        // Speed preference: boost agents with low stated maxResponseMs
        if (capPref.speedWeight > 0.3 && cap.maxResponseMs < 1000) {
          score = Math.min(1, score + capPref.speedWeight * 0.08);
        }
      }
    }

    scores[did] = score;
  }

  return scores;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function decayScore(score: number, lastUsed: string): number {
  const daysSince = (Date.now() - new Date(lastUsed).getTime()) / 86_400_000;
  // Exponential decay toward neutral 0.5; half-life = DECAY_HALF_LIFE_DAYS
  const factor = Math.exp((-daysSince * Math.LN2) / DECAY_HALF_LIFE_DAYS);
  return 0.5 + (score - 0.5) * factor;
}
```

- [ ] **Step 6: Run preferences tests**

```bash
cd packages/aroha-preferences && npm test
```

Expected: all tests pass, including the three new scoring suites.

- [ ] **Step 7: Commit**

```bash
git add packages/aroha-preferences/src/profile.ts packages/aroha-preferences/src/satisfaction.ts packages/aroha-preferences/src/filter.ts packages/aroha-preferences/src/preferences.test.ts
git commit -m "feat(preferences): time decay, trust-level priors, and EMA dimension weights"
```

---

## Task 9: Transport — WebSocket stream token + error propagation + URL fix

**Files:**
- Modify: `packages/aroha-core/src/transport/server.ts`
- Modify: `packages/aroha-core/src/transport/client.ts`

Three issues: WS streams have no auth (anyone knowing correlationId can subscribe), WS errors are silently swallowed, WS URL is built by string concat.

**Design:** Server issues a one-time random `streamToken` in the 202 response body. Client passes it in `?tok=` on WS connect. Server validates and consumes the token (30s TTL). Token is optional — servers/clients not using it continue to work.

- [ ] **Step 1: Update server.ts — stream token issuance and validation**

In `packages/aroha-core/src/transport/server.ts`:

Add these imports at the top:
```ts
import { randomBytes } from "@noble/hashes/utils";
```

Add a private field to `ArohaServer`:
```ts
private readonly streamTokens = new Map<string, { cid: string; expiresMs: number }>();
```

Replace `handleInbound` — the section that returns 202 — with token issuance. Find the two places where `res.writeHead(202)` is called (one in devMode, one in normal mode) and replace:

```ts
// devMode path (around line 208):
// Replace:
res.writeHead(202);
res.end();

// With:
const devStreamToken = Buffer.from(randomBytes(16)).toString("base64url");
this.streamTokens.set(devStreamToken, { cid: envelope.correlationId, expiresMs: Date.now() + 30_000 });
res.writeHead(202, { "Content-Type": "application/json" });
res.end(JSON.stringify({ streamToken: devStreamToken }));
```

```ts
// Normal path (around line 262):
// Replace:
res.writeHead(202);
res.end();

// With:
const streamToken = Buffer.from(randomBytes(16)).toString("base64url");
this.streamTokens.set(streamToken, { cid: envelope.correlationId, expiresMs: Date.now() + 30_000 });
res.writeHead(202, { "Content-Type": "application/json" });
res.end(JSON.stringify({ streamToken }));
```

Replace `handleWsConnection` with:

```ts
private handleWsConnection(ws: WebSocket, req: IncomingMessage): void {
  const url = new URL(req.url ?? "/", "http://localhost");
  const cid = url.searchParams.get("cid");
  if (!cid) { ws.close(1008, "Missing cid parameter"); return; }

  const tok = url.searchParams.get("tok");
  if (tok) {
    const entry = this.streamTokens.get(tok);
    if (!entry || entry.cid !== cid || entry.expiresMs < Date.now()) {
      ws.close(1008, "Invalid or expired stream token");
      return;
    }
    this.streamTokens.delete(tok); // one-time use
  }

  this.wsClients.set(cid, ws);
  ws.on("close", () => this.wsClients.delete(cid));
}
```

- [ ] **Step 2: Update client.ts — stream token, URL construction, error propagation**

Replace `packages/aroha-core/src/transport/client.ts` with:

```ts
import { WebSocket } from "ws";
import { type ArohaEnvelope } from "../messages/envelope.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SendOptions {
  timeoutMs?: number;
}

export type SendResult =
  | { envelope: ArohaEnvelope; streamToken?: undefined }
  | { envelope: null; streamToken?: string };

// ─── Client ───────────────────────────────────────────────────────────────────

export class ArohaClient {
  /**
   * Send a Aroha message and await a synchronous response.
   * On 202 (async), returns { envelope: null, streamToken } where streamToken
   * (if present) should be passed to stream() for authenticated WS access.
   */
  async send(
    endpoint: string,
    envelope: ArohaEnvelope,
    opts: SendOptions = {}
  ): Promise<SendResult> {
    const { timeoutMs = 30_000 } = opts;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 202) {
      try {
        const body = await response.json() as { streamToken?: string };
        return { envelope: null, streamToken: body.streamToken };
      } catch {
        return { envelope: null };
      }
    }

    if (!response.ok) {
      const error = await response.text();
      throw new ArohaTransportError(response.status, error);
    }

    return { envelope: await response.json() as ArohaEnvelope };
  }

  /**
   * Open a WebSocket stream to receive ArohaStream events for a given saga.
   *
   * @param wsEndpoint    WebSocket URL (wss://<host>/aroha/stream)
   * @param correlationId The saga correlationId to subscribe to
   * @param streamToken   One-time token from the 202 response (recommended)
   */
  stream(
    wsEndpoint: string,
    correlationId: string,
    streamToken?: string
  ): AsyncIterable<ArohaEnvelope> {
    const u = new URL(wsEndpoint);
    u.searchParams.set("cid", correlationId);
    if (streamToken) u.searchParams.set("tok", streamToken);
    const ws = new WebSocket(u.toString());

    return {
      [Symbol.asyncIterator]() {
        const queue: ArohaEnvelope[] = [];
        let resolve: ((value: IteratorResult<ArohaEnvelope>) => void) | null = null;
        let done = false;
        let error: Error | null = null;

        ws.on("message", (data) => {
          const envelope = JSON.parse(data.toString()) as ArohaEnvelope;
          if (resolve) {
            const r = resolve;
            resolve = null;
            r({ value: envelope, done: false });
          } else {
            queue.push(envelope);
          }
        });

        ws.on("close", () => {
          done = true;
          if (resolve) {
            const r = resolve;
            resolve = null;
            r({ value: undefined as unknown as ArohaEnvelope, done: true });
          }
        });

        ws.on("error", (err) => {
          error = err;
          if (resolve) {
            const r = resolve;
            resolve = null;
            // Signal error through next() by setting error and resolving
            r({ value: undefined as unknown as ArohaEnvelope, done: true });
          }
        });

        return {
          next(): Promise<IteratorResult<ArohaEnvelope>> {
            if (error) return Promise.reject(error);
            if (queue.length > 0) {
              return Promise.resolve({ value: queue.shift()!, done: false });
            }
            if (done) {
              return Promise.resolve({ value: undefined as unknown as ArohaEnvelope, done: true });
            }
            return new Promise((r) => { resolve = r; });
          },
          return(): Promise<IteratorResult<ArohaEnvelope>> {
            ws.close();
            return Promise.resolve({ value: undefined as unknown as ArohaEnvelope, done: true });
          },
        };
      },
    };
  }

  async fetchDIDDocument(agentBaseUrl: string): Promise<Record<string, unknown>> {
    const response = await fetch(`${agentBaseUrl}/.well-known/aroha-agent.json`);
    if (!response.ok) throw new Error(`Failed to fetch DID Document from ${agentBaseUrl}`);
    return response.json() as Promise<Record<string, unknown>>;
  }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

export class ArohaTransportError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: string
  ) {
    super(`Aroha transport error ${statusCode}: ${body}`);
    this.name = "ArohaTransportError";
  }
}
```

- [ ] **Step 3: Run core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/aroha-core/src/transport/server.ts packages/aroha-core/src/transport/client.ts
git commit -m "feat(transport): WebSocket stream token auth, error propagation fix, URL construction fix"
```

---

## Task 10: web-did.ts — Rotation verification + fetch timeout

**Files:**
- Modify: `packages/aroha-core/src/identity/web-did.ts`

`resolveWebDID` checks rotation cool-down but never verifies the predecessor signature. Fetch has no timeout.

- [ ] **Step 1: Write failing test**

In `packages/aroha-core/src/identity/did.test.ts` (or create it if it doesn't exist), add:

```ts
import { describe, it, expect } from "vitest";
import { resolveWebDID, generateWebAgent, rotateKey, verifyKeyRotation, type WebAgentKeyPair } from "./web-did.js";

describe("resolveWebDID — rotation chain verification", () => {
  it("verifyKeyRotation returns true for a valid rotation", async () => {
    const agent = await generateWebAgent("example.com", "test-agent");
    const rotated = await rotateKey(agent);
    const record = rotated.webDocument.arohaWeb.keyHistory[0];
    expect(await verifyKeyRotation(record)).toBe(true);
  });

  it("verifyKeyRotation returns false for a tampered rotation record", async () => {
    const agent = await generateWebAgent("example.com", "test-agent");
    const rotated = await rotateKey(agent);
    const record = { ...rotated.webDocument.arohaWeb.keyHistory[0] };
    // Tamper with the signature
    record.predecessorSignature = "invalidsignature";
    expect(await verifyKeyRotation(record)).toBe(false);
  });
});
```

- [ ] **Step 2: Run test — confirm pass for verifyKeyRotation (it already exists), and that it tests the right thing**

```bash
cd packages/aroha-core && npx vitest run did
```

Expected: tests pass (verifyKeyRotation is already implemented; this just adds coverage for the tamper case).

- [ ] **Step 3: Update resolveWebDID to verify rotation chain and add fetchTimeoutMs**

In `packages/aroha-core/src/identity/web-did.ts`, replace the `resolveWebDID` function signature and the HTTPS fetch block:

```ts
export async function resolveWebDID(
  did: string,
  verifyDNS = true,
  dnsResolver?: (domain: string) => Promise<string[]>,
  fetchTimeoutMs = 10_000
): Promise<WebDIDResolutionResult> {
  const url = wellKnownUrl(did);

  // ── Step 1: Fetch DID Document over HTTPS (with timeout) ─────────────────
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), fetchTimeoutMs);
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    throw new Error(`Failed to resolve ${did}: HTTP ${res.status} from ${url}`);
  }
  const doc = await res.json() as WebDIDDocument;

  if (doc.id !== did) {
    throw new Error(`DID mismatch: document claims ${doc.id}, expected ${did}`);
  }

  const activeKey = fromMultibase(doc.verificationMethod[0].publicKeyMultibase);

  // ── Step 2: Verify all rotation records in keyHistory ────────────────────
  if (doc.arohaWeb?.keyHistory?.length > 0) {
    for (const rotation of doc.arohaWeb.keyHistory) {
      const rotationValid = await verifyKeyRotation(rotation);
      if (!rotationValid) {
        throw new Error(
          `DID ${did}: key rotation record (rotatedAt ${rotation.rotatedAt}) has invalid predecessor signature`
        );
      }
    }
  }

  // ── Step 3: Check key rotation cool-down ─────────────────────────────────
  let keyTrusted = true;
  let trustReason: string | undefined;
  if (doc.arohaWeb?.keyHistory?.length > 0) {
    const latestRotation = doc.arohaWeb.keyHistory[0];
    const trustAfter = new Date(latestRotation.trustAfter);
    if (new Date() < trustAfter) {
      keyTrusted = false;
      trustReason = `Key rotation cool-down active until ${latestRotation.trustAfter}`;
    }
  }

  // ── Step 4: DNS TXT key-commitment verification ───────────────────────────
  let dnsVerified = false;
  if (verifyDNS) {
    const { domain, path } = parseWebDID(did);
    let txtRecords: string[] = [];
    if (dnsResolver) {
      txtRecords = await dnsResolver(domain).catch(() => []);
    } else if (typeof Deno !== "undefined") {
      try {
        const records = await (Deno as unknown as { resolveDns(n: string, t: string): Promise<string[][]> })
          .resolveDns(`_aroha.${domain}`, "TXT");
        txtRecords = records.flat();
      } catch { /* DNS unavailable — fall back to HTTPS-only */ }
    }

    for (const txt of txtRecords) {
      const parsed = parseDNSTXT(txt);
      if (!parsed) continue;
      if (parsed.path !== path) continue;
      const expectedHash = keyCommitmentHash(activeKey);
      if (parsed.keyhash === expectedHash) {
        dnsVerified = true;
        break;
      }
    }
  }

  return { document: doc, dnsVerified, keyTrusted, trustReason };
}
```

- [ ] **Step 4: Run core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/aroha-core/src/identity/web-did.ts packages/aroha-core/src/identity/did.test.ts
git commit -m "fix(identity): verify rotation chain signatures in resolveWebDID; add fetch timeout"
```

---

## Task 11: Identity — did:aroha: key rotation support

**Files:**
- Modify: `packages/aroha-core/src/identity/did.ts`
- Modify: `packages/aroha-core/src/identity/web-did.ts`

`did:aroha:` has no key rotation. `KeyRotationRecord` is defined only in `web-did.ts`; move it to `did.ts` so base identities can use it.

- [ ] **Step 1: Write failing tests**

In `packages/aroha-core/src/identity/did.test.ts`, add:

```ts
import { generateDID, rotateDIDKey, extractPublicKey } from "./did.js";

describe("rotateDIDKey", () => {
  it("returns a new keypair with a different public key", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    expect(Buffer.from(rotated.publicKey).toString("hex"))
      .not.toBe(Buffer.from(original.publicKey).toString("hex"));
  });

  it("adds a keyHistory entry signed by the predecessor", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    expect(rotated.document.keyHistory).toHaveLength(1);
    const record = rotated.document.keyHistory![0];
    expect(record.rotatedAt).toBeTruthy();
    expect(record.predecessorSignature).toBeTruthy();
  });

  it("rotation record has valid predecessor signature", async () => {
    const { verifyKeyRotation } = await import("./web-did.js");
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    const record = rotated.document.keyHistory![0];
    expect(await verifyKeyRotation(record)).toBe(true);
  });

  it("extractPublicKey returns the new key after rotation (past cool-down)", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    // Rotate with 0-hour cool-down for test purposes
    const rotated = await rotateDIDKey(original, 0);
    const extracted = extractPublicKey(rotated.document);
    expect(Buffer.from(extracted).toString("hex"))
      .toBe(Buffer.from(rotated.publicKey).toString("hex"));
  });

  it("extractPublicKey throws during cool-down window", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original, 24); // 24-hour cool-down
    expect(() => extractPublicKey(rotated.document)).toThrow(/cool-down/i);
  });
});
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
cd packages/aroha-core && npx vitest run did
```

Expected: `rotateDIDKey` not found.

- [ ] **Step 3: Update did.ts — add KeyRotationRecord, rotateDIDKey, update extractPublicKey**

In `packages/aroha-core/src/identity/did.ts`, add the following after the imports:

```ts
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
```

Add the `KeyRotationRecord` interface and update `DIDDocument`:

```ts
export interface KeyRotationRecord {
  rotatedAt: string;
  trustAfter: string;
  predecessorKey: string;
  newKeyHash: string;
  predecessorSignature: string;
}

export interface DIDDocument {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  keyAgreement: string[];
  service: ServiceEndpoint[];
  created: string;
  updated: string;
  /** Rotation history (newest-first). Present only after at least one rotation. */
  keyHistory?: KeyRotationRecord[];
}
```

Update `extractPublicKey` to enforce cool-down:

```ts
export function extractPublicKey(doc: DIDDocument): Uint8Array {
  const vm = doc.verificationMethod[0];
  if (!vm) throw new Error(`DID ${doc.id} has no verification methods`);

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
```

Add `rotateDIDKey` at the bottom of `did.ts`:

```ts
import { bytesToHex } from "@noble/hashes/utils";

function keyCommitmentHash(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}

/**
 * Rotate to a new keypair for a did:aroha: identity.
 * The predecessor key signs the rotation record.
 * The new key is not trusted until coolDownHours have elapsed.
 */
export async function rotateDIDKey(
  current: AgentKeyPair,
  coolDownHours = 24
): Promise<AgentKeyPair> {
  const newPrivateKey = ed.utils.randomPrivateKey();
  const newPublicKey = await ed.getPublicKeyAsync(newPrivateKey);

  const oldPubMultibase = toMultibase(current.publicKey);
  const now = new Date();
  const trustAfter = new Date(now.getTime() + coolDownHours * 3_600_000);

  const payload = new TextEncoder().encode(
    oldPubMultibase + toMultibase(newPublicKey) + now.toISOString()
  );
  const sig = await ed.signAsync(payload, current.privateKey);

  const rotation: KeyRotationRecord = {
    rotatedAt: now.toISOString(),
    trustAfter: trustAfter.toISOString(),
    predecessorKey: oldPubMultibase,
    newKeyHash: keyCommitmentHash(newPublicKey),
    predecessorSignature: Buffer.from(sig).toString("base64url"),
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
    updated: now.toISOString(),
    keyHistory: [rotation, ...(current.document.keyHistory ?? [])],
  };

  return { did: current.did, privateKey: newPrivateKey, publicKey: newPublicKey, document: newDoc };
}
```

- [ ] **Step 4: Update web-did.ts to import KeyRotationRecord from did.ts**

In `packages/aroha-core/src/identity/web-did.ts`, remove the `KeyRotationRecord` interface definition and replace it with an import:

```ts
// Remove the local KeyRotationRecord interface declaration.
// Add to the imports from "./did.js":
import {
  type DIDDocument,
  type AgentKeyPair,
  type VerificationMethod,
  type KeyRotationRecord,   // ← added
  toMultibase,
  fromMultibase,
} from "./did.js";
```

- [ ] **Step 5: Run core tests**

```bash
cd packages/aroha-core && npm test
```

Expected: all tests pass including the new rotation tests.

- [ ] **Step 6: Commit**

```bash
git add packages/aroha-core/src/identity/did.ts packages/aroha-core/src/identity/web-did.ts packages/aroha-core/src/identity/did.test.ts
git commit -m "feat(identity): add key rotation support to did:aroha: identities"
```

---

## Task 12: Code Quality — Deduplicate readBody + mandate typo

**Files:**
- Create: `packages/aroha-core/src/transport/http-utils.ts`
- Modify: `packages/aroha-core/src/transport/server.ts`
- Modify: `packages/aroha-credentials/src/middleware.ts`
- Modify: `packages/aroha-credentials/src/mandate.ts`

`readBody` is defined verbatim in both `server.ts` and `middleware.ts`. Three error messages in `mandate.ts` say "attentuate".

- [ ] **Step 1: Create shared http-utils.ts**

Create `packages/aroha-core/src/transport/http-utils.ts`:

```ts
import { type IncomingMessage } from "http";

export function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
```

- [ ] **Step 2: Update server.ts to use shared readBody**

In `packages/aroha-core/src/transport/server.ts`:

Add import at the top:
```ts
import { readBody } from "./http-utils.js";
```

Remove the local `readBody` function at the bottom of the file (the one starting at line ~282).

- [ ] **Step 3: Update middleware.ts to use shared readBody**

In `packages/aroha-credentials/src/middleware.ts`:

Replace the import of `ArohaEnvelope, ArohaMiddleware, ArohaHttpRoute` with:
```ts
import { type ArohaEnvelope, type ArohaMiddleware, type ArohaHttpRoute, readBody } from "@aroha-sdk/core";
```

Remove the local `readBody` function at the bottom of `middleware.ts`.

- [ ] **Step 4: Export readBody from @aroha-sdk/core**

In `packages/aroha-core/src/index.ts` (or `packages/aroha-core/src/transport/index.ts`), add:

Check what's exported from transport:

```ts
// In packages/aroha-core/src/transport/index.ts, add:
export * from "./http-utils.js";
```

- [ ] **Step 5: Fix "attentuate" typo in mandate.ts**

In `packages/aroha-credentials/src/mandate.ts`, do a global find-replace of `"attentuate"` → `"attenuate"`. There are 3 occurrences in error messages inside `assertNarrowing`.

(Note: Task 2 already replaced `assertNarrowing` with correct spelling in the new version — verify no remaining occurrences from the old text remain.)

```bash
grep -n "attentuate" packages/aroha-credentials/src/mandate.ts
```

If any remain, fix them manually.

- [ ] **Step 6: Run all tests**

```bash
cd packages/aroha-core && npm test
cd packages/aroha-credentials && npx vitest run
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add packages/aroha-core/src/transport/http-utils.ts packages/aroha-core/src/transport/server.ts packages/aroha-core/src/transport/index.ts packages/aroha-credentials/src/middleware.ts packages/aroha-credentials/src/mandate.ts
git commit -m "refactor: extract shared readBody; fix attentuate typo in mandate errors"
```

---

## Final Verification

- [ ] **Run full test suite from root**

```bash
npm test
```

Expected: all packages with test scripts pass (`@aroha-sdk/core`, `@aroha-sdk/preferences`, `@aroha-sdk/credentials`).

- [ ] **Check TypeScript compiles**

```bash
npm run build
```

Expected: no TypeScript errors across all packages.

- [ ] **Final commit if anything unstaged**

```bash
git status
```

If clean: done. If anything unstaged, investigate before committing.
