<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol — Comprehensive Improvements Design

**Date:** 2026-05-25  
**Scope:** 22 improvements across auth, scoring, transport, mandate, and code quality  
**Packages touched:** `aroha-core`, `aroha-credentials`, `aroha-preferences`

---

## 1. Security & Correctness Fixes

### 1.1 RBAC Bypass for SpendingMandate and SatisfactionSignal

**File:** `packages/aroha-credentials/src/rbac.ts`

`actionForMessageType` returns `null` for `ArohaSpendingMandate` and `ArohaSatisfactionSignal`, causing the RBAC middleware to skip permission checks entirely for these types.

**Fix:** Add a `"mandate"` action. Map `ArohaSpendingMandate` → `"mandate"`. Map `ArohaSatisfactionSignal` → `null` (intentional skip — satisfaction signals are private and originate from the personal agent itself, not from external callers, so RBAC doesn't apply). Update `DEFAULT_RBAC_PERMISSIONS` to grant `"mandate"` to `HumanAdmin`, `HumanUser`, and `AgentOrchestrator`.

```ts
// New action added to ArohaAction union
export type ArohaAction = "query" | "reserve" | "commit" | "cancel" | "delegate" | "negotiate" | "admin" | "mandate";

// actionForMessageType additions
case "ArohaSpendingMandate": return "mandate";
// ArohaSatisfactionSignal stays null — private, not externally callable

// DEFAULT_RBAC_PERMISSIONS additions
[ArohaRole.HumanAdmin]:        [..., "mandate"],
[ArohaRole.HumanUser]:         [..., "mandate"],
[ArohaRole.AgentOrchestrator]: [..., "mandate"],
```

### 1.2 handleRegister Unknown-Issuer Fallthrough

**File:** `packages/aroha-credentials/src/middleware.ts`, `handleRegister` function

When `resolveIssuerPublicKey` is configured but returns `null` (unrecognized issuer), the code falls through to `registry.registerTrusted(cred)`. This stores credentials from unknown issuers without any verification.

**Fix:** Return 401 when the issuer is unknown:
```ts
if (pubKey) {
  // verify and register
} else {
  res.writeHead(401);
  res.end(JSON.stringify({ error: `Unknown credential issuer: ${cred.issuerDID}` }));
  return;
}
```

### 1.3 resolveWebDID Missing Rotation Signature Verification

**File:** `packages/aroha-core/src/identity/web-did.ts`, `resolveWebDID`

The function checks the cool-down window of the latest rotation but never calls `verifyKeyRotation()`. A malicious DID Document could contain a fabricated rotation record with an invalid predecessor signature, and it would pass validation once the cool-down window passes.

**Fix:** After fetching the document, verify all rotation records in `keyHistory`:
```ts
for (const rotation of doc.arohaWeb.keyHistory) {
  const rotationValid = await verifyKeyRotation(rotation);
  if (!rotationValid) {
    throw new Error(`DID ${did}: rotation record has invalid predecessor signature`);
  }
}
```

### 1.4 assertNarrowing Incomplete Constraint Checks

**File:** `packages/aroha-credentials/src/mandate.ts`, `assertNarrowing`

Two constraint fields are not validated:
- `merchantCategory`: parent can restrict to `"travel"` but child can widen to `null` (any)
- `validUntil`/`validFrom`: child can extend beyond parent's time window

**Fix:** Add checks for both:
```ts
// merchantCategory narrowing
if (parent.merchantCategory !== undefined && parent.merchantCategory !== null) {
  if (child.merchantCategory === null || child.merchantCategory === undefined) {
    throw new Error(`Cannot attenuate: child merchantCategory must not widen parent's restriction`);
  }
  // If both are strings, they must match (or child must be a sub-category — simplest: must equal)
  if (child.merchantCategory !== parent.merchantCategory) {
    throw new Error(`Cannot attenuate: child merchantCategory "${child.merchantCategory}" not allowed by parent "${parent.merchantCategory}"`);
  }
}

// validUntil narrowing
if (parent.validUntil !== undefined && child.validUntil !== undefined) {
  if (new Date(child.validUntil) > new Date(parent.validUntil)) {
    throw new Error(`Cannot attenuate: child validUntil extends beyond parent`);
  }
}

// validFrom narrowing (child must not start before parent)
if (parent.validFrom !== undefined && child.validFrom !== undefined) {
  if (new Date(child.validFrom) < new Date(parent.validFrom)) {
    throw new Error(`Cannot attenuate: child validFrom precedes parent`);
  }
}
```

### 1.5 devMode Guard Fail-Closed

**File:** `packages/aroha-core/src/transport/server.ts`

`NODE_ENV === "production"` is fail-open — environments not setting `NODE_ENV` (containers, edge, staging) won't be protected.

**Fix:** Flip to fail-closed — only allow `devMode` when explicitly in development:
```ts
if (this.opts.devMode && process.env.NODE_ENV !== "development") {
  throw new Error(
    "[Aroha] devMode can only be enabled when NODE_ENV=development. " +
    "Current NODE_ENV: " + (process.env.NODE_ENV ?? "(unset)")
  );
}
```

### 1.6 WebSocket Stream Authentication

**File:** `packages/aroha-core/src/transport/server.ts` + `client.ts`

WebSocket streams are authenticated only by `?cid=` (correlationId), which is observable in logs and can be guessed. Anyone who knows the correlationId can subscribe to a saga's event stream.

**Fix:** Add a short-lived HMAC token to the stream URL, derived from `(correlationId + agentPrivateKey + timestamp)`. The server validates the token on connection. Token validity window: 60 seconds (enough for connection setup, too short to replay usefully).

```ts
// In client — generate a stream token
export function buildStreamToken(correlationId: string, privateKey: Uint8Array): string {
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${correlationId}:${ts}`;
  const hmac = /* HMAC-SHA256(payload, privateKey) */ ...;
  return `${Buffer.from(hmac).toString("base64url")}:${ts}`;
}

// Stream URL becomes:
`${wsEndpoint}?cid=${encodeURIComponent(cid)}&tok=${token}`

// In server — validate on ws connection
const token = url.searchParams.get("tok");
// verify HMAC + timestamp within 60s window
```

---

## 2. Operational Improvements (Pluggable Stores)

### 2.1 Pluggable NonceStore Interface

**File:** `packages/aroha-core/src/messages/nonce.ts`

`NonceRegistry` uses a private `Map<string, number>` — in-memory only. Horizontal deployments share no state, breaking replay protection.

**Design:** Extract a `NonceStore` interface. `NonceRegistry` accepts an optional store; defaults to in-memory `MapNonceStore`.

```ts
export interface NonceStore {
  /** Returns true if the nonce is fresh (first seen), false if replay. */
  setIfAbsent(nonce: string, expiryMs: number): Promise<boolean>;
  evictExpired(): Promise<void>;
}

export class NonceRegistry {
  constructor(
    private readonly store: NonceStore = new MapNonceStore(),
    cleanupIntervalMs = 60_000
  ) { ... }
}

export class MapNonceStore implements NonceStore { ... } // current Map implementation
```

`ArohaServer` constructor gains an optional `nonceStore?: NonceStore` option, passed through to `NonceRegistry`.

### 2.2 Pluggable CredentialStore Interface

**File:** `packages/aroha-credentials/src/registry.ts`

`CredentialRegistry` uses a private `Map<string, HumanCredential>` — same horizontal scale issue.

**Design:** Same pattern as NonceStore:

```ts
export interface CredentialStore {
  set(id: string, credential: HumanCredential): Promise<void> | void;
  get(id: string): Promise<HumanCredential | undefined> | HumanCredential | undefined;
  delete(id: string): Promise<boolean> | boolean;
  values(): AsyncIterable<HumanCredential> | Iterable<HumanCredential>;
}

export class CredentialRegistry {
  constructor(private readonly store: CredentialStore = new MapCredentialStore()) { ... }
}

export class MapCredentialStore implements CredentialStore { ... } // current Map implementation
```

---

## 3. Data Model Alignment

### 3.1 ArohaSatisfactionSignalBody Missing Fields

**File:** `packages/aroha-core/src/messages/types.ts`

The wire format `ArohaSatisfactionSignalBody` is missing three fields that the scoring engine `SatisfactionSignal` uses:
- `capability: string` — needed to update capability-level dimension preferences
- `withinSLA: boolean` — drives the +0.05 EMA bonus
- `requiredCompensation: boolean` — drives the -0.10 EMA penalty

Without these fields, satisfaction signals transmitted over the protocol cannot carry the context the scorer needs.

**Fix:** Add the three fields to `ArohaSatisfactionSignalBody`:
```ts
export interface ArohaSatisfactionSignalBody {
  sagaId: string;
  agentDID: string;
  capability: string;              // added
  outcome: "satisfied" | "neutral" | "dissatisfied";
  dimensions: { price: ...; quality: ...; speed: ... };
  withinSLA: boolean;              // added
  requiredCompensation: boolean;   // added
}
```

### 3.2 Trust Level 3 Description Fix

**File:** `packages/aroha-core/src/identity/credentials.ts`

Trust level 3 description says `"reputation score >= 8000"`. The scoring system produces 0–1 floats. The threshold should read `>= 0.8`.

**Fix:** Change the description string:
```ts
3: "Reputable — reputation score >= 0.8",
```

---

## 4. Scoring Logic Improvements

### 4.1 Time-Weighted Score Decay

**File:** `packages/aroha-preferences/src/filter.ts`, `scoreAgents`

`lastUsed` is stored in `AgentDynamicScore` but ignored. Scores from agents not used in months are treated as fresh.

**Fix:** Apply exponential decay at read time in `scoreAgents`:
```ts
const DECAY_HALF_LIFE_DAYS = 180; // score halves toward neutral after 180 days of inactivity

function decayScore(score: number, lastUsed: string): number {
  const daysSince = (Date.now() - new Date(lastUsed).getTime()) / 86_400_000;
  // Exponential decay toward neutral (0.5)
  const factor = Math.exp(-daysSince / (DECAY_HALF_LIFE_DAYS / Math.LN2));
  return 0.5 + (score - 0.5) * factor;
}
```

This doesn't modify the stored score — it's computed on read, so the raw EMA history is preserved and the agent naturally recovers if it starts transacting again.

### 4.2 Trust-Level Cold-Start Prior

**File:** `packages/aroha-preferences/src/filter.ts`, `scoreAgents`

All unknown agents start at 0.5, regardless of trust level. An agent with a verified corporate VC (trust level 2) deserves a higher starting point than an unregistered public agent.

**Fix:** Look up the agent's required trust level from its manifest and use it as a prior:
```ts
const TRUST_LEVEL_PRIORS: Record<0|1|2|3|4, number> = {
  0: 0.3,   // public, unregistered
  1: 0.45,  // registered + staked
  2: 0.55,  // VC-verified
  3: 0.7,   // reputable
  4: 0.85,  // user-trusted
};

// In scoreAgents:
const trustLevel = (agent.manifest.capabilities.find(c => c.id === capabilityId)?.requiredTrustLevel ?? 1) as 0|1|2|3|4;
let score = dynamic ? decayScore(dynamic.score, dynamic.lastUsed) : TRUST_LEVEL_PRIORS[trustLevel];
```

### 4.3 Dimension Preference Accumulation (EMA)

**File:** `packages/aroha-preferences/src/satisfaction.ts`, `updateCapabilityPreference`

Currently, each satisfaction signal fully overwrites the dimension preference booleans. Ten good price experiences followed by one bad one sets `preferPrice: true`, erasing the learned pattern.

**Fix:** Replace the boolean trio with a float trio (0–1 EMA), keeping the same semantics but accumulating over time:

```ts
export interface CapabilityPreference {
  // Replace boolean with 0-1 EMA: 0=don't care, 1=strongly prefer this dimension
  priceWeight:   number;
  qualityWeight: number;
  speedWeight:   number;
}

// In updateCapabilityPreference:
const PREF_DECAY = 0.9;
const PREF_NEW   = 0.1;

function updateCapabilityPreference(
  current: CapabilityPreference,
  signal: SatisfactionSignal
): CapabilityPreference {
  // If dissatisfied on a dimension, that dimension matters more to the user
  const priceSignal   = signal.dimensions.price   === "dissatisfied" ? 1 : 0;
  const qualitySignal = signal.dimensions.quality === "dissatisfied" ? 1 : 0;
  const speedSignal   = signal.dimensions.speed   === "dissatisfied" ? 1 : 0;

  return {
    priceWeight:   current.priceWeight   * PREF_DECAY + priceSignal   * PREF_NEW,
    qualityWeight: current.qualityWeight * PREF_DECAY + qualitySignal * PREF_NEW,
    speedWeight:   current.speedWeight   * PREF_DECAY + speedSignal   * PREF_NEW,
  };
}
```

The filter/score layer reads these weights when composing the soft score boost. The old boolean fields `preferPrice`, `preferQuality`, `preferSpeed` are replaced; the `CapabilityPreference` default becomes `{ priceWeight: 0, qualityWeight: 0, speedWeight: 0 }`.

---

## 5. Transport & Client Fixes

### 5.1 WebSocket Error Propagation

**File:** `packages/aroha-core/src/transport/client.ts`, `stream` method

WebSocket `error` events resolve the iterator as `done: true` instead of rejecting. Callers cannot distinguish a clean close from a connection error.

**Fix:**
```ts
ws.on("error", (err) => {
  error = err;
  if (resolve) {
    const r = resolve;
    resolve = null;
    r(Promise.reject(err) as unknown as IteratorResult<ArohaEnvelope>);
  }
});

// In next():
if (error) return Promise.reject(error);
```

### 5.2 WebSocket URL Construction

**File:** `packages/aroha-core/src/transport/client.ts:79`

String concatenation breaks if `wsEndpoint` already has query params.

**Fix:** Use `URL` constructor:
```ts
const u = new URL(wsEndpoint);
u.searchParams.set("cid", correlationId);
// (tok param added by stream auth when key is provided)
const ws = new WebSocket(u.toString());
```

### 5.3 resolveWebDID Fetch Timeout

**File:** `packages/aroha-core/src/identity/web-did.ts`, `resolveWebDID`

The HTTPS fetch for the DID Document has no timeout.

**Fix:** Add `AbortController` with configurable timeout (default 10s):
```ts
export async function resolveWebDID(
  did: string,
  verifyDNS = true,
  dnsResolver?: (domain: string) => Promise<string[]>,
  fetchTimeoutMs = 10_000
): Promise<WebDIDResolutionResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), fetchTimeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/json" } });
    ...
  } finally {
    clearTimeout(timer);
  }
}
```

---

## 6. Code Quality

### 6.1 Deduplicate readBody

**Files:** `transport/server.ts` and `credentials/middleware.ts` each define an identical `readBody` function.

**Fix:** Move `readBody` to a shared internal utility in `aroha-core` and export it. `credentials/middleware.ts` imports from `@aroha-sdk/core`.

```ts
// packages/aroha-core/src/transport/http-utils.ts  (new file)
export function readBody(req: IncomingMessage): Promise<string> { ... }

// server.ts and middleware.ts import from there
```

### 6.2 Mandate Typo Fix

**File:** `packages/aroha-credentials/src/mandate.ts`

Three error messages say "attentuate" (extra 't') instead of "attenuate".

**Fix:** Global search-replace in the file.

### 6.3 CredentialRegistry Route Ordering

**File:** `packages/aroha-credentials/src/middleware.ts`, `credentialRegistryRoutes`

The GET list route uses `url.startsWith("/aroha/credentials")`, which is broader than the GET by-ID regex. Currently safe because list comes last, but fragile.

**Fix:** Make the list route more specific:
```ts
test: (url) => url === "/aroha/credentials" || url.startsWith("/aroha/credentials?"),
```

---

## 7. did:aroha: Key Rotation Support

**File:** `packages/aroha-core/src/identity/did.ts`

`did:aroha:` identities have no key rotation mechanism. Only `did:aroha-web:` has cryptographically chained rotation. A compromised `did:aroha:` key has no recovery path.

**Design:** Add `keyHistory` to the base `DIDDocument` (making `WebDIDDocument` a natural superset) and add a `rotateDIDKey()` function that follows the same predecessor-signature pattern as `web-did.ts`:

```ts
// New optional field on DIDDocument
export interface DIDDocument {
  ...
  keyHistory?: KeyRotationRecord[];  // newest-first, from web-did types
}

// New function
export async function rotateDIDKey(
  current: AgentKeyPair,
  coolDownHours = 24
): Promise<AgentKeyPair> { ... }
```

The `extractPublicKey()` resolver is updated to check if the latest rotation's `trustAfter` has passed before returning the active key.

---

## Summary Table

| # | Tier | File(s) | Change |
|---|------|---------|--------|
| 1 | Security | `rbac.ts` | Add `mandate` action, map `ArohaSpendingMandate` |
| 2 | Security | `middleware.ts` | Unknown issuer → 401, not `registerTrusted` |
| 3 | Security | `web-did.ts` | Call `verifyKeyRotation` in `resolveWebDID` |
| 4 | Security | `mandate.ts` | `assertNarrowing` add `merchantCategory` check |
| 5 | Security | `mandate.ts` | `assertNarrowing` add `validUntil`/`validFrom` check |
| 6 | Security | `server.ts` | `devMode` fail-closed (`!== "development"`) |
| 7 | Security | `server.ts` + `client.ts` | WebSocket HMAC stream token |
| 8 | Ops | `nonce.ts` + `server.ts` | `NonceStore` interface, `MapNonceStore` default |
| 9 | Ops | `registry.ts` | `CredentialStore` interface, `MapCredentialStore` default |
| 10 | Ops | `web-did.ts` | Add `fetchTimeoutMs` to `resolveWebDID` |
| 11 | Data Model | `messages/types.ts` | Add `capability`, `withinSLA`, `requiredCompensation` to `ArohaSatisfactionSignalBody` |
| 12 | Data Model | `identity/credentials.ts` | Fix trust level 3 description `>= 8000` → `>= 0.8` |
| 13 | Scoring | `preferences/filter.ts` | Time-weighted score decay with 180-day half-life |
| 14 | Scoring | `preferences/filter.ts` | Trust-level cold-start priors |
| 15 | Scoring | `preferences/satisfaction.ts` | EMA on dimension preferences (replace booleans with weights) |
| 16 | Transport | `transport/client.ts` | WebSocket error propagation (reject instead of done:true) |
| 17 | Transport | `transport/client.ts` | WebSocket URL via `URL` constructor |
| 18 | Transport | `web-did.ts` | `resolveWebDID` fetch timeout |
| 19 | Quality | `server.ts` + `middleware.ts` | Deduplicate `readBody` into shared `http-utils.ts` |
| 20 | Quality | `mandate.ts` | Fix "attentuate" typo (3 occurrences) |
| 21 | Quality | `middleware.ts` | Make registry list route URL match more specific |
| 22 | Identity | `identity/did.ts` | Key rotation for `did:aroha:` identities |

---

## Test Coverage

Each change that alters logic needs a test:
- `rbac.test.ts`: spending mandate with/without `mandate` role
- `mandate.test.ts`: `assertNarrowing` with `merchantCategory`, `validUntil`, `validFrom` edge cases
- `preferences.test.ts`: time decay, trust-level prior, dimension weight EMA
- `registry.test.ts`: `CredentialStore` interface via `MapCredentialStore`
- `nonce.test.ts`: `NonceStore` interface via `MapNonceStore`
- `web-did.test.ts`: `resolveWebDID` with invalid rotation signature, fetch timeout

No new tests needed for pure refactors (readBody dedup, typo fix, URL fix).
