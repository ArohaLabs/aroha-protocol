<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/policy

**Policy-as-Code** — deterministic JSON boundary enforcement evaluated at the transport layer, before any LLM or application code runs.

> If an agent tries to hallucinate a `"delete-database"` request, the protocol rejects it. The LLM never sees it.

---

## The problem it solves

LLMs are probabilistic. Given a sufficiently creative prompt, a model might:
- Construct a `transfer-funds` request for an amount 10× above the company policy
- Add an unexpected `admin: true` parameter to a capability that only allows read access
- Embed a long free-text prompt inside a structured parameter to manipulate a downstream agent

Policy-as-Code removes the LLM from the security boundary. Rules are deterministic JSON checks evaluated **after** envelope signature verification, **before** the handler dispatches to application code or an LLM. No reasoning involved.

---

## Installation

```bash
npm install @aroha-sdk/policy
```

---

## Quickstart

```typescript
import { ArohaPolicyEngine, createPolicyMiddleware, createStructuredPayloadMiddleware } from "@aroha-sdk/policy";
import { ArohaServer } from "@aroha-sdk/core";

const engine = new ArohaPolicyEngine();

// Hard cap on spend
engine.addPolicy({
  capabilityId: "transfer-funds",
  maxSpendPerCall: { amount: 500, currency: "USD", paramKey: "amount" },
  requiredParamKeys: ["recipient", "amount", "currency"],
});

// Block destructive actions globally
engine.addPolicy({
  capabilityId: "*",   // default — applies to capabilities that have no policy of their own
  blockedParamValues: [
    { key: "action", value: "delete" },
    { key: "action", value: "drop-table" },
    { key: "admin", value: true },
  ],
});

// Allowlist for a sensitive capability
engine.addPolicy({
  capabilityId: "execute-query",
  allowedParamKeys: ["query", "database", "limit"],
  paramAllowedValues: [
    { key: "database", allowedValues: ["analytics", "reporting"] },
  ],
  rateLimitPerMinute: 10,
});

const server = new ArohaServer({
  // ...
  middleware: [
    createPolicyMiddleware(engine),              // policy checks
    createStructuredPayloadMiddleware({           // anti-injection
      maxStringLength: 512,
      maxParamDepth: 3,
    }),
  ],
});
```

---

## Policy rules

### `maxSpendPerCall`

Reject requests where a numeric parameter exceeds a limit.

```typescript
maxSpendPerCall: {
  amount: 500,         // maximum allowed value
  currency: "USD",     // for error messages only (not exchanged)
  paramKey: "amount",  // which param to read (default: "amount")
}
```

### `allowedParamKeys`

Reject requests containing any parameter key not on the whitelist.

```typescript
allowedParamKeys: ["city", "checkIn", "checkOut", "guests"]
// Request with { city, checkIn, checkOut, secret: "..." } → DENIED
```

### `blockedParamValues`

Reject requests containing specific (key, value) combinations.

```typescript
blockedParamValues: [
  { key: "action", value: "delete" },
  { key: "role",   value: "admin" },
]
```

### `requiredParamKeys`

Reject requests missing mandatory fields. Prevents incomplete or malformed requests from reaching application code.

```typescript
requiredParamKeys: ["recipient", "amount"]
// Request with just { amount: 100 } → DENIED ("recipient" missing)
```

### `paramAllowedValues`

Allowlist for a specific parameter's values. Use for enum-style enforcement.

```typescript
paramAllowedValues: [
  { key: "env", allowedValues: ["staging", "production"] }
]
// { env: "dev" } → DENIED
```

### `rateLimitPerMinute`

Sliding-window rate limit per sender DID per capability. Uses an in-process counter — for distributed rate limiting, implement `IPolicyEngine` with Redis storage.

### `requiresHITLApproval`

Hard policy rule that marks a capability as always requiring human approval, independent of SagaEngine configuration. Useful for capabilities where a policy document requires a human sign-off regardless of transaction size.

---

## `createStructuredPayloadMiddleware`

Closes the prompt-injection surface at the transport layer.

```typescript
createStructuredPayloadMiddleware({
  maxStringLength: 512,  // reject string params > N characters
  maxParamDepth: 3,      // reject deeply-nested param objects
})
```

A `"search"` capability receiving `{ query: "<500-word jailbreak prompt>" }` is rejected before the application handler sees it.

---

## Custom policy engine

Implement `IPolicyEngine` to integrate with OPA (Open Policy Agent), Cedar, or any external policy system:

```typescript
import type { IPolicyEngine, PolicyResult } from "@aroha-sdk/policy";

class OPAPolicyEngine implements IPolicyEngine {
  addPolicy() { /* load into OPA bundle */ }
  removePolicy() { /* ... */ }

  async evaluate(capability, params, senderDID): Promise<PolicyResult> {
    const response = await fetch("http://opa-server:8181/v1/data/aroha/allow", {
      method: "POST",
      body: JSON.stringify({ input: { capability, params, senderDID } }),
    });
    const { result } = await response.json();
    return result ? { outcome: "allow" } : { outcome: "deny", reason: "OPA denied" };
  }
}

// Use exactly like ArohaPolicyEngine:
const server = new ArohaServer({
  middleware: [createPolicyMiddleware(new OPAPolicyEngine())],
});
```

---

## Policy evaluation order

```
Inbound ArohaRequest
       │
       ▼
[1] validateEnvelope()       — signature, expiry, nonce (core protocol)
       │
       ▼
[2] createPolicyMiddleware() — requiredKeys, allowedKeys, blockedValues,
       │                       paramAllowedValues, maxSpend, rateLimit
       ▼
[3] createStructuredPayloadMiddleware() — string length, nesting depth
       │
       ▼
[4] Your application handler / LLM
```

Steps 1–3 are deterministic. Step 4 is the only place reasoning occurs — and it only runs for requests that passed all policy checks.
