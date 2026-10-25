<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Agent Playground

A CodePen-style in-browser environment where you write a capability handler in JavaScript, click **Run**, and watch real Ed25519-signed Aroha envelopes fly between two agents — with no server, no build step, and no API key.

---

## Open the playground

```bash
# From the repo root:
open examples/playground/index.html
# or just double-click the file in your file manager
```

Or serve it locally:

```bash
npx serve examples/playground
# Open: http://localhost:3000
```

---

## What you see

```
┌─────────────────────────────┬─────────────────────────────┐
│  Capability Handler (JS)    │  Protocol Output            │
│  ──────────────────────     │  ──────────────────────     │
│  async function             │  Agent A Identity           │
│  handleCapability(          │  Agent B Identity           │
│    capability, params       │                             │
│  ) { ... }                  │  → ArohaRequest (signed)     │
├─────────────────────────────│  ✓ Ed25519 verified         │
│  Request (JSON)             │                             │
│  ──────────────────────     │  ← ArohaResponse (signed)    │
│  {                          │  ✓ Ed25519 verified         │
│    "capability": "greet",   │                             │
│    "params": { "name":      │  Result: { "message": ... } │
│      "Alice" }              │                             │
│  }                          │                             │
└─────────────────────────────┴─────────────────────────────┘
```

**Left pane — two editors:**

- **Capability Handler** — write `async function handleCapability(capability, params)`. Return a result object; throw to produce a `ArohaError`.
- **Request** — JSON with `capability` and `params`. Edit freely.

**Right pane — live protocol output:**

- Both agents generate fresh Ed25519 keypairs on every Run
- The full signed `ArohaRequest` JSON — with syntax-highlighted proof value (amber)
- `✓ Ed25519 signature verified` at Agent B
- The full signed `ArohaResponse` (or `ArohaError` if your handler throws)
- `✓ Ed25519 signature verified` at Agent A

---

## How to use it

1. Edit the **Capability Handler** to add your own cases:

```javascript
async function handleCapability(capability, params) {
  switch (capability) {

    case "weather":
      // Call a real API if you have one, or mock it
      return {
        city: params.city,
        temp: 22,
        condition: "Partly cloudy",
      };

    case "translate":
      return {
        original: params.text,
        translated: `[${params.text} in ${params.lang}]`,
      };

    default:
      throw new Error(`Unknown capability: ${capability}`);
  }
}
```

2. Update the **Request**:

```json
{
  "capability": "weather",
  "params": { "city": "Tokyo" }
}
```

3. Click **▶ Run** (or press `Ctrl+Enter` / `Cmd+Enter`)

---

## What's happening under the hood

Every click of **Run** does real protocol work:

```
1. Agent A generates Ed25519 keypair → did:aroha:<32-hex-pubkey>
2. Agent B generates Ed25519 keypair → did:aroha:<32-hex-pubkey>

3. Agent A builds ArohaRequest:
   { type, from, to, body, correlationId, nonce, issuedAt, expires }
   ↓
   signs with Agent A's private key → proof.proofValue (Ed25519Signature2020)

4. Agent B receives envelope
   ↓
   verifyAsync(proof.proofValue, payload, agentA.publicKey)
   → ✓ valid

5. Agent B executes handleCapability() with your JS code

6. Agent B builds ArohaResponse:
   { type, from, to, body, correlationId, ... }
   ↓
   signs with Agent B's private key → proof.proofValue

7. Agent A verifies Agent B's response signature → ✓ valid
```

The cryptography is real — `@noble/ed25519` loaded from CDN, running in your browser's JavaScript engine. Nothing is simulated.

---

## Keyboard shortcut

| Key | Action |
|-----|--------|
| `Ctrl+Enter` / `Cmd+Enter` | Run the protocol |

---

## Example handlers to try

### Arithmetic

```javascript
async function handleCapability(capability, params) {
  if (capability === "add")
    return { result: Number(params.a) + Number(params.b) };
  if (capability === "multiply")
    return { result: Number(params.a) * Number(params.b) };
  throw new Error(`Unknown: ${capability}`);
}
```

Request:
```json
{ "capability": "add", "params": { "a": 17, "b": 25 } }
```

### Error path

```javascript
async function handleCapability(capability, params) {
  if (!params.userId) throw new Error("userId is required");
  return { user: { id: params.userId, name: "Alice" } };
}
```

Request:
```json
{ "capability": "get-user", "params": {} }
```

This triggers a `ArohaError` envelope — the handler's throw is caught and signed as an error response.

---

## Difference from the vc-demo

| | **Agent Playground** | **vc-demo** |
|---|---|---|
| Purpose | Learn the protocol / experiment | Demonstrate to investors |
| Agents | In-browser, ephemeral keys | In-process Node.js agents |
| Crypto | Real (noble/ed25519 CDN) | Real (aroha-core) |
| Saga | ArohaRequest only | Full saga (Reserve → Commit → Cancel) |
| Server required | No | Yes (`node scripts/vc-demo.mjs`) |
| Code editable | Yes | No |

For the full saga demo with human-in-the-loop, see [Browser Demos →](browser.md).
