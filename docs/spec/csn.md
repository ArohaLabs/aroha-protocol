<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Capability Schema Negotiation (CSN)

CSN is Aroha's mechanism for two agents to agree on a capability mapping
when the requestor does not know the provider's exact capability name.
It addresses the same problem as ANP's meta-protocol, using a different approach.

## CSN compared with ANP's meta-protocol

ANP meta-protocol: the LLM generates a **new ad-hoc protocol** for the two
agents, which they must both code-generate and interpret. The generated
protocol is not covered by ANP's own type definitions.

Aroha CSN maps the requestor's intent to an **existing, typed Aroha
capability**. The provider's saga semantics, error codes, signing, and SLA
guarantees are all preserved because the agreed capability is already
registered and typed.

| Dimension | ANP meta-protocol | **Aroha CSN** |
|-----------|-------------------|--------------|
| Matching  | LLM generates new protocol | Deterministic structural schema match first |
| LLM role  | Always required | Only for ambiguous cases (score 0.5–0.85) |
| Result    | Ad-hoc protocol | Maps to existing typed capability |
| Type safety | Not covered (generated protocol) | **Preserved** |
| Saga / error codes | Not applicable | **Preserved** |
| Terms negotiation | Separate round | **Same round** |
| Caching | None | **SHA-256 cached → repeats skip matching** |

---

## How CSN Works

```
Requestor                             Provider
   │                                      │
   │── ArohaNegotiate (+ CSN extension) ──►│
   │   capabilityIntent: "convert USD"    │ 1. SHA-256 schema → cache hit?
   │   desiredSchema: {input: {...}}      │    ↳ yes → ArohaAccept immediately
   │   schemaHash: "abc123"               │ 2. Structural schema matching (0–1)
   │                                      │    ↳ score ≥ 0.85 → confident match
   │                                      │    ↳ score 0.5–0.85 → LLM fallback
   │                                      │    ↳ score < 0.5 → incompatible
   │◄── ArohaAccept (+ CSN extension) ─────│ 3. Returns agreed capability + schema
   │   resolvedCapability: "fx-convert"   │    + pricing/SLA terms
   │   agreedSchema: {...}                │
   │   matchMethod: "schema"              │
   │   compatibilityScore: 0.95           │
```

---

## Compatibility Score

The structural score compares the **required properties** of the desired
input schema against the provider's registered schema:

- **≥ 0.85** — Confident match. No LLM call needed.
- **0.5–0.85** — Ambiguous. LLM fallback recommended (if configured).
- **< 0.5** — Incompatible.

Required properties are weighted `1.0`; optional properties `0.4`.
Type compatibility: `number ↔ integer` are treated as compatible (`0.7` weight).

---

## Quick-Start

=== "TypeScript"

    **Provider** — register capabilities and mount the CSN handler:

    ```typescript
    import { CapabilityRegistry, CSNHandler } from "@aroha-sdk/orchestrator";

    const registry = new CapabilityRegistry();
    registry.register({
      name:         "fx-convert",
      description:  "Convert between two currencies",
      inputSchema: {
        type: "object",
        properties: {
          amount: { type: "number" },
          from:   { type: "string" },
          to:     { type: "string" },
        },
        required: ["amount", "from", "to"],
      },
      outputSchema:   { type: "object", properties: { converted: { type: "number" } } },
      supportsSaga:   true,
      defaultPricing: { model: "per-call", amount: 0.001, currency: "USD" },
      defaultSLA:     { maxResponseMs: 500, p99Ms: 200 },
    });

    const csnHandler = new CSNHandler(registry, {
      agentDID:   "did:aroha:fx-agent",
      privateKey: agentPrivKey,
      // Optional LLM adapter — only called when score is 0.5–0.85
      llmMatcher: { match: async (intent, candidates) => callYourLLM(intent, candidates) },
    });

    // In your ArohaServer onMessage:
    server.onMessage = async (envelope, respond) => {
      if (envelope.type === "ArohaNegotiate" && envelope.body.csn) {
        const reply = await csnHandler.handle(envelope, envelope.from);
        respond(reply);
        return;
      }
      // ... other handlers
    };
    ```

    **Requestor** — discover and call a capability:

    ```typescript
    import { CapabilityNegotiator } from "@aroha-sdk/orchestrator";

    const negotiator = new CapabilityNegotiator(client, orchestratorDID, privateKey);

    const result = await negotiator.discover(
      "https://fx.example.com/aroha/v1",
      "did:aroha-web:fx.example.com:agent",
      {
        capabilityIntent: "convert currency from USD to JPY",
        desiredSchema: {
          input: {
            type: "object",
            properties: {
              amount: { type: "number" },
              from:   { type: "string" },
              to:     { type: "string" },
            },
            required: ["amount", "from", "to"],
          },
        },
      }
    );

    // result.resolvedCapability === "fx-convert"
    // result.matchMethod === "schema"   (deterministic — no LLM used)
    // result.rounds === 0               (cache hit on second call)

    // Now call it
    await client.request(agentEndpoint, {
      capability: result.resolvedCapability,
      params:     { amount: 100, from: "USD", to: "JPY" },
    });
    ```

=== "Python"

    **Provider:**

    ```python
    from aroha.csn import CapabilityRegistry, CapabilityEntry, CSNHandler

    registry = CapabilityRegistry()
    registry.register(CapabilityEntry(
        name="fx-convert",
        description="Convert between two currencies",
        input_schema={
            "type": "object",
            "properties": {
                "amount": {"type": "number"},
                "from":   {"type": "string"},
                "to":     {"type": "string"},
            },
            "required": ["amount", "from", "to"],
        },
        supports_saga=True,
        default_pricing={"model": "per-call", "amount": 0.001, "currency": "USD"},
        default_sla={"maxResponseMs": 500},
    ))

    handler = CSNHandler(registry, agent_did=did, private_key=key)

    async def on_message(envelope, respond, stream):
        if envelope["type"] == "ArohaNegotiate" and "csn" in envelope["body"]:
            reply = await handler.handle(envelope, envelope["from"])
            respond(reply)
    ```

    **Requestor:**

    ```python
    from aroha.csn import CapabilityNegotiator, DiscoveryRequest

    negotiator = CapabilityNegotiator(send=http_send, orchestrator_did=my_did, private_key=key)
    result = await negotiator.discover(
        agent_endpoint="https://fx.example.com/aroha/v1",
        agent_did="did:aroha-web:fx.example.com:agent",
        request=DiscoveryRequest(
            capability_intent="convert currency from USD to JPY",
            desired_schema={
                "input": {"type": "object", "properties": {
                    "amount": {"type": "number"},
                    "from":   {"type": "string"},
                    "to":     {"type": "string"},
                }, "required": ["amount", "from", "to"]},
            },
        ),
    )
    # result.resolved_capability == "fx-convert"
    ```

=== "Go / Java"

    *Coming soon — the Go and Java SDKs are not yet published.*

    CSN is language agnostic; the message shapes above are the normative part.

## LLM Matcher Adapter

The LLM matcher is **optional** and **injected** — CSN works without one.
When structural scoring is ambiguous (0.5–0.85), the matcher receives the
intent string and candidate capabilities, and returns the best match name.

=== "TypeScript"

    ```typescript
    import OpenAI from "openai";

    const openai = new OpenAI();

    const llmMatcher = {
      async match(intent: string, candidates: Array<{ name: string; description: string }>) {
        const list = candidates.map((c) => `- ${c.name}: ${c.description}`).join("\n");
        const resp = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: "Reply with only the capability name that best matches the user intent. Return null if uncertain." },
            { role: "user", content: `Intent: ${intent}\n\nCapabilities:\n${list}` },
          ],
        });
        const result = resp.choices[0].message.content?.trim() ?? null;
        return result === "null" ? null : result;
      },
    };

    const csnHandler = new CSNHandler(registry, { agentDID, privateKey, llmMatcher });
    ```

=== "Python"

    ```python
    import anthropic

    class ClaudeMatcher:
        def __init__(self):
            self.client = anthropic.Anthropic()

        async def match(self, intent: str, candidates: list[dict]) -> str | None:
            lines = "\n".join(f"- {c['name']}: {c['description']}" for c in candidates)
            msg = self.client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=50,
                messages=[{
                    "role": "user",
                    "content": f"Reply with only the capability name that best matches: {intent}\n{lines}"
                }],
            )
            result = msg.content[0].text.strip()
            return None if result == "null" else result

    handler = CSNHandler(registry, agent_did=did, private_key=key,
                         llm_matcher=ClaudeMatcher())
    ```

---

## Discovery Cache

Agreed mappings are cached by `(agentDID, schemaHash)`. On subsequent calls
with the same schema, the result is returned instantly — zero network round
trips, zero LLM calls.

```typescript
// First call — 1 round trip
const r1 = await negotiator.discover(endpoint, agentDID, request);
// r1.rounds === 1, r1.matchMethod === "schema"

// Second call — cache hit
const r2 = await negotiator.discover(endpoint, agentDID, request);
// r2.rounds === 0, r2.matchMethod === "cache"
```

The cache is backed by an in-memory store by default. For production,
implement `IDiscoveryStore` to persist to Redis or PostgreSQL.

```typescript
import { DiscoveryCache, type IDiscoveryStore } from "@aroha-sdk/orchestrator";

class RedisDiscoveryStore implements IDiscoveryStore {
  async get(key: string) { /* ... */ }
  async set(key: string, entry: CacheEntry) { /* ... */ }
  async delete(key: string) { /* ... */ }
  async keys(prefix?: string) { /* ... */ }
}

const cache      = new DiscoveryCache(new RedisDiscoveryStore());
const negotiator = new CapabilityNegotiator(client, orchestratorDID, key, cache);
```

---

## CSN + Saga Flow

After CSN resolves a capability, continue with the normal Aroha saga:

```typescript
const discovery = await negotiator.discover(endpoint, agentDID, { ... });

// ── Reserve ────────────────────────────────────────────────────────────────
const ack = await client.reserve(endpoint, {
  capability: discovery.resolvedCapability,   // ← from CSN
  params:     { amount: 100, from: "USD", to: "JPY" },
  holdDurationMs: 5000,
});

// ── Commit ─────────────────────────────────────────────────────────────────
const result = await client.commit(endpoint, { reservationToken: ack.reservationToken });
```

All saga guarantees (compensating transactions, error codes, satisfaction
signals) are preserved because CSN maps to an *existing* capability — not
a generated ad-hoc protocol.

---

## Message Type Reference

### ArohaNegotiate (with CSN extension)

```json
{
  "type": "ArohaNegotiate",
  "body": {
    "capability":    "unknown",
    "proposedTerms": {},
    "csn": {
      "capabilityIntent":          "convert currency from USD to JPY",
      "desiredSchema": {
        "input": { "type": "object", "properties": { "amount": {"type": "number"}, ... } }
      },
      "schemaHash":                "sha256hex of desiredSchema",
      "requestCapabilityManifest": false
    }
  }
}
```

### ArohaAccept (with CSN extension)

```json
{
  "type": "ArohaAccept",
  "body": {
    "capability":    "fx-convert",
    "acceptedTerms": { "price": { "model": "per-call", "amount": 0.001 } },
    "csn": {
      "resolvedCapability": "fx-convert",
      "agreedSchema":       { "input": { ... }, "output": { ... } },
      "schemaHash":         "echo of requestor's schemaHash",
      "matchMethod":        "schema",
      "compatibilityScore": 0.95,
      "capabilityManifest": null
    }
  }
}
```

### Match method values

| Value | Meaning |
|-------|---------|
| `"schema"` | Deterministic structural match (preferred) |
| `"intent"` | LLM-assisted fallback (score was 0.5–0.85) |
| `"cache"`  | Recovered from SHA-256 negotiation cache |
