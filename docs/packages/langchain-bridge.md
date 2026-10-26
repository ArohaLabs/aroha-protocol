<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/langchain-bridge

**Bring Your Own Framework (BYOF)** — use Aroha as the transport and identity layer while keeping your framework as the reasoning layer. It hands Aroha capabilities to LangChain-style tool runners and to anything that takes OpenAI function tools.

> Aroha is transport. Your framework is the brain.

---

## The problem it solves

You've already built agents in LangChain or another framework. You don't want to rewrite them. But you do want:

- **Verifiable identity**: every inter-agent call is cryptographically signed
- **Discovery**: other agents can find your tools without hardcoded URLs (register the descriptors from Pattern 4)
- **RBAC**: role-based access control at the transport layer (`@aroha-sdk/credentials` middleware on an `ArohaServer`)

`@aroha-sdk/langchain-bridge` gives you signed calls in both directions without touching your existing agent code. The provider it creates answers `ArohaRequest` only; saga steps (`ArohaReserve` / `ArohaCommit` / `ArohaCancel`) are not handled by the bridge.

---

## Installation

```bash
npm install @aroha-sdk/langchain-bridge
```

No hard dependency on any LangChain version — the bridge uses duck-typed interfaces: a LangChain-style tool (`name`, `description`, `schema`, `call`) and an OpenAI Chat Completions function tool.

---

## Patterns

### Pattern 1: Call a Aroha agent from LangChain

Wrap any Aroha capability as a LangChain tool. Your LangChain agent calls it like any other tool — Aroha handles signing, verification, and discovery transparently.

```typescript
import { arohaCapabilityToLangChainTool } from "@aroha-sdk/langchain-bridge";

const flightSearchTool = arohaCapabilityToLangChainTool("search-flights", {
  endpoint: "https://flight-agent.example/aroha/v1",
  agentDID: "did:aroha:flight-agent",
  callerDID: myDID,
  callerPrivateKey: myPrivateKey,
  description: "Search available flights. Input: { origin, destination, date }",
  schema: {
    type: "object",
    properties: {
      origin: { type: "string" },
      destination: { type: "string" },
      date: { type: "string", format: "date" },
    },
    required: ["origin", "destination", "date"],
  },
});

// Use with any LangChain agent:
const agent = createToolCallingAgent({ tools: [flightSearchTool, ...otherTools] });
```

### Pattern 2: Use the OpenAI function-tool format

```typescript
import { arohaCapabilityToOpenAITool } from "@aroha-sdk/langchain-bridge";

const hotelTool = arohaCapabilityToOpenAITool("search-hotels", {
  endpoint: "https://hotel-agent.example/aroha/v1",
  agentDID: "did:aroha:hotel-agent",
  callerDID: myDID,
  callerPrivateKey: myPrivateKey,
  description: "Search available hotels. Input: { city, checkIn, checkOut }",
});

// { type: "function", function: { name, description, parameters }, invoke() }
// Tested against OpenAI's function-tool rules and the official `openai` npm client (see the package README).
// AutoGen and Semantic Kernel are not tested.
```

### Pattern 3: Expose LangChain tools as a Aroha provider

Your existing LangChain toolset becomes a Aroha agent. Other Aroha agents can discover it and call it with signed envelopes (`ArohaRequest`).

```typescript
import { langChainAgentToArohaProvider } from "@aroha-sdk/langchain-bridge";

// Your existing LangChain tools — unchanged
const myTools = [searchTool, calculatorTool, databaseTool];

// Expose them as a Aroha provider
const server = langChainAgentToArohaProvider(myTools, {
  agentDID: "did:aroha:my-langchain-agent",
  agentPrivateKey: myPrivateKey,
  port: 3100,
  resolvePublicKey: registry.resolvePublicKey.bind(registry),
  didDocument: myDIDDocument,
});

await server.start();
// Now any Aroha orchestrator can discover and call your tools
```

### Pattern 4: Get Aroha capability descriptors for registry registration

```typescript
import { langChainToolsToCapabilities } from "@aroha-sdk/langchain-bridge";

const capabilities = langChainToolsToCapabilities(myTools);
// [{ capabilityId, description, inputSchema }, ...]

// Register with InMemoryRegistry (register(did, manifestCID, publicKey, options))
await registry.register(agentDID, manifestCID, pubKey, {
  capabilityIds: capabilities.map((c) => c.capabilityId),
});
```

---

## API reference

### `arohaCapabilityToLangChainTool(capabilityId, opts): LangChainToolLike`

Wraps a Aroha capability as a LangChain-compatible tool object.

| Option | Type | Description |
|--------|------|-------------|
| `endpoint` | `string` | Aroha endpoint URL of the remote agent |
| `agentDID` | `string` | DID of the remote agent (`to` field) |
| `callerDID` | `string` | Your agent's DID (`from` field) |
| `callerPrivateKey` | `Uint8Array` | Ed25519 private key for signing |
| `description` | `string` | Human-readable description for the LLM |
| `schema?` | `Record<string, unknown>` | JSON Schema for tool input |
| `client?` | `ArohaClient` | Optional pre-configured client |

### `arohaCapabilityToOpenAITool(capabilityId, opts): OpenAIFunctionLike`

Same options as above. Returns `{ type: "function", function: { name, description, parameters }, invoke() }`.

### `langChainAgentToArohaProvider(tools, opts): ArohaServer`

Exposes a `LangChainToolLike[]` as a Aroha provider. Returns a `ArohaServer` — call `.start()` to listen.

### `langChainToolsToCapabilities(tools): ArohaCapabilityDescriptor[]`

Converts tools to capability descriptors for registry registration.

---

## Duck-typed interfaces

The bridge never imports LangChain directly. It uses these minimal interfaces:

```typescript
interface LangChainToolLike {
  name: string;
  description: string;
  schema?: Record<string, unknown>;
  call(input: string | Record<string, unknown>): Promise<string>;
}

interface OpenAIFunctionLike {
  type: "function";
  function: { name: string; description: string; parameters?: Record<string, unknown> };
  invoke(args: Record<string, unknown>): Promise<unknown>;
}
```

Any object that matches these shapes works. The OpenAI shape is checked in CI against OpenAI's function-tool rules and the `openai` client. Other frameworks that accept OpenAI function tools should work, but none is tested.

---

## What Aroha adds to your framework

| Concern | LangChain alone | With @aroha-sdk/langchain-bridge |
|---------|----------------|------------------------------|
| Inter-agent auth | None — caller trusts any response | Ed25519 signed every message |
| Discovery | Hardcoded URLs | Registry — find agents by capability |
| Saga / rollback | Manual | Not handled by the bridge (the provider answers `ArohaRequest` only) |
| RBAC | None | Credential-based at transport layer (`@aroha-sdk/credentials` middleware) |
| Audit | No standard | Not provided by the bridge — `@aroha-sdk/audit` gives a SHA-256 hash-chained log |
