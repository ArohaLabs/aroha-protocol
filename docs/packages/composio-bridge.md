<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/composio-bridge

Aroha ↔ Composio bridge. Composio is the integration platform behind TrustClaw and many other AI agent frameworks. It exposes "actions" — named, typed functions that LLMs can call. This bridge registers Aroha capabilities as Composio custom actions, so any Composio-connected agent (TrustClaw, Claude + Composio, GPT-4 + Composio, etc.) can call your Aroha agents without knowing the underlying protocol.

```bash
npm install @aroha-sdk/composio-bridge
```

---

## registerArohaCapabilities()

Register one or more Aroha capabilities as Composio actions in a single call:

```typescript
import { Composio }                    from "composio-core";
import { registerArohaCapabilities }   from "@aroha-sdk/composio-bridge";
import { generateDID }                 from "@aroha-sdk/core";

const composio = new Composio({ apiKey: process.env.COMPOSIO_API_KEY });
const identity = await generateDID("my-composio-caller");

await registerArohaCapabilities(composio, [
  {
    endpoint:         "http://travel-agent.aroha-labs.com",
    agentDID:         "did:aroha:travel-agent",
    capabilityId:     "search-flights",
    description:      "Search for available flights between two airports on a given date",
    callerDID:        identity.did,
    callerPrivateKey: identity.privateKey,
    inputSchema: {
      origin:      { type: "string", description: "IATA origin airport code" },
      destination: { type: "string", description: "IATA destination airport code" },
      date:        { type: "string", description: "Departure date in YYYY-MM-DD format" },
    },
  },
  {
    endpoint:         "http://weather.aroha-labs.com",
    agentDID:         "did:aroha:weather-agent",
    capabilityId:     "get-weather",
    description:      "Get current weather for a city",
    callerDID:        identity.did,
    callerPrivateKey: identity.privateKey,
    inputSchema: {
      city: { type: "string", description: "City name" },
    },
  },
]);
```

The actions are now available to any agent connected to this Composio workspace.

---

## arohaCapabilityToComposioAction()

Convert a single Aroha capability to a Composio action definition without registering it:

```typescript
import { arohaCapabilityToComposioAction } from "@aroha-sdk/composio-bridge";

const action = arohaCapabilityToComposioAction({
  endpoint:         "http://travel-agent.aroha-labs.com",
  agentDID:         "did:aroha:travel-agent",
  capabilityId:     "search-flights",
  description:      "Search for flights",
  callerDID:        identity.did,
  callerPrivateKey: identity.privateKey,
});

// action.name        → "aroha_search-flights"
// action.description → "Search for flights"
// action.execute     → async (params) => ArohaResponse.body.result
```

---

## buildComposioActionHandler()

Build a standalone Composio action handler function for use with custom action registration:

```typescript
import { buildComposioActionHandler } from "@aroha-sdk/composio-bridge";

const handler = buildComposioActionHandler({
  endpoint:         "http://travel-agent.aroha-labs.com",
  agentDID:         "did:aroha:travel-agent",
  capabilityId:     "book-flight",
  callerDID:        identity.did,
  callerPrivateKey: identity.privateKey,
});

// handler is (params: Record<string, unknown>) => Promise<ComposioActionResult>
```

---

## ArohaComposioOptions

```typescript
interface ArohaComposioOptions {
  /** Base URL of the Aroha agent. */
  endpoint: string;
  /** DID of the Aroha agent to call. */
  agentDID: string;
  /** Capability ID to invoke. */
  capabilityId: string;
  /** Human-readable description for the Composio action catalogue. */
  description?: string;
  /** JSON Schema for the action's input parameters. */
  inputSchema?: Record<string, { type: string; description?: string }>;
  /** Caller DID for signing outbound envelopes. */
  callerDID: string;
  /** Ed25519 private key for signing. */
  callerPrivateKey: Uint8Array;
  /** Timeout per call in ms. Default: 30_000 */
  timeoutMs?: number;
}
```

---

## TrustClaw integration

TrustClaw uses Composio actions for all external tool calls. After registering your Aroha capabilities:

```python
# Python — TrustClaw agent
from trustclaw import Agent
from composio_trustclaw import ComposioToolSet, Action

toolset = ComposioToolSet()
tools   = toolset.get_tools(actions=["aroha_search-flights", "aroha_get-weather"])

agent = Agent(tools=tools)
agent.run("Find me a flight from London to Tokyo next Friday and check the weather in Tokyo")
```

The TrustClaw agent calls the Aroha-backed Composio actions as if they were native tools — identity, signing, and optional settlement happen transparently in the bridge.

---

## How it works

1. `registerArohaCapabilities()` creates a Composio custom action for each capability.
2. When a Composio-connected agent calls the action, the bridge builds an `ArohaRequest` envelope signed with the caller's Ed25519 key.
3. The envelope is sent to the Aroha agent's endpoint.
4. The `ArohaResponse.body.result` is returned as the Composio action result.
5. If the agent requires settlement, the bridge negotiates `ArohaReserve` / `ArohaCommitAck` before returning.

See also: [`@aroha-sdk/openclaw-bridge`](openclaw-bridge.md) · [`@aroha-sdk/hermes-bridge`](hermes-bridge.md)
