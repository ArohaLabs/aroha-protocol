<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/composio-bridge

Aroha ↔ Composio bridge. Composio is the integration platform behind TrustClaw and many other AI agent frameworks. It exposes "actions" — named, typed functions that LLMs can call. This bridge registers Aroha capabilities as Composio custom actions, so any Composio-connected agent (TrustClaw, Claude + Composio, GPT-4 + Composio, etc.) can call your Aroha agents without knowing the underlying protocol.

```bash
npm install @aroha-sdk/composio-bridge
```

---

## registerArohaCapabilities()

Register one or more Aroha capabilities as Composio actions in a single call. Any client that has `addCustomAction()` or `createAction()` is accepted:

```typescript
import { Composio }                    from "composio-core";
import { registerArohaCapabilities }   from "@aroha-sdk/composio-bridge";
import { generateDID }                 from "@aroha-sdk/core";

const composio = new Composio({ apiKey: process.env.COMPOSIO_API_KEY });
const identity = await generateDID("my-composio-caller", "https://caller.example/aroha/v1");

const actions = await registerArohaCapabilities(composio, [
  {
    endpoint:         "https://travel-agent.example/aroha/v1",
    agentDID:         "did:aroha:travel-agent",
    capabilityId:     "search-flights",
    description:      "Search for available flights between two airports on a given date",
    callerDID:        identity.did,
    callerPrivateKey: identity.privateKey,
    parameters: {
      origin:      { type: "string", description: "IATA origin airport code" },
      destination: { type: "string", description: "IATA destination airport code" },
      date:        { type: "string", description: "Departure date in YYYY-MM-DD format" },
    },
    required: ["origin", "destination", "date"],
  },
  {
    endpoint:         "https://weather.example/aroha/v1",
    agentDID:         "did:aroha:weather-agent",
    capabilityId:     "get-weather",
    description:      "Get current weather for a city",
    callerDID:        identity.did,
    callerPrivateKey: identity.privateKey,
    parameters: {
      city: { type: "string", description: "City name" },
    },
  },
]);
// actions[0].name === "aroha_travel_agent_search_flights"
```

The actions are now available to any agent connected to this Composio workspace.

---

## arohaCapabilityToComposioAction()

Convert a single Aroha capability to a Composio action definition without registering it:

```typescript
import { arohaCapabilityToComposioAction } from "@aroha-sdk/composio-bridge";

const action = arohaCapabilityToComposioAction({
  endpoint:         "https://travel-agent.example/aroha/v1",
  agentDID:         "did:aroha:travel-agent",
  capabilityId:     "search-flights",
  description:      "Search for flights",
  callerDID:        identity.did,
  callerPrivateKey: identity.privateKey,
});

// action.name        → "aroha_travel_agent_search_flights"
// action.description → "Search for flights"
// action.execute     → async (params) => { data, successful, error? }
```

The action name is `aroha_<agent DID without the did:method: prefix>_<capability id>`, with every non-alphanumeric character replaced by `_`.

---

## buildComposioActionHandler()

Build a map of action name → `execute` function, for tool routers that use the same action format without Composio:

```typescript
import { buildComposioActionHandler } from "@aroha-sdk/composio-bridge";

const handlers = buildComposioActionHandler([
  {
    endpoint:         "https://travel-agent.example/aroha/v1",
    agentDID:         "did:aroha:travel-agent",
    capabilityId:     "book-flight",
    description:      "Book a flight",
    callerDID:        identity.did,
    callerPrivateKey: identity.privateKey,
  },
]);

const result = await handlers.get("aroha_travel_agent_book_flight")!({ flightId: "NZ90" });
// result: ComposioActionResult — { data, successful, error? }
```

---

## ArohaComposioOptions

```typescript
interface ArohaComposioOptions {
  /** HTTP endpoint of the remote Aroha agent. */
  endpoint: string;
  /** DID of the remote Aroha agent. */
  agentDID: string;
  /** Capability ID on the remote agent. */
  capabilityId: string;
  /** Human-readable description for the LLM. */
  description: string;
  /** JSON Schema properties for the capability's parameters. */
  parameters?: Record<string, ComposioActionParameter>;
  /** Required parameter names. */
  required?: string[];
  /** DID of the caller (this bridge). */
  callerDID: string;
  /** Ed25519 private key for signing envelopes. */
  callerPrivateKey: Uint8Array;
  /** ArohaClient to send with. Default: a new ArohaClient. */
  client?: ArohaClient;
}
```

---

## TrustClaw integration

TrustClaw uses Composio actions for external tool calls. After registering your Aroha capabilities, a TrustClaw agent can request them from its Composio toolset by their registered names (for example `aroha_travel_agent_search_flights`) and call them as if they were native tools — identity and signing happen in the bridge.

---

## How it works

1. `registerArohaCapabilities()` creates a Composio custom action for each capability.
2. When a Composio-connected agent calls the action, the bridge builds an `ArohaRequest` envelope signed with the caller's Ed25519 key.
3. The envelope is sent to the Aroha agent's endpoint.
4. The `ArohaResponse.body.result` is returned as the action result (`{ data, successful: true }`); an `ArohaError` or a transport failure is returned as `{ data: null, error, successful: false }`.
5. The bridge does not attach a spending mandate or run settlement. If the target agent requires a mandate it rejects the call — issue and forward mandates with `@aroha-sdk/credentials` in your own request path.

See also: [`@aroha-sdk/openclaw-bridge`](openclaw-bridge.md) · [`@aroha-sdk/hermes-bridge`](hermes-bridge.md)
