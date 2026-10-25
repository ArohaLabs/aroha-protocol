# @aroha-sdk/composio-bridge

Register Aroha agent capabilities as Composio custom actions, so Composio-connected agents
(TrustClaw, Claude + Composio, and others) can call Aroha agents with signed requests.

## Install

```bash
npm install @aroha-sdk/composio-bridge
```

## Quick example

```typescript
import { registerArohaCapabilities, arohaCapabilityToComposioAction } from "@aroha-sdk/composio-bridge";

// Register one or more Aroha capabilities with any client exposing addCustomAction()/createAction()
const actions = await registerArohaCapabilities(composio, [
  {
    endpoint: "https://flight-agent.example/aroha/v1",
    agentDID: "did:aroha:flight-agent",
    capabilityId: "search-flights",
    description: "Search available flights between two airports",
    parameters: {
      origin: { type: "string", description: "IATA code" },
      destination: { type: "string", description: "IATA code" },
    },
    required: ["origin", "destination"],
    callerDID: myDID,             // every call is a signed ArohaRequest from this DID
    callerPrivateKey: myPrivateKey,
  },
]);
// actions[0].name === "aroha_flight_agent_search_flights"

// Or build a single action without registering it
const action = arohaCapabilityToComposioAction({
  endpoint: "https://flight-agent.example/aroha/v1",
  agentDID: "did:aroha:flight-agent",
  capabilityId: "search-flights",
  description: "Search available flights",
  callerDID: myDID,
  callerPrivateKey: myPrivateKey,
});
const result = await action.execute({ origin: "AKL", destination: "SYD" }); // { data, successful, error? }
```

The bridge signs each request with the caller's key; it does not attach a spending mandate.
If the target agent requires one, it rejects the call — issue and forward mandates with
`@aroha-sdk/credentials` in your own request path.

## API

- `arohaCapabilityToComposioAction(opts)` — one Aroha capability → a Composio action (`name`, `description`, `parameters`, `execute`).
- `registerArohaCapabilities(composio, opts[])` — convert and register a batch; returns the actions.
- `buildComposioActionHandler(opts[])` — `Map<actionName, execute>` for routers that use the same action format without Composio.
- `ArohaComposioOptions` — `{ endpoint, agentDID, capabilityId, description, parameters?, required?, callerDID, callerPrivateKey, client? }`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
