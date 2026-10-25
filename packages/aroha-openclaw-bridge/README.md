# @aroha-sdk/openclaw-bridge

Expose Aroha agent capabilities as OpenClaw skills, and OpenClaw skills as Aroha message handlers.

## Install

```bash
npm install @aroha-sdk/openclaw-bridge
```

## Quick example

```typescript
import { createArohaOpenClawPlugin, arohaCapabilityToOpenClawSkill } from "@aroha-sdk/openclaw-bridge";

const caller = {
  endpoint: "https://travel-agent.example/aroha/v1",
  agentDID: "did:aroha:travel-agent",
  callerDID: pluginDID,           // each skill call is a signed ArohaRequest from this DID
  callerPrivateKey: pluginPrivateKey,
};

// One plugin, several skills, each backed by a remote Aroha capability
export default createArohaOpenClawPlugin("aroha-travel", [
  { capabilityId: "search-flights", description: "Search flights between two airports", ...caller },
  { capabilityId: "book-hotel", description: "Book a hotel room", ...caller },
]);

// Or a single skill
const skill = arohaCapabilityToOpenClawSkill("search-flights", {
  ...caller,
  description: "Search flights",
  parameters: { origin: { type: "string", description: "IATA code", required: true } },
});
```

The bridge signs requests but does not attach a spending mandate; an agent that requires one
rejects the call. Mandate enforcement happens in the receiving Aroha agent.

## API

- `arohaCapabilityToOpenClawSkill(capabilityId, opts)` — an `OpenClawSkill` whose `execute()` calls the remote capability.
- `createArohaOpenClawPlugin(name, capabilities[])` — bundle several capabilities into an `OpenClawPlugin`.
- `openClawSkillToArohaHandler(skill, { agentDID, agentPrivateKey, keyId? })` — the other direction: serve an OpenClaw skill as an Aroha `MessageHandler`. Every reply is a signed envelope from `agentDID`; the function throws if the identity is missing.
- `ArohaSkillOptions` — `{ endpoint, agentDID, callerDID, callerPrivateKey, description, parameters?, client? }`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
