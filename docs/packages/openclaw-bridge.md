<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/openclaw-bridge

Aroha ↔ OpenClaw bridge. OpenClaw is a local personal AI assistant that connects to Telegram, Discord, WhatsApp, and Slack, and extends via "skills" — named modules that register commands with descriptions.

This bridge works in both directions:

- **`arohaCapabilityToOpenClawSkill()`** — exposes a remote Aroha capability as an OpenClaw skill. Your assistant calls it by name and the bridge handles identity and signing. It does not attach a spending mandate; an agent that requires one rejects the call.
- **`openClawSkillToArohaHandler()`** — wraps an existing OpenClaw skill as an Aroha message handler so other Aroha agents can call it via signed envelopes.

```bash
npm install @aroha-sdk/openclaw-bridge
```

---

## Aroha capability → OpenClaw skill

Create a file in your OpenClaw plugins directory:

```javascript
// openclaw-plugins/aroha-travel.mjs
import { arohaCapabilityToOpenClawSkill } from "@aroha-sdk/openclaw-bridge";
import { generateDID }                    from "@aroha-sdk/core";

const identity = await generateDID("my-openclaw-caller", "https://caller.example/aroha/v1");

export default {
  name: "aroha-travel",
  skills: [
    arohaCapabilityToOpenClawSkill("search-flights", {
      endpoint:         "https://travel-agent.example/aroha/v1",
      agentDID:         "did:aroha:travel-agent-prod",
      callerDID:        identity.did,
      callerPrivateKey: identity.privateKey,
      description:      "Search and book flights via the Aroha travel network",
    }),
    arohaCapabilityToOpenClawSkill("get-weather", {
      endpoint:         "https://weather.example/aroha/v1",
      agentDID:         "did:aroha:weather-agent",
      callerDID:        identity.did,
      callerPrivateKey: identity.privateKey,
      description:      "Get current weather and forecast for any city",
    }),
  ],
};
```

Your assistant can now call `search-flights` or `get-weather` as native commands.

---

## OpenClaw skill → Aroha handler

Expose an existing OpenClaw skill to other Aroha agents:

```typescript
import { openClawSkillToArohaHandler } from "@aroha-sdk/openclaw-bridge";
import { ArohaServer }                 from "@aroha-sdk/core";

const myOpenClawSkill = {
  name: "translate",
  description: "Translate text into another language",
  execute: async ({ text, targetLang }) => translateText(text, targetLang),
};

const server = new ArohaServer({
  agentDID:    myDID,
  didDocument: identity.document,
  port:        3001,
  onMessage:   openClawSkillToArohaHandler(myOpenClawSkill, {
    agentDID:        myDID,
    agentPrivateKey: identity.privateKey, // replies are signed with this key
  }),
});

await server.start();
```

`openClawSkillToArohaHandler` throws if `agentDID` or a 32-byte `agentPrivateKey` is missing. `keyId` (default `${agentDID}#key-1`) sets the verification method of the reply proof.

---

## createArohaOpenClawPlugin()

Helper that bundles several Aroha capabilities into a single OpenClaw plugin:

```typescript
import { createArohaOpenClawPlugin } from "@aroha-sdk/openclaw-bridge";

const caller = { callerDID: identity.did, callerPrivateKey: identity.privateKey };

const plugin = createArohaOpenClawPlugin("aroha-suite", [
  { capabilityId: "search-flights",    description: "Search flights",       endpoint: "https://travel.example.com/aroha/v1",  agentDID: "did:aroha:travel-agent",  ...caller },
  { capabilityId: "get-exchange-rate", description: "Get an exchange rate", endpoint: "https://finance.example.com/aroha/v1", agentDID: "did:aroha:finance-agent", ...caller },
  { capabilityId: "get-weather",       description: "Get the weather",      endpoint: "https://weather.example.com/aroha/v1", agentDID: "did:aroha:weather-agent", ...caller },
]);

export default plugin;
```

---

## ArohaSkillOptions

```typescript
interface ArohaSkillOptions {
  /** HTTP endpoint of the remote Aroha agent. */
  endpoint: string;
  /** DID of the remote Aroha agent. */
  agentDID: string;
  /** DID of this OpenClaw plugin acting as a caller. */
  callerDID: string;
  /** Ed25519 private key for signing envelopes. */
  callerPrivateKey: Uint8Array;
  /** Human-readable description used by the LLM to decide when to call this skill. */
  description: string;
  /** JSON Schema properties for the skill's parameters. */
  parameters?: OpenClawSkill["parameters"];
  /** ArohaClient to send with. Default: a new ArohaClient. */
  client?: ArohaClient;
}
```

---

## How it works

OpenClaw skills are JavaScript objects with a `name` and `execute()` function. The bridge maps the `execute()` call to an `ArohaRequest` envelope, sends it signed to the target agent, and returns the `ArohaResponse.body.result` as the skill's output. The personal assistant never sees the Aroha protocol.

See also: [`@aroha-sdk/hermes-bridge`](hermes-bridge.md) · [`@aroha-sdk/composio-bridge`](composio-bridge.md)
