<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/openclaw-bridge

Aroha ↔ OpenClaw bridge. OpenClaw is a local personal AI assistant that connects to Telegram, Discord, WhatsApp, and Slack, and extends via "skills" — named modules that register commands with descriptions.

This bridge works in both directions:

- **`arohaCapabilityToOpenClawSkill()`** — exposes a remote Aroha capability as an OpenClaw skill. Your assistant calls it by name and Aroha handles identity, signing, and settlement.
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

const identity = await generateDID("my-openclaw-caller");

export default {
  name: "aroha-travel",
  skills: [
    arohaCapabilityToOpenClawSkill("search-flights", {
      endpoint:         "http://travel-agent.aroha-labs.com",
      agentDID:         "did:aroha:travel-agent-prod",
      callerDID:        identity.did,
      callerPrivateKey: identity.privateKey,
      description:      "Search and book flights via the Aroha travel network",
    }),
    arohaCapabilityToOpenClawSkill("get-weather", {
      endpoint:         "http://weather.aroha-labs.com",
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

---

## createArohaOpenClawPlugin()

Helper that registers multiple Aroha capabilities as a single OpenClaw plugin from a capability manifest:

```typescript
import { createArohaOpenClawPlugin } from "@aroha-sdk/openclaw-bridge";

const plugin = await createArohaOpenClawPlugin({
  pluginName:       "aroha-suite",
  callerDID:        identity.did,
  callerPrivateKey: identity.privateKey,
  capabilities: [
    { endpoint: "http://travel.example.com", agentDID: "did:aroha:travel-agent", capabilityId: "search-flights" },
    { endpoint: "http://finance.example.com", agentDID: "did:aroha:finance-agent", capabilityId: "get-exchange-rate" },
    { endpoint: "http://weather.example.com", agentDID: "did:aroha:weather-agent", capabilityId: "get-weather" },
  ],
});

export default plugin;
```

---

## ArohaSkillOptions

```typescript
interface ArohaSkillOptions {
  /** URL of the Aroha agent. */
  endpoint: string;
  /** DID of the Aroha agent to call. */
  agentDID: string;
  /** Capability ID to invoke (matches the agent's registered capability). */
  capabilityId?: string;
  /** Caller DID for signing outbound envelopes. */
  callerDID: string;
  /** Ed25519 private key for signing. */
  callerPrivateKey: Uint8Array;
  /** Human-readable description shown in the assistant's help text. */
  description?: string;
  /** Timeout per call in ms. Default: 30_000 */
  timeoutMs?: number;
}
```

---

## How it works

OpenClaw skills are JavaScript objects with a `name` and `execute()` function. The bridge maps the `execute()` call to an `ArohaRequest` envelope, sends it signed to the target agent, and returns the `ArohaResponse.body.result` as the skill's output. The personal assistant never sees the Aroha protocol.

See also: [`@aroha-sdk/hermes-bridge`](hermes-bridge.md) · [`@aroha-sdk/composio-bridge`](composio-bridge.md)
