<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/hermes-bridge

Aroha ↔ Hermes Agent and ZeroClaw bridge. Both Hermes Agent (Nous Research) and ZeroClaw use MCP servers as their integration point for external tools. This bridge starts a stdio MCP server that proxies calls through to an Aroha agent, so your Hermes or ZeroClaw configuration can call any Aroha agent as a native tool. Run one bridge per Aroha agent.

```bash
npm install @aroha-sdk/hermes-bridge
```

---

## Hermes Agent (hermes.config.json)

Add an `mcpServers` entry pointing to the bridge binary (`aroha-mcp-server`, which `npx` runs):

```json
{
  "mcpServers": {
    "aroha-travel": {
      "command": "npx",
      "args": [
        "@aroha-sdk/hermes-bridge",
        "--endpoint",  "https://travel-agent.example.com",
        "--agent-did", "did:aroha:travel-agent"
      ]
    },
    "aroha-weather": {
      "command": "npx",
      "args": [
        "@aroha-sdk/hermes-bridge",
        "--endpoint",  "https://weather.example.com",
        "--agent-did", "did:aroha:weather-agent"
      ]
    }
  }
}
```

`--endpoint` and `--agent-did` are the only flags. Each capability the agent publishes becomes a tool Hermes can call natively. The bridge handles identity and Ed25519 signing underneath — Hermes never needs to know the protocol. It does not attach a spending mandate; an agent that requires one rejects the call.

---

## ZeroClaw (zeroclaw.toml)

```toml
[[mcp_servers]]
name    = "aroha-travel"
command = "npx @aroha-sdk/hermes-bridge --endpoint https://travel-agent.example.com --agent-did did:aroha:travel-agent"

[[mcp_servers]]
name    = "aroha-payment"
command = "npx @aroha-sdk/hermes-bridge --endpoint https://pay.example.com --agent-did did:aroha:payment-agent"
```

---

## Programmatic usage

If you need to embed the MCP server within a Node.js process rather than launching it via npx:

```typescript
import { createHermesMcpServer } from "@aroha-sdk/hermes-bridge";

// Fetches the agent's /.well-known/aroha-agent.json and maps each capability to an MCP tool
const server = await createHermesMcpServer({
  endpoint: "https://travel-agent.example.com",
  agentDID: "did:aroha:travel-agent",

  // Optional: your own identity for signed outbound envelopes (pass both).
  // An ephemeral identity is generated if omitted.
  bridgeDID:  myDID,
  privateKey: myPrivateKey,
});

console.error(`${server.tools.length} tools registered`);
await server.serve(process.stdin, process.stdout); // MCP JSON-RPC over stdio
```

The returned object also has `handleToolCall(name, args)` for calling a tool directly.

---

## HermesMcpServerOptions

```typescript
interface HermesMcpServerOptions {
  /** Aroha HTTP endpoint of the remote agent to expose. */
  endpoint: string;
  /** DID of the remote agent. */
  agentDID: string;
  /** Ed25519 private key for this bridge's identity. Ephemeral if omitted. */
  privateKey?: Uint8Array;
  /** DID for this bridge instance. Generated if omitted. */
  bridgeDID?: string;
}
```

---

## How it works

1. On startup the bridge fetches the agent's manifest (`/.well-known/aroha-agent.json`) to discover its capability list.
2. Each capability is registered as an MCP `Tool` with the same name, description, and parameter schema.
3. When Hermes/ZeroClaw calls a tool, the bridge builds an `ArohaRequest` envelope, signs it with Ed25519, and forwards it to the Aroha agent.
4. The `ArohaResponse` body is returned to Hermes/ZeroClaw as the tool result.

See also: [`@aroha-sdk/openclaw-bridge`](openclaw-bridge.md) · [`@aroha-sdk/mcp-bridge`](mcp-bridge.md)
