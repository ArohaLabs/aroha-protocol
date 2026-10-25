<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/hermes-bridge

Aroha ↔ Hermes Agent and ZeroClaw bridge. Both Hermes Agent (Nous Research) and ZeroClaw use MCP servers as their integration point for external tools. This bridge starts a stdio MCP server that proxies calls through to one or more Aroha agents, so your Hermes or ZeroClaw configuration can call any Aroha agent as a native tool.

```bash
npm install @aroha-sdk/hermes-bridge
```

---

## Hermes Agent (hermes.config.json)

Add an `mcpServers` entry pointing to the bridge binary:

```json
{
  "mcpServers": {
    "aroha-travel": {
      "command": "npx",
      "args": [
        "@aroha-sdk/hermes-bridge",
        "--endpoint",  "http://travel-agent.example.com",
        "--agent-did", "did:aroha:travel-agent",
        "--capabilities", "search-flights,book-flight,cancel-flight"
      ]
    },
    "aroha-weather": {
      "command": "npx",
      "args": [
        "@aroha-sdk/hermes-bridge",
        "--endpoint",  "http://weather.example.com",
        "--agent-did", "did:aroha:weather-agent"
      ]
    }
  }
}
```

Each registered capability becomes a tool Hermes can call natively. Aroha handles identity, Ed25519 signing, and settlement underneath — Hermes never needs to know the protocol.

---

## ZeroClaw (zeroclaw.toml)

```toml
[[mcp_servers]]
name    = "aroha-travel"
command = "npx @aroha-sdk/hermes-bridge --endpoint http://travel-agent.example.com --agent-did did:aroha:travel-agent"

[[mcp_servers]]
name    = "aroha-payment"
command = "npx @aroha-sdk/hermes-bridge --endpoint http://pay.example.com --agent-did did:aroha:payment-agent"
```

---

## Programmatic usage

If you need to embed the MCP server within a Node.js process rather than launching it via npx:

```typescript
import { createHermesMcpServer } from "@aroha-sdk/hermes-bridge";

const server = await createHermesMcpServer({
  endpoint:     "http://travel-agent.example.com",
  agentDID:     "did:aroha:travel-agent",
  capabilities: ["search-flights", "book-flight"],

  // Optional: provide your own DID for signed outbound envelopes
  callerDID:        myDID,
  callerPrivateKey: myPrivateKey,
});

// server is a stdio MCP server — attach to your stdio transport
await server.connect(stdioTransport);
```

---

## HermesMcpServerOptions

```typescript
interface HermesMcpServerOptions {
  /** Base URL of the Aroha agent. */
  endpoint: string;
  /** DID of the Aroha agent to call. */
  agentDID: string;
  /**
   * Capabilities to expose as MCP tools.
   * If omitted, the bridge fetches them from the agent's DID document.
   */
  capabilities?: string[];
  /** Your caller DID. Auto-generated if omitted (ephemeral). */
  callerDID?: string;
  /** Ed25519 private key for signing outbound envelopes. */
  callerPrivateKey?: Uint8Array;
  /** Timeout per call in ms. Default: 30_000 */
  timeoutMs?: number;
}
```

---

## How it works

1. On startup the bridge reads the agent's DID document to discover its capability list.
2. Each capability is registered as an MCP `Tool` with the same name, description, and parameter schema.
3. When Hermes/ZeroClaw calls a tool, the bridge builds an `ArohaRequest` envelope, signs it with Ed25519, and forwards it to the Aroha agent.
4. The `ArohaResponse` body is returned to Hermes/ZeroClaw as the tool result.
5. Settlement (if enabled on the agent) is negotiated transparently via `ArohaReserve` / `ArohaCommitAck`.

See also: [`@aroha-sdk/openclaw-bridge`](openclaw-bridge.md) · [`@aroha-sdk/mcp-bridge`](mcp-bridge.md)
