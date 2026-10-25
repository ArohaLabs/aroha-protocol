# @aroha-sdk/hermes-bridge

MCP stdio bridge — expose an Aroha agent's capabilities as MCP tools to Hermes Agent, ZeroClaw,
or any MCP host that launches tool servers over stdio.

## Install

```bash
npm install @aroha-sdk/hermes-bridge
```

## Use from an MCP host

```json
{
  "mcpServers": {
    "aroha": {
      "command": "npx",
      "args": ["@aroha-sdk/hermes-bridge", "--endpoint", "http://localhost:3000", "--agent-did", "did:aroha:travel-agent"]
    }
  }
}
```

ZeroClaw:

```toml
[[mcp_servers]]
name = "aroha"
command = "npx @aroha-sdk/hermes-bridge --endpoint http://localhost:3000 --agent-did did:aroha:travel-agent"
```

## Programmatic use

```typescript
import { createHermesMcpServer } from "@aroha-sdk/hermes-bridge";

// Fetches the agent's /.well-known/aroha-agent.json and maps each capability to an MCP tool
const server = await createHermesMcpServer({
  endpoint: "http://localhost:3000",
  agentDID: "did:aroha:travel-agent",
  // privateKey + bridgeDID: optional; an ephemeral identity is generated if omitted
});

console.error(`${server.tools.length} tools registered`);
await server.serve(process.stdin, process.stdout); // MCP JSON-RPC over stdio
```

Every tool call is forwarded as an `ArohaRequest` signed by the bridge's identity. The bridge does
not attach a spending mandate; an agent that requires one rejects the call.

## API

- `createHermesMcpServer({ endpoint, agentDID, privateKey?, bridgeDID? })` — returns `{ tools, handleToolCall(name, args), serve(input, output) }`.
- `startFromCli()` — the `aroha-mcp-server` bin entry point (`--endpoint`, `--agent-did`).

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
