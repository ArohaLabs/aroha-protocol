<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Recipe: Converting an MCP Server to Aroha

Model Context Protocol (MCP) servers expose **tools** over JSON-RPC (stdio or HTTP).
Aroha extends MCP with Ed25519 identity, atomic sagas, and registry-based discovery.

The `@aroha-sdk/mcp-bridge` package handles bidirectional translation:
- `arohaAgentToMcpTools()` — exposes a Aroha agent's capabilities as MCP tools
- `mcpToolsToArohaCapabilities()` — registers an MCP server's tools as Aroha capabilities

---

## Option A — CLI sidecar (fastest, ~2 minutes)

```bash
aroha convert \
  --from mcp \
  --name my-tools-aroha \
  --port 3001 \
  --endpoint http://localhost:8080 \
  --out ./my-tools-aroha

cd my-tools-aroha
npm install && npm run dev
```

The wrapper fetches your MCP server's tool list from `GET /tools` at startup,
registers each tool as a Aroha capability, and proxies `ArohaRequest` messages to
the MCP tool call handler.

**Prerequisite:** Your MCP server must expose `GET /tools` (list of `McpToolDefinition`).
If it only supports stdio, add an HTTP shim (see below).

---

## Option B — Native conversion

### Step 1 — Expose MCP tools via HTTP

If your MCP server runs over stdio, wrap it with a minimal HTTP layer:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createServer } from "node:http";

const mcpServer = new McpServer({ name: "my-tools", version: "1.0.0" });

// Register your tools...
mcpServer.tool("web_search", "Search the web", { query: z.string() }, async ({ query }) => {
  const results = await search(query);
  return { content: [{ type: "text", text: JSON.stringify(results) }] };
});

// Expose tools list and tool call over HTTP
const httpServer = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/tools") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ tools: mcpServer.listTools() }));
    return;
  }
  if (req.method === "POST" && req.url === "/call") {
    let body = "";
    for await (const chunk of req) body += chunk;
    const { name, arguments: args } = JSON.parse(body);
    const result = await mcpServer.callTool(name, args);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  }
});

httpServer.listen(8080);
```

### Step 2 — Scaffold a Aroha provider

```bash
aroha init my-tools-agent --type provider --port 3001
cd my-tools-agent
npm install @aroha-sdk/mcp-bridge
```

### Step 3 — Wire up the bridge in `src/server.ts`

```typescript
import { ArohaClient } from "@aroha-sdk/core";
import { arohaAgentToMcpTools, mcpToolsToArohaCapabilities, type McpToolDefinition } from "@aroha-sdk/mcp-bridge";

const MCP_ENDPOINT = "http://localhost:8080";

// At startup: fetch tool list from MCP server
const res = await fetch(`${MCP_ENDPOINT}/tools`);
const { tools } = await res.json() as { tools: McpToolDefinition[] };

// Expose MCP tools as a Aroha DiscoveredAgent
const arohaCapabilities = mcpToolsToArohaCapabilities(tools);
// Use arohaCapabilities in your manifest

// Build the MCP call handler
const client = new ArohaClient();
const { handleToolCall } = arohaAgentToMcpTools(
  syntheticDiscoveredAgent,  // see template src/mcp-adapter.ts for full setup
  identity.did,
  identity.privateKey,
  client,
  crypto.randomUUID()
);
```

### Step 4 — Handle ArohaRequest in `src/handlers.ts`

```typescript
case "ArohaRequest": {
  const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };
  // MCP tool names use snake_case prefixed with "aroha_"
  const mcpToolName = `aroha_${capability.replace(/-/g, "_")}`;

  const mcpResult = await handleToolCall(mcpToolName, params);
  if (mcpResult.isError) {
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.UpstreamError, message: mcpResult.content[0]?.text ?? "MCP error", retryable: true },
      correlationId, privateKey);
  }

  const text = mcpResult.content[0]?.text ?? "{}";
  const result = (() => { try { return JSON.parse(text); } catch { return { text }; } })();
  return buildEnvelope("ArohaResponse", agentDID, from,
    { capability, result },
    correlationId, privateKey);
}
```

### Step 5 — Capability name mapping

MCP tool names are `snake_case`; Aroha capabilities are `kebab-case`.
The bridge handles this automatically:

```
MCP tool name:   "web_search"
Aroha capability: "web-search"
Bridge name:     "aroha_web_search"  (what bridge uses internally)
```

---

## MCP → Aroha capability manifest

```typescript
import { mcpToolsToArohaCapabilities } from "@aroha-sdk/mcp-bridge";

const arohaCapabilities = mcpToolsToArohaCapabilities(tools);
// Returns CapabilityDefinition[] ready to include in your Aroha manifest
// All capabilities get sagaRole: "none" (MCP tools are stateless)
```

To make a tool transactional, override `sagaRole` after conversion:

```typescript
const capabilities = mcpToolsToArohaCapabilities(tools).map((cap) =>
  cap.id === "book-item"
    ? { ...cap, sagaRole: "participant" as const, reserveCapabilityId: "book-item", cancelCapabilityId: "book-item" }
    : cap
);
```

---

## Use Aroha agents as MCP tools (reverse direction)

The bridge also works in reverse — expose discovered Aroha agents as MCP tools
so Claude Desktop or any MCP client can call them:

```typescript
import { arohaAgentToMcpTools } from "@aroha-sdk/mcp-bridge";
import { ArohaDiscovery } from "@aroha-sdk/registry";

const agents = await discovery.discover(["search-flights"]);
const { tools, handleToolCall } = arohaAgentToMcpTools(
  agents[0],
  orchestratorDID,
  orchestratorPrivateKey,
  arohaClient,
  crypto.randomUUID()
);

// Register tools with your MCP server
for (const tool of tools) {
  mcpServer.tool(tool.name, tool.description, tool.inputSchema.properties, async (args) => {
    return handleToolCall(tool.name, args);
  });
}
```

---

## See also

- [MCP bridge source](../../packages/aroha-mcp-bridge/src/index.ts)
- [General conversion recipe](./converting-existing-agents.md)
- [Aroha spec](../spec/aroha-1.0.md)
