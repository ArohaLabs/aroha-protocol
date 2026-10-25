<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/mcp-bridge

Protocol adapter between the Model Context Protocol (MCP) and Aroha.
Works in both directions.

```bash
npm install @aroha-sdk/mcp-bridge
```

---

## arohaAgentToMcpTools

**Aroha → MCP:** Expose a discovered Aroha agent's capabilities as MCP tool definitions.
Claude Desktop or any MCP client can call them as normal tools.

```typescript
import { arohaAgentToMcpTools } from "@aroha-sdk/mcp-bridge";

const { tools, handleToolCall } = arohaAgentToMcpTools(
  discoveredAgent,          // DiscoveredAgent from ArohaDiscovery
  orchestratorDID,          // string
  orchestratorPrivateKey,   // Uint8Array
  arohaClient,               // ArohaClient
  correlationId             // string
);

// Register tools with your MCP server
for (const tool of tools) {
  mcpServer.tool(tool.name, tool.description, tool.inputSchema, async (args) =>
    handleToolCall(tool.name, args)
  );
}
```

Each tool name follows the pattern `aroha_<capability_id_snake_case>`:

```
Aroha capability: "search-flights"
MCP tool name:   "aroha_search_flights"
```

---

## mcpToolsToArohaCapabilities

**MCP → Aroha:** Convert MCP tool definitions to Aroha capability definitions
for inclusion in a capability manifest.

```typescript
import { mcpToolsToArohaCapabilities } from "@aroha-sdk/mcp-bridge";

const capabilities = mcpToolsToArohaCapabilities(mcpTools);
// Returns CapabilityDefinition[] — all with sagaRole: "none"
// Override sagaRole for transactional tools:
const capped = capabilities.map((c) =>
  c.id === "book-flight"
    ? { ...c, sagaRole: "participant" as const, reserveCapabilityId: "book-flight", cancelCapabilityId: "book-flight" }
    : c
);
```

---

## McpToolDefinition

```typescript
interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  _aroha?: {
    agentDID: string;
    capabilityId: string;
    sagaRole: "none" | "participant";
  };
}
```

---

## Full conversion guide

See [Converting from MCP →](../recipes/convert-from-mcp.md) for:

- Adding an HTTP `/tools` shim to stdio MCP servers
- Generating a Aroha wrapper with `aroha convert --from mcp`
- Using Aroha agents as MCP tools (reverse direction)
