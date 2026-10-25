<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# MCP Quickstart — Monetize Your MCP Server

Turn any existing MCP server into a paid Aroha agent with **one line of code**.

Your MCP tools keep working exactly as they do now. Aroha adds:

- A signed, verifiable identity (DID) for your server
- An endpoint that any Aroha orchestrator can discover and call
- Optional per-call pricing (charge other agents for access)

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Node.js | ≥ 22 |
| An existing MCP server | — |

## Install

```bash
npm install @aroha-sdk/mcp-bridge
```

## Wrap your server

=== "From a tool list"

    ```typescript
    import { wrapMcp } from "@aroha-sdk/mcp-bridge";

    const tools = [
      {
        name: "search-web",
        description: "Search the web and return top results",
        inputSchema: {
          type: "object" as const,
          properties: {
            query: { type: "string", description: "Search query" },
            limit: { type: "number", description: "Max results", default: 5 },
          },
          required: ["query"],
        },
      },
    ];

    const agent = await wrapMcp(tools, {
      name: "web-search-agent",
      price: 0.005,  // $0.005 per call — or omit for free
    });

    const { stop } = await agent.start();

    console.log(`Agent: ${agent.did}`);
    console.log(`Endpoint: ${agent.endpoint}`);
    // → Agent: did:aroha:web-search-agent
    // → Endpoint: http://localhost:3001
    ```

=== "From an MCP server instance"

    ```typescript
    import { wrapMcp } from "@aroha-sdk/mcp-bridge";
    import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

    // Your existing MCP server
    const server = new McpServer({ name: "my-tools", version: "1.0.0" });
    server.tool("analyze-sentiment", /* ... */);

    // Wrap it — pass a function that returns the tool list
    const agent = await wrapMcp(
      () => server.listTools(),
      { name: "sentiment-tools", price: 0.01 }
    );
    await agent.start();
    ```

## What happens

When `agent.start()` is called:

1. An Ed25519 keypair is auto-generated (or use your own via `opts.privateKey`)
2. A DID is assigned: `did:aroha:<name>` (or use your own via `opts.did`)
3. An HTTP server starts on `opts.port` (default `3001`)
4. Your tools are served at two endpoints:
   - `GET /.well-known/aroha-agent.json` — DID document + capability list
   - `POST /aroha/v1` — signed ArohaRequest envelope handler

## Test your wrapped agent

```bash
# Inspect the DID document
curl http://localhost:3001/.well-known/aroha-agent.json | jq .

# Call a capability via the CLI
npx @aroha-sdk/cli call http://localhost:3001 search-web '{"query":"AI agents 2026"}'
```

## Publish to the sandbox registry

Once running, register your agent so other Aroha clients can discover it:

```bash
npx @aroha-sdk/cli publish \
  --endpoint http://your-server.com \
  --did did:aroha:web-search-agent
```

See [Sandbox →](sandbox.md) for the full registration flow.

## Options reference

```typescript
interface WrapMcpOptions {
  name: string;           // agent display name → derives the DID
  port?: number;          // HTTP port (default: 3001)
  price?: number;         // USD per call (default: free)
  did?: string;           // override auto-generated DID
  privateKey?: Uint8Array; // override auto-generated Ed25519 key
}
```

## Production deployment

The `wrapMcp()` server is a plain Node.js HTTP server. Deploy it anywhere:

=== "Docker"

    ```dockerfile
    FROM node:22-alpine
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci
    COPY . .
    EXPOSE 3001
    CMD ["node", "dist/server.js"]
    ```

=== "Vercel"

    Not recommended for `wrapMcp()` — use Vercel only for REST APIs, not long-lived agent servers.
    For serverless deployment, use the `@aroha-sdk/micro` package instead.

=== "Fly.io"

    ```bash
    fly launch --name my-aroha-agent
    fly deploy
    ```

---

## Next steps

- [Add payments and reputation →](spec/aroha-1.0.md#commerce-layer)
- [View the mcp-bridge API reference →](packages/mcp-bridge.md)
- [Convert existing recipes →](recipes/convert-from-mcp.md)
