<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# MCP Quickstart — Wrap Your MCP Server

Turn an existing MCP server into an Aroha agent with one `wrapMcp()` call.

Your MCP tools keep working exactly as they do now. Aroha adds:

- A signed, verifiable identity (DID) for your server
- An endpoint that other Aroha agents can discover and call
- Optional per-call pricing, enforced through spending mandates (`requireMandate`)

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
    import { wrapMcp, registryPublicKeyResolver } from "@aroha-sdk/mcp-bridge";

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
      resolvePublicKey: registryPublicKeyResolver(),   // required: verifies who is calling
      handlers: {                                      // required: one entry per tool name
        "search-web": async (args) => ({ content: [{ type: "text", text: await mySearch(args) }] }),
      },
      // Pricing: price: 0.005 needs requireMandate: true plus expectedRoot or trustedRoots;
      // start() refuses a priced tool without them.
    });

    const { stop } = await agent.start();

    console.log(`Agent: ${agent.did}`);
    console.log(`Endpoint: ${agent.endpoint}`);
    // → Agent: did:aroha:web-search-agent
    // → Endpoint: http://localhost:3001
    ```

=== "From an MCP server instance"

    ```typescript
    import { wrapMcp, registryPublicKeyResolver } from "@aroha-sdk/mcp-bridge";
    import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

    // Your existing MCP server
    const server = new McpServer({ name: "my-tools", version: "1.0.0" });
    server.tool("analyze-sentiment", /* ... */);

    // Wrap it — pass a function that returns the tool list, and the tool implementations
    const agent = await wrapMcp(
      () => server.listTools(),
      {
        name: "sentiment-tools",
        resolvePublicKey: registryPublicKeyResolver(),
        handlers: { "analyze-sentiment": async (args) => analyzeSentiment(args) },
      }
    );
    await agent.start();
    ```

## What happens

When `agent.start()` is called:

1. An Ed25519 keypair is auto-generated (or use your own via `opts.privateKey`)
2. A DID is assigned: `did:aroha:<name>` (or use your own via `opts.did`)
3. An HTTP server starts on `opts.port` (default `3001`), bound to `127.0.0.1` unless you set `opts.host`
4. `start()` throws if any tool has no entry in `handlers`
5. Your tools are served at two endpoints:
   - `GET /.well-known/aroha-agent.json` — DID document + capability list
   - `POST /aroha/v1` — signed ArohaRequest envelope handler

## Test your wrapped agent

```bash
# Inspect the DID document
curl http://localhost:3001/.well-known/aroha-agent.json | jq .

# Check that the endpoint answers
npx @aroha-sdk/cli doctor http://localhost:3001
```

Calls must be signed `ArohaRequest` envelopes from a caller whose key `resolvePublicKey`
can find; use `@aroha-sdk/core` (`ArohaClient`, `buildEnvelope`) or the LangChain bridge.

## Register with a registry

`@aroha-sdk/cli` has no `publish` command. For local development, run the in-memory
sandbox registry (`npx @aroha-sdk/cli dev`, see [Sandbox →](sandbox.md)). To run your
own registry, see `apps/registry-server/DEPLOY.md` in the repository. A hosted sign-up
for the Aroha registry is not currently offered.

## Options reference

```typescript
interface WrapMcpOptions {
  name: string;           // agent display name → derives the DID
  handlers: Record<string, (args: Record<string, unknown>) => Promise<McpToolCallResult>>; // one per tool
  resolvePublicKey: PublicKeyResolver; // caller DID → public key (no default)
  requireMandate?: boolean;  // require a spending mandate; needs expectedRoot, trustedRoots or kelSource
  port?: number;          // HTTP port (default: 3001)
  host?: string;          // bind address (default: "127.0.0.1")
  price?: number;         // USD per call (default: free); needs requireMandate
  did?: string;           // override auto-generated DID
  privateKey?: Uint8Array; // override auto-generated Ed25519 key
}
// Full list: WrapMcpOptions in packages/aroha-mcp-bridge/src/index.ts
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

- [View the mcp-bridge API reference →](packages/mcp-bridge.md)
- [Convert existing recipes →](recipes/convert-from-mcp.md)
