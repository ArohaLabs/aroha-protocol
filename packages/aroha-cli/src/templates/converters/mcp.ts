// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { TOOLCHAIN, sdkDeps } from "../versions.js";

export interface McpConverterOptions {
  name: string;
  port: number;
  mcpEndpoint: string;
}

export function mcpConverterTemplate(opts: McpConverterOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/mcp-adapter.ts", adapterTs(opts));
  files.set("MIGRATION.md", migrationMd(opts));
  return files;
}

function packageJson(opts: McpConverterOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha wrapper for MCP server: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials", "@aroha-sdk/mcp-bridge", "@aroha-sdk/registry"),
      },
      devDependencies: {
        ...TOOLCHAIN,
      },
      engines: { node: ">=22.0.0" },
    },
    null,
    2
  );
}

function tsconfig(): string {
  return JSON.stringify(
    {
      compilerOptions: {
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        lib: ["ES2022"],
        strict: true,
        outDir: "./dist",
        rootDir: "./src",
      },
      include: ["src/**/*"],
      exclude: ["dist", "node_modules"],
    },
    null,
    2
  );
}

function serverTs(opts: McpConverterOptions): string {
  const { name, port } = opts;
  return `import { generateDID, ArohaServer, ArohaClient } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { buildMcpHandler } from "./mcp-adapter.js";

const identity = await generateDID(
  "${name}",
  \`http://localhost:${port}/aroha/v1\`
);

const knownPublicKeys = new Map<string, Uint8Array>();
knownPublicKeys.set(identity.did, identity.publicKey);
const agentRoles = new Map<string, ArohaRole[]>();
agentRoles.set(identity.did, [ArohaRole.AgentProvider]);

export function registerPeer(did: string, publicKey: Uint8Array): void {
  knownPublicKeys.set(did, publicKey);
  agentRoles.set(did, [ArohaRole.AgentOrchestrator]);
}

// Build the MCP adapter (fetches tool list from MCP server at startup)
const { handleMessage } = await buildMcpHandler(
  identity.did,
  identity.privateKey,
  new ArohaClient()
);

const server = new ArohaServer({
  agentDID: identity.did,
  didDocument: identity.document,
  port: ${port},
  // Loopback by default (core binds 127.0.0.1). Set HOST=0.0.0.0 to accept
  // connections from other machines — containers, LAN peers.
  host: process.env.HOST ?? "127.0.0.1",
  resolvePublicKey: async (did) => knownPublicKeys.get(did) ?? null,
  middleware: [
    createRbacMiddleware({
      resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
      resolveIssuerPublicKey: async (did) => knownPublicKeys.get(did) ?? null,
    }),
  ],
  onMessage: async (envelope, respond, _stream) => {
    const reply = await handleMessage(envelope);
    respond(reply);
  },
});

await server.start();
console.log(\`[${name}] Aroha→MCP bridge at http://localhost:${port}/aroha/v1\`);
console.log(\`[${name}] MCP server: ${opts.mcpEndpoint}\`);
console.log(\`[${name}] DID: \${identity.did}\`);
`;
}

function adapterTs(opts: McpConverterOptions): string {
  return `import {
  buildEnvelope,
  ArohaErrorCode,
  ArohaClient,
  type ArohaEnvelope,
} from "@aroha-sdk/core";
import {
  mcpToolsToArohaCapabilities,
  arohaAgentToMcpTools,
  type McpToolDefinition,
} from "@aroha-sdk/mcp-bridge";
import type { DiscoveredAgent } from "@aroha-sdk/registry";

const MCP_ENDPOINT = process.env.MCP_ENDPOINT ?? "${opts.mcpEndpoint}";

/**
 * Fetches the MCP tool list at startup, converts them to Aroha capabilities,
 * and returns a message handler that proxies Aroha calls to the MCP server.
 */
export async function buildMcpHandler(
  agentDID: string,
  privateKey: Uint8Array,
  client: ArohaClient
): Promise<{ handleMessage: (env: ArohaEnvelope) => Promise<ArohaEnvelope> }> {
  // 1. Fetch MCP tool definitions from the upstream server
  const tools = await fetchMcpTools();
  console.log(\`[mcp-adapter] Loaded \${tools.length} MCP tools: \${tools.map((t) => t.name).join(", ")}\`);

  // 2. Build a synthetic DiscoveredAgent for arohaAgentToMcpTools
  const arohaCapabilities = mcpToolsToArohaCapabilities(tools);
  const syntheticAgent: DiscoveredAgent = {
    record: { didHash: agentDID, active: true } as never,
    manifest: {
      aroha: "1.0",
      did: agentDID,
      name: "mcp-upstream",
      version: "1.0.0",
      endpoint: MCP_ENDPOINT,
      protocols: ["aroha/1.0"],
      capabilities: arohaCapabilities,
      signature: "",
    },
    endpoint: MCP_ENDPOINT,
  };

  const correlationId = crypto.randomUUID();
  const { handleToolCall } = arohaAgentToMcpTools(
    syntheticAgent,
    agentDID,
    privateKey,
    client,
    correlationId
  );

  // 3. Build the Aroha message handler
  async function handleMessage(envelope: ArohaEnvelope): Promise<ArohaEnvelope> {
    const { from, correlationId: cid } = envelope;

    if (envelope.type !== "ArohaRequest") {
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.UnknownCapability, message: \`MCP bridge only handles ArohaRequest (got \${envelope.type})\`, retryable: false },
        cid, privateKey);
    }

    const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };
    const mcpToolName = \`aroha_\${capability.replace(/-/g, "_")}\`;

    const mcpResult = await handleToolCall(mcpToolName, params);
    if (mcpResult.isError) {
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.ServiceUnavailable, message: mcpResult.content[0]?.text ?? "MCP error", retryable: true },
        cid, privateKey);
    }

    const resultText = mcpResult.content[0]?.text ?? "{}";
    const result = (() => { try { return JSON.parse(resultText); } catch { return { text: resultText }; } })();

    return buildEnvelope("ArohaResponse", agentDID, from,
      { capability, result },
      cid, privateKey);
  }

  return { handleMessage };
}

/** Fetch tool definitions from the MCP server's /tools endpoint. */
async function fetchMcpTools(): Promise<McpToolDefinition[]> {
  const res = await fetch(\`\${MCP_ENDPOINT}/tools\`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(\`MCP server returned HTTP \${res.status} on /tools\`);
  const json = await res.json() as { tools: McpToolDefinition[] };
  return json.tools ?? [];
}
`;
}

function migrationMd(opts: McpConverterOptions): string {
  const { name, port, mcpEndpoint } = opts;
  return `# Migration: MCP → Aroha

This project exposes your MCP server (\`${mcpEndpoint}\`) as a Aroha-compliant agent
using the \`@aroha-sdk/mcp-bridge\` adapter.

## Protocol differences

| MCP | Aroha |
|-----|------|
| Tool-call JSON-RPC over stdio or HTTP | Signed JSON-LD envelopes over HTTPS |
| No cryptographic identity | Ed25519 DID |
| Stateless tool calls | Saga support (reserve/commit/cancel) |
| No capability registry | Publishable to Aroha registry |

## How it works

At startup, the bridge fetches your MCP server's tool list from \`${mcpEndpoint}/tools\`
and registers each tool as a Aroha capability. Inbound \`ArohaRequest\` messages
are mapped to MCP tool calls via \`arohaAgentToMcpTools()\`.

\`\`\`
Aroha orchestrator
    │  ArohaRequest { capability: "my-tool", params }
    ▼
Aroha→MCP bridge (port ${port})
    │  mcpToolName = "aroha_my_tool"
    │  handleToolCall("aroha_my_tool", params)
    ▼
Your MCP server (${mcpEndpoint})
    │  Tool result
    ▼
Aroha→MCP bridge
    │  buildEnvelope("ArohaResponse", ...)
    ▼
Aroha orchestrator
\`\`\`

## Running

\`\`\`bash
# Start your MCP server first (must expose GET /tools)
# Then:
npm install && npm run dev

# Override MCP endpoint:
MCP_ENDPOINT=http://my-mcp-host:8080 npm run dev
\`\`\`

## Expose your MCP server via \`/tools\`

If your MCP server doesn't expose HTTP \`GET /tools\`, add a shim:

\`\`\`typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
// ... your server setup ...
app.get("/tools", (_req, res) => {
  res.json({ tools: server.listTools() });
});
\`\`\`

## Full conversion (native Aroha)

For saga support and higher trust levels, convert the MCP server to handle
Aroha natively. See [the full recipe](../../docs/recipes/convert-from-mcp.md).
`;
}
