// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { TOOLCHAIN, sdkDeps } from "../versions.js";

export interface LangChainConverterOptions {
  name: string;
  port: number;
  language: "typescript" | "python";
}

export function langchainConverterTemplate(opts: LangChainConverterOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/langchain-adapter.ts", adapterTs(opts));
  files.set("src/tools.ts", toolsTs());
  files.set("MIGRATION.md", migrationMd(opts));
  return files;
}

function packageJson(opts: LangChainConverterOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha wrapper for LangChain agent: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials"),
        "@langchain/core": "^0.3.0",
        langchain: "^0.3.0",
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

function serverTs(opts: LangChainConverterOptions): string {
  const { name, port } = opts;
  return `import { generateDID, ArohaServer } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { handleMessage } from "./langchain-adapter.js";

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
    const reply = await handleMessage(envelope, identity.did, identity.privateKey);
    respond(reply);
  },
});

await server.start();
console.log(\`[${name}] Aroha→LangChain bridge at http://localhost:${port}/aroha/v1\`);
console.log(\`[${name}] DID: \${identity.did}\`);
`;
}

function adapterTs(_opts: LangChainConverterOptions): string {
  return `import { buildEnvelope, ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";
import { getTools, capabilityToToolName, toolNameToCapability } from "./tools.js";

// Build and cache the tool registry at startup
const tools = await getTools();
const toolsByCapability = new Map(
  tools.map((t) => [toolNameToCapability(t.name), t])
);

console.log(\`[langchain-adapter] Registered \${tools.length} tools as Aroha capabilities:\`);
for (const t of tools) console.log(\`  - \${toolNameToCapability(t.name)}\`);

/**
 * Maps Aroha messages to LangChain tool calls.
 *
 * Each LangChain Tool becomes a Aroha capability:
 *   tool.name  →  capability ID  (e.g. "web_search" → "web-search")
 *   tool.description → capability description
 *   tool.schema      → inputSchema
 *
 * Only ArohaRequest is handled (LangChain tools are stateless — no saga).
 * For transactional tools, implement reserve/commit/cancel manually.
 */
export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { from, correlationId } = envelope;

  if (envelope.type !== "ArohaRequest") {
    return buildEnvelope("ArohaError", agentDID, from,
      {
        code: ArohaErrorCode.UnknownCapability,
        message: \`LangChain adapter only handles ArohaRequest (received \${envelope.type}). \" +
          "LangChain tools are stateless — implement saga handlers manually if needed.\`,
        retryable: false,
      },
      correlationId, privateKey);
  }

  const { capability, params } = envelope.body as {
    capability: string;
    params: Record<string, unknown>;
  };

  const tool = toolsByCapability.get(capability);
  if (!tool) {
    return buildEnvelope("ArohaError", agentDID, from,
      {
        code: ArohaErrorCode.UnknownCapability,
        message: \`No LangChain tool found for capability "\${capability}". \" +
          \`Available: \${[...toolsByCapability.keys()].join(", ")}\`,
        retryable: false,
      },
      correlationId, privateKey);
  }

  let result: unknown;
  try {
    // LangChain tools accept a string or object input
    const input = Object.keys(params).length === 1 && "query" in params
      ? (params.query as string)
      : params;
    result = await tool.invoke(input as Parameters<typeof tool.invoke>[0]);
  } catch (err) {
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.ServiceUnavailable, message: String(err), retryable: true },
      correlationId, privateKey);
  }

  return buildEnvelope("ArohaResponse", agentDID, from,
    { capability, result: typeof result === "string" ? { text: result } : result },
    correlationId, privateKey);
}
`;
}

function toolsTs(): string {
  return `import type { StructuredToolInterface } from "@langchain/core/tools";

/**
 * Register your LangChain tools here.
 * Each tool is automatically exposed as a Aroha capability.
 *
 * Tool name convention:
 *   LangChain: snake_case  (e.g. "web_search")
 *   Aroha:      kebab-case  (e.g. "web-search")
 *
 * The adapter handles this conversion automatically via
 * capabilityToToolName() / toolNameToCapability() below.
 */
export async function getTools(): Promise<StructuredToolInterface[]> {
  // TODO: import and register your LangChain tools
  //
  // Example:
  //   import { TavilySearchResults } from "@langchain/community/tools/tavily_search";
  //   import { Calculator } from "@langchain/community/tools/calculator";
  //   return [
  //     new TavilySearchResults({ maxResults: 5 }),
  //     new Calculator(),
  //   ];
  //
  // LangChain tool docs: https://js.langchain.com/docs/how_to/tools_builtin

  console.warn("[tools] No LangChain tools registered — implement getTools() in src/tools.ts");
  return [];
}

/** Convert a Aroha capability ID (kebab-case) to a LangChain tool name (snake_case). */
export function capabilityToToolName(capability: string): string {
  return capability.replace(/-/g, "_");
}

/** Convert a LangChain tool name (snake_case) to a Aroha capability ID (kebab-case). */
export function toolNameToCapability(toolName: string): string {
  return toolName.replace(/_/g, "-");
}
`;
}

function migrationMd(opts: LangChainConverterOptions): string {
  const { name, port } = opts;
  return `# Migration: LangChain → Aroha

This project exposes your LangChain tools as Aroha capabilities.

## How it works

Each LangChain \`Tool\` becomes a Aroha capability:

\`\`\`
LangChain Tool                   Aroha Capability
──────────────────────────────   ─────────────────────────────
tool.name  "web_search"      →   capability ID "web-search"
tool.description             →   capability description
tool.schema                  →   inputSchema
tool.invoke(input)           →   ArohaRequest handler
\`\`\`

## Quick start

1. **Register your tools** — edit \`src/tools.ts\`:

\`\`\`typescript
import { TavilySearchResults } from "@langchain/community/tools/tavily_search";
import { Calculator } from "@langchain/community/tools/calculator";

export async function getTools() {
  return [
    new TavilySearchResults({ maxResults: 5 }),
    new Calculator(),
  ];
}
\`\`\`

2. **Install and run**:

\`\`\`bash
npm install
npm run dev
# Agent starts at http://localhost:${port}/aroha/v1
# Capabilities: web-search, calculator
\`\`\`

3. **Test**:

\`\`\`bash
# From another terminal, send a ArohaRequest using ArohaClient:
node -e "
import('@aroha-sdk/core').then(async ({ ArohaClient, buildEnvelope, generateDID }) => {
  const me = await generateDID('test', 'http://localhost:9999/aroha/v1');
  const req = await buildEnvelope('ArohaRequest', me.did, 'did:aroha:${name}',
    { capability: 'web-search', params: { query: 'Aroha protocol' } },
    crypto.randomUUID(), me.privateKey);
  const client = new ArohaClient();
  const reply = await client.send('http://localhost:${port}/aroha/v1', req);
  console.log(reply.body);
});
"
\`\`\`

## Saga support

LangChain tools are stateless — they don't natively support reserve/commit/cancel.
The adapter returns a \`ArohaError\` for saga messages.

To add saga support for a tool, implement the handlers directly in \`src/langchain-adapter.ts\`:
add cases for \`ArohaReserve\`, \`ArohaCommit\`, and \`ArohaCancel\` and cache results
between reserve and commit.

## Python LangChain

If your agent is in Python, use the Aroha Python SDK (\`sdks/python/\`) to wrap
your LangChain tools. See [the full recipe](../../docs/recipes/convert-from-langchain.md).
`;
}
