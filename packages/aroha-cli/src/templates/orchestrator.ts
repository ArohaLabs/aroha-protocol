// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { TOOLCHAIN, sdkDeps } from "./versions.js";

export interface OrchestratorOptions {
  name: string;
  port: number;
  apiPort: number;
}

export function orchestratorTemplate(opts: OrchestratorOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/orchestrate.ts", orchestrateTs(opts));
  files.set("src/intent.ts", intentTs());
  files.set("README.md", readme(opts));
  return files;
}

// ─── package.json ─────────────────────────────────────────────────────────────

function packageJson(opts: OrchestratorOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha orchestrator agent: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials", "@aroha-sdk/registry", "@aroha-sdk/orchestrator", "@aroha-sdk/preferences"),
        uuid: "^10.0.0",
      },
      devDependencies: {
        ...TOOLCHAIN,
        "@types/uuid": "^10.0.0",
      },
      engines: { node: ">=22.0.0" },
    },
    null,
    2
  );
}

// ─── tsconfig.json ────────────────────────────────────────────────────────────

function tsconfig(): string {
  return JSON.stringify(
    {
      compilerOptions: {
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        lib: ["ES2022"],
        strict: true,
        declaration: true,
        declarationMap: true,
        sourceMap: true,
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

// ─── src/server.ts ────────────────────────────────────────────────────────────

function serverTs(opts: OrchestratorOptions): string {
  const { name, port, apiPort } = opts;
  return `import { createServer } from "node:http";
import { generateDID, ArohaServer, ArohaClient } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { ArohaDiscovery, ArohaHttpRegistry } from "@aroha-sdk/registry";
import { ArohaIpfsClient } from "@aroha-sdk/registry/ipfs";
import { SagaEngine, AgentSelector } from "@aroha-sdk/orchestrator";
import { Orchestrator } from "./orchestrate.js";
import { decomposeIntent } from "./intent.js";

// ── Identity ──────────────────────────────────────────────────────────────────
const identity = await generateDID(
  "${name}",
  \`http://localhost:${port}/aroha/v1\`
);

const knownPublicKeys = new Map<string, Uint8Array>();
knownPublicKeys.set(identity.did, identity.publicKey);
const agentRoles = new Map<string, ArohaRole[]>();
agentRoles.set(identity.did, [ArohaRole.AgentOrchestrator]);

// ── Aroha infrastructure ───────────────────────────────────────────────────────
const arohaClient = new ArohaClient();

// TODO: set AROHA_REGISTRY_URL + API key. Left unset, the SDK uses its
// managed-registry default (AROHA_MANAGED_REGISTRY_URL).
const registry = new ArohaHttpRegistry({
  baseUrl: process.env.AROHA_REGISTRY_URL || undefined,
  apiKey: process.env.AROHA_API_KEY ?? "",
});

// TODO: set AROHA_IPFS_GATEWAY to your IPFS gateway (no default host is baked in).
const ipfs = new ArohaIpfsClient({ endpoint: process.env.AROHA_IPFS_GATEWAY ?? "" });
const discovery = new ArohaDiscovery(registry, ipfs);
const selector = new AgentSelector(arohaClient, identity.did, identity.privateKey);
const saga = new SagaEngine(arohaClient, identity.did, identity.privateKey);

const orchestrator = new Orchestrator(identity.did, identity.privateKey, discovery, selector, saga);

// ── Aroha server (receives inbound messages from providers) ────────────────────
const arohaServer = new ArohaServer({
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
  onMessage: async (_envelope, respond, _stream) => {
    // Orchestrators rarely need to handle inbound Aroha messages,
    // but you can respond to delegation or satisfaction signals here.
    respond(undefined as never);
  },
});

await arohaServer.start();

// ── REST API (receives task requests from users / UI) ─────────────────────────
const api = createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/task") {
    let body = "";
    for await (const chunk of req) body += chunk;
    const { intent } = JSON.parse(body) as { intent: string };

    try {
      const steps = await decomposeIntent(intent);
      const result = await orchestrator.execute(steps);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    }
    return;
  }
  res.writeHead(404);
  res.end();
});

api.listen(${apiPort}, () => {
  console.log(\`[${name}] Aroha endpoint : http://localhost:${port}/aroha/v1\`);
  console.log(\`[${name}] REST API      : http://localhost:${apiPort}/task\`);
  console.log(\`[${name}] DID           : \${identity.did}\`);
});
`;
}

// ─── src/orchestrate.ts ───────────────────────────────────────────────────────

function orchestrateTs(opts: OrchestratorOptions): string {
  return `import type { ArohaDiscovery, DiscoveredAgent } from "@aroha-sdk/registry";
import type { AgentSelector, SagaEngine } from "@aroha-sdk/orchestrator";

export interface TaskStep {
  capability: string;
  params: Record<string, unknown>;
  transactional: boolean;
}

export interface OrchestrationResult {
  success: boolean;
  steps: Array<{ capability: string; result?: unknown; error?: string }>;
}

export class Orchestrator {
  constructor(
    private readonly did: string,
    private readonly privateKey: Uint8Array,
    private readonly discovery: ArohaDiscovery,
    private readonly selector: AgentSelector,
    private readonly saga: SagaEngine
  ) {}

  async execute(steps: TaskStep[]): Promise<OrchestrationResult> {
    const results: OrchestrationResult["steps"] = [];
    const sagaParticipants: Array<{
      agentDID: string;
      agentEndpoint: string;
      capability: string;
      params: Record<string, unknown>;
      holdDurationMs: number;
    }> = [];

    for (const step of steps) {
      // 1. Discover agents with this capability
      const agents = await this.discovery.discover([step.capability]);
      if (!agents.length) {
        results.push({ capability: step.capability, error: "No agents found for capability" });
        continue;
      }

      // 2. Select the best agent (fan-out ArohaRequest, pick winner by score)
      const selection = await this.selector.select(step.capability, step.params, agents);
      if (!selection.winner) {
        results.push({ capability: step.capability, error: "Agent selection failed" });
        continue;
      }

      if (step.transactional) {
        // Queue for saga execution
        sagaParticipants.push({
          agentDID: selection.winner.agent.manifest.did,
          agentEndpoint: selection.winner.agent.endpoint,
          capability: step.capability,
          params: step.params,
          holdDurationMs: 300_000,
        });
        results.push({ capability: step.capability });
      } else {
        // Fire-and-forget query — already handled by AgentSelector.select()
        results.push({ capability: step.capability, result: selection.winner.response });
      }
    }

    // 3. Execute saga: reserve all → commit all (or compensate on failure)
    if (sagaParticipants.length) {
      const sagaResult = await this.saga.execute(sagaParticipants);
      if (!sagaResult.success) {
        return { success: false, steps: results };
      }
      // Merge saga results back
      for (const [idx, result] of Object.entries(sagaResult.results)) {
        results[Number(idx)].result = result;
      }
    }

    return { success: true, steps: results };
  }
}
`;
}

// ─── src/intent.ts ────────────────────────────────────────────────────────────

function intentTs(): string {
  return `import type { TaskStep } from "./orchestrate.js";

/**
 * Decompose a natural-language intent into structured task steps.
 *
 * Replace the stub below with an LLM call (Anthropic, OpenAI, etc.) or
 * a rule-based parser suited to your domain.
 *
 * Each step maps to a Aroha capability + params pair.
 * Set transactional=true for capabilities that need reserve/commit/cancel.
 */
export async function decomposeIntent(intent: string): Promise<TaskStep[]> {
  // TODO: replace with LLM-based or rule-based intent decomposition
  //
  // Example using Anthropic SDK:
  //   const anthropic = new Anthropic();
  //   const message = await anthropic.messages.create({
  //     model: "claude-sonnet-4-6",
  //     max_tokens: 1024,
  //     messages: [{ role: "user", content: DECOMPOSE_PROMPT + intent }],
  //   });
  //   return JSON.parse(message.content[0].text) as TaskStep[];

  // Stub: echo intent as a single non-transactional search step
  console.warn("[intent] Using stub decomposition — implement decomposeIntent() for production");
  return [
    {
      capability: "search",
      params: { query: intent },
      transactional: false,
    },
  ];
}
`;
}

// ─── README.md ────────────────────────────────────────────────────────────────

function readme(opts: OrchestratorOptions): string {
  const { name, port, apiPort } = opts;
  return `# ${name}

Aroha orchestrator agent scaffolded by \`@aroha-sdk/cli\`.

## Architecture

\`\`\`
User / UI
    │  POST /task  { intent: "..." }
    ▼
REST API (port ${apiPort})
    │
    ▼
decomposeIntent()  →  TaskStep[]
    │
    ▼
Orchestrator.execute()
    ├── ArohaDiscovery  →  find agents by capability
    ├── AgentSelector  →  fan-out ArohaRequest, pick winner
    └── SagaEngine     →  reserve → commit (or compensate)
\`\`\`

## Quick start

\`\`\`bash
npm install
npm run dev
\`\`\`

**Aroha endpoint:** http://localhost:${port}/aroha/v1
**REST API:** http://localhost:${apiPort}/task

### Send a task

\`\`\`bash
curl -X POST http://localhost:${apiPort}/task \\
  -H "Content-Type: application/json" \\
  -d '{"intent": "book a flight from London to Tokyo on June 1st"}'
\`\`\`

## Next steps

1. **Implement intent decomposition** — wire up an LLM in \`src/intent.ts\`
2. **Configure the registry** — set \`AROHA_REGISTRY_URL\` and \`AROHA_API_KEY\` env vars
3. **Persist the DID** — save \`identity.privateKey\` to a secrets manager
4. **Add preference learning** — integrate \`@aroha-sdk/preferences\` for user-aware agent selection

## Files

| File | Purpose |
|------|---------|
| \`src/server.ts\` | ArohaServer + REST API setup |
| \`src/orchestrate.ts\` | Discovery → selection → saga execution |
| \`src/intent.ts\` | Natural-language → TaskStep decomposition |
`;
}
