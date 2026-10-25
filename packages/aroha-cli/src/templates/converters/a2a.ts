// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { TOOLCHAIN, sdkDeps } from "../versions.js";

export interface A2AConverterOptions {
  name: string;
  port: number;
  a2aEndpoint: string;
}

export function a2aConverterTemplate(opts: A2AConverterOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/a2a-adapter.ts", adapterTs(opts));
  files.set("MIGRATION.md", migrationMd(opts));
  return files;
}

function packageJson(opts: A2AConverterOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha wrapper for A2A agent: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials", "@aroha-sdk/a2a-bridge"),
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

function serverTs(opts: A2AConverterOptions): string {
  const { name, port } = opts;
  return `import { generateDID, ArohaServer } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { handleMessage } from "./a2a-adapter.js";

// ── Identity ──────────────────────────────────────────────────────────────────
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

// ── Aroha server ───────────────────────────────────────────────────────────────
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
console.log(\`[${name}] Aroha→A2A bridge live at http://localhost:${port}/aroha/v1\`);
console.log(\`[${name}] Proxying to A2A agent at ${opts.a2aEndpoint}\`);
console.log(\`[${name}] DID: \${identity.did}\`);
`;
}

function adapterTs(opts: A2AConverterOptions): string {
  return `import { buildEnvelope, ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";
import { a2aToAroha, arohaToA2a, sendMessage, type A2AMessage } from "@aroha-sdk/a2a-bridge";

const A2A_ENDPOINT = process.env.A2A_ENDPOINT ?? "${opts.a2aEndpoint}";

/**
 * Receives a Aroha envelope from an orchestrator, converts it to an A2A message,
 * forwards it to the upstream A2A agent, and converts the A2A response back to Aroha.
 *
 * Security note: The A2A bridge operates at Trust Level 1. For higher trust levels,
 * upgrade the upstream agent to speak Aroha natively.
 */
export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { from, correlationId } = envelope;

  // Only proxy request-type messages; pass through others
  const proxyTypes = ["ArohaRequest", "ArohaReserve", "ArohaCommit", "ArohaCancel"] as const;
  if (!proxyTypes.includes(envelope.type as typeof proxyTypes[number])) {
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.UnknownCapability, message: \`A2A bridge does not handle \${envelope.type}\`, retryable: false },
      correlationId, privateKey);
  }

  // ── Aroha → A2A ──────────────────────────────────────────────────────────────
  // Any Aroha mandate the caller sent (body.credentialToken) is forwarded in the
  // A2A message metadata under "aroha.mandate".
  const mandateToken = (envelope.body as { credentialToken?: unknown }).credentialToken;
  const a2aMessage = arohaToA2a(envelope, {
    mandateToken: typeof mandateToken === "string" ? mandateToken : undefined,
  });

  // ── Forward to upstream A2A agent (JSON-RPC SendMessage, A2A 1.0) ───────────
  // A2A_ENDPOINT is the JSON-RPC url from the agent's Agent Card.
  let a2aResponse: A2AMessage;
  try {
    const result = await sendMessage(A2A_ENDPOINT, a2aMessage);
    if (result.kind === "message") {
      a2aResponse = result.message;
    } else {
      // A task: use its status message, else its first artifact, as the reply.
      const { task } = result;
      a2aResponse = task.status.message ?? {
        messageId: task.id,
        taskId: task.id,
        role: "ROLE_AGENT",
        parts: task.artifacts?.[0]?.parts ?? [{ data: { taskId: task.id, state: task.status.state } }],
      };
    }
  } catch (err) {
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.ServiceUnavailable, message: \`A2A upstream error: \${err}\`, retryable: true },
      correlationId, privateKey);
  }

  // ── A2A → Aroha ──────────────────────────────────────────────────────────────
  // Convert the A2A response back to a Aroha envelope.
  // The bridge infers the Aroha type from A2A role (agent=ArohaResponse).
  const arohaResponse = a2aToAroha(a2aResponse, agentDID, from);

  // Re-sign with this agent's key (the bridge produces an unsigned envelope)
  return buildEnvelope(
    arohaResponse.type,
    agentDID,
    from,
    arohaResponse.body,
    correlationId,
    privateKey
  );
}
`;
}

function migrationMd(opts: A2AConverterOptions): string {
  const { name, port, a2aEndpoint } = opts;
  return `# Migration: A2A → Aroha

This project wraps your existing A2A agent (\`${a2aEndpoint}\`) with a Aroha-compliant
interface using the \`@aroha-sdk/a2a-bridge\` adapter.

## What changed

| Before (A2A) | After (Aroha wrapper) |
|--------------|---------------------|
| A2A JSON-RPC \`SendMessage\` | POST \`/aroha/v1\` accepts signed Aroha envelopes |
| No cryptographic identity | Ed25519 DID: \`did:aroha:${name}\` |
| No saga support | Reserve/Commit/Cancel proxied through bridge |
| No registry | Publishable to Aroha registry via \`src/manifest.ts\` |

## How it works

\`\`\`
Aroha orchestrator
    │  ArohaRequest (signed)
    ▼
[${name}] Aroha server (port ${port})
    │  Verify signature, check RBAC
    │  arohaToA2a(envelope)
    ▼
Your A2A agent (${a2aEndpoint})
    │  JSON-RPC SendMessage (A2A 1.0)
    ▼
[${name}] Aroha server
    │  a2aToAroha(response)
    │  buildEnvelope (re-sign)
    ▼
Aroha orchestrator ← ArohaResponse (signed)
\`\`\`

## Running the bridge

\`\`\`bash
# Start your existing A2A agent first (on ${a2aEndpoint})
# Then start the Aroha bridge:
npm install && npm run dev
\`\`\`

Override the A2A endpoint at runtime:
\`\`\`bash
A2A_ENDPOINT=http://my-a2a-host:8080 npm run dev
\`\`\`

## Security upgrade path

The A2A bridge runs at **Trust Level 1** (no Ed25519 proofs on A2A messages).
To reach Trust Level 2–4, migrate your A2A agent to handle Aroha envelopes natively:

1. Run \`aroha init ${name}-native --type provider\`
2. Copy your business logic from the A2A handler into the generated \`src/handlers.ts\`
3. Remove this bridge

See the [full conversion recipe](../../docs/recipes/convert-from-a2a.md).
`;
}
