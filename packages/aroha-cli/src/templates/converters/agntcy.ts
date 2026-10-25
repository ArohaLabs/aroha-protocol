// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { TOOLCHAIN, sdkDeps } from "../versions.js";

export interface AgntcyConverterOptions {
  name: string;
  port: number;
  agntcyEndpoint: string;
}

export function agntcyConverterTemplate(opts: AgntcyConverterOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/agntcy-adapter.ts", adapterTs(opts));
  files.set("src/capability-map.ts", capabilityMapTs());
  files.set("MIGRATION.md", migrationMd(opts));
  return files;
}

function packageJson(opts: AgntcyConverterOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha wrapper for Agntcy agent: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials"),
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

function serverTs(opts: AgntcyConverterOptions): string {
  const { name, port } = opts;
  return `import { generateDID, ArohaServer } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { handleMessage } from "./agntcy-adapter.js";

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
console.log(\`[${name}] Aroha→Agntcy bridge at http://localhost:${port}/aroha/v1\`);
console.log(\`[${name}] Proxying to Agntcy agent at ${opts.agntcyEndpoint}\`);
console.log(\`[${name}] DID: \${identity.did}\`);
`;
}

function adapterTs(opts: AgntcyConverterOptions): string {
  return `import { buildEnvelope, ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";
import { arohaToAgntcy, agntcyToAroha } from "./capability-map.js";

const AGNTCY_ENDPOINT = process.env.AGNTCY_ENDPOINT ?? "${opts.agntcyEndpoint}";

/**
 * Bridges Aroha messages to the Agntcy HTTP API.
 *
 * Agntcy uses a JSON-over-HTTP protocol:
 *   POST /invoke  { capability, input }  →  { output }
 *
 * Saga (reserve/commit/cancel) is emulated: Agntcy has no native hold concept,
 * so reserve immediately calls /invoke and caches the result until commit.
 */
export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { from, correlationId } = envelope;

  switch (envelope.type) {

    case "ArohaRequest": {
      const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };
      const agntcyRequest = arohaToAgntcy(capability, params);

      let result: unknown;
      try {
        const res = await fetch(\`\${AGNTCY_ENDPOINT}/invoke\`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(agntcyRequest),
        });
        if (!res.ok) throw new Error(\`HTTP \${res.status}\`);
        const json = await res.json() as { output: unknown };
        result = agntcyToAroha(capability, json.output);
      } catch (err) {
        return buildEnvelope("ArohaError", agentDID, from,
          { code: ArohaErrorCode.ServiceUnavailable, message: String(err), retryable: true },
          correlationId, privateKey);
      }

      return buildEnvelope("ArohaResponse", agentDID, from,
        { capability, result },
        correlationId, privateKey);
    }

    case "ArohaReserve": {
      // Agntcy has no native hold — call the upstream and cache the result
      const { capability, params, holdDurationMs } = envelope.body as {
        capability: string;
        params: Record<string, unknown>;
        holdDurationMs: number;
      };
      const agntcyRequest = arohaToAgntcy(capability, params);

      let result: unknown;
      try {
        const res = await fetch(\`\${AGNTCY_ENDPOINT}/invoke\`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(agntcyRequest),
        });
        if (!res.ok) throw new Error(\`HTTP \${res.status}\`);
        const json = await res.json() as { output: unknown };
        result = agntcyToAroha(capability, json.output);
      } catch (err) {
        return buildEnvelope("ArohaError", agentDID, from,
          { code: ArohaErrorCode.ServiceUnavailable, message: String(err), retryable: true },
          correlationId, privateKey);
      }

      const reservationToken = \`AGN-\${crypto.randomUUID()}\`;
      const expiresAt = new Date(Date.now() + holdDurationMs);
      // Store result for commit phase
      pendingResults.set(reservationToken, { result, expiresAt, committed: false });

      return buildEnvelope("ArohaReserveAck", agentDID, from,
        { reservationToken, expiresAt: expiresAt.toISOString() },
        correlationId, privateKey);
    }

    case "ArohaCommit": {
      const { reservationToken } = envelope.body as { reservationToken: string };
      const pending = pendingResults.get(reservationToken);
      if (!pending) {
        return buildEnvelope("ArohaError", agentDID, from,
          { code: ArohaErrorCode.InvalidToken, message: "Unknown reservation token", retryable: false },
          correlationId, privateKey);
      }
      if (!pending.committed) pending.committed = true;
      return buildEnvelope("ArohaCommitAck", agentDID, from,
        { reservationToken, result: pending.result },
        correlationId, privateKey);
    }

    case "ArohaCancel": {
      const { reservationToken } = envelope.body as { reservationToken: string };
      // Agntcy has no cancel concept — just discard the cached result
      pendingResults.delete(reservationToken);
      return buildEnvelope("ArohaCancelAck", agentDID, from,
        { reservationToken },
        correlationId, privateKey);
    }

    default:
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.UnknownCapability, message: \`Unsupported: \${envelope.type}\`, retryable: false },
        correlationId, privateKey);
  }
}

// In-memory cache of Agntcy results (replace with Redis/DB in production)
const pendingResults = new Map<string, { result: unknown; expiresAt: Date; committed: boolean }>();
`;
}

function capabilityMapTs(): string {
  return `/**
 * Agntcy ↔ Aroha capability mapping.
 *
 * Agntcy uses snake_case capability IDs and wraps inputs/outputs under
 * { input: { ... } } / { output: { ... } }.
 *
 * Aroha uses kebab-case capability IDs and passes params/result directly.
 *
 * Customize the maps below to match your Agntcy agent's actual schema.
 */

// Maps Aroha capability ID → Agntcy capability ID
const Aroha_TO_AGNTCY: Record<string, string> = {
  // "search-flights": "search_flights",
  // "book-hotel":     "book_hotel",
  // TODO: add your capability mappings
};

// Maps Aroha capability ID → input transform function
const INPUT_TRANSFORMS: Record<string, (params: Record<string, unknown>) => Record<string, unknown>> = {
  // "search-flights": (p) => ({ origin: p.origin, destination: p.destination, date: p.date }),
  // TODO: add input transforms matching your Agntcy agent's expected schema
};

// Maps Aroha capability ID → output transform function
const OUTPUT_TRANSFORMS: Record<string, (output: unknown) => unknown> = {
  // "search-flights": (o) => (o as { flights: unknown[] }).flights,
  // TODO: add output transforms to shape Agntcy output into Aroha result format
};

export function arohaToAgntcy(
  capability: string,
  params: Record<string, unknown>
): { capability: string; input: Record<string, unknown> } {
  const agntcyCap = Aroha_TO_AGNTCY[capability] ?? capability.replace(/-/g, "_");
  const transform = INPUT_TRANSFORMS[capability];
  const input = transform ? transform(params) : params;
  return { capability: agntcyCap, input };
}

export function agntcyToAroha(capability: string, output: unknown): unknown {
  const transform = OUTPUT_TRANSFORMS[capability];
  return transform ? transform(output) : output;
}
`;
}

function migrationMd(opts: AgntcyConverterOptions): string {
  const { name, port, agntcyEndpoint } = opts;
  return `# Migration: Agntcy → Aroha

This project wraps your Agntcy agent (\`${agntcyEndpoint}\`) with a Aroha interface.

## Protocol differences

| Agntcy | Aroha |
|--------|------|
| HTTP POST \`/invoke { capability, input }\` | HTTP POST \`/aroha/v1\` (signed envelope) |
| YAML capability manifest | JSON capability manifest (IPFS-hosted) |
| No cryptographic identity | Ed25519 DID |
| No saga / atomic transactions | Native saga (reserve/commit/cancel) |
| snake_case capability IDs | kebab-case capability IDs |

## Bridge architecture

\`\`\`
Aroha orchestrator
    │  ArohaRequest { capability: "search-flights", params }
    ▼
Aroha→Agntcy bridge (port ${port})
    │  arohaToAgntcy()  →  { capability: "search_flights", input: params }
    │  POST ${agntcyEndpoint}/invoke
    ▼
Your Agntcy agent
    │  { output: { ... } }
    ▼
Aroha→Agntcy bridge
    │  agntcyToAroha()  →  ArohaResponse { result }
    ▼
Aroha orchestrator
\`\`\`

## Setup

1. **Map capabilities** — edit \`src/capability-map.ts\` to match your Agntcy agent's schema
2. **Run**: \`npm install && npm run dev\`
3. Override upstream: \`AGNTCY_ENDPOINT=http://... npm run dev\`

## Saga emulation

Agntcy has no native hold/cancel concept. The bridge emulates sagas by:
- **ArohaReserve**: calls \`/invoke\` immediately and caches the result in memory
- **ArohaCommit**: returns the cached result (idempotent)
- **ArohaCancel**: discards the cache (no compensation on the upstream)

For true atomic transactions, migrate your Agntcy agent to handle Aroha natively.
See [the full conversion recipe](../../docs/recipes/convert-from-agntcy.md).
`;
}
