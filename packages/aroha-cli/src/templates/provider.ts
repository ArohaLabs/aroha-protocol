// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { NODE_ENGINE, TOOLCHAIN, sdkDeps } from "./versions.js";

export interface ProviderOptions {
  name: string;
  port: number;
  capabilities: string[];
}

export function providerTemplate(opts: ProviderOptions): Map<string, string> {
  const files = new Map<string, string>();
  files.set("package.json", packageJson(opts));
  files.set("tsconfig.json", tsconfig());
  files.set(".gitignore", gitignore());
  files.set(".env.example", envExample());
  files.set("src/identity.ts", identityTs());
  files.set("src/mandate.ts", mandateTs());
  files.set("src/server.ts", serverTs(opts));
  files.set("src/handlers.ts", handlersTs(opts));
  files.set("src/manifest.ts", manifestTs(opts));
  files.set("README.md", readme(opts));
  return files;
}

// ─── package.json ─────────────────────────────────────────────────────────────

function packageJson(opts: ProviderOptions): string {
  return JSON.stringify(
    {
      name: opts.name,
      version: "1.0.0",
      description: `Aroha provider agent: ${opts.name}`,
      type: "module",
      main: "./dist/server.js",
      scripts: {
        dev: "tsx src/server.ts",
        build: "tsc -p tsconfig.json",
        start: "node dist/server.js",
      },
      dependencies: {
        ...sdkDeps("@aroha-sdk/core", "@aroha-sdk/credentials", "@aroha-sdk/registry"),
        "@noble/ed25519": "^2.1.0",
      },
      devDependencies: { ...TOOLCHAIN },
      engines: { node: NODE_ENGINE },
    },
    null,
    2
  );
}

// ─── .gitignore / .env.example ────────────────────────────────────────────────

function gitignore(): string {
  return `node_modules/
dist/
# Holds AROHA_PRIVATE_KEY — never commit it.
.env
`;
}

function envExample(): string {
  return `# Ed25519 private key (64 hex chars). Generated into .env on first run if unset.
# In production, set it from your secrets manager instead.
AROHA_PRIVATE_KEY=

# DID of the human (or organisation) whose spending authority you accept.
# When set, every ArohaRequest / ArohaReserve must carry a mandate whose signed
# chain verifies back to exactly this DID and is granted to the caller.
AROHA_MANDATE_ROOT_DID=
`;
}

// ─── src/identity.ts ──────────────────────────────────────────────────────────

/** Persistent identity loader. Shared with the create-app orchestrator template. */
export function identityTs(): string {
  return `import { existsSync, readFileSync, writeFileSync } from "node:fs";
import * as ed from "@noble/ed25519";
import { buildDIDDocument, type AgentKeyPair } from "@aroha-sdk/core";

const ENV_FILE = ".env";
const KEY_VAR = "AROHA_PRIVATE_KEY";

/**
 * Load this agent's identity, creating it on first run.
 *
 * The private key comes from AROHA_PRIVATE_KEY (process env, or the .env file
 * in the working directory). If neither has one, a new key is generated and
 * written to .env (filling an empty AROHA_PRIVATE_KEY= line if there is one),
 * so the agent keeps the same DID and key on every restart.
 */
export async function loadOrCreateIdentity(agentId: string, endpoint: string): Promise<AgentKeyPair> {
  let hex = process.env[KEY_VAR] || readKeyFromEnvFile();

  if (!hex) {
    hex = Buffer.from(ed.utils.randomPrivateKey()).toString("hex");
    saveKeyToEnvFile(hex);
    console.log(\`[identity] Generated a new private key and saved it to \${ENV_FILE} (\${KEY_VAR}). Keep that file out of version control.\`);
  }

  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(\`\${KEY_VAR} must be 64 hex characters (a 32-byte Ed25519 private key)\`);
  }
  const privateKey = Uint8Array.from(Buffer.from(hex, "hex"));
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const document = buildDIDDocument(agentId, publicKey, endpoint, new Date().toISOString());
  return { did: document.id, privateKey, publicKey, document };
}

function envLines(): string[] {
  return existsSync(ENV_FILE) ? readFileSync(ENV_FILE, "utf8").split(/\\r?\\n/) : [];
}

/** The last non-empty AROHA_PRIVATE_KEY=... value in .env, if any. */
function readKeyFromEnvFile(): string | undefined {
  const values = envLines()
    .filter((l) => l.startsWith(\`\${KEY_VAR}=\`))
    .map((l) => l.slice(KEY_VAR.length + 1).trim())
    .filter((v) => v.length > 0);
  return values.at(-1);
}

function saveKeyToEnvFile(hex: string): void {
  const lines = envLines();
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const emptyIdx = lines.findIndex((l) => l.trim() === \`\${KEY_VAR}=\`);
  if (emptyIdx !== -1) {
    lines[emptyIdx] = \`\${KEY_VAR}=\${hex}\`;
  } else {
    lines.push(\`\${KEY_VAR}=\${hex}\`);
  }
  writeFileSync(ENV_FILE, lines.join("\\n") + "\\n", { mode: 0o600 });
}
`;
}

// ─── src/mandate.ts ───────────────────────────────────────────────────────────

function mandateTs(): string {
  return `import { verifyMandateChain, resolveContentAddressedKey } from "@aroha-sdk/credentials";
import type { ArohaEnvelope } from "@aroha-sdk/core";

/**
 * Mandate enforcement.
 *
 * A mandate is a signed, scoped grant of spending authority (limit, merchant
 * scope, expiry). It starts at a human (the ROOT) and is narrowed by each
 * agent that delegates it; every token carries its whole signed chain. Over
 * MCP the convention is \`_meta["aroha/mandate"]\` with a holder proof.
 * ArohaServer hands this agent the signed envelope rather than the raw HTTP
 * request, so here the mandate travels in the envelope body as
 * \`credentialToken\`, where the sender's envelope signature covers it.
 *
 * Set AROHA_MANDATE_ROOT_DID to the DID of the human (or organisation) whose
 * authority you accept. Every ArohaRequest and ArohaReserve must then carry a
 * mandate whose chain verifies link by link back to exactly that root, and
 * whose final grantee is the DID that signed the envelope. A token that only
 * proves "someone signed this" (a valid leaf with no verified chain) is
 * rejected. If AROHA_MANDATE_ROOT_DID is unset, mandates are NOT enforced and
 * a warning is printed at startup.
 *
 * Keys: the default resolver derives keys from content-addressed
 * \`did:aroha:z…\` DIDs. For registry-named DIDs pass a registry-backed
 * resolver; for rotatable \`did:aroha:E…\` DIDs pass \`kelSource\` (see
 * createMandateKeyResolver in @aroha-sdk/credentials). To honour revocations,
 * pass an \`isRevoked\` hook — it is consulted for every link in the chain.
 */
const ROOT_DID = process.env.AROHA_MANDATE_ROOT_DID?.trim() || undefined;

if (process.env.AROHA_MANDATE_ISSUER_PUBLIC_KEY?.trim() && !ROOT_DID) {
  // Fail closed rather than silently stop enforcing after an upgrade.
  throw new Error(
    "AROHA_MANDATE_ISSUER_PUBLIC_KEY is no longer used: a single issuer key cannot prove a delegated " +
    "chain. Set AROHA_MANDATE_ROOT_DID to the DID of the human root you accept mandates from."
  );
}
if (ROOT_DID && !ROOT_DID.startsWith("did:")) {
  throw new Error("AROHA_MANDATE_ROOT_DID must be a DID (did:aroha:…)");
}
if (!ROOT_DID) {
  console.warn("[mandate] AROHA_MANDATE_ROOT_DID is not set: requests are NOT checked for a mandate.");
}

const GATED_TYPES = new Set<string>(["ArohaRequest", "ArohaReserve"]);

/** ArohaServer middleware: reject gated messages without a mandate chain from ROOT_DID to the sender. */
export async function mandateMiddleware(
  envelope: ArohaEnvelope,
  reject: (status: number, errorCode: string, reason: string) => void
): Promise<void> {
  if (!ROOT_DID || !GATED_TYPES.has(envelope.type)) return;

  const token = (envelope.body as { credentialToken?: unknown }).credentialToken;
  if (typeof token !== "string" || token.length === 0) {
    reject(403, "Aroha_UNAUTHORIZED", "A mandate is required (body.credentialToken)");
    return;
  }

  const result = await verifyMandateChain(token, resolveContentAddressedKey, {
    expectedRoot: ROOT_DID,         // authority must originate from this human
    expectedGrantee: envelope.from, // and be held by the DID that signed this envelope
  });
  // Gate on chainVerified, not on \`valid\` alone.
  if (!result.valid || result.chainVerified !== true) {
    reject(403, "Aroha_FORBIDDEN", \`Mandate rejected: \${result.reason ?? "chain not verified"}\`);
  }
}
`;
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

function serverTs(opts: ProviderOptions): string {
  const { name, port } = opts;
  return `import { ArohaServer } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { handleMessage } from "./handlers.js";
import { loadOrCreateIdentity } from "./identity.js";
import { mandateMiddleware } from "./mandate.js";
import { registerAgent } from "./manifest.js";

// ── Identity ──────────────────────────────────────────────────────────────────
// Loaded from AROHA_PRIVATE_KEY; generated and saved to .env on first run, so
// the DID and key stay the same across restarts.
const identity = await loadOrCreateIdentity(
  "${name}",
  \`http://localhost:${port}/aroha/v1\`
);

// ── Peer registry ─────────────────────────────────────────────────────────────
// Add each peer that is allowed to send you messages.
const knownPublicKeys = new Map<string, Uint8Array>();
knownPublicKeys.set(identity.did, identity.publicKey);

const agentRoles = new Map<string, ArohaRole[]>();
agentRoles.set(identity.did, [ArohaRole.AgentProvider]);

/** Call this at startup after exchanging public keys with peer orchestrators. */
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
    mandateMiddleware,
  ],

  onMessage: async (envelope, respond, _stream) => {
    const reply = await handleMessage(envelope, identity.did, identity.privateKey);
    respond(reply);
  },
});

await server.start();

// ── Registry ──────────────────────────────────────────────────────────────────
// Uncomment to register with the Aroha registry so orchestrators can discover you.
// await registerAgent(identity);

console.log(\`[${name}] Aroha endpoint : http://localhost:${port}/aroha/v1\`);
console.log(\`[${name}] DID document  : http://localhost:${port}/.well-known/aroha-agent.json\`);
console.log(\`[${name}] DID           : \${identity.did}\`);
`;
}

// ─── src/handlers.ts ──────────────────────────────────────────────────────────

function handlersTs(opts: ProviderOptions): string {
  const sagaCaps = opts.capabilities.filter(
    (c) => !c.startsWith("search-") && !c.startsWith("list-") && !c.startsWith("get-")
  );
  const queryCaps = opts.capabilities.filter(
    (c) => c.startsWith("search-") || c.startsWith("list-") || c.startsWith("get-")
  );

  const requestCases = queryCaps
    .map(
      (c) => `
        case "${c}": {
          // TODO: replace with your business logic
          const result = { items: [], message: "No results yet — implement ${c}" };
          return buildEnvelope("ArohaResponse", agentDID, from,
            { capability, result },
            correlationId, privateKey);
        }`
    )
    .join("");

  const reserveCases = sagaCaps
    .map(
      (c) => `
      case "${c}": {
        // TODO: validate params, check inventory, then issue a reservation token
        const token = \`RES-\${crypto.randomUUID()}\`;
        const expiresAt = new Date(Date.now() + holdDurationMs);
        reservations.set(token, { capability, params, expiresAt, committed: false });
        return buildEnvelope("ArohaReserveAck", agentDID, from,
          { reservationToken: token, expiresAt: expiresAt.toISOString() },
          correlationId, privateKey);
      }`
    )
    .join("");

  return `import { buildEnvelope, ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";

// In-memory store — swap for a database / Redis in production
const reservations = new Map<string, {
  capability: string;
  params: unknown;
  expiresAt: Date;
  committed: boolean;
  result?: Record<string, unknown>;
}>();

export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { type, body, from, correlationId } = envelope;

  switch (type) {
    case "ArohaRequest":
      return handleRequest(envelope, agentDID, privateKey);
    case "ArohaReserve":
      return handleReserve(envelope, agentDID, privateKey);
    case "ArohaCommit":
      return handleCommit(envelope, agentDID, privateKey);
    case "ArohaCancel":
      return handleCancel(envelope, agentDID, privateKey);
    default:
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.UnknownCapability, message: \`Unsupported message type: \${type}\`, retryable: false },
        correlationId, privateKey);
  }
}

// ── Read-only queries ─────────────────────────────────────────────────────────

async function handleRequest(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };
  const { from, correlationId } = envelope;

  switch (capability) {${requestCases}
    default:
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.UnknownCapability, message: \`Unknown capability: \${capability}\`, retryable: false },
        correlationId, privateKey);
  }
}

// ── Saga: Reserve ─────────────────────────────────────────────────────────────

async function handleReserve(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { capability, params, holdDurationMs } = envelope.body as {
    capability: string;
    params: Record<string, unknown>;
    holdDurationMs: number;
  };
  const { from, correlationId } = envelope;

  switch (capability) {${reserveCases || `
      // TODO: add transactional capabilities here`}
    default:
      return buildEnvelope("ArohaError", agentDID, from,
        { code: ArohaErrorCode.UnknownCapability, message: \`Cannot reserve: \${capability}\`, retryable: false },
        correlationId, privateKey);
  }
}

// ── Saga: Commit (must be idempotent) ─────────────────────────────────────────

async function handleCommit(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { reservationToken } = envelope.body as { reservationToken: string };
  const { from, correlationId } = envelope;

  const res = reservations.get(reservationToken);
  if (!res) {
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.InvalidToken, message: "Unknown or expired reservation token", retryable: false },
      correlationId, privateKey);
  }

  if (new Date() > res.expiresAt) {
    reservations.delete(reservationToken);
    return buildEnvelope("ArohaError", agentDID, from,
      { code: ArohaErrorCode.ReservationExpired, message: "Reservation has expired", retryable: false },
      correlationId, privateKey);
  }

  // Idempotency guard — same token always returns the same result
  if (!res.committed) {
    res.committed = true;
    // TODO: finalize booking / charge payment / issue confirmation
    res.result = { status: "confirmed", confirmationId: \`CONF-\${crypto.randomUUID().slice(0, 8).toUpperCase()}\` };
  }

  return buildEnvelope("ArohaCommitAck", agentDID, from,
    { reservationToken, result: res.result ?? {} },
    correlationId, privateKey);
}

// ── Saga: Cancel (compensating transaction) ───────────────────────────────────

async function handleCancel(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const { reservationToken } = envelope.body as { reservationToken: string; reason?: string };
  const { from, correlationId } = envelope;

  const res = reservations.get(reservationToken);
  if (res?.committed) {
    // TODO: issue refund / void confirmation if already committed
    console.log(\`[cancel] Compensating committed reservation \${reservationToken}\`);
  }

  reservations.delete(reservationToken);

  return buildEnvelope("ArohaCancelAck", agentDID, from,
    { reservationToken },
    correlationId, privateKey);
}
`;
}

// ─── src/manifest.ts ──────────────────────────────────────────────────────────

function manifestTs(opts: ProviderOptions): string {
  const { name, port, capabilities } = opts;
  const sagaCaps = capabilities.filter(
    (c) => !c.startsWith("search-") && !c.startsWith("list-") && !c.startsWith("get-")
  );

  const capDefs = capabilities
    .map((c) => {
      const isSaga = sagaCaps.includes(c);
      return `    {
      id: "${c}",
      version: "1.0.0",
      description: "TODO: describe what ${c} does",
      inputSchema: { type: "object" as const, properties: {}, required: [] },
      outputSchema: { type: "object" as const },
      async: false,
      maxResponseMs: ${isSaga ? 30000 : 5000},
      requiredTrustLevel: ${isSaga ? 2 : 1} as 0 | 1 | 2 | 3 | 4,
      pricing: { model: "${isSaga ? "per-transaction" : "free"}" as const },
      sagaRole: "${isSaga ? "participant" : "none"}" as const,
      ${isSaga ? `reserveCapabilityId: "${c}",\n      cancelCapabilityId: "${c}",` : ""}
    }`;
    })
    .join(",\n");

  return `import * as ed from "@noble/ed25519";
import type { AgentKeyPair } from "@aroha-sdk/core";
// import { ArohaHttpRegistry } from "@aroha-sdk/registry";

/** Build, sign, and register the capability manifest for this agent. */
export async function registerAgent(identity: AgentKeyPair): Promise<void> {
  const manifest = buildManifest(identity);

  // Sign the manifest
  const signingInput = JSON.stringify(sortKeys({ ...manifest, signature: "" }));
  const sigBytes = await ed.signAsync(new TextEncoder().encode(signingInput), identity.privateKey);
  manifest.signature = Buffer.from(sigBytes).toString("base64url");

  // Publish to IPFS (replace with your IPFS endpoint)
  // const ipfsCID = await ipfsClient.add(JSON.stringify(manifest));

  // Register with the HTTP registry (set AROHA_REGISTRY_URL + AROHA_API_KEY).
  // The registry requires proof that you hold the agent key: the signer signs
  // its one-time challenge (POST /v1/agents/challenge) during register().
  // const registry = new ArohaHttpRegistry({ baseUrl: process.env.AROHA_REGISTRY_URL || undefined, apiKey: process.env.AROHA_API_KEY! });
  // await registry.register(identity.did, ipfsCID, identity.publicKey, { signer: { privateKey: identity.privateKey } });

  console.log("[manifest] Agent manifest built — uncomment IPFS + registry lines to publish");
  console.log(JSON.stringify(manifest, null, 2));
}

function buildManifest(identity: AgentKeyPair) {
  return {
    aroha: "1.0" as const,
    did: identity.did,
    name: "${name}",
    version: "1.0.0",
    endpoint: \`http://localhost:${port}/aroha/v1\`,
    protocols: ["aroha/1.0" as const],
    capabilities: [
${capDefs}
    ],
    signature: "",
  };
}

function sortKeys(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(obj)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, v && typeof v === "object" && !Array.isArray(v) ? sortKeys(v as Record<string, unknown>) : v])
  );
}
`;
}

// ─── README.md ────────────────────────────────────────────────────────────────

function readme(opts: ProviderOptions): string {
  const { name, port, capabilities } = opts;
  return `# ${name}

Aroha provider agent scaffolded by \`@aroha-sdk/cli\`.

## Capabilities

${capabilities.map((c) => `- \`${c}\``).join("\n")}

## Quick start

\`\`\`bash
npm install
npm run dev
\`\`\`

The agent starts at **http://localhost:${port}/aroha/v1**.
DID Document: **http://localhost:${port}/.well-known/aroha-agent.json**

## Next steps

1. **Add business logic** — open \`src/handlers.ts\` and replace the TODO stubs
2. **Keep the key safe** — the first run writes \`AROHA_PRIVATE_KEY\` to \`.env\` (git-ignored) and reuses it afterwards. In production, set it from a secrets manager
3. **Require mandates** — set \`AROHA_MANDATE_ROOT_DID\` to the human you accept authority from; callers must then send a mandate in \`body.credentialToken\` whose chain verifies back to that DID (see \`src/mandate.ts\`)
4. **Publish the manifest** — uncomment the IPFS + registry lines in \`src/manifest.ts\`
5. **Register peers** — call \`registerPeer(did, publicKey)\` for each orchestrator you trust

## Files

| File | Purpose |
|------|---------|
| \`src/server.ts\` | ArohaServer setup, peer registry, middleware |
| \`src/identity.ts\` | Loads or creates the persistent identity (\`AROHA_PRIVATE_KEY\`) |
| \`src/mandate.ts\` | Mandate chain verification middleware (\`verifyMandateChain\`) |
| \`src/handlers.ts\` | Message dispatch and saga (reserve/commit/cancel) |
| \`src/manifest.ts\` | Capability manifest builder and registry publisher |

## Aroha Protocol docs

- [Protocol spec](https://github.com/ArohaLabs/aroha-spec/blob/main/spec/aroha-1.0.md)
- [Documentation](https://github.com/ArohaLabs/aroha-protocol/tree/main/docs)
`;
}
