<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# CLI Reference

`@aroha-sdk/cli` (`aroha`) scaffolds new Aroha agents and converts existing agents from other protocols.

## Installation

```bash
npm install -g @aroha-sdk/cli
# or, inside this monorepo:
node packages/aroha-cli/dist/cli.js --help
```

## Commands

### `aroha init`

Scaffold a new Aroha agent from scratch.

```
aroha init [name] [options]
```

**Options**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | `provider \| orchestrator` | prompted | Agent type |
| `--port` | number | prompted | Aroha server port |
| `--api-port` | number | `3010` | REST API port (orchestrator only) |
| `--capabilities` | string | prompted | Comma-separated capability IDs |
| `-y, --yes` | boolean | `false` | Skip all prompts, use defaults |

**Generated files (provider)**

| File | Purpose |
|------|---------|
| `src/server.ts` | `ArohaServer` setup, peer registry |
| `src/identity.ts` | Loads the agent's Ed25519 key from `AROHA_PRIVATE_KEY`, generating it into `.env` on first run |
| `src/mandate.ts` | Mandate chain verification (`AROHA_MANDATE_ROOT_DID`) |
| `src/handlers.ts` | Message dispatch + saga (reserve/commit/cancel) skeleton |
| `src/manifest.ts` | Capability manifest builder + registry publisher |
| `package.json` | Dependencies: `@aroha-sdk/core`, `@aroha-sdk/credentials`, `@aroha-sdk/registry` |
| `tsconfig.json` | TypeScript config |
| `.gitignore`, `.env.example` | `.env` is git-ignored |
| `README.md` | Agent-specific quickstart |

**Generated files (orchestrator)**

| File | Purpose |
|------|---------|
| `src/server.ts` | `ArohaServer` + REST API setup |
| `src/orchestrate.ts` | Discovery → selection → saga execution |
| `src/intent.ts` | Natural-language → task step decomposition stub |
| `package.json`, `tsconfig.json`, `README.md` | Project files |

**Examples**

```bash
# Interactive wizard
aroha init

# Provider with two capabilities
aroha init my-flight-agent \
  --type provider \
  --port 3001 \
  --capabilities search-flights,book-flight

# Orchestrator
aroha init my-assistant \
  --type orchestrator \
  --port 3000 \
  --api-port 3010

# Skip all prompts
aroha init demo-agent --type provider -y
```

---

### `aroha convert`

Wrap an existing agent for the Aroha protocol.
Your existing agent keeps running unchanged; the wrapper proxies Aroha messages to it.

```
aroha convert [options]
```

**Options**

| Flag | Type | Description |
|------|------|-------------|
| `--from` | `a2a \| agntcy \| mcp \| langchain` | Source protocol (auto-detected if `--dir` given) |
| `--dir` | path | Existing agent directory (used for auto-detection) |
| `--out` | path | Output directory (default: `<name>`) |
| `--name` | string | Name for the generated wrapper |
| `--port` | number | Aroha port for this wrapper |
| `--endpoint` | URL | Upstream agent URL (A2A / Agntcy / MCP) |
| `--language` | `typescript \| python` | LangChain target language |
| `-y, --yes` | boolean | Skip prompts, use defaults |

**Protocol support**

=== "A2A (Agent2Agent, Linux Foundation)"

    Uses `@aroha-sdk/a2a-bridge`. Proxies Aroha envelopes to/from an A2A HTTP endpoint.

    ```bash
    aroha convert \
      --from a2a \
      --endpoint http://localhost:8080 \
      --name my-flight-aroha \
      --port 3001
    ```

    **Generated files:** `src/server.ts`, `src/a2a-adapter.ts`, `MIGRATION.md`

    !!! warning "Trust Level 1 only"
        A2A messages carry no Ed25519 proof. The bridge operates at Trust Level 1.
        For Trust Level 2+, convert natively using `aroha init`.

=== "Agntcy"

    Maps Agntcy's `POST /invoke { capability, input }` to Aroha capability handlers.
    Emulates saga on top of the stateless Agntcy protocol.

    ```bash
    aroha convert \
      --from agntcy \
      --endpoint http://localhost:8080 \
      --name my-agntcy-aroha
    ```

    **Generated files:** `src/server.ts`, `src/agntcy-adapter.ts`, `src/capability-map.ts`, `MIGRATION.md`

    After generation, edit `src/capability-map.ts` to map your Agntcy capability IDs
    and schemas to Aroha format.

=== "MCP"

    Uses `@aroha-sdk/mcp-bridge`. Fetches tool list from `GET /tools` at startup,
    registers each tool as a Aroha capability.

    ```bash
    aroha convert \
      --from mcp \
      --endpoint http://localhost:8080 \
      --name my-mcp-aroha
    ```

    **Generated files:** `src/server.ts`, `src/mcp-adapter.ts`, `MIGRATION.md`

    !!! note "MCP server HTTP requirement"
        Your MCP server must expose `GET /tools` (list of `McpToolDefinition`).
        See [the MCP recipe](recipes/convert-from-mcp.md) for adding an HTTP shim to stdio servers.

=== "LangChain"

    Wraps LangChain tools as Aroha capabilities.
    Each `Tool` becomes one capability; tool names are converted from `snake_case` to `kebab-case`.

    ```bash
    aroha convert \
      --from langchain \
      --language typescript \
      --name my-lc-aroha
    ```

    **Generated files:** `src/server.ts`, `src/langchain-adapter.ts`, `src/tools.ts`, `MIGRATION.md`

    Edit `src/tools.ts` and register your tools:

    ```typescript
    import { TavilySearchResults } from "@langchain/community/tools/tavily_search";

    export async function getTools() {
      return [new TavilySearchResults({ maxResults: 5 })];
    }
    ```

**Auto-detection**

If you pass `--dir`, the CLI detects the protocol automatically:

```bash
aroha convert --dir ./existing-agent
# Detected protocol: langchain (from package.json)
```

Detection checks `package.json` dependencies, Python `requirements.txt`, and file content heuristics.

---

### `aroha create-bridge`

Scaffold a standalone npm bridge package — the fast path for wrapping a REST API or connecting an existing framework to Aroha.

```
aroha create-bridge [options]
```

**Options**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--name` | string | prompted | Bridge name (e.g. `hubspot`) → package `@aroha-sdk/hubspot-bridge` |
| `--sdk` | string | prompted | SDK / API being wrapped (e.g. `HubSpot`) |
| `--out` | path | `aroha-<name>-bridge` | Output directory |
| `-y, --yes` | boolean | `false` | Skip all prompts, use defaults |

**Generated files**

| File | Purpose |
|------|---------|
| `package.json` | `name: "@aroha-sdk/<name>-bridge"`, dependency on `@aroha-sdk/core` |
| `tsconfig.json` | TypeScript config (ESM, strict) |
| `src/index.ts` | Public exports |
| `src/types.ts` | Duck-typed interfaces (no hard SDK version dependency) |
| `src/bridge.ts` | `handleCapability()` stub — fill in your REST calls |
| `README.md` | Pre-filled usage guide |

**Examples**

```bash
# Interactive
aroha create-bridge

# Skip prompts — scaffold a HubSpot bridge
aroha create-bridge --name hubspot --sdk HubSpot -y
cd aroha-hubspot-bridge

# Implement handleCapability() in src/bridge.ts
npm run build
# Rename the package to a scope you own (the @aroha-sdk scope is not open to others), then:
npm publish --access public
```

**Bridge pattern (duck-typed, no hard dep):**

```typescript
// src/bridge.ts — generated skeleton
async function handleCapability(
  client: HubSpotClientLike,            // duck-typed interface from src/types.ts — no SDK import
  capability: string,
  params: Record<string, unknown>
): Promise<Record<string, unknown>> {
  switch (capability) {
    case "example-read": {
      // TODO: replace with real HubSpot call
      return { status: "ok", capability, params };
    }
    default:
      throw new Error(`Unknown capability: ${capability}`);
  }
}
```

The duck-typed approach means your bridge has **no runtime dependency** on the SDK you're wrapping — consumers install the SDK themselves.

[Full guide: Wrap Any REST API in ~50 lines →](wrap-any-rest-api.md)

---

### `aroha add capability`

Add a new capability skeleton to an existing agent **in-place**.

```
aroha add capability [id] [options]
```

**Options**

| Flag | Type | Description |
|------|------|-------------|
| `--saga` | boolean | Also inject `ArohaReserve` / `ArohaCommit` / `ArohaCancel` handlers |

**Examples**

```bash
# Read-only query capability
aroha add capability search-hotels

# Transactional capability (full saga)
aroha add capability book-hotel --saga
```

What it modifies:

- **`src/handlers.ts`** — injects a `case "my-capability"` stub into `handleRequest` (and saga handlers if `--saga`)
- **`src/manifest.ts`** — appends the capability definition to the manifest array

!!! tip
    Run this command from the root of a `aroha init`-generated agent directory.

---

### Other commands

| Command | What it does |
|---------|--------------|
| `aroha dev [--port <n>]` | Local dev sandbox: in-memory capability registry and live dashboard (default port 3000). See [Sandbox](sandbox.md). |
| `aroha create-app [name] [-y]` | Scaffold a multi-agent project: `orchestrator/`, `agents/worker-a/`, `agents/worker-b/`, `frontend/`, `docker-compose.yml` |
| `aroha doctor [endpoint]` | Check Node.js version, `.env` (`AROHA_AGENT_DID`; read with Node's `util.parseEnv`, so quotes, `export`, inline `#` comments and CRLF are handled as `node --env-file` handles them), the endpoint's DID document (`id` equals `AROHA_AGENT_DID`, a usable Ed25519 `verificationMethod` key) and that `POST /aroha/v1` answers |
| `aroha telemetry [status\|on\|off]` | No telemetry endpoint is built in; telemetry exists only if you set `AROHA_TELEMETRY_ENDPOINT` to an https URL you control |

There is no `call`, `publish`, `discover`, `keygen` or `conformance` command.

---

## Global flags

| Flag | Description |
|------|-------------|
| `--help, -h` | Show help |
| `--version` | Print CLI version |

---

## Capability ID conventions

Aroha uses `kebab-case` for all capability IDs:

| Pattern | Example | Saga? |
|---------|---------|-------|
| `search-*` | `search-flights` | No |
| `list-*` | `list-hotels` | No |
| `get-*` | `get-weather` | No |
| `book-*` | `book-flight` | Yes |
| `send-*` | `send-email` | Yes |
| `create-*` | `create-order` | Yes |

The CLI auto-detects saga intent from the capability name prefix when prompting.

---

## Full recipe docs

| From | Guide |
|------|-------|
| A2A | [recipes/convert-from-a2a.md](recipes/convert-from-a2a.md) |
| Agntcy | [recipes/convert-from-agntcy.md](recipes/convert-from-agntcy.md) |
| MCP | [recipes/convert-from-mcp.md](recipes/convert-from-mcp.md) |
| LangChain | [recipes/convert-from-langchain.md](recipes/convert-from-langchain.md) |
| General | [recipes/converting-existing-agents.md](recipes/converting-existing-agents.md) |
