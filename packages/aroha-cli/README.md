# @aroha-sdk/cli

The Aroha command-line tool — scaffold agents pre-wired for mandate verification, diagnose your setup, and manage the local dev registry.

## Install

```bash
npm install -g @aroha-sdk/cli
# or use without installing:
npx @aroha-sdk/cli <command>
```

## Quick example

```bash
# Scaffold a new agent pre-wired for mandate verification
aroha init my-agent
# → prompts: agent type (provider/orchestrator), port, capabilities
# → writes src/mandate.ts: verifyMandateChain() back to AROHA_MANDATE_ROOT_DID

# Zero-config defaults
aroha init my-agent --yes

# Convert an existing MCP server to an Aroha agent
aroha convert --from mcp --dir .

# Health-check your environment and running agent
aroha doctor
aroha doctor http://localhost:3001
# ✓ Node.js  v22.11.0
# ✓ .env     AROHA_AGENT_DID=did:aroha:my-agent
# ✓ DID document  did:aroha:my-agent  12ms
# ✓ Round-trip  200 in 38ms

# Start local dev registry + dashboard
aroha dev
```

## Why this exists in the mandate chain

Scaffold commands produce agents that verify the full mandate chain (`verifyMandateChain()` to a configured human root) before any handler logic runs — so mandate enforcement is the default, not an afterthought. `aroha doctor` verifies that your keypair and DID are configured correctly before you issue your first mandate.

## API (commands)

- `aroha init <name>` — scaffold a new mandate-aware agent (`--type`, `--port`, `--api-port`, `--capabilities`, `--yes`).
- `aroha create-app [name]` — scaffold a multi-agent project.
- `aroha convert --from <a2a|agntcy|mcp|langchain>` — wrap an existing agent as an Aroha agent.
- `aroha add capability [id]` — add a capability to an existing agent (`--saga` for reserve/commit/cancel handlers).
- `aroha create-bridge` — scaffold a bridge package (`--name`, `--sdk`, `--out`).
- `aroha doctor [endpoint]` — check Node version (≥ 22), env vars, the endpoint's DID document at `/.well-known/aroha-agent.json` (its `id` must equal `AROHA_AGENT_DID` and its `verificationMethod` must hold a usable Ed25519 key; an `@aroha-sdk/run` manifest is reported as a warning), and an unsigned round-trip.
- `aroha dev` — start a local registry and developer dashboard.
- `aroha telemetry [status|on|off]` — the CLI has no built-in telemetry endpoint and sends nothing unless you set `AROHA_TELEMETRY_ENDPOINT`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).