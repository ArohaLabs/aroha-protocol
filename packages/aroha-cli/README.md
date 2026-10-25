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
# → prompts: name, DID, LLM provider, settlement adapter
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
# ✓ Endpoint http://localhost:3001  (did:aroha:my-agent, 2 capabilities)
# ✓ Signed round-trip  38ms

# Start local dev registry + dashboard
aroha dev
```

## Why this exists in the mandate chain

Scaffold commands produce agents that verify the full mandate chain (`verifyMandateChain()` to a configured human root) before any handler logic runs — so mandate enforcement is the default, not an afterthought. `aroha doctor` verifies that your keypair and DID are configured correctly before you issue your first mandate.

## API (commands)

- `aroha init <name>` — scaffold a new mandate-aware agent.
- `aroha convert --from mcp` — wrap an MCP server as an Aroha agent.
- `aroha doctor [endpoint]` — check Node version, env vars, endpoint reachability, and signed round-trip.
- `aroha dev` — start a local registry and developer dashboard.
- `aroha publish` — publish the agent manifest to IPFS and register on the Hub.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).