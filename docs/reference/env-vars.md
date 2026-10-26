<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Environment Variables

All variables are optional unless marked **required**.

---

## LLM / AI

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | demos | Claude API key. When set, enables real LLM reasoning in the demo terminal. Without it, the demo falls back to rule-based intent decomposition. |
| `VLLM_URL` | — | `chat-demo.mjs` | OpenAI-compatible endpoint for intent decomposition. Example: `http://localhost:8000/v1`. |
| `VLLM_MODEL` | `Qwen/Qwen2.5-1.5B-Instruct` | Same as above | Model name passed to the vllm API. |

---

## Registry

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `AROHA_REGISTRY_URL` | `https://aroha-registry.aroha-labs.workers.dev` | `@aroha-sdk/core/endpoints` (`resolveRegistryUrl`: `ArohaHttpRegistry`, `@aroha-sdk/micro`, `@aroha-sdk/mcp-server`), Python, Go and Java SDKs | Base URL of the Aroha HTTP registry. An explicit `baseUrl` / `registryUrl` option takes precedence. |
| `AROHA_API_KEY` | — | `@aroha-sdk/mcp-server`, `@aroha-sdk/run` (`serve` registration), Python SDK | Registry API key. `ArohaHttpRegistry` does not read it; pass `apiKey` to its constructor. |
| `AROHA_IPFS_GATEWAY` | `https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs` | `@aroha-sdk/core/endpoints` (`resolveIpfsGateway`), `@aroha-sdk/registry` agent functions, `@aroha-sdk/run` | IPFS gateway for fetching capability manifests. `ArohaIpfsClient` does not read it; pass `endpoint` to its constructor. |

---

## Agents

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `AGENT_ENDPOINT` | `http://localhost:{port}` | `@aroha-sdk/micro` | Public base URL of the agent, when the `endpoint` option is not set. |
| `NODE_ENV` | — | `@aroha-sdk/core` (`ArohaServer`) | `devMode: true` is refused at `start()` unless this is `development`. |

---

## Blockchain

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `ANVIL_URL` | `http://127.0.0.1:8545` | `scripts/setup-chain.mjs` | EVM RPC endpoint the setup script deploys to; written into `chain-addresses.json`. `ArohaRegistryContract` does not read it; pass `rpcUrl` to its constructor. |

---

## Demo servers

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `PORT` | `3050` / `3040` | `scripts/chat-demo.mjs` / `scripts/vc-demo.mjs` | HTTP port for the demo server. Each script has a different default. |

---

## Email (optional)

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `GMAIL_USER` | — | `scripts/chat-demo.mjs` | Gmail address for the demo's email step. |
| `GMAIL_APP_PASSWORD` | — | `scripts/chat-demo.mjs` | Gmail app password for `GMAIL_USER`. |

---

## Setting variables

=== "Shell (temporary)"

    ```bash
    ANTHROPIC_API_KEY=sk-ant-... npm run demo:vc
    ```

=== ".env file (not tracked)"

    ```bash
    # Create .env at project root
    echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
    # Load with a tool like dotenv-cli:
    npx dotenv -e .env npm run demo:vc
    ```

=== "WSL / Linux export"

    ```bash
    export ANTHROPIC_API_KEY=sk-ant-...
    npm run demo:vc
    ```
