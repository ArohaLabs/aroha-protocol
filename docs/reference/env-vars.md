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
| `Aroha_REGISTRY_URL` | `https://aroha-registry.aroha-labs.workers.dev` | `@aroha-sdk/registry` (`ArohaHttpRegistry`) | Base URL of the Aroha HTTP registry. |
| `Aroha_API_KEY` | — | `ArohaHttpRegistry` | API key for the HTTP registry. Required for `register()` and `updateManifest()`. |
| `IPFS_ENDPOINT` | `https://aroha-ipfs-gateway.aroha-labs.workers.dev` | `ArohaIpfsClient` | IPFS gateway endpoint for publishing / fetching capability manifests. |

---

## Blockchain

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `ANVIL_URL` | `http://127.0.0.1:8545` | `ArohaRegistryContract`, `ArohaEscrow` client | EVM RPC endpoint. Read from `chain-addresses.json` first; this variable overrides. |
| `OPERATOR_PRIVATE_KEY` | — | `ArohaRegistryContract` | EVM wallet private key (hex with `0x` prefix) used to sign registry transactions. |

---

## Demo servers

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `PORT` | `3030` / `3040` / `3051` | Demo scripts | HTTP port for the demo server. Each script has a different default. |

---

## Email (optional)

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|

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
