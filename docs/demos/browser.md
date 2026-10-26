<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Browser Demos

Three browser-based experiences are available, each targeting a different audience. All run locally; none needs a hosted service.

> The saga, settlement and on-chain parts of these demos use optional extensions, not the core protocol ([extensions document](../spec/extensions.md), [positioning](../positioning.md)). For the core mandate flow, run `npm run demo:mandate` (no network, no server).

---

## Agent Playground — learn the protocol

The simplest entry point. Write a capability handler in JavaScript, click **Run**, and watch real Ed25519-signed envelopes fly between two in-browser agents.

```bash
open examples/playground/index.html
# No server needed — double-click the file
```

**Features:**

- Two code editors: capability handler (JS) + request (JSON)
- Real `@noble/ed25519` key generation + signing in your browser
- Full signed `ArohaRequest` → verification → handler execution → signed `ArohaResponse`
- Syntax-highlighted envelope JSON with Ed25519 proof value in amber
- `Ctrl+Enter` / `Cmd+Enter` to run
- Zero server, zero build step, zero API key

[Full playground guide →](playground.md)

---

---

## vc-demo — Multi-agent saga demo

The cleanest, most self-contained demo. Four in-process agents with real Ed25519 identities,
human-in-the-loop bookings, and live SSE protocol trace.

```bash
node scripts/vc-demo.mjs
# Open: http://localhost:3040
```

**Features:**

- Two selectable scenarios — toggle between them at the top of the page
- **Scenario 1 — Travel Booking:** 4 agents (Personal, Flight, Hotel, Payment) book a Tokyo business trip atomically across 3 providers
- **Scenario 2 — Enterprise IT Incident Response:** DevOps Agent uses GitHub + Jira agents to open an incident ticket and tracking issue; saga pauses for human rollback approval before committing
- Real signed Aroha envelopes — inspect every Ed25519 proof
- Human-in-the-loop: flight/hotel selection, payment confirmation, rollback approval
- SSE real-time protocol trace — every message as it happens
- Post-saga explorer: navigate each agent's decisions and message log
- Scenario 2 shows `InMemoryRegistry` (no blockchain) and HITL approval gate in action

No blockchain, no IPFS, no API key required.

Override port:
```bash
PORT=3040 node scripts/vc-demo.mjs
```

---

## chat-demo — Full blockchain demo (optional on-chain extensions)

The most complete demo. Requires Anvil (local EVM) + vllm (optional).

```bash
# Step 1: Start Anvil
anvil

# Step 2: Deploy contracts
node scripts/setup-chain.mjs

# Step 3 (optional): Start vllm
python3 -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-1.5B-Instruct --port 8000 --enforce-eager

# Step 4: Start demo
VLLM_URL=http://localhost:8000/v1 PORT=3051 node scripts/chat-demo.mjs
# Open: http://localhost:3051
```

**Features:**

- Per-agent thinking panels (FL / HT / PY agents reasoning in real-time)
- Live blockchain activity log (ArohaRegistry, ArohaEscrow, ArohaReputation)
- Aroha Protocol modal explaining architecture layers and smart contract methods
- Send any prompt to trigger a full multi-agent saga with on-chain settlement

Try: `Book me a business trip to Tokyo May 1–7`

---

## Demo comparison

| Feature | Playground | terminal (`demo:vc`) | browser (`vc-demo`) | browser (`chat-demo`) |
|---------|-----------|---------------------|---------------------|-----------------------|
| Server required | No | No | Yes | Yes |
| Blockchain | No | No | No | Yes (Anvil) |
| LLM required | No | No | No | No (vllm optional) |
| Human-in-the-loop | No | No | Yes (both scenarios) | Yes |
| On-chain settlement | No | No | No | Yes |
| Enterprise IT scenario | No | No | Yes (Scenario 2) | No |
| GitHub + Jira agents | No | No | Yes (Scenario 2) | No |
| Code editable | Yes | No | No | No |
| Best for | Learning / experimenting | CI / quick demo | End-to-end walkthroughs | Technical deep-dives |
