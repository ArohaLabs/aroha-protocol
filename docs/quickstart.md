<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Quickstart

Get your first Aroha agent running in under 5 minutes.
No blockchain, no GPU, no API keys required.

## Choose your path

=== "npx (fastest)"

    ```bash
    npx create-aroha-agent my-agent
    cd my-agent && npm install && npm run dev
    ```

    That's it. Your agent is running at `http://localhost:3001/aroha/v1`.

    Open `src/handlers.ts` and replace the stub implementations with your logic.

=== "Existing MCP server"

    Wrap your MCP tools:

    ```typescript
    import { wrapMcp, registryPublicKeyResolver } from "@aroha-sdk/mcp-bridge";

    const agent = await wrapMcp(tools, {
      name: "my-tools",
      resolvePublicKey: registryPublicKeyResolver(),       // who may call (required)
      handlers: { "my-tool": async (args) => myTool(args) }, // one per tool name (required)
    });
    await agent.start();
    // Your MCP tools are now an Aroha agent at http://localhost:3001
    ```

    Full guide: [MCP Quickstart →](quickstart-mcp.md)

=== "LangChain"

    Call any Aroha agent as a LangChain tool:

    ```typescript
    import { createArohaLangChainTool } from "@aroha-sdk/langchain-bridge";

    const tool = await createArohaLangChainTool(
      "http://localhost:3001",
      "search-flights",
      "Search available flights by origin, destination, and date"
    );
    // Use `tool` with createOpenAIFunctionsAgent, AgentExecutor, etc.
    ```

    Full guide: [LangChain Quickstart →](quickstart-langchain.md)

---

## npx path — step by step

### 1 — Scaffold

```bash
npx create-aroha-agent my-booking-agent
```

This generates a complete agent project in `./my-booking-agent/`:

```
my-booking-agent/
├── src/
│   ├── server.ts      # ArohaServer setup
│   ├── handlers.ts    # ← your business logic goes here
│   ├── identity.ts    # loads (or generates) the agent's Ed25519 key
│   ├── mandate.ts     # mandate chain verification
│   └── manifest.ts    # capability definitions
├── .env               # AROHA_AGENT_DID=did:aroha:my-booking-agent, AROHA_PRIVATE_KEY (filled on first run)
├── README.md
├── package.json
└── tsconfig.json
```

### 2 — Install and start

```bash
cd my-booking-agent
npm install
npm run dev
```

Expected output:

```
[my-booking-agent] Aroha endpoint : http://localhost:3001/aroha/v1
[my-booking-agent] DID document  : http://localhost:3001/.well-known/aroha-agent.json
[my-booking-agent] DID           : did:aroha:my-booking-agent
```

On the first run the agent also generates a private key and saves it to `.env`.

### 3 — Implement your handlers

Open `src/handlers.ts`. `handleMessage` dispatches on the envelope type. Read-only
capabilities (`search-…`, `list-…`, `get-…`) have a `case` in `handleRequest`; the
others (`book-item`) have a `case` in `handleReserve`, with `handleCommit` and
`handleCancel` completing the saga. Replace each `// TODO` with your logic:

```typescript
case "search-items": {
  // TODO: replace with your business logic
  const result = { items: [], message: "No results yet — implement search-items" };
  return buildEnvelope("ArohaResponse", agentDID, from,
    { capability, result },
    correlationId, privateKey);
}
```

### 4 — Test it

```bash
# Check your agent's DID document
curl http://localhost:3001/.well-known/aroha-agent.json

# Check the environment and that the endpoint answers
npx @aroha-sdk/cli doctor http://localhost:3001
```

---

## Run the full demo

Want to see multi-agent sagas, payments, and rollback in action?

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd aroha-protocol && npm install && npm run build
npm run demo:vc
```

This runs two scripted terminal scenarios with simulated agents (~35 seconds):

!!! example "Scenario 1 — Travel Saga"
    PersonalAgent books a Tokyo trip atomically across FlightAgent and HotelAgent.
    Demonstrates multi-party saga, atomic rollback, and AI-driven orchestration.

!!! example "Scenario 2 — Hedge Fund Analyst"
    HedgeFundAgent pays $0.20 to TwitterScraperMCP for real-time BTC sentiment.
    Demonstrates micro-payments, MCP bridge, and machine-to-machine data commerce.

!!! tip "Enable real Claude reasoning"
    ```bash
    ANTHROPIC_API_KEY=sk-ant-... npm run demo:vc
    ```

---

## Next steps

<div class="grid cards" markdown>

-   :material-api: **MCP server authors**

    ---

    Expose your existing MCP tools as an Aroha agent.

    [MCP Quickstart →](quickstart-mcp.md)

-   :material-language-python: **LangChain developers**

    ---

    Use Aroha agents as native LangChain tools.

    [LangChain Quickstart →](quickstart-langchain.md)

-   :material-store: **Sandbox registry**

    ---

    Run a local sandbox registry and the pre-built mock agents.

    [Sandbox →](sandbox.md)

-   :material-sitemap: **Architecture**

    ---

    Learn how the protocol layers fit together.

    [Architecture →](architecture.md)

</div>
