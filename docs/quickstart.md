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

    Add one import to your MCP server:

    ```typescript
    import { wrapMcp } from "@aroha-sdk/mcp-bridge";

    const agent = await wrapMcp(server.listTools(), {
      name: "my-tools",
      price: 0.01,  // optional: charge per call
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
│   └── manifest.ts    # capability definitions
├── .env               # AROHA_AGENT_DID=did:aroha:my-booking-agent
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
[my-booking-agent] DID: did:aroha:my-booking-agent
[my-booking-agent] Endpoint: http://localhost:3001/aroha/v1
[my-booking-agent] Capabilities: search-items, book-item
[my-booking-agent] Ready ✓
```

### 3 — Implement your handlers

Open `src/handlers.ts`. Each capability is a typed async function:

```typescript
export const handlers: CapabilityHandlers = {
  "search-items": async ({ query, limit = 10 }) => {
    // Replace with your real data source
    return { items: [{ id: "1", name: query, price: 99 }] };
  },

  "book-item": async ({ itemId, userId }) => {
    // Replace with your booking logic
    return { bookingId: crypto.randomUUID(), status: "confirmed" };
  },
};
```

### 4 — Test it

```bash
# Check your agent's DID document
curl http://localhost:3001/.well-known/aroha-agent.json

# Send a test request (the CLI handles signing for you)
npx @aroha-sdk/cli call http://localhost:3001 search-items '{"query":"flights"}'
```

---

## Run the full demo

Want to see multi-agent sagas, payments, and rollback in action?

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd aroha && npm install && npm run build
npm run demo:vc
```

This runs two scenarios (~35 seconds):

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

    Add one line to your existing MCP server to monetize it.

    [MCP Quickstart →](quickstart-mcp.md)

-   :material-language-python: **LangChain developers**

    ---

    Use Aroha agents as native LangChain tools.

    [LangChain Quickstart →](quickstart-langchain.md)

-   :material-store: **Sandbox registry**

    ---

    Try pre-built agents from the public Aroha sandbox.

    [Sandbox →](sandbox.md)

-   :material-sitemap: **Architecture**

    ---

    Learn how the six protocol layers fit together.

    [Architecture →](architecture.md)

</div>
