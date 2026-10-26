<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# LangChain Quickstart

Use Aroha agents as native LangChain tools — without managing DIDs or private keys.

The `@aroha-sdk/langchain-bridge` package gives you:

- `createArohaLangChainTool()` — call any Aroha agent endpoint as a LangChain tool (auto-generates caller identity)
- `arohaCapabilityToOpenAITool()` — same, but as an OpenAI Chat Completions function tool (tested with the official `openai` client)
- `langChainAgentToArohaProvider()` — expose your LangChain tools as a discoverable Aroha agent

---

## Install

```bash
npm install @aroha-sdk/langchain-bridge langchain @langchain/openai
```

## Call an Aroha agent from LangChain

```typescript
import { createArohaLangChainTool } from "@aroha-sdk/langchain-bridge";
import { ChatOpenAI } from "@langchain/openai";
import { createOpenAIFunctionsAgent, AgentExecutor } from "langchain/agents";
import { pull } from "langchain/hub";

// 1. Create a tool from any Aroha agent endpoint
const flightSearch = await createArohaLangChainTool(
  "http://localhost:3001",           // Aroha agent endpoint
  "search-flights",                  // capability ID
  "Search available flights by origin, destination, and date. Returns flight options with prices."
);

const hotelSearch = await createArohaLangChainTool(
  "http://localhost:3002",
  "search-hotels",
  "Search hotels by city and check-in/check-out dates."
);

// 2. Plug them into any LangChain agent — no special wiring needed
const llm = new ChatOpenAI({ modelName: "gpt-4o", temperature: 0 });
const prompt = await pull<ChatPromptTemplate>("hwchase17/openai-functions-agent");

const agent = await createOpenAIFunctionsAgent({
  llm,
  tools: [flightSearch, hotelSearch],
  prompt,
});

const executor = AgentExecutor.fromAgentAndTools({ agent, tools: [flightSearch, hotelSearch] });

const result = await executor.invoke({
  input: "Book me the cheapest flight from NYC to Tokyo next week and a hotel near Shinjuku."
});

console.log(result.output);
```

## Expose LangChain tools as an Aroha agent

If you have existing LangChain tools and want other Aroha agents to discover and call them:

```typescript
import { langChainAgentToArohaProvider, langChainToolsToCapabilities } from "@aroha-sdk/langchain-bridge";
import { DynamicTool } from "langchain/tools";
import { generateKeyPair, generateDid } from "@aroha-sdk/core";

const myTools = [
  new DynamicTool({
    name: "summarize-document",
    description: "Summarize a document given its URL or text content.",
    func: async (input: string) => {
      const { url } = JSON.parse(input);
      // ... your summarization logic
      return JSON.stringify({ summary: "..." });
    },
  }),
];

const { privateKey, publicKey } = await generateKeyPair();   // persist this key: it is the agent's identity
const did = generateDid(publicKey);

const server = langChainAgentToArohaProvider(myTools, {
  agentDID: did,
  agentPrivateKey: privateKey,
  port: 3003,
  resolvePublicKey: async (did) => { /* ... */ },
  didDocument: { /* ... */ },
});

await server.start();
console.log(`LangChain tools now discoverable at: http://localhost:3003`);
```

## With OpenAI function tools

```typescript
import { arohaCapabilityToOpenAITool } from "@aroha-sdk/langchain-bridge";

const tool = arohaCapabilityToOpenAITool("search-flights", {
  endpoint: "http://localhost:3001",
  agentDID: "did:aroha:flight-agent",
  callerDID: "did:aroha:my-assistant",
  callerPrivateKey: myKey,
  description: "Search available flights",
  schema: {
    type: "object",
    properties: {
      origin: { type: "string" },
      destination: { type: "string" },
      date: { type: "string", format: "date" },
    },
    required: ["origin", "destination", "date"],
  },
});

// Pass `tool` in `tools`, then run the model's tool_calls with invoke()
const result = await tool.invoke({ origin: "JFK", destination: "NRT", date: "2026-08-01" });
```

## How `createArohaLangChainTool()` works

1. Generates an ephemeral Ed25519 keypair (per-process, discarded on exit)
2. Fetches `GET <endpoint>/.well-known/aroha-agent.json` to discover the agent's DID
3. Returns a LangChain `Tool`-compatible object whose `call()` method sends signed `ArohaRequest` envelopes
4. The remote agent validates the signature, runs the capability, and returns a signed `ArohaResponse`

The caller identity is ephemeral by default. For persistent identities (required for paid capabilities), pass an explicit `callerDID` and `callerPrivateKey` using the lower-level `arohaCapabilityToLangChainTool()`.

---

## Next steps

- [Browse the sandbox registry →](sandbox.md)
- [See the full bridge API →](packages/langchain-bridge.md)
- [Convert an existing LangChain app →](recipes/convert-from-langchain.md)
