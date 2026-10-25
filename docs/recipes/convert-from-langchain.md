<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Recipe: Converting a LangChain Agent to Aroha

LangChain agents orchestrate LLM calls and tool use. Aroha wraps each LangChain
**Tool** as a discoverable Aroha capability and optionally wraps the agent's
**chain / executor** as an orchestrator.

Supported frameworks: LangChain.js (TypeScript), LangChain (Python).

---

## Option A — CLI scaffold (fastest)

```bash
aroha convert \
  --from langchain \
  --name my-lc-agent-aroha \
  --port 3001 \
  --language typescript \
  --out ./my-lc-agent-aroha

cd my-lc-agent-aroha
npm install
```

Then edit **`src/tools.ts`** to register your LangChain tools:

```typescript
import { TavilySearchResults } from "@langchain/community/tools/tavily_search";
import { Calculator } from "@langchain/community/tools/calculator";

export async function getTools() {
  return [
    new TavilySearchResults({ maxResults: 5 }),
    new Calculator(),
  ];
}
```

```bash
npm run dev
# Each tool is now a Aroha capability:
#   web-search  (from TavilySearchResults)
#   calculator  (from Calculator)
```

---

## Option B — Native TypeScript conversion

### Step 1 — Scaffold

```bash
aroha init my-agent --type provider --port 3001
cd my-agent
npm install langchain @langchain/core @langchain/openai
```

### Step 2 — Map tools to capabilities

Each `StructuredTool` becomes one Aroha capability:

| LangChain | Aroha |
|-----------|------|
| `tool.name` (snake_case) | capability ID (kebab-case) |
| `tool.description` | capability description |
| `tool.schema` (Zod) | `inputSchema` (JSON Schema) |
| `tool.invoke(input)` | `ArohaRequest` handler |

```typescript
// src/handlers.ts
import { TavilySearchResults } from "@langchain/community/tools/tavily_search";

const searchTool = new TavilySearchResults({ maxResults: 5 });

case "ArohaRequest": {
  const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };

  if (capability === "web-search") {
    // LangChain tools accept string or object input
    const result = await searchTool.invoke(params.query as string);
    return buildEnvelope("ArohaResponse", agentDID, from,
      { capability, result: { text: result } },
      correlationId, privateKey);
  }
}
```

### Step 3 — Register capabilities in the manifest

Convert the Zod schema to JSON Schema for the Aroha manifest:

```typescript
// src/manifest.ts
import { zodToJsonSchema } from "zod-to-json-schema";
import { TavilySearchResults } from "@langchain/community/tools/tavily_search";

const searchTool = new TavilySearchResults({ maxResults: 5 });

{
  id: "web-search",
  version: "1.0.0",
  description: searchTool.description,
  inputSchema: zodToJsonSchema(searchTool.schema) as Record<string, unknown>,
  outputSchema: { type: "object", properties: { text: { type: "string" } } },
  async: false,
  maxResponseMs: 10_000,
  requiredTrustLevel: 1,
  pricing: { model: "free" },
  sagaRole: "none",
}
```

### Step 4 — Expose a LangChain chain as an orchestrator

If your LangChain **chain** (not just tools) should be accessible via Aroha,
expose it as a separate capability:

```typescript
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "langchain/agents";

const llm = new ChatOpenAI({ model: "gpt-4o-mini" });
const agent = createReactAgent({ llm, tools: myTools });

case "ArohaRequest": {
  if (capability === "run-agent") {
    const { query } = params as { query: string };
    const agentResult = await agent.invoke({ input: query });
    return buildEnvelope("ArohaResponse", agentDID, from,
      { capability, result: { output: agentResult.output } },
      correlationId, privateKey);
  }
}
```

---

## Option C — Python LangChain with Aroha Python SDK

Use the Aroha Python SDK (`sdks/python/`) to wrap Python LangChain agents.

### Setup

```bash
cd sdks/python
pip install -e .
```

### Wrap a LangChain tool

```python
from aroha import ArohaServer, generate_did, build_envelope, ArohaErrorCode
from langchain_community.tools import TavilySearchResults

search = TavilySearchResults(max_results=5)

async def handle_message(envelope, respond):
    body = envelope["body"]
    if envelope["type"] == "ArohaRequest":
        cap = body["capability"]
        params = body["params"]

        if cap == "web-search":
            result = await search.ainvoke(params.get("query", ""))
            reply = await build_envelope(
                "ArohaResponse", agent_did, envelope["from"],
                {"capability": cap, "result": {"text": result}},
                envelope["correlationId"], private_key
            )
            respond(reply)
            return

        reply = await build_envelope(
            "ArohaError", agent_did, envelope["from"],
            {"code": ArohaErrorCode.UNKNOWN_CAPABILITY, "message": f"Unknown: {cap}", "retryable": False},
            envelope["correlationId"], private_key
        )
        respond(reply)

identity = generate_did("my-lc-agent", "http://localhost:3001/aroha/v1")
server = ArohaServer(agent_did=identity["did"], did_document=identity["document"], port=3001, on_message=handle_message)
await server.start()
```

### Wrap a LangChain AgentExecutor (Python)

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")
agent_executor = AgentExecutor(agent=create_react_agent(llm, tools), tools=tools)

if cap == "run-agent":
    agent_result = await agent_executor.ainvoke({"input": params["query"]})
    reply = await build_envelope("ArohaResponse", ..., {"capability": cap, "result": {"output": agent_result["output"]}}, ...)
```

---

## LangChain → Aroha capability ID conventions

```
LangChain name   →  Aroha capability ID
─────────────────────────────────────────
"tavily_search"  →  "tavily-search"
"calculator"     →  "calculator"
"web_browser"    →  "web-browser"
"sql_database"   →  "sql-database"
```

The CLI adapter handles this automatically via `toolNameToCapability()` in `src/tools.ts`.

---

## Saga support for LangChain tools

LangChain tools are stateless — they don't natively support reserve/commit/cancel.

For tools that touch external state (databases, APIs), add saga handlers manually:

```typescript
case "ArohaReserve": {
  if (capability === "send-email") {
    // Draft the email and hold it (don't send yet)
    const draftId = await emailService.createDraft(params);
    const token = `RES-${crypto.randomUUID()}`;
    drafts.set(token, { draftId, expiresAt: new Date(Date.now() + holdDurationMs) });
    return buildEnvelope("ArohaReserveAck", ...);
  }
}
case "ArohaCommit": {
  const draft = drafts.get(reservationToken);
  if (!draft?.committed) {
    draft!.committed = true;
    await emailService.sendDraft(draft!.draftId);  // send only on commit
  }
  return buildEnvelope("ArohaCommitAck", ...);
}
case "ArohaCancel": {
  const draft = drafts.get(reservationToken);
  if (draft) await emailService.deleteDraft(draft.draftId);
  drafts.delete(reservationToken);
  return buildEnvelope("ArohaCancelAck", ...);
}
```

---

## See also

- [General conversion recipe](./converting-existing-agents.md)
- [Generated wrapper source](../../packages/aroha-cli/src/templates/converters/langchain.ts)
- [Aroha Python SDK](https://github.com/ArohaLabs/aroha-protocol/tree/main/sdks/aroha-py)
- [Aroha spec](../spec/aroha-1.0.md)
