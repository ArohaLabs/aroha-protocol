# @aroha-sdk/langchain-bridge

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/langchain-bridge)

Use Aroha agents as LangChain / OpenAI-function tools, and expose LangChain tools as an Aroha agent.

## Install

```bash
npm install @aroha-sdk/langchain-bridge
```

## Quick example

```typescript
import { arohaCapabilityToLangChainTool, arohaCapabilityToOpenAITool } from "@aroha-sdk/langchain-bridge";
import { AgentExecutor } from "langchain/agents";

// Wrap one capability of a remote Aroha agent as a LangChain-compatible tool.
// Every call is a signed ArohaRequest from callerDID.
const flightTool = arohaCapabilityToLangChainTool("search-flights", {
  endpoint: "http://localhost:3001",
  agentDID: "did:aroha:flight-agent",
  callerDID: myDID,
  callerPrivateKey: myPrivateKey,
  description: "Search available flights by origin, destination, and date",
  schema: { type: "object", properties: { origin: { type: "string" }, destination: { type: "string" } } },
});

const executor = AgentExecutor.fromAgentAndTools({ agent, tools: [flightTool] });
const result = await executor.invoke({ input: "Find flights from AKL to NRT next Monday" });

// The same capability as an OpenAI Chat Completions function tool
const fnTool = arohaCapabilityToOpenAITool("search-flights", {
  endpoint: "http://localhost:3001",
  agentDID: "did:aroha:flight-agent",
  callerDID: myDID,
  callerPrivateKey: myPrivateKey,
  description: "Search available flights",
});
```

The bridge signs requests but does not attach a spending mandate; an agent that requires one
rejects the call.

## OpenAI function tools: what is tested

`arohaCapabilityToOpenAITool` returns a Chat Completions `tools[]` entry,
`{ type: "function", function: { name, description, parameters } }`, plus an `invoke(args)`
method. JSON serialisation drops the method, so you can pass the object to an OpenAI client as-is.
`src/openai-tool.test.ts` checks, in CI:

- **The definition follows OpenAI's function-tool rules.** The name matches `^[a-zA-Z0-9_-]{1,64}$`.
  Characters outside that set become `_`. An id longer than 64 characters is cut to 55 and given an
  8-hex-digit hash suffix. `parameters` is a JSON Schema whose top-level `type` is `"object"`, or is
  omitted when you pass no `schema`. A schema with another top-level type throws. Nothing else goes
  on the wire.
- **The definition works with the official `openai` npm client (7.x).** The test sends it in
  `chat.completions.create` to a local stub of `/v1/chat/completions` and checks the request body
  carries the definition unchanged. It takes the tool call the stub returns, runs it with `invoke()`
  against a real Aroha provider, which receives a signed `ArohaRequest`, and sends the result back
  as a `role: "tool"` message.
- **Not offered: `strict` mode.** The bridge never sets `strict`. If you set `strict: true` yourself,
  your schema must meet OpenAI's strict rules, such as `additionalProperties: false` and every
  property listed in `required`.

This is what "OpenAI function-tool compatible" means here. Any framework that accepts that
definition can use it. **AutoGen and Semantic Kernel are not tested.** Neither has a JavaScript
runtime this package plugs into, and the test suite does not run them. For the Responses API,
which takes a flat `{ type: "function", name, parameters }`, move `function`'s fields up one level.

## API

- `arohaCapabilityToLangChainTool(capabilityId, opts)` — `{ name, description, schema, call(input) }` that sends a signed `ArohaRequest`.
- `arohaCapabilityToOpenAITool(capabilityId, opts)` — the same as an OpenAI Chat Completions function tool (see above).
- `toolNameFor(capabilityId)` / `OPENAI_FUNCTION_NAME_PATTERN` — the tool-name mapping and the pattern it satisfies.
- `ArohaCapabilityToToolOptions` — `{ endpoint, agentDID, callerDID, callerPrivateKey, description, schema?, client? }`.
- `createArohaLangChainTool(endpoint, capabilityId, description, { schema?, client? })` — zero-config variant with an ephemeral caller identity and DID discovery from `/.well-known/aroha-agent.json`. Prefer the explicit form above when the target agent verifies callers.
- `langChainAgentToArohaProvider(tools, { agentDID, agentPrivateKey, port, resolvePublicKey, didDocument })` — expose LangChain tools as an `ArohaServer`.
- `langChainToolsToCapabilities(tools)` — capability descriptors for registry registration.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
