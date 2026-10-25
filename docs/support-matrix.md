<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Support Matrix

**Owner:** @projectmed99 · **Measured:** 2026-10-19 on branch `fix/audit-remediation` (after the support-gap work) · **Review:** every release, and in the same PR as any change to a row below.

What Aroha works with, and how sure we are. Every row says how it is verified — a claim with no test says so. Positioning context: [What Aroha is (and is not)](positioning.md).

| Mark | Meaning |
|---|---|
| ✅ | Implemented and covered by automated tests that run in CI |
| 🧪 | Implemented; no automated test in this repository |
| 📄 | A documented integration path, **not verified** against that product from this repository |
| ⚠️ | Partial — see the note |
| ❌ | Not supported |

> **Released 2026-10-19.** Everything on this page is published: npm (tag `npm-v2026.10.19`, 32 packages) and PyPI `aroha` 2.0.0 (tag `python-v2.0.0`). The Java SDK and Go module are not released (see [SDKs](#sdks)).

---

## At a glance

| Area | Supported today |
|---|---|
| **Languages** | TypeScript (reference) · Python (beta) · Go (partial) · Java (partial) |
| **Protocols** | MCP 2026-07-28 (stdio and Streamable HTTP + OAuth) · A2A 1.0 · OpenTelemetry (OTLP) · SSF/CAEP security events |
| **Frameworks** | LangChain · LangGraph · CrewAI · AutoGen · Google ADK · OpenAI and OpenAI Agents SDK (Python) · LangChain · Composio · OpenClaw · Hermes Agent / ZeroClaw (TypeScript) ✅ |
| **Harnesses** | Any stdio MCP client via `mcp-guard` (Claude Desktop, Claude Code, Cursor, Windsurf, Cline, Zed) · Aroha runtime (desktop) · remote MCP with enterprise sign-in (ID-JAG) and MCP Tasks ✅ — Remote-MCP hosts (ChatGPT, Codex, Meta Muse, Claude, Duet) 📄 |
| **Models** | Model-agnostic protocol. Runtime: Anthropic, OpenAI, Google Gemini, any OpenAI-compatible endpoint, and local Ollama / vLLM / LM Studio / custom URL ✅ (Gemini and custom endpoints tested against local stubs, not live services) |
| **Coding agents** | Four Agent Skills (`SKILL.md`), validated; `llms.txt` index |

---

## Integration paths — easiest first

The fastest way for an existing agent to adopt Aroha. The [`aroha-integrate`](https://github.com/ArohaLabs/aroha-protocol/blob/main/skills/aroha-integrate/SKILL.md) Agent Skill walks a coding agent through choosing and applying one, then proving the refusals.

| Path | Who it is for | Effort | What you get | Status |
|---|---|---|---|---|
| **A. Wrap an MCP server with `mcp-guard`** | Anyone using MCP tools in an assistant | Config change, no code | Block / approval gate / per-session limits on every tool; audit log | ✅ |
| **B. Verify mandates in a handler** | Owners of a tool server or API that agents call | ~10 lines | Refuse anything outside the person's signed grant, offline; holder proof over MCP (`_meta`) or plain HTTP (`Aroha-Mandate` header) | ✅ (needs the 2.x release on npm) |
| **C. Issue and present a mandate** | Agents acting on a person's behalf | ~15 lines | A narrowing, use-limited, expiring grant carried with each call | ✅ |
| **D. Run the Aroha runtime** | A person's own assistant | Install | Deny-by-default tools, approvals with saved, revocable permissions, receipts, rooms | ✅ |
| **E. Remote MCP connector** | Hosted assistants that add remote MCP servers | Deploy + OAuth provider | Aroha Hub as a remote connector | ⚠️ server ✅, per-host registration 📄 |

---

## Frameworks

| Framework | Language | Package | What it does | Status | Evidence |
|---|---|---|---|---|---|
| **MCP** (Model Context Protocol, 2026-07-28) | TS | `@aroha-sdk/mcp-bridge` | MCP tools ↔ Aroha capabilities; `wrapMcp()`; mandate carriage in `_meta["aroha/mandate"]` with holder proof | ✅ | 5 test files |
| MCP — guard | TS | `@aroha-sdk/mcp-guard` | Firewall in front of any stdio MCP server | ✅ | 2 test files |
| MCP — server | TS | `@aroha-sdk/mcp-server` | Aroha Hub as an MCP server: stdio and remote (Streamable HTTP + OAuth, CIMD, RFC 9728) | ✅ | 4 test files; [verified scope](integrations/remote-mcp-connector.md) |
| **A2A** 1.0 (Linux Foundation) | TS | `@aroha-sdk/a2a-bridge` | Message mapping, JSON-RPC client and server, signed agent cards, mandate carriage, `GetTask` / `CancelTask` | ✅ | 61 tests, including CI interop in both directions with the official `@a2a-js/sdk` 1.3.0 |
| **LangChain** / OpenAI function tools | TS | `@aroha-sdk/langchain-bridge` | Aroha capabilities as LangChain tools, and as OpenAI function tools (any framework that accepts them) | ✅ | 25 tests, including an end-to-end run through the official `openai` client |
| **Composio** | TS | `@aroha-sdk/composio-bridge` | Aroha capabilities as Composio actions | ✅ | 1 test file |
| **OpenClaw** | TS | `@aroha-sdk/openclaw-bridge` | Aroha capabilities as OpenClaw skills and back | ✅ | 1 test file |
| **Hermes Agent / ZeroClaw** | TS | `@aroha-sdk/hermes-bridge` | Aroha agents as MCP stdio servers | ✅ | 1 test file |
| **LangChain / LangGraph** | Python | `aroha.bridges.langchain_bridge`, `langchain_v1` | Capabilities as LangChain tools; wrap a chain or graph as `/v1/run` | ✅ | Tested against the real framework (langchain-core 1.6, langgraph 1.2) with stubbed models, plus framework-free tests that always run |
| **CrewAI** | Python | `aroha.bridges.crewai_bridge`, `crewai_v1` | Capabilities as CrewAI tools; wrap a Crew as `/v1/run` | ✅ | Tested against the real framework (crewai 1.15) with stubbed models, plus framework-free tests that always run |
| **AutoGen** | Python | `aroha.bridges.autogen_bridge` | Capabilities as AutoGen `FunctionTool`s | ✅ | Tested against the real framework (autogen-core / agentchat 0.7 (0.4+; legacy pyautogen 0.2 not supported)) with stubbed models, plus framework-free tests that always run |
| **Google ADK** | Python | `aroha.bridges.google_adk` | Wrap an ADK Runner as `/v1/run` | ✅ | Tested against the real framework (google-adk 2.12) with stubbed models, plus framework-free tests that always run |
| **OpenAI client / Agents SDK** | Python | `aroha.bridges.openai_v1` | Wrap an OpenAI client or Agents SDK agent as `/v1/run` | ✅ | Tested against the real framework (openai 2.54, openai-agents 0.20) with stubbed models, plus framework-free tests that always run |
| Converters (A2A, Agntcy, LangChain, MCP) | CLI | `@aroha-sdk/cli` `aroha convert --from …` | Generate an Aroha wrapper for an existing agent | ✅ | CLI template tests |

## Harnesses (where an agent runs)

| Harness | How Aroha attaches | Status | Notes |
|---|---|---|---|
| **Aroha runtime** (desktop app, Windows / macOS / Linux) | Built in | ✅ | Deny-by-default tools, standing permissions, receipts, rooms, kill switch |
| **Claude Desktop** | `mcp-guard` or `mcp-server` (stdio) | ✅ path · 📄 product | Install steps documented; the MCP stdio protocol is tested, not the Claude Desktop build |
| **Claude Code** | `mcp-guard` / `mcp-server` (stdio); Agent Skills load directly | ✅ path · 📄 product | Same: protocol tested, product not driven from CI |
| **Cursor, Windsurf, Cline, Zed** | `mcp-guard` (stdio) | ✅ path · 📄 product | Any stdio MCP client; each product not individually tested |
| **ChatGPT, Codex, OpenAI "dots"** | Remote MCP connector (plugin / Developer Mode) | 📄 | [Documented](integrations/remote-mcp-connector.md); not tested against ChatGPT |
| **Meta Muse** | Remote MCP connector (custom connector) | 📄 | Documented; not tested against Muse |
| **Claude (custom connectors), Duet** | Remote MCP connector (custom connector) | 📄 | [Documented](integrations/remote-mcp-connector.md); not tested against Claude; Duet access is by waitlist |
| **Agent-to-agent hosts (A2A)** | `a2a-bridge` server and client | ✅ | CI interop with the official A2A SDK in both directions |
| Enterprise-managed MCP auth (ID-JAG / Cross App Access) | `mcp-server` resource-server side | ✅ path · 📄 production IdPs | Tested end to end with the MCP SDK's Cross App Access provider against a reference IdP and authorization server; not yet against Okta, Entra or Keycloak. [Details](integrations/remote-mcp-connector.md) |
| MCP Tasks extension (`io.modelcontextprotocol/tasks`) | `mcp-server` (`aroha_call`) | ✅ | Per-user scoped, bounded, cancellable; polling (no task notifications); in-memory per process |

## Agents

| Agent | What it is | Status | Published |
|---|---|---|---|
| GitHub, Jira | Provider agents over the real APIs (issues, PRs, transitions) | ✅ 2 test files each | No — in repository only |
| Salesforce, Stripe, Zendesk | Proxy agents over the real APIs | ✅ 2 test files each | No — in repository only |
| Gmail MCP server | Search, read, label, draft over the ordinary Gmail API | ✅ | npm `@aroha-sdk/gmail-mcp` |
| Personal agent | Reference orchestrator | ✅ | No — reference |
| Mock provider, sandbox agents (flight, hotel, weather, web search, summarizer) | **Mock data**, for demos and tests | ✅ | Examples |

## Models

The protocol never calls a model: mandates, verification and receipts are model-agnostic and work with any model behind any framework above. The table is the **Aroha runtime's** own inference support.

| Provider / engine | How | Status | Notes |
|---|---|---|---|
| **Anthropic** (Claude) | Hosted API key | ✅ | Streaming and tool calls |
| **OpenAI** (GPT) | Hosted API key | ✅ | Streaming and tool calls |
| **Ollama** | Local, detected at `127.0.0.1:11434` | ✅ | Any model Ollama serves; tool use needs a tool-calling model |
| **vLLM** | Local, detected at `127.0.0.1:8000` (OpenAI-compatible) | ✅ | Same |
| **LM Studio** | Local, detected at `127.0.0.1:1234` (OpenAI-compatible) | ✅ | Same |
| **Google Gemini** | Hosted API key | ✅ | Streaming and tool calls; tested against a local stub of the Gemini API, not the live service |
| **Any OpenAI-compatible endpoint** (Together, Groq, OpenRouter, a company gateway…) | `openaiCompatibleBaseUrl` + key | ✅ | Bearer auth only (Azure's `api-key` header is not supported); https, or http to loopback |
| **Custom local engine URL** | `engineUrl` | ✅ | Probed before the default ports |

## SDKs

Full detail: [SDK feature matrix](sdks/feature-matrix.md).

| | TypeScript | Python | Go | Java |
|---|:---:|:---:|:---:|:---:|
| Maturity | Reference | Beta | Partial | Partial |
| Envelope sign / verify | ✅ | ✅ | ✅ | ✅ |
| Spending mandates + chain verification (v2) | ✅ | ✅ | ✅ | ✅ |
| Task mandates | ✅ | ✅ | ✅ | ✅ |
| Rotatable DIDs + Key Event Log | ✅ | ✅ | ✅ | ✅ |
| Conversation profile (rooms, consent, turns) verification | ✅ | ✅ | ✅ | ✅ |
| Registry client | ✅ | ✅ | ✅ | ✅ |
| Durable stores: nonces, enrollment, spending ledger (Postgres, Redis; one shared layout) | ✅ (unreleased) | ✅ (unreleased) | ❌ | ❌ |
| Published | npm 2.0.0 | PyPI 2.0.0 | Not released (private repository) | Not released (no Maven Central credentials) |

## Published versions

Published on 2026-10-19 (release tags `npm-v2026.10.19` and `python-v2.0.0`); verified by installing from the public registries.

| Package | Published version | Registry | Stability |
|---|---|---|---|
| `@aroha-sdk/core` | 2.0.0 | npm | Stable |
| `@aroha-sdk/credentials` | 2.0.0 | npm | Stable |
| `@aroha-sdk/run` | 2.0.0 | npm | Stable |
| `@aroha-sdk/cli` | 1.3.0 | npm | Stable |
| `create-aroha-agent` | 1.3.0 | npm | Stable |
| `@aroha-sdk/mcp-bridge` | 3.0.0 | npm | Stable |
| `@aroha-sdk/mcp-guard` | 0.2.1 | npm | Beta |
| `@aroha-sdk/mcp-server` | 2.0.0 | npm | Experimental |
| `@aroha-sdk/policy` | 1.3.1 | npm | Beta |
| `@aroha-sdk/delegation` | 0.3.0 | npm | Experimental |
| `@aroha-sdk/a2a-bridge` | 2.0.0 | npm | Experimental |
| `@aroha-sdk/langchain-bridge` | 2.0.0 | npm | Beta |
| `@aroha-sdk/composio-bridge` | 1.2.3 | npm | Experimental |
| `@aroha-sdk/openclaw-bridge` | 2.0.0 | npm | Experimental |
| `@aroha-sdk/hermes-bridge` | 1.2.5 | npm | Beta |
| `@aroha-sdk/telemetry` | 1.2.3 | npm | Beta |
| `aroha` (Python) | 2.0.0 | PyPI | Beta |

Stability tiers: [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md).

## Health metrics

Each figure is from a run on the date given; re-run before quoting.

| Metric | Value | Measured | How to reproduce |
|---|---|---|---|
| CI on the branch head | Passing | 2026-10-19, run 39269362862 | GitHub Actions `ci.yml` |
| Workspace tests (TypeScript) | 4,461 passed; 1 needs a local model | Commit `84003ae` (last full workspace run) | `npm test` |
| Runtime tests | 2,027 passed of 2,031; 1 needs a local model, 2 timing-sensitive under full-suite load (pass alone), 1 skipped | 2026-10-19, `b63aef34` | `npm test -w apps/aroha-runtime` in [`ArohaLabs/aroha-runtime`](https://github.com/ArohaLabs/aroha-runtime) |
| Conformance suite | 123 / 123 | 2026-10-19, `b63aef34` | `npx vitest run --config vitest.conformance.config.ts` |
| Python SDK tests | 476 passed (framework suites skip unless installed) | 2026-10-19 | `pytest` in `sdks/aroha-py` |
| Java SDK tests | 174 passed (TypeScript interop included) | 2026-10-19 | `mvn test` in `sdks/java` |
| Go SDK tests | 244 passed, `go vet` clean | 2026-10-19 | `go test ./...` in `sdks/go` |
| Mandate chain verification (2 links, offline) | 3.6 ms p50 · 4.4 ms p95 | 2026-10-19, developer laptop — indicative | `npm run benchmark:b6` |
| Agent Skills valid (`agentskills validate`) | 4 / 4 | 2026-10-19 | see `skills/README.md` |
| Independent implementations | 0 | — | — |
| Security audit | Not yet | — | [review scope](security/review-scope.md) |

## Gaps we know about

- Hosted assistants (ChatGPT, Codex, Muse, Claude, Duet) and individual MCP clients are documented paths, not tested products — they need accounts on those products.
- Gemini and custom OpenAI-compatible endpoints are tested against local stubs, not the live services; Azure OpenAI's `api-key` header is not supported.
- Enterprise sign-in (ID-JAG) is tested against a reference IdP, not a production one.
- MCP Tasks are polling-only and held in memory per process (several instances must route on `Mcp-Name`).
- Multi-hop task-chain verification and task receipts are TypeScript-only.
- Pre-built provider agents are not published to npm.
