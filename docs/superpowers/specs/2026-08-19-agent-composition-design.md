<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# What Composes an Agent — Design

**Date:** 2026-08-19
**Status:** Built
**Scope:** How `aroha-runtime` assembles an agent, measured against what the agent-SDK ecosystem converged on, and what is deliberately absent.

---

## 1. What the industry settled on

The ecosystem's decomposition, as of 2026, is **model + system prompt + tools (MCP) + skills + memory + sessions + permissions**, run by an agent loop with context management. Anthropic's Agent SDK composes exactly that list; OpenAI's and Google's differ in orchestration but not in the primitives.

The distinction that took longest to settle, and the one that matters most here:

> **MCP is the integration layer — what an agent can reach. Skills are the knowledge layer — how to use it well.**

A tool call *does* something. A skill *tells the model how something is done here*. Conflating them is why an earlier `SkillRecord` in this repo went nowhere: it registered a service endpoint under the name "skill", which is a directory entry, and nothing ever loaded it.

The `SKILL.md` format was opened as a public standard in December 2025 and is read by roughly forty agent products.

---

## 2. What this runtime composes

| Primitive | Where |
|---|---|
| Model | `AgentRecord.model`, `EngineManager` |
| System prompt | `AgentRecord.systemPrompt` |
| Tools | `McpManager` + `mcp-guard`, every call gated |
| **Skills** | `host/skills.ts`, open `SKILL.md` format |
| **Knowledge** | `host/knowledge.ts`, hybrid BM25 + dense with RRF |
| **Memory** | `host/memory.ts`, per person, hybrid recall |
| **Sessions** | `host/threads.ts`, append-only JSONL, per person |
| Permissions | `mcp.decide()` and HITL suspend/resume |
| Agent loop | `host/handler.ts` |
| **Context management** | `host/budget.ts` |

Plus what no general-purpose SDK carries, because they assume one owner and this does not: a DID per agent, sealed-envelope consult across organisations, mandate delegation, a hash-chained audit log, action requests gated on a signed human approval, outbound PII screening, and BBS selective disclosure.

**That is the actual distinction.** Aroha is a runtime and a protocol for agents belonging to *different* organisations that must prove who they are to each other. The SDKs are libraries for agents belonging to you. Competing with them on library ergonomics would be a losing race; nothing in the previous paragraph has an equivalent in any of them.

---

## 3. Skills

### 3.1 Discovery

```
<workspace>/skills/<name>/SKILL.md          available to every agent
<workspace>/agents/<slug>/skills/<name>/    that agent only, shadows the above
```

Agent-level shadows workspace-level by name, matching the standard's personal-over-project precedence.

### 3.2 Progressive disclosure

Descriptions are cheap and always in the system prompt so the model knows what it could reach for. Bodies are expensive and load only on use. A runtime that pasted every body into every prompt would spend the context window on instructions for tasks nobody asked about.

Both invocation paths from the standard work:

- **Model-invoked** — a built-in `load_skill` tool, offered in the same shape as an MCP tool so the existing loop needed no change to offer it.
- **User-invoked** — `/name` at the start of a message. Deterministic, and works on a model that cannot call tools at all.

### 3.3 Frontmatter honoured

`description`, `disable-model-invocation`, `user-invocable`. Unknown keys are **ignored rather than rejected**, so a skill using a field another product supports still loads here — just without that behaviour.

### 3.4 Two deliberate departures

**Dynamic context injection is not implemented.** The standard splices the stdout of a backticked command into the body before the model sees it. That is arbitrary shell execution triggered by a file, with none of the approval the MCP path demands for far less. Those lines are replaced with a visible note rather than silently dropped, so a model is not left following instructions that reference output it never received.

**A skill body does not pass through the dual-context Worker.** It is local, author-written instruction with the same standing as the system prompt; summarising it would discard the detail the model asked for. Safe because nothing on that path came from outside the workspace — which is also the limit of the claim: a skill installed from a remote source would need different handling, and that is not built.

### 3.5 Naming collision, unresolved by design

`@aroha-sdk/run` exports `registerSkill`/`SKILL_TYPES`, where "skill" means a **registry listing** — a name, a description, an endpoint. It is served by the live registry and clients depend on it, so removing it is a breaking change to a deployed service and is not made here. It is documented in place, and `skillType` in particular remains the field this spec's §3.1 called out as validated, stored, round-tripped, and read by nothing.

---

## 4. Isolated contexts, and why they are not "subagents"

Five places need to read text that may be adversarial — a tool result, another firm's answer, a user's message — and decide something about it. Each runs in its own context with its own prompt and **no tools**: the guarantee is that whatever reads attacker-influenceable text has no authority to act on it (design spec §9.1 Layer 2).

`host/isolated.ts` makes that structural rather than repeated. There is no tools parameter for a caller to pass.

**This is not the ecosystem's subagent primitive**, which spawns a full agent with its own tools, loop and budget for a subtask. Building that speculatively would mean a second agent loop to keep correct with no current caller, so it is not built. Naming this one "subagent" would overclaim.

---

## 5. What remains absent, and why

| Absent | Reasoning |
|---|---|
| **Hooks** (lifecycle callbacks) | A real primitive elsewhere. Nothing here needs one yet; the extension points that exist — MCP, skills, the guard — cover current cases. |
| **Plugins** (packaging skills + agents + hooks + MCP) | Only earns its cost once there is an ecosystem to package for. |
| **Spawned subagents** | See §4. |
| **Summarisation of trimmed history** | Deferred in the memory spec §2.5 and still deferred: a bad summary is worse than a clean gap, and the gap is now reported. |
| **Semantic memory without an embedding model** | Recall degrades to word overlap. Stated at the point of use, not implied away. |
