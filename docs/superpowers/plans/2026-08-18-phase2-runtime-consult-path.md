# Phase 2 Stage 1: Runtime Consult Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give aroha-runtime a real "consult" capability — an agent can answer a question from another agent (inbound) and can ask one of its own (outbound) — built entirely on the primitives already published in Phase 1 (`@aroha-sdk/core`'s loop guard, `@aroha-sdk/policy`'s outbound screener). This is the foundational slice of the runtime's internal-consult-design spec; later stages (audit persistence, operator console, action-request/signed-approval, quotas, chat UI, human identity) build on top of it and are planned separately once this lands.

**Architecture:** `buildConsultHandler` answers an inbound consult with a bounded, tainted-from-turn-one, reversible-tools-only tool loop — a parallel code path to `buildHandler`'s chat loop, not a modification of it, because a consult is one request/response (`ConsultResult`), not a chat stream. `consult-compose.ts` builds the outbound question from a conversation, mirroring the isolated-Worker-context shape `extractWithWorker` already established. Both wire into the existing LAN/relay transports by branching on `body.capability`, exactly where those transports already branch on `"chat"` vs. everything else.

**Tech Stack:** TypeScript, vitest, `@aroha-sdk/core` (consult primitives, already published at 1.7.0), `@aroha-sdk/policy` (OutboundScreener, published at 1.3.0).

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §4 (consult path), §9 (build order steps 1–2)

## Global Constraints

- Copyright header on every new file: `// Copyright (c) 2026 Aroha Labs` / `// SPDX-License-Identifier: Apache-2.0`
- Real infrastructure over mocks, matching `lan-server.test.ts`'s own convention: real `ArohaServer`, real sealed/signed envelopes over real HTTP, real `McpManager` against the real test-server fixture. Only the LLM (`EngineManager`) is faked.
- `@aroha-sdk/core` is already a runtime dependency at `^1.5.0` — the caret range covers the published `1.7.0`, so `npm install` (not a manual version bump) is what pulls the new consult exports in.
- `@aroha-sdk/policy` is NOT yet a runtime dependency — add it.
- Consult-triggered tool calls are tier ≤ 2 and `reversibility: "full"` only, **refused, not escalated** (design spec §4.2) — a `"block"` `ToolDecision`, never `"gate"`. Unmapped tools fail closed via `getRiskTier`'s own default (tier 5 for anything not in `CAPABILITY_TAXONOMY`), so most third-party MCP tools will be refused during a consult unless explicitly mapped — a real, disclosed limitation, not a bug to route around.
- The consulted agent receives the caller's **constructed question only** — never conversation history. Composition happens on the CALLER's side before the request is sent; the answering side just answers `params.question`.
- Every consult-driven tool call is tainted **from the first call**, unlike chat's session-taint-after-first-tool-result model (`handler.ts`'s `tainted` starts `false`) — a consult's `question` is externally sourced content from the moment it arrives, so there is no "first trusted turn" the way a local user's own first chat message is trusted.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/mcp/manager.ts` | *Modify* — add `requireReversible` policy to `decide()`/`callTool()` |
| `apps/aroha-runtime/src/host/consult-handler.ts` | *Create* — `buildConsultHandler`, the inbound answering path |
| `apps/aroha-runtime/src/host/consult-compose.ts` | *Create* — `composeQuestion`, the outbound question-construction path |
| `apps/aroha-runtime/src/transport/lan-server.ts` | *Modify* — route `body.capability === "consult"` |
| `apps/aroha-runtime/src/transport/relay-client.ts` | *Modify* — same routing, relay transport |
| `apps/aroha-runtime/src/transport/consult-client.ts` | *Create* — `sendConsult`, composes + screens + sends an outbound consult over LAN |
| `apps/aroha-runtime/package.json` | *Modify* — add `@aroha-sdk/policy` dependency |

---

## Task 1: Tier/reversibility tool-call restriction in McpManager

**Files:**
- Modify: `apps/aroha-runtime/src/mcp/manager.ts`
- Test: `apps/aroha-runtime/src/mcp/manager.test.ts`

**Interfaces:**
- Produces: `McpManager.decide(name, { tainted?, requireReversible? })` and `McpManager.callTool(name, args, { tainted?, requireReversible?, preApproved? })` — both gain the new `requireReversible` option, consumed by Task 3's `buildConsultHandler`.

- [ ] **Step 1: Write the failing tests**

Add to `apps/aroha-runtime/src/mcp/manager.test.ts`, inside a new top-level `describe`:

```ts
describe("McpManager — requireReversible (design spec §4.2)", () => {
  beforeEach(async () => {
    const ws = ensureWorkspace(resolveWorkspace(root));
    manager = new McpManager(new McpRegistry(ws));
    await manager.install({ name: "fixture", command: process.execPath, args: [fixture] });
  });

  afterEach(async () => {
    await manager.uninstall("fixture");
  });

  it("refuses a tool with no taxonomy entry (fail-closed on unmapped tools)", () => {
    // "add" and "explode" (the fixture's tools) are not in CAPABILITY_TAXONOMY,
    // so getRiskTier defaults to 5 — refused, not merely gated.
    const decision = manager.decide("fixture__add", { requireReversible: true });
    expect(decision.action).toBe("block");
    expect(decision.reason).toContain("reversible");
  });

  it("refuses rather than gates — a consult never gets an approval prompt for this", () => {
    const decision = manager.decide("fixture__add", { requireReversible: true });
    expect(decision.action).not.toBe("gate");
  });

  it("does not restrict a normal (non-consult) call", () => {
    const decision = manager.decide("fixture__add");
    expect(decision.action).toBe("allow");
  });

  it("callTool refuses the same way decide() does, without executing", async () => {
    const result = await manager.callTool("fixture__add", { a: 1, b: 2 }, { requireReversible: true });
    expect(result.isError).toBe(true);
    expect(result.text).toContain("reversible");
  });

  it("allows a tool explicitly mapped to tier <= 2 and full reversibility", () => {
    // "web-search" is tier 1 / reversibility "full" in CAPABILITY_TAXONOMY.
    // The fixture has no such tool, so this exercises decide() directly
    // against a taxonomy-known name without requiring a matching server.
    const decision = manager.decide("fixture__web-search" as string, { requireReversible: true });
    // Un-namespaced name is "web-search" once split — taxonomy match succeeds
    // even though no server named "fixture" actually exposes it; decide()
    // only checks connectivity for the SERVER half of the namespaced name.
    expect(decision.action).toBe("allow");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/aroha-runtime && npx vitest run src/mcp/manager.test.ts`
Expected: FAIL — `requireReversible` is not a recognised option; TypeScript will actually refuse to compile the test until Step 3 adds it, so this "fails" at the type-check stage, which is the correct RED for an interface-first change.

- [ ] **Step 3: Implement**

In `apps/aroha-runtime/src/mcp/manager.ts`, add the import and helper near `isHighRiskCapability`:

```ts
import { CAPABILITY_TAXONOMY, getRiskTier, getReversibility } from "@aroha-sdk/core";
```

```ts
/**
 * Design spec §4.2 — a consult is semantically a read. Tool calls it
 * triggers are restricted to tier <= 2 and full reversibility, REFUSED
 * (not gated) outside that. Unknown tools fail closed: getRiskTier
 * defaults unmapped capabilities to tier 5, so most third-party MCP tools
 * are refused during a consult unless explicitly added to
 * CAPABILITY_TAXONOMY — a real, disclosed limitation.
 */
function isConsultSafe(toolName: string): boolean {
  return getRiskTier(toolName) <= 2 && getReversibility(toolName) === "full";
}
```

Update `decide()`'s signature and body:

```ts
  decide(namespacedName: string, opts?: { tainted?: boolean; requireReversible?: boolean }): ToolDecision {
    const sep = namespacedName.indexOf("__");
    if (sep === -1) {
      return { action: "block", reason: `Malformed tool name (expected "server__tool"): ${namespacedName}` };
    }
    const serverName = namespacedName.slice(0, sep);
    const toolName = namespacedName.slice(sep + 2);
    if (!this.connections.has(serverName)) {
      return { action: "block", reason: `No connected MCP server named "${serverName}"` };
    }

    if (opts?.requireReversible && !isConsultSafe(toolName)) {
      return {
        action: "block",
        reason: `Tool "${toolName}" is not permitted during a consult — restricted to tier <= 2, ` +
                `fully reversible capabilities (design spec §4.2), and this tool is either unmapped ` +
                `or exceeds that (tier ${getRiskTier(toolName)}, reversibility "${getReversibility(toolName)}").`,
      };
    }

    const tainted = opts?.tainted ?? false;
    const decision = this.guard.decide(toolName, { tainted });

    if (decision.action === "allow" && tainted && isHighRiskCapability(toolName)) {
      return {
        action: "gate",
        reason: `Tool "${toolName}" is a high-risk capability and this call may have been influenced by untrusted content (design spec §9.1 Layer 3)`,
      };
    }
    return decision;
  }
```

Update `callTool()`'s `opts` type to match (it already forwards `opts` into `decide(namespacedName, opts)`, so no body change beyond the type):

```ts
  async callTool(
    namespacedName: string,
    args: Record<string, unknown>,
    opts?: { tainted?: boolean; requireReversible?: boolean; preApproved?: boolean },
  ): Promise<McpToolResult> {
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/aroha-runtime && npx vitest run src/mcp/manager.test.ts`
Expected: PASS, all tests including pre-existing ones.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/mcp/manager.ts apps/aroha-runtime/src/mcp/manager.test.ts
git commit -m "feat(runtime): tier/reversibility tool restriction for consults

Design spec §4.2: a consult is semantically a read. decide()/callTool()
gain requireReversible, refusing (never gating) any tool call above
tier 2 or short of full reversibility. Unknown tools fail closed via
getRiskTier's own tier-5 default for unmapped capabilities."
```

---

## Task 2: Add @aroha-sdk/policy dependency

**Files:**
- Modify: `apps/aroha-runtime/package.json`

- [ ] **Step 1: Add the dependency**

In `apps/aroha-runtime/package.json`'s `dependencies`, add (alphabetical, matching the existing list's ordering):

```json
    "@aroha-sdk/policy": "^1.3.0",
```

- [ ] **Step 2: Install and verify**

Run: `cd "<repo root>" && npm install`
Expected: lockfile updates, no errors. Then: `cd apps/aroha-runtime && npx tsc -p tsconfig.json --noEmit` — expected clean (nothing imports it yet, so this just proves the install resolved).

- [ ] **Step 3: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/package.json package-lock.json
git commit -m "chore(runtime): add @aroha-sdk/policy — needed for the outbound consult screener"
```

---

## Task 3: Inbound consult handler

**Files:**
- Create: `apps/aroha-runtime/src/host/consult-handler.ts`
- Test: `apps/aroha-runtime/src/host/consult-handler.test.ts`

**Interfaces:**
- Consumes: `EngineManager.chat(model, messages, opts): AsyncGenerator<ChatChunk>` (existing, see `handler.ts`); `McpManager.tools()`, `McpManager.decide()`, `McpManager.callTool()` (Task 1's extended shape); `ConsultParams`, `ConsultResult`, `ConsultSource` from `@aroha-sdk/core`.
- Produces: `buildConsultHandler(agent, engine, mcp?): (params: ConsultParams) => Promise<ConsultResult>`, consumed by Task 5/6's transport wiring.

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { buildConsultHandler } from "./consult-handler.js";
import type { AgentRecord } from "./store.js";
import type { EngineManager } from "../engine/manager.js";
import type { McpManager } from "../mcp/manager.js";
import type { ChatChunk } from "../engine/types.js";
import type { ConsultParams } from "@aroha-sdk/core";

const agent: AgentRecord = {
  slug: "answerer", did: "did:aroha:zANSWERER", name: "Answerer",
  systemPrompt: "Answer briefly and factually.", model: "test-model",
  createdAt: new Date().toISOString(),
};

function fakeEngine(reply: string): EngineManager {
  return {
    async *chat(): AsyncGenerator<ChatChunk> {
      yield { type: "delta", text: reply };
      yield { type: "done" };
    },
  } as unknown as EngineManager;
}

const baseParams: ConsultParams = {
  question: "What is our standard vendor payment term?",
  hopCount: 1,
  consultChain: ["did:aroha:zASKER"],
};

describe("buildConsultHandler", () => {
  it("answers the constructed question with no tools configured", async () => {
    const handler = buildConsultHandler(agent, fakeEngine("Net 30."));
    const result = await handler(baseParams);
    expect(result.answer).toBe("Net 30.");
    expect(result.sources).toEqual([]);
  });

  it("never sees conversation history — only the constructed question reaches the model", async () => {
    const seen: unknown[] = [];
    const engine = {
      async *chat(model: string, messages: unknown[]) {
        seen.push(messages);
        yield { type: "delta", text: "ok" };
        yield { type: "done" };
      },
    } as unknown as EngineManager;
    await buildConsultHandler(agent, engine)(baseParams);
    const messages = seen[0] as Array<{ role: string; content: string }>;
    // System prompt + exactly the constructed question — nothing else.
    expect(messages).toHaveLength(2);
    expect(messages[1].content).toBe(baseParams.question);
  });

  it("returns a behaviourHash so a prompt/model change is detectable (design spec §11.3)", async () => {
    const handler = buildConsultHandler(agent, fakeEngine("Net 30."));
    const result = await handler(baseParams);
    expect(result.behaviourHash).toMatch(/^[0-9a-f]{16}$/);

    const changedAgent = { ...agent, systemPrompt: "Answer differently." };
    const result2 = await buildConsultHandler(changedAgent, fakeEngine("Net 30."))(baseParams);
    expect(result2.behaviourHash).not.toBe(result.behaviourHash);
  });
});

describe("buildConsultHandler — tool restriction (design spec §4.2)", () => {
  it("taints every tool call from the first one, unlike chat's session-taint model", async () => {
    let sawTainted: boolean | undefined;
    let sawRequireReversible: boolean | undefined;
    const engine = {
      async *chat(model: string, messages: unknown[], opts: { tools?: unknown[] }) {
        if (opts.tools && opts.tools.length > 0) {
          yield { type: "tool_call", call: { id: "1", function: { name: "fixture__lookup", arguments: "{}" } } };
        } else {
          yield { type: "delta", text: "Net 30, per the lookup." };
        }
        yield { type: "done" };
      },
    } as unknown as EngineManager;

    const mcp = {
      tools: async () => [{ type: "function", function: { name: "fixture__lookup" } }],
      decide: (name: string, opts?: { tainted?: boolean; requireReversible?: boolean }) => {
        sawTainted = opts?.tainted;
        sawRequireReversible = opts?.requireReversible;
        return { action: "allow" as const };
      },
      callTool: async () => ({ isError: false, text: "payment term: net 30" }),
    } as unknown as McpManager;

    await buildConsultHandler(agent, engine, mcp)(baseParams);
    expect(sawTainted).toBe(true);
    expect(sawRequireReversible).toBe(true);
  });

  it("records sources from every tool call made", async () => {
    let toolCalled = false;
    const engine = {
      async *chat(model: string, messages: unknown[], opts: { tools?: unknown[] }) {
        if (!toolCalled) {
          toolCalled = true;
          yield { type: "tool_call", call: { id: "1", function: { name: "fixture__lookup", arguments: "{}" } } };
        } else {
          yield { type: "delta", text: "Net 30." };
        }
        yield { type: "done" };
      },
    } as unknown as EngineManager;

    const mcp = {
      tools: async () => [{ type: "function", function: { name: "fixture__lookup" } }],
      decide: () => ({ action: "allow" as const }),
      callTool: async () => ({ isError: false, text: "payment term: net 30" }),
    } as unknown as McpManager;

    const result = await buildConsultHandler(agent, engine, mcp)(baseParams);
    expect(result.sources).toEqual([{ tool: "fixture__lookup", summary: expect.any(String) }]);
  });

  it("a refused tool call does not crash the consult — the model gets told and can still answer", async () => {
    let attempted = false;
    const engine = {
      async *chat(model: string, messages: unknown[], opts: { tools?: unknown[] }) {
        if (!attempted) {
          attempted = true;
          yield { type: "tool_call", call: { id: "1", function: { name: "fixture__delete", arguments: "{}" } } };
        } else {
          yield { type: "delta", text: "I could not check that, but generally: net 30." };
        }
        yield { type: "done" };
      },
    } as unknown as EngineManager;

    const mcp = {
      tools: async () => [{ type: "function", function: { name: "fixture__delete" } }],
      decide: () => ({ action: "block" as const, reason: "not reversible" }),
      callTool: async () => { throw new Error("must not execute a blocked call"); },
    } as unknown as McpManager;

    const result = await buildConsultHandler(agent, engine, mcp)(baseParams);
    expect(result.answer).toContain("net 30");
    expect(result.sources).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/aroha-runtime && npx vitest run src/host/consult-handler.test.ts`
Expected: FAIL — no module `./consult-handler.js`.

- [ ] **Step 3: Implement**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Answers an inbound consult (design spec §4). A parallel code path to
 * buildHandler, not a variant of it: a consult is one request/response
 * (ConsultResult), never a chat stream, and it starts from a CONSTRUCTED
 * question, never conversation history — the composer that builds that
 * question runs on the CALLER's side (consult-compose.ts) before the
 * request is ever sent here.
 *
 * Tool calls are tainted from the FIRST call, not after the first tool
 * round the way buildHandler's chat loop works — a consult's question is
 * externally sourced content from the moment it arrives, so there is no
 * "first trusted turn" the way a local user's own opening chat message is
 * trusted. Every call also carries requireReversible: true (design spec
 * §4.2) — refused outright above tier 2 or short of full reversibility,
 * never escalated to a human gate, because there is no human on this side
 * of a background consult to gate to.
 */

import { createHash } from "node:crypto";
import type { ConsultParams, ConsultResult, ConsultSource } from "@aroha-sdk/core";
import type { EngineManager } from "../engine/manager.js";
import type { McpManager } from "../mcp/manager.js";
import type { AgentRecord } from "./store.js";
import type { ChatMessage } from "../engine/types.js";

const MAX_TOOL_ITERATIONS = 8;

/**
 * A stable fingerprint of which prompt/model answered (design spec §11.3 —
 * "behavioural versioning"). Detectable, not preventable: a department
 * changing its agent's prompt or model silently changes every consumer's
 * results, and this makes the change visible after the fact in the audit
 * record rather than invisible.
 */
function behaviourHash(agent: AgentRecord): string {
  return createHash("sha256")
    .update(`${agent.model}\u0000${agent.systemPrompt}`)
    .digest("hex")
    .slice(0, 16);
}

export function buildConsultHandler(
  agent: AgentRecord,
  engine: EngineManager,
  mcp?: McpManager,
): (params: ConsultParams) => Promise<ConsultResult> {
  return async function answerConsult(params: ConsultParams): Promise<ConsultResult> {
    const messages: ChatMessage[] = [
      { role: "system", content: agent.systemPrompt },
      { role: "user", content: params.question },
    ];

    const tools = mcp ? await mcp.tools() : [];
    const sources: ConsultSource[] = [];

    for (let iteration = 0; iteration < MAX_TOOL_ITERATIONS; iteration++) {
      let answer = "";
      const pendingCalls: Array<{ id: string; name: string; args: string }> = [];

      for await (const chunk of engine.chat(agent.model, messages, { tools })) {
        if (chunk.type === "delta") {
          answer += chunk.text;
        } else if (chunk.type === "tool_call") {
          pendingCalls.push({
            id: chunk.call.id,
            name: chunk.call.function.name,
            args: chunk.call.function.arguments,
          });
        }
      }

      if (pendingCalls.length === 0) {
        return { answer, sources, behaviourHash: behaviourHash(agent) };
      }

      if (!mcp) {
        throw new Error("model requested a tool call but no MCP manager is configured");
      }

      messages.push({
        role: "assistant",
        content: "",
        tool_calls: pendingCalls.map((c) => ({
          id: c.id,
          type: "function" as const,
          function: { name: c.name, arguments: c.args },
        })),
      });

      for (const call of pendingCalls) {
        let args: Record<string, unknown>;
        try {
          args = JSON.parse(call.args || "{}") as Record<string, unknown>;
        } catch {
          args = {};
        }

        // Refused, not escalated (design spec §4.2) — there is no human on
        // a background consult to escalate to, so a "gate"-worthy call is
        // simply not made; the model is told why and can still answer with
        // whatever it already knows.
        const decision = mcp.decide(call.name, { tainted: true, requireReversible: true });
        let resultText: string;
        if (decision.action !== "allow") {
          resultText = `Tool call refused: ${decision.reason}`;
        } else {
          const result = await mcp.callTool(call.name, args, { tainted: true, requireReversible: true });
          resultText = result.text;
          if (!result.isError) {
            sources.push({ tool: call.name, summary: result.text });
          }
        }

        messages.push({ role: "tool", content: resultText, tool_call_id: call.id });
      }
    }

    return {
      answer: `I was unable to produce a final answer within ${MAX_TOOL_ITERATIONS} tool-call rounds.`,
      sources,
      behaviourHash: behaviourHash(agent),
    };
  };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/aroha-runtime && npx vitest run src/host/consult-handler.test.ts`
Expected: PASS, all 6 tests.

**Note on Step 3's implementation vs. the "sources" test:** the source summary in this handler is the raw tool result text, not a Worker-extracted summary (unlike `buildHandler`'s dual-context Layer 2 pattern). This is a deliberate, disclosed simplification for this task — revisit when Stage 2 (audit) is built, since an unextracted raw tool result in `sources` is itself untrusted content now flowing into the audit log and into the caller's context. Flag this explicitly in the commit message so it is not silently forgotten.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/host/consult-handler.ts apps/aroha-runtime/src/host/consult-handler.test.ts
git commit -m "feat(runtime): inbound consult handler

buildConsultHandler answers a constructed question (never conversation
history) with a bounded, reversible-tools-only tool loop, tainted from
the first call rather than after the first tool round the way chat's
session-taint model works -- a consult's question is externally sourced
from the moment it arrives.

behaviourHash fingerprints the agent's prompt/model so a silent change
is detectable after the fact (design spec S11.3).

Known simplification, flagged for the audit-log stage: sources carry the
raw tool result text, not a Worker-extracted summary the way buildHandler's
dual-context loop produces -- revisit once that content starts flowing
into a persisted audit log."
```

---

## Task 4: Outbound consult composer

**Files:**
- Create: `apps/aroha-runtime/src/host/consult-compose.ts`
- Test: `apps/aroha-runtime/src/host/consult-compose.test.ts`

**Interfaces:**
- Consumes: `EngineManager.chat()`
- Produces: `composeQuestion(engine, model, conversation, domainHint?): Promise<string>`, consumed by Task 6's `sendConsult`.

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { composeQuestion, COMPOSER_SYSTEM_PROMPT } from "./consult-compose.js";
import type { EngineManager } from "../engine/manager.js";
import type { ChatChunk } from "../engine/types.js";
import type { ChatMessage } from "../engine/types.js";

function fakeEngine(reply: string, capture?: ChatMessage[][]): EngineManager {
  return {
    async *chat(model: string, messages: ChatMessage[]): AsyncGenerator<ChatChunk> {
      capture?.push(messages);
      yield { type: "delta", text: reply };
      yield { type: "done" };
    },
  } as unknown as EngineManager;
}

describe("composeQuestion", () => {
  it("returns the composed question", async () => {
    const out = await composeQuestion(
      fakeEngine("What is the standard vendor payment term?"),
      "test-model",
      [{ role: "user", content: "what do we normally pay vendors on" }],
    );
    expect(out).toBe("What is the standard vendor payment term?");
  });

  it("runs in an isolated context with its own system prompt", async () => {
    const captured: ChatMessage[][] = [];
    await composeQuestion(
      fakeEngine("q?", captured), "test-model",
      [{ role: "user", content: "x" }],
    );
    expect(captured[0][0]).toEqual({ role: "system", content: COMPOSER_SYSTEM_PROMPT });
  });

  it("drops system messages from the transcript it composes from", async () => {
    const captured: ChatMessage[][] = [];
    await composeQuestion(
      fakeEngine("q?", captured), "test-model",
      [
        { role: "system", content: "INTERNAL SYSTEM PROMPT" },
        { role: "user", content: "a question" },
      ],
    );
    expect(JSON.stringify(captured[0])).not.toContain("INTERNAL SYSTEM PROMPT");
  });

  it("includes the domain hint when given", async () => {
    const captured: ChatMessage[][] = [];
    await composeQuestion(
      fakeEngine("q?", captured), "test-model",
      [{ role: "user", content: "x" }], "finance",
    );
    expect(JSON.stringify(captured[0])).toContain("finance");
  });

  it("falls back to the last user message when the model returns nothing", async () => {
    const out = await composeQuestion(
      fakeEngine("   "), "test-model",
      [{ role: "user", content: "what are the payment terms" }],
    );
    expect(out).toBe("what are the payment terms");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/aroha-runtime && npx vitest run src/host/consult-compose.test.ts`
Expected: FAIL — no module `./consult-compose.js`.

- [ ] **Step 3: Implement**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Turns a conversation into one question worth asking another agent
 * (design spec §4.1) — the TypeScript mirror of doc-intel's
 * consult_compose.py, same isolated-Worker-context shape as
 * extractWithWorker in handler.ts: its own system prompt, no tools, and
 * only its output crosses the boundary. This is the data-minimisation
 * step — a constructed question is materially more answerable than a raw
 * transcript fragment, and it is what keeps conversation history,
 * identity, and unrelated context from ever leaving this agent.
 */

import type { EngineManager } from "../engine/manager.js";
import type { ChatMessage } from "../engine/types.js";

export const COMPOSER_SYSTEM_PROMPT =
  "You turn a conversation into ONE self-contained question to ask another " +
  "agent. Output only the question — no preamble, no explanation, no " +
  "quotation marks. The other agent has no access to this conversation, so " +
  "the question must stand entirely on its own. Include only what is needed " +
  "to answer it. Never include personal data, names, contact details, " +
  "account numbers, or internal identifiers unless they are essential to the " +
  "question itself.";

export async function composeQuestion(
  engine: EngineManager,
  model: string,
  conversation: ChatMessage[],
  domainHint?: string,
): Promise<string> {
  const usable = conversation.filter(
    (m) => (m.role === "user" || m.role === "assistant") && m.content,
  );
  const transcript = usable.map((m) => `${m.role}: ${m.content}`).join("\n");
  const prefix = domainHint ? `Subject area: ${domainHint}\n\n` : "";

  const messages: ChatMessage[] = [
    { role: "system", content: COMPOSER_SYSTEM_PROMPT },
    { role: "user", content: `${prefix}Conversation:\n${transcript}\n\nThe question to ask:` },
  ];

  let composed = "";
  for await (const chunk of engine.chat(model, messages, {})) {
    if (chunk.type === "delta") composed += chunk.text;
  }
  composed = composed.trim();
  if (composed) return composed;

  for (let i = usable.length - 1; i >= 0; i--) {
    if (usable[i].role === "user") return usable[i].content.trim();
  }
  return "";
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/aroha-runtime && npx vitest run src/host/consult-compose.test.ts`
Expected: PASS, all 5 tests.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/host/consult-compose.ts apps/aroha-runtime/src/host/consult-compose.test.ts
git commit -m "feat(runtime): outbound consult question composer

TS mirror of doc-intel's consult_compose.py, same isolated-Worker-context
shape handler.ts's extractWithWorker already established. Falls back to
the last user message when the model returns nothing usable -- sending
the user's own words beats sending an empty question."
```

---

## Task 5: Wire "consult" into the LAN transport

**Files:**
- Modify: `apps/aroha-runtime/src/transport/lan-server.ts`
- Test: `apps/aroha-runtime/src/transport/lan-server.test.ts`

**Interfaces:**
- Consumes: `buildConsultHandler` (Task 3), `checkConsultLoop`, `ConsultLoopState` from `@aroha-sdk/core`.

- [ ] **Step 1: Write the failing tests**

Append to `apps/aroha-runtime/src/transport/lan-server.test.ts`. This file already has `makeLanAgent`, `fakeEngine`, `freePort` helpers and imports `buildEnvelope`, `sealEnvelope`, `generateContentAddressedDID` — reuse them. Add:

```ts
import { ArohaClient, checkConsultLoop, type ArohaRequestBody } from "@aroha-sdk/core";
import type { ConsultParams } from "@aroha-sdk/core";

describe("startLanListener — consult capability", () => {
  it("answers a well-formed consult request", async () => {
    const port = freePort();
    const { agent, publicKey } = await makeLanAgent(port, "Net 30.");
    const asker = await generateContentAddressedDID("lan://asker");

    const client = new ArohaClient();
    const params: ConsultParams = {
      question: "What is the standard vendor payment term?",
      hopCount: 1, consultChain: [asker.did],
    };
    const body: ArohaRequestBody = { capability: "consult", params: params as unknown as Record<string, unknown> };
    const request = await buildEnvelope("ArohaRequest", asker.did, agent.did, body, crypto.randomUUID(), asker.privateKey, 120);
    const reply = await client.send(`http://127.0.0.1:${port}`, request, { timeoutMs: 5000 });

    expect(reply?.body.capability).toBe("consult");
    const result = (reply?.body as { result: { answer: string } }).result;
    expect(result.answer).toBe("Net 30.");
  });

  it("refuses a consult that loops back to this agent", async () => {
    const port = freePort();
    const { agent } = await makeLanAgent(port, "should not be reached");
    const asker = await generateContentAddressedDID("lan://asker");

    const client = new ArohaClient();
    const params: ConsultParams = {
      question: "x", hopCount: 1, consultChain: [agent.did],
    };
    const body: ArohaRequestBody = { capability: "consult", params: params as unknown as Record<string, unknown> };
    const request = await buildEnvelope("ArohaRequest", asker.did, agent.did, body, crypto.randomUUID(), asker.privateKey, 120);
    const reply = await client.send(`http://127.0.0.1:${port}`, request, { timeoutMs: 5000 });

    expect(reply?.type).toBe("ArohaError");
    expect((reply?.body as { code: string }).code).toBe("Aroha_FORBIDDEN");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/aroha-runtime && npx vitest run src/transport/lan-server.test.ts`
Expected: FAIL — the listener refuses `capability: "consult"` with `UnknownCapability` today.

- [ ] **Step 3: Implement**

In `lan-server.ts`, add imports:

```ts
import { checkConsultLoop, type ConsultParams } from "@aroha-sdk/core";
import { buildConsultHandler } from "../host/consult-handler.js";
```

Replace the capability check inside `onMessage`:

```ts
      const body = envelope.body as ArohaRequestBody;
      if (body.capability !== "chat" && body.capability !== "consult") {
        respond(await buildEnvelope(
          "ArohaError",
          agent.did,
          envelope.from,
          {
            code: ArohaErrorCode.UnknownCapability,
            message: `Unknown capability "${body.capability}" — this LAN listener only serves "chat" and "consult"`,
            retryable: false,
          },
          envelope.correlationId,
          privateKey,
        ));
        return;
      }

      if (body.capability === "consult") {
        const params = body.params as unknown as ConsultParams;
        const loop = checkConsultLoop(
          { hopCount: params.hopCount, consultChain: params.consultChain },
          agent.did,
        );
        if (!loop.ok) {
          respond(await buildEnvelope(
            "ArohaError", agent.did, envelope.from,
            { code: ArohaErrorCode.Forbidden, message: loop.reason, retryable: false },
            envelope.correlationId, privateKey,
          ));
          return;
        }
        const result = await buildConsultHandler(agent, opts.engine, opts.mcp)(params);
        respond(await buildEnvelope(
          "ArohaResponse", agent.did, envelope.from,
          { capability: "consult", result },
          envelope.correlationId, privateKey,
        ));
        return;
      }
```

(The existing chat-handling body follows unchanged, now reached only for `body.capability === "chat"`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/aroha-runtime && npx vitest run src/transport/lan-server.test.ts`
Expected: PASS, all tests including pre-existing ones.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/transport/lan-server.ts apps/aroha-runtime/src/transport/lan-server.test.ts
git commit -m "feat(runtime): serve the consult capability over LAN

Free gate first: checkConsultLoop runs before any model call, so a
looping or over-deep chain is refused with Aroha_FORBIDDEN before the
answering agent's model or tools are ever touched."
```

---

## Task 6: Wire "consult" into the relay transport

**Files:**
- Modify: `apps/aroha-runtime/src/transport/relay-client.ts`
- Test: `apps/aroha-runtime/src/transport/relay-client.test.ts`

Mirror Task 5 exactly — `relay-client.ts` has the identical `if (body.capability !== "chat")` guard and hardcoded chat handling per the codebase audit. Apply the same diff shape.

- [ ] **Step 1: Write the failing tests** — same two cases as Task 5's Step 1, adapted to this file's existing test setup/helpers (read the file first; it mirrors `lan-server.test.ts`'s structure per the earlier audit, but confirm exact helper names before writing rather than assuming they're identical).

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — same shape as Task 5 Step 3, applied to `relay-client.ts`.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/transport/relay-client.ts apps/aroha-runtime/src/transport/relay-client.test.ts
git commit -m "feat(runtime): serve the consult capability over the relay transport

Same wiring as the LAN listener (previous commit) -- checkConsultLoop
before any model call, refused with Aroha_FORBIDDEN on a loop or
over-deep chain."
```

---

## Task 7: Outbound consult sending

**Files:**
- Create: `apps/aroha-runtime/src/transport/consult-client.ts`
- Test: `apps/aroha-runtime/src/transport/consult-client.test.ts`

**Interfaces:**
- Consumes: `composeQuestion` (Task 4), `OutboundScreener` from `@aroha-sdk/policy`, `nextConsultHop` from `@aroha-sdk/core`, `ArohaClient`/`buildEnvelope` from `@aroha-sdk/core`.
- Produces: `sendConsult(opts): Promise<{ result?: ConsultResult; redactions: string[]; refused?: string }>` — the primitive Stage 2's chat-UI "invite an agent" affordance will call; this task covers the primitive and its tests only, not the UI trigger.

- [ ] **Step 1: Write the failing test**

Real two-node round trip, matching this codebase's own testing convention (`lan-server.test.ts`'s "real infrastructure, not mocks"): start a real `startLanListener` as the target, then call `sendConsult` against it.

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateContentAddressedDID } from "@aroha-sdk/core";
import { startLanListener, type LanListenerHandle } from "./lan-server.js";
import { sendConsult } from "./consult-client.js";
import type { AgentRecord } from "../host/store.js";
import type { EngineManager } from "../engine/manager.js";
import type { ChatChunk } from "../engine/types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let handle: LanListenerHandle | undefined;
afterEach(async () => { if (handle) { await handle.stop(); handle = undefined; } });

function freePort(): number { return 19900 + Math.floor(Math.random() * 90); }

function fakeEngine(reply: string): EngineManager {
  return {
    async *chat(): AsyncGenerator<ChatChunk> {
      yield { type: "delta", text: reply };
      yield { type: "done" };
    },
  } as unknown as EngineManager;
}

describe("sendConsult", () => {
  it("composes, screens, sends, and returns the remote answer", async () => {
    const port = freePort();
    const targetIdentity = await generateContentAddressedDID("lan://target");
    const target: AgentRecord = {
      slug: "target", did: targetIdentity.did, name: "Target",
      systemPrompt: "answer briefly", model: "test-model", createdAt: new Date().toISOString(),
    };
    handle = await startLanListener({
      agents: [{ agent: target, privateKey: targetIdentity.privateKey }],
      port, engine: fakeEngine("Net 30."),
    });

    const asker = await generateContentAddressedDID("lan://asker");
    const outcome = await sendConsult({
      engine: fakeEngine("What is the standard vendor payment term?"),
      model: "test-model",
      conversation: [{ role: "user", content: "what do we normally pay vendors on" }],
      askerDid: asker.did,
      askerPrivateKey: asker.privateKey,
      targetDid: target.did,
      targetEndpoint: `http://127.0.0.1:${port}`,
      hopCount: 0,
      consultChain: [],
    });

    expect(outcome.result?.answer).toBe("Net 30.");
    expect(outcome.redactions).toEqual([]);
  });

  it("redacts PII from the composed question before sending", async () => {
    const port = freePort();
    const targetIdentity = await generateContentAddressedDID("lan://target2");
    const target: AgentRecord = {
      slug: "target2", did: targetIdentity.did, name: "Target",
      systemPrompt: "answer briefly", model: "test-model", createdAt: new Date().toISOString(),
    };
    let seenQuestion = "";
    handle = await startLanListener({
      agents: [{ agent: target, privateKey: targetIdentity.privateKey }],
      port,
      engine: {
        async *chat(model: string, messages: Array<{ content: string }>) {
          seenQuestion = messages[messages.length - 1]?.content ?? "";
          yield { type: "delta", text: "ok" };
          yield { type: "done" };
        },
      } as unknown as EngineManager,
    });

    const asker = await generateContentAddressedDID("lan://asker2");
    await sendConsult({
      engine: fakeEngine("Chase the invoice for jane@example.com"),
      model: "test-model",
      conversation: [{ role: "user", content: "x" }],
      askerDid: asker.did, askerPrivateKey: asker.privateKey,
      targetDid: target.did, targetEndpoint: `http://127.0.0.1:${port}`,
      hopCount: 0, consultChain: [],
    });

    expect(seenQuestion).not.toContain("jane@example.com");
  });

  it("refuses locally without any network call when the hop limit is already exceeded", async () => {
    const asker = await generateContentAddressedDID("lan://asker3");
    const outcome = await sendConsult({
      engine: fakeEngine("should not be called"),
      model: "test-model",
      conversation: [{ role: "user", content: "x" }],
      askerDid: asker.did, askerPrivateKey: asker.privateKey,
      targetDid: "did:aroha:zUNREACHABLE",
      targetEndpoint: "http://127.0.0.1:1", // nothing listens here
      hopCount: 3, consultChain: ["a", "b", "c"],
    });

    expect(outcome.refused).toBeTruthy();
    expect(outcome.result).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/aroha-runtime && npx vitest run src/transport/consult-client.test.ts`
Expected: FAIL — no module `./consult-client.js`.

- [ ] **Step 3: Implement**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Sends an outbound consult (design spec §4): composes a self-contained
 * question from the local conversation, screens it for structured PII,
 * checks the loop guard BEFORE any network call (free gate first — a
 * local check costs nothing, a network round trip does), then sends it
 * to the target agent and returns its answer.
 */

import { ArohaClient, buildEnvelope, checkConsultLoop, nextConsultHop } from "@aroha-sdk/core";
import { createOutboundScreener } from "@aroha-sdk/policy";
import type { ConsultParams, ConsultResult } from "@aroha-sdk/core";
import { composeQuestion } from "../host/consult-compose.js";
import type { EngineManager } from "../engine/manager.js";
import type { ChatMessage } from "../engine/types.js";

const screener = createOutboundScreener();

export interface SendConsultOptions {
  engine: EngineManager;
  model: string;
  conversation: ChatMessage[];
  domainHint?: string;
  askerDid: string;
  askerPrivateKey: Uint8Array;
  targetDid: string;
  targetEndpoint: string;
  hopCount: number;
  consultChain: string[];
}

export interface SendConsultOutcome {
  result?: ConsultResult;
  redactions: string[];
  /** Set when the consult was refused, locally or remotely, instead of answered. */
  refused?: string;
}

export async function sendConsult(opts: SendConsultOptions): Promise<SendConsultOutcome> {
  const { hopCount, consultChain } = nextConsultHop(opts.hopCount, opts.consultChain, opts.askerDid);
  const loop = checkConsultLoop({ hopCount, consultChain: opts.consultChain }, opts.askerDid);
  if (!loop.ok) {
    return { redactions: [], refused: loop.reason };
  }

  const composed = await composeQuestion(opts.engine, opts.model, opts.conversation, opts.domainHint);
  const screened = screener.screen(composed);

  const params: ConsultParams = {
    question: screened.text, domainHint: opts.domainHint,
    hopCount, consultChain,
  };

  const client = new ArohaClient();
  const request = await buildEnvelope(
    "ArohaRequest", opts.askerDid, opts.targetDid,
    { capability: "consult", params: params as unknown as Record<string, unknown> },
    crypto.randomUUID(), opts.askerPrivateKey, 120,
  );

  let reply;
  try {
    reply = await client.send(opts.targetEndpoint, request, { timeoutMs: 60_000 });
  } catch (e) {
    return { redactions: screened.redactions.map((r) => r.category), refused: `Could not reach the target agent: ${(e as Error).message}` };
  }

  if (!reply || reply.type === "ArohaError") {
    const message = (reply?.body as { message?: string } | undefined)?.message ?? "The target agent refused the consult.";
    return { redactions: screened.redactions.map((r) => r.category), refused: message };
  }

  const result = (reply.body as { result: ConsultResult }).result;
  return { result, redactions: screened.redactions.map((r) => r.category) };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/aroha-runtime && npx vitest run src/transport/consult-client.test.ts`
Expected: PASS, all 3 tests.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/transport/consult-client.ts apps/aroha-runtime/src/transport/consult-client.test.ts
git commit -m "feat(runtime): outbound consult sending

Composes, screens, and sends -- checking the loop guard locally BEFORE
any network call, since a local check costs nothing and a round trip
does. Real two-node test: a genuine startLanListener as the target, not
a mock."
```

---

## Task 8: Full verification

- [ ] **Step 1: Runtime suite**

Run: `cd "<repo root>/apps/aroha-runtime" && npx vitest run`
Expected: every test passes, including every pre-existing one — this proves the chat path is untouched.

- [ ] **Step 2: Build**

Run: `cd "<repo root>" && npm run build`
Expected: clean.

- [ ] **Step 3: Full monorepo suite**

Run: `cd "<repo root>" && npm test`
Expected: clean.

- [ ] **Step 4: Commit any final fixups, then stop.** Do not push without checking in first — this stage is a coherent, working slice, but the remaining roadmap items below (particularly the audit log, which the design spec calls "from day one, not retrofitted") are a natural point for the user to review before continuing.

---

## Roadmap — not part of this plan

Per the design spec's own build order (§14), planned in detail as follow-up plans once this stage lands and is reviewed:

2. **Audit log** — extend `packages/aroha-audit`'s existing `AuditLog` (hash-chained, currently in-memory only) with disk persistence and new `AuditEventType`s for consult/action-request/admin events; add it as a runtime dependency; wire every consult outcome (answered, loop-refused, tool-refused, error) into it from both `lan-server.ts` and `relay-client.ts`. Revisit Task 3's disclosed simplification (raw tool-result text in `sources`) here, since that content will start flowing into a persisted log.
3. **Operator console** — `/v1/admin/*` routes in `gateway/server.ts` (paginated audit log, per-correlationId chain trace, quota status, kill switch, CSV/JSON export), gated behind the existing bearer token initially.
4. **Human identity Phase 1** — named local users (`aroha user add/list/revoke`), extending `gateway/guard.ts`'s single-token model to resolve an identity rather than a boolean, so `approvedByDid` can be populated. Gates the action-request path for any regulated deployment; should be built in parallel with or just before it.
5. **Action-request path** — the signed-approval flow, reusing `signInvariants`/`verifySignedInvariants`/`verifyInvariants` from `@aroha-sdk/credentials` (already implemented and published). Needs: the wire message shape, a pending-approval response, `/v1/resume`-style suspension for the requesting side, idempotency-key tracking, and `ArohaCommitEvidence`-shaped confirmation. Currently `lan-server.ts`/`relay-client.ts` hard-code `decision: "reject"` for any inbound approval on a background connection — this stage is what replaces that for action requests specifically.
6. **Quotas + triage** — per-caller-DID sliding window, `Aroha_CAPACITY_EXCEEDED`, and a cheap isolated-context triage classifier for "too vague, ask for clarification" (same Layer 2 pattern as the Worker/composer).
7. **Chat UI affordances** — in `ui/page.ts`: an invite-agent dialog wired to `sendConsult`, attributed/visually-distinct consult contributions in the transcript, and a real approve/reject UI at the `evt.type === "approval_required"` hook point that currently only logs the event as text.

Deferred further out, each substantial enough to need its own spec-to-plan cycle when picked up: OIDC/SSO (human-identity spec Phase 2), per-user approval keys (Phase 3), the Svelte UI rebuild, cross-thread memory/summarisation, and BBS+ selective attribute disclosure.
