# Phase 3 Stage 1: Cross-Thread Memory

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** An agent remembers durable facts across conversations, and a person can see and delete everything it remembers about them.

The memory spec removed `Capabilities.memory` as a dead flag rather than leaving a promise unkept, and named the condition for bringing it back: *"it needs an extraction step, a store, a retrieval step, and — importantly — a way for a user to see and delete what the agent remembered about them. That last part is not optional in a product handling client data, which is exactly why it should not be smuggled in behind a boolean."*

So the visibility and deletion routes are not a follow-up task here. They ship in the same stage as the storing, or the stage does not ship.

**Architecture:** Extraction runs in the isolated-context shape this codebase already uses three times (`extractWithWorker`, `composeQuestion`, `triageQuestion`): its own system prompt, no tools, and only its output crosses back. Facts live in a per-agent JSON file beside the agent's manifest. Retrieval is lexical overlap, not embeddings — stated plainly rather than implied to be smarter than it is.

**Tech Stack:** TypeScript, vitest, the existing `EngineManager` and workspace conventions.

**Spec:** [../specs/2026-08-18-memory-and-capability-honesty-design.md](../specs/2026-08-18-memory-and-capability-honesty-design.md) §3.3

## Global Constraints

- Copyright header on new files.
- **Off by default, per agent.** Extraction costs a model call per turn, and an agent that quietly starts retaining what people tell it is a worse default than one that forgets. Reintroducing the flag is only honest if the flag now does something — and if it starts off.
- **Every stored fact is inspectable and deletable**, individually and in bulk. This is the condition the spec set.
- **Extraction is an isolated context.** It reads conversation text to decide what to keep; that is the §9.1 Layer 2 shape, and it gets no tools.
- **Retrieval is lexical and must say so.** No embedding infrastructure exists here. Calling a keyword overlap "semantic memory" would be the same overclaiming the flag removal was meant to end.
- **A fact records which thread it came from**, so a person reading their memory can see where the agent got it.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/host/memory.ts` | *Create* — `MemoryStore`: durable facts per agent, list/forget |
| `apps/aroha-runtime/src/host/memory-extract.ts` | *Create* — `extractFacts`, isolated-context extraction |
| `apps/aroha-runtime/src/host/store.ts` | *Modify* — `memory?: boolean` on `AgentRecord` |
| `apps/aroha-runtime/src/host/handler.ts` | *Modify* — retrieve before the turn, extract after |
| `apps/aroha-runtime/src/gateway/server.ts` | *Modify* — memory routes |

---

## Task 1: MemoryStore

**Files:** Create `src/host/memory.ts` + test.

```ts
export interface MemoryFact {
  id: string;
  text: string;
  /** Which conversation it was learned from — provenance a person can follow. */
  sessionId: string;
  learnedAt: string;
}

export class MemoryStore {
  constructor(ws: Workspace, slug: string);
  remember(facts: string[], sessionId: string): MemoryFact[];
  all(): MemoryFact[];
  recall(query: string, limit?: number): MemoryFact[];
  forget(id: string): boolean;
  forgetAll(): number;
}
```

- Stored at `agents/<slug>/memory.json`, beside the manifest — deleting an agent takes its memory with it, which is the behaviour a person deleting an agent would expect.
- **Deduplicate on exact text.** An agent told the same thing in four threads should hold one fact, not four.
- **Cap the store** (500 facts, oldest evicted). Unbounded memory is unbounded prompt cost and an unbounded pile of personal data.
- `recall` scores by overlap of lowercased word tokens, ties broken by recency.

- [x] **Tests:** round-trip and persistence across instances; dedupe; cap with oldest-first eviction; recall ranks an overlapping fact above an unrelated one; recall returns nothing for no overlap; forget one; forget all; provenance survives.

- [x] Commit.

---

## Task 2: Extraction

**Files:** Create `src/host/memory-extract.ts` + test.

```ts
export const MEMORY_SYSTEM_PROMPT: string;
export async function extractFacts(
  engine: EngineManager, model: string, conversation: ChatMessage[],
): Promise<string[]>;
```

The prompt asks for durable facts about the user or their work — stable preferences, roles, project names — one per line, and explicitly NOT: anything transient, anything the assistant itself said, and anything the conversation only speculated about.

**Returns an empty list on anything unparseable or on a model failure.** Extraction is an enhancement; a bad extraction pass must not fail the turn the user actually asked for. It fails open in the sense of not blocking, and closed in the sense of storing nothing.

- [x] **Tests:** parses a line list; drops blanks and bullet punctuation; returns `[]` for an explicit "NONE"; returns `[]` when the engine throws; runs with its own system prompt and no tools; ignores system messages in the conversation it reads.

- [x] Commit.

---

## Task 3: Wire into the chat loop

**Files:** `handler.ts`, `store.ts`

- `AgentRecord` gains `memory?: boolean`, default false.
- When enabled: before the turn, `recall(userMessage)` and prepend what it finds to the system prompt under a heading that says plainly it is remembered from earlier conversations.
- After the turn completes, extract from the exchange and store.
- **Extraction must not delay the response.** The user's answer is already streamed; extraction runs after and its failure is logged, never surfaced as a turn failure.

- [x] **Tests:** disabled by default — no extra model call, nothing stored; enabled — recalled facts appear in the system prompt; enabled — facts are stored after the turn; an extraction failure does not fail the turn.

- [x] Commit.

---

## Task 4: See and delete — the condition

**Files:** `server.ts` (+ test)

| Route | Purpose |
|---|---|
| `GET /v1/agents/:slug/memory` | Everything this agent remembers, with provenance |
| `DELETE /v1/agents/:slug/memory/:id` | Forget one fact |
| `DELETE /v1/agents/:slug/memory` | Forget everything |

- [x] Tests through a real gateway: list shows stored facts; deleting one leaves the rest; deleting all empties it; an unknown agent is 404; an unknown fact id is 404 rather than a silent success.

- [x] Commit.

---

## Task 5: Verification

- [x] Runtime suite, build, monorepo tests, push, CI.
- [x] Update the memory spec: §3.3 built, with the limitations below.

---

## Disclosed limitations

- **Retrieval is lexical, not semantic.** "What did I say about the budget?" will not recall a fact phrased as "Q3 forecast" unless a word matches. Embeddings would fix it and are not built.
- **Extraction is a model's judgement.** It will keep things that do not matter and miss things that do. The store is visible and editable precisely because it will be wrong.
- **Facts are stored as written.** If a user tells an agent something sensitive and memory is on, that text sits in `memory.json` under the workspace — protected by file mode, not encrypted. The deletion routes are the mitigation, and the flag is off by default.
- **No per-user partitioning.** Memory belongs to the AGENT, so on a shared install everyone talking to that agent contributes to and reads the same store. That is wrong for a multi-user deployment and is why this pairs badly with OIDC mode until it is fixed.
