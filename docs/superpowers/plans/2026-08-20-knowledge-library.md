<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Knowledge Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store documents once in a workspace library and let each agent select the subset it retrieves from, migrating existing per-agent documents without losing any.

**Architecture:** A `KnowledgeLibrary` owns every document and chunk for the workspace at `~/.aroha/knowledge/`. Each `AgentRecord` gains a `documentIds` selection. `BuiltinProvider` retrieves over the library filtered by that selection, so retrieval stays agent-scoped while storage does not. Existing `agents/<slug>/knowledge.json` files migrate into the library on first start and become that agent's initial selection.

**Tech Stack:** TypeScript, Bun (compiled binary), Vitest, existing `KnowledgeStore` chunking/BM25/RRF logic.

**Spec:** `docs/superpowers/specs/2026-08-20-unified-desktop-app-design.md` — §5.1a is the section this implements.

## Global Constraints

- Documents live at `~/.aroha/knowledge/`, not `~/.aroha/agents/<slug>/knowledge.json`. Spec §5.1a.
- Retrieval is over the agent's selection, **never** the whole library. Spec §5.1a.
- Migration must lose no documents, and must not let one agent silently gain another's. Spec §5.1a.
- `/v1/agents/:slug/knowledge` changes meaning: what an agent can SEE, not what it OWNS. Spec §5.1a.
- The chunking, BM25, dense and RRF logic in `KnowledgeStore` is proven and must be reused, not rewritten.
- Browser tests are NOT part of `npm test`; run them with `npm run test:ui` after `node scripts/compile.mjs`.
- Run tests from `apps/aroha-runtime` with `npx vitest run <path>`.
- Commit messages: imperative mood, explain *why*.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/host/library.ts` | `KnowledgeLibrary` — every document and chunk for the workspace; add, list, remove, search/contextFor **filtered by a document-id set**. |
| `src/host/library.test.ts` | Library behaviour, including that filtering actually excludes. |
| `src/host/migrate-knowledge.ts` | One-time move of per-agent `knowledge.json` into the library. Idempotent. |
| `src/host/migrate-knowledge.test.ts` | Migration correctness, including the two-agents-same-document case. |
| `src/host/provider.ts` | `BuiltinProvider` retrieves from the library through a selection. |
| `src/host/store.ts` | `AgentRecord.documentIds`. |
| `src/gateway/server.ts` | `/v1/knowledge` (library) and `/v1/agents/:slug/knowledge` (selection). |

`src/host/knowledge.ts` is **kept**: `KnowledgeLibrary` reuses its `splitText`, BM25, dense and RRF functions. Do not rewrite retrieval.

---

## Task 1: `KnowledgeLibrary`

**Files:**
- Create: `src/host/library.ts`, `src/host/library.test.ts`

**Interfaces:**
- Consumes: from `./knowledge.js` — `splitText`, the scoring helpers, `KnowledgeDoc`, `Chunk`, `Hit`. Read that file first and reuse; do not reimplement.
- Produces: `class KnowledgeLibrary` with
  `add(name, text, vectors?, embedModel?): KnowledgeDoc | null`,
  `list(): KnowledgeDoc[]`,
  `remove(docId): boolean`,
  `status(): KnowledgeStatus`,
  `search(query, docIds: string[], limit?, queryVector?): Hit[]`,
  `contextFor(query, docIds: string[], limit?, queryVector?): string`

- [ ] **Step 1: Write the failing test**

Create `src/host/library.test.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveWorkspace, ensureWorkspace, type Workspace } from "../workspace/paths.js";
import { KnowledgeLibrary } from "./library.js";

let root: string;
let ws: Workspace;
let lib: KnowledgeLibrary;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aroha-library-"));
  ws = ensureWorkspace(resolveWorkspace(root));
  lib = new KnowledgeLibrary(ws);
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("KnowledgeLibrary", () => {
  it("starts empty", () => {
    expect(lib.list()).toEqual([]);
    expect(lib.status().docCount).toBe(0);
  });

  it("stores a document once, for the whole workspace", () => {
    const doc = lib.add("Rate card", "Late invoices carry 2% interest.");
    expect(doc).not.toBeNull();
    expect(lib.list()).toHaveLength(1);
    // A second library over the same workspace sees it — this is the point.
    expect(new KnowledgeLibrary(ws).list()).toHaveLength(1);
  });

  it("retrieves only from the documents it is given", () => {
    const rates = lib.add("Rate card", "Late invoices carry 2% interest.")!;
    const leave = lib.add("Handbook", "Annual leave is 28 days per year.")!;

    // The whole corpus contains both, but a selection of one must never
    // return the other. This is the property that keeps agents distinct.
    const onlyRates = lib.search("leave interest days", [rates.id], 4);
    expect(onlyRates.every((h) => h.docId === rates.id)).toBe(true);

    const onlyLeave = lib.search("leave interest days", [leave.id], 4);
    expect(onlyLeave.every((h) => h.docId === leave.id)).toBe(true);
  });

  it("returns nothing for an empty selection, rather than everything", () => {
    lib.add("Rate card", "Late invoices carry 2% interest.");
    // The dangerous default: an agent with no documents selected must get
    // silence, not the entire library.
    expect(lib.search("interest", [], 4)).toEqual([]);
    expect(lib.contextFor("interest", [], 4)).toBe("");
  });

  it("ignores ids that are not in the library", () => {
    const doc = lib.add("Rate card", "Late invoices carry 2% interest.")!;
    const hits = lib.search("interest", [doc.id, "no-such-doc"], 4);
    expect(hits.length).toBeGreaterThan(0);
  });

  it("removes a document and stops returning it to anyone", () => {
    const doc = lib.add("Rate card", "Late invoices carry 2% interest.")!;
    expect(lib.remove(doc.id)).toBe(true);
    expect(lib.search("interest", [doc.id], 4)).toEqual([]);
    expect(lib.status().docCount).toBe(0);
  });

  it("reports a removal that removed nothing as false", () => {
    expect(lib.remove("no-such-doc")).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/host/library.test.ts`
Expected: FAIL — `Cannot find module './library.js'`.

- [ ] **Step 3: Implement**

Create `src/host/library.ts`. Read `src/host/knowledge.ts` first and import its splitting and scoring helpers rather than copying them — export them from `knowledge.ts` if they are currently module-private.

Storage: one JSON file at `join(ws.root, "knowledge", "library.json")`, same shape as today's `{ docs, chunks, embedModel }`. Create the directory on write.

The filtering rule that matters: `search()` and `contextFor()` take a `docIds: string[]` and must consider **only** chunks whose `docId` is in that set. An empty array yields no hits — never the whole library.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/host/library.test.ts`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/aroha-runtime/src/host/library.ts apps/aroha-runtime/src/host/library.test.ts
git commit -m "feat(runtime): one document library for the workspace

Documents were stored per agent, so a customer with one corpus uploaded it
once per agent — untenable once the paid engine's index is measured in
gigabytes. They now live once, and retrieval takes the ids an agent may see.

The filtering is the load-bearing part: an empty selection returns silence,
not the whole library. An agent that quietly gained every document in the
workspace would erode the distinction that makes consulting another firm's
agent worth anything, and it would do so invisibly."
```

---

## Task 2: The agent's selection

**Files:**
- Modify: `src/host/store.ts` — `AgentRecord`
- Test: `src/host/store.test.ts` (append)

**Interfaces:**
- Produces: `AgentRecord.documentIds?: string[]`

- [ ] **Step 1: Write the failing test**

Append to `src/host/store.test.ts`:

```ts
describe("AgentRecord.documentIds", () => {
  it("round-trips a document selection", () => {
    const store = new AgentStore(ws);
    const rec = store.create({
      name: "Advisor", systemPrompt: "x", model: "m", documentIds: ["doc-1", "doc-2"],
    });
    expect(store.get(rec.slug)?.documentIds).toEqual(["doc-1", "doc-2"]);
  });

  it("reads an absent selection as empty, not as everything", () => {
    // Records written before this field existed must mean "no documents",
    // never "all documents" — the fail-open version would hand every old
    // agent the entire library on upgrade.
    const store = new AgentStore(ws);
    const rec = store.create({ name: "Old", systemPrompt: "x", model: "m" });
    expect(store.get(rec.slug)?.documentIds ?? []).toEqual([]);
  });
});
```

Match the surrounding file's setup for `ws` and imports; read it before writing.

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/store.test.ts`
Expected: FAIL — `documentIds` is not accepted by `create()` / not present on the record.

- [ ] **Step 3: Implement**

Add to `AgentRecord` in `src/host/store.ts`:

```ts
  /**
   * Documents from the workspace library this agent retrieves from.
   *
   * Absent means NONE, not all. Records written before the library existed
   * have no selection, and reading that as "everything" would hand every
   * existing agent the whole corpus on upgrade — silently, and in the one
   * direction a person would not think to check.
   */
  documentIds?: string[];
```

Thread it through `create()` and any record-writing path in the same file.

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/store.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/aroha-runtime/src/host/store.ts apps/aroha-runtime/src/host/store.test.ts
git commit -m "feat(runtime): an agent selects documents from the library

Absent means none, not all. An upgrade that read a missing selection as
'everything' would hand every existing agent the entire corpus, silently, in
the one direction nobody thinks to check."
```

---

## Task 3: Migration

**Files:**
- Create: `src/host/migrate-knowledge.ts`, `src/host/migrate-knowledge.test.ts`

**Interfaces:**
- Consumes: `KnowledgeLibrary` (Task 1), `AgentRecord.documentIds` (Task 2)
- Produces: `migrateAgentKnowledge(ws, store, library): MigrationResult` where
  `MigrationResult = { agentsMigrated: number; documentsMoved: number; alreadyDone: boolean }`

- [ ] **Step 1: Write the failing test**

Create `src/host/migrate-knowledge.test.ts` covering, at minimum:

```ts
  it("moves an agent's documents into the library and selects them", async () => {
    // Seed the OLD layout directly: agents/<slug>/knowledge.json
    // Then migrate, and assert: the library holds the docs, the agent's
    // documentIds names exactly those docs, and the old file is gone.
  });

  it("gives two agents holding the same document their own selections", async () => {
    // The case that must not merge: agent A and agent B each had a copy of
    // "Rate card". After migration BOTH must be able to retrieve it, and
    // neither may gain the other's other documents.
  });

  it("is idempotent — running twice moves nothing the second time", async () => {
    // Startup runs this every boot. A second run must report alreadyDone
    // and must not duplicate documents.
  });

  it("does nothing when there is nothing to migrate", async () => {
  });
```

Write the bodies out fully — seed real files with `writeFileSync`, use a real `Workspace`, and assert on real results. Read `src/host/knowledge.ts` for the exact on-disk shape to seed.

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/migrate-knowledge.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Create `src/host/migrate-knowledge.ts`.

Rules:
- For each agent with an `agents/<slug>/knowledge.json`: add its documents to the library, set the agent's `documentIds` to exactly those document ids, then delete the old file.
- Two agents holding the same document produce two library documents. **Do not deduplicate.** Deduplicating by content hash would be a silent merge across a trust boundary, and the whole point of the selection is that agents differ. A later feature can offer to merge; migration must not decide it.
- Idempotent: absence of any `knowledge.json` means the work is done.
- If a single agent's file is unreadable, migrate the rest and report it — one corrupt file must not block the whole workspace from starting.

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/migrate-knowledge.test.ts`
Expected: PASS.

- [ ] **Step 5: Wire it into startup**

In `src/main.ts`, run the migration once after the workspace and store exist, before the gateway starts. Report it only when it did something:

```ts
  const migration = migrateAgentKnowledge(ws, store, library);
  if (migration.documentsMoved > 0) {
    note(`  Migrated ${migration.documentsMoved} document(s) into the workspace library`);
  }
```

- [ ] **Step 6: Verify against a real old workspace**

Build and run against a workspace seeded in the OLD layout, and confirm the documents survive:

```bash
node scripts/compile.mjs
# seed a temp AROHA_HOME with agents/<slug>/knowledge.json, then:
AROHA_HOME=<temp> ./dist/bin/aroha-windows-x64.exe up --port 7860 --no-open
```
Expected: the migration line appears, `~/.aroha/knowledge/library.json` exists, and the agent still answers from its documents. Report the real output.

- [ ] **Step 7: Commit**

```bash
git add apps/aroha-runtime/src/host/migrate-knowledge.ts apps/aroha-runtime/src/host/migrate-knowledge.test.ts apps/aroha-runtime/src/main.ts
git commit -m "feat(runtime): migrate per-agent documents into the library

Runs once at startup and is idempotent. Two agents holding the same document
get two library entries and separate selections — deduplicating by content
would be a silent merge across a trust boundary, and the selection exists
precisely so agents differ. A later feature can offer to merge; migration
must not decide it.

One unreadable file migrates the rest and reports itself, because a single
corrupt document must not stop a workspace from starting."
```

---

## Task 4: Provider retrieves through the selection

**Files:**
- Modify: `src/host/provider.ts` — `BuiltinProvider`
- Modify: `src/host/runtime.ts` — `providerFor`
- Test: `src/host/provider.test.ts` (append)

**Interfaces:**
- Consumes: `KnowledgeLibrary` (Task 1), `AgentRecord.documentIds` (Task 2)
- Produces: `BuiltinProvider(library, documentIds, embedQuery?)`

- [ ] **Step 1: Write the failing test**

Append to `src/host/provider.test.ts`:

```ts
describe("BuiltinProvider — retrieval is scoped to the selection", () => {
  it("never returns a document the agent has not selected", async () => {
    // Two documents in the library, one selected. A query matching BOTH must
    // return only the selected one. This is the single most important
    // assertion in the tiering design: shared storage must not become shared
    // knowledge.
  });

  it("returns nothing when the agent has selected nothing", async () => {
  });

  it("reports docCount as the agent's selection, not the library's size", async () => {
    // status() drives the UI's "N documents" line and the retrieval guard in
    // the handler. Reporting the library's total would make an agent with no
    // documents claim to have some, and would run retrieval for nothing.
  });
});
```

Write the bodies fully, using a real `KnowledgeLibrary` on a real temp workspace.

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/provider.test.ts`
Expected: FAIL — the constructor does not take a library or a selection.

- [ ] **Step 3: Implement**

Change `BuiltinProvider` to take `(library: KnowledgeLibrary, documentIds: string[], embedQuery?: EmbedQuery)`. Pass `documentIds` into every `search`/`contextFor` call. `status()` reports counts for the SELECTION.

In `runtime.ts`, `providerFor(slug)` reads the agent's record for its `documentIds` and constructs the provider with the workspace library. Keep the query-vector memoization added previously.

`add()` on the provider now adds to the LIBRARY and appends the new id to the agent's selection — adding a document from an agent's screen should make that agent able to use it, which is what a person means by the action.

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/provider.test.ts`
Expected: PASS.

- [ ] **Step 5: Full suite + browser suite**

Run: `npx tsc --noEmit && npx vitest run`
Then: `node scripts/compile.mjs && npm run test:ui`
Expected: both green. Report totals.

- [ ] **Step 6: Commit**

```bash
git add apps/aroha-runtime/src/host apps/aroha-runtime/src/gateway
git commit -m "refactor(runtime): retrieve from the library through the agent's selection

Storage is shared; knowledge is not. Every retrieval passes the agent's
document ids, and status() counts the selection rather than the library, so
an agent with nothing selected reports nothing and skips retrieval entirely
instead of searching a corpus it cannot use."
```

---

## Task 5: Library and selection routes

**Files:**
- Modify: `src/gateway/server.ts`
- Test: `src/gateway/knowledge-threads-api.test.ts` (append) or a new `src/gateway/library-api.test.ts`

**Interfaces:**
- Produces:
  - `GET /v1/knowledge` — the library
  - `POST /v1/knowledge` — add to the library
  - `DELETE /v1/knowledge/:docId` — remove from the library
  - `GET /v1/agents/:slug/knowledge` — this agent's selection
  - `PUT /v1/agents/:slug/knowledge` — set the selection, body `{ documentIds: string[] }`

- [ ] **Step 1: Write the failing tests**

Cover: adding to the library does not select it for any agent; setting a selection changes what the agent sees; deleting a library document removes it from every agent's selection; and a selection naming an unknown id is rejected rather than stored.

Write full bodies, following the setup in the existing gateway tests.

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run src/gateway/`
Expected: FAIL — routes not found.

- [ ] **Step 3: Implement**

Keep `POST /v1/agents/:slug/knowledge` working as "add to library **and** select for this agent" — that is what the existing UI's Knowledge dialog does today, and breaking it would break a working screen before the port replaces it.

- [ ] **Step 4: Run to verify they pass**

Run: `npx vitest run src/gateway/`
Expected: PASS.

- [ ] **Step 5: Full verification**

Run: `npx tsc --noEmit && npx vitest run`
Then: `node scripts/compile.mjs && npm run test:ui`

- [ ] **Step 6: Commit**

```bash
git add apps/aroha-runtime/src/gateway
git commit -m "feat(runtime): library routes, and an agent's selection

/v1/knowledge manages the corpus; /v1/agents/:slug/knowledge now means what
an agent can SEE rather than what it owns. Deleting from the library removes
it from every selection, because a document that no longer exists must not
remain listed as one an agent uses.

POST /v1/agents/:slug/knowledge still adds and selects in one step: that is
what the existing Knowledge dialog does, and it keeps working until the port
replaces it."
```

---

## Task 6: The existing Knowledge dialog reflects the library

**Files:**
- Modify: `src/ui/page.ts` — the knowledge dialog
- Modify: `src/ui/styles.ts` if needed
- Test: `src/ui/screens.test.ts` (append)

- [ ] **Step 1: Add a browser test first**

Append to `src/ui/screens.test.ts` a test that opens the Knowledge dialog for an agent and asserts it distinguishes documents the agent uses from others in the library. Use `waitFor` on a JS-produced landmark, not static markup.

- [ ] **Step 2: Run to verify it fails**

Run: `node scripts/compile.mjs && npm run test:ui`
Expected: FAIL on the missing landmark.

- [ ] **Step 3: Implement**

Show the library with a checkbox per document indicating whether this agent uses it. Adding a document still adds and selects it. Keep the module under the 800-line cap; if the dialog pushes `page.ts` past it, extract the dialog into its own `src/ui/screens/knowledge.ts` and register it in `modules.test.ts`'s `JS_MODULES`.

- [ ] **Step 4: Verify**

Run: `node scripts/compile.mjs && npm run test:ui` — expect pass.
Then `npx vitest run` for the unit suite.

- [ ] **Step 5: Commit**

```bash
git add apps/aroha-runtime/src/ui
git commit -m "feat(ui): the knowledge dialog shows the library and what this agent uses

Storage is now shared, so the dialog has to distinguish 'exists in this
workspace' from 'this agent retrieves from it'. Conflating them would make a
shared corpus look like shared knowledge, which is exactly the confusion the
selection exists to prevent."
```

---

## Self-review

**Spec coverage.**

| Spec §5.1a requirement | Task |
|---|---|
| Documents at `~/.aroha/knowledge/` | 1 |
| Agent carries a selection | 2 |
| Retrieval over the selection, never the library | 1 (filter), 4 (provider) |
| `/v1/knowledge` manages the library | 5 |
| `/v1/agents/:slug/knowledge` means "can see" | 5 |
| Migration loses nothing, leaks nothing | 3 |
| Add-on indexes one corpus (seam closed) | Structural — delivered by 1 and 4; the add-on itself is a later plan |

Not covered here by design: connectors and skills moving to the same shape (spec §5.1a defers them), the screen port, and the add-on.

**Placeholder scan.** Tasks 3, 5 and 6 describe test cases and require the implementer to write full bodies against files they are told to read first, rather than inlining code that would be wrong the moment those files move. Every other step carries its code. No TBD or "handle errors appropriately".

**Type consistency.** `KnowledgeLibrary`, `MigrationResult`, `migrateAgentKnowledge`, `AgentRecord.documentIds`, and `BuiltinProvider(library, documentIds, embedQuery?)` are used with the same names and shapes throughout.

**Risk called out.** Task 4 changes `BuiltinProvider`'s constructor, which Plan 1's contract suite exercises. Those tests must be updated in the same task, not deleted — if a contract test becomes impossible to satisfy, that is a signal the interface is wrong, not that the test is.
