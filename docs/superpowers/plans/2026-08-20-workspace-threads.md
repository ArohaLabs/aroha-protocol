# Workspace Threads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move conversations out of individual agents and into the workspace, so one thread can involve any number of agents and every reply says which agent produced it.

**Architecture:** `ThreadStore` drops its agent slug and writes to a workspace-level `threads/` directory, keeping its per-owner partition. `ThreadMessage` gains an author for assistant replies, mirroring the `peerDid`/`peerName` fields peers already have. Existing per-agent threads migrate on first start with their owning agent stamped onto every assistant message. A turn is routed to the agent mentioned in it, else whoever answered last, else the workspace default. The sidebar is then rebuilt to doc-intel's structure, so conversations are the home and agents are a workspace resource rather than the way in.

**Tech Stack:** TypeScript (ESM), Bun single-binary compile, vitest, JSONL append-only thread files.

**Spec:** `docs/superpowers/specs/2026-08-20-unified-desktop-app-design.md` §5.1b (thread scope and routing), §5.1c (the information architecture) and §5.1d (what the running app looks like)

## Global Constraints

- **The owner partition is a privacy boundary and must survive intact.** `ThreadStore` hashes `ownerId` into the path precisely so one person's history is never handed to another. Dropping the agent slug must not drop, weaken, or default this. There is no default owner.
- **Migration never loses a message and never invents an author.** Every assistant message moved out of `agents/<slug>/threads/` is attributed to `<slug>` — that is a fact, not a guess. A message whose author genuinely cannot be determined keeps no author rather than being assigned one.
- **Migration is idempotent.** Running it twice must not duplicate a thread or re-append messages. It runs on every start.
- **Thread ids stay path-safe.** `ThreadStore.file()` refuses anything not matching the plain-id pattern. Keep that check; it is what stops a caller-supplied id becoming a path traversal.
- **Append-only.** Threads are JSONL written with `appendFileSync`, mode `0o600`. Do not rewrite a thread file in place to add authors — migration writes to the new location, it does not edit the old one.
- **Every task ends green:** `npm test` and `npx tsc --noEmit` from `apps/aroha-runtime`.

## Current state

| | |
|---|---|
| Path | `ws.agentsDir/<slug>/threads/<sha256(ownerId) first 32>/<id>.jsonl` |
| Constructor | `ThreadStore(ws: Workspace, slug: string, ownerId: string)` |
| Message roles | `user`, `assistant`, `system`, `peer` (peers carry `peerDid`/`peerName`) |
| Production callers | exactly one — `src/host/runtime.ts:221` |
| API | `/v1/agents/:slug/threads`, `src/gateway/server.ts:493-560` |

Only one production caller constructs a `ThreadStore`, which is what makes this change tractable.

---

### Task 1: Thread storage moves to the workspace

**Files:**
- Modify: `apps/aroha-runtime/src/host/threads.ts`
- Modify: `apps/aroha-runtime/src/workspace/paths.ts` (add `threadsDir`)
- Modify: `apps/aroha-runtime/src/host/runtime.ts:221`
- Test: `apps/aroha-runtime/src/host/threads.test.ts`

**Interfaces:**
- Produces: `ThreadStore(ws: Workspace, ownerId: string)` — slug dropped. `Workspace.threadsDir: string`. `ThreadMessage.agentSlug?: string` and `.agentName?: string`.

- [ ] **Step 1: Write the failing tests**

```ts
it("writes to the workspace, not inside an agent", () => {
  const store = new ThreadStore(ws, "owner-1");
  const id = store.create();
  store.append(id, [{ role: "user", content: "hello", at: T }]);
  expect(existsSync(ws.threadsDir)).toBe(true);
  expect(readdirSync(ws.agentsDir).length).toBe(0);
});

it("keeps two owners' conversations apart", () => {
  const a = new ThreadStore(ws, "owner-a");
  const b = new ThreadStore(ws, "owner-b");
  const id = a.create();
  a.append(id, [{ role: "user", content: "private", at: T }]);
  expect(b.list()).toEqual([]);
  expect(b.read(id)).toEqual([]);
});

it("records which agent produced an assistant reply", () => {
  const store = new ThreadStore(ws, "owner-1");
  const id = store.create();
  store.append(id, [
    { role: "user", content: "q", at: T },
    { role: "assistant", content: "a", at: T, agentSlug: "ledger", agentName: "Ledger" },
  ]);
  expect(store.read(id)[1].agentSlug).toBe("ledger");
});

it("still refuses an id that is not a plain id", () => {
  const store = new ThreadStore(ws, "owner-1");
  expect(() => store.read("../../escape")).toThrow(/invalid thread id/);
});
```

- [ ] **Step 2: Run them to watch them fail**

Run: `cd apps/aroha-runtime && npx vitest run src/host/threads.test.ts`
Expected: FAIL — the constructor still takes three arguments.

- [ ] **Step 3: Make the change**

Add `threadsDir` to `Workspace` alongside `agentsDir`. Drop `slug` from the constructor; keep the `ownerId` digest exactly as it is. Add `agentSlug?`/`agentName?` to `ThreadMessage`. Update the single caller at `runtime.ts:221`.

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(threads): store conversations in the workspace, not inside an agent"
```

---

### Task 2: Migrate existing threads on first start

**Files:**
- Create: `apps/aroha-runtime/src/host/migrate-threads.ts`
- Create: `apps/aroha-runtime/src/host/migrate-threads.test.ts`
- Modify: wherever `migrateAgentKnowledge` is invoked at startup — call this beside it

**Interfaces:**
- Consumes: `ThreadStore(ws, ownerId)` from Task 1.
- Produces: `migrateAgentThreads(ws: Workspace): void`.

**Read `src/host/migrate-knowledge.ts` first.** It solves the same problem for documents and its shape is the one to follow: per-agent try/catch so one unreadable file cannot stop the rest, and honest logging of what it could not move.

- [ ] **Step 1: Write the failing tests**

```ts
it("moves a thread out of an agent and stamps the author on assistant replies", () => {
  seedOldThread(ws, "ledger", "owner-1", "t1", [
    { role: "user", content: "q", at: T },
    { role: "assistant", content: "a", at: T },
  ]);
  migrateAgentThreads(ws);
  const msgs = new ThreadStore(ws, "owner-1").read("t1");
  expect(msgs[0].agentSlug).toBeUndefined();
  expect(msgs[1].agentSlug).toBe("ledger");
});

it("is idempotent", () => {
  seedOldThread(ws, "ledger", "owner-1", "t1", [{ role: "user", content: "q", at: T }]);
  migrateAgentThreads(ws);
  migrateAgentThreads(ws);
  expect(new ThreadStore(ws, "owner-1").read("t1")).toHaveLength(1);
});

it("keeps each owner's threads in their own partition", () => {
  seedOldThread(ws, "ledger", "owner-a", "ta", [{ role: "user", content: "a", at: T }]);
  seedOldThread(ws, "ledger", "owner-b", "tb", [{ role: "user", content: "b", at: T }]);
  migrateAgentThreads(ws);
  expect(new ThreadStore(ws, "owner-a").list().map((t) => t.id)).toEqual(["ta"]);
  expect(new ThreadStore(ws, "owner-b").list().map((t) => t.id)).toEqual(["tb"]);
});

it("migrates the rest when one agent's thread file is corrupt", () => {
  seedCorruptThread(ws, "broken", "owner-1", "bad");
  seedOldThread(ws, "ledger", "owner-1", "good", [{ role: "user", content: "q", at: T }]);
  migrateAgentThreads(ws);
  expect(new ThreadStore(ws, "owner-1").read("good")).toHaveLength(1);
});
```

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Write the migration**

Walk `agentsDir/<slug>/threads/<digest>/*.jsonl`. **The digest is already the owner partition — carry it across verbatim rather than recomputing it**, because the plaintext `ownerId` is not recoverable from the hash. Stamp `agentSlug`/`agentName` on `role === "assistant"` messages only. Leave `user`, `system` and `peer` messages untouched — peers already carry their own attribution. Skip a destination file that already exists, which is what makes it idempotent. Never delete the source in this task.

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(threads): migrate per-agent conversations into the workspace"
```

---

### Task 3: The `/v1/threads` API

**Files:**
- Modify: `apps/aroha-runtime/src/gateway/server.ts` (~493-560)
- Test: `apps/aroha-runtime/src/gateway/threads-api.test.ts`

**Interfaces:**
- Produces: `GET /v1/threads`, `POST /v1/threads`, `GET /v1/threads/:id`, `DELETE /v1/threads/:id`. `GET /v1/agents/:slug/threads` is retained and re-specified as *threads this agent has spoken in*, derived by scanning for `agentSlug === slug`.

- [ ] **Step 1: Write the failing tests**

```ts
it("lists workspace threads", async () => {
  const res = await fetch(`${url}/v1/threads`, { headers: auth });
  expect(res.status).toBe(200);
});

it("reports an agent's threads as the ones it has spoken in", async () => {
  // ledger has replied in a thread; diligence has never spoken
  const res = await fetch(`${url}/v1/agents/diligence/threads`, { headers: auth });
  expect((await res.json()).threads).toEqual([]);
});

it("refuses a thread id that is not a plain id", async () => {
  const res = await fetch(`${url}/v1/threads/..%2F..%2Fescape`, { headers: auth });
  expect(res.status).toBe(400);
});
```

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement the routes**

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(api): workspace thread routes, agent threads become participation"
```

---

### Task 4: Turn routing, three levels

**Files:**
- Create: `apps/aroha-runtime/src/host/route-turn.ts`
- Create: `apps/aroha-runtime/src/host/route-turn.test.ts`
- Modify: the turn path in `src/host/runtime.ts`

**Interfaces:**
- Produces: `routeTurn(text: string, history: ThreadMessage[], agents: string[], defaultAgent?: string): string | null`

**The rule, from spec §5.1b — corrected after reading `Thread.tsx:224`:**

```
mentioned in this message
  ?? whoever answered last in this thread
  ?? the workspace default agent
```

`null` only when all three miss — no mention, no history, and no default set. The third level is what lets someone open the app, type, and get an answer without choosing anybody; an earlier draft of this plan stopped at two levels and made a fresh conversation a dead end.

- [ ] **Step 1: Write the failing tests**

```ts
const agents = ["ledger", "diligence"];

it("routes to the mentioned agent", () => {
  expect(routeTurn("@diligence what renews?", [], agents, "ledger")).toBe("diligence");
});

it("prefers the mention over the last speaker", () => {
  const history = [{ role: "assistant", content: "a", at: T, agentSlug: "ledger" }];
  expect(routeTurn("@diligence and this?", history, agents, "ledger")).toBe("diligence");
});

it("routes to whoever answered last when nothing is mentioned", () => {
  const history = [
    { role: "user", content: "q", at: T },
    { role: "assistant", content: "a", at: T, agentSlug: "diligence" },
  ];
  expect(routeTurn("and the quarter before?", history, agents, "ledger")).toBe("diligence");
});

it("falls back to the workspace default on a fresh thread", () => {
  expect(routeTurn("hello", [], agents, "ledger")).toBe("ledger");
});

it("resolves to nothing when there is no mention, no history and no default", () => {
  expect(routeTurn("hello", [], agents, undefined)).toBeNull();
});

it("ignores a mention of an agent that does not exist", () => {
  expect(routeTurn("@nobody hello", [], agents, "ledger")).toBe("ledger");
});

it("does not treat an email address as a mention", () => {
  expect(routeTurn("mail controller@acme.example", [], agents, "ledger")).toBe("ledger");
});
```

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement `routeTurn`**

A mention is `@` at a word boundary followed by a known slug. `controller@acme.example` must not parse as a mention of `acme` — that test is the one that matters, and it is why matching is anchored rather than a bare search for `@`.

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(threads): route a turn by mention, last speaker, then workspace default"
```

---

### Task 5: The workspace default agent

**Files:**
- Modify: `apps/aroha-runtime/src/workspace/config.ts`
- Modify: `apps/aroha-runtime/src/gateway/server.ts`
- Test: `apps/aroha-runtime/src/workspace/config.test.ts`

**Interfaces:**
- Produces: `defaultAgent?: string` in workspace config; `GET/PUT /v1/settings`.

Small, and Task 4's third fallback is dead without it.

- [ ] **Step 1: Write the failing tests**

```ts
it("round-trips the default agent", () => {
  writeConfig(ws, { defaultAgent: "ledger" });
  expect(readConfig(ws).defaultAgent).toBe("ledger");
});

it("has no default until one is set", () => {
  expect(readConfig(ws).defaultAgent).toBeUndefined();
});

it("does not resolve a default naming an agent that no longer exists", () => {
  writeConfig(ws, { defaultAgent: "deleted" });
  expect(resolveDefaultAgent(ws, ["ledger"])).toBeUndefined();
});
```

That third test is the one worth having: a default pointing at a deleted agent must read as absent, not route every conversation into a void.

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement, and wire `/v1/settings`**

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(config): a workspace default agent, so a fresh conversation can just answer"
```

---

### Task 6: Replicate doc-intel's sidebar

**Files:**
- Modify: `apps/aroha-runtime/src/ui/page.ts`
- Modify: `apps/aroha-runtime/src/ui/screens.test.ts`

**Interfaces:**
- Consumes: `/v1/threads` (Task 3), `/v1/settings` (Task 5).

**Spec §5.1c is the specification for this task — follow it exactly.** The structure, top to bottom:

| Region | Contents |
|---|---|
| Primary action | **+ New conversation** |
| `Recent` | conversation list — its own scroll region, `flex:1; min-height:0` |
| `Workspace` | Agents · Knowledge · Tools · Skills, each with a count |
| Network | Share your agents · Remote agents |
| Footer | Settings |

Four things are not negotiable, because each is a decision rather than a detail:

1. **The app opens on a conversation, not the agent gallery.**
2. **The conversation list scrolls; the nav below it never moves.** `min-height: 0` on the scroll region is what makes this work in a flex column — without it a long history pushes the nav off-screen, which is the failure the source comment calls out by name.
3. **`Spaces` is not built.** The runtime has no such concept, and a nav entry for one would be a promise the product cannot keep. `Skills` gets a workspace-wide view; today it is per-agent only.
4. **The shell is three columns** — `280px` sidebar, conversation, `~460px` Preview rail (spec §5.1d). Build the grid here; Task 7 fills the third column. A two-column shell would have to be torn up again immediately.

Sidebar detail from §5.1d: section labels `RECENT` / `WORKSPACE` / `AROHA NETWORK`, counts right-aligned, and a footer carrying the theme toggle and *"Running on your hardware"*.

Rename to match: `MCP servers` becomes `Tools`, `Hub` becomes `Remote agents`. `Share your agents` becomes a place rather than a per-agent button — the per-agent Publish button stays where it is.

- [ ] **Step 1: Read `page.ts`'s current sidebar** (around line 76) and `DustApp.tsx:290-365` side by side.

- [ ] **Step 2: Write the failing browser assertions**

```ts
it("opens on a conversation, not the agent gallery", async () => {
  await withApp(async (app) => {
    await app.waitFor(`document.querySelector("#new-conversation")`);
    expect(await app.evaluate(`!!document.querySelector("#thread-view")`)).toBe(true);
    expect(await app.consoleErrors()).toEqual([]);
  });
});

it("keeps the workspace nav in place when the history is long", async () => {
  await withApp(async (app) => {
    await seedThreads(app, 40);
    const navTop = await app.evaluate(
      `document.querySelector("#nav-agents").getBoundingClientRect().top`,
    );
    expect(navTop).toBeLessThan(900);
  });
});

it("offers no place for a concept the runtime does not have", async () => {
  await withApp(async (app) => {
    expect(await app.evaluate(`!!document.querySelector("#nav-spaces")`)).toBe(false);
  });
});
```

- [ ] **Step 3: Run them to watch them fail** (`node scripts/compile.mjs`, then `npm run test:ui`)

- [ ] **Step 4: Rebuild the sidebar**

- [ ] **Step 5: Verify:** `npm test && npm run test:ui && npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(ui): conversations on top, agents as a workspace resource"
```

---


---

### Task 7: The Preview rail

**Files:**
- Modify: `apps/aroha-runtime/src/ui/screens/preview-panel.ts`
- Modify: `apps/aroha-runtime/src/ui/page.ts`
- Modify: `apps/aroha-runtime/src/ui/screens/preview-panel.test.ts`
- Modify: `apps/aroha-runtime/src/ui/screens.test.ts`

**Interfaces:**
- Consumes: the three-column grid from Task 6.

**This task corrects something already shipped.** `preview-panel.ts` renders approvals as a block **inline in the message stream**. Screenshots of the running application (spec §5.1d) show it is a **persistent right rail**, headed `Preview · N waiting on you`, listing everything awaiting a decision.

That difference is not cosmetic. Inline, a pending approval scrolls away and is lost behind new turns; in a rail it stays in view until it is answered. The rail is why the pattern works.

**What must not change:** the decision path. Same route, same payload, same disable-on-click ordering, same 404 handling for a restarted agent. Task 2's review verified those byte-for-byte — this task re-sites the rendering, nothing else. If `page.test.ts`'s approval assertions go red, you changed behaviour.

- [ ] **Step 1: Read the current module and the screenshots**

Read `src/ui/screens/preview-panel.ts`, then `scratch/docintel/10-conversation.png` for what the rail looks like beside a live conversation.

- [ ] **Step 2: Write the failing tests**

```ts
it("renders into the rail, not the message stream", () => {
  expect(PREVIEW_PANEL_JS).toContain("preview-rail");
});

it("heads the rail with how many decisions are waiting", () => {
  expect(railHeading(0)).toBe("Preview");
  expect(railHeading(1)).toBe("Preview · 1 waiting on you");
  expect(railHeading(3)).toBe("Preview · 3 waiting on you");
});

it("keeps a decided draft in the rail rather than dropping it", () => {
  // A decided draft collapses and stays; it does not vanish, or the
  // record of what you approved disappears the moment you approve it.
  expect(isCollapsed({ decision: "approved" })).toBe(true);
  expect(isRemoved({ decision: "approved" })).toBe(false);
});

it("still posts decisions to the existing resume route", () => {
  expect(PREVIEW_PANEL_JS).toContain("/v1/resume");
});
```

Export `railHeading` and `isRemoved` as real TypeScript so they are callable from Node. Take the singular/plural wording from the screenshot, not from this example.

- [ ] **Step 3: Run them to watch them fail**

- [ ] **Step 4: Move the rendering into the rail**

- [ ] **Step 5: Verify the decision path is untouched**

Run: `npx vitest run src/ui/page.test.ts src/ui/screens/preview-panel.test.ts`
Every existing approval assertion must still pass unchanged. Do not edit one to make it green.

- [ ] **Step 6: Verify:** `npm test && npm run test:ui && npx tsc --noEmit`

- [ ] **Step 7: Commit**

```bash
git commit -m "fix(ui): approvals belong in a standing rail, not the message stream"
```

---


---

### Task 8: The workspace send route

**Files:**
- Modify: `apps/aroha-runtime/src/gateway/server.ts`
- Test: `apps/aroha-runtime/src/gateway/threads-api.test.ts`

**Interfaces:**
- Consumes: `AgentRuntime.routeTurn(text, history)` (Task 4), `ThreadStore` (Task 1), `/v1/threads` (Task 3).
- Produces: `POST /v1/threads/:id/messages`.

**Why this task exists.** Task 4 added `routeTurn` and wired it into `AgentRuntime` — and it has **no caller**. There is no cross-agent turn path in this codebase: every mounted agent answers as itself, and the only send route (`/v1/agents/:slug/v1/run`) takes an explicit slug. Without this route, routing is dead code and Task 6's UI has no way to send a message in a conversation without first choosing an agent — which is the entire behaviour being replicated.

**Do not reimplement the turn engine.** This route resolves *which agent answers*, then hands off to the existing per-agent path. Streaming, approvals and audit all keep working because they are inherited, not rebuilt. If you find yourself duplicating the run loop, stop — the seam is in the wrong place.

**The response when nothing resolves.** `routeTurn` returns `null` when there is no mention, no history and no workspace default. That is a real state on a first run with no default set, and the UI must be able to tell the person what to do about it. Return a distinct, documented error the UI can act on — not a generic 400, and never a silent pick of an arbitrary agent.

- [ ] **Step 1: Read the existing send path**

Read how `/v1/agents/:slug/v1/run` is dispatched in `server.ts` (around line 793) and how it streams. Your route resolves a slug and delegates to the same machinery.

- [ ] **Step 2: Write the failing tests**

```ts
it("routes to the workspace default when nothing is mentioned", async () => {
  await setDefault("ledger");
  const res = await fetch(`${url}/v1/threads/${id}/messages`, {
    method: "POST", headers: auth, body: JSON.stringify({ text: "hello" }),
  });
  expect(res.status).toBe(200);
  const msgs = await loadThread(id);
  expect(msgs.at(-1)?.agentSlug).toBe("ledger");
});

it("routes to the mentioned agent over the default", async () => {
  await setDefault("ledger");
  await post(id, "@diligence what renews?");
  expect((await loadThread(id)).at(-1)?.agentSlug).toBe("diligence");
});

it("says so when no agent can be resolved", async () => {
  // fresh thread, no mention, no default set
  const res = await fetch(`${url}/v1/threads/${fresh}/messages`, {
    method: "POST", headers: auth, body: JSON.stringify({ text: "hello" }),
  });
  expect(res.status).toBe(409);
  expect((await res.json()).error).toBe("no_agent_resolved");
});

it("records the user's message even when routing fails", async () => {
  // Losing what someone typed because nothing could answer it is the
  // rudest possible failure. Decide deliberately whether the message is
  // kept or refused outright, and assert whichever you chose.
});

it("refuses a thread id that is not a plain id", async () => {
  const res = await fetch(`${url}/v1/threads/..%2F..%2Fescape/messages`, {
    method: "POST", headers: auth, body: JSON.stringify({ text: "x" }),
  });
  expect(res.status).toBe(400);
});
```

The fourth test has no assertion written for you on purpose — make the call, write the assertion, and say in your report which way you went and why.

- [ ] **Step 3: Run them to watch them fail**

- [ ] **Step 4: Implement the route**

Append the user's message, resolve the agent, delegate, then append the reply carrying `agentSlug` and `agentName`. The owner partition is resolved exactly as every other thread route does — no new default, no fallback.

- [ ] **Step 5: Verify:** `npm test && npx tsc --noEmit`

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(api): send a message to a conversation and let it route to an agent"
```

---

## Verification

1. `npm test` green from `apps/aroha-runtime` and project-wide.
2. `npm run test:ui` green with a compiled binary — 13 or more tests not skipped.
3. `npx tsc --noEmit` clean.
4. An end-to-end check against the compiled binary: start with an existing per-agent thread on disk; confirm it appears in `Recent` after migration with its assistant replies attributed; open the app fresh, type without mentioning anyone, and confirm the workspace default answers; then `@`-mention a second agent in the same thread and confirm it answers and its reply carries its own name.
5. Screenshot the sidebar and compare against `DustApp.tsx`'s structure region by region.
