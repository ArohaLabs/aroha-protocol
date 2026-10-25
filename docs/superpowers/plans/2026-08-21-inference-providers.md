# Inference Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each agent run on either a local model or a hosted API, chosen deliberately per agent, with the credential set through the interface rather than a hand-edited file — and with the product never claiming to be local when it is not.

**Architecture:** `AgentRecord` gains an `InferenceTarget`; absent reads as local, so no existing install changes meaning. A credential store at `~/.aroha/credentials/<provider>.json` (mode `0600`) sits behind one interface with room for a second credential kind. `EngineManager` stops choosing policy — the agent's target decides, and a hosted agent with no credential refuses rather than degrading. The interface shows the provider wherever the agent appears, warns once per agent before its first cloud turn with documents attached, and stops claiming "Running on your hardware" when that is false.

**Tech Stack:** TypeScript (ESM), Bun single-binary compile, vitest, headless Chrome via CDP.

**Spec:** `docs/superpowers/specs/2026-08-21-inference-providers-design.md`

**Scope:** API keys only. OAuth is deliberately deferred — §5 of the spec argues why (uneven provider support, OpenAI cannot do it at all), and §4.4's `Credential` union is the seam it slots into later. Do not build OAuth flows in this plan.

## Global Constraints

These are the product's confidentiality promises expressed as code rules. Every one of them is a way the product could lie to a customer who bought it for confidentiality.

- **Hosted inference is never a fallback.** No configuration, no missing engine, and no error path may cause a hosted provider to answer for an agent whose target is local. (Spec §3)
- **A hosted agent with no credential refuses the turn and says why.** It must not silently answer from the local model. A refusal is a support ticket; a silent downgrade is a wrong answer nobody knows to question. (Spec §4.1)
- **No credential value is ever returned by an API or reaches the browser.** The UI gets connected/not-connected, a masked hint (last four characters), and nothing else. (Spec §4.3)
- **Credential reads fail closed.** Unreadable or malformed is *absent*, never "assume it works" — the same rule `readLicence()` already applies.
- **Existing agents keep answering exactly as they do now**, with no edit and no migration. An absent `InferenceTarget` reads as `{ kind: "local", model }`.
- **The escaping hazard.** The UI is one template literal compiled into a binary. A single-escaped `\n` in source is consumed at build time, emits a real newline, terminates the enclosing JavaScript string, and blanks the entire interface. **A stray backtick in a comment does the same.** Write `\\n`, avoid backticks inside the template, and run `node --check` on the emitted script before committing. `modules.test.ts`'s quote-parity assertion may be REFINED, never deleted or bypassed.
- **Build DOM, never HTML strings** — the UI has an unbroken no-`innerHTML` invariant.
- **Every task ends green:** `npm test` and `npx tsc --noEmit` from `apps/aroha-runtime`. UI tasks also run `npm run test:ui` after `node scripts/compile.mjs`.
- Tests use temp workspaces only — **nothing may touch `~/.aroha`.**

## Current state

| | |
|---|---|
| Hosted providers | `anthropic \| openai \| google`, both wire formats, in `src/engine/hosted.ts` — **fully implemented, zero production callers** |
| Hosted config | none. `main.ts:217` passes `undefined`; no `config.toml` key exists |
| `resolve()` | local first, hosted as a **silent fallback** — dormant only because nothing supplies a config |
| "No engine" message | tells the user to set a key in `~/.aroha/config.toml` — **that key does not exist** |
| `AgentRecord` | `model: string`, no provider beside it |
| Prior art | `gateway/oidc.ts` implements Authorization Code + PKCE for human login (not needed this plan, needed by the OAuth follow-on) |

---

### Task 1: The credential store

**Files:**
- Create: `apps/aroha-runtime/src/host/credentials.ts`
- Create: `apps/aroha-runtime/src/host/credentials.test.ts`
- Modify: `apps/aroha-runtime/src/workspace/paths.ts` (add `credentialsDir`)

**Interfaces:**
- Produces:
```ts
export type Credential =
  | { kind: "api_key"; key: string }
  | { kind: "oauth"; accessToken: string; refreshToken?: string; expiresAt: string };

export interface CredentialStatus {
  provider: HostedProvider;
  connected: boolean;
  /** Last four characters, for recognising which key is installed. Never the key. */
  hint?: string;
}

export class CredentialStore {
  constructor(ws: Workspace);
  read(provider: HostedProvider): Credential | null;   // fails closed
  status(provider: HostedProvider): CredentialStatus;  // safe to send to a browser
  put(provider: HostedProvider, cred: Credential): void;
  remove(provider: HostedProvider): boolean;
}
```

**Read `src/host/licence.ts` first.** Its fail-closed read is the rule to copy: unreadable or incomplete is *absent*, because failing closed costs a support call while failing open grants access from a file nothing could parse.

- [ ] **Step 1: Write the failing tests**

```ts
it("round-trips an api key", () => {
  const store = new CredentialStore(ws);
  store.put("openai", { kind: "api_key", key: "sk-test-abcd1234" });
  expect(store.read("openai")).toEqual({ kind: "api_key", key: "sk-test-abcd1234" });
});

it("reports connected without ever revealing the key", () => {
  const store = new CredentialStore(ws);
  store.put("openai", { kind: "api_key", key: "sk-test-abcd1234" });
  const status = store.status("openai");
  expect(status.connected).toBe(true);
  expect(status.hint).toBe("1234");
  expect(JSON.stringify(status)).not.toContain("sk-test-abcd1234");
});

it("reads an unparseable credential as absent, not as present", () => {
  writeFileSync(join(ws.credentialsDir, "openai.json"), "{ not json");
  expect(new CredentialStore(ws).read("openai")).toBeNull();
  expect(new CredentialStore(ws).status("openai").connected).toBe(false);
});

it("reads a credential missing its key as absent", () => {
  mkdirSync(ws.credentialsDir, { recursive: true });
  writeFileSync(join(ws.credentialsDir, "openai.json"), JSON.stringify({ kind: "api_key" }));
  expect(new CredentialStore(ws).read("openai")).toBeNull();
});

it("writes with owner-only permissions", () => {
  const store = new CredentialStore(ws);
  store.put("openai", { kind: "api_key", key: "sk-test-abcd1234" });
  const mode = statSync(join(ws.credentialsDir, "openai.json")).mode & 0o777;
  // Windows does not honour POSIX modes; assert only where it means something.
  if (process.platform !== "win32") expect(mode).toBe(0o600);
});

it("keeps providers in separate files, so removing one leaves the other", () => {
  const store = new CredentialStore(ws);
  store.put("openai", { kind: "api_key", key: "sk-aaaa" });
  store.put("anthropic", { kind: "api_key", key: "sk-bbbb" });
  store.remove("openai");
  expect(store.read("openai")).toBeNull();
  expect(store.read("anthropic")).not.toBeNull();
});

it("refuses a provider name that is not a known provider", () => {
  const store = new CredentialStore(ws);
  // A provider name reaches this from an HTTP body; it must never become a path.
  expect(() => store.read("../../etc/passwd" as HostedProvider)).toThrow();
});
```

That last test is the one that matters most: the provider name arrives from a request body in Task 4, and an unvalidated one would be a path traversal into the workspace.

- [ ] **Step 2: Run them to watch them fail**

Run: `cd apps/aroha-runtime && npx vitest run src/host/credentials.test.ts`

- [ ] **Step 3: Implement**

Validate the provider against the known set before touching the filesystem. Write with `{ mode: 0o600 }`.

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(credentials): a fail-closed store for hosted provider keys"
```

---

### Task 2: An inference target on the agent

**Files:**
- Modify: `apps/aroha-runtime/src/host/store.ts`
- Test: `apps/aroha-runtime/src/host/store.test.ts`

**Interfaces:**
- Produces:
```ts
export type InferenceTarget =
  | { kind: "local"; model: string }
  | { kind: "hosted"; provider: HostedProvider; model: string };

/** An agent's target, defaulting an absent one to local. Never returns undefined. */
export function targetOf(record: AgentRecord): InferenceTarget;
```
`AgentRecord` gains `target?: InferenceTarget`; `CreateAgentInput` and `UpdateAgentInput` gain the same optional field.

**The compatibility rule is the whole point of this task.** An agent written before this existed has no `target`, and must read as `{ kind: "local", model }` — the behaviour it already has. Nobody edits anything on upgrade, and no migration runs.

- [ ] **Step 1: Write the failing tests**

```ts
it("reads an agent with no target as local, on its existing model", () => {
  const record = { slug: "ledger", model: "qwen2.5:7b" } as AgentRecord;
  expect(targetOf(record)).toEqual({ kind: "local", model: "qwen2.5:7b" });
});

it("round-trips a hosted target", async () => {
  const made = await store.create({
    name: "Diligence", systemPrompt: "x", model: "claude-opus-5",
    target: { kind: "hosted", provider: "anthropic", model: "claude-opus-5" },
  });
  expect(targetOf(store.get(made.slug)!)).toEqual({
    kind: "hosted", provider: "anthropic", model: "claude-opus-5",
  });
});

it("can move an agent from local to hosted and back", async () => {
  const made = await store.create({ name: "A", systemPrompt: "x", model: "qwen2.5:7b" });
  store.update(made.slug, { target: { kind: "hosted", provider: "openai", model: "gpt-4o" } });
  expect(targetOf(store.get(made.slug)!).kind).toBe("hosted");
  store.update(made.slug, { target: { kind: "local", model: "qwen2.5:7b" } });
  expect(targetOf(store.get(made.slug)!).kind).toBe("local");
});

it("treats a malformed target on disk as local rather than trusting it", () => {
  // Failing closed here means falling back to the LOCAL side, which is the
  // safe direction: a corrupt record must never silently start sending
  // prompts to a third party.
  const record = { slug: "x", model: "qwen2.5:7b", target: { kind: "hosted" } } as unknown as AgentRecord;
  expect(targetOf(record)).toEqual({ kind: "local", model: "qwen2.5:7b" });
});
```

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(agents): an inference target per agent, absent reading as local"
```

---

### Task 3: The agent's target decides, and a missing credential refuses

**Files:**
- Modify: `apps/aroha-runtime/src/engine/manager.ts`
- Modify: `apps/aroha-runtime/src/host/handler.ts` (pass the agent's target into the turn)
- Modify: `apps/aroha-runtime/src/main.ts` (the "no engine" message)
- Test: `apps/aroha-runtime/src/engine/manager.test.ts`

**Interfaces:**
- Consumes: `targetOf()` (Task 2), `CredentialStore` (Task 1).

**This is the task the whole design exists to get right.** Read spec §3 before starting.

**The signature change, and its callers.** `EngineManager.chat()` is
`chat(model: string, messages, opts)` today. It becomes:

```ts
async *chat(target: InferenceTarget, messages: ChatMessage[], opts?): AsyncGenerator<ChatChunk>
```

Passing the target rather than a bare model string is what makes the model
and its provider inseparable — a hosted model name can no longer reach a
local engine by accident. There are exactly **three production callers**,
all of which currently pass `agent.model` or a bare model:

- `src/host/handler.ts:400` — `engine.chat(agent.model, messages, { tools })`
- `src/host/consult-handler.ts:69` — same shape
- `src/host/isolated.ts:71` — passes a bare `model`

The first two become `targetOf(agent)`. `isolated.ts` runs a model chosen by
the caller rather than by an agent record — wrap it as
`{ kind: "local", model }` and say in your report whether that is right, or
whether that path should be able to target a hosted provider too.

Three things change:

1. **`resolve()` stops choosing policy.** It answers "is a local engine present", not "what should I use". Remove the hosted fallback branch entirely — not gate it, remove it.
2. **A hosted target resolves its credential.** No credential is a refusal carrying the provider name, not a downgrade.
3. **The "no local engine" message stops naming a `config.toml` key that does not exist.** Point at where a key is actually set once Task 5 exists; until then say plainly that a hosted provider can be connected in Settings.

- [ ] **Step 1: Write the failing tests**

```ts
it("never answers from a hosted provider for a local agent", async () => {
  // The anti-fallback rule (spec §3). With no local engine AND a working
  // hosted credential installed, a local-target agent must still fail.
  const mgr = new EngineManager(/* … no local engine detectable … */);
  const target = { kind: "local", model: "qwen2.5:7b" } as const;
  await expect(collect(mgr.chat(target, messages))).rejects.toThrow(/no local inference engine/i);
});

it("refuses a hosted turn when the provider is not connected", async () => {
  const target = { kind: "hosted", provider: "anthropic", model: "claude-opus-5" } as const;
  await expect(collect(mgr.chat(target, messages))).rejects.toThrow(/anthropic/i);
});

it("does not answer from the local model when a hosted credential is missing", async () => {
  // The silent-downgrade rule (spec §4.1). A local engine IS available here;
  // the hosted agent must still refuse rather than quietly using it.
  const target = { kind: "hosted", provider: "anthropic", model: "claude-opus-5" } as const;
  const err = await collect(mgr.chat(target, messages)).catch((e) => e);
  expect(String(err)).not.toContain("qwen");
});

it("uses the hosted provider when it is connected", async () => {
  credentials.put("anthropic", { kind: "api_key", key: "sk-test" });
  // Against a fake provider server, as hosted.test.ts already does.
  expect(await collect(mgr.chat(hostedTarget, messages))).toContain("hello");
});
```

Write `collect()` as a small helper that drains the chunk generator; `hosted.test.ts` already stands up a fake provider server — reuse that pattern rather than inventing a second one.

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests, then mutate to prove they bite**

Re-add the hosted fallback branch and confirm the first test fails. A test for a rule this important is worth nothing until you have watched it catch the violation. Report what you saw.

- [ ] **Step 5: Commit**

```bash
git commit -m "fix(engine): the agent's target decides, and hosted never answers for local"
```

---

### Task 4: The providers API

**Files:**
- Modify: `apps/aroha-runtime/src/gateway/server.ts`
- Test: `apps/aroha-runtime/src/gateway/providers-api.test.ts`

**Interfaces:**
- Produces: `GET /v1/providers`, `PUT /v1/providers/:provider`, `DELETE /v1/providers/:provider`.

```
GET    /v1/providers              -> { providers: CredentialStatus[] }
PUT    /v1/providers/:provider    { apiKey } -> 204
DELETE /v1/providers/:provider    -> 204
```

**Read `handleSettingsApi` in the same file first** and follow its shape, including how it resolves the caller and how it returns a *resolved* value rather than the stored one.

- [ ] **Step 1: Write the failing tests**

```ts
it("never returns the key, on any route", async () => {
  await put("openai", "sk-secret-value-9999");
  const body = await (await fetch(`${url}/v1/providers`, { headers: auth })).text();
  expect(body).not.toContain("sk-secret-value-9999");
  expect(JSON.parse(body).providers.find((p) => p.provider === "openai").hint).toBe("9999");
});

it("refuses a provider that is not a known provider", async () => {
  const res = await fetch(`${url}/v1/providers/..%2F..%2Fescape`, {
    method: "PUT", headers: auth, body: JSON.stringify({ apiKey: "x" }),
  });
  expect(res.status).toBe(400);
});

it("requires authentication like every other route", async () => {
  expect((await fetch(`${url}/v1/providers`)).status).toBe(401);
});

it("removing a provider disconnects it", async () => {
  await put("openai", "sk-aaaa");
  await fetch(`${url}/v1/providers/openai`, { method: "DELETE", headers: auth });
  const body = await (await fetch(`${url}/v1/providers`, { headers: auth })).json();
  expect(body.providers.find((p) => p.provider === "openai").connected).toBe(false);
});
```

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests to watch them pass**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(api): connect and disconnect hosted providers without exposing keys"
```

---

### Task 5: Choosing a provider, and connecting one

**Files:**
- Modify: `apps/aroha-runtime/src/ui/page.ts`
- Modify: `apps/aroha-runtime/src/ui/styles.ts`
- Test: `apps/aroha-runtime/src/ui/screens.test.ts`

**Interfaces:**
- Consumes: `/v1/providers` (Task 4), `target` on the agent (Task 2).

Two surfaces:

1. **In Settings** — a Providers section listing the three providers, each showing connected/not with its hint, a field to paste a key, and a way to disconnect. The field is `type="password"`, and a stored key is never populated back into it — the server cannot supply it and the UI must not pretend otherwise.
2. **On an agent** — the create and edit forms choose local or a hosted provider, and the agent card shows which. A hosted provider whose credential is not connected is selectable but shows plainly that it will not answer until connected.

- [ ] **Step 1: Write the failing browser assertions**

```ts
it("shows which provider an agent uses on its card", async () => {
  await withApp(async (app) => {
    await seedHostedAgent(app, "diligence", "anthropic");
    await app.evaluate(`document.querySelector("#nav-agents").click(); true`);
    const text = await app.evaluate<string>(`document.querySelector("#gallery").innerText`);
    expect(text).toContain("Anthropic");
  });
}, 120_000);

it("never puts a stored key back into the input", async () => {
  await withApp(async (app) => {
    await connectProvider(app, "openai", "sk-secret-value-9999");
    await openSettings(app);
    const value = await app.evaluate<string>(`document.querySelector("#provider-openai-key").value`);
    expect(value).toBe("");
    expect(await app.evaluate<string>(`document.body.innerText`)).not.toContain("sk-secret-value-9999");
  });
}, 120_000);
```

- [ ] **Step 2: Run them to watch them fail** (`node scripts/compile.mjs`, then `npm run test:ui`)

- [ ] **Step 3: Build both surfaces**

- [ ] **Step 4: Verify:** `npm test && npm run test:ui && npx tsc --noEmit`, and `node --check` on the emitted script

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(ui): choose an agent's provider, and connect one without editing a file"
```

---

### Task 6: Telling the truth about where inference runs

**Files:**
- Modify: `apps/aroha-runtime/src/ui/page.ts`
- Modify: `apps/aroha-runtime/src/gateway/server.ts` (extend `/v1/edition`-style reporting if needed)
- Test: `apps/aroha-runtime/src/ui/screens.test.ts`

**This task is the reason the others are worth doing.** Spec §4.2.

Three changes:

1. **The chat header names the provider for the answering agent** — per turn, because a thread can involve several agents.
2. **A once-per-agent warning** before the first cloud turn from an agent that has documents attached. It names what leaves the machine, and the answer is remembered per agent. Not per turn — a repeated dialog manufactures consent rather than informing.
3. **The footer stops lying:**

| Workspace | Footer |
|---|---|
| every agent local | `Running on your hardware` |
| any agent hosted | `Some agents use hosted models` |

The line must not simply vanish in a mixed workspace: a disappearing line is invisible, and the person who most needs to notice their setup changed is the one least likely to see an absence.

- [ ] **Step 1: Write the failing browser assertions**

```ts
it("stops claiming everything is local once an agent is hosted", async () => {
  await withApp(async (app) => {
    const before = await app.evaluate<string>(`document.querySelector("#side-footer").innerText`);
    expect(before).toContain("Running on your hardware");

    await seedHostedAgent(app, "diligence", "anthropic");
    await app.evaluate(`location.reload(); true`);
    await app.waitFor(`document.querySelector("#side-footer")`);

    const after = await app.evaluate<string>(`document.querySelector("#side-footer").innerText`);
    expect(after).not.toContain("Running on your hardware");
    expect(after).toContain("hosted");
  });
}, 120_000);

it("warns before the first cloud turn from an agent with documents — and only once", async () => {
  await withApp(async (app) => {
    await seedHostedAgent(app, "diligence", "anthropic");
    await attachDocument(app, "diligence");
    await connectProvider(app, "anthropic", "sk-test");

    await sendTurn(app, "@diligence what renews?");
    await app.waitFor(`document.querySelector("#cloud-warning")`);
    const text = await app.evaluate<string>(`document.querySelector("#cloud-warning").innerText`);
    // It has to name what leaves, not just that something does.
    expect(text.toLowerCase()).toContain("anthropic");
    expect(text.toLowerCase()).toContain("document");
    await app.evaluate(`document.querySelector("#cloud-warning-accept").click(); true`);

    // The second turn must NOT warn again. Asserting absence is the whole
    // point: a test that only checks the warning appears would pass just as
    // happily against a dialog that fires on every single turn.
    await sendTurn(app, "@diligence and the termination clause?");
    await new Promise((r) => setTimeout(r, 1500));
    expect(await app.evaluate<boolean>(`!!document.querySelector("#cloud-warning")`)).toBe(false);
  });
}, 120_000);
```

`seedHostedAgent`, `attachDocument`, `connectProvider` and `sendTurn` are helpers you write — `screens.test.ts` already has `seedThreads` to copy the shape from.

- [ ] **Step 2: Run them to watch them fail**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Verify:** `npm test && npm run test:ui && npx tsc --noEmit`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(ui): say where inference actually runs, and warn before the first cloud turn"
```

---

## Verification

The spec's §7 is the acceptance list. Each item, and how it is shown:

1. **The "no engine" message names something real** — read it; it must not name a `config.toml` key.
2. **No configuration makes hosted answer for a local agent** — Task 3's first test, mutation-proven.
3. **A hosted agent with no credential refuses and says why** — Task 3, and the error names the provider.
4. **No credential value reaches an API response or the browser** — Task 4 and Task 5 both assert the literal key is absent from the payload and the DOM.
5. **An agent with documents warns before its first cloud turn** — Task 6, proven to fire exactly once.
6. **"Running on your hardware" appears only when true** — Task 6.
7. **Existing agents keep answering with no edit** — Task 2, and the full suite passing unchanged is itself the evidence.

Plus: `npm test` green project-wide, `npm run test:ui` green with the browser count *increased*, `npx tsc --noEmit` clean, and an end-to-end check against the compiled binary — create a hosted agent with no credential and confirm it refuses by name; connect a key; confirm it answers; confirm a local agent in the same workspace still answers locally.
