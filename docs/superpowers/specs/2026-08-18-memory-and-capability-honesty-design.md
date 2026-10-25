<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Context Budget and Capability Honesty — Design

**Date:** 2026-08-18
**Status:** Draft for review
**Scope:** Two related problems in aroha-doc-intel's agent surface: conversation history grows unbounded until a model call fails, and three declared capability flags do nothing. Both are cases of the agent promising more than it delivers.

---

## 1. What was verified

Every claim below was checked against the code, not inferred.

### 1.1 History is replayed whole, with no budget

`studio-backend/runner.py:385`:

```python
if prior:
    messages.extend(prior)
```

Every earlier turn in a thread is replayed on every request. There is no trimming, no windowing, no summarisation, and no token accounting anywhere in `runner.py`, `agent_graph.py`, or `model_client.py`.

Three things compete for the same context window and none of them are measured:

| Consumer | Where | Growth |
|---|---|---|
| Conversation history | `runner.py:385` | Unbounded — every turn, forever |
| RAG context block | `runner.py` system parts | Per-query, sized by retrieval |
| Tool results | `agent_graph.py`, `MAX_TOOL_ROUNDS = 3` | Bounded per turn, but added to history |

The default local model is `gemma3:4b` (`model_client.py`'s own docstring calls it "the fast local default"), which has a small context window. **This fails locally long before it fails on a cloud model** — and it fails as "the agent stopped working in this thread," which is hard to attribute to length.

The runtime (`aroha-runtime`) has the same gap plus a worse one: its `InMemorySessionStore` is a `Map` that is lost on restart, and `memory: "persistent"` silently falls back to it unless a custom store is injected.

### 1.2 Three capability flags are never read

| Flag | Declared | Read anywhere? | User-facing? |
|---|---|---|---|
| `Capabilities.memory` | `models.py:43`, `api/studio.ts:34`, `seeds.py` | **No** | No |
| `Capabilities.webSearch` | `models.py:42`, `api/studio.ts:33`, `seeds.py` | **No** | No |
| `Skill.skillType` | `models.py:141`, validated in `aroha_identity.py:48` | **No** | **Yes** |

`memory` and `webSearch` are dead in the model but never shown to a user — an agent is always created with both `false`, and nothing reads them. Low harm, but they misrepresent the API to anyone integrating against it.

`skillType` is the real problem. `DustApp.tsx:735` renders it as a **user-facing dropdown labelled "Type"**:

```tsx
{ key: 'skillType', label: 'Type', required: false,
  options: ['custom', 'rag', 'web-search', 'memory', 'code', 'data'] },
```

A user of the client's product selects **"memory"** — or "rag", or "web-search" — and gets behaviour identical to "custom". The value is validated, stored, round-tripped, and ignored. This is a visible promise the software does not keep.

---

## 2. Context budget

### 2.1 Approach

Budget by tokens, not message count. A message-count cap ("keep the last 20") is wrong in both directions: twenty short turns waste available context, and twenty turns containing RAG excerpts blow past it.

**`litellm` is already a direct dependency** (`model_client.py:25`), and it ships both pieces needed:

- `litellm.get_max_tokens(model)` — the model's context window. **Verified: this RAISES for Ollama models** (`gemma3:4b` and `ollama_chat/gemma3:4b` both throw `Model isn't mapped yet`), so it must be wrapped in try/except rather than checked for a null return.
- `litellm.token_counter(model=..., messages=...)` — real token counts for that model's tokenizer

So this needs no new dependency and no hand-rolled tokenizer.

### 2.2 Allocation

Reserve, in order, and fit history into what remains:

| Claim | Reserved |
|---|---|
| Model's max context | `get_max_tokens(model)` in try/except; **configurable fallback (default 8192)** |
| Response headroom | 20%, min 512 tokens — output needs room too |
| System prompt + RAG block | Measured, never trimmed |
| Tool schemas | Measured, never trimmed |
| **History** | Whatever is left |

System instructions and retrieved evidence are never dropped: an agent that forgets its instructions to remember chit-chat is worse than one that forgets chit-chat.

### 2.3 Trimming rule

Drop **oldest-first, in whole turns**, keeping the most recent exchanges. Never split a turn — a tool call whose result is dropped, or an assistant reply whose question is gone, produces incoherent context that is worse than a shorter one.

Always keep the current user message. If the current message alone exceeds the budget, that is a real error surfaced plainly ("this message is too long for the selected model"), not a silent truncation.

### 2.4 Visibility

`runner.py` already has a `trace` mechanism reporting "Conversation memory — replayed N earlier messages." Extend it to report when trimming occurred:

> *Conversation memory — replayed 12 of 34 earlier messages (22 dropped to fit the model's context window).*

An operator debugging "why did it forget?" needs this. Silent trimming is the same failure as silent truncation, just later.

### 2.5 Explicitly not in scope

**Summarisation of dropped turns** is the obvious next step and is deliberately deferred: it costs a model call per trim, introduces its own failure mode (a bad summary is worse than a clean gap), and cannot be evaluated until trimming exists and someone notices what is missing. Ship the budget, then decide whether summarisation earns its cost.

---

## 3. Capability honesty

Three options per flag. The recommendation differs by flag because the harm differs.

### 3.1 `Skill.skillType` — fix first

User-facing and actively misleading. Options:

| Option | Assessment |
|---|---|
| **Remove the dropdown** | Honest immediately, one-line change, loses nothing that works |
| **Implement each type** | `rag`, `web-search`, `memory`, `code`, `data` are five separate features — a project, not a fix |
| **Keep it as a label** | Only defensible if relabelled "Category" and documented as organisational, not behavioural |

**Recommended: remove the dropdown**, keep `skillType` on the model as `"custom"` for wire compatibility with `aroha_identity.py`'s manifest. A skill's *instructions* already determine what it does; the type adds nothing but an unkept promise.

### 3.2 `Capabilities.webSearch` — remove or implement

Not user-facing, so the harm is limited to API consumers. Web search is a genuinely useful capability and a plausible thing to build, but a flag that has meant nothing since it was written should not keep sitting in the model implying otherwise.

**Recommended: remove from `Capabilities`.** Reintroduce it when the feature is built — an agent needing web search can already get it through an MCP connector today, which is the mechanism that actually works.

### 3.3 `Capabilities.memory` — the interesting one

"Remembers across sessions" is a real feature people want, and unlike the other two it is *partially* true: conversations already persist per-thread. What does not exist is memory that **crosses** threads.

Options:

| Option | What it means |
|---|---|
| **Remove** | Honest; conversation history within a thread continues to work and is what most users actually mean |
| **Implement as fact extraction** | After each thread, extract durable facts to a per-agent store; retrieve relevant ones into future threads. A real feature — and a real project |
| **Redefine as thread persistence** | Rename to reflect what already happens. Misleading in a different direction: it would be always-true, so still not a meaningful toggle |

**Recommended: remove now, and treat cross-thread memory as its own scoped feature later.** Done properly it needs an extraction step, a store, a retrieval step, and — importantly — a way for a user to *see and delete* what the agent remembered about them. That last part is not optional in a product handling client data, which is exactly why it should not be smuggled in behind a boolean.

#### Status: BUILT (Phase 3 Stage 1)

The flag is back because all four conditions above are met, in the same stage:

| Condition | Where |
|---|---|
| Extraction | `apps/aroha-runtime/src/host/memory-extract.ts` — isolated context, own system prompt, no tools |
| Store | `apps/aroha-runtime/src/host/memory.ts` — `agents/<slug>/memory.json`, deduped, capped at 500 oldest-evicted |
| Retrieval | `MemoryStore.recall` — lexical token overlap, folded into the agent's own system prompt |
| See and delete | `GET`/`DELETE /v1/agents/:slug/memory`, `DELETE .../memory/:id`, plus the 🧠 dialog in the UI |

The flag itself is `AgentRecord.memory`, absent meaning off, toggled by `PATCH /v1/agents/:slug`. It is off by default because extraction costs a model call per turn and an agent that quietly starts retaining what people tell it is a worse default than one that forgets.

Two design points worth keeping:

- **The memory routes are not behind the flag.** An agent whose memory was just switched off still holds what it learned — which is exactly when someone needs to read and delete it. Turning the flag off stops new writes and erases nothing; conflating the two would mean a person who paused memory silently lost their history.
- **Extraction runs after the turn returns and is not awaited.** The user's answer has already streamed; holding the connection open for a second model call to write to a store they may never open would be a visible cost for an invisible feature. Failures are logged and dropped.

Limitations, disclosed rather than designed away:

- ~~**Retrieval is lexical, not semantic.**~~ **Fixed.** Recall is now hybrid — word overlap fused with cosine over embeddings by Reciprocal Rank Fusion — and falls back to lexical when no embedding model is installed. The original disclosure was accurate when written; it stopped being so when knowledge retrieval brought embeddings into the runtime, and the claim was corrected alongside the code. Verified against nomic-embed-text: "Which accounting software does my firm use?" recalls a fact reading "The firm uses Xero for bookkeeping", which shares no content word with it.
- **Extraction is a model's judgement.** It will keep things that do not matter and miss things that do. The store is visible and editable precisely because it will be wrong.
- **Facts are stored as written**, protected by file mode 0600, not encrypted. The deletion routes are the mitigation and the flag is off by default.
- ~~**No per-user partitioning.**~~ **Fixed in Stage 2.** Memory is now one store per person under `agents/<slug>/memory/`, keyed by a hash of the owner's id. See §3.4.

---

## 4. Interaction with the consult work

Both problems get worse under [the consult design](./2026-08-18-internal-consult-design.md):

- A **consulted** agent answers a constructed question with RAG results attached and **no human watching**. A silent truncation there is invisible to both firms, and the asking firm receives a confident answer produced from a context that quietly lost half its evidence.
- The consult **audit log** records the question and answer. If the answer was produced from a truncated context, the audit record is misleading unless truncation is recorded too.

So `ConsultAuditRecord` should carry a `contextTrimmed: bool`. Cheap to add, and it is the difference between an audit trail and a plausible-looking one.

---

## 5. Testing

- Budget arithmetic with a stubbed `get_max_tokens` — no model needed.
- A long history is trimmed to fit; the system prompt and RAG block survive; the newest turns survive.
- Turn boundaries are respected — no orphaned tool result, no reply without its question.
- An over-long single message errors plainly rather than truncating.
- The trace reports the drop count.
- A short conversation is untouched, and the pre-existing tests pass unchanged — the signal that normal use did not regress.
- After the flag removals: every existing test still passes, and `grep` finds no remaining reader (there were none to begin with, which is what makes removal safe).

---

## 6. Disclosed limitations

- **Token counts are estimates for local models.** `litellm.token_counter` is exact for models whose tokenizer it knows and approximate otherwise. The 20% response reserve absorbs the error; a model with an unknown tokenizer and a tight window may still be trimmed conservatively.
- **Trimming loses information.** Nothing here summarises what it drops (§2.5). The user is told, which is the honest minimum, not a fix.
- **Removing flags is a breaking API change** for any consumer reading `capabilities.memory` or `capabilities.webSearch`. Verified: nothing in this repo does. An external consumer would break — acceptable given both fields have always been meaningless, but it should ship in a release note rather than silently.

---

## 3.4 Per-person memory (Phase 3 Stage 2)

Stage 1 shipped memory belonging to the AGENT. On a shared install that meant two colleagues fed and read one store: a fact one of them stated in confidence would surface, unprompted, in the other's conversation. That is not a rough edge in a product handling client data — it is the failure the see-and-delete condition was written to prevent, arriving by a different door.

Fixing it required answering a question the run protocol could not: **who is speaking?** `serve()` built `HandlerContext` from the request body alone, and the `callerDid` it already derived from a verified `aroha-sig` signature was computed and discarded. A handler could not know who it was talking to.

### The `Caller` type

`@aroha-sdk/run` gains `HandlerContext.caller`, required rather than optional:

```ts
interface Caller {
  kind: "person" | "agent" | "unattributed";
  id: string;
  displayName?: string;
}
```

Three decisions, each load-bearing:

- **It is NOT on the wire.** `RunRequest` has no `caller`. A caller that could name itself in its own request body could name anyone. `buildHandlerContext` sets the field *after* spreading the parsed body, so a client that invents one is ignored rather than trusted.
- **It is required, not optional.** Every hand-built `HandlerContext` in the codebase — the LAN listener, the relay client, four test harnesses — had to say who was calling. That is the point: a handler keying anything per person gets an id belonging to nobody rather than `undefined` silently pooling every caller into one bucket. Making it optional would have made the LAN and relay paths default to "unknown" without anyone noticing.
- **Precedence is proof over assertion.** A verified `aroha-sig` signature wins; the host's `ServeOptions.resolveCaller` is consulted only when there is no signature; absent both, `unattributed`. A host bug must not be able to relabel a cryptographically identified agent as any person it likes.

### How the gateway names the human

The gateway knows who is signed in and the wire cannot carry that safely, so it sets `x-aroha-caller` on the request it builds for `agent.fetch` — **unconditionally**, deleting any inbound copy first. Overwrite, never merge: the one-line difference between a private field and an impersonation primitive, and there is a test that fails if it is changed back.

### Partitioning

One file per owner at `agents/<slug>/memory/<sha256(ownerId)>.json`. Names are hashed because a person DID in a directory listing discloses who uses this runtime to anyone who can read the workspace, without opening a file.

- A remote agent gets the unattributed bucket, never a person's — another firm's words do not belong in a local person's memory.
- **There is no admin view across owners.** A store built to hold what someone told an agent in private should not have one.
- A pre-partitioning `memory.json` migrates into the unattributed bucket, not into whoever opens the runtime first. Those facts were recorded when there was no owner; assigning one now would invent an attribution that was never made.

### Remaining limitation

`Caller.kind: "person"` is only as good as the host's identity. On a personal install with no named users everyone is unattributed and therefore shares one bucket — correct, since there is one human — but it means enabling OIDC *after* facts exist leaves those earlier facts in the shared bucket rather than migrating them to whoever stated them. Nothing recorded who that was.

---

## 7. Status of §2, the context budget

**BUILT**, in `apps/aroha-runtime`, following the allocation table above.

| Claim | Where |
|---|---|
| Model's max context | `engine/model-info.ts` reads it from Ollama's `/api/show`; `contextTokens` in config.toml is the ceiling actually planned against, default 8192 |
| Response headroom | 20%, floor 512 tokens — `host/budget.ts` |
| System prompt + retrieved passages | Measured, never trimmed |
| Tool schemas | Measured, never trimmed |
| History | Whatever remains, dropped oldest-first in whole turns |

Two departures from the design as written, both deliberate:

- **The budget is not the model's maximum.** Ollama serves a `num_ctx` window well below what a model supports — gemma3:4b reports 131072 while being served a fraction of it — and drops the excess silently. Planning against the model's own maximum would reproduce the exact failure the budget prevents, while looking correct. So the model's maximum is an upper bound and the configured value is the working figure.
- **Token counting is by characters, not a tokenizer.** Every model here has its own, the OpenAI-compatible API exposes none of them, and shipping one means either a native addon the compiled binary cannot load or a table that is wrong for whatever was pulled today. 3.5 chars/token is pessimistic on purpose: over-estimating trims one turn too many, under-estimating overflows, so the error points the safe way.

Trimming is reported through a `trace` run event rather than happening silently — silent trimming is silent truncation with a delay, and an operator asking "why did it forget?" has to be able to see that it did.

Verified as a controlled experiment: the same 62-message history with a fact planted in the first turn answers correctly at a 16000-token budget and reports "Replayed 8 of 62 earlier messages — 54 dropped" at 1500, where the model then correctly says it does not have that information.
