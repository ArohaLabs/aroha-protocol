<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Unified Desktop App — Design

**Status:** approved for planning
**Date:** 2026-08-20

One desktop application that replaces two products: the Aroha local runtime and
Aroha Document Intelligence. Document Intelligence's interface is ported into
the runtime; its proprietary retrieval engine becomes a paid add-on that is
fetched, not bundled.

---

## 1. Why this shape

Two products today. `aroha-runtime` is a single Bun binary with an embedded
interface and no runtime dependencies. `aroha-doc-intel` is a React/Vite
frontend over a FastAPI backend that needs Python, torch, and two 2.2 GB
models. A customer receiving both receives two installers, two interfaces, and
two mental models of the same company's software.

The merge is possible because of one fact discovered while surveying the code:
**the pricing boundary and the packaging boundary are the same line.**

The runtime already performs hybrid retrieval — recursive chunking, BM25, dense
vectors, reciprocal rank fusion — with zero additional dependencies. Document
Intelligence's engine adds figures, tables, layout-aware parsing, BGE
reranking, and page-level citations, and needs ~640 MB of Python plus 4.4 GB of
model weights to do it.

So the free tier is not a crippled version of the paid one. It is a smaller,
genuinely useful engine, and the paid tier is a separate artifact a free user
never downloads. Nothing has to be disabled, and nothing that can't be shipped
has to be shipped.

---

## 2. What the survey established

These are findings, not assumptions. Each one changed the design.

### 2.1 Most of doc-intel's frontend is dead code

`index.html` loads `main.tsx`, which mounts `DustApp` and nothing else.
`App.tsx` is imported by no file in the repository.

Confirmed against the built bundle rather than by reading imports: a string
unique to the live tree (`"What this document can answer"`) appears in
`dist/assets/index-DcoT1jf-.js`; strings unique to the `App.tsx` tree
(`"Business domain"`, `"Deployment environment"`, `"Document library size"`)
appear zero times.

| Tree | Lines | Ships |
|---|---|---|
| `screens/dust/*` | 4,585 | yes |
| `components/*` | 476 | yes |
| `screens/agents/ui.tsx` | 169 | yes |
| `hooks/*` | 76 | yes |
| `App.tsx` and everything it routes (Screen0–4, ScreenValidate, ScreenBatchDocs, Settings, Welcome, Improve, `screens/agents/*` except `ui.tsx`) | ~10,000 | **no** |

The port target is the live tree only. `ClaimSubdomain.tsx` and
`WixDnsSetup.tsx` (271 lines) drive the DNS subdomain-provisioning flow removed
from the protocol on 2026-08-20 and are not ported (§9.1). That leaves
**5,035 lines** to port, out of 5,306 live.

### 2.2 The API surface splits along the product boundary

Endpoints the live UI calls fall into two families:

| Family | Endpoints | Served by |
|---|---|---|
| Document intelligence | `/api/v1/documents`, `/search`, `/onboarding/{analyse,confirm,ingest,ingest/batch,profiles,recommend}`, `/validate`, `/heal/jobs`, `/state` | the knowledge provider — built-in or add-on |
| Agent concerns | `/agents`, `/agents/run`, `/agents/run/stream`, `/approvals`, `/connectors{,/check,/discover}`, `/consult`, `/conversations` | **the runtime, which already implements all of these** |

The second family maps onto existing runtime routes: `/v1/agents`, streaming
run, the `approval_required` + `/v1/resume` gate, `/v1/mcp`,
`/v1/peers/consult`, and thread storage. Doc-intel's 9,400-line FastAPI backend
therefore does not need porting. It divides into "already exists" and "is the
add-on", and the parts that are neither are not on the live path.

### 2.3 The add-on's weight is torch, and torch is there for two models

The retrieval serving path imports exactly: `FlagEmbedding`, `fastapi`, `fitz`,
`httpx`, `langchain_text_splitters`, `pydantic`,
`sentence_transformers`, `yaml`.

`scipy`, `pandas`, `pyarrow`, `litellm`, `chromadb` and `langgraph` appear in
the development virtualenv but not on this path — they belong to benchmarking
and the studio backend, and are not shipped.

| Code | Size |
|---|---|
| torch (CPU build 2.12.0+cpu) | 502 MB |
| transformers | 61 MB |
| PyMuPDF | 51 MB |
| fastapi, httpx, pydantic, yaml, splitters | ~25 MB |

≈ **640 MB, of which torch is 78%** — present solely to execute `BAAI/bge-m3`
and `BAAI/bge-reranker-v2-m3`.

Model weights are not in the virtualenv. They are fetched to a HuggingFace
cache at first use: 2.2 GB each, 4.4 GB total.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│ aroha-desktop  (Tauri, ~5 MB)                       │
│   window + process supervisor                       │
└───────────────┬─────────────────────────────────────┘
                │ spawns sidecar, reads --json handshake
┌───────────────▼─────────────────────────────────────┐
│ aroha  (Bun binary, ~95 MB)                         │
│   HTTP API + embedded UI on 127.0.0.1               │
│   ┌───────────────────────────────────────────────┐ │
│   │ KnowledgeProvider  (one interface)            │ │
│   │   ├── BuiltinProvider   — in-binary, free     │ │
│   │   └── AddonProvider     — HTTP, paid          │ │
│   └───────────────────────────────────────────────┘ │
└───────────────┬─────────────────────────────────────┘
                │ localhost HTTP, only when licensed
┌───────────────▼─────────────────────────────────────┐
│ aroha-rag-addon  (Python, fetched at activation)    │
│   RAG engine over FastAPI + model weights           │
└─────────────────────────────────────────────────────┘
```

**The base install contains no Python.** A free user downloads roughly 100 MB
and has a working product with hybrid retrieval.

### 3.1 Where the code lives

The ported interface lives in the `aroha` monorepo at
`apps/aroha-runtime/src/ui/`, because that is what compiles into the binary
that serves it.

The add-on remains in `aroha-doc-intel`, which keeps proprietary retrieval in a
separate repository from the open protocol — a property worth preserving
independently of packaging, given the stated intention to open the protocol.

---

## 4. The interface port

### 4.1 Method

The runtime's UI has no bundler and no framework. Its established unit of
organisation is a TypeScript module exporting a string, composed into one page:
`markdown.ts`, `styles.ts`, `templates.ts` and `font.ts` already work this way
and are interpolated by `page.ts`.

The port extends that pattern rather than introducing a new one. Each ported
screen becomes its own module under `src/ui/screens/`:

```
src/ui/screens/collection.ts        ← Collection.tsx        (773)
src/ui/screens/thread.ts            ← Thread.tsx            (500)
src/ui/screens/document-review.ts   ← DocumentReview.tsx    (396)
src/ui/screens/mention-composer.ts  ← MentionComposer.tsx   (414)
src/ui/screens/preview-panel.ts     ← PreviewPanel.tsx      (276)
src/ui/screens/email-setup.ts       ← EmailSetup.tsx        (269)
src/ui/screens/shell.ts             ← DustApp.tsx           (1,686)
src/ui/primitives.ts                ← screens/agents/ui.tsx (169)
```

`page.ts` composes them. No module may exceed roughly 800 lines; where a source
screen is larger, it is split by responsibility during the port rather than
transcribed whole. `DustApp.tsx` at 1,686 lines is the one certain split — it
is a shell plus routing plus state, and those separate cleanly.

### 4.2 Why the size limit is a hard rule

The existing 3,100-line `page.ts` produces one `<script>` block. On 2026-08-19 a
single unescaped `\n` inside one string in that block made the entire interface
render blank, and locating it required `node --check` on the emitted script.
The whole UI is one parse unit: any syntax error anywhere destroys all of it.

Adding 5,000 lines to a single template literal converts that from an incident
into a recurring condition. Per-module boundaries do not change the parse-unit
property, but they contain the blast radius of an edit and make each piece
individually testable.

### 4.3 Guardrails, built before the port begins

1. **A parse test per module**, extending the existing `page.test.ts` check that
   the emitted script is valid JavaScript.
2. **A headless screen harness** that loads every screen through the compiled
   binary and asserts its landmark elements exist — written and passing against
   the *current* screens before any porting starts, so it is a regression net
   rather than a description of whatever was built.
3. **Behaviour parity checks** against the React original for the screens where
   behaviour is not obvious from markup: `Collection` retrieval display,
   `Thread` streaming, `MentionComposer` mention resolution.

The order matters. A harness written after the port tests the port's
assumptions; written before, it tests the product's behaviour.

---

## 5. Knowledge tiering

### 5.1 One interface, two implementations

`KnowledgeStore`'s current surface is `add`, `list`, `search`, `contextFor`,
`status`, `remove`, returning `Hit { docId, docName, text }`.

The provider interface generalises this. The richer fields are optional, and
absent from the built-in provider rather than faked:

```ts
export interface RetrievalHit {
  docId: string;
  docName: string;
  text: string;
  /** Present only from the add-on: 1-based source page. */
  page?: number;
  /** Present only from the add-on: figure/table extractions supporting this hit. */
  artifacts?: Array<{ kind: "figure" | "table"; caption?: string; ref: string }>;
  /** Present only from the add-on: post-rerank score. */
  score?: number;
}

export interface KnowledgeProvider {
  add(name: string, text: string): Promise<KnowledgeDoc | null>;
  list(): Promise<KnowledgeDoc[]>;
  search(query: string, limit?: number): Promise<RetrievalHit[]>;
  contextFor(query: string, limit?: number): Promise<string>;
  status(): Promise<ProviderStatus>;
  remove(docId: string): Promise<boolean>;
}

export interface ProviderStatus {
  kind: "builtin" | "addon";
  docCount: number;
  chunkCount: number;
  /** Built-in: dense vectors available. Add-on: always true. */
  hybrid: boolean;
  embedModel?: string;
  /** Add-on only, and only when it is running. */
  addonVersion?: string;
}
```

`BuiltinProvider` wraps today's `KnowledgeStore` unchanged. `AddonProvider`
speaks HTTP to the add-on process.

### 5.1a Documents live in a workspace library, agents select from it

**Amended 2026-08-20, after surveying doc-intel's shell.** The two products
scope the same concerns differently, and the port has to reconcile them rather
than merge them:

| Concern | doc-intel | runtime today |
|---|---|---|
| Documents | `/api/v1/documents/{id}` — workspace-wide | `/v1/agents/{slug}/knowledge` — per agent |
| Connectors / MCP | `/connectors/{id}` — workspace-wide | per agent |
| Skills | top-level place | per agent |
| Conversations | `/agents/{id}/conversations` | per agent — **they agree, and that is the problem; see §5.1b** |

Neither model is wrong, and each throws something away. Per-agent storage makes
a customer upload the same corpus once per agent — untenable when the paid
engine's index is measured in gigabytes. Workspace-wide storage makes every
agent know the same things, which erodes the distinction that makes consulting
another firm's agent worth anything.

**The unified app therefore stores documents ONCE in a workspace library, and
each agent selects the subset it uses.** Upload once; agents still differ in
what they know.

Concretely:

- Documents live at `~/.aroha/knowledge/`, not `~/.aroha/agents/<slug>/knowledge.json`.
- An agent record carries a selection — the document ids it retrieves from.
- Retrieval is over the agent's selection, never the whole library, so an
  agent's answers stay scoped to what it was given.
- `/v1/knowledge` manages the library. `/v1/agents/:slug/knowledge` becomes the
  agent's selection: what it can see, not what it owns.
- Existing installs migrate on first start: each agent's `knowledge.json` moves
  into the library and becomes that agent's initial selection, so nobody loses
  documents and nobody's agent silently gains access to another's.

### 5.1b Conversations live in the workspace, agents participate

**Amended 2026-08-20.** §5.1a's table recorded conversations as the one concern
where the two products "already agree". They do agree — both scope a
conversation to a single agent — and that agreement is exactly what has to go.

Today a thread is stored *inside* an agent:

```
~/.aroha/agents/<slug>/threads/<digest>/<id>.jsonl
```

and `ThreadMessage` carries no author for assistant replies, because with one
agent per thread the author is implied. doc-intel abandoned this design and
says why in `Thread.tsx`'s own header: *"the previous design had one agent per
conversation, so the label was implicit and mentions were impossible."*

The runtime is that previous design. It is already half-way out — a `peer` role
with `peerDid`/`peerName` gives *remote* agents attribution — but local agents
get none.

**A conversation therefore belongs to the workspace, and agents take part in
it.** Concretely:

- Threads move to a workspace-level `~/.aroha/threads/`.
- `ThreadMessage` gains an author for assistant replies, mirroring what
  `peerDid`/`peerName` already do for peers.
- `/v1/threads` manages conversations. `/v1/agents/:slug/threads` becomes
  "threads this agent takes part in", not "threads this agent owns".
- Existing threads migrate on first start, every existing assistant message
  attributed to the agent that owned the thread — nobody loses history, and
  no message is left with an author the UI has to guess at.

**Routing: mention, then last speaker, then the workspace default.**
**Corrected 2026-08-20 after reading `DustApp.tsx` and `Thread.tsx` properly.**
An earlier draft of this section stopped at two levels and had a fresh
conversation resolve to nothing. doc-intel resolves in three
(`Thread.tsx:224`):

```
agentId = mentioned in this message
       ?? whoever answered last in this thread
       ?? the workspace default agent
```

The third level is the one that matters for the feel of the product: it is why
you can open the app, type, and get an answer without choosing anybody. The
default is a workspace setting, changed in Settings
(`DustApp.tsx:1574`), not a per-thread choice.

A thread still keeps no participant list — participants are derived from who
has actually spoken. That is the least state that can be wrong, and it is what
makes `@` mean something; in a one-agent thread it means nothing at all.

**A mention grants, it does not only route.** Mentioning a document, tool or
skill attaches it to that single message (`Thread.tsx:238-242`, carrying
`documentIds`, `connectorIds`, `skillIds`). Mentioning an *agent* decides who
answers. Those are two different operations sharing one gesture, and the port
must keep them distinct.

**What does not change.** Each agent still answers from its own knowledge
selection, memory and skills. Sharing a conversation does not merge what two
agents know; it only lets them speak in the same place. That is the same
boundary §5.1a draws for documents, and it is what keeps consulting another
firm's agent worth anything.

Connectors and skills follow the same shape for the same reason, but that is
Plan 3's work — documents come first because the paid engine indexes them and
the size argument bites hardest there.

**This also settles a defect found in Plan 1's final review.** Document CRUD
still routed through `knowledgeFor()` while retrieval went through the
provider, so an `AddonProvider` corpus would have been invisible to the
document routes and reported zero documents. With one library there is one
corpus: the add-on indexes the library, and per-agent scoping is a filter over
retrieval rather than a second store. The seam closes instead of widening.

### 5.1c The interface follows doc-intel's information architecture

**Added 2026-08-20.** The screens were being ported one at a time onto the
runtime's existing agent-first navigation, which quietly preserved the very
model §5.1b removes. The shell's structure is itself a design decision and is
replicated, not adapted.

`DustApp.tsx` opens on `place = 'thread'` (line 31). The sidebar, top to
bottom:

| Region | Contents |
|---|---|
| Primary action | **+ New conversation** |
| `Recent` | the conversation list — its own scroll region, `flex:1; minHeight:0` |
| `Workspace` | Agents · Knowledge · Tools · Skills · Spaces, each with a count |
| Network | Share your agents · Remote agents |
| Footer | Settings |

The scroll behaviour is deliberate and load-bearing, in the source's own words:
a long history *"scrolls in place instead of pushing the nav below it out of
view — the nav is what you reach for constantly, so it never moves, no matter
how many conversations pile up."*

**The consequence, stated plainly: you do not create an agent to begin.** You
open a conversation and pull in what it needs. Agents are a workspace resource
managed alongside documents and tools — not the entry point, and not the thing
a conversation belongs to.

Mapping onto what the runtime has today:

| doc-intel | runtime | Gap |
|---|---|---|
| Recent conversations | — | threads are per-agent; §5.1b closes this |
| Agents | Agents | none |
| Knowledge | Knowledge | none |
| Tools | MCP servers | naming only |
| Skills | per-agent only | needs a workspace view |
| Spaces | — | **no equivalent; out of scope until one exists** |
| Share your agents | a per-agent Publish button | needs a place |
| Remote agents | Hub | naming only |
| Settings | — | needed, if only to hold the default agent |

`Spaces` is deliberately not invented. A nav entry for a concept the runtime
does not have would be a promise the product cannot keep.

### 5.1d What the running application actually looks like

**Added 2026-08-20, from screenshots of doc-intel running against its own
data** — not from reading its source. Several of these could not have been
inferred from the code, and one contradicts what was already built.

**The layout is three columns, not two.**

```
280px sidebar  |  conversation  |  ~460px Preview rail
```

**The Preview is a persistent right rail, headed `Preview · N waiting on
you`.** This is the correction that matters: `preview-panel.ts` was ported as
a block rendered *inline in the message stream*. In the real application it is
a standing column that lists everything awaiting a decision, with each draft
collapsible and `Approve` / `Decline` at its foot. Inline is a different
product: it buries a pending decision in scrollback instead of keeping it in
view. The rail is the design.

**The conversation.** Turns are labelled `You` and the agent's display name —
never a generic "Assistant". Citations render inline as small numbered chips
with a `N sources` link beneath the turn. A gated step shows in the rail as
`Step 1: Client Email Drafter`, so a multi-step run is legible while it is
still running.

**The composer.** The routed agent sits above the input as a chip
(`Orchestration Agent`), removable, which is how the default from §5.1b is made
visible rather than implied. Placeholder: *"Ask anything. @ to bring in an
agent, document, tool or skill."*

**The `@` picker** opens above the composer, grouped under a header naming the
kinds it is showing (`TOOLS · SKILLS`), one row per item with its kind
right-aligned. It is a picker over the workspace, not an autocomplete over
agents.

**Empty state.** A conversation with no turns reads *"What would you like to
know?"* over *"Type @ to bring in an agent, a document, a tool or a skill."* —
the app teaches the mention gesture at the point of use.

**Sidebar detail.** Section labels are `RECENT`, `WORKSPACE`, and `AROHA
NETWORK` (the last in the accent). The footer carries a dark-theme toggle and
the line *"Running on your hardware"*. Counts are right-aligned on each
workspace row; `Knowledge` shows none.

### 5.2 The screens do not fork

There is one set of document screens. When the add-on is present, hits carry
page numbers and artifacts and the screens render them; when it is absent, the
same screens render what the built-in provider returns.

This is a deliberate constraint. Two parallel document experiences — a "basic"
one and a "pro" one — would double the port, double the test surface, and make
the upgrade feel like switching products rather than gaining capability.

Where the add-on is genuinely absent rather than merely quieter — a scanned PDF
the built-in provider cannot read at all — the screen says so plainly and names
what would read it. It does not present an empty result as success.

### 5.3 Provider selection

The runtime selects at startup and on licence change:

1. No valid licence → `BuiltinProvider`.
2. Valid licence, add-on not installed → `BuiltinProvider`, and the UI offers
   the download.
3. Valid licence, add-on installed → the runtime supervises the add-on process
   and uses `AddonProvider`.
4. Valid licence, add-on installed, process unhealthy → `BuiltinProvider`, and
   the UI says the add-on is down and why.

Case 4 is the one that matters. A paid customer whose add-on crashes gets
degraded retrieval and an explanation, never an error page — and never silent
degradation presented as normal, because a customer paying for reranking should
know when they are not getting it.

---

## 6. Licensing

An Ed25519-signed licence file, verified offline by the runtime using the
signing primitives already in `@aroha-sdk/core`.

It gates **the add-on only**: the download endpoint, and the runtime's
willingness to start the add-on process.

**It is not a technical control over anything else, and the design does not
pretend otherwise.** The base app is intended to become open source; any
client-side check in it is removable in one commit. The licence is therefore a
commercial instrument with an enforcement point that happens to be real — the
add-on artifact is served from infrastructure Aroha Labs operates, and cannot
be obtained without a valid licence. What is not shipped cannot be unlocked.

Contents: customer identity, issue and expiry dates, entitlement list, and a
signature over all of it. Expiry stops future downloads and updates; an
already-installed add-on continues to work for a grace period recorded in the
licence, because a customer's document search failing at midnight on a renewal
date is a support incident, not an enforcement success.

### 6.1 Explicitly rejected: a remote-agent quota

An earlier proposal limited free installs to N connected remote agents.
Rejected on two grounds.

It is unenforceable where it matters: two runtimes communicating over a LAN or
directly never touch Aroha infrastructure, so the counter would live in the
customer's own binary on the customer's own machine. The codebase already
concedes this about its existing quota — `consultQuotaPerHour` is documented as
"cost and runaway-loop protection, not a Sybil defence."

It is also strategically wrong. Metering agent-to-agent connection taxes the
network effect that makes protocol adoption worth anything, and is
irreconcilable with donating the protocol to a standards body — one cannot
donate a protocol and retain a toll on its principal verb.

Metering, if wanted later, belongs on infrastructure Aroha Labs actually
operates: the relay (`AgentRelay`, a Durable Object in the registry Worker)
carries traffic and can count it honestly. Direct LAN and peer-to-peer
connections stay free permanently.

---

## 7. Add-on delivery

> **v1 scope:** per decision 3 in §9, the add-on is installed by Aroha Labs during
> customer setup. This section describes the delivery model to grow into once
> customer count makes hand-installation impractical; none of the fetch
> infrastructure below is built for v1. The sizing analysis in §7.1 applies
> either way, because it governs how much has to be moved onto the machine
> however it gets there.

**Nothing from the add-on ships in the base installer** — neither code nor
models. Both are fetched at activation, after licence verification, from an
endpoint Aroha Labs controls rather than from HuggingFace: versions can then be
pinned, the download authenticated, and a paid product avoids a third-party
runtime dependency.

Weights are stored under the workspace so they are inspectable and removable,
not in a hidden per-user cache.

Air-gapped customers get an offline pack and a `--models-from <path>` flag.
This is required, not optional: the stated delivery is per-laptop installs into
enterprises, and some of those machines will have no route to the internet.

### 7.1 Size, and the decision that sets it

| Path | Code | Models | Activation download |
|---|---|---|---|
| torch, as today | ~640 MB | 4.4 GB | ~5.0 GB |
| ONNX + int8 | ~100 MB | ~1.1 GB | ~1.2 GB |

The ONNX path removes torch, transformers and sentence_transformers entirely,
replacing them with `onnxruntime`.

**This is a measurement, not a debate.** The repository already contains
`run_golden.py`, `run_comparison.py`, `run_auto_tune.py` and `bench-results/`.
If int8 holds accuracy on the golden set, the add-on is ~1.2 GB; if it does
not, it is ~5 GB and torch ships.

Sequencing: v1 ships whichever the benchmark supports at the time. The
conversion is not on the critical path for customer delivery, because coupling
a packaging optimisation to a delivery date is how both slip. Retrieval
accuracy is the product being sold, and it governs this choice.

---

## 8. Testing

| Layer | What it covers |
|---|---|
| Module parse tests | every UI module emits valid JavaScript |
| Screen harness | every screen renders its landmarks through the compiled binary |
| Parity checks | ported behaviour matches the React original where behaviour is non-obvious |
| Provider contract | one suite run against both `BuiltinProvider` and `AddonProvider` |
| Degradation | add-on absent, add-on unhealthy, licence expired |
| Desktop lifecycle | existing coverage retained: handshake, single-instance attach, ownership on exit |

The provider contract suite is the important one: running identical assertions
against both implementations is what keeps the free and paid paths from
diverging into two products with one name.

---

## 9. Decisions taken

1. **Scope: all live screens are ported**, except the two DNS screens in §9.1 —
   whose capability is replaced by an addressing section over the existing
   personal-name route. The seven in §4.1, plus the shared primitives and hooks.

2. **Source: `feature/dust-ux`.** The port targets that branch, not `main` — it
   is the newer interface. Its seven unpushed commits have been left untouched
   throughout and remain unpushed; the port reads from the working tree.

3. **Add-on delivery: assisted setup, not self-serve.** For v1, Aroha Labs
   installs and configures the add-on for each paying customer directly. No
   authenticated download endpoint, no licence-gated fetch service, no offline
   media pack tooling is built.

   This removes an entire subsystem from v1, and it removes it honestly: with a
   small number of enterprise customers onboarded by hand, a distribution
   service would be speculative infrastructure serving nobody. It is the right
   trade while customer count is low, and it is the wrong one once it is not —
   the trigger to revisit is the first customer nobody from Aroha Labs visits.

   The consequence for §6: **the add-on's presence is the entitlement.** It is
   installed only on machines entitled to it. The licence file still exists and
   still carries identity, entitlement and expiry — it is cheap, reuses
   existing Ed25519 primitives, and drives the provider selection in §5.3 — but
   in this model its job is bookkeeping and expiry, not distribution control.
   Nothing is built to enforce distribution, because the installation step
   already is that control.

### 9.1 DNS dropped; addressing integrated into the interface

`ClaimSubdomain.tsx` (115 lines) and `WixDnsSetup.tsx` (156) are **not ported**.
Both serve the vanity-subdomain flow removed from the protocol on 2026-08-20,
and `ClaimSubdomain` calls a provisioning route that now returns 404 in
production. Porting them would wire two screens to a backend that does not
answer.

**The capability they served is not dropped with them.** A firm wanting a
memorable address for its agent is a real need that outlives the mechanism, so
the unified interface carries addressing — by the route that already works.

The runtime already implements this end to end and simply never surfaced it:

| Piece | Where |
|---|---|
| Derive a label from the agent's public key | `derivePersonalLabel()` in `@aroha-sdk/registry` (scrypt over a 2048-word BIP-39 list) |
| Mint it against the registry | `mintPersonalName()` in `apps/aroha-runtime/src/hub/personal-name.ts` |
| HTTP route | `POST /v1/agents/:slug/personal-name`, body `{ apiKey, registryUrl }` |
| Registry endpoints | `POST /v1/personal-names`, `GET /v1/personal-names/:label` |

So this is a UI task, not a subsystem. The addressing section mounts where the
DNS screens are today — the shell's settings area, `DustApp.tsx` lines 1668 and
1681 — and calls the existing route.

It is also a strictly better answer to the same need. The label derives from the
agent's own key, so it is self-certifying and verifiable offline by
`verifyPersonalLabel()`; it needs no DNS, no vendor account, no provisioning
service, and nothing Aroha Labs can revoke. The removed flow needed all four.

DNS itself may return later under a design yet to be decided. Nothing here
forecloses it: a future screen mounts in the same settings area.

## 10. Out of scope

- Rewriting doc-intel's studio backend. It divides into routes the runtime
  already serves and routes belonging to the add-on.
- Porting the `App.tsx` tree (~10,000 lines). It does not ship today.
- DNS subdomain provisioning, removed from the protocol on 2026-08-20, and the
  two screens that drove it (§9.1). Agent addressing is IN scope, served by
  personal names through the route that already exists.
- Auto-update for the desktop app.
- Code signing, which is procurement-blocked and tracked separately.

---

## 11. Follow-on

The website's Document Intelligence page currently describes the product
without showing it. Once the unified app exists, that page gets real
screenshots of the actual interface, replacing the present description-only
treatment.
