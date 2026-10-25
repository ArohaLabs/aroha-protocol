# Aroha — UI/UX Design Brief

A complete description of the product as it exists today, written to be handed
to a design tool. Everything below is implemented and running unless a line
says otherwise.

---

## 1. What the product is

**Aroha** is a desktop application (Tauri shell + a local Bun server that
serves an embedded web UI on `127.0.0.1`). It lets a firm run AI agents on its
own hardware, give them documents, connect tools, and let them consult other
firms' agents over a cryptographic protocol — without documents or
conversations leaving the machine unless the user explicitly chooses a hosted
model.

One sentence: **a local-first agent workspace with verifiable identity,
human-in-the-loop approvals, and a tamper-evident audit log.**

Audience: professional services firms (accountants, lawyers, consultancies) —
**not developers.** The interface must read as business software, not a
developer tool. Confidentiality is the reason they bought it.

---

## 2. The five design principles the product is built on

These are non-negotiable and should shape every screen:

1. **Never claim something that isn't true.** The footer says "Running on your
   hardware" only when every agent is local. In a mixed workspace it says
   "Some agents use hosted models" — it never silently disappears.
2. **No silent fallback.** A hosted agent with no credential *refuses the turn
   and says why*. It never quietly answers from a different model.
3. **A pending decision must stay in view**, never scroll away into history.
   Approvals live in a standing right rail, not in the message stream.
4. **Never a generic "Assistant".** Every reply is labelled with the agent that
   produced it, because several agents can speak in one conversation.
5. **Say what would appear here.** Empty states describe what fills them rather
   than apologising.

---

## 3. Information architecture

You do **not** create an agent to begin. You open a conversation and pull in
what it needs with `@`. Agents are a workspace resource, like documents.

**Three-column layout:**

```
280px sidebar   |   conversation (flex)   |   ~460px Preview rail
```

### Sidebar (top to bottom)

| Region | Contents |
|---|---|
| Brand | `Aroha` wordmark |
| Primary action | **`+ New conversation`** (filled brand button, full width) |
| `RECENT` | conversation list — **its own scroll region** (`flex:1; min-height:0`) so a long history scrolls in place and never pushes the nav below out of view |
| `WORKSPACE` | Agents · Knowledge · Tools · Skills · Activity · Request an action — each row with a right-aligned count chip |
| `AROHA NETWORK` (label in brand accent) | Share your agents · Remote agents |
| Footer | Settings · theme toggle (light/dark/system) · the runtime claim line |
| Below footer | `v1.2.3` version string, tiny and muted |

There is deliberately **no "Spaces"** entry — the runtime has no such concept
and a nav item for one would be a promise the product can't keep.

### Main column places (mutually exclusive)

`thread` (default on open) · `gallery` (Agents) · `library` (Knowledge) ·
`skills` · `activity` · `share` · `hub` (Remote agents)

---

## 4. Screens, in detail

### 4.1 Conversation (the default screen)

**Header** (hidden until an agent is on screen): agent display name, DID
beneath it in muted monospace-ish type, and a row of chips on the right:

- model name chip (e.g. `qwen2.5:7b`)
- **where this turn ran** — either a green "on" chip `On your hardware`, or a
  neutral chip naming the provider (`Anthropic`). Re-rendered per turn, not
  per thread, because several agents can answer in one conversation.
- `memory on` (green) or `remote`

**Empty state:** large `What would you like to know?` over
`Type @ to bring in an agent, a document, a tool or a skill.`

**Message stream:**

- **User turn** — plain bubble, text verbatim, never markdown-rendered.
- **Agent turn** — circular avatar (first initial, colour hashed from the
  name), the agent's name above the body, markdown-rendered body, and:
  - an **activity strip** above the body showing the agent's work as it
    happens: retrieval, skill loading, tool calls — each a row with an icon
    and a status (running / done / failed). Before this existed the user just
    saw a pause.
  - a **turn footer** appearing only when the turn ends:
    `2.4s · 1,240 in · 380 out · qwen2.5:7b` plus an **`Inspect`** button that
    opens "What the model was given".
  - inline citation chips (small, numbered) with an `N sources` link beneath.
- **Peer turn** (another firm's agent) — visually distinct, with a
  **non-collapsible** header: peer name · DID, plus redaction and provenance
  markers. It must never look identical to your own agent's reply.
- Messages animate in with a 6px rise + fade, respecting
  `prefers-reduced-motion`.

**Composer** (bottom, sticky):

- A row of removable **mention chips** above the input showing who/what is
  attached to this message — including the routed agent (e.g.
  `Orchestration Agent ×`), which is how the workspace default is made visible
  instead of implied.
- `@` button, then the input:
  placeholder `Ask anything. @ to bring in an agent, document, tool or skill`,
  then a filled `Send`.
- **The `@` picker** opens *above* the composer as a floating panel: rows
  grouped under small-caps headers naming the kinds shown (`AGENTS`,
  `REMOTE AGENTS`), one row per item with its kind right-aligned, keyboard
  navigable with a highlighted index.

**Routing rule to make legible:** who answers is decided per message —
mentioned agent, then whoever answered last, then the workspace default agent.

### 4.2 Preview rail (persistent right column)

Heading: **`Preview`**, or **`Preview · 3 waiting on you`** when decisions are
open.

Each item is a collapsible draft card for a gated tool call:

- a step label (`Step 1: Client Email Drafter`)
- the tool name, a reason, and the arguments as a formatted JSON block
- foot: **`Approve`** (filled brand) / **`Decline`** (ghost)
- once answered the card **collapses but is never removed**, showing
  `Approved — running…` or `Rejected.`

Design need: readable at 460px with long JSON, and the "waiting on you" count
must be the most scannable thing on screen.

### 4.3 Agents (gallery)

Head: `Your agents` + an explanatory paragraph + `+ New agent`.

**Agent card** — the densest component in the app and the one most in need of
design attention. It carries:

- avatar (38px, initial, hashed colour), name
- badge chips: model · `memory on` · hosted provider chip, reading either
  `Anthropic` (green/on) or **`Anthropic · not connected`** (neutral, tooltip:
  will not answer until connected under Settings)
- the system prompt as a clamped paragraph
- a stats line: what it *has* (documents, skills, tools)
- the DID, full width, truncated
- an action row of seven buttons: **Chat** (filled), then ghost:
  `Publish`, `Address`, `Skills`, `Knowledge`, `Provider`, `Memory`
- a **separate danger row** below with `Delete` (ghost-danger), so its position
  never depends on how the row above wrapped

Empty state: `No agents yet` / "An agent is a name, a system prompt and a
model. It gets its own identity and keys when you create it." / `+ New agent`.

### 4.4 Knowledge (workspace library)

Head: `Knowledge` + "Every document in the workspace library, in one place. A
document lives here once no matter how many agents use it; open an agent's own
Knowledge dialog to choose which of these it searches." + `+ Add a document`.

- An inline add form (Name, Text textarea, Cancel / `Add to library`)
- A status line and a **document list**
- Clicking a document opens **Document Review**

**Document Review** — built but gated behind the paid retrieval add-on. It
answers two questions in the order people ask them: did this go in cleanly
(chunk quality, section counts), and can the system find the answers it holds
(per-question search verdicts, expandable passages), plus a self-healing
questions list with an add-a-question form. When the add-on is absent it
renders a **locked notice** naming what would read the document — it never
presents an empty result as success.

### 4.5 Skills

Read-only aggregate: "Every skill any agent on this runtime has, in one
place." A skill is still owned by an agent; adding and removing happen from
that agent's card. Skills are SKILL.md files (frontmatter description + body).

### 4.6 Activity (audit log)

Head: `Activity` + "Every consult, action and refusal this runtime recorded,
newest first. Each entry is chained to the one before it, so a missing or
altered record shows up as a broken chain rather than a gap nobody notices." +
`Refresh`.

- **Audit health banner** — the most important status element in the app.
  Three states, each a title plus an explanatory paragraph:
  - `Chain intact` (success)
  - `Some records were not written to disk` (warning)
  - `This log no longer verifies` (danger)
- **Filter chips** row, one per event type with counts, plus `All`. Counts come
  from an unfiltered read so the chips never vanish when one is applied.
- **Entry rows** — coloured status dot, event label, actor DID, relative time.
  Expanding shows a key/value grid of the stored record (ending with
  `This record's hash` and `Names the record before`) and, when the entry
  belongs to a multi-agent interaction,
  `The whole interaction (3 records)` as a trace list.
- Empty state explains that local chats aren't recorded, and what will appear.

### 4.7 Share your agents

A card grid aggregating the per-agent Publish action: "Publish an agent's
definition or a callable endpoint to a registry, so another firm's agent can
find and consult it."

### 4.8 Remote agents (hub)

A list of discovered/registered remote agents by DID and display name.
Selecting one opens a conversation with a `remote` chip in the header. Their
answers arrive **attributed beside** your agent's, never replacing it.

---

## 5. Dialogs (modal)

Each has a bold title, an explanatory hint paragraph, fields, then a
right-aligned action row (ghost cancel + filled primary).

| Dialog | Contents |
|---|---|
| **New agent** | Template tile grid ("Start from"), Name, System prompt (6-row textarea), Model, **Where it runs** (provider select), memory checkbox |
| **Where \<agent\> runs** | Provider select + Model input + a hint explaining local vs hosted |
| **Publish \<agent\>** | Registry URL, API key (password), Mode select (definition / endpoint), conditional Endpoint URL, Visibility (public / unlisted / private), status line |
| **Address \<agent\>** | Explains the addressable name is derived from the agent's own key, not DNS. Registry URL + API key, then displays the minted label |
| **Skills for \<agent\>** | Existing skills list + Name / SKILL.md textarea |
| **Knowledge for \<agent\>** | Checkbox list over the **workspace library** — checking selects it for *this* agent. Plus an inline add-document form |
| **Settings** | Default agent select, then a **Providers** section |
| **Tools** | Connected MCP servers list, then tabs: `Browse published` (catalogue grid) / `Add manually` (Name, Command, Arguments) |
| **What the model was given** (Inspect) | The actual prompt inputs: retrieved passages, skill text, surviving history |
| **What \<agent\> remembers** | Memory toggle, fact list, `Forget everything` |
| **Request an action** | Peer list, action name, JSON parameters, `Ask what it would do` |

### Providers row (inside Settings)

Per provider: name + a status chip reading `connected · ends in ab12` or
`not connected`; then a password field (`Paste API key`), a message slot, and
`Connect` / `Replace key`, plus `Disconnect` (ghost-danger) when connected.
**The key is never returned to the browser** — only connected state and a
four-character hint.

### The cloud warning dialog (shown once per agent)

Fired before an agent's **first** hosted turn. The most consequential dialog in
the product:

- Title: **`This leaves your machine`**
- Body: "\<Agent\> answers using Anthropic, which runs on Anthropic's servers,
  not on this computer. Sending this means your message — and passages from
  this agent's documents — are sent to Anthropic."
- Scope paragraph: "This is an answer about the agent, not about these files.
  It is remembered for everyone who uses this workspace, and it covers any
  document added to \<Agent\> later — you will not be asked again while it
  stays on Anthropic."
- `Attached today (3):` followed by a document list
- Hint: "Asked once for this agent. Move it back to a local model from its card
  at any time."
- Actions: `Keep it on this machine` (ghost) / `Send to Anthropic` (primary)

---

## 6. Visual language (current tokens — refine, don't discard)

Typeface: **Public Sans**, variable weight 100–900, inlined.

Light:

```
brand #14705A   hover #0F5B49   active #0B4739   subtle #E8F3EF
bg #FBFBFA   surface #FFFFFF   surface-2 #F4F5F4   sidebar #F7F8F7
fg #12211C   fg-muted #5A6661   fg-subtle #6B7772
border #E3E6E4   border-strong #CFD5D2
danger #B4232A   warn #8A5A08   success #14705A   verified #A83634
```

Dark (warm-neutral, not pure black — long reading sessions):

```
brand #3FA98A   bg #101413   surface #171C1A   surface-2 #1F2624
sidebar #131817   fg #E8EDEB   border #262E2B
danger #F1877F   warn #E0B571   verified #F3625D
```

Radii `6 / 10 / 14 / 999`. Type scale `11 / 12.5 / 14 / 16 / 20 / 26`. Three
shadow steps. Theme selected by `[data-theme]` on `<html>`, so a person can
override what their OS says.

Reasoning worth preserving: the brand is pulled back from `#0F6E56` so it reads
as ink rather than paint; `fg-subtle` is deliberately darker than it looks like
it should be because it is used at 11px, where the lighter grey failed AA;
`verified` is a distinct semantic token for "cryptographically verified" —
never a shade of danger, even though both are red.

Motion: a 6px rise + fade for arriving messages, a blink for the thinking
indicator, a spin for loaders. All collapsed under `prefers-reduced-motion`.

---

## 7. Component inventory to design

- Sidebar nav item (icon + label + count), section heading (small caps, one in
  brand accent), primary sidebar button
- Conversation list row (title, relative time, active state)
- Chip: neutral / `on` (green) / danger, plus a **filter chip** variant
- Agent card, empty card, template tile
- Avatar (initial, name-hashed colour, two sizes)
- Message rows: user / agent / peer; activity step row; tool-call block;
  tool-result block; citation chip; turn-meta footer
- Composer: chip row, `@` button, input, send, floating grouped picker
- Preview rail card with collapse and Approve / Decline
- Audit health banner (three states), activity row + expandable key/value grid,
  trace line
- Document list row, document review sections, locked-feature notice
- Dialog shell, field group, hint paragraph, action row, password field with
  status chip
- Status line, and one empty state per place

---

## 8. States that must be designed, not left to chance

- Streaming: thinking indicator → activity steps appear → text streams →
  footer resolves. Auto-scroll sticks to the bottom unless the user scrolls up.
- Sending disabled while a turn is in flight.
- Hosted agent, provider not connected → a refusal naming the provider and
  pointing at Settings.
- No local engine detected → a message naming what to install.
- Retrieval add-on absent or unhealthy → degraded retrieval, stated plainly.
- Long history (40+ conversations) — the nav must not move.
- Long DIDs, long model names, long document names — all truncate.
- Mixed workspace footer wording.
- Every place's empty state.

---

## 9. Constraints the design has to live inside

- Rendered by a **framework-less, bundler-less** embedded page: plain DOM built
  in TypeScript modules that emit CSS and JS strings. Lean on custom properties
  and simple, composable CSS; avoid anything that presumes a component
  framework or a build step.
- **No external network requests at all** — no CDN fonts, no remote images.
  Every asset is inlined.
- Desktop window sizes primarily (roughly 1100–1800px wide). The three-column
  layout should degrade by collapsing the Preview rail first, then the sidebar.
- Light and dark are both first-class.
- Accessibility: AA contrast including 11px hint text, visible focus rings,
  `aria-expanded` on disclosures, keyboard-navigable picker and dialogs.

---

## 10. What the design most needs to deliver

1. A calmer, more considered **three-column shell** — the current one is
   functional, but sidebar, conversation and rail don't yet read as one system.
2. A **redesigned agent card** — seven ghost buttons in a row is the weakest
   moment in the product.
3. A **Preview rail** treatment that makes "3 waiting on you" impossible to
   miss without being alarming.
4. A **provenance and trust visual language**: local vs hosted, your agent vs
   another firm's agent, verified vs unverified — consistent everywhere those
   distinctions appear (cards, chat header, message attribution, footer).
5. **Activity** rendered as something a non-technical partner would actually
   read.
6. Dialog and form styling that feels like professional software rather than a
   developer console.
