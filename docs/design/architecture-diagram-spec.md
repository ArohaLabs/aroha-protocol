# Aroha Protocol — Architecture Diagram Spec (for Figma generation)

> Hand this whole file to Claude with Figma access: "Generate this architecture
> diagram in Figma, following the spec exactly."

## Canvas & style

- **Frame**: 1920 × 1200, name it `Aroha Protocol Architecture`.
- **Background**: deep navy `#0A1628`, with a subtle radial glow of `#0F6E56` at 25% opacity, top-left.
- **Palette** (brand):
  - Primary green `#0F6E56`, dark green `#085041`, mint `#5DCAA5`, pale mint `#E1F5EE`
  - Card fill `#101F35`, card stroke `#2A4159`, text `#E7EEF6`, muted text `#8496AB`
  - Danger red `#F87171`, amber `#FBBF24`, info blue `#7DD3FC`
- **Type**: Inter (or Segoe UI). Title 40/bold white; zone labels 13/bold, uppercase, letter-spacing 8%, mint; node titles 16/semibold; node subtitles 12/regular muted. Code labels in a mono font, 12.
- **Cards**: 16px corner radius, 1.5px stroke, 24px inner padding. Zones are larger rounded rects (20px radius) with 1px stroke at 40% opacity and their label pinned top-left.
- **Title block** (top-center): `Aroha Protocol` 40/bold white; subtitle 16 muted: `Cryptographically bounded authority for every agent in the chain`.

## Arrow semantics (add as a legend card, bottom-right)

| Style | Meaning |
|---|---|
| Solid mint arrow → | Authority flows down (mandates, always narrowing) |
| Dashed amber arrow ← | Receipts flow back (nested, one correlationId) |
| Solid blue arrow | Discovery / registry reads |
| Thin gray line | Runtime call (request/response) |
| Red ✗ on a line | Rejected: forged, widened, over-budget, or depth-exhausted |

## Zone 1 — "HUMANS & CLIENTS" (top strip, full width)

Three cards in a row:
1. **Human / Root Issuer** — subtitle: `issues the root mandate · approves gates`. Small key icon.
2. **AI Assistants (MCP clients)** — subtitle: `Claude Desktop · Cursor · Windsurf · Cline · Zed`.
3. **Hub Web UI** — subtitle: `discover · chat · register agents` — mono chip: `aroha-labs.com`.

## Zone 2 — "GUARD EDGE" (thin horizontal band under Zone 1)

One wide card, mint gradient fill (`#5DCAA5` → `#0F6E56`), dark text:
- **mcp-guard** — subtitle: `firewall for MCP tools — block · gate · limit · audit — fails closed`.
- Gray runtime lines from *AI Assistants* pass **through** this card down to *MCP Servers* in Zone 5. One of the three lines gets a red ✗ before the card's south edge (label: `delete_* blocked`), one turns amber with label `gate: ask human` looping back up to *Human*, one passes through labeled `allowed`.

## Zone 3 — "PROTOCOL STACK" (center-left, ~46% width; five stacked layer bars)

Stacked bars, bottom-up, each a full-width card inside the zone; left edge shows layer number chip (L0 at bottom):

| # | Layer bar title | Right-aligned mono package chips |
|---|---|---|
| L4 | **Application** | `serve()` · `@aroha-sdk/run` · Hub · Studio |
| L3 | **Orchestration** | `SagaEngine` · selector · HITL approval · `@aroha-sdk/orchestrator` |
| L2 | **Authority & Extensions** | mandates (spending/task) · attenuation · delegation chains · `@aroha-sdk/credentials` · `@aroha-sdk/delegation` |
| L1 | **Transport & Messages** | signed envelopes · `ArohaRequest/Response` · saga msgs · HTTP/WS |
| L0 | **Identity & Crypto** | `did:aroha` · Ed25519 · key rotation · `@aroha-sdk/core` |

Color the L2 bar with a 2px mint stroke (it is the thesis layer); label under the stack, small italic: `authority can only narrow as it descends`.

## Zone 4 — "AGENT WEB (runtime)" (center-right, ~34% width)

A small network diagram inside its own zone:
- Node **A — root issuer** (left), node **B — orchestrator** (center, chip `ctx.delegate()`), nodes **C — searcher** and **D — summariser** (right, stacked).
- Solid mint arrows A→B, B→C, B→D, each labeled `mandate ↓scope`.
- Dashed amber arrows back C→B, D→B, B→A labeled once: `receipt tree`.
- From C, a short line to the right ending in a red ✗, labeled `depth 0 — cannot re-delegate`.
- Under the nodes, a mini mono card:
  `orchestrator (complete)`
  `├─ searcher — web-search`
  `└─ summariser — summarise`

## Zone 5 — "INFRASTRUCTURE & TOOLS" (bottom strip, full width)

Five cards in a row:
1. **Registry** — subtitle: `discovery by capability · keys · reputation` — mono chip: `Cloudflare Workers + D1`.
2. **IPFS Gateway** — subtitle: `content-addressed manifests` — mono chip: `immutable CIDs`.
3. **Reputation Engine** — subtitle: `Bayesian Beta · asymmetric decay (τf 60d / τs 180d)`.
4. **MCP Servers** — subtitle: `GitHub · filesystem · DB · 10k+ ecosystem` (this is the card the Zone-2 guard lines land on).
5. **Sandbox Agents** — subtitle: `flight · hotel · weather · search — live, mock data`.

Blue arrows: *Hub Web UI* → *Registry* (`discover`), *B — orchestrator* → *Registry* (`resolve keys`), *Registry* → *IPFS Gateway* (`fetch manifest`). Thin gray line *Reputation Engine* ↔ *Registry*.

## Zone 6 — "ECOSYSTEM STANDARDS" (narrow vertical rail, far right)

Three small cards top-to-bottom, each connected by a thin gray line labeled `bridge` into the L2/L1 bars of the stack:
1. **MCP** — `tools` — note: `mcp-bridge · mcp-guard`
2. **A2A** — `agent messaging` — note: `a2a-bridge`
3. **AP2** — `payments` — note: `mandate chains terminate here`

Caption under the rail, small italic: `MCP calls the tools · A2A carries messages · AP2 moves money — Aroha bounds the authority in between`.

## Footer

Centered, muted, mono 12: `Apache-2.0 · spec: github.com/ArohaLabs/aroha-protocol · docs: aroha-labs.com/docs`

## Layout balance notes

- Zones 3 and 4 sit side-by-side and should share a top edge; Zone 6 is a slim rail no wider than 220px.
- Keep ≥ 40px gutters between zones; nothing touches the frame edge (64px margin).
- Every arrow label is 11/mono, placed above its line, never crossing another element.
