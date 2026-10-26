<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

---
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Aroha

**Aroha Protocol**

<p class="tagline">
No agent can exceed the scope it was granted. Aroha is the open protocol for authority that travels with the work:
who is acting, what a person allowed, how to stop it, and a receipt anyone can verify — across MCP, A2A and any vendor.
</p>

<div class="badges">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0--draft-6200ea">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue">
  <img alt="Node" src="https://img.shields.io/badge/node-%3E%3D22-brightgreen">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.4-3178c6">
  <a href="https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Packages" src="https://img.shields.io/badge/npm-%40aroha--sdk-6a1b9a">
  <img alt="Status" src="https://img.shields.io/badge/W3C%20CG-not%20yet%20proposed-lightgrey">
</div>

[Get Started](quickstart.md){ .md-button .md-button--primary }
[The Problem We Solve](problem-statement.md){ .md-button }
[What Aroha Is (and Is Not)](positioning.md){ .md-button }
[View on GitHub](https://github.com/ArohaLabs/aroha-protocol){ .md-button }

</div>

---

## The Problem

Agents now act for people, and hand work to other agents and tools run by other companies. Connecting them is solved. Proving what each one was allowed to do is not.

<div class="grid cards" markdown>

-   :material-arrow-expand-all: **Authority widens as it is passed on**

    ---

    Each hop presents its own credential. The person's limit, purpose and expiry are lost on the way, so the last tool enforces whatever its own key allows.

-   :material-hand-back-left-off-outline: **Stopping is slow and partial**

    ---

    Revoking one grant stops one hop. Agents further down keep working, and nothing tells a downstream verifier that the authority is gone.

-   :material-file-question-outline: **Logs, not evidence**

    ---

    Each operator keeps its own unsigned logs. Nobody outside can check who authorised what, and refused actions are rarely recorded.

</div>

> **MCP and A2A connect agents. Identity providers name them. Aroha bounds what they may do, and proves what they did.**

[Read the full problem statement →](problem-statement.md){ .md-button }

---

## How Aroha Solves It

Four questions, answered for every action.

<div class="grid cards" markdown>

-   :material-fingerprint: **1. Who is acting?**

    ---

    People and agents get `did:aroha` identifiers backed by their own keys, with a key event log that records rotation and whether the holder is a person or an agent.

-   :material-file-sign: **2. What were they allowed to do?**

    ---

    A person signs a mandate — actions, limits, purpose, expiry. Each agent can pass on only a narrower one. Any verifier checks the chain back to the person, offline, in milliseconds.

-   :material-stop-circle-outline: **3. Can it be stopped?**

    ---

    Signed revocation status from a registry witness, pushed to subscribers as SSF/CAEP security events, and an on/off kill switch.

-   :material-receipt-text-check-outline: **4. What actually happened?**

    ---

    A signed receipt for every allowed and refused action, naming the person, the acting agent and any delegate. Bundle receipts as evidence and anchor them with the witness.

-   :material-account-group-outline: **Shared chats with people and agents**

    ---

    Rooms record who is present and what each person consented to; every turn is signed by its speaker; memory is scoped so an agent recalls a fact only for people allowed to see it.

-   :material-puzzle: **Works with what you run**

    ---

    A remote MCP server and an MCP guard, A2A signed agent cards, LangChain and Composio bridges, OpenTelemetry export, Agent Skills, and SDKs for TypeScript, Python, Go and Java.

</div>

[What Aroha is (and is not) →](positioning.md){ .md-button }

---

## 60-Second Quickstart

=== "Run the demo"

    ```bash
    git clone https://github.com/ArohaLabs/aroha-protocol
    cd aroha-protocol
    npm install && npm run build
    npm run demo:mandate
    ```

=== "Scaffold a new agent"

    ```bash
    npm install -g @aroha-sdk/cli
    aroha init my-agent --type provider --capabilities search-flights,book-flight
    cd my-agent && npm install && npm run dev
    ```

=== "Convert from A2A / MCP"

    ```bash
    npm install -g @aroha-sdk/cli
    aroha convert --from a2a --endpoint http://localhost:8080
    # or:
    aroha convert --from mcp --endpoint http://localhost:8080
    ```

`demo:mandate` runs in seconds with no network: a person grants an assistant $1,000 for flights, the assistant narrows it to $450 for a flight agent, the flight agent narrows it to one $389.99 payment — and every widened, tampered, expired, wrong-recipient or wrong-key mandate is refused.

More demos: `npm run demo:chat` (LLM agents exchanging signed messages), `npm run demo:fintech`, `npm run demo:vc` (multi-agent travel and research scenarios).

---

## Protocol in One Diagram

```mermaid
sequenceDiagram
    participant P as Person
    participant A as Assistant agent
    participant S as Specialist agent
    participant T as Tool / API
    participant W as Registry witness

    P->>A: Mandate (book flights, ≤ $500, 1 h) signed by Person
    A->>S: Narrower mandate (≤ $300) signed by Assistant, chain attached
    S->>T: Request + mandate chain + holder proof
    T->>T: Verify chain to Person offline; check limits
    T->>W: Revocation status (cached / pushed)
    T-->>S: Result + signed receipt (allowed or denied)
    P->>W: Revoke
    W-->>T: Security event pushed — next request refused
```

---

## Package Architecture

```
Core — the four questions
  @aroha-sdk/core         Identity (did:aroha), signed envelopes, receipts, conversation profile
  @aroha-sdk/credentials  Mandates, attenuation, chain verification, revocation hooks
  @aroha-sdk/delegation   Multi-hop delegation with depth limits and stitched receipts
  @aroha-sdk/policy       Deterministic limits checked before any model sees a request
  registry-server         Revocation status, SSF push, witness anchoring
  aroha-runtime           Local runtime: kill switch, receipts, rooms, scoped memory (separate repository; not yet released)

Adapters
  @aroha-sdk/mcp-server   Remote MCP server (2026 authorization spec)
  @aroha-sdk/mcp-guard    Mandate checks in front of any MCP server
  @aroha-sdk/mcp-bridge   MCP ↔ Aroha (_meta["aroha/mandate"] with holder proof)
  @aroha-sdk/a2a-bridge   A2A ↔ Aroha, signed agent cards
  @aroha-sdk/langchain-bridge · composio-bridge · telemetry (OTLP)

Extensions (maintained, optional)
  orchestrator (sagas) · settlement · commerce · reputation  (developed outside this repository; on npm)
  preferences · cache · registry discovery
```

See [the repository map](positioning.md#map-of-the-repository) for every package.

---

## Protocol Layers

| # | Layer | What it defines |
|---|-------|----------------|
| 0 | **Transport** | HTTPS endpoints, `/.well-known/aroha-agent.json`, WebSocket streaming |
| 1 | **Identity** | `did:aroha:` DIDs, Ed25519 keys, Verifiable Credentials, RBAC |
| 2 | **Registry** | Signed witness: revocation status, anchoring, agent metadata (optional discovery extension) |
| 3 | **Messaging** | Signed JSON-LD envelopes, 19 message types, replay protection |

Sagas (Reserve → Commit → Cancel) and preference context are extensions, specified in the [extensions document](spec/extensions.md).

[Read the full specification →](spec/aroha-1.0.md){ .md-button }
