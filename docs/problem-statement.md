<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# The Problem Aroha Solves

> Positioning reference: [What Aroha is (and is not)](positioning.md). This page explains the problem; that page is the source of truth for how Aroha describes itself.

## Agents act on our behalf, and nothing proves they stayed inside what we allowed

AI agents now book, buy, file, merge, email and pay. Increasingly they do it by handing work to other agents and tools, often run by other companies: a person asks an assistant, the assistant delegates to a specialist agent, the specialist calls a tool server.

Connecting those parties is no longer the hard part. MCP connects agents to tools; A2A connects agents to agents; identity providers now issue identities to agents. What is still missing is **authority that travels with the work**:

- The tool at the end of the chain sees a request and a token. It cannot tell which person the work came from, what that person actually allowed, or whether the agents in between widened it.
- When the person changes their mind, there is no standard way to make every agent and tool in the chain stop.
- After the fact, there is no record that a third party — an auditor, a counterparty, the person themselves — can verify without trusting the operator's own logs.

## Three concrete failures

### 1. Authority widens as it is passed on

A person tells their assistant "spend up to $500 on flights". The assistant calls a travel agent, which calls a booking tool. Each hop presents its own credential. Nothing carried along the way records the $500 limit, the purpose, or the expiry, so the booking tool enforces whatever its own API key allows. A prompt injection or a bug anywhere in the chain inherits the full power of the last credential.

### 2. Stopping is slow and partial

Revoking an API key or an OAuth grant stops one hop. Agents further down keep working with the tokens and cached decisions they already hold. There is no graduated stop — slow down, pause, stop — and no way for a downstream verifier to learn that the authority it is relying on has been withdrawn.

### 3. There is no evidence, only logs

Every operator keeps its own logs. They are not signed, they do not name everyone involved (the person, the acting agent, the delegate, the guest in a shared chat), they rarely record refused actions, and they cannot be checked by anyone outside the operator. When something goes wrong, there is no shared account of who authorised what.

## Why existing solutions fall short

| Solution | What it solves | What it leaves open |
|----------|---------------|----------------|
| MCP, A2A | Connecting agents to tools and to each other | What the caller is allowed to do, on whose behalf; evidence of what it did |
| Enterprise IdPs (Entra Agent ID, Okta / Auth0, AgentCore Identity) | Agent identities and short-lived tokens inside one organisation | Authority that narrows and stays checkable after it leaves that directory; verifiable receipts |
| OAuth token exchange, ID-JAG | One hop of delegation, issued by a central server | Multi-hop attenuation without a server round trip at each hop |
| Payment mandates (AP2, card-network agent programmes) | Whether an agent may pay, and for what | Every non-payment action around the payment |
| Capability tokens (Biscuit, UCAN, macaroons) | Offline attenuation of a token | Identity of people vs agents, revocation push, receipts, a verifier profile, conformance |
| Framework guardrails | Checks inside one codebase | Anything that crosses to another vendor's agent |

None of these is wrong. Aroha is designed to sit on top of them, not replace them.

## What Aroha defines

Aroha answers four questions for every action an agent takes:

1. **Who is acting?** People and agents get `did:aroha` identifiers backed by keys they control. A key event log records rotation and whether the identifier is a person or an agent.
2. **What were they allowed to do?** A person signs a **mandate** — actions, limits, purpose, expiry — to an agent. Each agent can pass on only a narrower mandate, signed by itself. Any verifier can check the whole chain back to the person, offline.
3. **Can it be stopped?** Revocation is signed and published by a registry witness and pushed to subscribers as security event tokens. Runtimes expose a graduated kill switch.
4. **What actually happened?** Every allowed *and refused* action produces a signed **receipt** naming the person, the acting agent and any delegate, which can be bundled as evidence and anchored with the witness.

The same four answers apply inside a shared chat: rooms record who is present and what each person consented to, every turn is signed by its speaker, and memory is scoped so an agent recalls a fact only for the people allowed to see it.

## Who benefits

- **Teams shipping agents that act for customers** — can show a customer, an auditor or a counterparty exactly what the agent was allowed to do and did.
- **Tool and API providers** — can accept requests from agents they do not control, and refuse anything outside the person's grant.
- **Security and compliance teams** — get a stop switch that reaches the whole chain, and evidence that does not depend on trusting one operator's logs.
- **People** — can grant narrowly, change their mind, and see what was done in their name.

## Further reading

- [What Aroha is (and is not)](positioning.md) — scope, market map, efficiency
- [Quickstart](quickstart.md) — issue and verify a mandate chain
- [Remote MCP connector](integrations/remote-mcp-connector.md) — add Aroha to an MCP client
- [Specification](spec/aroha-1.0.md)
