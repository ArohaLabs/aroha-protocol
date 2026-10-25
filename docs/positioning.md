<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# What Aroha Is (and Is Not)

**Owner:** @projectmed99 · **Last reviewed:** 2026-10-19 · **Review:** each release, or when the market map below changes

This page is the reference for how Aroha describes itself. Where another page disagrees with it, this page wins and the other page is a bug.

---

## Motto

> **No agent can exceed the scope it was granted.**

Short form: *Authority you can verify.*

## Vision

Every action an AI agent takes can be traced to the person who authorised it, is bounded by what they allowed, can be stopped when they change their mind, and can be proven afterwards — across vendors, without anyone taking it on trust.

## The problem

People hand work to AI agents. Those agents hand work to other agents and to tools, often run by other companies. Today, nothing that travels with the work proves:

- what each agent in the chain was allowed to do,
- that it stayed inside that, and
- what it actually did.

Identity providers can tell you *which* agent holds a token. They cannot tell a tool three hops away that the request in front of it is a narrowed, unexpired, unrevoked piece of a specific person's instruction — and they leave no record that a third party can check later.

## What Aroha solves: four questions for every action

| Question | Aroha primitive | Where it lives |
|---|---|---|
| **1. Who is acting?** A person or an agent, with a key they control | `did:aroha` identifiers, key event log with person/agent kind | `@aroha-sdk/core` |
| **2. What were they allowed to do?** A signed grant that can only narrow as it is passed on | Mandates (intent, payment, task), attenuation, room consent records | `@aroha-sdk/credentials`, conversation profile |
| **3. Can it be stopped?** Revocation every verifier sees, and a stop switch | Signed revocation status, SSF/CAEP push, graduated kill switch | registry, runtime |
| **4. What actually happened?** A record anyone can verify, including refusals | Action receipts v2 (allowed and denied), disclosure, evidence bundles, registry witness anchoring | `@aroha-sdk/core`, runtime, registry |

Everything in the reference implementation either answers one of these questions or connects them to a stack people already run.

## What Aroha is not

| Aroha is not… | Use instead | How Aroha relates |
|---|---|---|
| An agent framework or orchestrator | LangGraph, CrewAI, Claude Agent SDK, OpenAI Agents SDK | Aroha bounds what their agents may do; it does not plan or run them |
| A transport or tool protocol | MCP, A2A | Aroha rides on them (`_meta["aroha/mandate"]` over MCP, signed agent cards over A2A) |
| An identity provider | Entra Agent ID, Okta / Auth0, AWS AgentCore Identity | Aroha can take an IdP-issued identity as the root of a mandate chain; it carries authority *past* the IdP's boundary |
| A payments network or checkout protocol | AP2, Visa Intelligent Commerce, Mastercard Agent Pay, ACP | Spending mandates map onto their mandate envelopes; Aroha covers the non-payment actions around them |
| A blockchain project | — | The registry is a signed witness. On-chain contracts in `contracts/` are optional and not part of the core |
| A marketplace or commerce platform | — | `@aroha-sdk/commerce` and `@aroha-sdk/settlement` remain as extensions; they are not the product |
| A memory product | — | Shared rooms with scoped memory are the reference demonstration of the authority model in a chat with several people and agents |

## Where Aroha sits in the market

The agent-authority space has three groups. Aroha is built to work with the first two and is a direct alternative only to the third.

**Enterprise identity platforms** — Microsoft Entra Agent ID, Okta for AI Agents / Agent SSO (Cross App Access, ID-JAG), Auth0 for AI Agents, AWS Bedrock AgentCore Identity. They give agents identities and short-lived tokens inside one organisation's directory, and they are where enterprises will start. Their tokens describe *access*, issued per hop by a central server. Aroha adds a portable chain that a verifier outside that directory can check offline, and receipts that outlive the token.

**Payments mandates** — Google AP2 (now developed at the FIDO Alliance), Visa Trusted Agent Protocol / Intelligent Commerce, Mastercard Agent Pay and Verifiable Intent, the Agentic Commerce Protocol. They solve "may this agent pay, and for what" for card and checkout flows. Aroha's spending mandates are compatible in shape; Aroha's scope is every action, not only payment.

**Open delegation formats and research protocols** — Biscuit, UCAN, macaroons; individual IETF drafts on agent authorization (on-behalf-of, AIMS, AAuth); research protocols such as AIP (invocation-bound capability tokens) and HDP (human delegation provenance). These are closest to Aroha's core. Aroha's difference is that it ships the whole loop — identity, attenuating mandates, revocation push, signed receipts, a verifier profile, conformance vectors and SDKs in four languages — rather than a token format alone.

The market view behind this summary, with sources, is maintained privately by the GTM team.

## Why this approach is efficient

- **No new infrastructure for the common case.** A verifier needs the token and nothing else: `did:aroha:z` identifiers commit to their own key, so checking a chain makes no network call. Measured: a two-link chain (human → orchestrator → agent) verifies in **3.6 ms p50 / 4.4 ms p95** on a developer laptop ([B6](benchmark-methodology.md#b6-mandate-chain-verification-offline); indicative only until re-run on the controlled benchmark environment). Revocation adds one cached lookup or a push subscription.
- **No per-hop round trip to a central server.** Delegation happens by the delegating agent signing a narrower mandate, not by asking an authorization server for a new token at every hop.
- **Adopt at the edge, not by migration.** One verify call in a handler, one wrapper around an MCP server, or the remote MCP connector. Existing agents, IdPs and frameworks stay.
- **Standards over invention where they exist.** MCP authorization (RFC 9728, client ID metadata documents), SSF/CAEP security event tokens, A2A signed agent cards, OpenTelemetry. Aroha defines only what they do not: attenuating mandates and verifiable receipts.

What each framework, harness, agent and model integration covers, and how it is verified: [Support matrix](support-matrix.md).

## Map of the repository

| Group | Packages and apps | Status in the positioning |
|---|---|---|
| **Core: the four questions** | `aroha-core`, `aroha-credentials`, `aroha-delegation`, `aroha-policy`, `aroha-audit`, `aroha-bbs` (selective disclosure, unaudited), `apps/registry-server` (revocation, witness, SSF), `ArohaLabs/aroha-runtime` (kill switch, receipts, rooms), the conversation profile | The product |
| **Adapters: meet people where they are** | `aroha-mcp-server`, `aroha-mcp-guard`, `aroha-mcp-bridge`, `aroha-a2a-bridge`, `aroha-langchain-bridge`, `aroha-composio-bridge`, `aroha-hermes-bridge`, `aroha-openclaw-bridge`, `aroha-telemetry`, `skills/`, Python / Go / Java SDKs | Supported; how adoption happens |
| **Developer tooling** | `aroha-cli`, `create-aroha-agent`, `aroha-run`, `aroha-micro`, `aroha-evals`, `ArohaLabs/aroha-runtime` (UI and desktop shell), `apps/status` | Supported |
| **Extensions: kept, not promoted** | In `ArohaLabs/aroha-extensions`: `aroha-orchestrator` (sagas), `aroha-settlement`, `aroha-commerce`, `aroha-reputation`. Here: `aroha-trust`, `aroha-preferences`, `aroha-cache`, `aroha-resilience`, `aroha-chaos`, `aroha-trusted-mesh`, `aroha-registry` discovery, `apps/ipfs-gateway`, `contracts/` | Maintained for existing users. Not part of how Aroha is described |
| **Examples** | `examples/*`, `aroha-gmail-mcp`, demos | Illustrations |

No code was removed when this positioning was adopted. The documentation as it stood before is preserved on the branch `archive/pre-positioning-2026-10-19`.

## Language to use and to avoid

| Use | Avoid | Why |
|---|---|---|
| "authority", "mandate", "bounded", "verifiable receipt" | "HTTP for agents", "DNS for agents", "agent economy" | Transport and discovery are solved by MCP and A2A; claiming them invites the wrong comparison |
| "works with MCP and A2A" | "MCP connects agents to data, Aroha connects agents to each other" | Aroha is a layer on top, not a peer |
| "takes your IdP identity as the root" | "replaces OAuth" | Enterprises will not replace their IdP |
| "signed witness" | "on-chain", "trustless", "Web3" | The registry is not a blockchain |
| "Apache-2.0" | "MIT-licensed" | Relicensed 2026-10-07 |
