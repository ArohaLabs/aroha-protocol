<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol Community Group — W3C Charter

**Status:** Draft — **not yet submitted.** No W3C Community Group has been proposed or formed; this document is a proposal draft. The current plan is instead to join the existing W3C *Agent Identity Registry Protocol Community Group* and offer `did:aroha` as input (see [docs/trust.md](docs/trust.md)).  
**Proposed Group Name:** Aroha Protocol Community Group  
**Proposed Short Name:** `aroha`  
**Proposed W3C URL:** https://www.w3.org/community/aroha/  
**Specification Repository:** https://github.com/ArohaLabs/aroha-protocol (`spec-public/`)  
**Reference Implementation:** https://github.com/ArohaLabs/aroha-protocol  
**Version:** 1.0 — 2026-07-01  

---

## Mission

The Aroha Protocol Community Group develops open, vendor-neutral standards for **authenticated, accountable, and economically sovereign communication between AI agents**.

As AI systems increasingly act autonomously — browsing the web, calling APIs, and delegating to other agents — there is a critical need for a shared protocol that provides:

- **Verifiable identity** so every agent interaction can be traced to a cryptographic principal
- **Signed message envelopes** so every request and response carries a non-repudiable proof of origin
- **Saga coordination** so multi-step agentic workflows can commit and compensate atomically
- **Pluggable settlement** so agents can transact value — from API credits to fiat-pegged tokens — without coupling to any specific payment network
- **Privacy-preserving consent** so human principals maintain control over data shared by their agents

The Aroha Protocol is not a framework, SDK, or cloud service. It is a protocol specification, analogous to HTTP or OAuth 2.0, which any conformant implementation may adopt independently.

---

## Scope

The Community Group will develop and maintain:

1. **The Aroha Core Specification** — Layers 0–5 of the Aroha Protocol:
   - Layer 0: Transport (HTTPS + WebSocket)
   - Layer 1: Identity (`did:aroha:` and `did:aroha-web:` DID methods)
   - Layer 2: Cryptography (Ed25519 signing, X25519 ECDH encryption, post-quantum migration path)
   - Layer 3: Messaging (16 signed message types, nonce replay protection, envelope schema)
   - Layer 4: Capability Schema Negotiation (CSN)
   - Layer 5: Saga Coordination (reserve-commit-compensate pattern, LIFO compensation, DLQ)

2. **The `did:aroha:` DID Method Specification** — a conformant W3C DID method for agent identities rooted in the Aroha Registry

3. **The `did:aroha-web:` DID Method Specification** — a two-factor domain-anchored DID method combining HTTPS and DNS TXT verification with key-rotation cool-down

4. **The Aroha Conformance Test Suite** — an executable, publicly available suite that implementations may run to demonstrate conformance at Tiers 1–3

5. **Protocol Extension Specifications** (non-normative, informational):
   - Settlement interface contracts
   - Reputation signal schema
   - Bridge protocol patterns (MCP, A2A, LangChain, Composio)

### Out of scope

The following are explicitly out of scope for this CG:

- Specific LLM models or inference APIs
- Specific blockchain networks or smart contract implementations
- Application-layer semantics (what agents *do* with their capabilities)
- Programming language SDKs (which are implementations, not specifications)

---

## Deliverables

| Deliverable | Type | Target Date |
|---|---|---|
| Aroha Core Specification 1.0 | CG Final Report | Q3 2026 |
| `did:aroha:` Method Specification 1.0 | CG Final Report | Q3 2026 |
| `did:aroha-web:` Method Specification 1.0 | CG Final Report | Q3 2026 |
| Aroha Conformance Test Suite 1.0 | CG Note | Q4 2026 |
| Aroha Protocol 1.1 (incremental) | CG Draft | Q1 2027 |

The Aroha Core Specification is already in draft form at [`docs/spec/aroha-1.0.html`](docs/spec/aroha-1.0.html) formatted as a W3C ReSpec CG-DRAFT document (published at https://www.aroha-labs.com/spec/aroha-1.0.html).

---

## Dependencies and Liaisons

The Aroha Protocol builds directly on W3C standards and IETF RFCs. The Community Group will maintain active liaison with:

| Standard | Relationship |
|---|---|
| W3C DID Core 1.0 | Aroha DIDs are intended to be conformant DID methods; `did:aroha:` and `did:aroha-web:` are not yet registered and will be submitted to the DID Method Registry |
| W3C Verifiable Credentials Data Model 2.0 | Aroha credential issuance uses the VC Data Model for credential structure |
| W3C JSON-LD 1.1 | Envelope context and credential context use JSON-LD |
| W3C Trace Context (traceparent) | `@aroha-sdk/telemetry` implements W3C Trace Context |
| IETF RFC 8032 (EdDSA) | Ed25519 signing is normative in Layer 2 |
| IETF RFC 8037 (CFRG Curves) | X25519 key agreement is normative in Layer 2 |
| IETF RFC 8615 (Well-Known URIs) | `/.well-known/aroha-agent.json` follows this convention |
| DIDComm v2 (DIF) | Aroha envelopes are structurally informed by DIDComm; interoperability is a design goal |

---

## Participation

Participation is open to W3C Members and the public under the [W3C Community Contributor License Agreement (CLA)](https://www.w3.org/community/about/agreements/cla/).

**How to join:**  
Visit https://www.w3.org/community/aroha/ and click "Join this Group".

**Communication:**
- GitHub Issues: https://github.com/ArohaLabs/aroha-protocol/issues
- Mailing list: public-aroha@w3.org (proposed)
- Weekly calls: Tuesdays 16:00 UTC (proposed)

**Contribution process:**
1. All substantive contributions must be made via GitHub Pull Request on the spec repository
2. Contributors must have signed the W3C CLA
3. Editorial changes (typos, formatting) may be merged by editors without a full vote
4. Normative changes require a 2-week review period and rough consensus among active participants
5. Objections are resolved by the Chairs, with escalation to the W3C Team if needed

---

## Decision Process

The CG operates by **rough consensus** — the principle that a decision may proceed when no sustained, substantive objection from an active participant remains unresolved.

**Editors** maintain the specification text and may make editorial changes without a vote.

**Normative changes** (changes to MUST/SHALL/MUST NOT language or to schema definitions) require:
1. A GitHub issue open for at least 7 days
2. A PR open for at least 14 days
3. No unresolved objections from active participants at close of review

**Major changes** (adding or removing a protocol layer, changing a DID method) require a formal CG poll open for at least 28 days and a minimum of 5 positive votes from distinct organisations.

---

## Intellectual Property

All participants in this Community Group agree to the terms of the [W3C Community Contributor License Agreement (CLA)](https://www.w3.org/community/about/agreements/cla/), which grants W3C and the public a royalty-free licence to use the contributions in a specification.

The reference implementation and all SDKs are licensed under the **Apache License 2.0** (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)).

Specification documents in `docs/spec/` (mirrored from `spec-public/spec/`) are currently licensed under the Apache License 2.0 (see [`spec-public/LICENSE`](spec-public/LICENSE)). If and when a W3C Community Group is formed, the specification text would be relicensed as W3C Community Group rules require (for example under the [W3C Software and Document Notice and License](https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document)). No Community Group exists yet.

**Patent policy:** CG Final Reports produced by this group are eligible to enter the W3C Patent Policy Exclusion Opportunity process if the group later transitions to a W3C Working Group.

---

## Chairs and Editors

**Proposed Chairs:**
- To be nominated by founding members at the first CG call

**Editors (current):**
- See [MAINTAINERS.md](MAINTAINERS.md)

---

## Transition to Working Group

The CG will pursue elevation to a W3C Working Group when:

1. At least **two independent implementations** have demonstrated conformance at Tier 2 or above against the Aroha Conformance Test Suite
2. The CG Final Report for Aroha Core 1.0 has been published
3. Sufficient W3C Member interest exists to charter a Working Group

An independent implementation is one that:
- Is **not** a fork of the reference TypeScript implementation in this repository
- Is written by an organisation with no financial relationship to the specification editors
- Has passed the Aroha Conformance Test Suite at Tier 2 or above and submitted the results publicly

Current conformant implementations known to the CG:
- TypeScript reference implementation (`@aroha-sdk/*`) — Tier 3 ✓
- Python SDK — Tier 2 (in progress)
- Go SDK — Tier 1 (in progress)
- Java SDK — Tier 1 (in progress)

---

## Relationship to Existing Work

| Project | Relationship |
|---|---|
| Model Context Protocol (MCP, Anthropic) | Bridge: `@aroha-sdk/mcp-bridge` wraps MCP servers as Aroha capabilities. Aroha adds identity, signing, settlement, and saga coordination on top of MCP's tool interface. |
| Agent2Agent Protocol (A2A, Google) | Bridge: `@aroha-sdk/a2a-bridge` maps A2A tasks to Aroha saga steps. Aroha adds escrow settlement and LIFO compensation. |
| LangChain / LangGraph | Bridge: `@aroha-sdk/langchain-bridge`. Aroha provides the inter-agent transport; LangChain remains the intra-agent orchestration framework. |
| W3C Verifiable Credentials | Aroha uses VC Data Model 2.0 for credential issuance (`@aroha-sdk/credentials`). Aroha does not replace VCs — it carries them. |
| W3C DID Core | Aroha defines two DID methods (`did:aroha:`, `did:aroha-web:`). They are **not yet registered** with the W3C DID Method Registry; registration is planned. |
| DIDComm v2 (DIF) | Aroha envelopes are structurally similar to DIDComm messages. Interoperability is a goal for a future extension specification. |
| OpenID for Verifiable Credentials (OID4VC) | Compatible: Aroha `@aroha-sdk/credentials` can issue OID4VC-compatible credentials. |

---

## Contact

To file a charter with W3C staff:

```
Email: groups-request@w3.org
Subject: Propose Community Group: Aroha Protocol
Body: Please create the Aroha Protocol Community Group per the attached charter.
Attach: This file (CHARTER.md)
```

Questions: open an issue at https://github.com/ArohaLabs/aroha-protocol/issues
