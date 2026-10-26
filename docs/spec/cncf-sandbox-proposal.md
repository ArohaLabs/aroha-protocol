<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol — CNCF Sandbox Proposal

**Status:** Draft — not submitted to the CNCF  
**Draft date:** 2026-07-01  
**Project name:** Aroha Protocol  
**Project website:** https://www.aroha-labs.com  
**GitHub:** https://github.com/ArohaLabs/aroha-protocol  
**License:** Apache-2.0  
**Sponsor:** To be confirmed  
**Stage requested:** Sandbox  

---

## About the project

Aroha is an open protocol for **authenticated, accountable, and economically sovereign communication between AI agents**. It defines a layered wire format, a DID-based identity scheme, and a saga coordination pattern that allows agents from different vendors and frameworks to interoperate without sharing infrastructure, credentials, or billing accounts.

As AI systems increasingly act autonomously — calling APIs, delegating tasks, and orchestrating multi-step workflows — the industry needs a shared protocol analogous to HTTP or OAuth 2.0: one that any conformant implementation can adopt independently.

Aroha is that protocol.

---

## Problem statement

Today's multi-agent systems suffer from three interoperability gaps:

1. **Identity** — Agents have no standard way to prove who they are. Every framework invents its own auth scheme (API keys, JWT tokens, OAuth scopes) with no way to verify cross-vendor claims.

2. **Accountability** — When an agent calls another agent, there is no standard audit trail. If a multi-step workflow fails or causes harm, there is no cryptographic record of which agent did what, when, and on whose behalf.

3. **Economics** — Agents that sell capabilities have no standard settlement interface. Every integration requires custom billing code; there is no standard way for an agent to charge for a capability, issue a receipt, or compensate a prior step when a saga fails.

Aroha addresses all three with a single protocol.

---

## Architecture

The core specification ([Aroha 1.0](aroha-1.0.md), a draft) defines four layers:

| Layer | Name | What it standardises |
|---|---|---|
| 0 | Transport | HTTPS + WebSocket, TLS 1.3+. No new transport — existing infrastructure works. |
| 1 | Identity | `did:aroha:` and `did:aroha-web:` DID methods, Ed25519 signing (RFC 8032). Every agent has a W3C DID. A post-quantum migration path is described in a non-normative appendix. |
| 2 | Registry | Pluggable registry (HTTP baseline, optional blockchain) holding signed capability manifests. |
| 3 | Messaging | 19 signed message types (`ArohaRequest`, `ArohaResponse`, `ArohaReserve`, `ArohaCommitAck`, `ArohaCancel`, …). Nonce replay protection, message expiry, recipient DID check. |

Defined outside the core: saga coordination (reserve-commit-compensate with LIFO compensation) and preference context in the [extensions document](extensions.md), and [Capability Schema Negotiation (CSN)](csn.md) — typed capability descriptors that callers negotiate before committing.

The kernel is Layers 0–3. Extensions (`@aroha-sdk/settlement`, `@aroha-sdk/commerce`, `@aroha-sdk/credentials`) are opt-in and do not affect the wire protocol.

---

## Cloud-native alignment

### Runs everywhere cloud-native workloads run

Aroha agents are plain HTTPS servers. No sidecar, no service mesh requirement, no cloud-specific SDK.

| Platform | Support |
|---|---|
| Kubernetes | Deploy as any HTTP workload — `ClusterIP` service + `Ingress` |
| AWS Lambda | Cold-start-safe — `@aroha-sdk/run` starts in <50 ms |
| Google Cloud Run | Stateless — session memory is pluggable (Redis, Postgres) |
| Cloudflare Workers | `@aroha-sdk/core` is pure Web Crypto API — runs in edge runtimes |
| Azure Container Apps | Standard containerised HTTP service |

### Observability — W3C Trace Context

`@aroha-sdk/telemetry` implements [W3C Trace Context](https://www.w3.org/TR/trace-context/) (`traceparent` / `tracestate`) natively. Aroha envelopes carry trace context across agent boundaries — every multi-agent saga produces a single distributed trace visible in Datadog, Jaeger, Grafana Tempo, and any OpenTelemetry-compatible backend.

### Security — defence-in-depth

| Control | Implementation |
|---|---|
| Transport security | TLS 1.3 (standard HTTPS) |
| Message integrity | Ed25519 signature on every envelope |
| Replay protection | Nonce + 5-minute expiry window on every inbound message |
| Identity | W3C DID — no API key distribution required |
| Authorisation | `@aroha-sdk/credentials` — RBAC middleware with Verifiable Credential issuance |
| Encryption | X25519 ECDH + AES-256-GCM for sensitive bodies |
| mTLS bypass | `@aroha-sdk/trusted-mesh` — skip Ed25519 on VPC-internal networks |
| Audit trail | `@aroha-sdk/audit` — SHA-256 hash-chained, tamper-evident log |
| Policy-as-Code | `@aroha-sdk/policy` — deterministic JSON policy enforcement pre-LLM |

### Multi-agent saga coordination — distributed systems native

The Aroha saga engine (`@aroha-sdk/orchestrator`) implements the reserve-commit-compensate pattern for distributed transactions across agents that are independently deployed and operated. This is the same problem domain as sagas in microservice architectures — Aroha solves it for the multi-agent layer.

---

## CNCF landscape alignment

| CNCF category | Aroha position |
|---|---|
| **App definition and development** | Protocol layer for agent-to-agent communication |
| **Orchestration and management** | Saga coordination, agent selection, fan-out |
| **Observability and analysis** | W3C Trace Context; Datadog/Grafana/Jaeger integration |
| **Security and compliance** | Ed25519 identity, RBAC, audit log, Policy-as-Code |
| **Runtime** | Works with any OCI container runtime; no runtime lock-in |

Aroha does **not** compete with:
- Service meshes (Istio, Linkerd) — Aroha rides on top of standard HTTPS
- Message queues (NATS, Kafka) — Aroha is synchronous request/response + streaming, not queuing
- Workflow engines (Argo, Temporal) — Aroha provides the inter-agent protocol; orchestration frameworks (LangChain, CrewAI) remain the intra-agent layer

---

## Current state

### Reference implementation

32 npm packages under `@aroha-sdk/*`, plus `create-aroha-agent`, published on npm (release 2.0.0, 2026-10-19; the full list and versions are in [`CHANGELOG.md`](../../CHANGELOG.md)). They include:

**Kernel:** `@aroha-sdk/core`, `@aroha-sdk/registry`

**Extensions:** `@aroha-sdk/credentials`, `@aroha-sdk/settlement`, `@aroha-sdk/commerce`, `@aroha-sdk/orchestrator`, `@aroha-sdk/preferences`, `@aroha-sdk/reputation`

**Agent lifecycle:** `@aroha-sdk/run`, `@aroha-sdk/micro`, `@aroha-sdk/evals`, `@aroha-sdk/audit`

**Bridges:** `@aroha-sdk/mcp-bridge`, `@aroha-sdk/a2a-bridge`, `@aroha-sdk/langchain-bridge`, `@aroha-sdk/hermes-bridge`, `@aroha-sdk/openclaw-bridge`, `@aroha-sdk/composio-bridge`

**Enterprise:** `@aroha-sdk/telemetry`, `@aroha-sdk/trusted-mesh`, `@aroha-sdk/cache`, `@aroha-sdk/policy`

**Reliability:** `@aroha-sdk/resilience`, `@aroha-sdk/chaos`, `@aroha-sdk/cli`

### Additional SDKs

Python: published on PyPI as `aroha` 2.0.0 (beta). Go and Java: partial implementations in `sdks/go` and `sdks/java`, not released.

### Test coverage

- 88 unit tests in `@aroha-sdk/core` (crypto, identity, messaging, DID)
- 21 conformance tests in `@aroha-sdk/run`
- Conformance suite run by GitHub Actions on pull requests that touch `packages/**` and weekly
- Total: ~400 tests across all packages

### Specification

- `docs/spec/aroha-1.0.html` — W3C ReSpec format, unofficial draft, served at https://www.aroha-labs.com/spec/aroha-1.0.html
- `docs/spec/did-aroha-method-1.0.html` — `did:aroha:` DID method spec in W3C ReSpec format, served at https://www.aroha-labs.com/spec/did-aroha-method-1.0.html; `did:aroha` is not registered in the W3C DID method registry
- `CHARTER.md` — draft W3C Community Group charter, not submitted

---

## Governance

### License

Apache License 2.0 — all code and specification documents (see `LICENSE`, `NOTICE` and `spec-public/LICENSE`), as CNCF expects for project code. Relicensed from MIT on 2026-10-07.

### Open governance model

- **Spec changes (target process):** 2-week public comment period on GitHub → consensus vote requiring ≥2 independent implementors. Today there is one maintainer and no independent implementor, so spec changes are reviewed by the maintainer.
- **Extension packages:** PR + one reviewer approval (do not affect the wire protocol)
- **Maintainer nomination:** ≥3 months consistent contribution + existing maintainer nomination + no objections within 7 days
- Full governance documented in [`docs/governance.md`](../governance.md)

### No single-vendor control (goal)

The goal is a spec committee in which ≥2 independent implementors approve any normative change to the wire protocol. That committee is not yet in place: today there is one maintainer, who reviews spec changes (see [`docs/governance.md`](../governance.md)).

### W3C Community Group

No W3C Community Group has been proposed. The plan is to join the existing Agent Identity Registry Protocol Community Group and offer `did:aroha` as input. `CHARTER.md` is a draft and has not been submitted.

---

## CNCF asks

If accepted into CNCF Sandbox, the project requests:

1. **Neutral governance home** — CNCF Technical Oversight Committee oversight for specification decisions
2. **Conformance testing infrastructure** — CNCF-hosted runner for the Aroha Conformance Test Suite, accessible to any implementation
3. **Ecosystem registry** — `community/registry.json` hosted as a neutral CNCF artifact directory (analogous to CNCF Landscape)
4. **LFX tooling** — Project lifecycle management, contributor tracking, and community health dashboards

---

## Why CNCF now

The Aroha Protocol is at the inflection point where community governance matters:

- Specification 1.0 is drafted (not yet submitted to a standards body) — the right time to transfer stewardship before ecosystem lock-in
- Reference implementation is complete and published — CNCF does not need to incubate nascent code
- Multiple SDKs exist (TypeScript and Python published; Go and Java partial, not released) — vendor-neutral governance is needed to prevent TypeScript-SDK bias in spec decisions
- Bridge ecosystem is forming (MCP, A2A, LangChain, Composio, OpenClaw, Hermes) — a neutral registry is needed to host the ecosystem directory

---

## Due diligence responses

**Does the project have a code of conduct?**  
Yes — [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md) at the repo root (Contributor Covenant v2.1).

**Does the project have a security disclosure policy?**  
Yes — [`SECURITY.md`](../../SECURITY.md). Private disclosure through GitHub private vulnerability reporting or by email to contact@aroha-labs.com with `SECURITY` in the subject; 48-hour acknowledgement target, 5 business days for everything else (one maintainer — see [`MAINTAINERS.md`](../../MAINTAINERS.md)).

**Does the project have a contributing guide?**  
Yes — [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

**Is the project listed in the CNCF Landscape?**  
Not yet — to be submitted to [landscape.cncf.io](https://landscape.cncf.io) upon Sandbox acceptance.

**Does the project have a roadmap?**  
Yes — [`CHANGELOG.md`](../../CHANGELOG.md) for historical releases; [`docs/governance.md`](../governance.md) for the W3C and CNCF submission timeline.

**What is the project's release cadence?**  
Monthly minor releases with patch releases as needed. Releases are published to npm and PyPI; the release tags so far (for example `npm-v2026.10.19`, `python-v2.0.0`) were made in the private development repository, and this repository has no tags or GitHub releases yet.

**Does the project vendor dependencies?**  
No — all dependencies are declared in `package.json` files and resolved from npm. No vendored copies.

---

## Contact

**Primary contact:** Rajagopal Ganesan (@projectmed99)  
**Email:** rajagopal.ganesan@aroha-labs.com · **Issues:** https://github.com/ArohaLabs/aroha-protocol/issues  
**CNCF Slack (proposed):** `#aroha-protocol`
