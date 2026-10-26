<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Governance & Open Standards

Aroha is designed to be owned by the industry, not by any single vendor. This document describes the governance model, standards submission process, and how to participate.

---

## Current status

| Track | Status |
|-------|--------|
| Protocol specification | v1.0 draft — frozen |
| W3C Community Group submission | Not yet proposed — plan: join the existing Agent Identity Registry Protocol Community Group and offer `did:aroha` as input |
| CNCF Sandbox proposal | Draft only, not submitted |
| npm packages | Published under `@aroha-sdk/` scope (without npm provenance) |
| License | Apache-2.0 |
| Governance model | Meritocratic open governance (this document) — a repository ruleset on `main` enforces one approving review from a code owner and the required CI checks (organisation admins can bypass); the other rules below are a **manual process** |
| Maintainers | One maintainer (bus factor 1) — see [MAINTAINERS.md](../MAINTAINERS.md) |

> **Enforcement status (2026-10-25):** the repository is public. A ruleset on `main` requires a pull request with **one approving review from a code owner** (`CODEOWNERS` names the Core Maintainer, @projectmed99, for every path), the required CI and conformance status checks, and signed commits; a second ruleset restricts release tags. **Organisation admins can bypass both.** The DCO check and the spec comment period are not enforced by repository settings: where this document says a change "requires" them, read it as the project's policy, followed as a manual process. Canonical status: [trust.md](trust.md).

---

## Design principles

1. **Vendor neutrality** — No cloud provider or framework vendor controls the protocol. Target: spec changes require multi-party consensus (today there is one maintainer and no working group, so this is not yet in effect).
2. **Minimal core** — The kernel (Layers 0–3) is frozen and conservative. Extensions are where experimentation happens.
3. **Backwards compatibility** — Existing Aroha 1.0 agents must work unmodified with future protocol versions.
4. **Privacy by design** — Consent tokens and GDPR-aligned B2C patterns are first-class, not bolted on.
5. **Verifiable without trusting the operator** — Mandates verify offline; revocation and receipts are signed and can be anchored with an independent registry witness. On-chain contracts are optional; air-gapped deployments use an in-memory registry and policy gates.

---

## W3C Community Group submission

The `docs/spec/` directory contains the full Aroha 1.0 specification formatted for W3C Community Group submission.

**Submission timeline:**
1. ✓ Protocol frozen at v1.0
2. ✓ Reference implementation complete (this repository)
3. → W3C CG submission — `docs/spec/aroha-1.0.md` as the charter specification
4. → Two independent implementations required for W3C Working Group consideration
5. → Working Group Note (informational standard)

**How to accelerate this:** Implement an independent Aroha 1.0 agent in Python, Go, or Rust and submit it as a conformance report. Two conformant independent implementations are a prerequisite for Working Group consideration; they do not trigger it automatically, and no W3C submission has been made yet.

---

## CNCF Sandbox proposal

Aroha's architecture maps cleanly onto CNCF's scope:

| CNCF criterion | Aroha alignment |
|----------------|----------------|
| Cloud-native runtime | Runs on Kubernetes, Lambda, Cloudflare Workers |
| Open governance | Apache-2.0 licence; multi-vendor spec committee is a goal, not yet in place |
| Distributed systems focus | Multi-agent saga coordination across cloud boundaries |
| gRPC/REST compatibility | Transport layer is plain HTTPS + WebSocket |
| Observability | W3C Trace Context via `@aroha-sdk/telemetry` |
| Security | mTLS + Ed25519 signatures + RBAC |

**Draft proposal:** `docs/spec/cncf-sandbox-proposal.md` (to be submitted after W3C CG acceptance).

The CNCF home would cover:
- Protocol governance (Technical Oversight Committee)
- Reference implementation stewardship
- Conformance testing infrastructure
- Ecosystem registry (`community/registry.json`) as a neutral directory

---

## Spec change process

The Aroha protocol kernel (Layers 0–3) is frozen at v1.0. The target process for changes is below. **Current reality:** there is one maintainer, no working group and no independent implementors, so steps 3–4 cannot run yet; spec changes are reviewed by the maintainer as a manual process and recorded in CHANGELOG.md.

```
1. Issue filed on GitHub with [SPEC] label
2. 2-week public comment period
3. Working group meeting (recorded, notes published)
4. Consensus vote — requires approval from ≥2 independent implementors
5. Merged to docs/spec/ with a numbered amendment
```

Extension packages (`@aroha-sdk/settlement`, `@aroha-sdk/commerce`, etc., now developed outside this repository) follow a lighter process — one reviewer approval is the policy, since extensions don't affect the wire protocol.

---

## Strategic partnerships

We are actively seeking partnerships with:

| Organisation | Ask | Why |
|-------------|-----|-----|
| **Anthropic** | List the Aroha remote MCP connector; consider `_meta["aroha/mandate"]` as a convention for delegated authority over MCP | MCP carries the call; Aroha carries what the caller is allowed to do — natural complement |
| **Vercel** | Official Aroha template in Vercel Marketplace | Serverless Aroha agents in one click for 4M+ Vercel developers |
| **Cloudflare** | Official Aroha Worker template in Cloudflare Workers Marketplace | Edge-native Aroha agents at 200+ PoPs |
| **Hugging Face** | Mandate verification in the smolagents tool-calling path | HF has the open-source agent community; Aroha bounds what those agents may do and records it |
| **LangChain** | `@aroha-sdk/langchain-bridge` as an officially recommended integration | 90k+ LangChain GitHub stars — this is the fastest path to developer adoption |
| **Databricks** | Aroha receipts as the audit record for Mosaic AI agent actions | Enterprise data platform + verifiable agent receipts = auditable enterprise agents |

**Partnership contact:** email contact@aroha-labs.com.

---

## How to get involved

### As a developer
- Star and watch the GitHub repository
- Build a bridge using `aroha create-bridge` and submit to `community/registry.json`
- File conformance reports for independent implementations

### As an organisation
- Implement Aroha 1.0 in your primary language SDK
- Join the W3C Agent Identity Registry Protocol Community Group, which the project plans to join (no Aroha-specific Community Group exists)
- Sponsor the CNCF Sandbox proposal process

### As a framework maintainer
- Integrate `@aroha-sdk/[your-framework]-bridge` as an official extension
- Co-author the bridge with the Aroha team
- Share distribution through your existing developer channels

---

## License

All Aroha specifications, reference implementations, and tooling are licensed under the [Apache License 2.0](../LICENSE).

The `@aroha-sdk/` npm namespace is managed by the Aroha protocol project. Community packages may use any namespace (`@yourorg/aroha-*` or `aroha-*` are common conventions).

---

## Conformance

A Aroha 1.0 conformant implementation must:

1. Generate and manage Ed25519 keypairs for agent identity
2. Produce `did:aroha:` DIDs with a Well-Known DID Configuration endpoint
3. Sign all outbound `ArohaEnvelope` messages with `Ed25519Signature2020`
4. Verify inbound envelope signatures, expiry, nonce, and recipient fields
5. Implement at least one of: `ArohaRequest/Response`, or `ArohaReserve/ReserveAck/Commit/CommitAck/Cancel/CancelAck`
6. Reject expired messages (past `expires` field)
7. Reject replayed nonces within the message TTL window

Conformance test suite: [docs/conformance/test-matrix.md](conformance/test-matrix.md).

Independent implementer onboarding: [docs/conformance/implementer-packet.md](conformance/implementer-packet.md).

---

## Maintainers

Maintainers are responsible for code review, issue triage, release publication, and governance participation.

| Role | Responsibilities | Review SLA |
|------|-----------------|------------|
| Core Maintainer (@projectmed99) | Protocol spec changes, all PRs, releases | 5 business days |
| Ecosystem Maintainer (vacant — covered by the Core Maintainer) | Community submissions, bridge PRs, ecosystem health | 5 business days |
| Security Maintainer (vacant — covered by the Core Maintainer) | Vulnerability intake, threat model, audit coordination | 48-hour acknowledgement (best effort), 5 business days otherwise |

**Current maintainers:** listed in [MAINTAINERS.md](../MAINTAINERS.md). Repository access is wider than the maintainer list (five accounts, three with admin and two with write access); see the "Access" section of MAINTAINERS.md. Reconciling access with roles is an owner decision.

### Becoming a Maintainer

1. Consistent contribution over ≥3 months (PRs, reviews, issue triage).
2. Nominated by an existing maintainer.
3. No objections from current maintainers within 7 days.
4. Added to `MAINTAINERS.md` and granted repository write access.

### Maintainer Offboarding

Maintainers who are inactive for 6 months are moved to Emeritus status. Emeritus maintainers retain credit but lose write access. Re-activation requires a re-nomination.

---

## Contribution Process

### Quick Reference

1. Fork the repository.
2. Create a branch: `feat/`, `fix/`, `docs/`, or `chore/` prefix.
3. Make changes. Run `npm run build && npm test && npm run lint`.
4. Open a pull request against `main`.
5. Address review feedback. All CI checks must be green.
6. A maintainer merges when approved.

Steps 5 and 6 are enforced by the `main` ruleset (required status checks, and one approving review from a code owner, who is the maintainer); organisation admins can bypass it.

Full contributing guide: [CONTRIBUTING.md](../CONTRIBUTING.md).

### PR Requirements

These are the project's merge policy. Required CI checks and one code-owner approval are enforced by the `main` ruleset (admins can bypass); the rest is checked by the maintainer by hand (see the enforcement status note above).

- [ ] CI passes (build, test, lint, typecheck)
- [ ] At least 1 maintainer approval
- [ ] No unresolved review comments
- [ ] Spec changes follow the Spec change process above (2-week comment period)
- [ ] New packages include conformance test coverage for all MUST rows they implement

### Commit Message Convention

```
<type>(<scope>): <short description>

Types: feat, fix, docs, refactor, test, chore
Scope: core, cli, credentials, registry, policy, conformance, ecosystem
```

---

## Trust & Status

The canonical trust and status page is [docs/trust.md](trust.md). All status references in this document and elsewhere must stay consistent with that page.

**Consistency rule:** If you change a status row in `trust.md`, also update this document if the same status appears here. If you update governance/W3C/CNCF status here, update `trust.md` within the same PR.
