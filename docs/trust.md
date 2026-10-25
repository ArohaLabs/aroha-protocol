<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Trust & Reliability

This page is the single source of truth for Aroha's build health, standards status, security posture, and compatibility.

**Status legend:** ✅ in place and enforced by code or a verified setting · 🔄 partial / draft · ⬜ not started · ⚠️ known gap · **manual process** = done by a person, not enforced by automation · **not enforced** = the control is not active.

---

## Repository and plan constraints

The `ArohaLabs/aroha-protocol` repository is **private** and the organisation is on GitHub's **Free plan** (verified 2026-10-09). On this plan the following controls are **not available**, so none of them is in place:

| Control | Status |
|---------|--------|
| Branch protection / rulesets on `main` (required checks, required reviews) | **Not enforced** — repository plan does not support it (owner decision: make public or upgrade) |
| `CODEOWNERS` review enforcement | **Not enforced** — the file exists, but without branch protection review is a **manual process** |
| Tag protection (who may push release tags) | **Not enforced** — repository plan does not support it (owner decision: make public or upgrade) |
| Private vulnerability reporting (GitHub security advisories intake) | **Not enabled** — report by email (see [SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)) |
| Required reviewers on the `release` deployment environment | **Not enforced** — repository plan does not support it; release approval is a **manual process** |
| GitHub artifact attestations | **Not available** on this plan |
| GitHub Discussions | Disabled |

Repository access: five accounts hold access (two admin, three write); only one is documented as a maintainer. See the "Access" section of [MAINTAINERS.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/MAINTAINERS.md). Whether that access is appropriate is an **owner decision**.

---

## CI Status

| Check | Status |
|-------|--------|
| Build & Tests | [![CI](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml) |
| Conformance Suite | [![Conformance](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml) |
| Release Gate | [![Release Gate](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/release-gate.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/release-gate.yml) |

**CI policy:** CI runs build, typecheck and tests on every push and pull request. Merges to `main` are **not blocked** on these checks: they are not required checks, because the repository plan does not support branch protection (owner decision: make public or upgrade). Keeping `main` green is a **manual process**.

**Dependency audit:** CI runs `npm audit --audit-level=high --omit=dev`. It is currently **report-only** — the dependency tree has open high/critical advisories — with accepted exceptions tracked in [`.github/audit-allowlist.json`](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/audit-allowlist.json). It becomes blocking once the tree is clean. Dependabot version updates are configured in [`.github/dependabot.yml`](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/dependabot.yml); whether Dependabot **alerts** are enabled is **unverified** (owner to check in repository settings).

**DCO:** the [DCO workflow](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/dco.yml) runs on pull requests to `main` and checks only commits after the cut-off recorded in [CONTRIBUTING.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CONTRIBUTING.md). It is **not a required check** (the plan does not support required checks). No commit currently on `main` carries a `Signed-off-by` line.

---

## Standards & Governance Status

| Track | Status | Detail |
|-------|--------|--------|
| Protocol specification | ✅ v1.0 published (draft-quality; changes go through the spec process) | [aroha-1.0.md](spec/aroha-1.0.md) |
| W3C Community Group | ⬜ Not yet proposed | [CHARTER.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CHARTER.md) is a draft; nothing has been submitted to W3C |
| W3C Agent Identity Registry CG | ⬜ Not joined — **owner to join** | An existing CG (proposed 2026-04-24) whose scope covers an agent DID method, agent credentials and revocation. Joining it, and submitting `did:aroha` and the KEL as input, replaces proposing a separate CG. Owner: @projectmed99. Target: 2026-11-30. |
| `did:aroha` DID method | 🔄 Specified, **not registered** in the W3C DID Method Registry | [did-method.md](spec/did-method.md) |
| CNCF Sandbox proposal | ⬜ Draft only, not submitted | [cncf-sandbox-proposal.md](spec/cncf-sandbox-proposal.md) |
| npm packages | ✅ Published (without npm provenance — see [Release integrity](#release-integrity)); release `npm-v2026.10.19` (2026-10-19) published 32 packages, including `@aroha-sdk/core` and `@aroha-sdk/credentials` 2.0.0 | `@aroha-sdk/*` on npmjs.com; stability tiers in [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md) |
| TypeScript SDK | ✅ Reference implementation | `@aroha-sdk/core`, `@aroha-sdk/credentials`, `@aroha-sdk/registry` |
| Python SDK | 🔄 Beta — `aroha` 2.0.0 released 2026-10-19 (`python-v2.0.0`) | `aroha` on PyPI |
| Go SDK | 🔄 Partial — envelope, signatures, spending and task mandates, conversation profile verification, registry client, saga; not released | [feature matrix](sdks/feature-matrix.md) |
| Java SDK | 🔄 Partial — envelope, signatures, spending and task mandates, conversation profile verification, registry client, saga; 174 automated tests; not released | [feature matrix](sdks/feature-matrix.md) |
| Maven Central publishing | ⬜ **Not operational** — owner must provision `SONATYPE_*` / `GPG_*` secrets; the workflow fails fast without them | [publish-maven.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-maven.yml) |
| Local runtime | ⬜ Not released — no runtime release has been published | |
| License | ✅ Apache-2.0 | [LICENSE](https://github.com/ArohaLabs/aroha-protocol/blob/main/LICENSE) |
| Maintainers | ⚠️ One maintainer (bus factor 1) | [MAINTAINERS.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/MAINTAINERS.md) |
| Governance model | 🔄 Published; review and approval rules are a manual process, not enforced | [governance.md](governance.md) |

**Consistency note:** The status rows above are the canonical source. Do not publish conflicting status in README, pitch decks, announcements or blog posts without updating this table first.

---

## Security

| Item | Status | Detail |
|------|--------|--------|
| Independent security review / SOC 2 | ⬜ Auditor not selected; no SOC 2 report | See [security/review-scope.md](security/review-scope.md) |
| Threat model | 🔄 Draft | See [security/threat-model.md](security/threat-model.md) |
| Published security advisories | None published | Fixes are recorded as CHANGELOG security entries. GitHub security advisories are not in use (private vulnerability reporting is not enabled) |
| Incident response process | 🔄 Draft — single maintainer, manual process | See [security/incident-response.md](security/incident-response.md) |
| Responsible disclosure | 🔄 Published — email intake only | Report by email to the maintainer ([SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)) |
| Key and secret management | 🔄 Draft | See [security/key-management.md](security/key-management.md) |
| Production hardening guide | 🔄 Draft | See [security/hardening.md](security/hardening.md) |
| Automated alerting | 🔄 Minimal | The only automated alert is the scheduled conformance run, which opens or updates a GitHub issue on failure. There is no paging or on-call. |

### Conversation profile and protocol additions — what is enforced (2026-10-15)

"Enforced in the SDK" means the verifier function refuses the case, and a test proves it. It does **not** mean the Aroha runtime calls that function. Runtime wiring is listed separately.

| Feature | Enforced in the SDK | Enforced in the runtime | Evidence / gap |
|---|---|---|---|
| `ArohaDisclosure` on envelopes | ✅ `validateEnvelope` refuses a malformed disclosure or one naming another agent; the envelope signature covers it | ⬜ The runtime does not attach disclosures yet | `packages/aroha-core/src/messages/disclosure.test.ts` |
| Action receipt v2 (identities, `outcome`, denied receipts) | ✅ `signActionReceipt` issues v2; `verifyActionReceipt` accepts v1 and v2 and refuses unknown fields | 🔄 The runtime signs receipts for executed actions (v2 once rebuilt on this core). It does **not** emit denied receipts or fill requester, principal or `presentedHash` yet | `action-receipt-v2.test.ts`, vectors |
| `UserApproval.presentedHash` | ✅ `userApprovalSigningBytes` / `verifyUserApprovalSignature`; legacy approvals still verify | ⬜ The runtime builds and checks approval signatures inline and does not compute `presentedHash` yet | `action/user-approval.test.ts` |
| Task mandate `onBehalfOf` / `roomId` | ✅ Narrowing keeps them; `enforceTaskConstraints` refuses a wrong or missing room or member (`CONTEXT_MISMATCH`) | ⬜ `enforceTaskConstraints` still has no production caller in the runtime; guest grants are not issued | `conversation-bindings.test.ts`, vector `taskMandateV2` |
| Spending mandate `actingFor` | ✅ TypeScript and Python chain verifiers refuse a child that drops or flips it | n/a (SDK verifiers) | `conversation-bindings.test.ts`, `test_mandate_acting_for.py` |
| Signed rooms, consent records, signed turns | ✅ `verifyRoom` / `verifyConsent` (per-event signatures, membership at each event's epoch) / `verifyTurn` in `@aroha-sdk/core`; independent Python verifiers pass the same vectors | ⬜ The runtime has no rooms, person invitations, consent records or signed turns yet | `packages/aroha-core/src/conversation/*.test.ts`, `sdks/aroha-py/tests/test_conversation_vectors.py` |
| Memory record (`MemoryFact` scope, speaker kind, consent, cascade deletion) | ⬜ Schema and spec rules only | ⬜ Not implemented | `spec-public/schemas/memory-record.schema.json` |
| A2A server with signed Agent Card | ✅ `createA2aRequestHandler` verifies every inbound mandate before the handler; card signatures are checked by `verifyAgentCardSignature` | n/a (library) | `packages/aroha-a2a-bridge/src/server.test.ts`; interop with the official `@a2a-js/sdk` 1.3.0 in both directions (discovery, card signatures, `SendMessage` with and without a valid mandate, `GetTask` / `CancelTask`) runs in CI on localhost: `packages/aroha-a2a-bridge/src/interop-a2a-js.test.ts` |
| OTLP export and receipt trace links | ✅ Best-effort exporter (drops spans and never blocks); receipts carry a validated `traceparent` | ⬜ Not wired into the runtime | `packages/aroha-telemetry/src/otlp.test.ts` |
| Credential vault rule (the model never has access to credentials) | n/a | 🔄 Credentials stay in the OS keystore and transport; tool results are not filtered for secrets | [hardening §11](security/hardening.md#11-credential-vault-rule) |
| Evidence preservation | n/a | 🔄 Manual runbook; witnessed anchoring is off by default | [evidence-preservation.md](security/evidence-preservation.md) |
| Graduated stop (`throttled` / `paused`), SSF/CAEP revocation events | ⬜ Not implemented | ⬜ Not implemented | The kill switch is on/off and covers consults; revocation is pull-only |

Spec: [aroha-1.0 §6.6–§6.8 and §12](spec/aroha-1.0.md). Schemas and vectors: `spec-public/schemas/`, `spec-public/vectors/conversation-v1.json`. Integration drafts: [UCP mapping](integrations/ucp-mapping.md) (documentation only); [ID-JAG profile](integrations/id-jag-profile.md) — the resource-server side is implemented in `@aroha-sdk/mcp-server` and tested against a reference IdP and authorization server, not yet against a production IdP.

**To report a vulnerability:** email the maintainer listed in [MAINTAINERS.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/MAINTAINERS.md) (see [SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)) — do not open a public issue.

---

## Compatibility Matrix

| Aroha Package | Node.js | TypeScript | Status |
|---------------|---------|------------|--------|
| `@aroha-sdk/core` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/cli` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/credentials` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/orchestrator` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/registry` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/mcp-bridge` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/a2a-bridge` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/langchain-bridge` | ≥22 | ≥5.4 | ✅ |

**Protocol bridges:**

| Bridge | Direction | Protocol version | Tested |
|--------|-----------|-----------------|--------|
| MCP bridge | MCP ↔ Aroha | MCP / Aroha 1.0 | Unit tests |
| A2A bridge | A2A ↔ Aroha | A2A 1.0 / Aroha 1.0 | Unit tests and CI interop with the official `@a2a-js/sdk` 1.3.0 in both directions |
| LangChain bridge | LangChain ↔ Aroha | LC 0.2+ / Aroha 1.0 | Unit tests |

---

## Conformance

The reference implementation is tested against the Aroha conformance suite on pushes and pull requests to `main` that touch `packages/**`, and on a weekly scheduled run (Mondays 02:00 UTC). A failed scheduled run opens or updates a GitHub issue. See [conformance.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/conformance.yml).

| Layer | Tests | Status |
|-------|-------|--------|
| L0 — DID & Identity | — | See CI |
| L1 — Signed Envelopes | — | See CI |
| L2 — Capability Registry | — | See CI |
| L3 — Saga Pattern | — | See CI |
| L4 — Commerce | — | See CI |

Full test matrix: [conformance/test-matrix.md](conformance/test-matrix.md)

Conformance tiers: [conformance/tiers.md](conformance/tiers.md)

Independent implementer onboarding: [conformance/implementer-packet.md](conformance/implementer-packet.md)

---

## Release Hygiene

### Release tag scheme

The [release quality gate](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/release-gate.yml) recognises these tags:

| Artifact | Tag format |
|----------|-----------|
| A single npm package | `@aroha-sdk/<name>@<version>` |
| `create-aroha-agent` | `create-aroha-agent@<version>` |
| Batch npm release | `npm-v<anything>` |
| Python SDK | `python-v<version>` |
| Java SDK | `java-v<version>` |
| Go SDK | `sdks/go/v<version>` |

Older tags of the form `v1.2.3` and `python-sdk-v*` exist in the repository. They are **legacy** and are not recognised by the gate.

The gate's CHANGELOG check requires the tag to appear under a **dated release heading** in CHANGELOG.md, not under `[Unreleased]`.

- Packages are versioned **independently** (for example `@aroha-sdk/core` 2.0.0, `@aroha-sdk/cli` 1.3.0); see [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md).
- **Known gap:** package versions 1.4–1.9 were published without changelog entries (see CHANGELOG.md).
- No `file:` path dependencies are permitted in published packages.

### Release integrity

- Every publish workflow ([publish-npm.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-npm.yml), [publish-pypi.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-pypi.yml), [publish-go.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-go.yml), [publish-maven.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-maven.yml), [runtime-release.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/runtime-release.yml)) runs the release quality gate first, and the publish job depends on it.
- Publish jobs run in a GitHub environment named `release`. **Required reviewers on that environment are not configured** — the repository plan does not support them — so release approval is a **manual process** until the owner upgrades the plan or makes the repository public.
- Tag protection is **not enforced** (see [Repository and plan constraints](#repository-and-plan-constraints)): anyone with write access can push a release tag.
- npm packages are published **without npm provenance** (provenance requires a public repository). The target, once the repository is public, is npm Trusted Publishing (OIDC). No GitHub artifact attestations are produced.
- The runtime release attaches a CycloneDX SBOM and `checksums.txt`. Runtime binaries are **unsigned**: Windows binaries are not signed, and macOS signing steps exist but the required signing secrets are not provisioned, so macOS binaries are unsigned too. No runtime release has been published yet.
- Maven Central publishing is **not operational** until the owner provisions the `SONATYPE_*` and `GPG_*` secrets.
- Secrets inventory, custodians and rotation: [security/key-management.md](security/key-management.md).

### Content removed from the tree

GTM PDFs and third-party PDFs were removed from the working tree but **remain in git history**. No history rewrite has been done — that is pending an owner decision.

---

*Last updated: 2026-10-21. Maintained by the core maintainer. Update this page whenever any status row changes.*
