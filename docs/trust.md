<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Trust & Reliability

This page is the single source of truth for Aroha's build health, standards status, security posture, and compatibility.

**Status legend:** ✅ in place and enforced by code or a verified setting · 🔄 partial / draft · ⬜ not started · ⚠️ known gap · **manual process** = done by a person, not enforced by automation · **not enforced** = the control is not active.

---

## Repository and plan constraints

The `ArohaLabs/aroha-protocol` repository is **public** since 2026-10-25; the organisation is on GitHub's **Free plan**. Its public history starts with a single squashed commit ("Aroha: initial public release"). Controls in force (verified 2026-10-25):

| Control | Status |
|---------|--------|
| Ruleset "main" on the default branch | ✅ Active — pull request required with **1 approving review from a code owner**; required status checks `Build & Test (22.x)`, `TypeScript`, `Lint`, `Python SDK (pytest)`, `Durable stores (Postgres 16, Redis 7)`, `Links (internal, blocking)`, `Aroha Conformance Suite`; **signed commits required**; force-push and deletion blocked. ⚠️ **Organisation admins can bypass** (bypass mode "always"; three admin accounts) |
| Classic branch protection | Not used — the rulesets replace it |
| `CODEOWNERS` review | ✅ Required — the "main" ruleset requires a code owner's approval, and `CODEOWNERS` names @projectmed99 for every path. ⚠️ Organisation admins can bypass |
| Ruleset "release tags" (who may create, update or delete release tags) | ✅ Active — tags matching `npm-v*`, `python-v*`, `java-v*`, `sdks/go/v*`, `runtime-v*`, `@aroha-sdk/*`, `create-aroha-agent@*` are restricted. ⚠️ Organisation admins can bypass |
| Private vulnerability reporting (GitHub security advisories intake) | ✅ Enabled — see [SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md) |
| Secret scanning and push protection | ✅ Enabled |
| Dependabot security updates | ✅ Enabled |
| CodeQL code scanning (default setup) | ✅ Active |
| Required reviewers on the `release` deployment environment | ✅ Required reviewers: @projectmed99 or @rajganesan-aroha-labs must approve each publish run (verified 2026-10-26). Deployments are not yet restricted to release tags |
| GitHub artifact attestations | ⬜ Not used |
| GitHub Discussions | ✅ Enabled — [Discussions](https://github.com/ArohaLabs/aroha-protocol/discussions) |

Repository access: five accounts hold access (three admin, two write); only one is documented as a maintainer. See the "Access" section of [MAINTAINERS.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/MAINTAINERS.md). Whether that access is appropriate is an **owner decision**.

---

## CI Status

| Check | Status |
|-------|--------|
| Build & Tests | [![CI](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml) |
| Conformance Suite | [![Conformance](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml) |
| Release Gate | [![Release Gate](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/release-gate.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/release-gate.yml) |

**CI policy:** CI runs build, typecheck and tests on every push and pull request. Since 2026-10-25, merges to `main` require the status checks listed under [Repository and plan constraints](#repository-and-plan-constraints) (the "main" ruleset); organisation admins can bypass them. The first push-triggered CI and Conformance runs on public `main` (2026-10-25) never started and are stuck queued in GitHub; CI and Conformance have since passed on pull requests, and the scheduled Conformance run passed on `main` on 2026-10-26.

**Dependency audit:** CI runs `npm audit --audit-level=high --omit=dev`. It is currently **report-only** — the dependency tree has open high/critical advisories — with accepted exceptions tracked in [`.github/audit-allowlist.json`](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/audit-allowlist.json). It becomes blocking once the tree is clean. Dependabot version updates are configured in [`.github/dependabot.yml`](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/dependabot.yml), and Dependabot security updates are enabled.

**DCO:** the [DCO workflow](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/dco.yml) runs on pull requests to `main` and checks only commits after the cut-off recorded in [CONTRIBUTING.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CONTRIBUTING.md). It is **not** one of the required checks in the "main" ruleset, so a failing DCO run is advisory (**manual process**: the reviewer does not merge a PR with a red DCO check).

---

## Standards & Governance Status

| Track | Status | Detail |
|-------|--------|--------|
| Protocol specification | ✅ v1.0 published (draft-quality; changes go through the spec process) | [aroha-1.0.md](spec/aroha-1.0.md) |
| W3C Community Group | ⬜ Not yet proposed | [CHARTER.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CHARTER.md) is a draft; nothing has been submitted to W3C |
| W3C Agent Identity Registry Protocol CG | ⬜ Not joined — **owner to join** | An existing CG (proposed 2026-04-24) whose scope covers an agent DID method, agent credentials and revocation. Joining it, and submitting `did:aroha` and the KEL as input, replaces proposing a separate CG. Owner: @projectmed99. Target: 2026-11-30. |
| `did:aroha` DID method | 🔄 Specified; registration requested on 2026-10-27 ([w3c/did-extensions#766](https://github.com/w3c/did-extensions/pull/766)), under review — **not registered** until it is merged | [did-method.md](spec/did-method.md) |
| CNCF Sandbox proposal | ⬜ Draft only, not submitted | [cncf-sandbox-proposal.md](spec/cncf-sandbox-proposal.md) |
| npm packages | ✅ Published (without npm provenance — see [Release integrity](#release-integrity)); release `npm-v2026.10.19` (2026-10-19) published 32 packages, including `@aroha-sdk/core` and `@aroha-sdk/credentials` 2.0.0 | `@aroha-sdk/*` on npmjs.com; stability tiers in [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md) |
| TypeScript SDK | ✅ Reference implementation | `@aroha-sdk/core`, `@aroha-sdk/credentials`, `@aroha-sdk/registry` |
| Python SDK | 🔄 Beta — `aroha` 2.0.0 released 2026-10-19 (`python-v2.0.0`) | `aroha` on PyPI |
| Go SDK | 🔄 Partial — envelope, signatures, spending and task mandates, conversation profile verification, registry client, saga; not released | [feature matrix](sdks/feature-matrix.md) |
| Java SDK | 🔄 Partial — envelope, signatures, spending and task mandates, conversation profile verification, registry client, saga; 174 automated tests; not released | [feature matrix](sdks/feature-matrix.md) |
| Maven Central publishing | ⬜ **Not operational** — owner must provision `SONATYPE_*` / `GPG_*` secrets; the workflow fails fast without them | [publish-maven.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-maven.yml) |
| Local runtime | ⬜ Not released — no runtime release has been published; the runtime is no longer in this repository | |
| License | ✅ Apache-2.0 | [LICENSE](https://github.com/ArohaLabs/aroha-protocol/blob/main/LICENSE) |
| Maintainers | ⚠️ One maintainer (bus factor 1) | [MAINTAINERS.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/MAINTAINERS.md) |
| Governance model | 🔄 Published; one approving review from a code owner (the Core Maintainer) on `main` is enforced by a ruleset (organisation admins can bypass); the spec comment period is a manual process | [governance.md](governance.md) |

**Consistency note:** The status rows above are the canonical source. Do not publish conflicting status in README, pitch decks, announcements or blog posts without updating this table first.

---

## Security

| Item | Status | Detail |
|------|--------|--------|
| Independent security review / SOC 2 | ⬜ Auditor not selected; no SOC 2 report | See [security/review-scope.md](security/review-scope.md) |
| Threat model | 🔄 Draft | See [security/threat-model.md](security/threat-model.md) |
| Published security advisories | None published | Fixes are recorded as CHANGELOG security entries. Private vulnerability reporting is enabled (since 2026-10-25); no GitHub security advisory has been published yet |
| Incident response process | 🔄 Draft — single maintainer, manual process | See [security/incident-response.md](security/incident-response.md) |
| Responsible disclosure | 🔄 Published — GitHub private vulnerability reporting or email | [Report a vulnerability](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new), or email contact@aroha-labs.com with the subject "SECURITY" ([SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)) |
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
| Graduated stop (`throttled` / `paused`) | ⬜ Not implemented | ⬜ Not implemented | The kill switch is on/off and covers consults |
| SSF/CAEP revocation events | ✅ The reference registry (`apps/registry-server`) is an OpenID Shared Signals transmitter: a mandate revocation emits CAEP `session-revoked`, a newly accepted KEL revocation emits CAEP `credential-change`; push (RFC 8935) or poll (RFC 8936) delivery | ⬜ The runtime does not subscribe; SDK verifiers check revocation by pull | `apps/registry-server/src/routes/ssf.test.ts`, `ssf-credential.test.ts`; CHANGELOG 2.0.0 |

Spec: [aroha-1.0 §6.6–§6.8 and §12](spec/aroha-1.0.md). Schemas and vectors: `spec-public/schemas/`, `spec-public/vectors/conversation-v1.json`. Integration drafts: [UCP mapping](integrations/ucp-mapping.md) (documentation only); [ID-JAG profile](integrations/id-jag-profile.md) — the resource-server side is implemented in `@aroha-sdk/mcp-server` and tested against a reference IdP and authorization server, not yet against a production IdP.

**To report a vulnerability:** use [GitHub private vulnerability reporting](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new) or email contact@aroha-labs.com with the subject "SECURITY" (see [SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)) — do not open a public issue.

---

## Compatibility Matrix

| Aroha Package | Node.js | TypeScript | Status |
|---------------|---------|------------|--------|
| `@aroha-sdk/core` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/cli` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/credentials` | ≥22 | ≥5.4 | ✅ |
| `@aroha-sdk/orchestrator` (no longer in this repository; 1.4.0 remains on npm) | ≥22 | ≥5.4 | ✅ |
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

The reference implementation is tested against the Aroha conformance suite on pushes and pull requests to `main` that touch `packages/**` (or the suite's config, its workflow, or the root `package.json` / `package-lock.json`), and on a weekly scheduled run (Mondays 02:00 UTC). For other changes the check still reports, as skipped-and-passing, so it can stay a required check. A failed scheduled run opens or updates a GitHub issue. See [conformance.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/conformance.yml).

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

No tags or GitHub releases exist in this public repository yet; the 2.0.0 release tags (`npm-v2026.10.19`, `python-v2.0.0`) were made in the private development repository. Older tags of the form `v1.2.3` and `python-sdk-v*` are **legacy** and are not recognised by the gate.

The gate's CHANGELOG check requires the tag to appear under a **dated release heading** in CHANGELOG.md, not under `[Unreleased]`.

- Packages are versioned **independently** (for example `@aroha-sdk/core` 2.0.0, `@aroha-sdk/cli` 1.3.0); see [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md).
- **Known gap:** package versions 1.4–1.9 were published without changelog entries (see CHANGELOG.md).
- No `file:` path dependencies are permitted in published packages.

### Release integrity

- Every publish workflow ([publish-npm.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-npm.yml), [publish-pypi.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-pypi.yml), [publish-go.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-go.yml), [publish-maven.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/publish-maven.yml)) runs the release quality gate first, and the publish job depends on it.
- Publish jobs run in a GitHub environment named `release`, which requires approval from @projectmed99 or @rajganesan-aroha-labs before a publish job runs (verified 2026-10-26). Deployments are not yet restricted to release tags, and no secrets are set yet (see [key-management.md](security/key-management.md)).
- Release tags are restricted by the "release tags" ruleset (see [Repository and plan constraints](#repository-and-plan-constraints)); organisation admins can bypass it.
- npm packages are published **without npm provenance**: every published version, including 2.0.0, was built while the repository was private, and provenance requires a public repository. The target is npm Trusted Publishing (OIDC). No GitHub artifact attestations are produced.
- The runtime and its release workflow have moved out of this repository. No runtime release has been published.
- Maven Central publishing is **not operational** until the owner provisions the `SONATYPE_*` and `GPG_*` secrets.
- Secrets inventory, custodians and rotation: [security/key-management.md](security/key-management.md).

### Content removed from the tree

GTM PDFs and third-party PDFs were removed from the working tree before the repository was made public. The public history starts with a single squashed commit that does not contain them.

---

*Last updated: 2026-10-26. Maintained by the core maintainer. Update this page whenever any status row changes.*
