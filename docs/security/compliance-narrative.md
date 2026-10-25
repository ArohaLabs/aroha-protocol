<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Compliance Narrative — SOC 2 & ISO 27001 Mapping

**Owner:** Security Agent  
**Version:** 1.0 — 2026-05-28  
**Status:** Draft — not reviewed by auditor  
**Audience:** Enterprise buyers, compliance teams, and auditors evaluating Aroha for production use

This document maps Aroha's security controls to SOC 2 Type II Trust Service Criteria (TSC) and ISO 27001:2022 Annex A controls. It provides a narrative for enterprise procurement and compliance conversations.

> **Self-assessed; not auditor-reviewed.** No SOC 2 report or ISO 27001 certification exists, and no auditor has evaluated this mapping. It describes how controls *could* map, as input to your own assessment.

---

## Summary

Aroha is an open-source protocol, not a SaaS service. Formal SOC 2 certification applies to operators deploying Aroha, not to the protocol itself. However, the reference implementation is designed to make SOC 2 and ISO 27001 compliance achievable for operators:

- **Cryptographic controls** (CC6, CC7) are built into the protocol — all agent communications are signed with Ed25519 and optionally encrypted.
- **Access controls** (CC6) are enforced via DID-based authentication — no unauthenticated agent invocation is possible.
- **Availability** (A1) is supported by the saga pattern's automatic rollback, preventing partial state that could block recovery.
- **Change management** (CC8) uses a CI and release quality gate, but merge approval and required checks are **not enforced** — the repository is private on GitHub's Free plan, which does not support branch protection (owner decision: make public or upgrade). Review is a **manual process** by a single maintainer.

> **Status legend:** ✅ enforced by code or a verified setting · ✅ (config) available in code, operator must configure · 🔄 partial · **Manual process** done by a person, not enforced · **Not enforced** control not active.

---

## SOC 2 Trust Service Criteria Mapping

### CC1 — Control Environment

| Criterion | Aroha Control | Status |
|-----------|--------------|--------|
| CC1.1 — COSO principles and commitment to integrity | Apache-2.0-licensed open governance; code of conduct; contributor DCO (checked on PRs for commits after a cut-off; not a required check; no commit on `main` is signed off yet) | 🔄 Partial |
| CC1.2 — Board oversight of security | No board or independent oversight body exists. Governance model documented in governance.md; one maintainer | **Not in place** |
| CC1.3 — Policies and responsibilities | SECURITY.md, MAINTAINERS.md, CONTRIBUTING.md published | 🔄 Documented; adherence is a manual process |
| CC1.4 — Commitment to competence | Maintainer nomination process; review SLAs documented (best effort, single maintainer) | 🔄 Documented; manual process |
| CC1.5 — Accountability | MAINTAINERS.md names one maintainer; four other accounts hold admin/write access with undocumented roles (owner decision) | 🔄 Partial |

### CC6 — Logical and Physical Access Controls

| Criterion | Aroha Control | Status |
|-----------|--------------|--------|
| CC6.1 — Restrict access to authorized users | Every agent interaction requires a valid DID and Ed25519 signature | ✅ |
| CC6.2 — New access provisioned based on authorization | Agents self-register with DID; capability grants managed by policy layer (`@aroha-sdk/policy`) | ✅ |
| CC6.3 — Access removed when no longer authorized | Key rotation and DID deactivation prevent further access | ✅ |
| CC6.6 — Logical access controls (authentication) | Ed25519 signature on every envelope; no unauthenticated requests | ✅ |
| CC6.7 — Transmission encryption | TLS 1.3+ required for transport (see hardening guide) | ✅ (config) |
| CC6.8 — Detection of unauthorized access | Signature verification failure logging; replay detection | ✅ |

### CC7 — System Operations

| Criterion | Aroha Control | Status |
|-----------|--------------|--------|
| CC7.1 — Detection and monitoring | Telemetry via `@aroha-sdk/telemetry` (W3C Trace Context) for operators. Project-side automated alerting is limited to the weekly scheduled conformance run, which opens or updates a GitHub issue on failure | 🔄 Partial |
| CC7.2 — Monitor for configuration changes | CI/release gate run on changes; branch protection on `main` | **Not enforced** — repository plan does not support branch protection (owner decision: make public or upgrade) |
| CC7.3 — Response to threats | Incident response playbook (incident-response.md); single maintainer | 🔄 Draft; manual process |
| CC7.4 — Evaluation and communication of security events | Responsible disclosure by email (SECURITY.md); CHANGELOG security entries. GitHub security advisories / private vulnerability reporting not enabled | 🔄 Partial |
| CC7.5 — Recovery from events | Saga automatic rollback; durable saga state store | ✅ |

### CC8 — Change Management

| Criterion | Aroha Control | Status |
|-----------|--------------|--------|
| CC8.1 — Changes authorized, designed, documented, approved | PR review process; spec change process (2-week comment period). Required reviews and `CODEOWNERS` enforcement unavailable on the current plan | **Manual process** — not enforced |
| CC8.1 — Changes tested | CI quality gate (build, test, lint, typecheck) runs on every push and PR; not a required check | 🔄 Runs; not enforced |
| CC8.1 — Changes reviewed for security | PR checklist includes security considerations; maintainer review | **Manual process**; formal security review pending |
| CC8.1 — Release authorization | Publish workflows run the release quality gate first; publish runs in a `release` environment without required reviewers (plan does not support them); tag protection unavailable | **Manual process** — not enforced |

### A1 — Availability

| Criterion | Aroha Control | Status |
|-----------|--------------|--------|
| A1.1 — Capacity planning | Saga timeout configuration; registry rate limiting | ✅ (config) |
| A1.2 — Environmental threats | Cloud-native design; stateless agents with external state store | ✅ |
| A1.3 — Recovery | Saga rollback on failure; durable saga state prevents data loss | ✅ |

---

## ISO 27001:2022 Annex A Mapping (Selected Controls)

| Annex A Control | Description | Aroha Mapping |
|-----------------|-------------|---------------|
| A.5.15 — Access control | Identity-based access | DID + Ed25519 authentication on every envelope |
| A.5.17 — Authentication information | Credential management | Ed25519 keypair; key rotation; secrets manager guidance |
| A.8.3 — Information access restriction | Restrict data access | `@aroha-sdk/policy` capability-level access control |
| A.8.7 — Protection against malware | Malware controls | Open source supply chain; CI `npm audit` (report-only until open high/critical advisories are cleared); Dependabot version updates. npm packages are published **without** provenance (requires a public repository); runtime binaries are unsigned |
| A.8.9 — Configuration management | Secure configuration | Hardening guide; production configuration checklist |
| A.8.15 — Logging | Audit logging | Telemetry package; security event logging guidance |
| A.8.16 — Monitoring activities | Continuous monitoring | CI conformance runner (weekly schedule plus PR/push to `main`; failure opens a GitHub issue); signature failure logging for operators |
| A.8.20 — Network security | Network controls | TLS 1.3+ enforcement; rate limiting; no plaintext HTTP |
| A.8.24 — Cryptography | Cryptographic controls | Ed25519 for signing; TLS for transport; nonce for replay prevention |
| A.8.26 — Application security requirements | Secure SDLC | CI gate; release quality gate; threat model |
| A.8.29 — Security testing in development | Security testing | Conformance suite; security review in scope (Weeks 7–8) |
| A.8.32 — Change management | Change control | PR process; spec change process; CHANGELOG — review and approval are a manual process, not enforced by repository settings |
| A.8.24 / A.5.17 — Project secrets | Key management | Secrets inventory and rotation: [key-management.md](key-management.md) |

---

## Operator Compliance Guidance

If you are an operator seeking SOC 2 or ISO 27001 certification for a system built on Aroha:

1. **Reference this document** as evidence of Aroha's control design.
2. **Implement the hardening guide** ([docs/security/hardening.md](hardening.md)) — controls marked "✅ (config)" require your configuration.
3. **Generate your own threat model** — extend [docs/security/threat-model.md](threat-model.md) with your deployment-specific trust boundaries.
4. **Maintain your own CHANGELOG and release process** for your agents and bridges.
5. **Contact your auditor** to confirm this document's applicability to your audit scope.

**ASSUMPTION:** This mapping is self-assessed by the Aroha team. It has not been reviewed by a SOC 2 or ISO 27001 auditor. Enterprise customers requiring certified compliance should commission their own audit.

---

*For questions about enterprise compliance, email the maintainer listed in [MAINTAINERS.md](../../MAINTAINERS.md). GitHub Discussions is not enabled.*
