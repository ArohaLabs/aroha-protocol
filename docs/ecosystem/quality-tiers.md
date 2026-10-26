<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Ecosystem Quality Tiers

**Owner:** Ecosystem Agent  
**Version:** 1.0 — 2026-05-28  
**Status:** Draft — pending first external submission cycle

This document defines the quality tiers for community packages, bridges, and agents in the Aroha ecosystem. Tiers give users a reliable signal about the maturity and safety of community contributions.

---

## Why Tiers?

An open ecosystem without quality signals is a liability. Without tiers:
- Adopters can't distinguish production-ready packages from experiments.
- Malicious or broken packages damage trust in the whole ecosystem.
- Maintainers have no clear bar to aim for.

Tiers create a **graduated trust ladder** — entry is easy, elevation requires verified quality.

---

## Tier Overview

| Tier | Badge | What it means |
|------|-------|---------------|
| Listed | ○ Listed | Self-submitted, unverified — use at your own risk |
| Verified | ◑ Verified | Passed automated conformance checks |
| Certified | ● Certified | Full review: conformance + security + maintenance |

---

## Tier 1 — Listed

**How to enter:** Open a pull request adding your package to [docs/ecosystem.md](../ecosystem.md) using the submission template.

**Requirements:**
- [ ] Public source repository (GitHub, GitLab, or equivalent)
- [ ] Apache 2.0, MIT, or compatible open source license
- [ ] README with: description, installation, and a basic usage example
- [ ] States which Aroha protocol layers it implements or bridges
- [ ] Contact or maintainer listed

**What it does NOT guarantee:**
- Conformance with any Aroha protocol requirement
- Security review
- Ongoing maintenance

**Listing is permanent unless the package is removed by its maintainer or violates the Code of Conduct.**

---

## Tier 2 — Verified

**How to enter:** Submit to the Verified tier by opening a conformance report issue (see [conformance/implementer-packet.md](../conformance/implementer-packet.md)) and linking it in your ecosystem PR.

**Requirements (all must be met):**
- [ ] All Tier 1 requirements
- [ ] Passes Aroha conformance suite for all layers the package claims to implement (Core conformance or higher — see [conformance/test-matrix.md](../conformance/test-matrix.md))
- [ ] CI is publicly visible and green (GitHub Actions, CircleCI, or equivalent)
- [ ] At least 1 published release (tagged, with CHANGELOG or release notes)
- [ ] Interoperability test against reference implementation completed and documented
- [ ] Issue tracker is public and responsive (your own maintainers respond within 10 business days)

**Verification process:**
1. Submit conformance report issue with your test results.
2. The Aroha maintainer reviews within 5 business days (see [MAINTAINERS.md](../../MAINTAINERS.md); there is one maintainer, no separate conformance team).
3. If approved, maintainer adds `Verified` badge to their README and is listed in the Verified section of the ecosystem page.

**Verified status is reviewed every 6 months.** If CI goes red or a MUST conformance test regresses, Verified status is suspended until resolved.

> **Status: manual process — not yet operating.** There is no automation that re-checks Verified entries, and no 6-monthly re-review has been run yet. Re-review will be done by hand by the maintainer.

---

## Tier 3 — Certified

**How to enter:** Contact the Aroha maintainer (contact@aroha-labs.com) to initiate the Certified review process. Intended for production integrations and implementations used in enterprise deployments.

**Requirements (all must be met):**
- [ ] All Tier 2 requirements
- [ ] Full Core conformance (all MUST + all SHOULD pass)
- [ ] Security review by a named reviewer (Aroha team member or third-party auditor)
- [ ] No unresolved High or Critical security findings
- [ ] Documented maintenance commitment: patch SLA for security issues, planned support window
- [ ] At least 2 production deployments documented (may be anonymised)
- [ ] Governance: at least 2 maintainers listed with clear succession plan

**Certification is annual.** Annual re-review required to maintain status.

> **Status: manual process — not yet operating.** No package has been Certified and no annual re-review process is running.

---

## Submission Template

Add this block to your ecosystem PR:

```markdown
## Submission

**Package name:** @yourorg/aroha-xxx
**Repository:** https://github.com/yourorg/aroha-xxx
**License:** MIT / Apache 2.0 / [other]
**Tier requested:** Listed / Verified / Certified
**Layers implemented:** L0, L1, L2, L3, L4 (list applicable)
**Type:** Bridge / Agent / Extension / SDK / Tool
**Language:** TypeScript / Python / Rust / Go / [other]
**Conformance report issue:** #xxx (required for Verified and above)
**Brief description (1–2 sentences):**
```

---

## Removal Policy

A package may be removed from the ecosystem listing if:
- The repository is deleted, made private, or abandoned (no activity for 12+ months)
- A Critical security vulnerability is disclosed and not patched within 30 days
- The package violates the Code of Conduct
- The maintainer requests removal

Removal from Listed does not remove Verified or Certified status records from the conformance archive.

---

## Monthly Ecosystem Health Report

> **Status: manual process — not yet operating.** No monthly ecosystem report has been published. The table below lists the metrics the report is intended to track and their targets; the template is [monthly-report-template.md](monthly-report-template.md).

The monthly report is intended to track:

| Metric | Target |
|--------|--------|
| Total ecosystem entries | Growing month-over-month |
| % non-core entries | ≥30% by Day 90 |
| Verified entries | ≥3 by Week 10 |
| Certified entries | ≥1 by Day 90 |
| New submissions this month | — |
| Suspended / removed this month | — |

Report template: [monthly-report-template.md](monthly-report-template.md).
