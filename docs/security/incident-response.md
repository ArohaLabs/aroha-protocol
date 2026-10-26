<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Incident Response Playbook

**Owner:** Core Maintainer (acting Security Maintainer) — see [MAINTAINERS.md](../../MAINTAINERS.md)  
**Version:** 1.1 — 2026-10-09  
**Status:** Draft — manual process, single maintainer; not yet exercised  
**Applies to:** Security incidents affecting the Aroha reference implementation, the published packages and SDKs, or the project's CI/release pipeline

---

## Operating reality

This playbook describes what the project can actually do today:

- **One maintainer.** Every role below is held by the same person. There is no second reviewer, no on-call rotation and no paging.
- **Two intake channels**, both described in [SECURITY.md](../../SECURITY.md): email to contact@aroha-labs.com with the subject "SECURITY", and [GitHub private vulnerability reporting](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new).
- **No private security fork.** Fixes are prepared on a local, unpushed branch until release (see Phase 3).
- **Automated detection is minimal.** The only automated alert is the weekly scheduled conformance run, which opens or updates a GitHub issue on failure.
- **Release controls are partly enforced.** A ruleset on `main` requires a pull request with one approving review from a code owner, required status checks and signed commits; a tag ruleset restricts creating, updating and deleting release tags; and the `release` environment requires an approval before each publish. The three organisation admins can bypass both.

---

## Severity Levels

| Severity | Definition | Examples (high-level) |
|----------|------------|---------|
| **Critical** | Active misuse observed or likely; loss of key confidentiality; loss of funds; signature verification can be circumvented | Control gap in envelope or mandate signature verification; settlement integrity gap in production |
| **High** | Serious control weakness with significant data or fund exposure | Gap in replay protection; saga cancel/commit ordering weakness |
| **Medium** | Control weakness that requires significant preconditions | Registry entry trust gap requiring a party-controlled DID |
| **Low** | Minor issue with limited impact | Excess detail in error messages |

---

## Roles

All roles are held by the Core Maintainer (@projectmed99), who is also the acting Security Maintainer.

| Role | Responsibility during incident | Holder |
|------|-------------------------------|--------|
| **Incident Commander** | Declares the incident, owns decisions and communication | Core Maintainer |
| **Technical Lead** | Investigates root cause, develops and validates the fix | Core Maintainer |
| **Communications** | Reporter updates, user notices, disclosure timing | Core Maintainer |

**Fallback if the maintainer is unavailable:** there is no second responder. The reporter-side fallback is described in [SECURITY.md — If the maintainer is unavailable](../../SECURITY.md#if-the-maintainer-is-unavailable). If the maintainer expects an extended absence, a public notice of reduced security coverage is posted in SECURITY.md and [trust.md](../trust.md). Naming a second responder is an owner decision.

---

## Phase 1 — Intake & Triage

1. **Receive report** by email (contact@aroha-labs.com, subject "SECURITY") or through GitHub private vulnerability reporting (see [SECURITY.md](../../SECURITY.md)).
2. **Acknowledge** to the reporter within 48 hours (best-effort target from SECURITY.md).
3. **Assess severity** using the table above. When uncertain, choose the higher severity.
4. **Record the incident privately** — in a private note or local file held by the maintainer. Do not use public issues.
5. **Confirm the report** — verify the control weakness is real before escalating.

**Critical/High:** proceed to Phase 2 immediately.  
**Medium/Low:** handle within the SECURITY.md targets (30 / 90 days).

---

## Phase 2 — Containment

### For Critical issues

- [ ] Review available signals (npm download anomalies, reports from users) for signs of active misuse.
- [ ] If misuse is likely: publish a short public notice recommending mitigating action (for example "disable feature X", "rotate keys") without technical detail, even before a fix is ready.
- [ ] Consider deprecating the affected package versions (`npm deprecate`).
- [ ] Notify known production users directly, where contact details are available.
- [ ] If project credentials may be affected, follow [key-management.md](key-management.md).

### For all severities

- [ ] Scope impact: which packages, SDKs and versions are affected?
- [ ] Determine whether any project keys or CI/CD secrets may be affected.
- [ ] Record findings in the private incident record.

---

## Phase 3 — Fix Development

1. **Develop the fix** on a local branch that is not pushed until release. (There is no private security fork; the repository is public, so pushed branches are visible to everyone.)
2. **Review** — the maintainer self-reviews. There is no second maintainer. Where the reporter agrees, ask them to validate the fix privately before release.
3. **Test** — all existing tests must pass; add a regression test for the control weakness.

---

## Phase 4 — Release & Disclosure

1. **Release** through the normal publish workflow, which runs the release quality gate first (see [release-gate.yml](https://github.com/ArohaLabs/aroha-protocol/blob/main/.github/workflows/release-gate.yml)).
2. **Write the advisory** as a security entry in CHANGELOG.md, including:
   - Affected versions and fixed version
   - Severity
   - A description of impact and mitigation that avoids detail enabling misuse before users upgrade
   - Credit to the reporter (unless they opt out), also added under Acknowledgements in SECURITY.md
3. **Coordinate the disclosure date** with the reporter. Default: publish together with the fix.
4. **Notify** known downstream integrations.
5. **Update** the security table in [trust.md](../trust.md).

A CVE identifier, if needed, must be requested through a CVE Numbering Authority, for example from a GitHub security advisory on this repository.

---

## Phase 5 — Post-Incident

Within 5 business days of resolution:

- [ ] Post-incident review: root cause, detection delay, fix timeline.
- [ ] Update the [threat model](threat-model.md) if a new risk scenario was identified.
- [ ] Update the [review scope](review-scope.md) remediation backlog.
- [ ] Add a regression test to the conformance suite if applicable.
- [ ] Publish a brief public summary if the incident was Critical or had broad user impact.

---

## Key Contacts & Resources

| Resource | Link |
|----------|------|
| Security intake (email or GitHub private vulnerability reporting) | [SECURITY.md](../../SECURITY.md) |
| Maintainer contact | [MAINTAINERS.md](../../MAINTAINERS.md) |
| Key and secret management | [key-management.md](key-management.md) |
| Threat model | [threat-model.md](threat-model.md) |
| npm package management | `npm deprecate @aroha-sdk/<pkg>@<version> "Security: use <fixed-version>"` |

---

## Communication Templates

### Reporter acknowledgement (within 48h)

> Thank you for your report. We have received it and are reviewing it. We will provide a severity assessment within 5 business days. Your report is being handled privately under coordinated disclosure. Note that the project has a single maintainer, so these timings are best effort.

### User notice (Critical, pre-fix)

> **Security Notice — Action Required**
>
> We have identified a [severity] issue in [@aroha-sdk/package] versions [X.Y.Z–A.B.C].
>
> **Impact:** [Brief, non-technical description]
>
> **Mitigation (until a fix is available):** [Steps users can take now]
>
> **Expected fix:** [Date or "within 72 hours"]
>
> Full details will be published in CHANGELOG.md when the fix is released.

---

*This playbook is reviewed after every incident and at least annually.*
