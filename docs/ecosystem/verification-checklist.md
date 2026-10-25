<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Community Package Verification Checklist

**Owner:** Ecosystem Agent  
**Version:** 1.0 — 2026-05-28  
**Use:** Run this checklist when reviewing a community package submission for Verified or Certified tier.

---

## How to Use

For each submission at Verified tier or above, work through this checklist in order. Check each box only when the criterion is confirmed. Any unchecked REQUIRED item blocks approval.

---

## Listed Tier Review (all submissions)

### Basic quality

- [ ] Public repository is accessible and not archived
- [ ] License is Apache 2.0, MIT, ISC, BSD-2-Clause, BSD-3-Clause, or MPL-2.0
- [ ] README exists and includes: description, installation instructions, basic usage example
- [ ] Package states which Aroha protocol layers it implements (L0–L4)
- [ ] Package type is clear: Bridge / Agent / Extension / SDK / Tool
- [ ] At least one maintainer is identified (GitHub user or organisation)
- [ ] Issue tracker is public

### Content checks

- [ ] No hard-coded credentials or private keys in the repository
- [ ] No `file:` path dependencies (these indicate dev artifacts leaked into the package)
- [ ] README does not make false claims about Aroha conformance (e.g., "fully conformant" without evidence)
- [ ] Package does not impersonate an official `@aroha-sdk/*` package

**Decision:** [ ] Approve for Listed | [ ] Request changes | [ ] Reject

**Reason (if not Approve):**

---

## Verified Tier Review (all of the above, plus:)

### Conformance evidence

- [ ] Conformance report issue is linked in the submission PR
- [ ] All MUST rows for claimed layers have a documented test result (pass or fail with explanation)
- [ ] No MUST row failures — all MUST tests pass
- [ ] Interoperability test result against reference implementation is documented
- [ ] Conformance grade is Core conformance or Full conformance (not Provisional)

### CI & release hygiene

- [ ] CI pipeline is publicly visible (GitHub Actions, CircleCI, Travis CI, or equivalent)
- [ ] CI is currently green on the default branch
- [ ] At least one tagged release exists
- [ ] Release has CHANGELOG or release notes

### Maintenance signals

- [ ] Issue tracker: most recent open issues have maintainer response within 10 business days
- [ ] Open pull requests are not stale (last activity <30 days or explicitly marked as stalled)
- [ ] No high-severity unresolved issues open for >30 days

### Technical spot-check (reviewer discretion)

- [ ] Envelope signing implementation looks correct (not skipping verification)
- [ ] No obvious replay attack vectors
- [ ] No shell injection or SQL injection patterns in payload handling
- [ ] Dependencies are reasonably up-to-date (no deps with known critical CVEs)

**Decision:** [ ] Approve for Verified | [ ] Approve for Listed only | [ ] Request changes | [ ] Reject

**Findings:**

---

## Certified Tier Review (all of the above, plus:)

### Full conformance

- [ ] All MUST rows pass
- [ ] All SHOULD rows pass OR all non-passing SHOULD rows have documented rationale

### Security review

- [ ] Named security reviewer identified (Aroha maintainer or qualified third party)
- [ ] Security review completed (report or summary provided)
- [ ] No unresolved Critical findings
- [ ] No unresolved High findings
- [ ] All Medium findings have an owner and due date

### Maintenance commitment

- [ ] At least 2 maintainers listed
- [ ] Succession plan or escalation path documented
- [ ] Patch SLA for security issues is documented
- [ ] Planned support window is stated (minimum: "actively maintained")

### Production evidence

- [ ] At least 2 production deployments documented (may be anonymised)
- [ ] Deployments are non-trivial (not toy or demo environments)

**Decision:** [ ] Approve for Certified | [ ] Approve for Verified only | [ ] Request changes | [ ] Reject

**Findings:**

---

## Reviewer Sign-off

| Field | Value |
|-------|-------|
| Reviewer | |
| Review date | |
| Submission PR | # |
| Package | |
| Tier approved | Listed / Verified / Certified / Rejected |
| Next review date (Verified: 6 months; Certified: 12 months) | |

---

*Questions about this checklist? See [quality-tiers.md](quality-tiers.md) for the full tier requirements.*
