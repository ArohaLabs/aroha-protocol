<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Maintainers

This file lists current maintainers and their responsibilities. For the governance model behind this, see [docs/governance.md](docs/governance.md).

---

## Current Maintainers

| Name | GitHub | Email | Role | Areas | Response SLA |
|------|--------|-------|------|-------|--------------|
| Rajagopal Ganesan | @projectmed99 | rajagopal.ganesan@aroha-labs.com | Core Maintainer (acting Ecosystem and Security Maintainer) | Everything: protocol spec, all packages and SDKs, CLI, runtime, releases, ecosystem, security intake | 5 business days |

The project has **one maintainer**. There is no second reviewer and no on-call rotation; plan
around a single **5 business day** response time for issues, pull requests, ecosystem
submissions and conformance reports.

**Security contact:** report privately through
[GitHub private vulnerability reporting](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new),
or email **contact@aroha-labs.com** with the subject line `[SECURITY] Aroha vulnerability report`
— see [SECURITY.md](SECURITY.md). Acknowledgement target: 48 hours (best effort, single maintainer).

---

## Access

Repository access on GitHub (verified 2026-10-25) is wider than the maintainer list above. The
GitHub role is what GitHub grants the account; it is not a statement of project responsibility.
Write access comes from membership of the ArohaLabs organisation, whose members get write on
every repository.

| GitHub account | GitHub role | Role in the project |
|----------------|-------------|---------------------|
| @projectmed99 | admin | Core Maintainer (see above) |
| @rajganesan-aroha-labs | admin | Rajagopal Ganesan's second account |
| @rajgane07 | admin | Rajagopal Ganesan's third account |
| @s1oly | write | Reviewer (Aroha Labs team): reviews PRs in their areas; not a code owner, so the Core Maintainer still approves |
| @zuther77 | write | Reviewer (Aroha Labs team): reviews PRs in their areas; not a code owner, so the Core Maintainer still approves |

Changes to `main` go through a pull request with one approving review from a code owner (`CODEOWNERS`
names @projectmed99 for every path), the required CI and conformance checks, and signed commits (a repository ruleset, in force since 2026-10-25). Release
tags are protected by a second ruleset. **Organisation admins can bypass both rulesets**; there are
three admin accounts above. Status of each control: [docs/trust.md](docs/trust.md).

---

## Roles

### Core Maintainer — @projectmed99
- Reviews and merges PRs to every path (`CODEOWNERS` names @projectmed99 throughout)
- Owns protocol spec changes (including the 2-week comment period)
- Cuts releases and runs the release quality gate
- Responds to issues within 5 business days

### Ecosystem Maintainer — **vacant**
Covered by the Core Maintainer until filled, on the same 5 business day response time.
- Reviews ecosystem submissions (PRs to `docs/ecosystem.md`, `community/`)
- Validates Verified tier conformance reports
- Publishes monthly ecosystem health reports

### Security Maintainer — **vacant**
Covered by the Core Maintainer until filled.
- Handles vulnerability report intake (GitHub private vulnerability reporting or email — see [SECURITY.md](SECURITY.md))
- Coordinates with external auditors (none engaged yet — see [docs/security/review-scope.md](docs/security/review-scope.md))
- Maintains the threat model and incident response playbook
- Acknowledgement within 48 hours, severity assessment within 5 business days

---

## Emeritus Maintainers

Former maintainers who remain credited but no longer have write access:

| Name | Period | Areas |
|------|--------|--------|
| — | — | — |

---

## Adding a Maintainer

See [docs/governance.md — Becoming a Maintainer](docs/governance.md) for the nomination process.

Short version:
1. Consistent contribution over ≥3 months.
2. Nominated by an existing maintainer via a PR to this file.
3. No objections from current maintainers within 7 days.
4. Added here, to `CODEOWNERS`, and granted repository write access.

Filling the Ecosystem or Security Maintainer role follows the same process.

---

## Escalation Path

With a single maintainer there is no one to escalate *to* inside the project. If you have had no
response after 5 business days:

1. Reply on the issue or pull request thread, or re-send your email.
2. After a further 5 business days, email **rajagopal.ganesan@aroha-labs.com** directly with
   `[ESCALATION]` in the subject and a link to the thread.
3. Security reports: follow [SECURITY.md](SECURITY.md); do not wait on a public thread.

---

*Last updated: 2026-10-25.*
