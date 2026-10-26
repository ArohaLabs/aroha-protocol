<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported Versions

Packages version independently (see [COMPATIBILITY.md](COMPATIBILITY.md)).

| Version | Supported |
|---------|-----------|
| Latest published release of each package / SDK | ✅ Security fixes |
| Anything older | ❌ Upgrade to the latest release |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public disclosure before a patch is available puts all users at risk.

### How to report

Use either channel:

- **GitHub private vulnerability reporting:**
  [open a private report](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new).
- **Email:** send the report to **contact@aroha-labs.com** with `SECURITY` in the subject line,
  for example `[SECURITY] Aroha vulnerability report`. Reports are handled by the maintainer
  listed in [MAINTAINERS.md](MAINTAINERS.md).

### If the maintainer is unavailable

The project has one maintainer and no second security contact. If you receive no
acknowledgement within the 48-hour target:

1. Re-send the report to contact@aroha-labs.com with `[SECURITY][RESEND]` in the subject line
   (or add a comment to your private report on GitHub).
2. If there is still no acknowledgement after a further 5 business days, you may treat the
   project as unresponsive and apply your own coordinated-disclosure policy. Please do not
   include exploitation details in any public channel.
3. If the maintainer expects to be unavailable for an extended period, the project will post a
   public notice of reduced security coverage in this file and in [docs/trust.md](docs/trust.md).

### What to include

- Affected package(s) and version(s)
- Description of the vulnerability and potential impact
- Reproduction steps (proof-of-concept if available)
- Your suggested severity (Critical / High / Medium / Low)
- Whether you'd like public credit when we disclose

---

## Response SLAs

| Milestone | Target (single maintainer — best effort) |
|-----------|-----|
| Acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Patch for Critical | 72 hours from confirmation |
| Patch for High | 7 days from confirmation |
| Patch for Medium | 30 days from confirmation |
| Patch for Low | 90 days or next scheduled release |
| Public disclosure | Coordinated with reporter; default 90 days from report |

---

## Coordinated Disclosure

We follow coordinated disclosure:

1. You report privately.
2. We confirm, assess severity, and develop a fix.
3. We agree on a disclosure date with you (default: 90 days after report, or sooner if a fix is ready).
4. We release the patch and publish an advisory at the same time (a CHANGELOG security entry, and a GitHub security advisory for reports received through private vulnerability reporting).
5. You receive credit in the advisory and under [Acknowledgements](#acknowledgements) unless you request otherwise.

---

## Scope

**In scope:**
- All packages under `packages/`
- All agents under `agents/`
- The SDKs under `sdks/` and the apps under `apps/`
- The CI/release pipeline (`.github/workflows/`)
- Cryptographic primitives (key generation, signing, verification)
- Saga state machine correctness (partial commit, replay, cancel race)

**Out of scope:**
- Third-party ecosystem packages in `community/` (report to their maintainers)
- Demo scripts in `scripts/` (they use simulated data — no production impact)
- Dependencies of this project (report to the upstream package maintainer)

---

## Security Advisories

No security advisories have been published. Fixes for reported issues are recorded as security
entries in [CHANGELOG.md](CHANGELOG.md).

---

## Acknowledgements

No vulnerability reports have been credited yet. Reporters who agree to be credited will be listed
here.

---

## Threat Model

Our public threat model is at [docs/security/threat-model.md](docs/security/threat-model.md). It describes assets, trust boundaries, named threat scenarios, and current control status.

---

## Key and Secret Management

How project signing keys and CI/CD secrets are inventoried, held and rotated:
[docs/security/key-management.md](docs/security/key-management.md).

---

## Supply-chain status

See [docs/trust.md](docs/trust.md) for the current release-integrity status (for example: npm
packages are published without provenance, and organisation admins can bypass the rulesets that
protect `main` and the release tags).

---

*This policy is reviewed and updated with each major release.*
