<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Engineering backlog

This file is a short pointer, not the backlog itself.

- **What changed and what is still owed:** [CHANGELOG.md](CHANGELOG.md) — the `[Unreleased]`
  section lists breaking changes, upgrade steps and known gaps.
- **Open work:** [GitHub Issues](https://github.com/ArohaLabs/aroha-protocol/issues).
- **Trust and status items** (CI evidence, maintainer coverage, security review): the trust page,
  [docs/trust.md](docs/trust.md).
- **SDK parity** (Python, Go, Java vs the TypeScript reference): [docs/sdks/feature-matrix.md](docs/sdks/feature-matrix.md).

Known engineering items at the time of writing:

- Bring `did:aroha-web` in the Python, Go and Java SDKs up to the current schema.
- Task mandates, disputes and the newer error codes outside TypeScript (see the feature matrix).
- First successful hosted runs of CI, Conformance and Release Gate, recorded on the trust page.

The go-to-market to-do list that used to live here moved out of this repository; it remains in
git history (`git log -- TODO.md`).
