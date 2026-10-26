<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Cross-implementation test vectors

Fixtures the TypeScript and Python SDKs both run against, so implementations
in different languages provably agree rather than merely intending to.

A protocol whose implementations disagree on a boundary case has a bug that
appears only in production, between two parties, with no shared log to
diagnose it from. These files make that class of bug impossible to introduce
quietly: change the behaviour and every language's suite fails at once.

| File | Consumed by |
|---|---|
| `consult-loop.json` | `packages/aroha-core/src/consult/loop-guard.test.ts`, `sdks/aroha-py/tests/test_consult.py` |
| `outbound-redaction.json` | `packages/aroha-policy/src/outbound-screener.test.ts`, `sdks/aroha-py/tests/test_policy.py` |

**Adding a case:** add it here first, watch both suites fail, then fix both.
Never add a case to one language's test file alone — that is how the two
drift apart.
