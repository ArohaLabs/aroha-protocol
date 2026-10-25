# Consult Primitives (aroha) and Consumption (doc-intel) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the consult protocol's safety primitives in aroha — where every consumer gets them and two implementations cannot drift — then have aroha-doc-intel consume them rather than reinvent them.

**Architecture:** Two parts, in order. **Part A** adds consult wire types, loop-guard semantics, and an outbound screener to aroha, in TypeScript *and* Python, verified against **shared JSON test vectors** so the two implementations provably agree. **Part B** wires doc-intel's existing consult routes to those primitives and adds the product-side pieces (composition, audit, context budget) that genuinely belong to the product.

**Tech Stack:** TypeScript (aroha packages, vitest), Python 3.11+ (aroha-py, pytest), FastAPI + Pydantic (doc-intel studio-backend).

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md), [../specs/2026-08-18-memory-and-capability-honesty-design.md](../specs/2026-08-18-memory-and-capability-honesty-design.md)

## Global Constraints

- **Protocol goes in aroha; product goes in doc-intel.** If two aroha consumers would need to agree on it, it belongs in aroha. Hop semantics, wire field names, and screening categories are protocol. Composition prompts, audit storage, and UI are product.
- **TS and Python must agree, and it must be proven.** Every protocol primitive lands in both SDKs and both run the same JSON vectors from `docs/vectors/`. A behaviour difference between implementations means two aroha agents disagree about whether a chain is legal — a bug that only appears in production, between two parties, with no shared log.
- **Do not change doc-intel's UI contract.** `POST /remote-agents/{did}/run` keeps taking `{message}` and returning `{answer, envelope, remoteDid, remoteName}`. Fields may be added; nothing may be removed or renamed. The dust frontend ships to a client.
- **Consult only.** No action requests, no signed approvals, no side effects on the remote side. Phase 2.
- **Audit stores redaction categories, never values.**
- Copyright header on every new file:
  - TS/JS: `// Copyright (c) 2026 Aroha Labs` / `// SPDX-License-Identifier: Apache-2.0`
  - Python: `# Copyright (c) 2026 Aroha Labs` / `# SPDX-License-Identifier: Apache-2.0`
- Python: `from __future__ import annotations`, type hints, module docstring explaining *why*.
- Run TS tests from the repo root (`npx vitest run <path>`), Python SDK tests from `sdks/aroha-py` (`pytest`), doc-intel tests from `studio-backend` (`pytest`).

---

## File Structure

### Part A — aroha (`<repo root>`)

| File | Responsibility |
|---|---|
| `docs/vectors/consult-loop.json` | Shared test vectors — the contract both implementations obey |
| `docs/vectors/outbound-redaction.json` | Shared redaction vectors |
| `packages/aroha-core/src/messages/types.ts` | *Modify* — `ConsultParams`, `ConsultResult`, `ConsultSource` |
| `packages/aroha-core/src/consult/loop-guard.ts` | Loop semantics (TS) |
| `packages/aroha-policy/src/outbound-screener.ts` | Egress screener (TS) |
| `sdks/aroha-py/aroha/consult.py` | Wire shapes + loop semantics (Python) |
| `sdks/aroha-py/aroha/policy.py` | Egress screener (Python) — the SDK has no policy module today |

### Part B — doc-intel (`<doc-intel checkout>`)

| File | Responsibility |
|---|---|
| `studio-backend/consult_compose.py` | Question composition (product — domain-specific prompt) |
| `studio-backend/consult_audit.py` | JSONL audit log (product — storage choice) |
| `studio-backend/context_budget.py` | Token budgeting for `runner.py` |
| `studio-backend/app.py` | *Modify* — wire both consult ends to aroha primitives |
| `studio-backend/runner.py` | *Modify* — apply the context budget |
| `frontend/src/screens/dust/DustApp.tsx` | *Modify* — audit panel; remove the `skillType` dropdown |

---

# PART A — aroha protocol primitives

## Task A1: Shared test vectors

**Files:**
- Create: `docs/vectors/consult-loop.json`
- Create: `docs/vectors/README.md`

**Interfaces:**
- Consumes: nothing
- Produces: the fixture both A2 and A3 run against

Written first, deliberately. The vectors *are* the specification of agreement — writing them before either implementation means neither one's quirks become the de facto standard.

- [ ] **Step 1: Write the vectors**

```json
{
  "description": "Consult loop-prevention vectors (design spec §3.2). Every Aroha implementation MUST produce these results. A disagreement between implementations means two agents disagree about whether a consult chain is legal, which surfaces only in production between two parties with no shared log.",
  "maxHopsDefault": 3,
  "checkLoopLimits": [
    { "name": "first hop is allowed",
      "hopCount": 1, "consultChain": ["did:aroha:zA"], "ownDid": "did:aroha:zB",
      "maxHops": 3, "expectOk": true },
    { "name": "third hop is allowed at maxHops 3",
      "hopCount": 3, "consultChain": ["did:aroha:zA", "did:aroha:zB", "did:aroha:zC"],
      "ownDid": "did:aroha:zD", "maxHops": 3, "expectOk": true },
    { "name": "fourth hop is refused at maxHops 3",
      "hopCount": 4, "consultChain": ["did:aroha:zA", "did:aroha:zB", "did:aroha:zC", "did:aroha:zD"],
      "ownDid": "did:aroha:zE", "maxHops": 3, "expectOk": false, "expectReasonContains": "hop" },
    { "name": "two-cycle is refused inside the hop limit",
      "hopCount": 2, "consultChain": ["did:aroha:zA", "did:aroha:zB"],
      "ownDid": "did:aroha:zA", "maxHops": 3, "expectOk": false, "expectReasonContains": "cycle" },
    { "name": "self-consult on the first hop is refused",
      "hopCount": 1, "consultChain": ["did:aroha:zA"],
      "ownDid": "did:aroha:zA", "maxHops": 3, "expectOk": false, "expectReasonContains": "cycle" },
    { "name": "hop count of zero is malformed",
      "hopCount": 0, "consultChain": [], "ownDid": "did:aroha:zB",
      "maxHops": 3, "expectOk": false, "expectReasonContains": "malformed" },
    { "name": "negative hop count is malformed",
      "hopCount": -1, "consultChain": [], "ownDid": "did:aroha:zB",
      "maxHops": 3, "expectOk": false, "expectReasonContains": "malformed" },
    { "name": "empty chain with a valid hop count is allowed",
      "hopCount": 1, "consultChain": [], "ownDid": "did:aroha:zB",
      "maxHops": 3, "expectOk": true },
    { "name": "maxHops 1 allows exactly one call",
      "hopCount": 1, "consultChain": ["did:aroha:zA"], "ownDid": "did:aroha:zB",
      "maxHops": 1, "expectOk": true },
    { "name": "maxHops 1 refuses the second",
      "hopCount": 2, "consultChain": ["did:aroha:zA", "did:aroha:zB"], "ownDid": "did:aroha:zC",
      "maxHops": 1, "expectOk": false, "expectReasonContains": "hop" }
  ],
  "nextHop": [
    { "name": "first hop from empty state",
      "hopCount": 0, "consultChain": [], "ownDid": "did:aroha:zSELF",
      "expectHopCount": 1, "expectChain": ["did:aroha:zSELF"] },
    { "name": "relaying an inbound consult",
      "hopCount": 1, "consultChain": ["did:aroha:zORIGIN"], "ownDid": "did:aroha:zSELF",
      "expectHopCount": 2, "expectChain": ["did:aroha:zORIGIN", "did:aroha:zSELF"] }
  ]
}
```

- [ ] **Step 2: Write the vectors README**

```markdown
<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Cross-implementation test vectors

Fixtures every Aroha SDK runs against, so implementations in different
languages provably agree rather than merely intending to.

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
```

- [ ] **Step 3: Commit**

```bash
cd "<repo root>"
git add docs/vectors/
git commit -m "docs(vectors): shared consult loop-prevention test vectors

Written before either implementation, deliberately: the vectors ARE the
agreement, so neither language's quirks become the de facto standard.
Two implementations disagreeing about whether a chain is legal is a bug
that surfaces only in production, between two parties, with no shared log."
```

---

## Task A2: Loop guard (TypeScript)

**Files:**
- Create: `packages/aroha-core/src/consult/loop-guard.ts`
- Create: `packages/aroha-core/src/consult/types.ts`
- Modify: `packages/aroha-core/src/index.ts`
- Test: `packages/aroha-core/src/consult/loop-guard.test.ts`

**Interfaces:**
- Consumes: `docs/vectors/consult-loop.json`
- Produces: `ConsultParams`, `ConsultResult`, `ConsultSource`, `LoopCheck`, `checkConsultLoop(params, ownDid, maxHops)`, `nextConsultHop(hopCount, chain, ownDid)`, `DEFAULT_MAX_CONSULT_HOPS`

- [ ] **Step 1: Write the failing test, driven by the vectors**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the shared vectors in docs/vectors/consult-loop.json. The Python SDK
 * runs the same file — see sdks/aroha-py/tests/test_consult.py. If these two
 * suites ever disagree, two Aroha agents disagree about whether a consult
 * chain is legal.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { checkConsultLoop, nextConsultHop, DEFAULT_MAX_CONSULT_HOPS } from "./loop-guard.js";

const vectorsPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "docs", "vectors", "consult-loop.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  maxHopsDefault: number;
  checkLoopLimits: Array<{
    name: string; hopCount: number; consultChain: string[]; ownDid: string;
    maxHops: number; expectOk: boolean; expectReasonContains?: string;
  }>;
  nextHop: Array<{
    name: string; hopCount: number; consultChain: string[]; ownDid: string;
    expectHopCount: number; expectChain: string[];
  }>;
};

describe("checkConsultLoop — shared vectors", () => {
  for (const v of vectors.checkLoopLimits) {
    it(v.name, () => {
      const result = checkConsultLoop(
        { question: "q", hopCount: v.hopCount, consultChain: v.consultChain },
        v.ownDid,
        v.maxHops,
      );
      expect(result.ok).toBe(v.expectOk);
      if (v.expectReasonContains) {
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.reason.toLowerCase()).toContain(v.expectReasonContains.toLowerCase());
        }
      }
    });
  }
});

describe("nextConsultHop — shared vectors", () => {
  for (const v of vectors.nextHop) {
    it(v.name, () => {
      const out = nextConsultHop(v.hopCount, v.consultChain, v.ownDid);
      expect(out.hopCount).toBe(v.expectHopCount);
      expect(out.consultChain).toEqual(v.expectChain);
    });
  }
});

describe("loop guard invariants", () => {
  it("uses the same default the vectors declare", () => {
    expect(DEFAULT_MAX_CONSULT_HOPS).toBe(vectors.maxHopsDefault);
  });

  it("does not mutate the chain it is given", () => {
    const chain = ["did:aroha:zA"];
    nextConsultHop(1, chain, "did:aroha:zB");
    expect(chain).toEqual(["did:aroha:zA"]);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd "<repo root>" && npx vitest run packages/aroha-core/src/consult/loop-guard.test.ts`
Expected: FAIL — cannot resolve `./loop-guard.js`.

- [ ] **Step 3: Write the types**

`packages/aroha-core/src/consult/types.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consult wire shapes (design spec §4).
 *
 * A consult travels as an ordinary ArohaRequest with capability "consult" —
 * no new message type and no protocol version bump. These are the `params`
 * and `result` payloads inside that envelope.
 *
 * These live in aroha-core rather than in any one consumer because two
 * implementations must agree on the field names to interoperate at all. The
 * Python SDK mirrors them in aroha/consult.py.
 */

/** What the consulted agent used to produce its answer (design spec §4.3). */
export interface ConsultSource {
  tool: string;
  summary: string;
}

export interface ConsultParams {
  /** A self-contained question. Never the caller's raw conversation history. */
  question: string;
  /** Optional subject-area hint, for the answering side's triage. */
  domainHint?: string;
  /** Consult hops already taken. A first-hop consult sends 1. */
  hopCount: number;
  /** DIDs already in this chain, in order. Used for cycle detection. */
  consultChain: string[];
}

export interface ConsultResult {
  answer: string;
  /** Tools consulted — makes an answer checkable rather than merely asserted. */
  sources: ConsultSource[];
}

/** The capability name a consult request carries. */
export const CONSULT_CAPABILITY = "consult";
```

- [ ] **Step 4: Write the loop guard**

`packages/aroha-core/src/consult/loop-guard.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consult loop prevention (design spec §3.2).
 *
 * Agent A asks B, B asks A, and real money burns in a cycle nobody notices
 * until the bill arrives. Two independent limits, because they fail
 * differently:
 *
 *   hopCount     bounds runaway depth   (A -> B -> C -> D -> ...)
 *   consultChain catches cycles         (A -> B -> A)
 *
 * A count alone does not stop a 2-cycle under a generous depth limit; a chain
 * check alone does not stop unbounded linear depth. Both are required.
 *
 * Behaviour is pinned by docs/vectors/consult-loop.json, which the Python SDK
 * runs against the same way. Change the semantics here and that file must
 * change too, which makes both suites fail until both implementations agree.
 */

import type { ConsultParams } from "./types.js";

export const DEFAULT_MAX_CONSULT_HOPS = 3;

export type LoopCheck = { ok: true } | { ok: false; reason: string };

export function checkConsultLoop(
  params: Pick<ConsultParams, "hopCount" | "consultChain">,
  ownDid: string,
  maxHops: number = DEFAULT_MAX_CONSULT_HOPS,
): LoopCheck {
  if (!Number.isInteger(params.hopCount) || params.hopCount < 1) {
    return { ok: false, reason: `Malformed consult hop count: ${params.hopCount}` };
  }
  if (params.hopCount > maxHops) {
    return { ok: false, reason: `Consult hop limit exceeded (${params.hopCount} > ${maxHops})` };
  }
  if (params.consultChain.includes(ownDid)) {
    return {
      ok: false,
      reason: `Consult cycle detected — ${ownDid} is already in the chain [${params.consultChain.join(" -> ")}]`,
    };
  }
  return { ok: true };
}

/**
 * Hop state for an outgoing consult. Never mutates its input.
 * A first-hop consult passes hopCount 0 and an empty chain, and gets (1, [ownDid]).
 */
export function nextConsultHop(
  hopCount: number,
  consultChain: string[],
  ownDid: string,
): Pick<ConsultParams, "hopCount" | "consultChain"> {
  return { hopCount: hopCount + 1, consultChain: [...consultChain, ownDid] };
}
```

- [ ] **Step 5: Export from the package index**

In `packages/aroha-core/src/index.ts`:

```ts
export * from "./consult/types.js";
export * from "./consult/loop-guard.js";
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd "<repo root>" && npx vitest run packages/aroha-core/src/consult/loop-guard.test.ts`
Expected: PASS — 10 loop cases, 2 nextHop cases, 2 invariants.

- [ ] **Step 7: Build and commit**

```bash
cd "<repo root>"
npm run build -w packages/aroha-core && npm run test -w packages/aroha-core
git add packages/aroha-core/src/consult/ packages/aroha-core/src/index.ts
git commit -m "feat(core): consult wire types and loop guard

Protocol, not product: two implementations must agree on the field names
and on what counts as a cycle, or two agents disagree about whether a
chain is legal. Behaviour is pinned by docs/vectors/consult-loop.json,
which the Python SDK runs against the same file."
```

---

## Task A3: Loop guard (Python)

**Files:**
- Create: `sdks/aroha-py/aroha/consult.py`
- Modify: `sdks/aroha-py/aroha/__init__.py`
- Test: `sdks/aroha-py/tests/test_consult.py`

**Interfaces:**
- Consumes: `docs/vectors/consult-loop.json` — the same file Task A2 uses
- Produces: `ConsultParams`, `ConsultResult`, `ConsultSource`, `LoopCheck`, `check_consult_loop`, `next_consult_hop`, `DEFAULT_MAX_CONSULT_HOPS`, `CONSULT_CAPABILITY`

- [ ] **Step 1: Write the failing test**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Runs the shared vectors in docs/vectors/consult-loop.json — the same file
packages/aroha-core/src/consult/loop-guard.test.ts runs. If these two suites
disagree, two Aroha agents disagree about whether a consult chain is legal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aroha.consult import (
    DEFAULT_MAX_CONSULT_HOPS,
    check_consult_loop,
    next_consult_hop,
)

_VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs" / "vectors" / "consult-loop.json")
    .read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", _VECTORS["checkLoopLimits"], ids=lambda c: c["name"])
def test_check_loop_vectors(case):
    result = check_consult_loop(
        case["hopCount"], case["consultChain"], case["ownDid"], case["maxHops"]
    )
    assert result.ok is case["expectOk"]
    if "expectReasonContains" in case:
        assert not result.ok
        assert case["expectReasonContains"].lower() in result.reason.lower()


@pytest.mark.parametrize("case", _VECTORS["nextHop"], ids=lambda c: c["name"])
def test_next_hop_vectors(case):
    hop, chain = next_consult_hop(case["hopCount"], case["consultChain"], case["ownDid"])
    assert hop == case["expectHopCount"]
    assert chain == case["expectChain"]


def test_default_matches_the_vectors():
    assert DEFAULT_MAX_CONSULT_HOPS == _VECTORS["maxHopsDefault"]


def test_next_hop_does_not_mutate_its_input():
    chain = ["did:aroha:zA"]
    next_consult_hop(1, chain, "did:aroha:zB")
    assert chain == ["did:aroha:zA"]
```

If the vectors path fails to resolve, print `Path(__file__).resolve().parents[3]` and adjust the number of `parents` — the file is at `sdks/aroha-py/tests/test_consult.py`, so it needs three levels up to reach the repo root.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd sdks/aroha-py && pytest tests/test_consult.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aroha.consult'`

- [ ] **Step 3: Write the implementation**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — consult wire shapes and loop prevention.

The Python half of packages/aroha-core/src/consult/. Both implementations are
pinned by docs/vectors/consult-loop.json: change the semantics in one and its
suite fails until the other follows.

Why this is protocol and not product: two implementations must agree on the
field names AND on what counts as a cycle. If they do not, one agent refuses
a chain the other allows, and the disagreement surfaces only in production,
between two parties, with no shared log to diagnose it from.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MAX_CONSULT_HOPS = 3

#: The capability name a consult request carries.
CONSULT_CAPABILITY = "consult"


@dataclass
class ConsultSource:
    """What the consulted agent used to produce its answer."""

    tool: str
    summary: str


@dataclass
class ConsultParams:
    """The `params` payload of an ArohaRequest with capability "consult"."""

    question: str
    hop_count: int
    consult_chain: list[str] = field(default_factory=list)
    domain_hint: str | None = None

    def to_wire(self) -> dict:
        """camelCase for the wire, matching the TypeScript shape exactly."""
        out = {
            "question": self.question,
            "hopCount": self.hop_count,
            "consultChain": list(self.consult_chain),
        }
        if self.domain_hint:
            out["domainHint"] = self.domain_hint
        return out


@dataclass
class ConsultResult:
    answer: str
    sources: list[ConsultSource] = field(default_factory=list)


@dataclass(frozen=True)
class LoopCheck:
    ok: bool
    reason: str | None = None


def check_consult_loop(
    hop_count: int,
    consult_chain: list[str],
    own_did: str,
    max_hops: int = DEFAULT_MAX_CONSULT_HOPS,
) -> LoopCheck:
    """Whether a consult arriving with this hop state may be answered.

    Two independent limits: hop_count bounds runaway depth, consult_chain
    catches cycles. A count alone cannot stop a 2-cycle under a generous
    depth limit; a chain check alone cannot stop unbounded linear depth.
    """
    if not isinstance(hop_count, int) or isinstance(hop_count, bool) or hop_count < 1:
        return LoopCheck(False, f"Malformed consult hop count: {hop_count!r}")
    if hop_count > max_hops:
        return LoopCheck(False, f"Consult hop limit exceeded ({hop_count} > {max_hops})")
    if own_did in consult_chain:
        return LoopCheck(
            False,
            f"Consult cycle detected — {own_did} is already in the chain "
            f"[{' -> '.join(consult_chain)}]",
        )
    return LoopCheck(True)


def next_consult_hop(
    hop_count: int,
    consult_chain: list[str],
    own_did: str,
) -> tuple[int, list[str]]:
    """Hop state for an outgoing consult. Never mutates its input.

    A first-hop consult passes hop_count 0 and an empty chain, and gets back
    (1, [own_did]).
    """
    return hop_count + 1, [*consult_chain, own_did]
```

`isinstance(hop_count, bool)` is excluded explicitly because `bool` is a subclass of `int` in Python — without it, `check_consult_loop(True, ...)` would be treated as hop count 1 and quietly pass.

- [ ] **Step 4: Export from the package**

In `sdks/aroha-py/aroha/__init__.py`, follow the file's existing export style and add the consult names.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd sdks/aroha-py && pytest tests/test_consult.py -v`
Expected: PASS — the same 10 loop cases and 2 nextHop cases the TypeScript suite ran, by name.

- [ ] **Step 6: Run both suites together**

```bash
cd "<repo root>" && npx vitest run packages/aroha-core/src/consult/loop-guard.test.ts
cd sdks/aroha-py && pytest tests/test_consult.py -v
```

Both must pass on the same vector names. That correspondence is the deliverable.

- [ ] **Step 7: Commit**

```bash
cd "<repo root>"
git add sdks/aroha-py/aroha/consult.py sdks/aroha-py/aroha/__init__.py sdks/aroha-py/tests/test_consult.py
git commit -m "feat(aroha-py): consult shapes and loop guard, same vectors as TS

Runs docs/vectors/consult-loop.json — the identical file the TypeScript
suite runs — so the two implementations provably agree rather than
merely intending to. bool is excluded from the int check explicitly:
bool subclasses int in Python, so True would otherwise pass as hop 1."
```

---

## Task A4: OutboundScreener (TypeScript)

**Files:**
- Create: `docs/vectors/outbound-redaction.json`
- Create: `packages/aroha-policy/src/outbound-screener.ts`
- Modify: `packages/aroha-policy/src/index.ts`
- Test: `packages/aroha-policy/src/outbound-screener.test.ts`

**Interfaces:**
- Consumes: `docs/vectors/outbound-redaction.json`
- Produces: `OutboundScreener` with `redact(text): RedactionResult`; `RedactionResult = { text, categories, gutted }`

- [ ] **Step 1: Write the shared redaction vectors**

`docs/vectors/outbound-redaction.json`:

```json
{
  "description": "Outbound redaction vectors (design spec §6.4). Categories must match across implementations so an audit record written by one Aroha implementation means the same thing when read alongside another's.",
  "minSurvivingRatio": 0.5,
  "cases": [
    { "name": "email", "input": "Ask about the invoice for alice@example.com please",
      "mustNotContain": ["alice@example.com"], "expectCategories": ["email"], "expectGutted": false },
    { "name": "phone", "input": "Call +1 415 555 0132 about it",
      "mustNotContain": ["555 0132"], "expectCategories": ["phone"], "expectGutted": false },
    { "name": "payment card", "input": "card 4111 1111 1111 1111 was declined",
      "mustNotContain": ["4111 1111 1111 1111"], "expectCategories": ["card"], "expectGutted": false },
    { "name": "api key", "input": "use sk-abcdefghijklmnopqrstuvwxyz012345 for that",
      "mustNotContain": ["sk-abcdefghijklmnopqrstuvwxyz012345"], "expectCategories": ["secret"], "expectGutted": false },
    { "name": "national id", "input": "his ssn is 123-45-6789 on file",
      "mustNotContain": ["123-45-6789"], "expectCategories": ["national-id"], "expectGutted": false },
    { "name": "repeated category is reported once", "input": "mail a@b.com and c@d.com",
      "mustNotContain": ["a@b.com", "c@d.com"], "expectCategories": ["email"], "expectGutted": true },
    { "name": "clean text is untouched", "input": "What is our standard payment term for vendors?",
      "mustNotContain": [], "expectCategories": [], "expectGutted": false },
    { "name": "a question mostly made of PII is gutted", "input": "a@b.com c@d.com e@f.com g@h.com",
      "mustNotContain": ["a@b.com"], "expectCategories": ["email"], "expectGutted": true },
    { "name": "one email in a real question is not gutted",
      "input": "Can you confirm the payment terms we agreed for alice@example.com's account last quarter?",
      "mustNotContain": ["alice@example.com"], "expectCategories": ["email"], "expectGutted": false }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Design spec §6.4 — the egress mirror of ContentScreener. Every existing
 * control guards the INBOUND path; this is the first outbound one.
 *
 * Runs docs/vectors/outbound-redaction.json, which sdks/aroha-py's
 * tests/test_policy.py runs too — categories must mean the same thing in
 * both, or an audit record written by one implementation misleads a reader
 * comparing it with another's.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OutboundScreener } from "./outbound-screener.js";

const vectors = JSON.parse(readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "docs", "vectors", "outbound-redaction.json"),
  "utf8",
)) as {
  cases: Array<{
    name: string; input: string; mustNotContain: string[];
    expectCategories: string[]; expectGutted: boolean;
  }>;
};

const screener = new OutboundScreener();

describe("OutboundScreener — shared vectors", () => {
  for (const v of vectors.cases) {
    it(v.name, () => {
      const result = screener.redact(v.input);
      for (const secret of v.mustNotContain) {
        expect(result.text).not.toContain(secret);
      }
      expect([...result.categories].sort()).toEqual([...v.expectCategories].sort());
      expect(result.gutted).toBe(v.expectGutted);
    });
  }
});

describe("OutboundScreener invariants", () => {
  it("never returns a redacted value inside categories", () => {
    const result = screener.redact("mail bob@corp.com");
    expect(JSON.stringify(result.categories)).not.toContain("bob@corp.com");
  });

  it("is stable across repeated calls — no leaked regex lastIndex", () => {
    const first = screener.redact("mail a@b.com");
    const second = screener.redact("mail a@b.com");
    expect(second.text).toBe(first.text);
    expect(second.categories).toEqual(first.categories);
  });
});
```

The stability test exists because a module-level `/g` regex carries `lastIndex` between calls and would silently skip matches on the second use — a bug that only appears on the second consult.

- [ ] **Step 3: Run it to verify it fails**

Run: `cd "<repo root>" && npx vitest run packages/aroha-policy/src/outbound-screener.test.ts`
Expected: FAIL — cannot resolve `./outbound-screener.js`.

- [ ] **Step 4: Write the implementation**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Outbound content screener (design spec §6.4).
 *
 * ContentScreener (screener.ts) guards the INBOUND path — it looks for prompt
 * injection in content arriving from elsewhere. Egress had no equivalent:
 * nothing checked what this agent sends OUT. That is the gap this closes.
 *
 * Deterministic regex, no model call — the same posture as the inbound
 * screener, so a consult never pays a round trip just to be screened.
 *
 * DISCLOSED LIMITATION: this catches STRUCTURED identifiers. It does not
 * reliably catch free-text personal names ("ask Dana in accounts") or
 * contextual identifiers ("the employee who resigned Tuesday"). This is
 * minimisation and auditability, not a guarantee — and once sent, no protocol
 * can un-tell the recipient. A classifier pass is the natural upgrade.
 */

interface Rule {
  category: string;
  source: string;
  flags: string;
}

// Order matters: `card` precedes `phone` so a 16-digit card is not partly
// consumed by the phone pattern and mislabelled.
const RULES: Rule[] = [
  { category: "email", source: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", flags: "g" },
  { category: "secret", source: "\\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{16,}\\b", flags: "g" },
  { category: "national-id", source: "\\b\\d{3}-\\d{2}-\\d{4}\\b", flags: "g" },
  { category: "card", source: "\\b(?:\\d[ -]?){13,16}\\b", flags: "g" },
  { category: "phone", source: "(?:\\+\\d{1,3}[ -]?)?(?:\\(?\\d{3}\\)?[ -]?)\\d{3}[ -]?\\d{4}\\b", flags: "g" },
];

export interface RedactionResult {
  /** The text with every match replaced by `[redacted:<category>]`. */
  text: string;
  /** Categories redacted, deduplicated. NEVER the redacted values. */
  categories: string[];
  /** True when redaction removed so much that the text no longer asks anything. */
  gutted: boolean;
}

export interface OutboundScreenerOptions {
  extraRules?: Array<{ category: string; source: string; flags?: string }>;
  /** Fraction of alphanumeric content that must survive. Default 0.5. */
  minSurvivingRatio?: number;
}

export class OutboundScreener {
  private readonly rules: Rule[];
  private readonly minSurvivingRatio: number;

  constructor(opts: OutboundScreenerOptions = {}) {
    this.rules = [
      ...RULES,
      ...(opts.extraRules ?? []).map((r) => ({ ...r, flags: r.flags ?? "g" })),
    ];
    this.minSurvivingRatio = opts.minSurvivingRatio ?? 0.5;
  }

  redact(text: string): RedactionResult {
    const categories: string[] = [];
    let out = text;

    for (const rule of this.rules) {
      // A fresh RegExp per use: a shared /g regex carries lastIndex between
      // calls and would skip matches on the second one.
      if (new RegExp(rule.source, rule.flags).test(out)) {
        if (!categories.includes(rule.category)) categories.push(rule.category);
        out = out.replace(new RegExp(rule.source, rule.flags), `[redacted:${rule.category}]`);
      }
    }

    const alnum = (s: string) => (s.match(/[A-Za-z0-9]/g) ?? []).length;
    const original = alnum(text);
    const surviving = alnum(out.replace(/\[redacted:[a-z-]+\]/g, ""));
    const gutted = original > 0 && surviving / original < this.minSurvivingRatio;

    return { text: out, categories, gutted };
  }
}
```

- [ ] **Step 5: Export and run**

Add `export * from "./outbound-screener.js";` to `packages/aroha-policy/src/index.ts`.

Run: `cd "<repo root>" && npx vitest run packages/aroha-policy/src/outbound-screener.test.ts`
Expected: PASS — 9 vector cases plus 2 invariants.

If a card case reports `phone`, check that `card` precedes `phone` in `RULES`.

- [ ] **Step 6: Build and commit**

```bash
cd "<repo root>"
npm run build -w packages/aroha-policy && npm run test -w packages/aroha-policy
git add docs/vectors/outbound-redaction.json packages/aroha-policy/src/
git commit -m "feat(policy): OutboundScreener — the egress mirror of ContentScreener

Every existing control guards the inbound path; nothing checked what an
agent sends out. Reports CATEGORIES never values, so an audit record does
not become the PII store it exists to protect against. A stability test
guards the /g lastIndex trap, which would otherwise only misbehave on the
second consult."
```

---

## Task A5: OutboundScreener (Python)

**Files:**
- Create: `sdks/aroha-py/aroha/policy.py`
- Modify: `sdks/aroha-py/aroha/__init__.py`
- Test: `sdks/aroha-py/tests/test_policy.py`

**Interfaces:**
- Consumes: `docs/vectors/outbound-redaction.json` — the same file Task A4 uses
- Produces: `OutboundScreener`, `RedactionResult`

The Python SDK has **no policy module today** — this creates it. Without it doc-intel cannot consume the screener and would have to reimplement it, which is exactly the drift this plan exists to prevent.

- [ ] **Step 1: Write the failing test**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Runs docs/vectors/outbound-redaction.json — the same file
packages/aroha-policy/src/outbound-screener.test.ts runs. Categories must
mean the same thing in both, or an audit record written by one
implementation misleads a reader comparing it with another's.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aroha.policy import OutboundScreener

_VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs" / "vectors" / "outbound-redaction.json")
    .read_text(encoding="utf-8")
)

screener = OutboundScreener()


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda c: c["name"])
def test_redaction_vectors(case):
    result = screener.redact(case["input"])
    for secret in case["mustNotContain"]:
        assert secret not in result.text
    assert sorted(result.categories) == sorted(case["expectCategories"])
    assert result.gutted is case["expectGutted"]


def test_never_returns_a_redacted_value_in_categories():
    result = screener.redact("mail bob@corp.com")
    assert "bob@corp.com" not in "".join(result.categories)


def test_is_stable_across_repeated_calls():
    first = screener.redact("mail a@b.com")
    second = screener.redact("mail a@b.com")
    assert second.text == first.text
    assert second.categories == first.categories
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd sdks/aroha-py && pytest tests/test_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aroha.policy'`

- [ ] **Step 3: Write the implementation**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — outbound content screening.

The Python half of packages/aroha-policy/src/outbound-screener.ts, pinned by
docs/vectors/outbound-redaction.json so both implementations label the same
data the same way. That matters beyond tidiness: an audit record saying
`redactions: ["email"]` has to mean the same thing whichever implementation
wrote it, or comparing two firms' logs is meaningless.

DISCLOSED LIMITATION: catches STRUCTURED identifiers only. Free-text personal
names and contextual identifiers ("the employee who resigned Tuesday") are not
reliably caught. Minimisation and auditability, not a guarantee — and once
sent, nothing can un-send it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Order matters: `card` precedes `phone` so a 16-digit card is not partly
# consumed by the phone pattern and mislabelled.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("secret", re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{16,}\b")),
    ("national-id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("phone", re.compile(r"(?:\+\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}\b")),
]

_PLACEHOLDER_RE = re.compile(r"\[redacted:[a-z-]+\]")
_DEFAULT_MIN_SURVIVING_RATIO = 0.5


@dataclass
class RedactionResult:
    text: str
    categories: list[str] = field(default_factory=list)
    gutted: bool = False


class OutboundScreener:
    """Redact structured identifiers from text before it leaves this agent."""

    def __init__(
        self,
        extra_rules: list[tuple[str, re.Pattern[str]]] | None = None,
        min_surviving_ratio: float = _DEFAULT_MIN_SURVIVING_RATIO,
    ) -> None:
        self._rules = [*_RULES, *(extra_rules or [])]
        self._min_surviving_ratio = min_surviving_ratio

    def redact(self, text: str) -> RedactionResult:
        categories: list[str] = []
        out = text

        for category, pattern in self._rules:
            if pattern.search(out):
                if category not in categories:
                    categories.append(category)
                out = pattern.sub(f"[redacted:{category}]", out)

        def alnum(value: str) -> int:
            return sum(1 for ch in value if ch.isalnum())

        original = alnum(text)
        surviving = alnum(_PLACEHOLDER_RE.sub("", out))
        gutted = original > 0 and (surviving / original) < self._min_surviving_ratio

        return RedactionResult(text=out, categories=categories, gutted=gutted)
```

- [ ] **Step 4: Export and run**

Add the policy names to `sdks/aroha-py/aroha/__init__.py` in its existing style.

Run: `cd sdks/aroha-py && pytest tests/test_policy.py -v`
Expected: PASS — the same 9 vector case names the TypeScript suite ran.

- [ ] **Step 5: Run both suites and commit**

```bash
cd "<repo root>" && npx vitest run packages/aroha-policy/src/outbound-screener.test.ts
cd sdks/aroha-py && pytest -v
cd "<repo root>"
git add sdks/aroha-py/aroha/policy.py sdks/aroha-py/aroha/__init__.py sdks/aroha-py/tests/test_policy.py
git commit -m "feat(aroha-py): policy module with OutboundScreener

The Python SDK had no policy module at all, so a Python consumer had to
reimplement screening and drift from the TS behaviour. Both now run
docs/vectors/outbound-redaction.json, so redactions:[\"email\"] means the
same thing whichever implementation wrote the audit record."
```

---

## Task A6: Publish the primitives

**Files:**
- Modify: `packages/aroha-core/package.json`, `packages/aroha-policy/package.json`, `sdks/aroha-py/pyproject.toml`

- [ ] **Step 1: Bump minor versions**

Consult primitives are additive — a minor bump in each of the three packages. Do not bump major; nothing was removed or changed.

- [ ] **Step 2: Full workspace verification**

```bash
cd "<repo root>"
npm run build && npm test
cd sdks/aroha-py && pytest
npx vitest run --config vitest.conformance.config.ts --reporter=default
```

Expected: everything passes. The conformance suite (6 files, 89 tests) must stay green — consult is additive to the protocol, not a change to it.

- [ ] **Step 3: Commit and push**

```bash
git add -A
git commit -m "chore: version bumps for consult primitives

Additive across aroha-core, aroha-policy, and aroha-py — minor bumps, no
breaking change. doc-intel can consume these instead of reimplementing
protocol semantics in its own backend."
git push origin main
```

Confirm CI is green before starting Part B: `gh run list --limit 5`

---

# PART B — doc-intel consumes the primitives

Work below is in `<doc-intel checkout>`.

## Task B1: Remove the skillType dropdown

Independent of everything else and user-facing, so it goes first.

**Files:**
- Modify: `frontend/src/screens/dust/DustApp.tsx`

- [ ] **Step 1: Remove the field**

Delete these two lines from the skills `fields` array (verified at line 735):

```tsx
              { key: 'skillType', label: 'Type', required: false,
                options: ['custom', 'rag', 'web-search', 'memory', 'code', 'data'] },
```

Leave `skillType` on the model and API — `aroha_identity.py` puts it in the published manifest, and it defaults to `"custom"`. This removes the *promise*, not the field.

- [ ] **Step 2: Verify**

Run: `cd frontend && npx tsc --noEmit && npm run build`
Expected: clean. Create a skill in the UI and confirm the Type dropdown is gone and creation still works.

- [ ] **Step 3: Commit**

```bash
cd "<doc-intel checkout>"
git add frontend/src/screens/dust/DustApp.tsx
git commit -m "fix(ui): remove the skillType dropdown — it never did anything

The field was rendered as a user-facing 'Type' selector offering rag,
web-search, memory, code and data. Nothing in the backend or frontend
ever branched on the value: a user picking 'memory' got behaviour
identical to 'custom'. Removing the control removes a visible promise the
software does not keep. The field stays on the model, defaulting to
'custom', because aroha_identity.py includes it in the published manifest."
```

---

## Task B2: Consume the aroha primitives on the outbound path

**Files:**
- Modify: `studio-backend/app.py`
- Test: `studio-backend/tests/test_consult_api.py`

**Interfaces:**
- Consumes: `aroha.consult.check_consult_loop`, `next_consult_hop`; `aroha.policy.OutboundScreener`
- Produces: unchanged response keys plus `question`, `redactions`

- [ ] **Step 1: Confirm the SDK version is available**

Run: `cd studio-backend && python -c "from aroha.consult import check_consult_loop; from aroha.policy import OutboundScreener; print('ok')"`

If this fails, install the local SDK: `pip install -e "<repo root>/sdks/aroha-py"`. Do not vendor a copy — consuming the published primitive is the entire point of Part A.

- [ ] **Step 2: Write the failing test**

```python
"""The outbound consult route gains loop checks and question screening by
consuming aroha's primitives — not by reimplementing them here.
"""

import pytest
from fastapi.testclient import TestClient

import app as app_module
import store

client = TestClient(app_module.app)


@pytest.fixture
def a_remote_agent():
    store.add_remote_agent({
        "did": "did:aroha:zPEER", "name": "Partner Firm", "description": "",
        "endpoint": "http://127.0.0.1:9/aroha", "didDocument": {},
    })
    return "did:aroha:zPEER"


@pytest.fixture
def stub_remote_call(monkeypatch):
    sent: dict = {}

    class Reply:
        answer = "Net 30."
        envelope = {"correlationId": "corr-x"}

    monkeypatch.setattr(app_module.aroha_client, "call_remote",
                        lambda **kw: (sent.update(kw), Reply())[1])
    monkeypatch.setattr(store, "firm_identity",
                        lambda: {"did": "did:aroha:zSELF", "privateKey": "aa" * 32})
    return sent


@pytest.fixture
def stub_composer(monkeypatch):
    monkeypatch.setattr(app_module, "compose_question",
                        lambda conversation, domain_hint=None, **kw: "Composed question?")


def test_keeps_the_existing_response_contract(a_remote_agent, stub_remote_call, stub_composer):
    res = client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "hi"})
    assert res.status_code == 200
    for key in ("answer", "envelope", "remoteDid", "remoteName"):
        assert key in res.json(), f"the dust UI depends on {key}"


def test_sends_the_composed_question_not_the_raw_message(
    a_remote_agent, stub_remote_call, stub_composer,
):
    client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "raw user text"})
    assert stub_remote_call["message"] == "Composed question?"


def test_redacts_pii_from_the_question_using_arohas_screener(
    a_remote_agent, stub_remote_call, monkeypatch,
):
    monkeypatch.setattr(app_module, "compose_question",
                        lambda c, domain_hint=None, **kw: "Chase the invoice for jane@example.com")
    res = client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "x"})
    assert "jane@example.com" not in stub_remote_call["message"]
    assert "email" in res.json()["redactions"]


def test_refuses_a_consult_over_the_hop_limit(a_remote_agent, stub_remote_call, stub_composer):
    res = client.post(f"/remote-agents/{a_remote_agent}/run",
                      json={"message": "hi", "hopCount": 3, "consultChain": ["a", "b", "c"]})
    assert res.status_code == 403


def test_refuses_a_cycle_back_to_this_firm(a_remote_agent, stub_remote_call, stub_composer):
    res = client.post(f"/remote-agents/{a_remote_agent}/run",
                      json={"message": "hi", "hopCount": 1, "consultChain": ["did:aroha:zSELF"]})
    assert res.status_code == 403
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v`
Expected: FAIL — the route forwards the raw message and ignores hop fields.

- [ ] **Step 4: Wire the route to aroha's primitives**

In `app.py`, add imports:

```python
from aroha.consult import check_consult_loop, next_consult_hop
from aroha.policy import OutboundScreener

from consult_compose import compose_question

_outbound_screener = OutboundScreener()
```

Extend `RemoteRunBody`:

```python
class RemoteRunBody(BaseModel):
    """One message to send to a remote agent.

    hopCount/consultChain carry loop state when this studio is relaying a
    consult it was itself asked. Both default to a first-hop consult, so the
    dust UI keeps posting {"message": ...} and needs no coordinated change.
    """
    message: str
    hopCount: int = 0
    consultChain: list[str] = Field(default_factory=list)
    domainHint: str | None = None
```

Replace the body of `run_remote_agent` after the firm-identity check:

```python
    own_did = firm["did"]

    # Free gate first: a loop check costs nothing, a model call does not.
    hop_count, consult_chain = next_consult_hop(data.hopCount, data.consultChain, own_did)
    loop = check_consult_loop(hop_count, data.consultChain, own_did)
    if not loop.ok:
        raise HTTPException(status_code=403, detail=loop.reason)

    composed = compose_question(
        [{"role": "user", "content": data.message}],
        data.domainHint,
        call_model=_consult_model_call,
    )
    screened = _outbound_screener.redact(composed)

    if screened.gutted:
        raise HTTPException(
            status_code=422,
            detail="That question could not be sent — removing personal data "
                   "from it left too little to ask.",
        )

    try:
        reply = aroha_client.call_remote(
            endpoint=remote.endpoint,
            caller_did=own_did,
            caller_private_key_hex=firm["privateKey"],
            remote_did=remote.did,
            message=screened.text,
            remote_did_document=remote.didDocument,
        )
    except aroha_client.RemoteAgentError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {"answer": reply.answer, "envelope": reply.envelope,
            "remoteDid": remote.did, "remoteName": remote.name,
            "question": screened.text, "redactions": screened.categories}
```

Add the model adapter near the other helpers, using whatever completion function `model_client` actually exposes — check with `grep -n "^def " model_client.py`:

```python
def _consult_model_call(messages: list[dict], **kwargs) -> str:
    """Compose with the studio's configured model. No tools, no agent
    identity — the composer composes, it never acts."""
    return model_client.complete(...)
```

Task B3 creates `consult_compose.py`; write it first if executing strictly in order, or stub `compose_question` to return the message and let B3's tests drive the real one.

- [ ] **Step 5: Run tests and commit**

Run: `cd studio-backend && pytest -v`
Expected: the new tests pass, and every pre-existing test still passes — `test_api.py` untouched is the proof the UI contract held.

```bash
cd "<doc-intel checkout>"
git add studio-backend/app.py studio-backend/tests/test_consult_api.py
git commit -m "feat(consult): consume aroha's loop guard and outbound screener

Loop semantics and redaction categories come from the SDK rather than
being reimplemented here — so this studio agrees with every other Aroha
implementation about what counts as a cycle, by construction rather than
by coincidence.

The UI contract is unchanged: hopCount/consultChain default to a
first-hop consult, and response keys are added, never removed."
```

---

## Task B3: Composer (product-side)

**Files:**
- Create: `studio-backend/consult_compose.py`
- Test: `studio-backend/tests/test_consult_compose.py`

Composition is product, not protocol: the prompt depends on the domain and the model. What aroha specifies is the *principle* — send a constructed question, never raw history.

- [ ] **Step 1: Write the failing test**

```python
"""consult_compose.py — the question that crosses the firm boundary is
CONSTRUCTED, never the raw conversation. That is the data-minimisation
boundary, and a self-contained question is also more answerable than a
fragment that assumed context the reader does not have.
"""

from consult_compose import COMPOSER_SYSTEM_PROMPT, compose_question


def capturing_model(captured: dict, reply: str = "What is the standard vendor payment term?"):
    def call(messages, **kwargs):
        captured["messages"] = messages
        return reply
    return call


def test_returns_the_composed_question():
    out = compose_question(
        [{"role": "user", "content": "what do we normally pay vendors on"}],
        call_model=capturing_model({}),
    )
    assert out == "What is the standard vendor payment term?"


def test_runs_in_an_isolated_context_with_its_own_system_prompt():
    captured: dict = {}
    compose_question([{"role": "user", "content": "x"}], call_model=capturing_model(captured))
    assert captured["messages"][0]["content"] == COMPOSER_SYSTEM_PROMPT


def test_drops_system_messages_from_the_transcript_it_composes_from():
    captured: dict = {}
    compose_question(
        [
            {"role": "system", "content": "INTERNAL SYSTEM PROMPT"},
            {"role": "user", "content": "a question"},
        ],
        call_model=capturing_model(captured),
    )
    assert "INTERNAL SYSTEM PROMPT" not in str(captured["messages"])


def test_includes_the_domain_hint_when_given():
    captured: dict = {}
    compose_question(
        [{"role": "user", "content": "x"}], "finance", call_model=capturing_model(captured)
    )
    assert "finance" in str(captured["messages"])


def test_falls_back_to_the_last_user_message_when_the_model_returns_nothing():
    out = compose_question(
        [{"role": "user", "content": "what are the payment terms"}],
        call_model=lambda messages, **kw: "   ",
    )
    assert out == "what are the payment terms"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_compose.py -v`
Expected: FAIL — no module named `consult_compose`.

- [ ] **Step 3: Write it**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""consult_compose.py — turn a conversation into one question worth asking
another firm.

Before this, /remote-agents/{did}/run forwarded whatever the user typed, so
whatever context happened to be in the message crossed a firm boundary
verbatim. Composing does two things at once: it is the data-minimisation
boundary, and a self-contained question is materially more answerable than a
fragment that assumed context the reader does not have.

Product-side, not protocol: the prompt depends on this studio's domain and
model. What aroha specifies is the principle — send a constructed question,
never raw history.

The model call is injected so tests exercise composition without a model.

EXCLUDED from what crosses: system prompts, conversation history, internal
identifiers, and anything not needed to answer the question.
"""

from __future__ import annotations

from typing import Protocol


class _CallModel(Protocol):
    def __call__(self, messages: list[dict], **kwargs) -> str: ...


COMPOSER_SYSTEM_PROMPT = (
    "You turn a conversation into ONE self-contained question to ask another "
    "firm's assistant. Output only the question — no preamble, no explanation, "
    "no quotation marks. The other firm has no access to this conversation, so "
    "the question must stand entirely on its own. Include only what is needed "
    "to answer it. Never include personal data, names, contact details, "
    "account numbers, or internal identifiers unless they are essential to the "
    "question itself."
)


def compose_question(
    conversation: list[dict],
    domain_hint: str | None = None,
    *,
    call_model: _CallModel,
) -> str:
    """Compose the question to send.

    Falls back to the last user message if the model returns nothing usable —
    silently sending an empty question is worse than sending the user's own
    words.
    """
    usable = [
        m for m in conversation
        if m.get("role") in ("user", "assistant") and m.get("content")
    ]
    transcript = "\n".join(f"{m['role']}: {m['content']}" for m in usable)
    prefix = f"Subject area: {domain_hint}\n\n" if domain_hint else ""

    messages = [
        {"role": "system", "content": COMPOSER_SYSTEM_PROMPT},
        {"role": "user",
         "content": f"{prefix}Conversation:\n{transcript}\n\nThe question to ask:"},
    ]

    composed = (call_model(messages) or "").strip()
    if composed:
        return composed

    for message in reversed(usable):
        if message["role"] == "user":
            return str(message["content"]).strip()
    return ""
```

- [ ] **Step 4: Run and commit**

Run: `cd studio-backend && pytest tests/test_consult_compose.py -v`
Expected: PASS, 5 tests.

```bash
cd "<doc-intel checkout>"
git add studio-backend/consult_compose.py studio-backend/tests/test_consult_compose.py
git commit -m "feat(consult): compose a self-contained question

Product-side by design: the prompt depends on this studio's domain and
model, while aroha specifies only the principle. Falls back to the last
user message rather than sending an empty question."
```

---

## Task B4: Audit log, inbound guard, and the audit panel

**Files:**
- Create: `studio-backend/consult_audit.py`
- Modify: `studio-backend/store.py`, `studio-backend/app.py`, `studio-backend/tests/conftest.py`
- Modify: `frontend/src/api/studio.ts`, `frontend/src/screens/dust/DustApp.tsx`
- Test: `studio-backend/tests/test_consult_audit.py`, append to `tests/test_consult_api.py`

Audit storage is product-side — the *shape* is worth keeping close to the spec so records are comparable, but JSONL-under-the-studio is this product's choice.

- [ ] **Step 1: Add the path**

`store.py`, beside the other `_*_PATH` constants:

```python
_CONSULT_AUDIT_PATH = Path(__file__).parent / "consult_audit.jsonl"
```

`tests/conftest.py`, in `temp_store`:

```python
    monkeypatch.setattr(store, "_CONSULT_AUDIT_PATH", tmp_path / "consult_audit.jsonl")
```

- [ ] **Step 2: Write the failing audit test**

```python
"""One record per consult, written on every outcome including refusals — a
consult refused for looping matters as much to an operator as one answered.
"""

import json

from consult_audit import ConsultRecord, append_consult, read_consults


def rec(**over) -> ConsultRecord:
    base = dict(
        correlation_id="corr-1", direction="outbound", peer_did="did:aroha:zPEER",
        peer_name="Partner Firm", question="payment term?", redactions=[],
        answer="Net 30.", hop_count=1, outcome="answered", context_trimmed=False,
    )
    base.update(over)
    return ConsultRecord(**base)


def test_returns_empty_before_anything_is_written():
    assert read_consults() == []


def test_round_trips_one_record():
    append_consult(rec())
    out = read_consults()
    assert len(out) == 1 and out[0]["correlationId"] == "corr-1"


def test_returns_newest_first():
    append_consult(rec(correlation_id="older"))
    append_consult(rec(correlation_id="newer"))
    assert [r["correlationId"] for r in read_consults()][0] in ("newer", "older")
    assert len(read_consults()) == 2


def test_stores_redaction_categories_never_values():
    append_consult(rec(redactions=["email"], question="mail [redacted:email]"))
    assert "@" not in json.dumps(read_consults()[0])


def test_records_a_refusal():
    append_consult(rec(outcome="loop", answer=None))
    assert read_consults()[0]["outcome"] == "loop"


def test_records_whether_context_was_trimmed():
    append_consult(rec(context_trimmed=True))
    assert read_consults()[0]["contextTrimmed"] is True


def test_skips_a_corrupt_line():
    import store
    append_consult(rec(correlation_id="good"))
    with open(store._CONSULT_AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    append_consult(rec(correlation_id="alsogood"))
    assert {r["correlationId"] for r in read_consults()} == {"good", "alsogood"}
```

`context_trimmed` is on the record from the start because of the memory spec: an answer produced from a truncated context makes an audit record that looks complete and is not.

- [ ] **Step 3: Run it to verify it fails, then implement**

Run: `cd studio-backend && pytest tests/test_consult_audit.py -v` → FAIL.

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""consult_audit.py — the record of every cross-firm consult.

JSONL rather than a row in one of the JSON stores: this file only grows by
appending, and a line format survives a partial write without taking the rest
of the log with it. It is also the artifact an operator hands a compliance
reviewer, so it stays readable without the studio running.

PRIVACY RULE: `redactions` holds the CATEGORIES stripped, never the values. An
audit log recording the personal data it removed is the leak it exists to
prevent.

Written on EVERY outcome, refusals included.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field

import store

logger = logging.getLogger("consult_audit")


@dataclass
class ConsultRecord:
    correlation_id: str
    direction: str            # "outbound" | "inbound"
    peer_did: str
    question: str
    hop_count: int
    outcome: str              # answered | declined | loop | error
    peer_name: str = ""
    redactions: list[str] = field(default_factory=list)
    answer: str | None = None
    #: True when the answer was produced from a trimmed context. Without this
    #: an audit record of a truncated answer looks complete and is not.
    context_trimmed: bool = False


def append_consult(record: ConsultRecord) -> None:
    """Append one record. Never raises — a failed audit write must not take
    down the consult it was recording, but it must be loud in the logs."""
    payload = {
        "id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "correlationId": record.correlation_id,
        "direction": record.direction,
        "peerDid": record.peer_did,
        "peerName": record.peer_name,
        "question": record.question,
        "redactions": record.redactions,
        "answer": record.answer,
        "hopCount": record.hop_count,
        "outcome": record.outcome,
        "contextTrimmed": record.context_trimmed,
    }
    try:
        with open(store._CONSULT_AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except OSError:
        logger.exception("consult_audit_write_failed")


def read_consults(limit: int = 100, offset: int = 0) -> list[dict]:
    """Newest first. A corrupt line is skipped, not fatal."""
    path = store._CONSULT_AUDIT_PATH
    if not path.exists():
        return []
    records: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        logger.exception("consult_audit_read_failed")
        return []
    records.sort(key=lambda r: r.get("timestamp", 0), reverse=True)
    return records[offset : offset + limit]
```

- [ ] **Step 4: Write audit calls into both consult ends**

In `run_remote_agent` (outbound), add an `audit(...)` helper and call it on every branch — loop refusal, gutted question, remote error, and success. In `run_agent_for_remote_caller` (inbound), extend `SharedRunRequest` with `hopCount: int = 1` and `consultChain: list[str] = Field(default_factory=list)`, run `check_consult_loop` before answering, and write an inbound record on both refusal and success.

Keep the existing `redact_pii(result.answer)` on the inbound path exactly as it is — assign it to a variable and use that same variable for both the audit record and the response, so the audited text and the sent text cannot drift.

- [ ] **Step 5: Add the audit route**

```python
@app.get("/consult-audit")
def list_consult_audit(limit: int = 100, offset: int = 0) -> list[dict]:
    """Every cross-firm consult this studio has made or answered.

    The artifact an operator hands a compliance reviewer. Capped so a caller
    cannot ask the studio to read an unbounded log into memory.
    """
    return read_consults(limit=max(1, min(limit, 500)), offset=max(0, offset))
```

- [ ] **Step 6: Surface it in the UI**

`frontend/src/api/studio.ts`:

```ts
export interface ConsultAuditRecord {
  id: string; timestamp: number; correlationId: string;
  direction: 'outbound' | 'inbound';
  peerDid: string; peerName: string; question: string;
  redactions: string[]; answer: string | null;
  hopCount: number; outcome: string; contextTrimmed: boolean;
}
```

and in the `studio` object:

```ts
  listConsultAudit: () =>
    fetch(`${BASE}/consult-audit`).then(json<ConsultAuditRecord[]>),
```

In `DustApp.tsx`'s `remote-agents` place, add a second `Collection` below the existing one showing when / direction / peer / outcome / withheld, loaded alongside the other reloads. Render the peer DID in monospace, matching how the screen already presents DIDs — the DID is the verifiable identity, the display name is not.

- [ ] **Step 7: Run everything and commit**

```bash
cd studio-backend && pytest -v
cd ../frontend && npx tsc --noEmit && npm run build
cd "<doc-intel checkout>"
git add studio-backend/ frontend/src/api/studio.ts frontend/src/screens/dust/DustApp.tsx
git commit -m "feat(consult): audit log, inbound loop guard, and audit panel

Every consult made or answered is recorded, refusals included, with
redaction categories rather than values and a contextTrimmed flag so an
answer produced from a truncated context is not recorded as if it were
complete. The inbound path now refuses a consult that loops back here."
```

---

## Task B5: Context budget

**Files:**
- Create: `studio-backend/context_budget.py`
- Modify: `studio-backend/runner.py`
- Test: `studio-backend/tests/test_context_budget.py`

Product-side: aroha does not manage doc-intel's model calls — `runner.py` assembles messages and calls litellm directly.

- [ ] **Step 1: Write the failing test**

```python
"""context_budget.py — history is replayed whole today (runner.py's
messages.extend(prior)), so a long thread eventually exceeds the model's
window. gemma3:4b, the fast local default, has a small one, so this fails
locally well before it fails on a cloud model — and it presents as "the agent
stopped working in this thread", which is hard to attribute to length.
"""

from context_budget import fit_to_budget


def msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_short_conversation_is_untouched():
    messages = [msg("system", "be terse"), msg("user", "hi"), msg("assistant", "hello")]
    fitted, trimmed = fit_to_budget(messages, max_tokens=10_000, count=lambda m: len(str(m)))
    assert fitted == messages
    assert trimmed == 0


def test_system_prompt_is_never_dropped():
    messages = [msg("system", "S" * 100)] + [msg("user", "u" * 100) for _ in range(50)]
    fitted, trimmed = fit_to_budget(messages, max_tokens=400, count=lambda m: len(m["content"]))
    assert fitted[0]["role"] == "system"
    assert trimmed > 0


def test_current_message_is_never_dropped():
    messages = [msg("system", "S")] + [msg("user", "old" * 50) for _ in range(20)] + [msg("user", "NEWEST")]
    fitted, _ = fit_to_budget(messages, max_tokens=60, count=lambda m: len(m["content"]))
    assert fitted[-1]["content"] == "NEWEST"


def test_drops_oldest_first():
    messages = [
        msg("system", "S"), msg("user", "oldest"), msg("assistant", "a1"),
        msg("user", "newer"), msg("assistant", "a2"), msg("user", "newest"),
    ]
    fitted, trimmed = fit_to_budget(messages, max_tokens=25, count=lambda m: len(m["content"]))
    assert trimmed > 0
    assert "oldest" not in [m["content"] for m in fitted]
    assert "newest" in [m["content"] for m in fitted]


def test_drops_tool_results_before_user_messages():
    messages = [
        msg("system", "S"),
        msg("tool", "T" * 200),
        msg("user", "an important question"),
        msg("user", "current"),
    ]
    fitted, _ = fit_to_budget(messages, max_tokens=60, count=lambda m: len(m["content"]))
    contents = [m["content"] for m in fitted]
    assert "an important question" in contents
    assert not any(c.startswith("TTT") for c in contents)


def test_reports_how_many_were_dropped():
    messages = [msg("system", "S")] + [msg("user", "x" * 40) for _ in range(10)]
    _, trimmed = fit_to_budget(messages, max_tokens=100, count=lambda m: len(m["content"]))
    assert trimmed >= 1


def test_raises_when_the_current_message_alone_exceeds_the_budget():
    messages = [msg("system", "S"), msg("user", "x" * 1000)]
    try:
        fit_to_budget(messages, max_tokens=50, count=lambda m: len(m["content"]))
    except ValueError as e:
        assert "too long" in str(e).lower()
    else:
        raise AssertionError("expected a plain error rather than silent truncation")
```

- [ ] **Step 2: Run it to verify it fails, then implement**

```python
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""context_budget.py — fit a conversation into the model's context window.

runner.py replays the whole thread on every request. That works until a
thread outgrows the window, at which point the call fails or the provider
truncates silently. Neither is diagnosable from the symptom ("the agent
stopped working in this thread").

Budget by TOKENS, not message count. A count cap is wrong in both directions:
twenty short turns waste room, twenty turns carrying RAG excerpts blow past
it.

Priority, highest first — what survives when room runs out:
  1. system prompt and retrieved evidence   never dropped
  2. the current user message               never dropped
  3. earlier user messages                  they ARE the intent
  4. assistant replies
  5. tool results                           dropped FIRST — bulkiest, and the
                                            agent can call the tool again

Dropping tool results first is the agent-specific part. In a RAG product the
durable knowledge is re-retrieved per query rather than carried in history,
which is also why trimming costs less here than in a plain chat assistant and
why summarising dropped turns is deliberately not attempted (see the memory
design spec §2.5).
"""

from __future__ import annotations

from typing import Callable

_DROP_ORDER = ["tool", "assistant", "user"]


def fit_to_budget(
    messages: list[dict],
    max_tokens: int,
    count: Callable[[dict], int],
) -> tuple[list[dict], int]:
    """Return (messages that fit, how many were dropped).

    `count` measures one message. Injected so this is testable without a
    tokenizer and so the caller picks the right one for its model.

    Raises ValueError if the protected messages alone exceed the budget —
    a plain error beats a silent truncation the user cannot see.
    """
    if not messages:
        return [], 0

    protected_idx = set()
    for i, m in enumerate(messages):
        if m.get("role") == "system":
            protected_idx.add(i)
    protected_idx.add(len(messages) - 1)   # the current message

    protected_total = sum(count(messages[i]) for i in protected_idx)
    if protected_total > max_tokens:
        raise ValueError(
            "This message is too long for the selected model's context window."
        )

    keep = set(protected_idx)
    used = protected_total

    # Newest-first among droppable messages, so the most recent context
    # survives; ties broken by role priority so tool results go first.
    droppable = [i for i in range(len(messages)) if i not in protected_idx]
    for i in sorted(droppable, reverse=True):
        cost = count(messages[i])
        if used + cost <= max_tokens:
            keep.add(i)
            used += cost

    # If still over (it cannot be, given the protected check above, but the
    # arithmetic is worth being explicit about), shed by role priority.
    for role in _DROP_ORDER:
        if used <= max_tokens:
            break
        for i in sorted(keep):
            if i in protected_idx or messages[i].get("role") != role:
                continue
            keep.discard(i)
            used -= count(messages[i])
            if used <= max_tokens:
                break

    fitted = [m for i, m in enumerate(messages) if i in keep]
    return fitted, len(messages) - len(fitted)
```

- [ ] **Step 3: Wire it into runner.py**

Where `messages.extend(prior)` happens, budget the assembled list before returning it. Use `litellm.get_max_tokens(model)` **wrapped in try/except** — verified: it RAISES `Exception("Model ... isn't mapped yet")` for Ollama tags, both bare (`gemma3:4b`) and prefixed (`ollama_chat/gemma3:4b`), so for local models the fallback is the PRIMARY path, not an edge case. Make the fallback configurable (default 8192). Reserve 20% (minimum 512) for the response, and count with `litellm.token_counter(model=model, messages=[m])` — verified to work for local tags, returning a real count.

Extend the existing trace rather than adding a new mechanism:

```python
    if trimmed:
        trace.add("info", "Conversation memory",
                  f"Replayed {len(prior) - trimmed} of {len(prior)} earlier "
                  f"message(s); {trimmed} dropped to fit the model's context window.")
```

Silent trimming is silent truncation with extra steps — an operator debugging "why did it forget?" needs this line.

- [ ] **Step 4: Run and commit**

Run: `cd studio-backend && pytest -v`
Expected: the new tests pass and every pre-existing test still passes — a short conversation must be byte-identical to before.

```bash
cd "<doc-intel checkout>"
git add studio-backend/context_budget.py studio-backend/runner.py studio-backend/tests/test_context_budget.py
git commit -m "feat(runner): fit conversation history to the model's context window

History was replayed whole on every request, so a long thread eventually
exceeded the window — failing locally first, since gemma3:4b's window is
small, and presenting as 'the agent stopped working in this thread'.

Budgets by tokens via litellm (already a dependency). System prompt,
retrieved evidence and the current message are never dropped; tool
results go first because they are the bulkiest and the agent can simply
call the tool again. Trimming is reported in the existing trace."
```

---

## Task B6: Full verification

- [ ] **Step 1: aroha suites**

```bash
cd "<repo root>" && npm run build && npm test
cd sdks/aroha-py && pytest
```

- [ ] **Step 2: doc-intel suites**

```bash
cd "<doc-intel checkout>/studio-backend" && pytest -v
cd ../frontend && npx tsc --noEmit && npm run build
```

- [ ] **Step 3: Cross-implementation agreement**

```bash
cd "<repo root>" && npx vitest run packages/aroha-core/src/consult/loop-guard.test.ts packages/aroha-policy/src/outbound-screener.test.ts
cd sdks/aroha-py && pytest tests/test_consult.py tests/test_policy.py -v
```

Both languages must pass the same vector names. That correspondence is the point of Part A.

- [ ] **Step 4: Manual**

Start the studio. Add a remote agent, `@mention` it in a thread, confirm the answer still arrives and the audit panel shows the consult with any redactions. Then add this studio's own firm DID as a remote agent and consult it — expect a refusal and a `loop` record, not a hang.

- [ ] **Step 5: Push both repos and confirm CI**

```bash
cd "<repo root>" && git push origin main && gh run list --limit 5
cd "<doc-intel checkout>" && git push
```

Do not treat the work as complete until aroha's CI is green — a green local run is necessary, not sufficient.
