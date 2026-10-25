# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Consult wire shapes and loop prevention (design spec §3.2, §4).

The Python mirror of ``packages/aroha-core/src/consult/``. Both run the same
vectors in ``docs/vectors/consult-loop.json``, which is what makes "mirror" a
verified claim rather than an intention.

A consult travels as an ordinary ArohaRequest with capability ``"consult"`` —
no new message type and no protocol version bump. The dataclasses here are the
``params`` and ``result`` payloads inside that envelope.

Field names on the wire stay camelCase to match the TypeScript SDK; the Python
attributes are snake_case per PEP 8. ``to_wire``/``from_wire`` are the only
places that mapping lives, so a rename cannot half-happen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "CONSULT_CAPABILITY",
    "DEFAULT_MAX_CONSULT_HOPS",
    "ConsultSource",
    "ConsultParams",
    "ConsultResult",
    "ConsultLoopState",
    "ConsultLoopVerdict",
    "check_consult_loop",
    "next_consult_hop",
]

#: The capability name a consult request carries.
CONSULT_CAPABILITY = "consult"

#: Consult depth allowed by default before an agent refuses (design spec §3.2).
DEFAULT_MAX_CONSULT_HOPS = 3


# ── Wire shapes ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConsultSource:
    """What the consulted agent used to produce its answer (design spec §4.3)."""

    tool: str
    summary: str

    def to_wire(self) -> dict[str, Any]:
        return {"tool": self.tool, "summary": self.summary}

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "ConsultSource":
        return cls(tool=d["tool"], summary=d["summary"])


@dataclass
class ConsultParams:
    """The ``params`` of an inbound or outbound consult request."""

    #: A self-contained question. Never the caller's raw conversation history.
    question: str
    #: Consult hops already taken. A first-hop consult sends 1.
    hop_count: int
    #: DIDs already in this chain, in order. Used for cycle detection.
    consult_chain: list[str] = field(default_factory=list)
    #: Optional subject-area hint, for the answering side's triage.
    domain_hint: Optional[str] = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {
            "question": self.question,
            "hopCount": self.hop_count,
            "consultChain": list(self.consult_chain),
        }
        if self.domain_hint is not None:
            wire["domainHint"] = self.domain_hint
        return wire

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "ConsultParams":
        return cls(
            question=d["question"],
            hop_count=d["hopCount"],
            consult_chain=list(d.get("consultChain") or []),
            domain_hint=d.get("domainHint"),
        )


@dataclass
class ConsultResult:
    """The ``result`` an answering agent returns."""

    answer: str
    #: Tools consulted — makes an answer checkable rather than merely asserted.
    sources: list[ConsultSource] = field(default_factory=list)
    #: Fingerprint of the answering agent's prompt/model (design spec §11.3 —
    #: "behavioural versioning"). Detectable, not preventable: makes a silent
    #: prompt/model change visible after the fact rather than invisible.
    #: Optional because not every answering implementation computes one yet.
    behaviour_hash: Optional[str] = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {"answer": self.answer, "sources": [s.to_wire() for s in self.sources]}
        if self.behaviour_hash is not None:
            wire["behaviourHash"] = self.behaviour_hash
        return wire

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "ConsultResult":
        return cls(
            answer=d["answer"],
            sources=[ConsultSource.from_wire(s) for s in d.get("sources") or []],
            behaviour_hash=d.get("behaviourHash"),
        )


# ── Loop prevention ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConsultLoopState:
    """The subset of ConsultParams the guard needs."""

    hop_count: int
    consult_chain: list[str]


@dataclass(frozen=True)
class ConsultLoopVerdict:
    ok: bool
    reason: Optional[str] = None


def check_consult_loop(
    state: ConsultLoopState,
    own_did: str,
    max_hops: int = DEFAULT_MAX_CONSULT_HOPS,
) -> ConsultLoopVerdict:
    """
    Decide whether an inbound consult may be served.

    Two independent limits, because neither alone is sufficient:

    - A hop count bounds depth. Alone it cannot stop A→B→A→B, which stays under
      any limit for a while and burns two agents' budgets doing it.
    - A chain membership check stops cycles. Alone it cannot stop an unbounded
      line of distinct agents.

    Both checks are cheap and run on the RECEIVING side, before any model or
    tool is touched. An agent that trusts a caller's self-reported hop count is
    trusting the party with the motive to lie about it, so treat these as a
    defence against accidents and misconfiguration; the peer allowlist is what
    defends against a hostile caller.

    Refusal order is fixed and MUST match the TypeScript implementation:
    malformed, then hop limit, then cycle. The reason lands in both parties'
    audit logs, so disagreeing about which reason to report for a request that
    violates several rules makes those logs unreconcilable.
    """
    hop_count = state.hop_count

    # bool is a subclass of int in Python; True would otherwise pass as hop 1.
    if isinstance(hop_count, bool) or not isinstance(hop_count, int) or hop_count < 1:
        return ConsultLoopVerdict(
            ok=False,
            reason=f"malformed consult: hopCount must be a positive integer, got {hop_count}",
        )

    # A well-formed sender increments the count and appends to the chain
    # together (see next_consult_hop), so the chain can never be LONGER than
    # the hop count. When it is, the two disagree about how far this consult
    # has travelled, and the hop count is the smaller — the one that would
    # evade the depth limit.
    #
    # Not proof against a determined liar: both fields are self-reported, and
    # trimming the chain to match still under-reports depth. It costs nothing,
    # catches the inconsistent case, and means evading the limit now also
    # means destroying the evidence cycle detection runs on.
    if len(state.consult_chain) > hop_count:
        return ConsultLoopVerdict(
            ok=False,
            reason=(
                f"malformed consult: the chain names {len(state.consult_chain)} agents "
                f"but hopCount is {hop_count} — a well-formed consult increments both together"
            ),
        )

    if hop_count > max_hops:
        return ConsultLoopVerdict(
            ok=False,
            reason=f"consult refused: hop {hop_count} exceeds the limit of {max_hops}",
        )

    if own_did in state.consult_chain:
        return ConsultLoopVerdict(
            ok=False,
            reason=f"consult refused: cycle — {own_did} is already in the consult chain",
        )

    return ConsultLoopVerdict(ok=True)


def next_consult_hop(
    hop_count: int,
    consult_chain: list[str],
    own_did: str,
) -> tuple[int, list[str]]:
    """
    Build the hop count and chain to send on an OUTBOUND consult.

    Call this whether originating a consult (hop_count 0, empty chain) or
    relaying one received from someone else — the arithmetic is the same, and
    having one function for both is what keeps an originator from forgetting to
    append itself and thereby erasing its own name from the cycle check.

    Returns a new list; the caller's chain is never mutated.
    """
    return hop_count + 1, [*consult_chain, own_did]
