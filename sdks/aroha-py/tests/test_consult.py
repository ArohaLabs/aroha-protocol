# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Runs the shared vectors in docs/vectors/consult-loop.json.

The TypeScript SDK runs the same file — see
packages/aroha-core/src/consult/loop-guard.test.ts. If these two suites ever
disagree, two Aroha agents disagree about whether a consult chain is legal,
and the disagreement surfaces only in production between two parties.
"""

import json
from pathlib import Path

import pytest

from aroha.consult import (
    DEFAULT_MAX_CONSULT_HOPS,
    ConsultLoopState,
    check_consult_loop,
    next_consult_hop,
)


def _load_vectors() -> dict:
    """Walk up to the repo root rather than hardcoding a depth, so moving the
    SDK inside the monorepo does not silently skip every shared vector."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "docs" / "vectors" / "consult-loop.json"
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "docs/vectors/consult-loop.json not found above %s — the shared vectors "
        "are the cross-language agreement and must not be skipped" % here
    )


VECTORS = _load_vectors()


@pytest.mark.parametrize("v", VECTORS["checkLoopLimits"], ids=lambda v: v["name"])
def test_check_consult_loop(v):
    verdict = check_consult_loop(
        ConsultLoopState(hop_count=v["hopCount"], consult_chain=v["consultChain"]),
        v["ownDid"],
        v["maxHops"],
    )
    assert verdict.ok is v["expectOk"]
    if v.get("expectReasonContains"):
        assert verdict.ok is False
        assert v["expectReasonContains"].lower() in (verdict.reason or "").lower()


@pytest.mark.parametrize("v", VECTORS["nextHop"], ids=lambda v: v["name"])
def test_next_consult_hop(v):
    hop_count, chain = next_consult_hop(v["hopCount"], v["consultChain"], v["ownDid"])
    assert hop_count == v["expectHopCount"]
    assert chain == v["expectChain"]


def test_default_matches_vectors():
    assert DEFAULT_MAX_CONSULT_HOPS == VECTORS["maxHopsDefault"]


def test_next_hop_does_not_mutate_input():
    chain = ["did:aroha:zA"]
    next_consult_hop(1, chain, "did:aroha:zB")
    assert chain == ["did:aroha:zA"]
