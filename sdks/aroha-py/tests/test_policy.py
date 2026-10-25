# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Runs the shared vectors in docs/vectors/outbound-redaction.json.

The TypeScript SDK runs the same file — see
packages/aroha-policy/src/outbound-screener.test.ts. A divergence here means
one SDK leaks an identifier its sibling catches, and the leak is visible only
to the receiving party, who has no reason to report it.
"""

import json
import re
from pathlib import Path

import pytest

from aroha.policy import (
    OutboundRule,
    OutboundScreener,
    create_outbound_screener,
    passes_luhn,
)


def _load_vectors() -> dict:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "docs" / "vectors" / "outbound-redaction.json"
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "docs/vectors/outbound-redaction.json not found above %s — the shared "
        "vectors are the cross-language agreement and must not be skipped" % here
    )


VECTORS = _load_vectors()


@pytest.mark.parametrize("v", VECTORS["cases"], ids=lambda v: v["name"])
def test_outbound_screener(v):
    result = create_outbound_screener().screen(v["input"])
    assert result.text == v["expectText"]
    assert [
        {"category": r.category, "count": r.count} for r in result.redactions
    ] == v["expectRedactions"]


def test_redacted_flag():
    screener = create_outbound_screener()
    assert screener.screen("nothing here").redacted is False
    assert screener.screen("a@b.com").redacted is True


def test_result_never_carries_matched_values():
    # The audit log records these verbatim (design spec §6.2). Values here
    # would make the audit trail the largest unredacted store of exactly the
    # identifiers the screener exists to remove.
    result = create_outbound_screener().screen("mail dana.k@example.com now")
    serialised = json.dumps([{"category": r.category, "count": r.count} for r in result.redactions])
    assert "dana" not in serialised
    assert "example.com" not in serialised


def test_extra_rules():
    screener = OutboundScreener(
        extra_rules=[OutboundRule(category="employee_id", pattern=re.compile(r"\bEMP-\d{6}\b"))]
    )
    result = screener.screen("see EMP-004512 for details")
    assert result.text == "see [REDACTED:EMPLOYEE_ID] for details"
    assert [(r.category, r.count) for r in result.redactions] == [("employee_id", 1)]


def test_luhn():
    assert passes_luhn("4111111111111111") is True
    assert passes_luhn("1234567890123456") is False
    assert passes_luhn("411") is False          # too short to be a card
    assert passes_luhn("41111111111111111111") is False  # too long
    assert passes_luhn("4111-1111") is False    # separators must be stripped first
