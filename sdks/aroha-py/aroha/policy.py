# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Outbound PII screening (design spec §5).

The Python mirror of ``packages/aroha-policy/src/outbound-screener.ts``. Both
run the vectors in ``docs/vectors/outbound-redaction.json``, which is what
makes "mirror" a verified claim rather than an intention.

Screening runs on text LEAVING an agent — the question sent to a peer, not the
answer shown to the user. It redacts rather than blocks: a consult that fails
because it mentioned a phone number teaches the user to route around the
screener, whereas one that succeeds with the number replaced usually still gets
a useful answer.

Scope is structured identifiers only. Emails, phone numbers, national IDs, card
numbers, IPs, and API keys have shapes; names, addresses, and medical details do
not, and a regex chasing them false-positives at a rate that gets the whole
feature switched off. Names are NOT redacted, and the vectors say so explicitly
so the omission is not later read as a bug. The real defence against
unstructured leakage is the composer, which constructs the outbound question
rather than forwarding the user's raw conversation.

Results carry categories and counts, never matched values. The audit log records
them verbatim (design spec §6.2) — values there would make the audit trail the
largest unredacted store of exactly the identifiers this module removes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern

__all__ = [
    "OutboundRule",
    "OutboundRedaction",
    "OutboundScreenResult",
    "OutboundScreener",
    "create_outbound_screener",
    "passes_luhn",
    "DEFAULT_OUTBOUND_RULES",
]


def passes_luhn(digits: str) -> bool:
    """
    Luhn checksum. Card numbers carry one; arbitrary long digit strings do not.

    Without this check every 16-digit order number, tracking number, and account
    reference in a question gets redacted — precisely the false-positive rate
    that gets a screener switched off.
    """
    if not re.fullmatch(r"\d{13,19}", digits):
        return False

    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


@dataclass(frozen=True)
class OutboundRule:
    """One identifier shape to look for."""

    category: str
    pattern: Pattern[str]
    #: Optional second gate. A pattern describes a shape; a validator can reject
    #: a match with the right shape and the wrong meaning — a 16-digit order
    #: number that is not a card, say. Return False to leave the match in place.
    validate: Optional[Callable[[str], bool]] = None


@dataclass(frozen=True)
class OutboundRedaction:
    category: str
    count: int


@dataclass(frozen=True)
class OutboundScreenResult:
    #: The text with every matched identifier replaced. Safe to send.
    text: str
    #: What was removed, by category. Never contains a matched value.
    redactions: list[OutboundRedaction] = field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return len(self.redactions) > 0


# Built-in rules, in application order.
#
# Order is load-bearing rather than incidental, and is shared verbatim with the
# TypeScript SDK:
#   email       — self-delimiting, cannot be confused with anything else
#   api_key     — distinctive prefixes, no overlap with the numeric rules
#   ssn         — 3-2-4 digits; must precede any looser numeric rule
#   credit_card — 13-19 digits; contains substrings the phone rule would match
#   ip_address  — dotted quads; must precede phone, which accepts "." separators
#   phone       — the loosest numeric rule, so it runs last on what remains
DEFAULT_OUTBOUND_RULES: list[OutboundRule] = [
    OutboundRule(
        category="email",
        pattern=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ),
    OutboundRule(
        category="api_key",
        # Prefixed secrets from the providers an agent is most likely to hold.
        pattern=re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}"
            r"|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"
        ),
    ),
    OutboundRule(
        category="ssn",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    OutboundRule(
        category="credit_card",
        pattern=re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        validate=lambda m: passes_luhn(re.sub(r"[ -]", "", m)),
    ),
    OutboundRule(
        category="ip_address",
        # Octet-bounded, so 999.1.1.1 is not treated as an address. A four-part
        # version string still matches; that false positive is accepted and
        # pinned by a vector rather than left to be rediscovered as a surprise.
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
    OutboundRule(
        category="phone",
        # International first: the domestic pattern would otherwise match the
        # tail of an international number and leave the country code stranded.
        pattern=re.compile(r"\+\d{1,3}[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"),
    ),
    OutboundRule(
        category="phone",
        # A separator is required. A bare run of ten digits is far more often an
        # order or account number than a phone number.
        pattern=re.compile(r"\(?\b\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b"),
    ),
]


def _placeholder(category: str) -> str:
    return f"[REDACTED:{category.upper()}]"


class OutboundScreener:
    def __init__(
        self,
        rules: Optional[list[OutboundRule]] = None,
        extra_rules: Optional[list[OutboundRule]] = None,
    ) -> None:
        """
        :param rules:       replace the built-in rules entirely
        :param extra_rules: applied after the built-ins, in the order given
        """
        if rules is not None:
            self.rules = list(rules)
        else:
            self.rules = [*DEFAULT_OUTBOUND_RULES, *(extra_rules or [])]

    def screen(self, text: str) -> OutboundScreenResult:
        counts: dict[str, int] = {}
        out = text

        for rule in self.rules:
            def _replace(match: re.Match, rule: OutboundRule = rule) -> str:
                value = match.group(0)
                if rule.validate is not None and not rule.validate(value):
                    return value
                counts[rule.category] = counts.get(rule.category, 0) + 1
                return _placeholder(rule.category)

            out = rule.pattern.sub(_replace, out)

        redactions = [
            OutboundRedaction(category=c, count=n) for c, n in sorted(counts.items())
        ]
        return OutboundScreenResult(text=out, redactions=redactions)


def create_outbound_screener(
    rules: Optional[list[OutboundRule]] = None,
    extra_rules: Optional[list[OutboundRule]] = None,
) -> OutboundScreener:
    """Create an OutboundScreener with the default rules."""
    return OutboundScreener(rules=rules, extra_rules=extra_rules)
