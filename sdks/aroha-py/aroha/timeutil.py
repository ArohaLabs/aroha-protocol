# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Timestamp helpers matching the TypeScript SDK's wire format.

``iso_ms`` produces what JavaScript's ``Date.prototype.toISOString`` does
(``2026-01-01T00:00:00.000Z`` — millisecond precision, ``Z`` suffix), and
``parse_iso_ms`` returns Unix milliseconds like ``Date.parse`` for ISO 8601
input (sub-millisecond digits are truncated, as V8 does).

Known difference from ``Date.parse``: JavaScript also accepts a range of
non-ISO, implementation-defined formats (``"Jan 1 2026"``) and treats a
date-time WITHOUT an offset as local time. Here only ISO 8601 parses, and an
offset-less value is read as UTC. Every timestamp an Aroha SDK emits carries
an explicit ``Z``, so the two agree on all conformant input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Union

__all__ = ["iso_ms", "parse_iso_ms", "to_ms", "now_ms"]

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def iso_ms(dt: Union[datetime, int, float]) -> str:
    """Format a datetime (or Unix ms) as ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    if not isinstance(dt, datetime):
        ms = int(dt)
        dt = datetime.fromtimestamp(ms // 1000, tz=timezone.utc).replace(microsecond=(ms % 1000) * 1000)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def to_ms(dt: datetime) -> int:
    """Unix milliseconds of a datetime (naive = UTC), truncated like JavaScript."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def parse_iso_ms(value: Any) -> Optional[int]:
    """Unix ms for an ISO 8601 string, or None when it does not parse (JavaScript's NaN)."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return to_ms(dt)


def now_ms() -> int:
    return to_ms(datetime.now(timezone.utc))
