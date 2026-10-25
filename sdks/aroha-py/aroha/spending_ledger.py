# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Running totals for spending under a mandate — port of the parts of
packages/aroha-credentials/src/spending-ledger.ts that verify_http_spend_request
uses.

A ledger keeps, per key, a limit and the amount allocated against it. Keys
are ``mandate_redemption_key(mandate)`` (``grantor#mandateId``). Amounts are
integer micro-USD, so adding 0.1 ten times is exactly 1.

``InMemorySpendingLedger`` is per process and empty again after a restart
(everything already spent can be spent again). Use it for one process and
for tests. A server with several processes, or one that restarts, needs a
shared durable ledger implementing the same four methods with an atomic
``allocate`` (a conditional UPDATE, a Redis script): see
``aroha.stores.postgres`` and ``aroha.stores.redis``.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Optional, Protocol

from aroha.mandate import spend_amount_micros

__all__ = [
    "BudgetExhaustedError",
    "BudgetStatus",
    "SpendingLedger",
    "InMemorySpendingLedger",
]

_MAX_SAFE_INTEGER = 2**53 - 1


class BudgetExhaustedError(Exception):
    """``allocate`` would take the total past the limit (or the key is unknown)."""

    code = "BUDGET_EXHAUSTED"

    def __init__(self, key: str, requested_usd: float, remaining_usd: float) -> None:
        super().__init__(f"Budget exhausted for {key}: requested ${requested_usd}, only ${remaining_usd} remaining")
        self.key = key
        self.requested_usd = requested_usd
        self.remaining_usd = remaining_usd


@dataclass
class BudgetStatus:
    key: str
    limit_usd: float
    allocated_usd: float
    remaining_usd: float
    allocation_count: int


class SpendingLedger(Protocol):
    """What verify_http_spend_request needs from a ledger (same contract as the TypeScript ISpendingLedger)."""

    def init(self, key: str, limit_usd: float) -> None:
        """Register ``key`` with ``limit_usd``. Idempotent: later calls for a known key change nothing."""

    def allocate(self, key: str, amount_usd: float) -> str:
        """ATOMICALLY add ``amount_usd`` if the total stays within the limit; return an allocation id.
        Raise BudgetExhaustedError otherwise (and for an unknown key)."""

    def release(self, key: str, allocation_id: str) -> None:
        """Return an allocation. Unknown or already-released ids are a no-op."""

    def status(self, key: str) -> Optional[BudgetStatus]:
        """Current state of ``key``, or None when not registered."""


def _micros(name: str, usd: float) -> int:
    if isinstance(usd, bool) or not isinstance(usd, (int, float)) or usd != usd or usd < 0 or usd == float("inf"):
        raise ValueError(f"{name} must be a finite, non-negative number of USD (got {usd!r})")
    m = spend_amount_micros(usd)
    if m > _MAX_SAFE_INTEGER:
        raise ValueError(f"{name} is too large to account for exactly (got {usd!r})")
    return m


class InMemorySpendingLedger:
    """Thread-safe, per-process ledger. Every check-and-add happens under one lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> [limit_micros, allocated_micros, {allocation_id: micros}]
        self._budgets: dict[str, tuple[int, list[int], dict[str, int]]] = {}

    def init(self, key: str, limit_usd: float) -> None:
        limit = _micros("limit_usd", limit_usd)
        with self._lock:
            if key not in self._budgets:
                self._budgets[key] = (limit, [0], {})

    def allocate(self, key: str, amount_usd: float) -> str:
        amount = _micros("amount_usd", amount_usd)
        with self._lock:
            b = self._budgets.get(key)
            if b is None:
                raise BudgetExhaustedError(key, amount_usd, 0)
            limit, allocated, allocations = b
            if allocated[0] + amount > limit:
                raise BudgetExhaustedError(key, amount_usd, (limit - allocated[0]) / 1_000_000)
            allocated[0] += amount
            allocation_id = str(uuid.uuid4())
            allocations[allocation_id] = amount
            return allocation_id

    def release(self, key: str, allocation_id: str) -> None:
        with self._lock:
            b = self._budgets.get(key)
            if b is None:
                return
            _, allocated, allocations = b
            amount = allocations.pop(allocation_id, None)
            if amount is not None:
                allocated[0] = max(0, allocated[0] - amount)

    def status(self, key: str) -> Optional[BudgetStatus]:
        with self._lock:
            b = self._budgets.get(key)
            if b is None:
                return None
            limit, allocated, allocations = b
            return BudgetStatus(key, limit / 1_000_000, allocated[0] / 1_000_000,
                                (limit - allocated[0]) / 1_000_000, len(allocations))
