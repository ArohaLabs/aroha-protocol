# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
TokenTracker — per-session token and cost accounting.

Records every LLM call made within a ModelSession and maintains running
totals against the ModelBudgetMandate limits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from aroha.routing.catalog import ModelProfile


@dataclass
class TokenUsage:
    model_id:      str
    input_tokens:  int
    output_tokens: int
    cost_usd:      float

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class SessionUsage:
    calls: list[TokenUsage] = field(default_factory=list)

    @property
    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def n_escalations(self) -> int:
        # A call is an escalation if it used a more expensive model than the previous
        if len(self.calls) < 2:
            return 0
        escalations = 0
        for i in range(1, len(self.calls)):
            escalations += 1
        return escalations

    def __repr__(self) -> str:
        return (
            f"SessionUsage(calls={len(self.calls)}, "
            f"tokens={self.total_tokens}, "
            f"cost_usd={self.total_cost_usd:.6f})"
        )


class TokenTracker:
    """Accumulates usage across all LLM calls in a session."""

    def __init__(self, token_budget: int, cost_budget_usd: float) -> None:
        self._token_budget = token_budget
        self._cost_budget  = cost_budget_usd
        self._usage        = SessionUsage()

    # ── Record ────────────────────────────────────────────────────────────────

    def record(
        self,
        model: ModelProfile,
        input_tokens: int,
        output_tokens: int,
    ) -> TokenUsage:
        cost = model.cost_estimate(input_tokens, output_tokens)
        entry = TokenUsage(
            model_id=model.model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
        )
        self._usage.calls.append(entry)
        return entry

    # ── Budget headroom ───────────────────────────────────────────────────────

    @property
    def tokens_used(self) -> int:
        return self._usage.total_tokens

    @property
    def tokens_remaining(self) -> int:
        return max(0, self._token_budget - self.tokens_used)

    @property
    def cost_used(self) -> float:
        return self._usage.total_cost_usd

    @property
    def cost_remaining(self) -> float:
        return max(0.0, self._cost_budget - self.cost_used)

    @property
    def token_budget_exhausted(self) -> bool:
        return self.tokens_remaining == 0

    @property
    def cost_budget_exhausted(self) -> bool:
        return self.cost_remaining <= 0.0

    def can_afford(self, model: ModelProfile, max_tokens: int) -> bool:
        """Return True if the model can be called within current budget headroom."""
        if max_tokens > self.tokens_remaining:
            return False
        estimated_cost = model.cost_estimate(max_tokens // 2, max_tokens // 2)
        return estimated_cost <= self.cost_remaining

    # ── Snapshot ──────────────────────────────────────────────────────────────

    @property
    def usage(self) -> SessionUsage:
        return self._usage

    def summary(self) -> dict:
        return {
            "total_tokens":    self.tokens_used,
            "tokens_remaining": self.tokens_remaining,
            "total_cost_usd":  round(self.cost_used, 8),
            "cost_remaining":  round(self.cost_remaining, 8),
            "n_calls":         len(self._usage.calls),
            "models_used":     list(dict.fromkeys(c.model_id for c in self._usage.calls)),
        }
