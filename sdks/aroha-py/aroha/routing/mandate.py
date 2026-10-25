# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
ModelBudgetMandate — query-side constraints for intelligent model selection.

Distinct from aroha.mandate.SpendingMandate (payment-side). Both can be
held simultaneously: the spending mandate gates *how much* can be paid;
the model budget mandate gates *which model* is selected and *how many
tokens* can be consumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import uuid

from aroha.routing.catalog import TaskType


@dataclass
class ModelBudgetMandate:
    """
    Declares the constraints an agent caller places on model selection.

    The selector, cascade controller, and allocator all read from this object.
    """

    # ── Hard resource caps ────────────────────────────────────────────────────
    token_budget: int
    """Maximum total tokens (input + output) for this session."""

    cost_budget_usd: float
    """Maximum USD spend for this session."""

    # ── Quality & task requirements ───────────────────────────────────────────
    quality_threshold: float
    """
    Minimum acceptable quality in [0, 1].
    The selector only considers models whose benchmark quality (adjusted by
    the online learner) meets or exceeds this threshold.
    """

    task_type: TaskType
    """
    Governs which quality benchmarks are used for model selection and which
    scoring heuristics the QualityScorer applies.
    """

    # ── Model constraints ─────────────────────────────────────────────────────
    context_window_required: int = 4_096
    """Minimum context window the selected model must support."""

    latency_budget_ms: int = 30_000
    """Maximum acceptable end-to-end latency per LLM call."""

    preferred_provider: Optional[str] = None
    """If set, restrict candidates to this provider ('anthropic', 'openai', 'google')."""

    # ── Cascade behaviour ─────────────────────────────────────────────────────
    allow_cascade: bool = True
    """
    Whether the CascadeController may escalate to a more expensive model when
    observed quality falls below quality_threshold.
    """

    max_cascade_steps: int = 2
    """Maximum number of escalation hops (not counting the initial call)."""

    # ── Multi-step allocation ─────────────────────────────────────────────────
    expected_steps: int = 1
    """
    Hint to the BudgetAllocator about how many LLM calls this session will make.
    The allocator uses this to partition the token/cost budget across steps.
    """

    # ── Metadata ─────────────────────────────────────────────────────────────
    mandate_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    registry_mandate_id: Optional[str] = None
    """Links to a registry spending_budgets row for cross-service accounting."""

    # ── Derived helpers ───────────────────────────────────────────────────────
    @property
    def shadow_price(self) -> float:
        """
        λ = quality_threshold / cost_budget_usd

        The KKT shadow price on the quality constraint. Used by the cascade
        controller to decide whether escalation is worth the extra cost:

            escalate iff  ΔQ / ΔCost ≥ λ
        """
        return self.quality_threshold / max(self.cost_budget_usd, 1e-9)

    def remaining(self, tokens_used: int, cost_used: float) -> "ModelBudgetMandate":
        """Return a narrowed mandate reflecting consumed resources."""
        return ModelBudgetMandate(
            token_budget=max(0, self.token_budget - tokens_used),
            cost_budget_usd=max(0.0, self.cost_budget_usd - cost_used),
            quality_threshold=self.quality_threshold,
            task_type=self.task_type,
            context_window_required=self.context_window_required,
            latency_budget_ms=self.latency_budget_ms,
            preferred_provider=self.preferred_provider,
            allow_cascade=self.allow_cascade,
            max_cascade_steps=self.max_cascade_steps,
            expected_steps=max(1, self.expected_steps - 1),
            mandate_id=self.mandate_id,
            registry_mandate_id=self.registry_mandate_id,
        )


class BudgetInfeasibleError(Exception):
    """
    Raised when no model in the catalog satisfies all mandate constraints.

    The `binding_constraint` attribute names the first constraint that
    eliminated all candidates so callers can give actionable feedback.
    """

    def __init__(self, message: str, binding_constraint: str = "unknown") -> None:
        super().__init__(message)
        self.binding_constraint = binding_constraint
