# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
ModelSelector — Problem 2: constrained cost minimisation.

Selects the cheapest model in the catalog that satisfies all constraints
declared in the ModelBudgetMandate:

    minimize:    cost(m) = p_in(m)·E[T_in] + p_out(m)·E[T_out]

    subject to:
      Q_lcb(m, task_type, c) ≥ quality_threshold   (quality — uses LCB for safety)
      context_window(m)       ≥ context_window_required
      avg_latency_ms(m)       ≤ latency_budget_ms
      cost_estimate(m)        ≤ cost_budget_usd
      provider(m)             == preferred_provider  (if set)

The quality check uses the OnlineLearner's lower-confidence bound (mean - 1σ)
rather than the raw mean. This makes the selector conservative when data is
scarce: new model/task combinations are held to a higher bar until enough
observations narrow the Beta posterior.

Token budget is split into estimated input / output tokens using the
DEFAULT_INPUT_FRACTION heuristic, which holds well across most task types.
"""

from __future__ import annotations

from dataclasses import dataclass

from aroha.routing.catalog import ModelProfile, TaskType, BUILTIN_MODELS, get_catalog
from aroha.routing.mandate import ModelBudgetMandate, BudgetInfeasibleError
from aroha.routing.learner import OnlineLearner

# Fraction of the token budget assumed to be input tokens.
# Remaining (1 - fraction) is assumed to be output.
DEFAULT_INPUT_FRACTION = 0.60


@dataclass
class SelectionResult:
    model: ModelProfile
    estimated_cost: float
    quality_lcb: float       # lower-confidence-bound quality used for gating
    n_feasible: int          # how many models passed all constraints


class ModelSelector:
    """
    Enumerates the catalog, filters by hard constraints, then picks the
    minimum-cost feasible model.

    Pass a shared OnlineLearner instance so quality estimates improve across
    sessions automatically.
    """

    def __init__(
        self,
        learner: OnlineLearner,
        catalog: list[ModelProfile] | None = None,
    ) -> None:
        self._learner = learner
        self._catalog = catalog or BUILTIN_MODELS

    # ── Public API ────────────────────────────────────────────────────────────

    def select(
        self,
        mandate: ModelBudgetMandate,
        complexity: float = 0.5,
    ) -> SelectionResult:
        """
        Return the cheapest feasible model for the mandate at the given
        task complexity estimate.

        Raises BudgetInfeasibleError (with binding_constraint set) if no
        model satisfies all constraints.
        """
        candidates = list(self._catalog)
        if mandate.preferred_provider:
            candidates = [m for m in candidates if m.provider == mandate.preferred_provider]

        # ── Hard constraint passes (order matters: cheapest filter first) ────
        after_provider  = candidates
        after_ctx       = [m for m in after_provider  if m.context_window   >= mandate.context_window_required]
        after_latency   = [m for m in after_ctx       if m.avg_latency_ms   <= mandate.latency_budget_ms]
        after_budget    = [m for m in after_latency   if self._cost(m, mandate) <= mandate.cost_budget_usd]
        after_tokens    = [m for m in after_budget    if self._total_tokens(mandate) <= mandate.token_budget]
        after_quality   = [
            m for m in after_tokens
            if self._learner.lower_confidence_bound(m.model_id, mandate.task_type, complexity)
               >= mandate.quality_threshold
        ]

        # Identify the binding constraint for a clear error message
        if not after_provider:
            raise BudgetInfeasibleError(
                f"No models available for provider '{mandate.preferred_provider}'.",
                binding_constraint="preferred_provider",
            )
        if not after_ctx:
            raise BudgetInfeasibleError(
                f"No model has context_window ≥ {mandate.context_window_required} tokens.",
                binding_constraint="context_window_required",
            )
        if not after_latency:
            raise BudgetInfeasibleError(
                f"No model meets latency_budget_ms ≤ {mandate.latency_budget_ms} ms.",
                binding_constraint="latency_budget_ms",
            )
        if not after_budget:
            raise BudgetInfeasibleError(
                f"No model fits within cost_budget_usd = ${mandate.cost_budget_usd:.4f}.",
                binding_constraint="cost_budget_usd",
            )
        if not after_tokens:
            raise BudgetInfeasibleError(
                f"token_budget = {mandate.token_budget} is smaller than the cheapest model's minimum.",
                binding_constraint="token_budget",
            )
        if not after_quality:
            raise BudgetInfeasibleError(
                f"No model meets quality_threshold = {mandate.quality_threshold} "
                f"for task_type = {mandate.task_type.value} at complexity = {complexity:.2f}.",
                binding_constraint="quality_threshold",
            )

        # ── Objective: minimise expected cost ─────────────────────────────────
        best = min(after_quality, key=lambda m: self._cost(m, mandate))
        return SelectionResult(
            model=best,
            estimated_cost=self._cost(best, mandate),
            quality_lcb=self._learner.lower_confidence_bound(
                best.model_id, mandate.task_type, complexity
            ),
            n_feasible=len(after_quality),
        )

    def rank_all(
        self,
        mandate: ModelBudgetMandate,
        complexity: float = 0.5,
    ) -> list[tuple[ModelProfile, float, float]]:
        """
        Return all feasible models sorted by cost ascending.
        Each entry is (model, estimated_cost, quality_lcb).
        Useful for the CascadeController to determine escalation targets.
        """
        result = []
        for m in self._catalog:
            if (
                (not mandate.preferred_provider or m.provider == mandate.preferred_provider)
                and m.context_window   >= mandate.context_window_required
                and m.avg_latency_ms   <= mandate.latency_budget_ms
                and self._cost(m, mandate) <= mandate.cost_budget_usd
                and self._total_tokens(mandate) <= mandate.token_budget
            ):
                q_lcb = self._learner.lower_confidence_bound(
                    m.model_id, mandate.task_type, complexity
                )
                result.append((m, self._cost(m, mandate), q_lcb))

        result.sort(key=lambda x: x[1])  # ascending cost
        return result

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _total_tokens(mandate: ModelBudgetMandate) -> int:
        return mandate.token_budget

    @staticmethod
    def _cost(model: ModelProfile, mandate: ModelBudgetMandate) -> float:
        in_tok  = int(mandate.token_budget * DEFAULT_INPUT_FRACTION)
        out_tok = mandate.token_budget - in_tok
        return model.cost_estimate(in_tok, out_tok)
