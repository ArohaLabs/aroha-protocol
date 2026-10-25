# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
CascadeController — Problem 3: KKT-optimal escalation.

Implements the FrugalGPT-style cascade with a principled escalation rule
derived from the KKT conditions of the constrained quality-cost optimisation:

    maximize   Q(model)
    subject to cost(model) ≤ budget

The Lagrangian is:
    L = Q - λ·(cost - budget)

At the optimum, ∂L/∂model = 0  ⟹  ∂Q/∂cost = λ

So: escalate iff the expected marginal quality gain per marginal dollar
    exceeds the shadow price λ, AND the budget can absorb the cost delta.

The shadow price λ is derived from the mandate:
    λ = quality_threshold / cost_budget_usd

This encodes the user's quality-cost preference: a high quality threshold
with a tight budget → high λ → escalation only when gain is very large.

Algorithm per call:
  1. Call initial model (chosen by ModelSelector)
  2. Score response quality with QualityScorer
  3. If quality ≥ threshold → return (success)
  4. Find next model tier in ranked feasible set
  5. Compute ΔQ_expected = E[Q_next] - observed_quality
  6. Compute ΔCost = cost_next - cost_current (already paid)
  7. If ΔQ/ΔCost ≥ λ AND budget_remaining ≥ ΔCost → escalate
  8. Else → return best-effort response
  9. Repeat up to max_cascade_steps times
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from aroha.routing.catalog import ModelProfile
from aroha.routing.mandate import ModelBudgetMandate
from aroha.routing.tracker import TokenTracker

if TYPE_CHECKING:
    from aroha.routing.providers.base import AbstractProvider, ProviderResponse
    from aroha.routing.scorer import QualityScorer
    from aroha.routing.learner import OnlineLearner
    from aroha.routing.selector import ModelSelector

log = logging.getLogger(__name__)


@dataclass
class EscalationStep:
    model_id:       str
    quality:        float
    cost_usd:       float
    input_tokens:   int
    output_tokens:  int
    escalated:      bool   # True if we moved to next tier after this step


@dataclass
class EscalationResult:
    response:       "ProviderResponse"
    quality:        float
    steps:          list[EscalationStep] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens:   int   = 0
    success:        bool  = True    # False = best-effort (quality < threshold)

    @property
    def n_escalations(self) -> int:
        return sum(1 for s in self.steps if s.escalated)


class CascadeController:
    """
    Manages multi-tier escalation within a single prompt.

    Usage:
        cascade = CascadeController(selector, learner, scorer, tracker)
        result  = await cascade.run(initial_model, prompt, mandate, provider, complexity)
    """

    def __init__(
        self,
        selector:   "ModelSelector",
        learner:    "OnlineLearner",
        scorer:     "QualityScorer",
        tracker:    TokenTracker,
    ) -> None:
        self._selector = selector
        self._learner  = learner
        self._scorer   = scorer
        self._tracker  = tracker

    async def run(
        self,
        initial_model: ModelProfile,
        prompt:        str,
        mandate:       ModelBudgetMandate,
        provider:      "AbstractProvider",
        complexity:    float = 0.5,
    ) -> EscalationResult:
        # Build the ranked feasible list once (ascending cost order)
        ranked = self._selector.rank_all(mandate, complexity)
        # Find the index of the initial model so we can walk upward
        model_ids = [m.model_id for m, _, _ in ranked]
        try:
            start_idx = model_ids.index(initial_model.model_id)
        except ValueError:
            start_idx = 0

        current_model = initial_model
        steps:  list[EscalationStep] = []
        cascade_hops = 0
        shadow_price = mandate.shadow_price  # λ = quality_threshold / cost_budget_usd

        while True:
            # ── Call the current model ────────────────────────────────────────
            max_out = min(
                mandate.token_budget // 2,
                self._tracker.tokens_remaining,
            )
            response = await provider.chat(
                model_id=current_model.model_id,
                prompt=prompt,
                max_tokens=max(1, max_out),
            )
            usage = self._tracker.record(
                current_model,
                response.input_tokens,
                response.output_tokens,
            )
            cost_this_call = usage.cost_usd

            # ── Score quality ─────────────────────────────────────────────────
            quality = self._scorer.score(
                response=response.content,
                task_type=mandate.task_type,
                original_input=prompt,
            )

            step_done = quality >= mandate.quality_threshold
            steps.append(EscalationStep(
                model_id=current_model.model_id,
                quality=quality,
                cost_usd=cost_this_call,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                escalated=False,
            ))

            if step_done:
                log.debug(
                    "cascade: quality=%.3f ≥ threshold=%.3f on %s — done",
                    quality, mandate.quality_threshold, current_model.model_id,
                )
                return EscalationResult(
                    response=response,
                    quality=quality,
                    steps=steps,
                    total_cost_usd=self._tracker.cost_used,
                    total_tokens=self._tracker.tokens_used,
                    success=True,
                )

            # ── Escalation decision ───────────────────────────────────────────
            if not mandate.allow_cascade or cascade_hops >= mandate.max_cascade_steps:
                log.debug("cascade: max_cascade_steps reached — returning best-effort")
                return EscalationResult(
                    response=response, quality=quality, steps=steps,
                    total_cost_usd=self._tracker.cost_used,
                    total_tokens=self._tracker.tokens_used,
                    success=False,
                )

            next_model = self._next_tier(ranked, start_idx + len(steps))
            if next_model is None:
                log.debug("cascade: no higher tier available — returning best-effort")
                return EscalationResult(
                    response=response, quality=quality, steps=steps,
                    total_cost_usd=self._tracker.cost_used,
                    total_tokens=self._tracker.tokens_used,
                    success=False,
                )

            # KKT escalation rule: ΔQ / ΔCost ≥ λ
            next_cost     = self._selector._cost(next_model, mandate)
            delta_q_exp   = (
                self._learner.get_mean(next_model.model_id, mandate.task_type, complexity)
                - quality
            )
            delta_cost    = max(next_cost - cost_this_call, 1e-9)
            marginal_gain = delta_q_exp / delta_cost

            budget_ok = self._tracker.cost_remaining >= next_cost
            kkt_ok    = marginal_gain >= shadow_price

            if not budget_ok:
                log.debug(
                    "cascade: budget_remaining=%.6f < next_cost=%.6f — returning best-effort",
                    self._tracker.cost_remaining, next_cost,
                )
                return EscalationResult(
                    response=response, quality=quality, steps=steps,
                    total_cost_usd=self._tracker.cost_used,
                    total_tokens=self._tracker.tokens_used,
                    success=False,
                )

            if not kkt_ok:
                log.debug(
                    "cascade: ΔQ/ΔCost=%.4f < λ=%.4f — escalation not worth it",
                    marginal_gain, shadow_price,
                )
                return EscalationResult(
                    response=response, quality=quality, steps=steps,
                    total_cost_usd=self._tracker.cost_used,
                    total_tokens=self._tracker.tokens_used,
                    success=False,
                )

            log.debug(
                "cascade: escalating %s → %s (ΔQ/ΔCost=%.4f ≥ λ=%.4f)",
                current_model.model_id, next_model.model_id, marginal_gain, shadow_price,
            )
            steps[-1].escalated = True
            current_model = next_model
            cascade_hops += 1

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _next_tier(
        ranked: list[tuple[ModelProfile, float, float]],
        current_idx: int,
    ) -> Optional[ModelProfile]:
        """Return the next model up in the ranked list, or None if at the top."""
        if current_idx + 1 < len(ranked):
            return ranked[current_idx + 1][0]
        return None
