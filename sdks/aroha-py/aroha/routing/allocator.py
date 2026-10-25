# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
BudgetAllocator — Problem 4: multi-step budget allocation.

Three modes, selectable per session:

  PROPORTIONAL (default)
      budget_step_i = remaining / remaining_steps
      Simple, online, no history needed. Underperforms on heterogeneous steps.

  IMPORTANCE_WEIGHTED
      budget_step_i = remaining × (w_i / Σ w_j for j ≥ i)
      Caller assigns importance weights per step type. Better when step
      complexity varies predictably (e.g. a final synthesis step is harder
      than intermediate retrieval steps).

  THOMPSON (learned, activates after MIN_OBSERVATIONS per arm)
      Models each step type as a bandit arm with Beta(α, β) posterior over
      quality-per-dollar efficiency. Samples from posterior to decide how
      much extra budget to give each step type.

      Reward signal:   r = quality / cost_usd   (efficiency)
      Normalisation:   reward = min(1, r / EFFICIENCY_SCALE)
      Update:          α += reward,  β += (1 - reward)

      Budget multiplier: 1 + (θ_sampled - 0.5), clipped to [0.5, 1.5]×base
      This gives steps with high historical efficiency up to 50% more budget,
      and penalises low-efficiency steps by up to 50%.

THOMPSON degrades gracefully: until MIN_OBSERVATIONS data points exist for
a step type, it falls back to PROPORTIONAL for that arm.
"""

from __future__ import annotations

import math
import random
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

MIN_OBSERVATIONS = 5     # Thompson activates after this many real data points
EFFICIENCY_SCALE = 500.0 # quality/dollar value treated as "perfect" reward


class AllocatorMode(str, Enum):
    PROPORTIONAL       = "proportional"
    IMPORTANCE_WEIGHTED = "importance_weighted"
    THOMPSON           = "thompson"


@dataclass
class StepBudget:
    token_budget: int
    cost_budget_usd: float
    step_type: str
    mode_used: AllocatorMode


class BudgetAllocator:
    """
    Partitions a session's total token + cost budget across multiple LLM
    calls (steps). Each step is identified by a step_type string (e.g.
    "retrieval", "reasoning", "synthesis") which becomes the bandit arm key.
    """

    def __init__(self, mode: AllocatorMode = AllocatorMode.PROPORTIONAL) -> None:
        self.mode = mode
        # {step_type: (alpha, beta, n_real_observations)}
        self._arms: dict[str, tuple[float, float, int]] = {}
        self._lock = threading.Lock()

    # ── Allocation ────────────────────────────────────────────────────────────

    def allocate(
        self,
        step_type: str,
        remaining_tokens: int,
        remaining_cost_usd: float,
        remaining_steps: int,
        importance_weight: float = 1.0,   # used only in IMPORTANCE_WEIGHTED mode
        total_weight: float = 1.0,        # sum of weights for remaining steps
    ) -> StepBudget:
        """Return the token and cost budget for one step."""
        remaining_steps = max(1, remaining_steps)

        if self.mode == AllocatorMode.PROPORTIONAL:
            return self._proportional(
                step_type, remaining_tokens, remaining_cost_usd, remaining_steps
            )

        if self.mode == AllocatorMode.IMPORTANCE_WEIGHTED:
            return self._importance_weighted(
                step_type, remaining_tokens, remaining_cost_usd,
                importance_weight, total_weight,
            )

        # THOMPSON
        return self._thompson(
            step_type, remaining_tokens, remaining_cost_usd, remaining_steps
        )

    def record_outcome(
        self,
        step_type: str,
        quality: float,
        cost_usd: float,
    ) -> None:
        """
        Feed back the observed quality and cost for a completed step.
        Updates the Beta posterior for that step type's arm.
        """
        efficiency = quality / max(cost_usd, 1e-9)
        reward     = min(1.0, efficiency / EFFICIENCY_SCALE)
        with self._lock:
            alpha, beta, n = self._arms.get(step_type, (1.0, 1.0, 0))
            self._arms[step_type] = (alpha + reward, beta + (1.0 - reward), n + 1)

    # ── Arm diagnostics ───────────────────────────────────────────────────────

    def arm_stats(self) -> dict[str, dict]:
        with self._lock:
            return {
                step_type: {
                    "mean_efficiency": alpha / (alpha + beta),
                    "n_observations":  n,
                    "alpha":           alpha,
                    "beta":            beta,
                }
                for step_type, (alpha, beta, n) in self._arms.items()
            }

    # ── Private modes ─────────────────────────────────────────────────────────

    def _proportional(
        self,
        step_type: str,
        remaining_tokens: int,
        remaining_cost: float,
        remaining_steps: int,
    ) -> StepBudget:
        return StepBudget(
            token_budget    = remaining_tokens  // remaining_steps,
            cost_budget_usd = remaining_cost    /  remaining_steps,
            step_type       = step_type,
            mode_used       = AllocatorMode.PROPORTIONAL,
        )

    def _importance_weighted(
        self,
        step_type: str,
        remaining_tokens: int,
        remaining_cost: float,
        importance_weight: float,
        total_weight: float,
    ) -> StepBudget:
        fraction = importance_weight / max(total_weight, 1e-9)
        return StepBudget(
            token_budget    = int(remaining_tokens * fraction),
            cost_budget_usd = remaining_cost * fraction,
            step_type       = step_type,
            mode_used       = AllocatorMode.IMPORTANCE_WEIGHTED,
        )

    def _thompson(
        self,
        step_type: str,
        remaining_tokens: int,
        remaining_cost: float,
        remaining_steps: int,
    ) -> StepBudget:
        with self._lock:
            alpha, beta, n = self._arms.get(step_type, (1.0, 1.0, 0))

        # Fall back to proportional until we have enough data
        if n < MIN_OBSERVATIONS:
            base_tokens = remaining_tokens  // remaining_steps
            base_cost   = remaining_cost    /  remaining_steps
            return StepBudget(
                token_budget    = base_tokens,
                cost_budget_usd = base_cost,
                step_type       = step_type,
                mode_used       = AllocatorMode.PROPORTIONAL,
            )

        # Sample θ from Beta(α, β)
        theta      = random.betavariate(alpha, beta)
        # Multiplier in [0.5, 1.5] centred at 1.0 when θ=0.5
        multiplier = max(0.5, min(1.5, 1.0 + (theta - 0.5)))

        base_tokens = remaining_tokens  // remaining_steps
        base_cost   = remaining_cost    /  remaining_steps

        return StepBudget(
            token_budget    = min(int(base_tokens * multiplier), remaining_tokens),
            cost_budget_usd = min(base_cost * multiplier,        remaining_cost),
            step_type       = step_type,
            mode_used       = AllocatorMode.THOMPSON,
        )
