# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
ModelSession — unified entry point tying all routing algorithms together.

Single-turn usage:
    session = ModelSession.create(provider, mandate)
    response = await session.chat("refactor this function to be async...")
    print(session.tracker.summary())

With registry feedback loop (recommended for production):
    session = ModelSession.create(
        provider=provider,
        mandate=mandate,
        registry_url=AROHA_MANAGED_REGISTRY_URL,  # from aroha.endpoints
        registry_api_key="ak_...",
        learner_path="/var/cache/aroha/learner.json",  # persists across restarts
        feedback_flush_every=10,
    )

Multi-step usage (budget allocated across steps):
    session = ModelSession.create(provider, mandate, allocator_mode=AllocatorMode.THOMPSON)
    async with session.step("retrieval") as step_mandate:
        r1 = await session.chat("fetch context for...", step_mandate=step_mandate)
    async with session.step("synthesis") as step_mandate:
        r2 = await session.chat("summarise the above...", step_mandate=step_mandate)

The session is NOT thread-safe for concurrent .chat() calls. For parallel
multi-step workloads, create one session per concurrent branch.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Optional

from aroha.routing.allocator import BudgetAllocator, AllocatorMode, StepBudget
from aroha.routing.cascade import CascadeController, EscalationResult
from aroha.routing.catalog import BUILTIN_MODELS
from aroha.routing.complexity import ComplexityEstimator
from aroha.routing.feedback import FeedbackSignal, RegistryFeedbackClient
from aroha.routing.learner import OnlineLearner
from aroha.routing.mandate import ModelBudgetMandate
from aroha.routing.providers.base import AbstractProvider
from aroha.routing.scorer import QualityScorer, ScorerMode
from aroha.routing.selector import ModelSelector
from aroha.routing.tracker import TokenTracker

log = logging.getLogger(__name__)


@dataclass
class ModelResponse:
    content:        str
    model_id:       str
    quality:        float
    input_tokens:   int
    output_tokens:  int
    cost_usd:       float
    n_escalations:  int
    success:        bool   # False = quality < threshold (best-effort)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class ModelSession:
    """
    Orchestrates complexity estimation → model selection → cascade → tracking
    → online learning → registry feedback for a single logical task session.

    Shared resources (learner, catalog) can be passed in for cross-session
    learning; if omitted, a fresh instance is created per session.
    """

    def __init__(
        self,
        provider:             AbstractProvider,
        mandate:              ModelBudgetMandate,
        learner:              Optional[OnlineLearner]          = None,
        allocator_mode:       AllocatorMode                   = AllocatorMode.PROPORTIONAL,
        scorer_mode:          ScorerMode                      = ScorerMode.AUTO,
        feedback_client:      Optional[RegistryFeedbackClient] = None,
        learner_path:         Optional[str]                   = None,
    ) -> None:
        self._provider      = provider
        self._mandate       = mandate
        self._learner       = learner or OnlineLearner(catalog=BUILTIN_MODELS)
        self._scorer        = QualityScorer()
        self._scorer_mode   = scorer_mode
        self._complexity    = ComplexityEstimator()
        self._selector      = ModelSelector(learner=self._learner)
        self._tracker       = TokenTracker(
            token_budget=mandate.token_budget,
            cost_budget_usd=mandate.cost_budget_usd,
        )
        self._allocator     = BudgetAllocator(mode=allocator_mode)
        self._cascade       = CascadeController(
            selector=self._selector,
            learner=self._learner,
            scorer=self._scorer,
            tracker=self._tracker,
        )
        self._feedback      = feedback_client
        self._learner_path  = learner_path

        # Load persisted learner state from disk if available
        if learner_path and Path(learner_path).exists():
            try:
                self._learner.load(learner_path)
                log.debug("Loaded learner state from %s", learner_path)
            except Exception as exc:
                log.warning("Could not load learner state from %s: %s", learner_path, exc)

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        provider:             AbstractProvider,
        mandate:              ModelBudgetMandate,
        learner:              Optional[OnlineLearner]          = None,
        allocator_mode:       AllocatorMode                   = AllocatorMode.PROPORTIONAL,
        scorer_mode:          ScorerMode                      = ScorerMode.AUTO,
        registry_url:         Optional[str]                   = None,
        registry_api_key:     Optional[str]                   = None,
        feedback_flush_every: int                             = 20,
        learner_path:         Optional[str]                   = None,
    ) -> "ModelSession":
        """
        Convenience factory.

        Pass registry_url + registry_api_key to enable the feedback loop:
          - On creation the learner is warmed from registry priors
          - After each chat() call, quality signals are batched and flushed
          - On learner_path, posteriors are persisted across process restarts
        """
        feedback_client: Optional[RegistryFeedbackClient] = None
        if registry_url and registry_api_key:
            feedback_client = RegistryFeedbackClient(
                registry_url=registry_url,
                api_key=registry_api_key,
                flush_every=feedback_flush_every,
            )

        return cls(
            provider=provider,
            mandate=mandate,
            learner=learner,
            allocator_mode=allocator_mode,
            scorer_mode=scorer_mode,
            feedback_client=feedback_client,
            learner_path=learner_path,
        )

    async def warm_from_registry(self) -> int:
        """
        Pull crowd-sourced priors from the registry and merge into the learner.
        Call once after create() for maximum cold-start quality.
        Returns the number of (model, task, bucket) keys updated.
        """
        if not self._feedback:
            return 0
        priors = await self._feedback.load_priors()
        updated = self._learner.load_from_priors(priors)
        log.debug("Warmed learner with %d registry priors", updated)
        return updated

    # ── Core chat ──────────────────────────────────────────────────────────────

    async def chat(
        self,
        prompt:        str,
        step_mandate:  Optional[ModelBudgetMandate] = None,
        system:        str = "",
    ) -> ModelResponse:
        """
        Route and execute a single LLM call within the budget mandate.

        If step_mandate is provided (from a .step() context), it overrides
        the session mandate for resource limits only (quality/task/cascade
        settings are inherited from the session mandate).
        """
        active_mandate = step_mandate or self._mandate

        if self._tracker.token_budget_exhausted or self._tracker.cost_budget_exhausted:
            raise RuntimeError(
                "Session budget exhausted. "
                f"Used {self._tracker.tokens_used}/{self._mandate.token_budget} tokens, "
                f"${self._tracker.cost_used:.6f}/${self._mandate.cost_budget_usd:.6f}."
            )

        # 1. Estimate complexity
        est = self._complexity.estimate(prompt, active_mandate.task_type)
        log.debug("complexity=%.3f (confidence=%.2f)", est.score, est.confidence)

        # 2. Select initial model
        selection = self._selector.select(active_mandate, complexity=est.score)
        log.debug(
            "selected model=%s (cost_est=%.6f, quality_lcb=%.3f, n_feasible=%d)",
            selection.model.model_id, selection.estimated_cost,
            selection.quality_lcb, selection.n_feasible,
        )

        # 3. Execute with cascade
        result: EscalationResult = await self._cascade.run(
            initial_model=selection.model,
            prompt=prompt,
            mandate=active_mandate,
            provider=self._provider,
            complexity=est.score,
        )

        # 4. Update online learner with final observation
        self._learner.update(
            model_id=result.response.model_id,
            task_type=active_mandate.task_type,
            complexity=est.score,
            quality=result.quality,
        )

        # 5. Record allocator outcome if inside a step
        if step_mandate is not None:
            self._allocator.record_outcome(
                step_type=getattr(step_mandate, "_step_type", "default"),
                quality=result.quality,
                cost_usd=result.total_cost_usd,
            )

        # 6. Auto-persist learner to disk
        if self._learner_path:
            self._learner.auto_save(self._learner_path)

        # 7. Buffer feedback signal for registry (fire-and-forget async flush)
        if self._feedback:
            from aroha.routing.learner import N_BUCKETS
            bucket = min(N_BUCKETS - 1, int(est.score * N_BUCKETS))
            signal = FeedbackSignal(
                model_id=result.response.model_id,
                task_type=active_mandate.task_type.value,
                complexity_bucket=bucket,
                quality=result.quality,
                token_count=result.response.input_tokens + result.response.output_tokens,
            )
            import asyncio
            asyncio.ensure_future(self._feedback.record(signal))

        total_usage = self._tracker.usage.calls
        last_call   = total_usage[-1] if total_usage else None

        return ModelResponse(
            content=result.response.content,
            model_id=result.response.model_id,
            quality=result.quality,
            input_tokens=result.response.input_tokens,
            output_tokens=result.response.output_tokens,
            cost_usd=last_call.cost_usd if last_call else 0.0,
            n_escalations=result.n_escalations,
            success=result.success,
        )

    # ── Multi-step context manager ─────────────────────────────────────────────

    @asynccontextmanager
    async def step(
        self,
        step_type:          str,
        importance_weight:  float = 1.0,
        total_weight:       float = 1.0,
    ) -> AsyncIterator[ModelBudgetMandate]:
        """
        Allocate a slice of the remaining budget for one step.

        Usage:
            async with session.step("synthesis", importance_weight=2.0, total_weight=3.0) as m:
                response = await session.chat("summarise...", step_mandate=m)
        """
        budget: StepBudget = self._allocator.allocate(
            step_type=step_type,
            remaining_tokens=self._tracker.tokens_remaining,
            remaining_cost_usd=self._tracker.cost_remaining,
            remaining_steps=self._mandate.expected_steps,
            importance_weight=importance_weight,
            total_weight=total_weight,
        )

        step_mandate = ModelBudgetMandate(
            token_budget=budget.token_budget,
            cost_budget_usd=budget.cost_budget_usd,
            quality_threshold=self._mandate.quality_threshold,
            task_type=self._mandate.task_type,
            context_window_required=self._mandate.context_window_required,
            latency_budget_ms=self._mandate.latency_budget_ms,
            preferred_provider=self._mandate.preferred_provider,
            allow_cascade=self._mandate.allow_cascade,
            max_cascade_steps=self._mandate.max_cascade_steps,
            expected_steps=1,
            mandate_id=self._mandate.mandate_id,
            registry_mandate_id=self._mandate.registry_mandate_id,
        )
        object.__setattr__(step_mandate, "_step_type", step_type)  # type: ignore[call-arg]

        yield step_mandate

    # ── Flush + close ─────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Flush any pending feedback signals and finalize the session."""
        if self._feedback:
            await self._feedback.flush()
        if self._learner_path:
            self._learner.auto_save(self._learner_path)

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def tracker(self) -> TokenTracker:
        return self._tracker

    @property
    def learner(self) -> OnlineLearner:
        return self._learner

    @property
    def mandate(self) -> ModelBudgetMandate:
        return self._mandate
