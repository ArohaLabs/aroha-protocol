# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
OnlineLearner — Problem 6: Bayesian quality curve update.

Models quality Q(model, task_type, complexity) as a Beta distribution:

    Q ~ Beta(α, β)
    Prior: α=2, β=2  (weakly informative, centred at 0.5, variance 0.05)

After observing quality q ∈ [0, 1]:
    α' = α + q
    β' = β + (1 - q)

    E[Q] = α / (α + β)
    Var[Q] = αβ / ((α+β)² (α+β+1))

Complexity is discretised into N_BUCKETS buckets so the Beta posterior
is separately maintained per complexity level. New (model, task_type)
combinations fall back to the catalog benchmark.

Thread safety: updates are protected by a threading.Lock. Each session
can share a single learner instance across requests.
"""

from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aroha.routing.catalog import ModelProfile, TaskType, get_model

N_BUCKETS = 10  # complexity [0,1] → bucket 0..9


@dataclass
class QualityEstimate:
    mean: float        # E[Q] = α/(α+β)
    uncertainty: float # Var[Q]
    n_observations: int
    from_prior: bool   # True if no real data yet (catalog benchmark used)


class OnlineLearner:
    """
    Maintains per-(model_id, task_type, complexity_bucket) Beta posteriors.
    Serialisable to/from JSON for persistence across process restarts.
    """

    def __init__(self, catalog: Optional[list[ModelProfile]] = None) -> None:
        # key: (model_id, task_type_value, bucket) → (alpha, beta)
        self._params: dict[tuple, tuple[float, float]] = {}
        self._catalog = {m.model_id: m for m in (catalog or [])}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def update(
        self,
        model_id: str,
        task_type: TaskType,
        complexity: float,
        quality: float,
    ) -> None:
        """
        Record one observation and update the Beta posterior for
        (model_id, task_type, complexity_bucket).
        """
        quality = max(0.0, min(1.0, quality))
        key = self._key(model_id, task_type, complexity)
        with self._lock:
            alpha, beta = self._params.get(key, self._prior(model_id, task_type))
            self._params[key] = (alpha + quality, beta + (1.0 - quality))

    def get(
        self,
        model_id: str,
        task_type: TaskType,
        complexity: float,
    ) -> QualityEstimate:
        """
        Return the current quality estimate for this (model, task, complexity).
        Falls back to catalog benchmark if no observations exist yet.
        """
        key = self._key(model_id, task_type, complexity)
        with self._lock:
            params = self._params.get(key)

        if params is None:
            fallback = self._catalog_benchmark(model_id, task_type)
            # Encode the catalog value as a weak Beta prior centred at that value
            alpha = fallback * 10
            beta  = (1.0 - fallback) * 10
            return QualityEstimate(
                mean=fallback,
                uncertainty=self._var(alpha, beta),
                n_observations=0,
                from_prior=True,
            )

        alpha, beta = params
        n = alpha + beta
        return QualityEstimate(
            mean=alpha / n,
            uncertainty=self._var(alpha, beta),
            n_observations=max(0, round(n - 4)),  # subtract the prior
            from_prior=False,
        )

    def get_mean(
        self,
        model_id: str,
        task_type: TaskType,
        complexity: float,
    ) -> float:
        return self.get(model_id, task_type, complexity).mean

    # ── Conservative estimate (mean - 1σ) ────────────────────────────────────

    def lower_confidence_bound(
        self,
        model_id: str,
        task_type: TaskType,
        complexity: float,
        z: float = 1.0,
    ) -> float:
        """
        Return mean - z*σ. The selector uses this (z=1) to conservatively
        gate model eligibility when uncertainty is high (few observations).
        """
        est = self.get(model_id, task_type, complexity)
        sigma = math.sqrt(max(0, est.uncertainty))
        return max(0.0, est.mean - z * sigma)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Path | str) -> None:
        """Persist current posteriors to a JSON file."""
        data = {
            json.dumps(list(k)): list(v)
            for k, v in self._params.items()
        }
        Path(path).write_text(json.dumps(data, indent=2))

    def load(self, path: Path | str) -> None:
        """Load posteriors from a JSON file written by save()."""
        raw = json.loads(Path(path).read_text())
        with self._lock:
            self._params = {
                tuple(json.loads(k)): tuple(v)
                for k, v in raw.items()
            }

    def load_from_priors(self, priors: list) -> int:
        """
        Warm the learner from registry-aggregated Beta(α,β) parameters.

        `priors` is a list of RegistryPrior dataclasses (or any objects with
        model_id, task_type, complexity_bucket, alpha, beta attributes).

        Only updates keys where the registry has *more* observations than our
        current local posterior, so local learning always wins over stale data.
        Returns the number of keys updated.
        """
        updated = 0
        with self._lock:
            for p in priors:
                task_val = p.task_type if isinstance(p.task_type, str) else p.task_type.value
                key = (p.model_id, task_val, p.complexity_bucket)
                local = self._params.get(key)
                if local is None:
                    # No local data yet — use registry prior directly
                    self._params[key] = (p.alpha, p.beta)
                    updated += 1
                else:
                    local_n    = local[0] + local[1]
                    registry_n = p.alpha + p.beta
                    if registry_n > local_n:
                        # Registry has seen more — blend: weight by observation count
                        w_local    = local_n / (local_n + registry_n)
                        w_registry = 1.0 - w_local
                        self._params[key] = (
                            w_local * local[0] + w_registry * p.alpha,
                            w_local * local[1] + w_registry * p.beta,
                        )
                        updated += 1
        return updated

    def auto_save(self, path: Path | str) -> None:
        """Save only if path is set. No-op when path is None. Used by ModelSession."""
        if path:
            try:
                self.save(path)
            except Exception:
                pass  # never crash a chat() call due to disk write

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _bucket(complexity: float) -> int:
        return min(N_BUCKETS - 1, int(complexity * N_BUCKETS))

    def _key(self, model_id: str, task_type: TaskType, complexity: float) -> tuple:
        return (model_id, task_type.value, self._bucket(complexity))

    def _prior(self, model_id: str, task_type: TaskType) -> tuple[float, float]:
        # Encode catalog benchmark as weak Beta(α, β) with total pseudo-count = 4
        q = self._catalog_benchmark(model_id, task_type)
        return (q * 4, (1.0 - q) * 4)

    def _catalog_benchmark(self, model_id: str, task_type: TaskType) -> float:
        profile = self._catalog.get(model_id) or get_model(model_id)
        if profile:
            return profile.quality_for(task_type)
        return 0.50  # unknown model → neutral prior

    @staticmethod
    def _var(alpha: float, beta: float) -> float:
        n = alpha + beta
        return (alpha * beta) / (n * n * (n + 1))
