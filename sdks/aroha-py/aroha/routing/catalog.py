# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Model catalog — static profiles for every supported LLM.

Quality benchmarks are derived from published evals (MMLU, HumanEval,
HellaSwag, MBPP, MT-Bench) normalised to [0, 1]. Pricing is in USD per
million tokens as of 2026-Q2; update via the aroha registry GET /v1/models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TaskType(str, Enum):
    REASONING       = "reasoning"
    CODE            = "code"
    EXTRACTION      = "extraction"
    CREATIVE        = "creative"
    CLASSIFICATION  = "classification"
    SUMMARIZATION   = "summarization"


class ModelTier(int, Enum):
    NANO     = 1   # ultra-cheap, simple tasks only
    SMALL    = 2   # cheap, most structured tasks
    MID      = 3   # balanced
    LARGE    = 4   # high quality
    FRONTIER = 5   # state-of-the-art


@dataclass(frozen=True)
class ModelProfile:
    model_id:              str
    provider:              str           # "anthropic" | "openai" | "google"
    tier:                  ModelTier
    input_price_per_mtok:  float         # USD per million input tokens
    output_price_per_mtok: float         # USD per million output tokens
    context_window:        int           # max tokens (input + output)
    avg_latency_ms:        int           # median TTFT + generation latency
    # Quality per task type — float in [0, 1]
    quality: dict[TaskType, float] = field(default_factory=dict)
    active: bool = True

    def cost_estimate(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens  * self.input_price_per_mtok  / 1_000_000
            + output_tokens * self.output_price_per_mtok / 1_000_000
        )

    def quality_for(self, task_type: TaskType) -> float:
        return self.quality.get(task_type, 0.5)


def _profile(
    model_id: str,
    provider: str,
    tier: ModelTier,
    inp: float,
    out: float,
    ctx: int,
    lat: int,
    q: dict[str, float],
) -> ModelProfile:
    return ModelProfile(
        model_id=model_id,
        provider=provider,
        tier=tier,
        input_price_per_mtok=inp,
        output_price_per_mtok=out,
        context_window=ctx,
        avg_latency_ms=lat,
        quality={TaskType(k): v for k, v in q.items()},
    )


# ── Built-in catalog ──────────────────────────────────────────────────────────
# Quality values are normalised from public benchmark suites.
# Task type quality degrades non-linearly with complexity — this is the
# *base* quality at median complexity. The OnlineLearner adjusts per
# (model, task_type, complexity_bucket) from observed outcomes.

BUILTIN_MODELS: list[ModelProfile] = [

    # ── Anthropic ─────────────────────────────────────────────────────────────
    _profile(
        "claude-haiku-4-5", "anthropic", ModelTier.NANO,
        inp=0.80, out=4.00, ctx=200_000, lat=800,
        q={
            "reasoning":      0.72,
            "code":           0.74,
            "extraction":     0.91,
            "creative":       0.71,
            "classification": 0.94,
            "summarization":  0.82,
        },
    ),
    _profile(
        "claude-sonnet-4-6", "anthropic", ModelTier.MID,
        inp=3.00, out=15.00, ctx=200_000, lat=1_800,
        q={
            "reasoning":      0.88,
            "code":           0.91,
            "extraction":     0.95,
            "creative":       0.87,
            "classification": 0.97,
            "summarization":  0.91,
        },
    ),
    _profile(
        "claude-opus-4-8", "anthropic", ModelTier.FRONTIER,
        inp=15.00, out=75.00, ctx=200_000, lat=4_200,
        q={
            "reasoning":      0.96,
            "code":           0.94,
            "extraction":     0.97,
            "creative":       0.94,
            "classification": 0.98,
            "summarization":  0.95,
        },
    ),

    # ── OpenAI ────────────────────────────────────────────────────────────────
    _profile(
        "gpt-4o-mini", "openai", ModelTier.NANO,
        inp=0.15, out=0.60, ctx=128_000, lat=700,
        q={
            "reasoning":      0.74,
            "code":           0.76,
            "extraction":     0.90,
            "creative":       0.72,
            "classification": 0.93,
            "summarization":  0.83,
        },
    ),
    _profile(
        "gpt-4o", "openai", ModelTier.MID,
        inp=2.50, out=10.00, ctx=128_000, lat=2_000,
        q={
            "reasoning":      0.91,
            "code":           0.90,
            "extraction":     0.95,
            "creative":       0.89,
            "classification": 0.97,
            "summarization":  0.92,
        },
    ),
    _profile(
        "o3", "openai", ModelTier.FRONTIER,
        inp=10.00, out=40.00, ctx=200_000, lat=6_000,
        q={
            "reasoning":      0.97,
            "code":           0.96,
            "extraction":     0.97,
            "creative":       0.91,
            "classification": 0.98,
            "summarization":  0.94,
        },
    ),

    # ── Google ────────────────────────────────────────────────────────────────
    _profile(
        "gemini-2.0-flash", "google", ModelTier.NANO,
        inp=0.10, out=0.40, ctx=1_000_000, lat=600,
        q={
            "reasoning":      0.70,
            "code":           0.71,
            "extraction":     0.88,
            "creative":       0.68,
            "classification": 0.92,
            "summarization":  0.80,
        },
    ),
    _profile(
        "gemini-2.0-pro", "google", ModelTier.MID,
        inp=1.25, out=5.00, ctx=2_000_000, lat=2_200,
        q={
            "reasoning":      0.87,
            "code":           0.88,
            "extraction":     0.94,
            "creative":       0.85,
            "classification": 0.96,
            "summarization":  0.90,
        },
    ),
]

_CATALOG_BY_ID: dict[str, ModelProfile] = {m.model_id: m for m in BUILTIN_MODELS}


def get_catalog(
    provider: Optional[str] = None,
    min_tier: ModelTier = ModelTier.NANO,
    active_only: bool = True,
) -> list[ModelProfile]:
    """Return a filtered view of the built-in catalog."""
    return [
        m for m in BUILTIN_MODELS
        if (not active_only or m.active)
        and m.tier >= min_tier
        and (provider is None or m.provider == provider)
    ]


def get_model(model_id: str) -> Optional[ModelProfile]:
    return _CATALOG_BY_ID.get(model_id)
