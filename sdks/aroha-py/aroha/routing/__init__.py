# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.routing — Token-budget-aware intelligent model selection.

Algorithms implemented:
  catalog    → ModelProfile registry with pricing + quality benchmarks
  complexity → Lightweight task complexity estimator (rule-based → ML-upgradeable)
  selector   → Constrained cost minimisation over feasible model set
  cascade    → KKT-optimal escalation controller (FrugalGPT-style)
  allocator  → Multi-step budget allocator with Thompson sampling
  scorer     → Quality scoring: heuristic / symbolic / LLM-as-judge
  learner    → Bayesian Beta quality curve with online updates
  tracker    → Per-session token + cost accounting
  session    → ModelSession — unified entry point for all of the above
"""

from aroha.routing.catalog import ModelProfile, TaskType, ModelTier, BUILTIN_MODELS, get_catalog
from aroha.routing.mandate import ModelBudgetMandate, BudgetInfeasibleError
from aroha.routing.complexity import ComplexityEstimator
from aroha.routing.selector import ModelSelector
from aroha.routing.cascade import CascadeController, EscalationResult
from aroha.routing.allocator import BudgetAllocator, AllocatorMode, StepBudget
from aroha.routing.scorer import QualityScorer, ScorerMode
from aroha.routing.learner import OnlineLearner
from aroha.routing.tracker import TokenTracker, TokenUsage
from aroha.routing.feedback import RegistryFeedbackClient, FeedbackSignal, RegistryPrior
from aroha.routing.session import ModelSession, ModelResponse

__all__ = [
    "ModelProfile",
    "TaskType",
    "ModelTier",
    "BUILTIN_MODELS",
    "get_catalog",
    "ModelBudgetMandate",
    "BudgetInfeasibleError",
    "ComplexityEstimator",
    "ModelSelector",
    "CascadeController",
    "EscalationResult",
    "BudgetAllocator",
    "AllocatorMode",
    "StepBudget",
    "QualityScorer",
    "ScorerMode",
    "OnlineLearner",
    "TokenTracker",
    "TokenUsage",
    "RegistryFeedbackClient",
    "FeedbackSignal",
    "RegistryPrior",
    "ModelSession",
    "ModelResponse",
]
