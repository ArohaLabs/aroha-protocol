# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
ComplexityEstimator — Problem 1.

Estimates task complexity c ∈ [0, 1] from the raw input text before any LLM
call. This drives the initial model tier selection in the ModelSelector.

Architecture:
  Rule-based estimator ships in v1 (zero dependencies, works out of the box).
  The estimate() method returns (complexity, confidence) so callers can treat
  low-confidence estimates conservatively (round up to a safer tier).

  The ML upgrade path is a drop-in: replace _rule_based() with a call to a
  scikit-learn / ONNX model trained on (input_features, observed_quality) pairs
  collected by the OnlineLearner. No interface change needed.

Feature set (v1.2):
  Structural:   token_count, sentence_count, avg_sentence_len, nesting_depth
  Lexical:      lexical_diversity, type_token_ratio, non_ascii_ratio
  Semantic:     reasoning_hits, requirement_count, constraint_chain_len
  Domain:       domain_score (medical/legal/financial/security/scientific)
  Content:      has_math, has_code, code_complexity, list_density
  Discourse:    question_count, hedging_score, negation_count
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Optional

from aroha.routing.catalog import TaskType


@dataclass
class ComplexityEstimate:
    score: float          # [0.0, 1.0] — 0 = trivial, 1 = maximally complex
    confidence: float     # [0.0, 1.0] — certainty of the estimate
    features: dict        # raw feature values (useful for debugging / training data)


# ── Structural patterns ────────────────────────────────────────────────────────

_SENTENCES  = re.compile(r"[.!?]+")
_LIST_ITEM  = re.compile(r"^\s*[-*•]\s+|\d+\.\s+", re.MULTILINE)
_CODE_FENCE = re.compile(r"```[\s\S]*?```", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`]+`")
_HEADING    = re.compile(r"^#{1,6}\s", re.MULTILINE)

# ── Reasoning / constraint patterns ───────────────────────────────────────────

_REASONING_SIGNALS = re.compile(
    r"\b(step[- ]by[- ]step|chain of thought|reason(?:ing)? through|analy[sz]e|"
    r"compare and contrast|pros and cons|trade[- ]off|implication|evaluate|"
    r"assess|critique|justify|synthesize|infer|deduce|therefore|consequently|"
    r"because|given that|it follows|in contrast|on the other hand)\b",
    re.IGNORECASE,
)

_REQUIREMENT_SIGNALS = re.compile(
    r"\b(must|shall|should|need to|require[sd]?|ensure|guarantee|"
    r"constraint|condition|rule|policy|enforce|strict|mandatory|forbidden|"
    r"not allowed|prohibited|only if|unless|provided that)\b",
    re.IGNORECASE,
)

_HEDGING_SIGNALS = re.compile(
    r"\b(might|may|could|perhaps|possibly|probably|likely|uncertain|"
    r"not sure|unclear|ambiguous|depends|it varies|in some cases|"
    r"generally|typically|often|sometimes|rarely)\b",
    re.IGNORECASE,
)

_NEGATION_SIGNALS = re.compile(
    r"\b(not|never|no\b|neither|nor|without|except|unless|but not|"
    r"other than|rather than|instead of|avoid|prevent|don't|doesn't|"
    r"isn't|aren't|won't|can't|couldn't|shouldn't)\b",
    re.IGNORECASE,
)

# ── Math detection ─────────────────────────────────────────────────────────────

_MATH_EXPR = re.compile(
    r"\d+\s*[\+\-\*/\^=<>≤≥]\s*\d+"
    r"|\b(integral|derivative|gradient|matrix|eigenvalue|polynomial|"
    r"theorem|proof|lemma|equation|formula|calculus|algebra|"
    r"probability|statistics|variance|regression)\b",
    re.IGNORECASE,
)

# ── Code complexity proxies ────────────────────────────────────────────────────

_CODE_KEYWORDS = re.compile(
    r"\b(def |class |import |from |async |await |return |yield |"
    r"for |while |if |else |elif |try |except |with |lambda |"
    r"function |const |let |var |=>|interface |struct |impl |pub )\b",
)
_CODE_CONTROL_FLOW = re.compile(
    r"\b(for|while|if|else|elif|switch|case|try|except|catch|finally)\b",
    re.IGNORECASE,
)

# ── Domain signals (specialised knowledge = harder) ───────────────────────────

_DOMAIN_PATTERNS: dict[str, re.Pattern] = {
    "medical": re.compile(
        r"\b(diagnosis|symptom|treatment|medication|dosage|clinical|"
        r"patient|prognosis|pathology|pharmaceutical|contraindication|"
        r"etiology|therapeutic|chronic|acute|comorbidity)\b",
        re.IGNORECASE,
    ),
    "legal": re.compile(
        r"\b(liability|jurisdiction|statute|regulation|compliance|"
        r"contract|plaintiff|defendant|tort|fiduciary|indemnify|"
        r"injunction|precedent|litigation|arbitration|breach)\b",
        re.IGNORECASE,
    ),
    "financial": re.compile(
        r"\b(portfolio|arbitrage|derivative|hedge|liquidity|volatility|"
        r"amortization|EBITDA|yield|coupon|tranche|collateral|"
        r"depreciation|leverage|equity|dividend|capital gains)\b",
        re.IGNORECASE,
    ),
    "security": re.compile(
        r"\b(vulnerability|exploit|CVE|CVSS|penetration|attack surface|"
        r"privilege escalation|injection|XSS|CSRF|authentication|"
        r"cryptography|cipher|zero-day|threat model|hardening)\b",
        re.IGNORECASE,
    ),
    "scientific": re.compile(
        r"\b(hypothesis|methodology|empirical|peer[- ]review|"
        r"statistical significance|p[- ]value|confidence interval|"
        r"meta[- ]analysis|cohort|control group|reproducibility|"
        r"falsifiable|experiment|correlation|causation)\b",
        re.IGNORECASE,
    ),
}


class ComplexityEstimator:
    """
    Multi-feature complexity estimator.

    Scoring is a weighted sum across 5 feature groups, each normalised to [0,1]:
      structural (25%) + semantic (25%) + domain (20%) + content (20%) + discourse (10%)

    Task-type multipliers applied after summing adjust for inherent difficulty
    differences across task categories.
    """

    def __init__(self, task_type_weights: Optional[dict[TaskType, dict[str, float]]] = None):
        self._weights = task_type_weights or {}

    def estimate(self, text: str, task_type: TaskType) -> ComplexityEstimate:
        features   = self._extract(text)
        score      = self._score(features, task_type)
        confidence = self._confidence(features)
        return ComplexityEstimate(
            score=max(0.0, min(1.0, score)),
            confidence=confidence,
            features=features,
        )

    # ── Feature extraction ─────────────────────────────────────────────────────

    def _extract(self, text: str) -> dict:
        chars = len(text)
        token_count = chars / 4  # rough tiktoken approximation

        # ── Structural ────────────────────────────────────────────────────────
        sentences      = [s for s in _SENTENCES.split(text) if s.strip()]
        sentence_count = max(1, len(sentences))
        avg_sentence_len = token_count / sentence_count

        # Nesting depth: how deep the structural hierarchy goes
        # (indentation levels, heading hierarchy, nested lists)
        lines = text.splitlines()
        indent_levels = [len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()]
        nesting_depth = max(indent_levels, default=0) / 4  # normalize by 4-space indent

        heading_count = len(_HEADING.findall(text))

        # ── Lexical ───────────────────────────────────────────────────────────
        words         = text.split()
        word_count    = max(1, len(words))
        unique_words  = len({w.lower().strip(".,!?;:\"'") for w in words})
        type_token_ratio = unique_words / word_count  # TTR: 0=repetitive, 1=diverse

        # Non-ASCII ratio: proxy for multilingual or symbolic content
        non_ascii = sum(1 for ch in text if ord(ch) > 127)
        non_ascii_ratio = non_ascii / max(1, chars)

        # ── Semantic ──────────────────────────────────────────────────────────
        reasoning_hits    = len(_REASONING_SIGNALS.findall(text))
        requirement_count = len(_REQUIREMENT_SIGNALS.findall(text))

        # Constraint chain: adjacent requirement words suggest cascading rules
        req_positions   = [m.start() for m in _REQUIREMENT_SIGNALS.finditer(text)]
        constraint_chain_len = 0
        if len(req_positions) >= 2:
            gap_threshold = 200  # chars
            chain_len, max_chain = 1, 1
            for i in range(1, len(req_positions)):
                if req_positions[i] - req_positions[i-1] < gap_threshold:
                    chain_len += 1
                    max_chain  = max(max_chain, chain_len)
                else:
                    chain_len = 1
            constraint_chain_len = max_chain

        # ── Domain ────────────────────────────────────────────────────────────
        domain_hits: dict[str, int] = {}
        for domain, pattern in _DOMAIN_PATTERNS.items():
            hits = len(pattern.findall(text))
            if hits > 0:
                domain_hits[domain] = hits
        domain_score = min(1.0, sum(domain_hits.values()) / 8)

        # ── Content ───────────────────────────────────────────────────────────
        has_math     = bool(_MATH_EXPR.search(text))
        code_fences  = _CODE_FENCE.findall(text)
        has_code     = bool(code_fences) or bool(_CODE_KEYWORDS.search(text))
        list_items   = len(_LIST_ITEM.findall(text))

        # Code complexity: count unique control-flow keywords in all code blocks
        code_text     = "\n".join(code_fences) if code_fences else ""
        code_control  = len(_CODE_CONTROL_FLOW.findall(code_text)) if code_text else 0
        code_complexity = min(1.0, code_control / 10)

        # ── Discourse ─────────────────────────────────────────────────────────
        question_count = text.count("?")
        hedging_score  = min(1.0, len(_HEDGING_SIGNALS.findall(text)) / 6)
        negation_count = len(_NEGATION_SIGNALS.findall(text))

        return {
            # structural
            "token_count":          token_count,
            "sentence_count":       sentence_count,
            "avg_sentence_len":     avg_sentence_len,
            "nesting_depth":        nesting_depth,
            "heading_count":        heading_count,
            # lexical
            "type_token_ratio":     type_token_ratio,
            "non_ascii_ratio":      non_ascii_ratio,
            # semantic
            "reasoning_hits":       reasoning_hits,
            "requirement_count":    requirement_count,
            "constraint_chain_len": constraint_chain_len,
            # domain
            "domain_score":         domain_score,
            "domain_hits":          domain_hits,
            # content
            "has_math":             has_math,
            "has_code":             has_code,
            "code_complexity":      code_complexity,
            "list_items":           list_items,
            # discourse
            "question_count":       question_count,
            "hedging_score":        hedging_score,
            "negation_count":       negation_count,
        }

    # ── Scoring ────────────────────────────────────────────────────────────────

    def _score(self, f: dict, task_type: TaskType) -> float:
        score = 0.0

        # ── Structural group (25%) ────────────────────────────────────────────
        token_norm       = math.log1p(f["token_count"]) / math.log1p(32_000)
        sentence_len_norm = min(1.0, f["avg_sentence_len"] / 50)
        nesting_norm     = min(1.0, f["nesting_depth"] / 8)
        structural = (
            0.50 * min(1.0, token_norm)
            + 0.30 * sentence_len_norm
            + 0.20 * nesting_norm
        )
        score += 0.25 * structural

        # ── Semantic group (25%) ──────────────────────────────────────────────
        reasoning_norm  = min(1.0, f["reasoning_hits"] / 6)
        req_norm        = min(1.0, f["requirement_count"] / 8)
        chain_norm      = min(1.0, f["constraint_chain_len"] / 5)
        semantic = (
            0.45 * reasoning_norm
            + 0.35 * req_norm
            + 0.20 * chain_norm
        )
        score += 0.25 * semantic

        # ── Domain group (20%) ────────────────────────────────────────────────
        score += 0.20 * f["domain_score"]

        # ── Content group (20%) ───────────────────────────────────────────────
        math_contrib  = 0.15 if f["has_math"] else 0.0
        code_contrib  = (0.10 + 0.10 * f["code_complexity"]) if f["has_code"] else 0.0
        list_norm     = min(1.0, f["list_items"] / 10)
        content = min(1.0, math_contrib + code_contrib + 0.05 * list_norm)
        score += 0.20 * content

        # ── Discourse group (10%) ─────────────────────────────────────────────
        neg_norm       = min(1.0, f["negation_count"] / 8)
        question_norm  = min(1.0, f["question_count"] / 5)
        discourse = (
            0.40 * f["hedging_score"]
            + 0.35 * neg_norm
            + 0.25 * question_norm
        )
        score += 0.10 * discourse

        # Lexical diversity bonus: high TTR on short texts = specialist vocabulary
        if f["token_count"] < 500 and f["type_token_ratio"] > 0.7:
            score += 0.03

        # Non-ASCII bonus: multilingual / symbolic input is harder
        if f["non_ascii_ratio"] > 0.05:
            score += 0.04

        # ── Task-type multipliers ─────────────────────────────────────────────
        multipliers = {
            TaskType.CLASSIFICATION: 0.60,   # inherently simpler
            TaskType.EXTRACTION:     0.75,    # benefits from size, not reasoning
            TaskType.SUMMARIZATION:  0.85,
            TaskType.CREATIVE:       1.10,    # open-ended = harder to evaluate
            TaskType.CODE:           1.10,    # code generation needs precision
            TaskType.REASONING:      1.20,    # multi-hop = hardest
        }
        score *= multipliers.get(task_type, 1.0)

        return score

    def _confidence(self, f: dict) -> float:
        # Count how many distinct signal types are present
        signals = sum([
            f["reasoning_hits"] > 0,
            f["requirement_count"] > 0,
            f["has_math"],
            f["has_code"],
            f["token_count"] > 300,
            f["list_items"] > 2,
            f["domain_score"] > 0.1,
            f["hedging_score"] > 0.1,
            f["non_ascii_ratio"] > 0.02,
        ])
        # 0 signals → 0.35 confidence, 6+ signals → 0.95
        return min(0.95, 0.35 + signals * 0.08)
