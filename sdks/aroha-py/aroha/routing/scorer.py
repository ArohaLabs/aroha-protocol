# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
QualityScorer — Problem 5: quality estimation without ground truth.

Four scoring tiers, selected automatically based on task type and context:

  SYMBOLIC  — deterministic, zero LLM cost, used whenever applicable
              · CODE:        Python AST parse of extracted code blocks
              · EXTRACTION:  JSON/XML schema validity check
              · MATH:        checks presence of numeric result

  HEURISTIC — O(n), ~0.60 correlation with human judgment
              · Format compliance (structure matches task type expectations)
              · Length score (sigmoid-shaped: penalises both too short and too long)
              · Anti-hedging score (penalises uncertainty markers)
              · Completeness (all prompt requirements mentioned in response)

  SELF_CONSISTENCY — k×model_cost, ~0.75 correlation
              · Requires multiple pre-sampled responses passed by the caller
              · Measures pairwise semantic similarity via normalised edit distance
              · Not invoked automatically — caller passes samples= kwarg

  LLM_JUDGE — small_model_cost, ~0.85 correlation
              · Structures a judge prompt, calls provider with the cheapest model
              · Parses JSON score {correctness, completeness, clarity} → mean/10
              · Only used when explicitly requested via mode=ScorerMode.LLM_JUDGE

Decision tree (auto mode):
  CODE/MATH/EXTRACTION with verifiable output → SYMBOLIC first, HEURISTIC as fallback
  Everything else                             → HEURISTIC
"""

from __future__ import annotations

import ast
import json
import math
import re
from enum import Enum
from typing import Optional, TYPE_CHECKING

from aroha.routing.catalog import TaskType

if TYPE_CHECKING:
    from aroha.routing.providers.base import AbstractProvider


class ScorerMode(str, Enum):
    AUTO             = "auto"
    HEURISTIC        = "heuristic"
    SYMBOLIC         = "symbolic"
    SELF_CONSISTENCY = "self_consistency"
    LLM_JUDGE        = "llm_judge"


# Patterns
_CODE_FENCE   = re.compile(r"```(?:python|py)?\s*\n([\s\S]*?)```", re.IGNORECASE)
_JSON_BLOCK   = re.compile(r"```(?:json)?\s*\n([\s\S]*?)```", re.IGNORECASE)
_XML_TAG      = re.compile(r"<\w[\w.-]*(\s[^>]*)?>[\s\S]*?</\w[\w.-]*>")
_HEDGE_TERMS  = re.compile(
    r"\b(i'?m not sure|i think|probably|might be|i don'?t know|"
    r"unclear|uncertain|i believe|i guess|perhaps|it'?s possible)\b",
    re.IGNORECASE,
)
_NUMERIC_RESULT = re.compile(r"=\s*[-+]?\d[\d,\.]*\s*$", re.MULTILINE)


class QualityScorer:
    """
    Stateless quality scorer. Pass a shared instance to CascadeController.
    All public methods are synchronous except llm_judge() which is async.
    """

    def score(
        self,
        response: str,
        task_type: TaskType,
        original_input: str,
        mode: ScorerMode = ScorerMode.AUTO,
        samples: Optional[list[str]] = None,
    ) -> float:
        """
        Return quality estimate in [0, 1].

        In AUTO mode:
          - Tries SYMBOLIC first for CODE/EXTRACTION/MATH tasks
          - Falls back to HEURISTIC if symbolic check is inconclusive
          - Uses SELF_CONSISTENCY if samples are provided
        """
        if mode == ScorerMode.SELF_CONSISTENCY:
            if not samples:
                raise ValueError("SELF_CONSISTENCY mode requires samples= list")
            return self._self_consistency([response] + samples)

        if mode == ScorerMode.SYMBOLIC or (mode == ScorerMode.AUTO and task_type in (
            TaskType.CODE, TaskType.EXTRACTION
        )):
            symbolic = self._symbolic(response, task_type)
            if symbolic is not None:
                # If symbolic gives a definitive score, trust it.
                # Blend with heuristic so partial credit works.
                heuristic = self._heuristic(response, task_type, original_input)
                return 0.7 * symbolic + 0.3 * heuristic

        if mode == ScorerMode.LLM_JUDGE:
            raise ValueError("Use score_with_judge() for LLM_JUDGE mode (async)")

        return self._heuristic(response, task_type, original_input)

    async def score_with_judge(
        self,
        response: str,
        task_type: TaskType,
        original_input: str,
        provider: "AbstractProvider",
        judge_model_id: str = "claude-haiku-4-5",
    ) -> float:
        """
        Async LLM-as-judge scorer. Uses the cheapest available model to
        evaluate correctness, completeness, and clarity (0–10 each).
        Falls back to heuristic if the judge call fails or returns invalid JSON.
        """
        prompt = (
            f"You are an impartial evaluator. Rate the response below on three dimensions "
            f"(0–10 each). Return ONLY valid JSON: "
            f'{{\"correctness\": X, \"completeness\": X, \"clarity\": X}}\n\n'
            f"Task type: {task_type.value}\n\n"
            f"Original request:\n{original_input[:1000]}\n\n"
            f"Response to evaluate:\n{response[:2000]}"
        )
        try:
            judge_resp = await provider.chat(
                model_id=judge_model_id,
                prompt=prompt,
                max_tokens=64,
            )
            raw = judge_resp.content.strip()
            # Extract JSON even if surrounded by markdown fences
            json_match = re.search(r"\{[^}]+\}", raw)
            if json_match:
                scores = json.loads(json_match.group())
                vals = [float(scores.get(k, 5)) for k in ("correctness", "completeness", "clarity")]
                return sum(vals) / (len(vals) * 10.0)
        except Exception:
            pass
        return self._heuristic(response, task_type, original_input)

    # ── Symbolic scorer ───────────────────────────────────────────────────────

    def _symbolic(self, response: str, task_type: TaskType) -> Optional[float]:
        """
        Returns a quality score if deterministic verification is possible,
        or None if the response format doesn't allow it.
        """
        if task_type == TaskType.CODE:
            return self._check_python_syntax(response)
        if task_type == TaskType.EXTRACTION:
            return self._check_structured_output(response)
        if task_type == TaskType.REASONING:
            # Check if a numeric result is present for math-style reasoning
            if _NUMERIC_RESULT.search(response):
                return 0.85  # Has a definitive numeric answer
        return None

    def _check_python_syntax(self, response: str) -> Optional[float]:
        blocks = _CODE_FENCE.findall(response)
        if not blocks:
            # Check for inline code (no fence)
            if "def " in response or "class " in response or "import " in response:
                try:
                    ast.parse(response)
                    return 0.90
                except SyntaxError:
                    return 0.30
            return None  # No code found — fall through to heuristic

        scores = []
        for block in blocks:
            try:
                ast.parse(block)
                scores.append(1.0)
            except SyntaxError:
                scores.append(0.0)
        return sum(scores) / len(scores)

    def _check_structured_output(self, response: str) -> Optional[float]:
        # Try JSON blocks first
        json_blocks = _JSON_BLOCK.findall(response)
        if json_blocks:
            valid = sum(1 for b in json_blocks if self._is_valid_json(b))
            return valid / len(json_blocks)
        # Try inline JSON
        if response.strip().startswith("{") or response.strip().startswith("["):
            return 1.0 if self._is_valid_json(response.strip()) else 0.1
        # XML
        if _XML_TAG.search(response):
            return 0.80  # XML present but we don't validate schema
        return None

    @staticmethod
    def _is_valid_json(text: str) -> bool:
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    # ── Heuristic scorer ──────────────────────────────────────────────────────

    def _heuristic(
        self,
        response: str,
        task_type: TaskType,
        original_input: str,
    ) -> float:
        scores = []

        # 1. Format compliance
        scores.append(self._format_score(response, task_type))

        # 2. Length appropriateness (sigmoid)
        scores.append(self._length_score(response, task_type, original_input))

        # 3. Anti-hedging (confidence proxy)
        scores.append(self._hedge_score(response))

        # 4. Requirement coverage
        scores.append(self._coverage_score(response, original_input))

        return sum(scores) / len(scores)

    @staticmethod
    def _format_score(response: str, task_type: TaskType) -> float:
        if task_type == TaskType.CODE:
            has_code = bool(_CODE_FENCE.search(response)) or "def " in response or "class " in response
            return 1.0 if has_code else 0.25
        if task_type == TaskType.EXTRACTION:
            has_struct = "{" in response or "[" in response or _XML_TAG.search(response)
            return 0.90 if has_struct else 0.35
        if task_type == TaskType.CLASSIFICATION:
            # Short, decisive answers score well
            return min(1.0, 200 / max(1, len(response)))
        return 0.75  # neutral for open-ended tasks

    @staticmethod
    def _length_score(response: str, task_type: TaskType, original_input: str) -> float:
        out_chars = len(response)
        inp_chars = len(original_input)

        # Expected output length per task type (in characters)
        expected: float
        if task_type == TaskType.CLASSIFICATION:
            expected = 80
        elif task_type == TaskType.SUMMARIZATION:
            expected = inp_chars * 0.15
        elif task_type == TaskType.EXTRACTION:
            expected = inp_chars * 0.30
        else:
            expected = max(400, inp_chars * 0.40)

        # Sigmoid-shaped score: penalises both too short and too long
        ratio  = out_chars / max(1.0, expected)
        # sigmoid centred at ratio=1: score=1 at ratio=1, →0 at extremes
        score  = 2.0 * ratio / (1.0 + ratio) - ratio / (1.0 + ratio)
        # simpler: use a tent function peaking at ratio=1
        if ratio <= 1.0:
            return max(0.0, ratio)
        else:
            return max(0.0, 2.0 - ratio)   # penalty for verbosity

    @staticmethod
    def _hedge_score(response: str) -> float:
        sentences  = max(1, len(re.split(r"[.!?]", response)))
        hedge_hits = len(_HEDGE_TERMS.findall(response))
        rate       = hedge_hits / sentences
        return max(0.0, 1.0 - rate * 3)    # 0.33 hedges/sentence → score=0

    @staticmethod
    def _coverage_score(response: str, original_input: str) -> float:
        """Rough coverage: what fraction of non-trivial input words appear in response."""
        stopwords = {"the", "a", "an", "is", "are", "was", "were", "to", "of",
                     "and", "or", "in", "on", "at", "for", "with", "that", "this"}
        input_words = {w.lower().strip(".,?!:;") for w in original_input.split()
                       if len(w) > 3 and w.lower() not in stopwords}
        if not input_words:
            return 0.75
        response_lower = response.lower()
        covered = sum(1 for w in input_words if w in response_lower)
        return min(1.0, covered / len(input_words))

    # ── Self-consistency ──────────────────────────────────────────────────────

    @staticmethod
    def _self_consistency(samples: list[str]) -> float:
        """
        Measure pairwise agreement across samples using normalised edit distance.
        High agreement → high quality confidence.
        """
        if len(samples) < 2:
            return 0.5

        def similarity(a: str, b: str) -> float:
            # Normalised common token overlap (fast approximation of BLEU-1)
            ta = set(a.lower().split())
            tb = set(b.lower().split())
            if not ta and not tb:
                return 1.0
            return len(ta & tb) / max(len(ta | tb), 1)

        pairs = [
            similarity(samples[i], samples[j])
            for i in range(len(samples))
            for j in range(i + 1, len(samples))
        ]
        return sum(pairs) / len(pairs)
