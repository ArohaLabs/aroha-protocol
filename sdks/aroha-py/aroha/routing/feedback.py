# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
RegistryFeedbackClient — closes the learning loop.

Local OnlineLearner instances are ephemeral; their Beta posteriors vanish on
process exit.  This client:
  • POST /v1/routing/feedback  — uploads batched quality signals to the registry
  • GET  /v1/routing/priors    — downloads crowd-sourced Beta(α,β) params so a
                                  fresh OnlineLearner starts warm, not from scratch

Usage (automatic via ModelSession):
    session = ModelSession.create(
        provider=provider,
        mandate=mandate,
        registry_url=AROHA_MANAGED_REGISTRY_URL,  # from aroha.endpoints
        registry_api_key="ak_...",
        feedback_flush_every=10,   # flush after every 10 chat() calls
    )

Usage (manual):
    client = RegistryFeedbackClient(
        registry_url=AROHA_MANAGED_REGISTRY_URL,  # from aroha.endpoints
        api_key="ak_...",
    )
    await client.flush(signals)
    priors = await client.load_priors()
    learner.load_from_priors(priors)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FeedbackSignal:
    model_id:          str
    task_type:         str
    complexity_bucket: int    # 0–9
    quality:           float  # 0–1
    token_count:       int = 0


@dataclass
class RegistryPrior:
    model_id:          str
    task_type:         str
    complexity_bucket: int
    alpha:             float
    beta:              float
    observations:      int


class RegistryFeedbackClient:
    """
    Async HTTP client for the /v1/routing feedback endpoints.

    Thread-safe buffer that accumulates signals and flushes in batches,
    avoiding a network round-trip on every single LLM call.
    """

    MAX_BATCH = 100
    TIMEOUT   = 10.0  # seconds

    def __init__(
        self,
        registry_url: str,
        api_key: str,
        *,
        flush_every: int = 20,
        max_retries: int = 2,
    ) -> None:
        self._base    = registry_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
        self._flush_every  = flush_every
        self._max_retries  = max_retries
        self._buffer: list[FeedbackSignal] = []
        self._lock = asyncio.Lock()
        self._call_count = 0

    # ── Public API ─────────────────────────────────────────────────────────────

    async def record(self, signal: FeedbackSignal) -> None:
        """Buffer a signal. Flushes automatically every `flush_every` calls."""
        async with self._lock:
            self._buffer.append(signal)
            self._call_count += 1
            should_flush = (
                self._call_count % self._flush_every == 0
                or len(self._buffer) >= self.MAX_BATCH
            )
        if should_flush:
            await self.flush()

    async def flush(self) -> int:
        """Upload all buffered signals. Returns number of signals sent."""
        async with self._lock:
            if not self._buffer:
                return 0
            batch, self._buffer = self._buffer[:self.MAX_BATCH], self._buffer[self.MAX_BATCH:]

        payload = {
            "signals": [
                {
                    "modelId":          s.model_id,
                    "taskType":         s.task_type,
                    "complexityBucket": s.complexity_bucket,
                    "quality":          s.quality,
                    "tokenCount":       s.token_count,
                }
                for s in batch
            ]
        }

        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                    resp = await client.post(
                        f"{self._base}/v1/routing/feedback",
                        json=payload,
                        headers=self._headers,
                    )
                    resp.raise_for_status()
                    return len(batch)
            except Exception as exc:
                if attempt == self._max_retries:
                    logger.warning("RegistryFeedbackClient: flush failed after %d retries: %s", attempt + 1, exc)
                    # Re-buffer the signals so they aren't silently dropped
                    async with self._lock:
                        self._buffer = batch + self._buffer
                    return 0
                await asyncio.sleep(2 ** attempt)  # 1s, 2s backoff

        return 0

    async def load_priors(self, model_id: Optional[str] = None) -> list[RegistryPrior]:
        """
        Fetch aggregated Beta(α,β) parameters from the registry.

        Returns an empty list on failure (callers fall back to built-in priors).
        """
        params = {}
        if model_id:
            params["modelId"] = model_id

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                resp = await client.get(
                    f"{self._base}/v1/routing/priors",
                    params=params,
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("RegistryFeedbackClient: load_priors failed: %s", exc)
            return []

        return [
            RegistryPrior(
                model_id=p["modelId"],
                task_type=p["taskType"],
                complexity_bucket=p["complexityBucket"],
                alpha=p["alpha"],
                beta=p["beta"],
                observations=p["observations"],
            )
            for p in data.get("priors", [])
        ]
