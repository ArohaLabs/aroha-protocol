# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Abstract provider interface — all LLM adapters implement this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderResponse:
    content:       str
    model_id:      str
    input_tokens:  int
    output_tokens: int
    stop_reason:   str = "end_turn"

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AbstractProvider(ABC):
    """Minimal async interface that CascadeController and ModelSession use."""

    @abstractmethod
    async def chat(
        self,
        model_id:   str,
        prompt:     str,
        max_tokens: int = 2048,
        system:     str = "",
        temperature: float = 0.0,
    ) -> ProviderResponse:
        """Send a single-turn chat prompt and return the response."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name: 'anthropic' | 'openai' | 'google' | ..."""
        ...
