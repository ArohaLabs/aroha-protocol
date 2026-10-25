# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Anthropic provider adapter (requires `pip install aroha[anthropic]`)."""

from __future__ import annotations

from aroha.routing.providers.base import AbstractProvider, ProviderResponse


class AnthropicProvider(AbstractProvider):
    """
    Thin async adapter over the `anthropic` Python SDK.

    Install:  pip install anthropic
    Usage:
        provider = AnthropicProvider(api_key="sk-ant-...")
        response = await provider.chat("claude-haiku-4-5", "Hello!")
    """

    def __init__(self, api_key: str, **client_kwargs) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "AnthropicProvider requires the 'anthropic' package. "
                "Install it with: pip install anthropic"
            ) from exc
        self._client = _anthropic.AsyncAnthropic(api_key=api_key, **client_kwargs)

    @property
    def name(self) -> str:
        return "anthropic"

    async def chat(
        self,
        model_id:    str,
        prompt:      str,
        max_tokens:  int   = 2048,
        system:      str   = "",
        temperature: float = 0.0,
    ) -> ProviderResponse:
        kwargs: dict = dict(
            model=model_id,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )
        if system:
            kwargs["system"] = system

        msg = await self._client.messages.create(**kwargs)
        content = msg.content[0].text if msg.content else ""
        return ProviderResponse(
            content=content,
            model_id=model_id,
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
            stop_reason=msg.stop_reason or "end_turn",
        )
