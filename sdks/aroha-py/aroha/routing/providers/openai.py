# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""OpenAI provider adapter (requires `pip install aroha[openai]`)."""

from __future__ import annotations

from aroha.routing.providers.base import AbstractProvider, ProviderResponse


class OpenAIProvider(AbstractProvider):
    """
    Thin async adapter over the `openai` Python SDK.

    Install:  pip install openai
    Usage:
        provider = OpenAIProvider(api_key="sk-...")
        response = await provider.chat("gpt-4o-mini", "Hello!")
    """

    def __init__(self, api_key: str, base_url: str | None = None, **client_kwargs) -> None:
        try:
            import openai as _openai
        except ImportError as exc:
            raise ImportError(
                "OpenAIProvider requires the 'openai' package. "
                "Install it with: pip install openai"
            ) from exc
        self._client = _openai.AsyncOpenAI(
            api_key=api_key,
            **({"base_url": base_url} if base_url else {}),
            **client_kwargs,
        )

    @property
    def name(self) -> str:
        return "openai"

    async def chat(
        self,
        model_id:    str,
        prompt:      str,
        max_tokens:  int   = 2048,
        system:      str   = "",
        temperature: float = 0.0,
    ) -> ProviderResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = await self._client.chat.completions.create(
            model=model_id,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        choice  = resp.choices[0]
        content = choice.message.content or ""
        usage   = resp.usage
        return ProviderResponse(
            content=content,
            model_id=model_id,
            input_tokens=usage.prompt_tokens     if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            stop_reason=choice.finish_reason or "stop",
        )
