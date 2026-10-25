# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.bridges.openai_v1 — Wrap an OpenAI client or Agents SDK agent as /v1/run

Usage (plain OpenAI client — OpenAI or AsyncOpenAI):
    from openai import OpenAI
    from aroha.bridges.openai_v1 import from_openai_client

    agent = from_openai_client(
        OpenAI(),
        model="gpt-4o",
        system_prompt="You are a helpful assistant.",
        name="My GPT Agent",
        memory="session",
        expose_mcp=True,
    )
    agent.start(port=8000)

Usage (OpenAI Agents SDK):
    from aroha.bridges.openai_v1 import from_openai_agent
    from agents import Agent
    agent = from_openai_agent(
        Agent(name="assistant", instructions="Be helpful.", model="gpt-4o"),
        name="OpenAI Agents Agent",
    )
    agent.start(port=8000)

Compatibility: tested against openai 2.54 (Chat Completions API, sync and
async clients) and openai-agents 0.20 — ``pip install aroha[openai]`` /
``aroha[openai-agents]``. Any client exposing ``chat.completions.create``
(Azure OpenAI, OpenAI-compatible gateways) works.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable

from aroha.agent import ArohaAgent


def _chat_messages(system_prompt: str, history: list, message: str) -> list[dict[str, str]]:
    msgs = [{"role": "system", "content": system_prompt}] if system_prompt else []
    for t in history or []:
        r = t.get("role", "user")
        if r in ("user", "assistant"):
            msgs.append({"role": r, "content": t.get("content", "")})
    msgs.append({"role": "user", "content": message})
    return msgs


def _is_async_callable(fn: Any) -> bool:
    # openai decorates AsyncCompletions.create with a sync wrapper
    # (required_args), so iscoroutinefunction is False on the bound method
    # and True only on the unwrapped original.
    try:
        return inspect.iscoroutinefunction(inspect.unwrap(fn))
    except Exception:
        return inspect.iscoroutinefunction(fn)


def from_openai_client(
    client,
    *,
    model             = "gpt-4o",
    system_prompt     = "You are a helpful assistant.",
    name              = "OpenAI LLM Agent",
    description       = "",
    memory            = "session",
    auth              = "aroha-sig",
    bearer_tokens     = None,
    verify_bearer     = None,
    expose_mcp        = False,
    content_guard     = None,
    approval_timeout  = 300.0,
):
    """
    Wrap an ``openai.OpenAI`` or ``openai.AsyncOpenAI`` client as an ArohaAgent.

    The previous version tested ``hasattr(client.chat.completions, "create")``
    to pick sync vs async — true for both clients — so an AsyncOpenAI client
    ran in a thread, returned an un-awaited coroutine and failed on
    ``.choices``.
    """
    async def handler(message, session_id, history, context, **kw):
        msgs = _chat_messages(system_prompt, history, message)
        create = client.chat.completions.create
        if _is_async_callable(create):
            resp = await create(model=model, messages=msgs)
        else:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, lambda: create(model=model, messages=msgs))
            if inspect.isawaitable(resp):
                resp = await resp
        return resp.choices[0].message.content or ""

    return ArohaAgent(
        name=name, handler=handler, description=description,
        memory=memory, auth=auth,
        bearer_tokens=set(bearer_tokens) if bearer_tokens else set(),
        verify_bearer=verify_bearer, expose_mcp=expose_mcp,
        content_guard=content_guard, approval_timeout=approval_timeout,
    )


def from_openai_agent(
    agent,
    *,
    name              = "OpenAI Agent",
    description       = "",
    memory            = "none",
    auth              = "aroha-sig",
    bearer_tokens     = None,
    verify_bearer     = None,
    expose_mcp        = False,
    content_guard     = None,
    approval_timeout  = 300.0,
):
    """
    Wrap an OpenAI Agents SDK ``Agent`` as an ArohaAgent.

    With memory="session" the earlier turns are passed to ``Runner.run`` as
    input items, so the agent sees the conversation (they used to be dropped).
    Requires: pip install aroha[openai-agents]
    """
    async def handler(message, session_id, history, context, **kw):
        try:
            from agents import Runner as AgentsRunner
        except ImportError:
            raise ImportError("Install the OpenAI Agents SDK: pip install aroha[openai-agents]")
        run_input: Any = message
        if history:
            run_input = _chat_messages("", history, message)
        result = await AgentsRunner.run(agent, run_input)
        out = result.final_output
        return out if isinstance(out, str) else str(out)

    return ArohaAgent(
        name=name, handler=handler, description=description,
        memory=memory, auth=auth,
        bearer_tokens=set(bearer_tokens) if bearer_tokens else set(),
        verify_bearer=verify_bearer, expose_mcp=expose_mcp,
        content_guard=content_guard, approval_timeout=approval_timeout,
    )
