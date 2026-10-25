# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.bridges.crewai_v1 — Wrap a CrewAI Crew as /v1/run

Usage:
    from crewai import Agent, Task, Crew
    from aroha.bridges.crewai_v1 import from_crew

    researcher = Agent(
        role="Researcher",
        goal="Research the given topic",
        backstory="Expert at finding information",
        llm="anthropic/claude-sonnet-4-6",
    )

    def make_crew(message: str) -> Crew:
        task = Task(
            description=message,
            agent=researcher,
            expected_output="Detailed research findings",
        )
        return Crew(agents=[researcher], tasks=[task])

    agent = from_crew(make_crew, name="Research Agent", memory="session", expose_mcp=True)
    agent.start(port=8000)

    # Or pass a ready Crew whose task descriptions use {message} (and,
    # optionally, {history}); it is copied per request and kicked off with
    # inputs={"message": ..., "history": ...}.

Compatibility: tested against crewai 1.15 (``pip install aroha[crewai]``).
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from aroha.agent import ArohaAgent


def from_crew(
    crew_factory:       Callable[[str], Any] | Any,
    *,
    name:               str = "CrewAI Agent",
    description:        str = "",
    memory:             str = "none",
    auth:               str = "aroha-sig",
    bearer_tokens:      set[str] | list[str] | None = None,
    verify_bearer:      Callable[[str], bool] | None = None,
    expose_mcp:         bool = False,
    content_guard:      Callable[[str, str], dict] | None = None,
    approval_timeout:   float = 300.0,
) -> ArohaAgent:
    """
    Wrap a CrewAI Crew as an ArohaAgent.

    Args:
        crew_factory:     A Crew instance or callable(message) -> Crew.
                          Use a factory when the task description is dynamic.
                          A Crew instance gets the message as the ``{message}``
                          kickoff input (it used to be dropped entirely).
        expose_mcp:       Mount /mcp JSON-RPC endpoint (Claude Desktop compatible).
        content_guard:    callable(message, trust) -> {"blocked": bool, "reason": str}
        approval_timeout: Seconds before a pending HITL approval auto-rejects.

    Requires: pip install aroha[crewai]
    """
    try:
        import crewai  # noqa: F401
    except ImportError:
        raise ImportError("Install CrewAI: pip install aroha[crewai]")

    is_factory = callable(crew_factory) and not hasattr(crew_factory, "kickoff")

    async def handler(message: str, session_id: str, history: list, context: dict, **kw: Any) -> str:
        loop = asyncio.get_running_loop()
        if is_factory:
            crew = crew_factory(message)
            # The factory put the message into the task itself. No inputs:
            # kickoff(inputs=...) interpolates "{...}" in task text, and a
            # user message containing braces would then fail to interpolate.
            result = await loop.run_in_executor(None, crew.kickoff)
        else:
            # A shared Crew holds per-run state (task outputs, usage
            # counters); concurrent requests must not share one.
            crew = crew_factory.copy() if hasattr(crew_factory, "copy") else crew_factory
            inputs = {"message": message, "history": _history_text(history)}
            result = await loop.run_in_executor(None, lambda: crew.kickoff(inputs=inputs))
        raw = getattr(result, "raw", None)
        return raw if isinstance(raw, str) else str(result)

    return ArohaAgent(
        name=name,
        handler=handler,
        description=description,
        memory=memory,
        auth=auth,
        bearer_tokens=set(bearer_tokens) if bearer_tokens else set(),
        verify_bearer=verify_bearer,
        expose_mcp=expose_mcp,
        content_guard=content_guard,
        approval_timeout=approval_timeout,
    )


def _history_text(history: list) -> str:
    return "\n".join(f"{t.get('role', 'user')}: {t.get('content', '')}" for t in history or [])
