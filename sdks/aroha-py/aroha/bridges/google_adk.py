# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.bridges.google_adk — Wrap a Google ADK Runner as /v1/run

Usage:
    from google.adk.agents import LlmAgent
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from aroha.bridges.google_adk import from_runner

    adk_agent = LlmAgent(name="weather_agent", model="gemini-2.0-flash",
                          instruction="You are a weather assistant.")
    session_service = InMemorySessionService()
    runner = Runner(agent=adk_agent, app_name="weather", session_service=session_service)

    aroha_agent = from_runner(runner, name="Weather Agent", expose_mcp=True)
    aroha_agent.start(port=8000)

The Aroha session id is the ADK session id. ADK keeps the conversation in its
own session service, so the Aroha-side history is not replayed into it; the
ADK session is created on the first request that names it.

ADK sessions are keyed by (user_id, session_id). With auth="aroha-sig" (the
default) the ADK user_id is the VERIFIED caller DID, so one caller cannot
read or extend another caller's ADK session by naming its session id. The
``user_id`` argument is used only when there is no verified caller
(auth="bearer" or an explicit auth="none").

Compatibility: tested against google-adk 2.12 with google-genai 2.31
(``pip install aroha[google-adk]``).
"""

from __future__ import annotations

from typing import Any

from aroha.agent import CALLER_CONTEXT_KEY, ArohaAgent


def from_runner(
    runner,
    *,
    name              = "Google ADK Agent",
    description       = "",
    memory            = "session",
    auth              = "aroha-sig",
    bearer_tokens     = None,
    verify_bearer     = None,
    expose_mcp        = False,
    content_guard     = None,
    approval_timeout  = 300.0,
    user_id           = "aroha-user",
):
    """
    Wrap a Google ADK Runner as an ArohaAgent.

    ``user_id`` is the fallback ADK user for requests without a verified
    caller; with auth="aroha-sig" the caller's DID is used instead.
    Requires: pip install aroha[google-adk]
    """
    async def handler(message, session_id, history, context, **kw):
        try:
            from google.genai import types as genai_types
        except ImportError:
            raise ImportError("Install Google ADK: pip install aroha[google-adk]")

        caller = (context or {}).get(CALLER_CONTEXT_KEY)
        adk_user = caller if isinstance(caller, str) and caller else user_id
        await _ensure_session(runner, adk_user, session_id)

        user_message = genai_types.Content(
            role="user", parts=[genai_types.Part(text=message)],
        )
        reply_parts = []
        async for event in runner.run_async(
            user_id=adk_user, session_id=session_id, new_message=user_message,
        ):
            if event.is_final_response() and event.content and event.content.parts:
                for part in event.content.parts:
                    # A thought part (Gemini thinking) is reasoning, not reply.
                    if getattr(part, "text", None) and not getattr(part, "thought", False):
                        reply_parts.append(part.text)
        return "".join(reply_parts) or "(no response)"

    return ArohaAgent(
        name=name, handler=handler, description=description,
        memory=memory, auth=auth,
        bearer_tokens=set(bearer_tokens) if bearer_tokens else set(),
        verify_bearer=verify_bearer, expose_mcp=expose_mcp,
        content_guard=content_guard, approval_timeout=approval_timeout,
    )


async def _ensure_session(runner: Any, user_id: str, session_id: str) -> None:
    """Create the ADK session on first use.

    ``Runner.run_async`` raises SessionNotFoundError (ValueError before
    google-adk 1.x) for a session id the session service has never seen —
    which is every Aroha session id — unless the runner was built with
    ``auto_create_session=True``. The old bridge never created one, so every
    first request failed.
    """
    if getattr(runner, "auto_create_session", False):
        return
    service = getattr(runner, "session_service", None)
    app_name = getattr(runner, "app_name", None)
    if service is None or app_name is None:
        return
    existing = await service.get_session(app_name=app_name, user_id=user_id, session_id=session_id)
    if existing is not None:
        return
    try:
        await service.create_session(app_name=app_name, user_id=user_id, session_id=session_id)
    except Exception:
        # A concurrent first request may have created it in between.
        if await service.get_session(app_name=app_name, user_id=user_id, session_id=session_id) is None:
            raise
