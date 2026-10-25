# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Google ADK bridge against the real package (no network, no Gemini call).

Skipped unless google-adk is installed (``pip install aroha[google-adk]``).
The LlmAgent's model is a ``google.adk.models.BaseLlm`` subclass that answers
locally, so a real Runner + InMemorySessionService run end to end. Last run
against google-adk 2.12.0 / google-genai 2.31.0.
"""

from __future__ import annotations

from typing import AsyncGenerator

import pytest

pytest.importorskip("google.adk")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.models import BaseLlm, LlmResponse  # noqa: E402
from google.adk.runners import Runner  # noqa: E402
from google.adk.sessions import InMemorySessionService  # noqa: E402
from google.genai import types  # noqa: E402

from aroha.bridges.google_adk import from_runner  # noqa: E402
from tests._bridge_helpers import run  # noqa: E402


class CountingLlm(BaseLlm):
    """Replies with how many user turns the session holds, plus the last one."""

    async def generate_content_async(self, llm_request, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        user_turns = [c for c in llm_request.contents if c.role == "user"]
        last = user_turns[-1].parts[0].text if user_turns else ""
        yield LlmResponse(content=types.Content(role="model", parts=[
            types.Part(text="hidden reasoning", thought=True),
            types.Part(text=f"{len(user_turns)}:{last}"),
        ]))


def _runner(service: InMemorySessionService, **kw) -> Runner:
    agent = LlmAgent(name="counter", model=CountingLlm(model="counting-llm"), instruction="Count.")
    return Runner(agent=agent, app_name="aroha-test", session_service=service, **kw)


async def test_first_request_creates_the_session_and_history_persists():
    service = InMemorySessionService()
    agent = from_runner(_runner(service), user_id="alice", auth="none")
    # Before the fix this raised SessionNotFoundError on every new session id.
    assert (await run(agent, "hello", "sess-1"))["message"] == "1:hello"
    assert (await run(agent, "again", "sess-1"))["message"] == "2:again"
    assert (await run(agent, "fresh", "sess-2"))["message"] == "1:fresh"
    session = await service.get_session(app_name="aroha-test", user_id="alice", session_id="sess-1")
    assert session is not None and len(session.events) == 4


async def test_runner_with_auto_create_session():
    service = InMemorySessionService()
    agent = from_runner(_runner(service, auto_create_session=True), auth="none")
    assert (await run(agent, "hi", "s"))["message"] == "1:hi"


async def test_existing_session_is_reused():
    service = InMemorySessionService()
    await service.create_session(app_name="aroha-test", user_id="aroha-user", session_id="pre", state={"k": "v"})
    agent = from_runner(_runner(service), auth="none")
    assert (await run(agent, "x", "pre"))["message"] == "1:x"
    session = await service.get_session(app_name="aroha-test", user_id="aroha-user", session_id="pre")
    assert session.state.get("k") == "v"
