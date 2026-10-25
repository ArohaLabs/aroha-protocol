# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""OpenAI bridges against the real SDKs, with HTTP served by httpx.MockTransport.

Skipped unless openai is installed (``pip install aroha[openai]``); the Agents
SDK case also needs openai-agents (``aroha[openai-agents]``). No request
leaves the process. Last run against openai 2.54.0 / openai-agents 0.20.0.
"""

from __future__ import annotations

import json

import httpx
import pytest

openai = pytest.importorskip("openai")

from aroha.bridges.openai_v1 import from_openai_agent, from_openai_client  # noqa: E402
from tests._bridge_helpers import run  # noqa: E402


class FakeChatCompletions:
    """Serves POST /v1/chat/completions; records each request body."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions"), request.url
        body = json.loads(request.content)
        self.requests.append(body)
        last = body["messages"][-1]["content"]
        return httpx.Response(200, json={
            "id": f"chatcmpl-{len(self.requests)}",
            "object": "chat.completion",
            "created": 0,
            "model": body["model"],
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": f"reply to {last}"},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })


async def test_sync_client_with_session_history():
    fake = FakeChatCompletions()
    client = openai.OpenAI(api_key="test", base_url="https://api.test/v1",
                           http_client=httpx.Client(transport=httpx.MockTransport(fake)))
    agent = from_openai_client(client, model="gpt-test", system_prompt="Be terse.", auth="none")
    assert (await run(agent, "hello", "s"))["message"] == "reply to hello"
    await run(agent, "next", "s")
    assert fake.requests[1]["model"] == "gpt-test"
    assert fake.requests[1]["messages"] == [
        {"role": "system", "content": "Be terse."},
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "reply to hello"},
        {"role": "user", "content": "next"},
    ]


async def test_async_client():
    fake = FakeChatCompletions()
    client = openai.AsyncOpenAI(api_key="test", base_url="https://api.test/v1",
                                http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake)))
    # Used to fail: the async create() was run in a thread and never awaited.
    agent = from_openai_client(client, model="gpt-test", auth="none")
    assert (await run(agent, "async hello"))["message"] == "reply to async hello"


async def test_agents_sdk_runner():
    agents = pytest.importorskip("agents")
    agents.set_tracing_disabled(True)
    fake = FakeChatCompletions()
    model = agents.OpenAIChatCompletionsModel(
        model="gpt-test",
        openai_client=openai.AsyncOpenAI(api_key="test", base_url="https://api.test/v1",
                                         http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake))),
    )
    sdk_agent = agents.Agent(name="assistant", instructions="Be helpful.", model=model)
    agent = from_openai_agent(sdk_agent, memory="session", auth="none")
    assert (await run(agent, "first", "s"))["message"] == "reply to first"
    assert (await run(agent, "second", "s"))["message"] == "reply to second"
    contents = [m.get("content") for m in fake.requests[1]["messages"]]
    assert contents[0] == "Be helpful."
    assert "first" in contents and "reply to first" in contents and contents[-1] == "second"
