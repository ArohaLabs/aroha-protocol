# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""CrewAI bridges against the real package (no network, no LLM).

Skipped unless crewai is installed (``pip install aroha[crewai]``). The crew's
LLM is a ``crewai.llms.base_llm.BaseLLM`` subclass that returns scripted
ReAct text, so a real Crew runs end to end offline. Last run against
crewai 1.15.28.
"""

from __future__ import annotations

import os

import pytest

# CrewAI phones home (telemetry, tracing prompts) unless told not to.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

pytest.importorskip("crewai")

from typing import Any  # noqa: E402

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402

from aroha.bridges.crewai_bridge import ArohaCrewTool, aroha_tools_for_crew  # noqa: E402
from aroha.bridges.crewai_v1 import from_crew  # noqa: E402
from tests._bridge_helpers import (  # noqa: E402
    PROVIDER_DID,
    PROVIDER_ENDPOINT,
    SEARCH_SCHEMA,
    Orchestrator,
    RecordingClient,
    discovered_agents,
    run,
)


class ScriptedLLM(BaseLLM):
    """Returns the scripted replies in order; records every prompt it got."""

    replies: list[str] = []
    prompts: list[Any] = []

    def call(self, messages, tools=None, callbacks=None, available_functions=None,
             from_task=None, from_agent=None, response_model=None, **kw: Any) -> Any:
        self.prompts.append(messages)
        return self.replies.pop(0) if self.replies else "Thought: done\nFinal Answer: (script exhausted)"

    def supports_function_calling(self) -> bool:
        return False  # ReAct text protocol: the crew parses "Action:" lines

    def get_context_window_size(self) -> int:
        return 8192


def _crew(llm: ScriptedLLM, description: str, tools: list | None = None) -> Crew:
    agent = Agent(role="Researcher", goal="Answer the question", backstory="Terse.",
                  llm=llm, tools=tools or [], verbose=False, max_iter=4)
    task = Task(description=description, expected_output="An answer", agent=agent)
    return Crew(agents=[agent], tasks=[task], verbose=False)


@pytest.fixture
def orch() -> Orchestrator:
    return Orchestrator()


def test_tool_constructs_and_validates_args(orch):
    client = RecordingClient(orch)
    tool = ArohaCrewTool(
        capability_id="search-flights", agent_did=PROVIDER_DID, agent_endpoint=PROVIDER_ENDPOINT,
        orchestrator_did=orch.did, private_key=orch.private_key, input_schema=SEARCH_SCHEMA, client=client,
    )
    assert tool.name == "aroha_search_flights"
    out = tool.run(origin="SFO")
    assert '"origin": "SFO"' in out
    assert client.sent[0][1]["body"]["params"] == {"origin": "SFO"}   # unset optional not sent as null
    with pytest.raises(ValueError, match="validation failed"):
        tool.run(passengers=2)  # "origin" is required by the capability schema


async def test_tool_async_path(orch):
    client = RecordingClient(orch)
    (tool,) = aroha_tools_for_crew(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    await tool.arun(origin="LHR")
    tool.run(origin="CDG")  # sync entry point from inside a running loop
    assert [e["body"]["params"]["origin"] for _, e in client.sent] == ["LHR", "CDG"]


def test_crew_agent_calls_aroha_tool(orch):
    client = RecordingClient(orch)
    tools = aroha_tools_for_crew(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    llm = ScriptedLLM(model="scripted", replies=[
        'Thought: I should search.\nAction: aroha_search_flights\nAction Input: {"origin": "SFO"}',
        "Thought: I have it.\nFinal Answer: flights found",
    ], prompts=[])
    result = _crew(llm, "Find flights from SFO", tools).kickoff()
    assert result.raw == "flights found"
    assert client.sent and client.sent[0][1]["body"] == {"capability": "search-flights", "params": {"origin": "SFO"}}


async def test_from_crew_factory():
    llm = ScriptedLLM(model="scripted", replies=["Thought: easy\nFinal Answer: 42"], prompts=[])
    agent = from_crew(lambda message: _crew(llm, message), auth="none")
    assert (await run(agent, "What is 6 x 7? {not a template}"))["message"] == "42"
    assert "What is 6 x 7? {not a template}" in str(llm.prompts[0])


async def test_from_crew_instance_interpolates_message():
    llm = ScriptedLLM(model="scripted", replies=["Final Answer: one", "Final Answer: two"], prompts=[])
    agent = from_crew(_crew(llm, "Answer this: {message}\nEarlier: {history}"), memory="session", auth="none")
    assert (await run(agent, "first question", "s"))["message"] == "one"
    assert (await run(agent, "second question", "s"))["message"] == "two"
    assert "Answer this: first question" in str(llm.prompts[0])
    assert "user: first question" in str(llm.prompts[1])
