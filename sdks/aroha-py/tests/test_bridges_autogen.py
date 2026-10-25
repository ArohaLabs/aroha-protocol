# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""AutoGen bridge against the real packages (no network, no LLM).

Skipped unless autogen-core / autogen-agentchat are installed
(``pip install aroha[autogen]``; the agent case also needs autogen-ext for its
ReplayChatCompletionClient). Last run against autogen 0.7.5.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("autogen_core")

from autogen_core import CancellationToken, FunctionCall  # noqa: E402
from autogen_core.tools import Tool  # noqa: E402

from aroha.bridges.autogen_bridge import ArohaAutoGenTool, aroha_tools_for_autogen  # noqa: E402
from tests._bridge_helpers import SEARCH_SCHEMA, Orchestrator, RecordingClient, discovered_agents  # noqa: E402


@pytest.fixture
def orch() -> Orchestrator:
    return Orchestrator()


def test_tools_satisfy_the_tool_protocol_and_carry_the_schema(orch):
    tools = aroha_tools_for_autogen(discovered_agents(), ["search-flights", "book-flight"],
                                    orch.did, orch.private_key, RecordingClient(orch))
    assert [t.name for t in tools] == ["aroha_search_flights", "aroha_book_flight"]
    assert all(isinstance(t, (Tool, ArohaAutoGenTool)) for t in tools)
    assert isinstance(tools[0], Tool)
    params = tools[0].schema["parameters"]
    assert params["properties"] == SEARCH_SCHEMA["properties"]
    assert params["required"] == ["origin"]
    assert tools[0].schema["description"] == "Search flights"
    assert tools[1].schema["parameters"]["properties"] == {}


async def test_run_json_sends_signed_request(orch):
    client = RecordingClient(orch)
    (tool,) = aroha_tools_for_autogen(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    out = await tool.run_json({"origin": "SFO", "passengers": 3}, CancellationToken(), call_id="c1")
    assert json.loads(out) == {"capability": "search-flights", "params": {"origin": "SFO", "passengers": 3}}
    assert tool.return_value_as_string(out) == out


async def test_assistant_agent_calls_aroha_tool(orch):
    agents_mod = pytest.importorskip("autogen_agentchat.agents")
    replay = pytest.importorskip("autogen_ext.models.replay")
    from autogen_core.models import CreateResult, RequestUsage

    client = RecordingClient(orch)
    tools = aroha_tools_for_autogen(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    model = replay.ReplayChatCompletionClient(
        [
            CreateResult(
                finish_reason="function_calls",
                content=[FunctionCall(id="call-1", name="aroha_search_flights", arguments='{"origin": "SFO"}')],
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                cached=False,
            ),
        ],
        model_info={"vision": False, "function_calling": True, "json_output": False,
                    "family": "unknown", "structured_output": False},
    )
    assistant = agents_mod.AssistantAgent("assistant", model_client=model, tools=tools)
    result = await assistant.run(task="Find flights from SFO")
    assert client.sent[0][1]["body"] == {"capability": "search-flights", "params": {"origin": "SFO"}}
    assert '"origin": "SFO"' in str(result.messages[-1].content)
