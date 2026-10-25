# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""LangChain / LangGraph bridges against the real packages (no network, no LLM).

Skipped unless langchain-core is installed (``pip install aroha[langgraph]``;
the LangGraph cases also need langgraph). Models are langchain-core's own
fake chat models. Last run against langchain-core 1.6.12 / langgraph 1.2.16.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.fake_chat_models import FakeListChatModel, GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain_core.prompts import ChatPromptTemplate  # noqa: E402
from langchain_core.runnables import RunnableLambda  # noqa: E402

from aroha.bridges.langchain_bridge import ArohaCapabilityTool, aroha_tools_for_agent  # noqa: E402
from aroha.bridges.langchain_v1 import from_chain, from_graph  # noqa: E402
from tests._bridge_helpers import SEARCH_SCHEMA, Orchestrator, RecordingClient, discovered_agents, run  # noqa: E402


class ToolCallingFakeModel(GenericFakeChatModel):
    """GenericFakeChatModel that accepts bind_tools (as a tool-calling agent needs)."""

    def bind_tools(self, tools: Any, **kwargs: Any):
        return self


@pytest.fixture
def orch() -> Orchestrator:
    return Orchestrator()


# ── langchain_bridge: Aroha capabilities as LangChain tools ───────────────────

async def test_tools_expose_capability_schema(orch):
    tools = await aroha_tools_for_agent(discovered_agents(), ["search-flights", "book-flight"],
                                        orch.did, orch.private_key, RecordingClient(orch))
    assert all(isinstance(t, ArohaCapabilityTool) for t in tools)
    search = tools[0]
    # The model sees the capability's real parameters, not a single "kwargs" blob.
    assert search.args == SEARCH_SCHEMA["properties"]
    schema = search.tool_call_schema
    if not isinstance(schema, dict):
        schema = schema.model_json_schema()
    assert schema["required"] == ["origin"]


async def test_tool_invoke_and_ainvoke(orch):
    client = RecordingClient(orch)
    (search,) = await aroha_tools_for_agent(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    out = await search.ainvoke({"origin": "SFO", "passengers": 2})
    assert '"origin": "SFO"' in out
    # Sync invoke from inside a running loop used to raise from asyncio.run().
    search.invoke({"origin": "JFK"})
    assert [e["body"]["params"] for _, e in client.sent] == [{"origin": "SFO", "passengers": 2}, {"origin": "JFK"}]


async def test_tool_call_message_round_trip(orch):
    client = RecordingClient(orch, reply={"type": "ArohaError", "body": {"message": "no seats"}})
    (search,) = await aroha_tools_for_agent(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    msg = await search.ainvoke({"name": search.name, "args": {"origin": "SFO"}, "id": "call-1", "type": "tool_call"})
    assert isinstance(msg, ToolMessage) and msg.tool_call_id == "call-1"
    assert msg.content == "Error: no seats"


@pytest.mark.filterwarnings("ignore:create_react_agent has been moved")
async def test_langgraph_react_agent_calls_aroha_tool(orch):
    prebuilt = pytest.importorskip("langgraph.prebuilt")
    client = RecordingClient(orch)
    tools = await aroha_tools_for_agent(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
    model = ToolCallingFakeModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": "aroha_search_flights", "args": {"origin": "SFO"}, "id": "c1"}]),
        AIMessage(content="Found flights from SFO."),
    ]))
    graph = prebuilt.create_react_agent(model, tools)
    result = await graph.ainvoke({"messages": [HumanMessage(content="flights from SFO?")]})
    tool_msgs = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_msgs) == 1 and '"capability": "search-flights"' in tool_msgs[0].content
    assert client.sent[0][1]["body"] == {"capability": "search-flights", "params": {"origin": "SFO"}}
    assert result["messages"][-1].content == "Found flights from SFO."


# ── langchain_v1: a chain / graph served as /v1/run ───────────────────────────

async def test_from_chain_prompt_and_fake_model():
    prompt = ChatPromptTemplate.from_messages([("system", "Be brief."), ("human", "{message}")])
    agent = from_chain(prompt | FakeListChatModel(responses=["first reply", "second reply"]), memory="session", auth="none")
    assert (await run(agent, "hello", "s1"))["message"] == "first reply"
    assert (await run(agent, "again", "s1"))["message"] == "second reply"


async def test_from_chain_content_blocks_and_agent_executor_dict():
    blocks = GenericFakeChatModel(messages=iter([
        AIMessage(content=[{"type": "text", "text": "Hello "}, {"type": "text", "text": "world"}]),
    ]))
    agent = from_chain(RunnableLambda(lambda x: x["message"]) | blocks, auth="none")
    assert (await run(agent, "hi"))["message"] == "Hello world"

    executor_like = RunnableLambda(lambda x: {"input": x["message"], "output": "the answer"})
    assert (await run(from_chain(executor_like, auth="none"), "question"))["message"] == "the answer"
    assert (await run(from_chain(executor_like, output_key="input", auth="none"), "question"))["message"] == "question"


def _echo_graph(checkpointer=None):
    graph_mod = pytest.importorskip("langgraph.graph")
    seen: list[int] = []

    def respond(state):
        seen.append(len(state["messages"]))
        return {"messages": [AIMessage(content=f"saw {len(state['messages'])} messages")]}

    g = graph_mod.StateGraph(graph_mod.MessagesState)
    g.add_node("respond", respond)
    g.add_edge(graph_mod.START, "respond")
    g.add_edge("respond", graph_mod.END)
    return g.compile(checkpointer=checkpointer), seen


async def test_from_graph_without_checkpointer_replays_history():
    graph, seen = _echo_graph()
    agent = from_graph(graph, auth="none")
    assert (await run(agent, "one", "t1"))["message"] == "saw 1 messages"
    assert (await run(agent, "two", "t1"))["message"] == "saw 3 messages"


async def test_from_graph_with_checkpointer_does_not_duplicate():
    memory = pytest.importorskip("langgraph.checkpoint.memory")
    graph, seen = _echo_graph(memory.InMemorySaver())
    agent = from_graph(graph, auth="none")
    await run(agent, "one", "t1")
    await run(agent, "two", "t1")
    # 2 from turn one + the new human message; replaying history made it 5.
    assert seen == [1, 3]
    await run(agent, "other thread", "t2")
    assert seen[-1] == 1
