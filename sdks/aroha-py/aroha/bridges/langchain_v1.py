# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.bridges.langchain_v1 — Wrap a LangChain chain/graph as /v1/run

Usage:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.prompts import ChatPromptTemplate
    from aroha.bridges.langchain_v1 import from_chain

    llm = ChatAnthropic(model="claude-sonnet-4-6")
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("human", "{message}"),
    ])
    chain = prompt | llm

    agent = from_chain(chain, name="My LangChain Agent", memory="session", expose_mcp=True)
    agent.register("https://my-agent.fly.dev", api_key="...", private_key=agent_key, manifest_cid="bafy...")
    agent.start(port=8000)

Compatibility: tested against langchain-core 1.6 and langgraph 1.2
(``pip install aroha[langchain]`` / ``aroha[langgraph]``). Any Runnable with
``ainvoke`` works; from_graph needs a graph whose state has a ``messages``
list (MessagesState, langgraph.prebuilt.create_react_agent,
langchain.agents.create_agent).
"""

from __future__ import annotations

from typing import Any, Callable

from aroha.agent import ArohaAgent


def from_chain(
    chain:              Any,
    *,
    name:               str = "LangChain Agent",
    description:        str = "",
    memory:             str = "none",
    auth:               str = "aroha-sig",
    bearer_tokens:      set[str] | list[str] | None = None,
    verify_bearer:      Callable[[str], bool] | None = None,
    expose_mcp:         bool = False,
    content_guard:      Callable[[str, str], dict] | None = None,
    approval_timeout:   float = 300.0,
    input_key:          str = "message",
    output_key:         str | None = None,
) -> ArohaAgent:
    """
    Wrap a LangChain Runnable (LCEL chain, AgentExecutor, etc.) as an ArohaAgent.

    Args:
        chain:            Any LangChain Runnable.
        input_key:        Key passed into chain.invoke() — defaults to "message".
        output_key:       Key to extract from chain output dict; None = auto-detect
                          ("output", "answer", "result", "text", "content", then
                          the last of "messages").
        expose_mcp:       Mount /mcp JSON-RPC endpoint (Claude Desktop compatible).
        content_guard:    callable(message, trust) -> {"blocked": bool, "reason": str}
        approval_timeout: Seconds before a pending HITL approval auto-rejects.

    With memory="session", earlier turns are passed as ``history`` (a list of
    ``{"role", "content"}`` dicts) next to ``input_key``.

    Requires: pip install aroha[langchain]
    """
    try:
        from langchain_core.runnables import Runnable  # noqa: F401
    except ImportError:
        raise ImportError("Install LangChain: pip install aroha[langchain]")

    async def handler(message: str, session_id: str, history: list, context: dict, **kw: Any) -> str:
        inputs: dict[str, Any] = {input_key: message}
        if history:
            inputs["history"] = history

        result = await chain.ainvoke(inputs)
        return _result_text(result, output_key)

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


def from_graph(
    graph:              Any,
    *,
    name:               str = "LangGraph Agent",
    description:        str = "",
    memory:             str = "session",
    auth:               str = "aroha-sig",
    bearer_tokens:      set[str] | list[str] | None = None,
    verify_bearer:      Callable[[str], bool] | None = None,
    expose_mcp:         bool = False,
    content_guard:      Callable[[str, str], dict] | None = None,
    approval_timeout:   float = 300.0,
) -> ArohaAgent:
    """
    Wrap a LangGraph CompiledGraph as an ArohaAgent.

    The Aroha session id is the LangGraph ``thread_id``. A graph compiled
    WITHOUT a checkpointer gets the session history as HumanMessage/AIMessage
    pairs; a graph WITH one already holds its thread's history, so only the
    new message is sent.

    Requires: pip install aroha[langgraph]
    """
    try:
        from langchain_core.runnables import Runnable  # noqa: F401
    except ImportError:
        raise ImportError("Install LangChain: pip install aroha[langchain]")

    async def handler(message: str, session_id: str, history: list, context: dict, **kw: Any) -> str:
        try:
            from langchain_core.messages import HumanMessage, AIMessage
        except ImportError:
            raise ImportError("Install langchain-core: pip install langchain-core")

        # Replaying Aroha's history into a checkpointed thread appended every
        # earlier turn a second time on each request.
        messages = []
        if getattr(graph, "checkpointer", None) is None:
            for turn in history:
                if turn.get("role") == "user":
                    messages.append(HumanMessage(content=turn["content"]))
                elif turn.get("role") == "assistant":
                    messages.append(AIMessage(content=turn["content"]))
        messages.append(HumanMessage(content=message))

        config = {"configurable": {"thread_id": session_id}}
        result = await graph.ainvoke({"messages": messages}, config=config)

        msgs = result.get("messages") if isinstance(result, dict) else None
        if msgs:
            return _message_text(msgs[-1])
        return str(result)

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


def _message_text(msg: Any) -> str:
    """Text of a LangChain message.

    ``content`` is a string or — for Anthropic, Gemini and the OpenAI
    Responses API — a list of content blocks. Returning the list made /v1/run
    reply with its Python repr.
    """
    content = getattr(msg, "content", msg)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return str(content)


_OUTPUT_KEYS = ("output", "answer", "result", "text", "content")


def _result_text(result: Any, output_key: str | None) -> str:
    if isinstance(result, str):
        return result
    if hasattr(result, "content"):
        return _message_text(result)  # AIMessage
    if isinstance(result, dict):
        if output_key is not None:
            return _result_text(result[output_key], None) if output_key in result else str(result)
        # AgentExecutor returns {"input": ..., "output": ...}. Taking the FIRST
        # key (the old behaviour) echoed the user's own message back.
        for key in _OUTPUT_KEYS:
            if key in result:
                return _result_text(result[key], None)
        if result.get("messages"):
            return _message_text(result["messages"][-1])
        return str(result)
    return str(result)
