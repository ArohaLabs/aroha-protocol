# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha -> LangChain bridge

Exposes Aroha capabilities as LangChain tools so any LangChain / LangGraph
agent can call them without knowing about the Aroha protocol. Each tool's
argument schema is the capability's ``inputSchema`` from the manifest, so the
model sees the real parameter names.

Usage:
    from aroha.bridges.langchain_bridge import aroha_tools_for_agent

    tools = await aroha_tools_for_agent(
        agents=discovered_agents,          # [{"did", "endpoint", "manifest"}]
        capability_ids=["search-flights", "book-flight"],
        orchestrator_did=identity.did,
        private_key=identity.private_key,
        client=ArohaClient(),
    )
    agent = create_react_agent(llm, tools)   # or langchain.agents.create_agent

Compatibility: tested against langchain-core 1.6 and langgraph 1.2
(``pip install aroha[langchain]``); needs langchain-core >= 0.3, the first
release that accepts a JSON-Schema dict as ``args_schema``.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, PrivateAttr

from aroha.bridges._common import call_capability, input_schema, iter_capabilities, run_sync, tool_name
from aroha.messages import new_correlation_id
from aroha.transport import ArohaClient

try:
    from langchain_core.tools import BaseTool
except ImportError:
    raise ImportError("Install langchain support: pip install aroha[langchain]")


class ArohaCapabilityTool(BaseTool):
    """A LangChain tool backed by an Aroha capability."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str
    agent_did: str
    agent_endpoint: str
    capability_id: str
    orchestrator_did: str
    correlation_id: str
    _private_key: Any = PrivateAttr(default=None)  # Ed25519PrivateKey
    _client: Any = PrivateAttr(default=None)       # ArohaClient

    def __init__(self, *, private_key: Any = None, client: Any = None, **data: Any) -> None:
        super().__init__(**data)
        self._private_key = private_key
        self._client = client if client is not None else ArohaClient()

    def _run(self, **kwargs: Any) -> str:
        """Synchronous entry point. Safe inside a running event loop."""
        return run_sync(self._arun(**kwargs))

    async def _arun(self, **kwargs: Any) -> str:
        return await call_capability(
            self._client,
            orchestrator_did=self.orchestrator_did,
            agent_did=self.agent_did,
            endpoint=self.agent_endpoint,
            capability_id=self.capability_id,
            params=kwargs,
            correlation_id=self.correlation_id,
            private_key=self._private_key,
        )


async def aroha_tools_for_agent(
    agents: list[dict[str, Any]],  # [{"did", "endpoint", "manifest"}]
    capability_ids: list[str],
    orchestrator_did: str,
    private_key: Any,
    client: ArohaClient,
) -> list[ArohaCapabilityTool]:
    """
    Convert Aroha agent capabilities into LangChain tools.

    Args:
        agents:           List of discovered Aroha agents
        capability_ids:   Which capabilities to expose as tools
        orchestrator_did: DID of the orchestrating agent
        private_key:      Ed25519PrivateKey of the orchestrator
        client:           ArohaClient instance

    All tools from one call share a correlation id, so the calls a single
    agent run makes are one saga on the provider side.
    """
    correlation_id = new_correlation_id()
    return [
        ArohaCapabilityTool(
            name=tool_name(cap["id"]),
            description=cap.get("description") or cap["id"],
            args_schema=input_schema(cap),
            agent_did=agent["did"],
            agent_endpoint=agent["endpoint"],
            capability_id=cap["id"],
            orchestrator_did=orchestrator_did,
            correlation_id=correlation_id,
            private_key=private_key,
            client=client,
        )
        for agent, cap in iter_capabilities(agents, capability_ids)
    ]
