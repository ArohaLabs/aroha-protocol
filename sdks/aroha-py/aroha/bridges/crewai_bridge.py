# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha -> CrewAI bridge

Wraps an Aroha provider capability as a CrewAI tool so CrewAI agents can call
Aroha capabilities as part of their crew workflows.

Usage:
    from aroha.bridges.crewai_bridge import ArohaCrewTool, aroha_tools_for_crew
    from crewai import Agent, Task, Crew

    flight_tool = ArohaCrewTool(
        capability_id="search-flights",
        agent_did="did:aroha:expedia-flights-v2",
        agent_endpoint="https://agents.expedia.com/aroha/v1",
        orchestrator_did=identity.did,
        private_key=identity.private_key,
        input_schema={"type": "object", "properties": {"origin": {"type": "string"}}},
    )

    researcher = Agent(role="Travel Researcher", tools=[flight_tool], ...)

    # or, from discovered manifests:
    tools = aroha_tools_for_crew(discovered_agents, ["search-flights"], identity.did, identity.private_key)

Compatibility: tested against crewai 1.15 (``pip install aroha[crewai]``);
needs crewai >= 0.80 (``crewai.tools.BaseTool`` as a pydantic model).
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import ConfigDict, PrivateAttr

from aroha.bridges._common import (
    call_capability,
    input_schema as _input_schema,
    iter_capabilities,
    model_from_schema,
    run_sync,
    tool_name,
)
from aroha.messages import new_correlation_id
from aroha.transport import ArohaClient

try:
    from crewai.tools import BaseTool as CrewBaseTool
except ImportError:
    raise ImportError("Install CrewAI support: pip install aroha[crewai]")


class ArohaCrewTool(CrewBaseTool):
    """CrewAI tool backed by an Aroha capability."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str
    agent_did: str
    agent_endpoint: str
    capability_id: str
    orchestrator_did: str
    correlation_id: Optional[str] = None
    _private_key: Any = PrivateAttr(default=None)
    _client: Any = PrivateAttr(default=None)

    def __init__(
        self,
        capability_id: str,
        agent_did: str,
        agent_endpoint: str,
        orchestrator_did: str,
        private_key: Any,
        description: str = "",
        *,
        input_schema: Optional[dict[str, Any]] = None,
        client: Optional[ArohaClient] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        # Every pydantic field goes through __init__. Assigning them after
        # super().__init__() (the old code) failed validation first: the
        # required fields were missing, so the tool could not be constructed.
        schema = _input_schema({"inputSchema": input_schema})
        super().__init__(
            name=tool_name(capability_id),
            description=description or f"Aroha capability: {capability_id}",
            args_schema=model_from_schema(tool_name(capability_id) + "_params", schema),
            capability_id=capability_id,
            agent_did=agent_did,
            agent_endpoint=agent_endpoint,
            orchestrator_did=orchestrator_did,
            correlation_id=correlation_id,
        )
        self._private_key = private_key
        self._client = client if client is not None else ArohaClient()

    def _run(self, **kwargs: Any) -> str:
        return run_sync(self._execute(kwargs))

    async def _arun(self, **kwargs: Any) -> str:
        return await self._execute(kwargs)

    async def _execute(self, params: dict[str, Any]) -> str:
        # CrewAI passes optional fields the model left out as None; they are
        # not part of what the model asked for.
        params = {k: v for k, v in params.items() if v is not None}
        return await call_capability(
            self._client,
            orchestrator_did=self.orchestrator_did,
            agent_did=self.agent_did,
            endpoint=self.agent_endpoint,
            capability_id=self.capability_id,
            params=params,
            correlation_id=self.correlation_id or new_correlation_id(),
            private_key=self._private_key,
        )


def aroha_tools_for_crew(
    agents: list[dict[str, Any]],   # [{"did", "endpoint", "manifest"}]
    capability_ids: list[str],
    orchestrator_did: str,
    private_key: Any,
    client: Optional[ArohaClient] = None,
) -> list[ArohaCrewTool]:
    """Convert discovered Aroha capabilities into CrewAI tools (one shared correlation id)."""
    correlation_id = new_correlation_id()
    return [
        ArohaCrewTool(
            capability_id=cap["id"],
            agent_did=agent["did"],
            agent_endpoint=agent["endpoint"],
            orchestrator_did=orchestrator_did,
            private_key=private_key,
            description=cap.get("description", ""),
            input_schema=cap.get("inputSchema"),
            client=client,
            correlation_id=correlation_id,
        )
        for agent, cap in iter_capabilities(agents, capability_ids)
    ]
