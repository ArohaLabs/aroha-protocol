# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha -> AutoGen bridge

Wraps Aroha capabilities as AutoGen tools so AutoGen agents (AgentChat's
AssistantAgent, or anything that takes an ``autogen_core.tools.Tool``) can
call Aroha capabilities as part of their conversations.

Usage:
    from aroha.bridges.autogen_bridge import aroha_tools_for_autogen
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    tools = aroha_tools_for_autogen(
        agents=discovered_agents,
        capability_ids=["search-flights", "book-flight"],
        orchestrator_did=identity.did,
        private_key=identity.private_key,
        client=ArohaClient(),
    )

    assistant = AssistantAgent(
        "assistant",
        model_client=OpenAIChatCompletionClient(model="gpt-4o"),
        tools=tools,
    )

Compatibility: written for the AutoGen 0.4+ packages (autogen-core /
autogen-agentchat), tested against 0.7.5 — ``pip install aroha[autogen]``.
The legacy ``pyautogen`` 0.2 / AG2 ``autogen`` package is NOT supported: the
previous version of this module imported ``autogen.FunctionTool``, a name no
AutoGen release has exported, so it could never be imported.

Each tool's parameter schema is the capability's ``inputSchema`` from the
manifest, passed through to the model as-is.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from aroha.bridges._common import call_capability, input_schema, iter_capabilities, params_from_model, tool_name
from aroha.messages import new_correlation_id
from aroha.transport import ArohaClient

try:
    from autogen_core import CancellationToken
    from autogen_core.tools import BaseTool, ToolSchema
except ImportError:
    raise ImportError("Install AutoGen support: pip install aroha[autogen]")


class ArohaToolArgs(BaseModel):
    """Open argument model: the capability's own JSON Schema is what the model
    sees (see ``ArohaAutoGenTool.schema``); validation is the provider's job."""

    model_config = ConfigDict(extra="allow")


class ArohaAutoGenTool(BaseTool[ArohaToolArgs, str]):
    """An AutoGen tool backed by an Aroha capability."""

    def __init__(
        self,
        *,
        capability_id: str,
        agent_did: str,
        agent_endpoint: str,
        orchestrator_did: str,
        private_key: Any,
        client: Any,
        correlation_id: str,
        description: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            ArohaToolArgs,
            str,
            tool_name(capability_id),
            description or f"Aroha capability: {capability_id}",
        )
        self.capability_id = capability_id
        self.agent_did = agent_did
        self.agent_endpoint = agent_endpoint
        self.orchestrator_did = orchestrator_did
        self.correlation_id = correlation_id
        self._parameters = input_schema({"inputSchema": parameters})
        self._private_key = private_key
        self._client = client

    @property
    def schema(self) -> ToolSchema:
        p = self._parameters
        return ToolSchema(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": p.get("properties", {}),
                "required": list(p.get("required", [])),
                "additionalProperties": bool(p.get("additionalProperties", False)),
            },
            strict=False,
        )

    async def run(self, args: ArohaToolArgs, cancellation_token: CancellationToken) -> str:
        return await call_capability(
            self._client,
            orchestrator_did=self.orchestrator_did,
            agent_did=self.agent_did,
            endpoint=self.agent_endpoint,
            capability_id=self.capability_id,
            params=params_from_model(args),
            correlation_id=self.correlation_id,
            private_key=self._private_key,
        )


def aroha_tools_for_autogen(
    agents: list[dict[str, Any]],   # [{"did", "endpoint", "manifest"}]
    capability_ids: list[str],
    orchestrator_did: str,
    private_key: Any,               # Ed25519PrivateKey
    client: ArohaClient,
) -> list[ArohaAutoGenTool]:
    """
    Convert discovered Aroha agent capabilities into AutoGen tools.

    Args:
        agents:           List of discovered Aroha agents
        capability_ids:   Which capabilities to expose as tools
        orchestrator_did: DID of the orchestrating agent
        private_key:      Ed25519PrivateKey of the orchestrator
        client:           ArohaClient instance

    Returns:
        Tools ready to pass as ``AssistantAgent(..., tools=tools)``
    """
    correlation_id = new_correlation_id()
    return [
        ArohaAutoGenTool(
            capability_id=cap["id"],
            agent_did=agent["did"],
            agent_endpoint=agent["endpoint"],
            orchestrator_did=orchestrator_did,
            private_key=private_key,
            client=client,
            correlation_id=correlation_id,
            description=cap.get("description", ""),
            parameters=cap.get("inputSchema"),
        )
        for agent, cap in iter_capabilities(agents, capability_ids)
    ]
