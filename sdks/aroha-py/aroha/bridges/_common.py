# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Shared plumbing for the protocol-layer bridges (langchain_bridge,
crewai_bridge, autogen_bridge).

Every one of those bridges does the same three things — pick capabilities out
of discovered manifests, send a signed ArohaRequest, turn the reply into the
string a framework tool returns — so the logic lives here once, has no
framework import, and is tested without any framework installed.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
from typing import Any, Coroutine, Iterator, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, create_model

from aroha.messages import build_envelope

T = TypeVar("T")

EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


def tool_name(capability_id: str) -> str:
    """Framework tool name for a capability: ``aroha_`` + the id with every
    character outside ``[A-Za-z0-9_]`` replaced by ``_``.

    OpenAI-compatible function names must match ``^[a-zA-Z0-9_-]{1,64}$``; the
    old ``replace('-', '_')`` let ids such as ``flights.search`` or
    ``ns:cap`` through and the model provider rejected the whole request.
    """
    return ("aroha_" + re.sub(r"[^A-Za-z0-9_]", "_", capability_id))[:64]


def input_schema(cap: dict[str, Any]) -> dict[str, Any]:
    """The capability's JSON Schema for its params, or an empty object schema."""
    schema = cap.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        return dict(EMPTY_SCHEMA)
    out = dict(schema)
    out.setdefault("type", "object")
    out.setdefault("properties", {})
    return out


def iter_capabilities(
    agents: list[dict[str, Any]], capability_ids: list[str]
) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield ``(agent, capability)`` for every wanted capability in the manifests."""
    wanted = set(capability_ids)
    for agent in agents:
        manifest = agent.get("manifest") or {}
        for cap in manifest.get("capabilities", []):
            if cap.get("id") in wanted:
                yield agent, cap


async def call_capability(
    client: Any,
    *,
    orchestrator_did: str,
    agent_did: str,
    endpoint: str,
    capability_id: str,
    params: dict[str, Any],
    correlation_id: str,
    private_key: Any,
) -> str:
    """Sign and send one ArohaRequest; return the tool-facing string."""
    envelope = build_envelope(
        "ArohaRequest",
        orchestrator_did,
        agent_did,
        {"capability": capability_id, "params": params},
        correlation_id,
        private_key,
    )
    response = await client.send(endpoint, envelope)
    return format_response(response)


def format_response(response: Optional[dict[str, Any]]) -> str:
    """Turn an Aroha reply into a tool result string.

    ``None`` is the transport's 202 (accepted, result streams later). An
    ArohaError becomes ``"Error: <message>"`` so the model sees the failure
    instead of the framework raising mid-conversation.
    """
    if response is None:
        return "Request accepted (async; the result streams over the agent's WebSocket)"
    body = response.get("body") or {}
    if response.get("type") == "ArohaError":
        return f"Error: {body.get('message', 'unknown error')}"
    return json.dumps(body.get("result", {}), indent=2)


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine from synchronous framework code.

    ``asyncio.run`` raises when an event loop is already running in this
    thread — which is exactly the case inside Jupyter, inside an async
    framework that calls a tool's sync entry point, or inside the /v1/run
    server. In that case the coroutine runs on a fresh loop in a worker thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


_JSON_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
}


def model_from_schema(name: str, schema: dict[str, Any]) -> type[BaseModel]:
    """A pydantic model for a capability's (flat) JSON Schema.

    For frameworks that want a model rather than a schema dict. Top-level
    properties map to typed fields (unknown or composite types become
    ``Any``); ``required`` is honoured; extra keys are allowed so a nested or
    future field is passed through to the provider rather than dropped.
    """
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    fields: dict[str, Any] = {}
    for key, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        typ = _JSON_TYPES.get(spec.get("type"), Any) if isinstance(spec.get("type"), str) else Any
        desc = spec.get("description")
        if key in required:
            fields[key] = (typ, Field(..., description=desc))
        else:
            fields[key] = (Optional[typ], Field(None, description=desc))
    model_name = re.sub(r"[^A-Za-z0-9_]", "_", name) or "ArohaParams"
    return create_model(model_name, __config__=ConfigDict(extra="allow"), **fields)


def params_from_model(args: Any) -> dict[str, Any]:
    """Model instance (or mapping) → params dict, dropping unset optional fields."""
    if isinstance(args, BaseModel):
        return args.model_dump(exclude_unset=True)
    return dict(args or {})
