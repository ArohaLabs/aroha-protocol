# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for the framework-bridge tests (tests/test_bridges_*.py).

Nothing here imports a framework. ``RecordingClient`` stands in for
``ArohaClient``: it records every envelope a bridge sends, checks its Ed25519
signature with the SDK's own validator, and replies like a provider would.
"""

from __future__ import annotations

import sys
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.messages import NonceRegistry, validate_envelope


class Orchestrator:
    def __init__(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aroha:" + to_multibase(self.public_bytes)


PROVIDER_DID = "did:aroha:flights-provider"
PROVIDER_ENDPOINT = "https://provider.example/aroha/v1"

SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "origin": {"type": "string", "description": "IATA code"},
        "passengers": {"type": "integer"},
    },
    "required": ["origin"],
}


def discovered_agents() -> list[dict[str, Any]]:
    return [{
        "did": PROVIDER_DID,
        "endpoint": PROVIDER_ENDPOINT,
        "manifest": {"capabilities": [
            {"id": "search-flights", "description": "Search flights", "inputSchema": SEARCH_SCHEMA},
            {"id": "book-flight", "description": "Book a flight"},
            {"id": "cancel-flight", "description": "Not requested"},
        ]},
    }]


class RecordingClient:
    """ArohaClient stand-in. ``reply`` is returned as-is (None = HTTP 202)."""

    def __init__(self, orchestrator: Orchestrator, reply: Any = "default") -> None:
        self.orchestrator = orchestrator
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.reply = reply

    async def send(self, endpoint: str, envelope: dict[str, Any], timeout: Optional[float] = None):
        ok, reason = validate_envelope(envelope, self.orchestrator.public_bytes, PROVIDER_DID, NonceRegistry())
        assert ok, f"bridge sent an envelope that does not validate: {reason}"
        self.sent.append((endpoint, envelope))
        if self.reply == "default":
            return {
                "type": "ArohaResponse",
                "body": {"result": {"capability": envelope["body"]["capability"], "params": envelope["body"]["params"]}},
            }
        return self.reply


_APPS: dict[int, Any] = {}


def asgi_client(agent) -> httpx.AsyncClient:
    # agent.app() builds a fresh app (and a fresh session store) on every
    # call, so one app is kept per agent for multi-turn tests.
    app = _APPS.setdefault(id(agent), (agent, agent.app()))[1]
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def run(agent, message: str, session_id: Optional[str] = None) -> dict[str, Any]:
    body: dict[str, Any] = {"message": message}
    if session_id:
        body["sessionId"] = session_id
    async with asgi_client(agent) as c:
        resp = await c.post("/v1/run", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


class Caller:
    """A calling agent for auth="aroha-sig" requests (did:aroha:z… of its key)."""

    def __init__(self) -> None:
        key = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        self.private_bytes = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aroha:" + to_multibase(self.public_bytes)


def trust_callers(agent, *callers: Caller) -> None:
    """Point a bridge-built agent's caller-key resolver at local test callers."""
    keys = {c.did: c.public_bytes for c in callers}
    agent.resolve_caller_key = keys.get


async def signed_post(agent, caller: Optional[Caller], message: str, session_id: Optional[str] = None,
                      context: Optional[dict[str, Any]] = None) -> httpx.Response:
    """POST /v1/run, Ed25519-signed by ``caller`` (unsigned when caller is None)."""
    import json as _json
    from aroha.signing import sign_request

    body = _json.dumps({"message": message, "sessionId": session_id, "history": [], "context": context or {}})
    headers = {"Content-Type": "application/json"}
    if caller is not None:
        headers.update(sign_request(did=caller.did, private_key=caller.private_bytes,
                                    method="POST", path="/v1/run", body=body))
    async with asgi_client(agent) as c:
        return await c.post("/v1/run", content=body, headers=headers)


def forget_module(name: str) -> None:
    """Drop a bridge module so the next import re-runs its framework import."""
    sys.modules.pop(name, None)
