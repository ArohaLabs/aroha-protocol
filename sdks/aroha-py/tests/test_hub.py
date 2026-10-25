# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
"""
aroha.hub — smoke tests using mocked HTTP (no live network required).

Tests verify that each function constructs the correct request (URL, headers,
payload) and parses the response correctly. httpx calls are patched via
unittest.mock so these run fully offline.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.hub import (
    call_agent,
    delete_agent,
    list_agents,
    register_agent,
    register_mcp,
    register_skill,
    resolve_agent,
)

from aroha.endpoints import AROHA_MANAGED_REGISTRY_URL as REGISTRY


@pytest.fixture(autouse=True)
def _no_registry_env(monkeypatch):
    # The default registry follows AROHA_REGISTRY_URL; keep the URL assertions
    # below independent of the developer's environment.
    monkeypatch.delenv("AROHA_REGISTRY_URL", raising=False)


def test_registry_default_follows_env_at_call_time(monkeypatch):
    agent_record = {"didHash": "abc123", "endpointUrl": "https://agent.example.com"}
    monkeypatch.setenv("AROHA_REGISTRY_URL", "https://reg.example.com/")
    with patch("httpx.get", return_value=_mock_response(agent_record)) as mock_get:
        resolve_agent("abc123")
    assert mock_get.call_args[0][0] == "https://reg.example.com/v1/agents/abc123"
    # An explicit registry_url still wins over the environment.
    with patch("httpx.get", return_value=_mock_response(agent_record)) as mock_get:
        resolve_agent("abc123", "https://mine.example.com")
    assert mock_get.call_args[0][0] == "https://mine.example.com/v1/agents/abc123"


def test_registry_default_is_managed_workers_dev_host(monkeypatch):
    from aroha.endpoints import AROHA_DEFAULT_IPFS_GATEWAY, resolve_ipfs_gateway, resolve_registry_url

    monkeypatch.delenv("AROHA_IPFS_GATEWAY", raising=False)
    assert REGISTRY == "https://aroha-registry.aroha-labs.workers.dev"
    assert resolve_registry_url() == REGISTRY
    assert resolve_ipfs_gateway() == AROHA_DEFAULT_IPFS_GATEWAY
    monkeypatch.setenv("AROHA_IPFS_GATEWAY", "https://gw.example.com/ipfs/")
    assert resolve_ipfs_gateway() == "https://gw.example.com/ipfs"


def _mock_response(data: Any, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.is_success = (200 <= status < 300)
    resp.raise_for_status = MagicMock()  # no-op on success
    return resp


# ── register_agent ─────────────────────────────────────────────────────────────

AGENT_KEY = bytes([3]) * 32


def test_register_agent_proves_key_possession():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aroha.hub import registration_challenge_message
    from aroha.identity import to_multibase
    import base64

    key = Ed25519PrivateKey.from_private_bytes(AGENT_KEY)
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    record = {"didHash": "abc123"}
    with patch("httpx.post", side_effect=[_mock_response({"nonce": "n-1", "expiresAt": 1}), _mock_response(record)]) as mock_post:
        result = register_agent(
            manifest={"cid": "bafy-test"},
            endpoint_url="https://agent.example.com",
            api_key="test-key",
            private_key=AGENT_KEY,
        )

    assert result["didHash"] == "abc123"
    challenge_call, register_call = mock_post.call_args_list
    did = "did:aroha:" + to_multibase(pub)
    assert challenge_call[0][0] == f"{REGISTRY}/v1/agents/challenge"
    assert challenge_call[1]["json"] == {"did": did}
    assert register_call[0][0] == f"{REGISTRY}/v1/agents"
    payload = register_call[1]["json"]
    assert set(payload) == {"did", "manifestCID", "publicKeyB64", "endpointUrl", "challengeNonce", "challengeSignature"}
    assert payload["did"] == did and payload["manifestCID"] == "bafy-test" and payload["challengeNonce"] == "n-1"
    assert payload["publicKeyB64"] == base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
    assert registration_challenge_message(did, "n-1") == (
        b'{"action":"prove-ownership","did":"' + did.encode() + b'","nonce":"n-1"}')
    sig = base64.urlsafe_b64decode(payload["challengeSignature"] + "==")
    key.public_key().verify(sig, registration_challenge_message(did, "n-1"))
    assert register_call[1]["headers"]["Authorization"] == "Bearer test-key"


def test_register_agent_requires_a_key_and_a_cid():
    with pytest.raises(ValueError, match="private_key is required"):
        register_agent(manifest={"cid": "bafy"}, endpoint_url="https://a.example", api_key="k")
    with pytest.raises(ValueError, match="cid"):
        register_agent(manifest={}, endpoint_url="https://a.example", api_key="k", private_key=AGENT_KEY)


def test_register_agent_e_did_sends_kel_without_challenge():
    from aroha.kel import incept
    ident = incept("agent")
    with patch("httpx.post", return_value=_mock_response({"didHash": "e"})) as mock_post:
        register_agent(manifest={"did": ident.did, "cid": "bafy"}, endpoint_url="https://a.example",
                       api_key="k", kel=ident.kel)
    assert mock_post.call_count == 1
    payload = mock_post.call_args[1]["json"]
    assert payload["did"] == ident.did and payload["kel"] == ident.kel
    assert "challengeNonce" not in payload and "capabilityIds" not in payload


# ── resolve_agent ──────────────────────────────────────────────────────────────

def test_resolve_agent_hits_correct_url():
    agent_record = {"didHash": "abc123", "endpointUrl": "https://agent.example.com"}
    with patch("httpx.get", return_value=_mock_response(agent_record)) as mock_get:
        result = resolve_agent("abc123")

    assert result["endpointUrl"] == "https://agent.example.com"
    assert mock_get.call_args[0][0] == f"{REGISTRY}/v1/agents/abc123"


# ── list_agents ────────────────────────────────────────────────────────────────

def test_list_agents_returns_agents_list():
    payload = {"agents": [{"didHash": "a1"}, {"didHash": "a2"}]}
    with patch("httpx.get", return_value=_mock_response(payload)):
        agents = list_agents()
    assert len(agents) == 2
    assert agents[0]["didHash"] == "a1"


def test_list_agents_reads_the_registry_servers_bare_array():
    # apps/registry-server returns GET /v1/agents as a bare array of records.
    payload = [
        {"didHash": "a1", "publishedBy": "acme"},
        {"didHash": "a2", "publishedBy": None},
        {"didHash": "a3", "publishedBy": "other"},
    ]
    with patch("httpx.get", return_value=_mock_response(payload)):
        assert [a["didHash"] for a in list_agents()] == ["a1", "a2", "a3"]
    with patch("httpx.get", return_value=_mock_response(payload)):
        # The server ignores ?org=, so the filter is applied client-side too.
        assert [a["didHash"] for a in list_agents(org="acme")] == ["a1"]


def test_list_agents_tolerates_unexpected_bodies():
    for payload in ({}, {"agents": None}, "oops", None):
        with patch("httpx.get", return_value=_mock_response(payload)):
            assert list_agents() == []


def test_list_agents_passes_org_filter():
    payload = {"agents": []}
    with patch("httpx.get", return_value=_mock_response(payload)) as mock_get:
        list_agents(org="acme")
    params = mock_get.call_args[1]["params"]
    assert params["org"] == "acme"


# ── delete_agent ───────────────────────────────────────────────────────────────

def test_delete_agent_returns_true_on_success():
    with patch("httpx.delete", return_value=_mock_response({}, status=200)):
        ok = delete_agent("abc123", api_key="key")
    assert ok is True


def test_delete_agent_returns_false_on_not_found():
    resp = _mock_response({}, status=404)
    resp.is_success = False
    with patch("httpx.delete", return_value=resp):
        ok = delete_agent("missing", api_key="key")
    assert ok is False


# ── register_mcp ───────────────────────────────────────────────────────────────
#
# POST /v1/mcps (apps/registry-server/src/routes/mcps.ts) requires did, name,
# and endpointUrl, and only ever persists toolIds: string[] — it has no
# "tools" field. register_mcp used to send neither a did nor toolIds, so every
# call 400'd server-side; nothing calling it could ever have succeeded. These
# tests assert the wire shape the registry actually accepts.

def test_register_mcp_sends_a_did():
    record = {"didHash": "mcp1"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_mcp(name="search-mcp", endpoint_url="https://mcp.example.com", api_key="key")
    payload = mock_post.call_args[1]["json"]
    assert payload["did"], "did must be present — the registry 400s without one"
    assert payload["did"].startswith("did:aroha:")


def test_register_mcp_honours_an_explicit_did():
    record = {"didHash": "mcp1"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_mcp(
            name="search-mcp", endpoint_url="https://mcp.example.com",
            did="did:aroha:my-search-mcp", api_key="key",
        )
    payload = mock_post.call_args[1]["json"]
    assert payload["did"] == "did:aroha:my-search-mcp"


def test_register_mcp_normalises_bare_tool_strings_to_tool_ids():
    record = {"didHash": "mcp1"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_mcp(
            name="search-mcp",
            endpoint_url="https://mcp.example.com",
            tools=["search", "fetch"],
            api_key="key",
        )
    payload = mock_post.call_args[1]["json"]
    # toolIds, not tools — the field the registry's insertMcp() actually reads.
    assert payload["toolIds"] == ["search", "fetch"]
    assert "tools" not in payload


def test_register_mcp_extracts_names_from_full_tool_dicts():
    tool = {"name": "search", "description": "web search", "inputSchema": {"type": "object"}}
    record = {"didHash": "mcp2"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_mcp("search-mcp", "https://mcp.example.com", tools=[tool], api_key="key")
    payload = mock_post.call_args[1]["json"]
    assert payload["toolIds"] == ["search"]


# ── register_skill ─────────────────────────────────────────────────────────────
#
# Same bug, same fix: POST /v1/skills requires did and name.

def test_register_skill_sends_a_did():
    record = {"didHash": "skill1"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_skill(name="my-rag-skill", skill_type="rag", api_key="key")
    payload = mock_post.call_args[1]["json"]
    assert payload["did"], "did must be present — the registry 400s without one"
    assert payload["skillType"] == "rag"


def test_register_skill_honours_an_explicit_did():
    record = {"didHash": "skill1"}
    with patch("httpx.post", return_value=_mock_response(record)) as mock_post:
        register_skill(
            name="my-rag-skill", skill_type="rag",
            did="did:aroha:my-rag-skill", api_key="key",
        )
    payload = mock_post.call_args[1]["json"]
    assert payload["did"] == "did:aroha:my-rag-skill"


# ── call_agent ─────────────────────────────────────────────────────────────────

def test_call_agent_resolves_then_posts_to_run():
    agent_record = {"didHash": "abc123", "endpointUrl": "https://agent.example.com"}
    run_response = {"message": "Hello from agent", "sessionId": "sess-1"}

    get_mock = _mock_response(agent_record)
    post_mock = _mock_response(run_response)

    with patch("httpx.get", return_value=get_mock), \
         patch("httpx.post", return_value=post_mock) as mock_post:
        result = call_agent("abc123", "Hello", session_id="sess-1")

    assert result["message"] == "Hello from agent"
    post_url = mock_post.call_args[0][0]
    assert post_url == "https://agent.example.com/v1/run"
    # call_agent now sends a pre-serialised body via `content=` rather than
    # letting httpx serialise via `json=`. That is required for aroha-sig: the
    # signature covers a hash of the body bytes, so the bytes that were signed
    # have to be the bytes that go on the wire.
    body = json.loads(mock_post.call_args[1]["content"])
    assert body["message"] == "Hello"
    assert body["sessionId"] == "sess-1"


def test_call_agent_signs_when_given_sign_as():
    """sign_as attaches aroha-sig headers over the exact body that is sent."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    from aroha.signing import verify_signed_request

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    agent_record = {"endpointUrl": "https://agent.example.com"}
    with patch("httpx.get", return_value=_mock_response(agent_record)), \
         patch("httpx.post", return_value=_mock_response({"message": "ok"})) as mock_post:
        call_agent("abc123", "Hi", sign_as=("did:aroha:alice", seed))

    headers = mock_post.call_args[1]["headers"]
    content = mock_post.call_args[1]["content"]

    # Verify with the real verifier rather than merely asserting the headers
    # exist — presence proves nothing about whether they would be accepted.
    result = verify_signed_request(
        headers=headers,
        method="POST",
        path="/v1/run",
        body=content,
        resolve_public_key=lambda did: pub,
    )
    assert result.ok is True
    assert result.did == "did:aroha:alice"


def test_call_agent_accepts_sign_as_as_a_mapping():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    agent_record = {"endpointUrl": "https://agent.example.com"}
    with patch("httpx.get", return_value=_mock_response(agent_record)), \
         patch("httpx.post", return_value=_mock_response({"message": "ok"})) as mock_post:
        call_agent("abc123", "Hi", sign_as={"did": "did:aroha:alice", "private_key": seed})

    assert "x-aroha-signature" in mock_post.call_args[1]["headers"]


def test_call_agent_attaches_bearer_token():
    agent_record = {"endpointUrl": "https://agent.example.com"}
    with patch("httpx.get", return_value=_mock_response(agent_record)), \
         patch("httpx.post", return_value=_mock_response({"message": "ok"})) as mock_post:
        call_agent("abc123", "Hi", bearer_token="tok-xyz")

    headers = mock_post.call_args[1]["headers"]
    assert headers["Authorization"] == "Bearer tok-xyz"


def test_call_agent_raises_if_no_endpoint():
    agent_record = {"didHash": "abc123"}  # no endpointUrl
    with patch("httpx.get", return_value=_mock_response(agent_record)):
        with pytest.raises(ValueError, match="no endpoint"):
            call_agent("abc123", "Hello")
