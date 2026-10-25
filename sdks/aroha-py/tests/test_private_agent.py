# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
"""End-to-end private agents: @serve(auth="aroha-sig") against a real app.

These drive the actual FastAPI application through TestClient rather than
calling the verifier directly, so they exercise the parts that only break when
the halves are wired together — reading the raw body after FastAPI has already
parsed it, header casing through the ASGI layer, and the path the server
derives from the URL.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from aroha.agent import serve
from aroha.signing import sign_request

ALICE = "did:aroha:alice"
MALLORY = "did:aroha:mallory"


def _keypair() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    return (
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


@pytest.fixture(scope="module")
def keys() -> dict[str, tuple[bytes, bytes]]:
    return {ALICE: _keypair(), MALLORY: _keypair()}


@pytest.fixture
def client(keys):
    pubs = {did: pair[1] for did, pair in keys.items()}

    @serve(
        name="Private Agent",
        auth="aroha-sig",
        allowed_callers=[ALICE],
        resolve_caller_key=lambda did: pubs.get(did),
    )
    async def private_agent(message: str, **_) -> str:
        return f"Echo: {message}"

    return TestClient(private_agent._build_app())


def _post(client, keys, did: str, signer: str, message: str = "Hello", **overrides):
    """POST /v1/run signed as `signer` but claiming to be `did`."""
    body = json.dumps({"message": message, "sessionId": None, "history": []})
    headers = sign_request(
        did=did,
        private_key=keys[signer][0],
        method="POST",
        path="/v1/run",
        body=body,
        **overrides,
    )
    headers["Content-Type"] = "application/json"
    return client.post("/v1/run", content=body, headers=headers)


class TestPrivateAgent:
    def test_allow_listed_caller_is_accepted(self, client, keys):
        res = _post(client, keys, ALICE, ALICE)
        assert res.status_code == 200
        assert res.json()["message"] == "Echo: Hello"

    def test_unsigned_request_is_rejected(self, client):
        res = client.post("/v1/run", json={"message": "Hello"})
        assert res.status_code == 401
        assert "signature" in res.json()["error"].lower()

    def test_caller_outside_allow_list_is_rejected(self, client, keys):
        res = _post(client, keys, MALLORY, MALLORY)
        assert res.status_code == 401
        assert res.json()["error"] == "Caller not permitted"

    def test_impersonation_is_rejected(self, client, keys):
        """Mallory signs with her own key but claims to be Alice."""
        res = _post(client, keys, ALICE, MALLORY)
        assert res.status_code == 401
        assert res.json()["error"] == "Invalid signature"

    def test_tampered_body_is_rejected(self, client, keys):
        body = json.dumps({"message": "Hello"})
        headers = sign_request(
            did=ALICE, private_key=keys[ALICE][0], method="POST", path="/v1/run", body=body
        )
        headers["Content-Type"] = "application/json"

        res = client.post("/v1/run", content=json.dumps({"message": "Goodbye"}), headers=headers)
        assert res.status_code == 401

    def test_replay_is_rejected(self, client, keys):
        body = json.dumps({"message": "Hello", "sessionId": None, "history": []})
        headers = sign_request(
            did=ALICE, private_key=keys[ALICE][0], method="POST", path="/v1/run", body=body
        )
        headers["Content-Type"] = "application/json"

        assert client.post("/v1/run", content=body, headers=headers).status_code == 200
        second = client.post("/v1/run", content=body, headers=headers)
        assert second.status_code == 401
        assert second.json()["error"] == "Replayed nonce"

    # The error must name the scheme actually in use. Telling someone to supply
    # a bearer token for an agent that does not accept bearer tokens sends them
    # in precisely the wrong direction.
    def test_rejection_reason_names_the_signature_not_a_bearer_token(self, client):
        res = client.post("/v1/run", json={"message": "Hello"})
        assert "bearer" not in res.json()["error"].lower()

    def test_health_stays_open(self, client):
        """Liveness probes must not require a signature."""
        assert client.get("/health").status_code == 200


class TestAttributionMode:
    """No allow-list: any verifiable caller is accepted."""

    def test_any_resolvable_caller_is_accepted(self, keys):
        pubs = {did: pair[1] for did, pair in keys.items()}

        @serve(
            name="Attribution Agent",
            auth="aroha-sig",
            resolve_caller_key=lambda did: pubs.get(did),
        )
        async def attribution_agent(message: str, **_) -> str:
            return f"Echo: {message}"

        client = TestClient(attribution_agent._build_app())
        res = _post(client, keys, MALLORY, MALLORY)
        assert res.status_code == 200

    def test_unknown_caller_is_still_rejected(self, keys):
        """Attribution mode still requires a resolvable key — it is not 'open'."""

        @serve(
            name="Attribution Agent",
            auth="aroha-sig",
            resolve_caller_key=lambda did: None,
        )
        async def attribution_agent(message: str, **_) -> str:
            return f"Echo: {message}"

        client = TestClient(attribution_agent._build_app())
        res = _post(client, keys, ALICE, ALICE)
        assert res.status_code == 401
        assert res.json()["error"] == "Unknown caller key"


class TestBearerUnaffected:
    """The existing bearer mode must keep working exactly as before."""

    def test_bearer_still_accepts_a_valid_token(self):
        @serve(name="Bearer Agent", auth="bearer", bearer_tokens={"s3cret"})
        async def bearer_agent(message: str, **_) -> str:
            return f"Echo: {message}"

        client = TestClient(bearer_agent._build_app())
        res = client.post(
            "/v1/run",
            json={"message": "Hello"},
            headers={"Authorization": "Bearer s3cret"},
        )
        assert res.status_code == 200

    def test_bearer_rejects_a_wrong_token(self):
        @serve(name="Bearer Agent", auth="bearer", bearer_tokens={"s3cret"})
        async def bearer_agent(message: str, **_) -> str:
            return f"Echo: {message}"

        client = TestClient(bearer_agent._build_app())
        res = client.post(
            "/v1/run", json={"message": "Hello"}, headers={"Authorization": "Bearer wrong"}
        )
        assert res.status_code == 401
        assert res.json()["error"] == "Bearer token required"

    def test_open_agent_needs_no_auth(self):
        @serve(name="Open Agent", auth="none")
        async def open_agent(message: str, **_) -> str:
            return f"Echo: {message}"

        client = TestClient(open_agent._build_app())
        assert client.post("/v1/run", json={"message": "Hello"}).status_code == 200
