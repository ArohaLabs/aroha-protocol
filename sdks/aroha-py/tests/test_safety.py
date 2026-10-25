# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Transport safety defaults: dev-mode gate, https-only clients, body cap, loopback bind, CORS, auth default."""

import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import aroha.safety as safety
from aroha.agent import ArohaAgent, serve
from aroha.client import ArohaClient as SimpleClient
from aroha.hub import call_agent, resolve_agent
from aroha.identity import generate_did
from aroha.safety import (
    MAX_BODY_BYTES,
    BodySizeLimitMiddleware,
    DevModeNotPermitted,
    InsecureEndpointError,
    is_loopback_host,
    require_secure_url,
)
from aroha.signing import registry_key_resolver
from aroha.transport import ArohaClient, ArohaServer


async def _no_key(_did):
    return None


async def _echo(env):
    return None


def _server(**kw):
    agent = generate_did("safety", "http://localhost:3001")
    doc = MagicMock()
    doc.to_dict.return_value = agent["document"]
    return ArohaServer(agent["did"], doc, _echo, _no_key, **kw)


# ── Dev-mode gate ─────────────────────────────────────────────────────────────

def test_dev_mode_is_refused_without_env(monkeypatch):
    monkeypatch.delenv("AROHA_DEV_MODE", raising=False)
    with pytest.raises(DevModeNotPermitted, match="AROHA_DEV_MODE=1"):
        _server(dev_mode=True)
    monkeypatch.setenv("AROHA_DEV_MODE", "yes")
    with pytest.raises(DevModeNotPermitted):
        _server(dev_mode=True)


def test_dev_mode_with_env_warns_once_on_stderr(monkeypatch, capsys):
    monkeypatch.setenv("AROHA_DEV_MODE", "1")
    monkeypatch.setattr(safety, "_warned", set())
    _server(dev_mode=True)
    _server(dev_mode=True)
    err = capsys.readouterr().err
    assert err.count("WARNING: ArohaServer dev_mode is ENABLED") == 1


def test_server_without_dev_mode_needs_no_env(monkeypatch):
    monkeypatch.delenv("AROHA_DEV_MODE", raising=False)
    assert _server().dev_mode is False


# ── HTTPS-only clients ────────────────────────────────────────────────────────

@pytest.mark.parametrize("host,ok", [
    ("localhost", True), ("api.localhost", True), ("127.0.0.1", True), ("127.8.9.10", True),
    ("[::1]", True), ("::1", True), ("10.0.0.1", False), ("example.com", False),
    ("localhost.example.com", False), ("128.0.0.1", False), (None, False),
])
def test_loopback_detection(host, ok):
    assert is_loopback_host(host) is ok


def test_require_secure_url():
    assert require_secure_url("https://agent.example.com/aroha/v1")
    assert require_secure_url("http://127.0.0.1:3001/aroha/v1")
    assert require_secure_url("http://[::1]:3001/")
    assert require_secure_url("http://localhost:8000")
    with pytest.raises(InsecureEndpointError, match="allow_insecure_http"):
        require_secure_url("http://agent.example.com/aroha/v1")
    assert require_secure_url("http://10.1.2.3/aroha/v1", allow_insecure_http=True)
    for bad in ("ftp://example.com", "file:///etc/hosts", "agent.example.com", "https://"):
        with pytest.raises(InsecureEndpointError):
            require_secure_url(bad, allow_insecure_http=True)


def test_transport_client_refuses_plain_http_before_sending():
    client = ArohaClient()
    with patch("httpx.AsyncClient") as ac:
        with pytest.raises(InsecureEndpointError):
            asyncio.run(client.send("http://agent.example.com/aroha/v1", {}))
        with pytest.raises(InsecureEndpointError):
            asyncio.run(client.fetch_did_document("http://agent.example.com"))
        ac.assert_not_called()


def test_simple_client_refuses_plain_http():
    c = SimpleClient({"did": "did:aroha:x", "private_key": b"\x01" * 32})
    with pytest.raises(InsecureEndpointError):
        asyncio.run(c.request("http://agent.example.com/aroha/v1", "did:aroha:y", "cap", {}))


def test_hub_refuses_plain_http_registry_and_endpoint():
    with pytest.raises(InsecureEndpointError):
        resolve_agent("abc", registry_url="http://registry.example.com")
    resp = MagicMock()
    resp.json.return_value = {"endpointUrl": "http://agent.example.com"}
    resp.raise_for_status.return_value = None
    with patch("httpx.get", return_value=resp), patch("httpx.post") as post:
        with pytest.raises(InsecureEndpointError, match="agent endpoint"):
            call_agent("abc", "hi")
        post.assert_not_called()
    with patch("httpx.get", return_value=resp), patch("httpx.post") as post:
        post.return_value = MagicMock(status_code=200, json=lambda: {"message": "ok"})
        assert call_agent("abc", "hi", allow_insecure_http=True) == {"message": "ok"}


def test_registry_key_resolver_refuses_plain_http():
    with pytest.raises(InsecureEndpointError):
        registry_key_resolver("http://registry.example.com")
    registry_key_resolver("http://127.0.0.1:8787")


# ── Body cap ──────────────────────────────────────────────────────────────────

def test_transport_server_rejects_oversized_body_with_413():
    client = TestClient(_server().app)
    big = b"{" + b" " * MAX_BODY_BYTES + b"}"
    res = client.post("/aroha/v1", content=big, headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    assert res.json() == {"error": "Payload too large"}
    # A small invalid body still reaches the handler (400, not 413).
    assert client.post("/aroha/v1", content=b"{nope").status_code == 400


def test_agent_rejects_oversized_body_with_413():
    @serve(name="cap", auth="none")
    async def cap(message, **_):
        return "ok"

    client = TestClient(cap.app())
    big = '{"message": "' + "a" * MAX_BODY_BYTES + '"}'
    assert client.post("/v1/run", content=big, headers={"Content-Type": "application/json"}).status_code == 413
    assert client.post("/v1/run", json={"message": "hi"}).status_code == 200


def test_body_cap_applies_without_content_length():
    seen = {}

    async def app(scope, receive, send):
        seen["body"] = (await receive())["body"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def run(chunks):
        sent = []
        it = iter(chunks)

        async def receive():
            c = next(it)
            return {"type": "http.request", "body": c, "more_body": c is not chunks[-1]}

        async def send(m):
            sent.append(m)

        await BodySizeLimitMiddleware(app, max_bytes=10)({"type": "http", "headers": []}, receive, send)
        return sent[0]["status"]

    assert asyncio.run(run([b"12345", b"67890", b"x"])) == 413
    assert asyncio.run(run([b"12345", b"67890"])) == 200
    assert seen["body"] == b"1234567890"


# ── Bind, CORS, auth defaults ────────────────────────────────────────────────

def test_default_bind_is_loopback():
    assert inspect.signature(ArohaServer.run).parameters["host"].default == "127.0.0.1"
    assert inspect.signature(ArohaAgent.start).parameters["host"].default == "127.0.0.1"


def test_cors_is_opt_in():
    @serve(name="nocors", auth="none")
    async def a(message, **_):
        return "ok"

    @serve(name="cors", auth="none", cors_origins=["https://app.example"])
    async def b(message, **_):
        return "ok"

    hdr = {"Origin": "https://evil.example"}
    assert "access-control-allow-origin" not in TestClient(a.app()).get("/health", headers=hdr).headers
    res = TestClient(b.app()).get("/health", headers={"Origin": "https://app.example"})
    assert res.headers["access-control-allow-origin"] == "https://app.example"


def test_auth_defaults_to_signed_requests():
    @serve(name="default-auth", resolve_caller_key=lambda did: None)
    async def a(message, **_):
        return "ok"

    assert a.auth == "aroha-sig"
    client = TestClient(a.app())
    assert client.post("/v1/run", json={"message": "hi"}).status_code == 401
    assert client.get("/.well-known/aroha-agent.json").json()["auth"] == {"type": "aroha-sig"}


def test_unknown_auth_mode_is_rejected():
    with pytest.raises(ValueError, match="auth must be"):
        ArohaAgent(name="x", handler=lambda **_: "", auth="nope").app()
