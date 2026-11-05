# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Web identities (spec §4.7): an HTTPS URL that publishes its signing key as a mandate party.

The shared cases come from packages/aroha-credentials/test-vectors/
web-identity-v1.json, the file the TypeScript SDK is checked against, so both
accept and refuse the same identifiers and documents. That file lives in the
monorepo, not in the wheel: the vector tests are skipped when it is absent
(set AROHA_WEB_IDENTITY_VECTORS to run them standalone). The rest covers
limits, the cache, the standard-library fetch and mandates end to end.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import aroha
from aroha.identity import to_multibase
from aroha.mandate import (
    SpendingConstraints,
    attenuate_to_cart,
    attenuate_to_payment,
    create_mandate_key_resolver,
    issue_intent_mandate,
    verify_mandate_chain,
)
from aroha.web_identity import (
    WEB_IDENTITY_MAX_DOCUMENT_BYTES,
    WebIdentityResponse,
    build_web_identity_document,
    check_web_identity,
    create_web_identity_resolver,
    ed25519_jwk_thumbprint,
    ed25519_public_key_to_jwk,
    is_special_use_address,
    is_web_identity,
    jwk_to_ed25519_public_key,
    looks_like_web_identity,
    resolve_web_identity,
    select_web_identity_key,
)


def _find_vectors() -> Optional[Path]:
    env = os.environ.get("AROHA_WEB_IDENTITY_VECTORS")
    if env:
        return Path(env)
    for parent in Path(__file__).resolve().parents:
        cand = parent / "packages" / "aroha-credentials" / "test-vectors" / "web-identity-v1.json"
        if cand.is_file():
            return cand
    return None


VECTORS_PATH = _find_vectors()
needs_vectors = pytest.mark.skipif(
    VECTORS_PATH is None,
    reason="web-identity-v1.json not found (only present in the monorepo checkout; "
    "set AROHA_WEB_IDENTITY_VECTORS to run these conformance tests standalone)",
)
V: dict[str, Any] = (
    json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    if VECTORS_PATH
    else {"identifiers": [], "loopbackIdentifiers": [], "thumbprints": [], "addresses": [], "documents": []}
)

ID = "https://agents.example.com/shopper"
HUMAN = "https://accounts.example.com/people/kiri"
ASSISTANT = "https://agents.example.com/assistant"
SHOP = "https://shop.example.net/agents/checkout"


class Party:
    def __init__(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TableFetch:
    """A fetch answering from a table of URL -> response, 404 otherwise, recording every request."""

    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str, timeout_s: float, max_bytes: int) -> WebIdentityResponse:
        self.calls.append(url)
        r = self.responses.get(url)
        if r is None:
            return WebIdentityResponse(404, b"not found")
        body = r["bodyText"] if "bodyText" in r else json.dumps(r.get("body"))
        headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
        return WebIdentityResponse(r["status"], body.encode("utf-8"), headers.get("cache-control"))


def serve(identities: dict[str, bytes], headers: Optional[dict[str, str]] = None) -> TableFetch:
    return TableFetch({
        identity: {"status": 200, "headers": headers or {}, "body": build_web_identity_document(identity, key)}
        for identity, key in identities.items()
    })


# ── Shared vectors ────────────────────────────────────────────────────────────

@needs_vectors
@pytest.mark.parametrize("case", V["identifiers"], ids=lambda c: c["note"])
def test_vector_identifiers(case: dict[str, Any]) -> None:
    assert is_web_identity(case["id"]) is case["valid"], case["id"]
    assert (check_web_identity(case["id"]) is None) is case["valid"]


@needs_vectors
@pytest.mark.parametrize("case", V["loopbackIdentifiers"], ids=lambda c: c["note"])
def test_vector_loopback_identifiers(case: dict[str, Any]) -> None:
    assert is_web_identity(case["id"], allow_loopback_http=True) is case["valid"], case["id"]
    if case["id"].startswith("http://"):
        assert is_web_identity(case["id"]) is False


@needs_vectors
@pytest.mark.parametrize("case", V["thumbprints"], ids=lambda c: c["publicKeyHex"][:16])
def test_vector_thumbprints(case: dict[str, Any]) -> None:
    key = bytes.fromhex(case["publicKeyHex"])
    assert ed25519_jwk_thumbprint(key) == case["thumbprint"]
    assert ed25519_public_key_to_jwk(key) == {
        "kty": "OKP", "crv": "Ed25519", "x": case["x"], "kid": case["thumbprint"], "use": "sig", "alg": "EdDSA",
    }
    assert jwk_to_ed25519_public_key({"kty": "OKP", "crv": "Ed25519", "x": case["x"]}) == key


@needs_vectors
@pytest.mark.parametrize("case", V["documents"], ids=lambda c: c["name"])
def test_vector_documents(case: dict[str, Any]) -> None:
    fetch = TableFetch(case["responses"])
    r = resolve_web_identity(case["identity"], fetch=fetch)
    resolver_key = create_web_identity_resolver(fetch=TableFetch(case["responses"]))(case["identity"])
    if case["expect"].get("error"):
        assert r.ok is False, "resolved"
        assert r.reason
        assert resolver_key is None
    else:
        assert r.ok is True, r.reason
        assert r.key is not None and r.key.hex() == case["expect"]["keyHex"]
        assert r.kid == case["expect"].get("kid")
        assert resolver_key is not None and resolver_key.hex() == case["expect"]["keyHex"]


def test_identifier_rejects_non_strings_and_long_strings() -> None:
    for bad in (None, 7, {}, ["https://example.com/a"], b"https://example.com/a"):
        assert is_web_identity(bad) is False
    assert is_web_identity("https://example.com/" + "a" * 2048) is False
    assert is_web_identity("https://xn--a-ecp.example/agent") in (True, False)  # decodable or not, never raises
    assert looks_like_web_identity("https://Example.com") is True
    assert looks_like_web_identity("did:aroha:zabc") is False
    assert looks_like_web_identity(None) is False


def test_key_helpers_reject_bad_keys() -> None:
    with pytest.raises(TypeError):
        ed25519_jwk_thumbprint(b"\x00" * 31)
    a = Party()
    assert ed25519_jwk_thumbprint(a.priv.public_key()) == ed25519_jwk_thumbprint(a.pub)
    # A non-canonical spelling of the same 32 bytes is not a key.
    x = ed25519_public_key_to_jwk(a.pub)["x"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    twin = x[:-1] + alphabet[alphabet.index(x[-1]) + 1]
    assert jwk_to_ed25519_public_key({"kty": "OKP", "crv": "Ed25519", "x": twin}) is None
    assert select_web_identity_key(None).reason == "key set has no keys array"
    assert select_web_identity_key({"keys": []}).reason == "key set has no Ed25519 signing key"
    assert select_web_identity_key({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}).reason == "key set contains private key material"


# ── Requests and limits ───────────────────────────────────────────────────────

def test_no_request_for_an_identifier_that_is_not_a_web_identity() -> None:
    fetch = TableFetch({})
    resolver = create_web_identity_resolver(fetch=fetch)
    for bad in ("https://169.254.169.254/latest/meta-data", "https://localhost/a", "http://agents.example.com/a",
                "https://example.com/a?x=1", "did:aroha:zNotAKey", "agent-7"):
        assert resolver(bad) is None
        assert resolve_web_identity(bad, fetch=fetch).ok is False
    assert fetch.calls == []


def test_size_caps() -> None:
    a = Party()
    doc = {**build_web_identity_document(ID, a.pub), "pad": "x" * WEB_IDENTITY_MAX_DOCUMENT_BYTES}
    fetch = TableFetch({ID: {"status": 200, "headers": {}, "body": doc}})
    r = resolve_web_identity(ID, fetch=fetch)
    assert r.ok is False and "more than 5120 bytes" in (r.reason or "")
    assert resolve_web_identity(ID, fetch=fetch, max_document_bytes=64 * 1024).ok is True

    keys_url = "https://keys.example.com/jwks.json"
    table = TableFetch({
        ID: {"status": 200, "headers": {}, "body": {"client_id": ID, "jwks_uri": keys_url}},
        keys_url: {"status": 200, "headers": {}, "body": {"keys": [ed25519_public_key_to_jwk(a.pub)], "pad": "x" * 4096}},
    })
    assert resolve_web_identity(ID, fetch=table).ok is True
    assert resolve_web_identity(ID, fetch=table, max_jwks_bytes=1024).ok is False


def test_fails_closed_when_fetch_raises_or_returns_garbage() -> None:
    def boom(url: str, timeout_s: float, max_bytes: int) -> WebIdentityResponse:
        raise OSError("network down")

    assert resolve_web_identity(ID, fetch=boom).ok is False
    assert create_web_identity_resolver(fetch=boom)(ID) is None
    not_utf8 = lambda url, t, m: WebIdentityResponse(200, b"\xff\xfe\x00")  # noqa: E731
    assert resolve_web_identity(ID, fetch=not_utf8).ok is False


def test_allow_host_is_asked_before_each_request() -> None:
    a = Party()
    keys_url = "https://keys.example.net/jwks.json"
    table = {
        ID: {"status": 200, "headers": {}, "body": {"client_id": ID, "jwks_uri": keys_url}},
        keys_url: {"status": 200, "headers": {}, "body": {"keys": [ed25519_public_key_to_jwk(a.pub)]}},
    }
    asked: list[str] = []
    assert resolve_web_identity(ID, fetch=TableFetch(table), allow_host=lambda h: asked.append(h) or True).ok is True
    assert asked == ["agents.example.com", "keys.example.net"]

    none = TableFetch(table)
    assert resolve_web_identity(ID, fetch=none, allow_host=lambda h: False).ok is False
    assert none.calls == []

    no_keys = TableFetch(table)
    assert resolve_web_identity(ID, fetch=no_keys, allow_host=lambda h: h == "agents.example.com").ok is False
    assert no_keys.calls == [ID]


def test_on_failure_reports_the_reason_and_may_raise() -> None:
    reasons: list[str] = []
    assert create_web_identity_resolver(fetch=TableFetch({}), on_failure=lambda i, why: reasons.append(f"{i}: {why}"))(ID) is None
    assert reasons == [f"{ID}: GET {ID} did not return HTTP 200"]

    def broken(identity: str, reason: str) -> None:
        raise RuntimeError("logger broke")

    assert create_web_identity_resolver(fetch=TableFetch({}), on_failure=broken)(ID) is None


# ── Address check ─────────────────────────────────────────────────────────────

@needs_vectors
@pytest.mark.parametrize("case", V["addresses"], ids=lambda c: f"{c['address']} ({c['note']})")
def test_vector_addresses(case: dict[str, Any]) -> None:
    assert is_special_use_address(case["address"]) is case["specialUse"], case["address"]


def test_special_use_rejects_non_strings() -> None:
    for bad in (None, 7, b"10.0.0.5", ["10.0.0.5"]):
        assert is_special_use_address(bad) is True


@pytest.mark.parametrize("answer", [["10.0.0.5"], ["169.254.169.254"], ["::1"], ["93.184.215.14", "127.0.0.1"], ["::ffff:192.168.1.1"], ["not-an-address"]])
def test_host_resolving_to_a_special_use_address_is_refused_without_a_request(answer: list[str]) -> None:
    a = Party()
    fetch = serve({ID: a.pub})
    r = resolve_web_identity(ID, fetch=fetch, lookup=lambda hostname: answer)
    assert r.ok is False and "special-use address" in (r.reason or "")
    assert fetch.calls == []


def test_host_whose_lookup_fails_is_refused() -> None:
    a = Party()
    fetch = serve({ID: a.pub})

    def failing(hostname: str) -> list[str]:
        raise OSError("name or service not known")

    r = resolve_web_identity(ID, fetch=fetch, lookup=failing)
    assert r.ok is False and "could not be resolved" in (r.reason or "")
    assert resolve_web_identity(ID, fetch=fetch, lookup=lambda hostname: []).ok is False
    assert fetch.calls == []


def test_key_set_host_is_checked_too_and_allow_host_runs_first() -> None:
    a = Party()
    keys_url = "https://keys.example.net/jwks.json"
    table = {
        ID: {"status": 200, "headers": {}, "body": {"client_id": ID, "jwks_uri": keys_url}},
        keys_url: {"status": 200, "headers": {}, "body": {"keys": [ed25519_public_key_to_jwk(a.pub)]}},
    }
    looked: list[str] = []

    def public(hostname: str) -> list[str]:
        looked.append(hostname)
        return ["93.184.215.14"]

    assert resolve_web_identity(ID, fetch=TableFetch(table), lookup=public).ok is True
    assert looked == ["agents.example.com", "keys.example.net"]

    internal_keys = TableFetch(table)
    r = resolve_web_identity(ID, fetch=internal_keys, lookup=lambda h: ["10.1.2.3"] if h == "keys.example.net" else ["93.184.215.14"])
    assert r.ok is False
    assert internal_keys.calls == [ID]

    looked.clear()
    resolve_web_identity(ID, fetch=TableFetch(table), allow_host=lambda h: False, lookup=public)
    assert looked == []


def test_no_lookup_with_a_custom_fetch_or_when_turned_off(monkeypatch: pytest.MonkeyPatch) -> None:
    a = Party()

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the system resolver must not be used here")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    assert resolve_web_identity(ID, fetch=serve({ID: a.pub})).ok is True
    assert resolve_web_identity(ID, fetch=serve({ID: a.pub}), lookup=False).ok is True


def test_built_in_fetch_uses_the_system_resolver_and_refuses_an_internal_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def getaddrinfo(host: str, *args: Any, **kwargs: Any) -> list[Any]:
        asked.append(host)
        return [(2, 1, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr("socket.getaddrinfo", getaddrinfo)
    # No fetch is passed, so the built-in one would be used; the address check stops it first.
    r = resolve_web_identity(ID)
    assert r.ok is False and "special-use address" in (r.reason or "")
    assert asked == ["agents.example.com"]

    def unresolvable(host: str, *args: Any, **kwargs: Any) -> list[Any]:
        raise OSError("name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", unresolvable)
    r = resolve_web_identity(ID)
    assert r.ok is False and "could not be resolved" in (r.reason or "")


# ── Cache ─────────────────────────────────────────────────────────────────────

class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_cache_reuses_a_key_for_five_minutes_then_asks_again() -> None:
    a, b, clock = Party(), Party(), Clock()
    fetch = serve({ID: a.pub})
    resolver = create_web_identity_resolver(fetch=fetch, now=clock)
    assert resolver(ID) == a.pub
    fetch.responses[ID]["body"] = build_web_identity_document(ID, b.pub)
    clock.t += 299.9
    assert resolver(ID) == a.pub
    assert len(fetch.calls) == 1
    clock.t += 0.2
    assert resolver(ID) == b.pub
    assert len(fetch.calls) == 2


def test_cache_honours_a_shorter_max_age_but_never_a_longer_one() -> None:
    a, clock = Party(), Clock()
    short = serve({ID: a.pub}, {"Cache-Control": "public, max-age=10"})
    resolver = create_web_identity_resolver(fetch=short, now=clock)
    resolver(ID)
    clock.t += 10.1
    resolver(ID)
    assert len(short.calls) == 2

    long = serve({ID: a.pub}, {"Cache-Control": "max-age=86400"})
    resolver = create_web_identity_resolver(fetch=long, now=clock, max_cache_s=60)
    resolver(ID)
    clock.t += 60.1
    resolver(ID)
    assert len(long.calls) == 2


@pytest.mark.parametrize("headers,max_cache_s", [({"Cache-Control": "no-store"}, 300.0), ({"Cache-Control": "no-cache"}, 300.0), ({}, 0.0)])
def test_cache_can_be_disabled(headers: dict[str, str], max_cache_s: float) -> None:
    a = Party()
    fetch = serve({ID: a.pub}, headers)
    resolver = create_web_identity_resolver(fetch=fetch, max_cache_s=max_cache_s)
    resolver(ID)
    resolver(ID)
    assert len(fetch.calls) == 2


def test_cache_never_holds_a_failure() -> None:
    a = Party()
    fetch = serve({ID: a.pub})
    doc = fetch.responses.pop(ID)
    resolver = create_web_identity_resolver(fetch=fetch)
    assert resolver(ID) is None
    fetch.responses[ID] = doc
    assert resolver(ID) == a.pub


# ── Publishing ────────────────────────────────────────────────────────────────

def test_build_document_round_trips_and_refuses_bad_input() -> None:
    a = Party()
    doc = build_web_identity_document(ID, a.pub, name="Shopper", uri="https://agents.example.com", extra={"token_endpoint_auth_method": "private_key_jwt"})
    assert doc == {
        "token_endpoint_auth_method": "private_key_jwt",
        "client_id": ID,
        "client_name": "Shopper",
        "client_uri": "https://agents.example.com",
        "jwks": {"keys": [ed25519_public_key_to_jwk(a.pub)]},
    }
    assert len(json.dumps(doc)) < WEB_IDENTITY_MAX_DOCUMENT_BYTES
    r = resolve_web_identity(ID, fetch=TableFetch({ID: {"status": 200, "headers": {}, "body": doc}}))
    assert r.ok and r.key == a.pub and r.kid == ed25519_jwk_thumbprint(a.pub)

    with pytest.raises(ValueError, match="path other than"):
        build_web_identity_document("https://example.com/", a.pub)
    with pytest.raises(ValueError):
        build_web_identity_document("http://localhost:8787/agent", a.pub)
    assert build_web_identity_document("http://localhost:8787/agent", a.pub, allow_loopback_http=True)["client_id"] == "http://localhost:8787/agent"
    with pytest.raises(TypeError):
        build_web_identity_document(ID, b"\x00" * 16)
    for member in ("client_id", "jwks", "jwks_uri", "client_secret", "client_secret_expires_at"):
        with pytest.raises(ValueError, match="extra must not set"):
            build_web_identity_document(ID, a.pub, extra={member: "x"})


def test_package_root_exports() -> None:
    for name in ("is_web_identity", "check_web_identity", "build_web_identity_document", "resolve_web_identity", "create_web_identity_resolver"):
        assert getattr(aroha, name) is globals().get(name, getattr(aroha, name))
        assert name in aroha.__all__


# ── Standard-library fetch against a real loopback server ─────────────────────

class _Handler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def do_GET(self) -> None:  # noqa: N802
        status, headers, body = self.routes.get(self.path, (404, {}, b"not found"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:  # silence the test output
        pass


@pytest.fixture()
def loopback():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.routes = {}
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_default_fetch_over_loopback(loopback: str) -> None:
    a = Party()
    identity = f"{loopback}/agents/shopper"
    doc = json.dumps(build_web_identity_document(identity, a.pub, allow_loopback_http=True)).encode()
    _Handler.routes = {
        "/agents/shopper": (200, {"Content-Type": "application/json", "Cache-Control": "max-age=30"}, doc),
        "/agents/moved": (302, {"Location": f"{loopback}/agents/shopper"}, b""),
        "/agents/huge": (200, {"Content-Type": "application/json"}, b" " * (WEB_IDENTITY_MAX_DOCUMENT_BYTES + 1)),
    }
    # Refused without the development option, with no request made.
    assert resolve_web_identity(identity).ok is False

    r = resolve_web_identity(identity, allow_loopback_http=True)
    assert r.ok is True, r.reason
    assert r.key == a.pub

    # A redirect is reported, never followed (following it would reach the real document).
    moved = resolve_web_identity(f"{loopback}/agents/moved", allow_loopback_http=True)
    assert moved.ok is False and "did not return HTTP 200" in (moved.reason or "")
    missing = resolve_web_identity(f"{loopback}/agents/missing", allow_loopback_http=True)
    assert missing.ok is False and "did not return HTTP 200" in (missing.reason or "")
    huge = resolve_web_identity(f"{loopback}/agents/huge", allow_loopback_http=True)
    assert huge.ok is False and "more than" in (huge.reason or "")


def test_default_fetch_gives_up_on_a_host_that_drips(loopback: str) -> None:
    import time as _time

    identity = f"{loopback}/agents/drip"

    class Drip(_Handler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "5000")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    _time.sleep(0.1)
            except OSError:
                pass

    original = _Handler.do_GET
    _Handler.do_GET = Drip.do_GET  # type: ignore[method-assign]
    try:
        started = _time.monotonic()
        r = resolve_web_identity(identity, allow_loopback_http=True, timeout_s=0.4)
        assert r.ok is False
        assert _time.monotonic() - started < 3
    finally:
        _Handler.do_GET = original  # type: ignore[method-assign]


# ── Mandates end to end ───────────────────────────────────────────────────────

def test_spending_chain_between_web_identities() -> None:
    human, assistant, shop = Party(), Party(), Party()
    fetch = serve({HUMAN: human.pub, ASSISTANT: assistant.pub, SHOP: shop.pub})
    intent = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=200, currency="USD"), human.priv)
    cart = attenuate_to_cart(intent, SHOP, SpendingConstraints(spend_limit_usd=80, currency="USD"), assistant.priv)
    payment = attenuate_to_payment(cart, SHOP, SpendingConstraints(spend_limit_usd=42.5, currency="USD"), shop.priv)

    resolve_key = create_mandate_key_resolver(web=create_web_identity_resolver(fetch=fetch))
    r = verify_mandate_chain(payment.token, resolve_key, expected_root=HUMAN, expected_grantee=SHOP)
    assert r.valid, r.reason
    assert r.chain_verified is True
    assert r.root_grantor == HUMAN
    assert sorted(fetch.calls) == sorted([HUMAN, ASSISTANT, SHOP])

    verify_mandate_chain(payment.token, resolve_key, expected_root=HUMAN)
    assert len(fetch.calls) == 3  # answered from the cache


def test_chain_mixing_did_and_web_identities() -> None:
    human, assistant, worker = Party(), Party(), Party()
    human_did, worker_did = "did:aroha:" + to_multibase(human.pub), "did:aroha:" + to_multibase(worker.pub)
    fetch = serve({ASSISTANT: assistant.pub})
    intent = issue_intent_mandate(human_did, ASSISTANT, SpendingConstraints(spend_limit_usd=100, currency="USD"), human.priv)
    cart = attenuate_to_cart(intent, worker_did, SpendingConstraints(spend_limit_usd=60, currency="USD"), assistant.priv)
    r = verify_mandate_chain(cart.token, create_mandate_key_resolver(web=create_web_identity_resolver(fetch=fetch)),
                             expected_root=human_did, expected_grantee=worker_did)
    assert r.valid, r.reason


def test_web_resolution_is_off_by_default() -> None:
    human = Party()
    intent = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=50, currency="USD"), human.priv)
    for resolve_key in (None, create_mandate_key_resolver(), create_mandate_key_resolver(web=False)):
        assert verify_mandate_chain(intent.token, resolve_key).valid is False


def test_fallback_answers_web_identities_only_when_web_is_off() -> None:
    human, other = Party(), Party()
    fetch = serve({HUMAN: other.pub})  # the URL publishes a DIFFERENT key
    intent = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=50, currency="USD"), human.priv)
    seen: list[str] = []

    def fallback(identity: str) -> bytes:
        seen.append(identity)
        return human.pub

    assert verify_mandate_chain(intent.token, create_mandate_key_resolver(fallback=fallback)).valid is True
    assert seen == [HUMAN]
    web = create_mandate_key_resolver(web=create_web_identity_resolver(fetch=fetch), fallback=fallback)
    assert verify_mandate_chain(intent.token, web).valid is False
    assert seen == [HUMAN]


def test_forged_and_rotated_keys_are_refused() -> None:
    human, thief, nxt, clock = Party(), Party(), Party(), Clock()
    fetch = serve({HUMAN: human.pub})
    resolve_key = create_mandate_key_resolver(web=create_web_identity_resolver(fetch=fetch, now=clock))

    forged = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=5000, currency="USD"), thief.priv)
    assert verify_mandate_chain(forged.token, resolve_key).valid is False

    intent = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=50, currency="USD"), human.priv)
    assert verify_mandate_chain(intent.token, resolve_key).valid is True
    fetch.responses[HUMAN]["body"] = build_web_identity_document(HUMAN, nxt.pub)
    clock.t += 300.1  # past the cache lifetime
    assert verify_mandate_chain(intent.token, resolve_key).valid is False


def test_chain_is_refused_when_an_intermediate_identity_cannot_be_fetched() -> None:
    human, assistant = Party(), Party()
    fetch = serve({HUMAN: human.pub})  # ASSISTANT publishes nothing
    intent = issue_intent_mandate(HUMAN, ASSISTANT, SpendingConstraints(spend_limit_usd=200, currency="USD"), human.priv)
    cart = attenuate_to_cart(intent, SHOP, SpendingConstraints(spend_limit_usd=80, currency="USD"), assistant.priv)
    assert verify_mandate_chain(cart.token, create_mandate_key_resolver(web=create_web_identity_resolver(fetch=fetch))).valid is False
