# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""did:aroha-web resolution: port of aroha-core resolveWebDID (TS parity is in test_cross_language.py)."""

import copy
import http.server
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.timeutil import iso_ms, to_ms
from aroha.web_did import (
    WebDIDError,
    _default_fetch,
    check_key_rotation,
    generate_web_agent,
    key_commitment_hash,
    parse_web_did,
    resolve_web_did,
    rotate_key,
    rotation_signing_payload,
    select_web_did_key,
    web_did_public_keys,
)

QUIET = {"logger": lambda m: None}


def serve(doc):
    return lambda url, timeout, cap: json.dumps(doc).encode()


def txt(*records):
    return lambda domain: list(records)


# ── Parsing ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("did", [
    "did:aroha-web:10.0.0.5:agent",
    "did:aroha-web:evil.com@10.0.0.5:agent",
    "did:aroha-web:example.com%2e:agent",
    "did:aroha-web:-bad.com:agent",
    "did:aroha-web:example.123:agent",
    "did:aroha-web:example.com:..:x",
    "did:aroha-web:example.com:Agents",
    "did:aroha-web:example.com:a?b",
    "did:aroha-web:",
])
def test_parse_rejects_non_hostnames_and_bad_paths(did):
    with pytest.raises(WebDIDError):
        parse_web_did(did)


def test_parse_accepts_hostnames_and_opt_in_ipv4():
    assert parse_web_did("did:aroha-web:stripe.com:payments-agent") == ("stripe.com", "payments-agent")
    assert parse_web_did("did:aroha-web:example.com") == ("example.com", "agent")
    assert parse_web_did("did:aroha-web:example.com:agents:fx") == ("example.com", "agents/fx")
    assert parse_web_did("did:aroha-web:10.0.0.5:x", allow_ip_literal=True) == ("10.0.0.5", "x")
    with pytest.raises(WebDIDError):
        parse_web_did("did:aroha-web:300.0.0.5:x", allow_ip_literal=True)


# ── Resolution ────────────────────────────────────────────────────────────────

def test_genesis_document_has_ts_wire_shape_and_resolves():
    a = generate_web_agent("example.com", "agents/fx")
    vm = a.document["verificationMethod"][0]
    assert vm["publicKeyMultibase"].startswith("z")
    assert a.document["arohaWeb"]["keyCommitmentHash"] == key_commitment_hash(a.public_key)
    r = resolve_web_did(a.did, fetch=serve(a.document), dns_resolver=txt(a.dns_txt_record), **QUIET)
    assert r.dns_verified and r.key_trusted
    assert select_web_did_key(r) == a.public_key


def test_dns_skipped_reports_dns_verified_false():
    a = generate_web_agent("example.com", "x")
    logs = []
    r = resolve_web_did(a.did, verify_dns=False, fetch=serve(a.document), logger=logs.append)
    assert r.dns_verified is False and r.key_trusted
    assert any("HTTPS-only" in m for m in logs)


def test_no_dns_resolver_fails_closed_unless_allowed():
    a = generate_web_agent("example.com", "x")
    with pytest.raises(WebDIDError, match="no DNS resolver"):
        resolve_web_did(a.did, fetch=serve(a.document), use_system_dns=False, **QUIET)
    r = resolve_web_did(a.did, fetch=serve(a.document), use_system_dns=False, allow_no_dns=True, **QUIET)
    assert r.dns_verified is False


def test_dns_for_another_key_accepts_nothing():
    a, other = generate_web_agent("example.com", "x"), generate_web_agent("example.com", "x")
    r = resolve_web_did(a.did, fetch=serve(a.document), dns_resolver=txt(other.dns_txt_record), **QUIET)
    assert not r.dns_verified and not r.key_trusted and r.accepted_keys == []
    with pytest.raises(WebDIDError, match="no accepted key"):
        select_web_did_key(r)
    # A DNS lookup that fails is a miss, not a pass.
    def boom(_):
        raise OSError("SERVFAIL")
    assert resolve_web_did(a.did, fetch=serve(a.document), dns_resolver=boom, **QUIET).accepted_keys == []


def test_self_declared_hash_must_match_the_key():
    a, other = generate_web_agent("example.com", "x"), generate_web_agent("example.com", "x")
    doc = copy.deepcopy(a.document)
    doc["verificationMethod"][0]["publicKeyMultibase"] = other.document["verificationMethod"][0]["publicKeyMultibase"]
    with pytest.raises(WebDIDError, match="keyCommitmentHash does not match"):
        resolve_web_did(a.did, fetch=serve(doc), dns_resolver=txt(a.dns_txt_record), **QUIET)
    # Without the declared hash, the key is still hashed and compared with DNS.
    del doc["arohaWeb"]["keyCommitmentHash"]
    r = resolve_web_did(a.did, fetch=serve(doc), dns_resolver=txt(a.dns_txt_record), **QUIET)
    assert r.accepted_keys == []


def test_document_for_another_did_is_rejected():
    a, b = generate_web_agent("example.com", "x"), generate_web_agent("example.com", "y")
    with pytest.raises(WebDIDError, match="DID mismatch"):
        resolve_web_did(a.did, fetch=serve(b.document), dns_resolver=txt(b.dns_txt_record), **QUIET)


def test_rotation_cutover_and_anchored_cool_down():
    a = generate_web_agent("example.com", "x")
    t0 = datetime.now(timezone.utc)
    b = rotate_key(a, 24, now=t0)
    hist = b.document["arohaWeb"]["keyHistory"]
    assert hist[0]["v"] == 2 and hist[0]["did"] == a.did
    soon, later = to_ms(t0) + 1000, to_ms(t0 + timedelta(hours=25))
    # DNS updated → current + predecessor during cool-down.
    r = resolve_web_did(b.did, fetch=serve(b.document), dns_resolver=txt(b.dns_txt_record), now=soon, **QUIET)
    assert [k.role for k in r.accepted_keys] == ["current", "predecessor"] and not r.key_trusted
    assert web_did_public_keys(r) == [b.public_key, a.public_key]
    # DNS still on the old key → old key until the cool-down ends, then the new one.
    r = resolve_web_did(b.did, fetch=serve(b.document), dns_resolver=txt(a.dns_txt_record), now=soon, **QUIET)
    assert [k.role for k in r.accepted_keys] == ["anchored"] and r.accepted_keys[0].public_key_multibase == to_multibase(a.public_key)
    r = resolve_web_did(b.did, fetch=serve(b.document), dns_resolver=txt(a.dns_txt_record), now=later, **QUIET)
    assert r.key_trusted and select_web_did_key(r) == b.public_key


def test_stripped_or_tampered_history_is_rejected():
    a = generate_web_agent("example.com", "x")
    b = rotate_key(a)
    stripped = copy.deepcopy(b.document)
    stripped["arohaWeb"]["keyHistory"] = []
    r = resolve_web_did(b.did, fetch=serve(stripped), dns_resolver=txt(a.dns_txt_record), **QUIET)
    assert r.accepted_keys == []
    shortened = copy.deepcopy(b.document)
    shortened["arohaWeb"]["keyHistory"][0]["trustAfter"] = shortened["arohaWeb"]["keyHistory"][0]["rotatedAt"]
    with pytest.raises(WebDIDError, match="invalid predecessor signature"):
        resolve_web_did(b.did, fetch=serve(shortened), dns_resolver=txt(a.dns_txt_record), **QUIET)
    # A record signed for another DID cannot be lifted into this one.
    lifted = copy.deepcopy(b.document)
    lifted["id"] = "did:aroha-web:example.com:y"
    with pytest.raises(WebDIDError, match="was signed for"):
        resolve_web_did("did:aroha-web:example.com:y", fetch=serve(lifted), dns_resolver=txt(a.dns_txt_record), **QUIET)


def test_rotation_payloads_v1_and_v2():
    rec = {"v": 2, "did": "did:aroha-web:e.com:x", "newKeyHash": "ab", "predecessorKey": "zK",
           "rotatedAt": "2026-01-01T00:00:00.000Z", "trustAfter": "2026-01-02T00:00:00.000Z"}
    assert rotation_signing_payload(rec) == (
        b'{"did":"did:aroha-web:e.com:x","newKeyHash":"ab","predecessorKey":"zK",'
        b'"rotatedAt":"2026-01-01T00:00:00.000Z","trustAfter":"2026-01-02T00:00:00.000Z","v":2}')
    v1 = {k: rec[k] for k in ("newKeyHash", "predecessorKey", "rotatedAt", "trustAfter")}
    assert rotation_signing_payload(v1) == b"zKab2026-01-01T00:00:00.000Z"
    assert check_key_rotation({**rec, "v": 3})[2] == "has unsupported version 3"


def test_legacy_v1_record_cannot_shorten_the_cool_down():
    old = Ed25519PrivateKey.generate()
    old_pub = old.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    a = generate_web_agent("example.com", "x")
    t0 = datetime.now(timezone.utc)
    rec = {"rotatedAt": iso_ms(t0), "trustAfter": iso_ms(t0),  # unsigned zero cool-down
           "predecessorKey": to_multibase(old_pub), "newKeyHash": key_commitment_hash(a.public_key)}
    rec["predecessorSignature"] = __import__("base64").urlsafe_b64encode(
        old.sign(rotation_signing_payload(rec))).rstrip(b"=").decode()
    doc = copy.deepcopy(a.document)
    doc["arohaWeb"]["keyHistory"] = [rec]
    old_txt = f"v=aroha1; path=x; keyhash={key_commitment_hash(old_pub)}"
    logs = []
    r = resolve_web_did(a.did, fetch=serve(doc), dns_resolver=txt(old_txt), now=to_ms(t0) + 60_000, logger=logs.append)
    assert r.deprecated_rotations and not r.key_trusted and r.accepted_keys[0].role == "anchored"
    assert any("legacy v1" in m for m in logs)


def test_document_size_cap_applies_to_injected_fetch():
    a = generate_web_agent("example.com", "x")
    with pytest.raises(WebDIDError, match="too large"):
        resolve_web_did(a.did, fetch=lambda u, t, m: b" " * (m + 1), dns_resolver=txt(a.dns_txt_record), **QUIET)


# ── Default fetcher: no redirects, size cap ───────────────────────────────────

class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
        elif self.path == "/big":
            body = b" " * (64 * 1024 + 1)
            self.send_response(200)
            self.end_headers()  # no Content-Length: the streamed cap must apply
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")


@pytest.fixture
def local_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_default_fetch_refuses_redirects_and_caps_size(local_server):
    assert _default_fetch(local_server + "/ok", 5, 64 * 1024) == b"{}"
    with pytest.raises(WebDIDError, match="redirect"):
        _default_fetch(local_server + "/redirect", 5, 64 * 1024)
    with pytest.raises(WebDIDError, match="too large"):
        _default_fetch(local_server + "/big", 5, 64 * 1024)


# ── Fixed TypeScript vector (tests/web_did_ts_vector.json, shared with Go and Java) ──

def test_typescript_vector_resolves_identically():
    from pathlib import Path
    vec = json.loads((Path(__file__).parent / "web_did_ts_vector.json").read_text(encoding="utf-8"))
    assert len(vec["cases"]) == 12
    for case in vec["cases"]:
        r = resolve_web_did(vec["did"], fetch=serve(vec["document"]), dns_resolver=txt(*case["txt"]),
                            now=case["nowMs"], **QUIET)
        got = {"dnsVerified": r.dns_verified, "keyTrusted": r.key_trusted,
               "acceptedKeys": [{"verificationMethodId": k.verification_method_id,
                                 "publicKeyMultibase": k.public_key_multibase, "role": k.role} for k in r.accepted_keys]}
        assert got == case["expect"], (case["name"], case["nowMs"])
