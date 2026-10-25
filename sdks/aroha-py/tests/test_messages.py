# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Envelope build/validate parity with aroha-core/src/messages/envelope.ts.

PINNED_* is a fixed-key envelope vector (private key = 32 bytes of 0x07).
The canonical string is the TypeScript ``JSON.stringify(sortKeysDeep(env))``
bytes; test_cross_language.py re-derives it with the built TS package when
node is available.
"""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.crypto import canonicalize_message, sign_message
from aroha.identity import generate_did, to_multibase
from aroha.messages import (
    MESSAGE_TYPES,
    ArohaErrorCode,
    NonceRegistry,
    build_envelope,
    validate_envelope,
)
from aroha.timeutil import iso_ms

PINNED_KEY = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
PINNED_PUB = PINNED_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
PINNED_ENVELOPE = {
    "@context": ["https://aroha-labs.com/contexts/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
    "type": "ArohaRequest",
    "from": "did:aroha:sender",
    "to": "did:aroha:receiver",
    "created": "2026-01-01T00:00:00.000Z",
    "expires": "2026-01-01T00:05:00.000Z",
    "nonce": "ab" * 32,
    "correlationId": "saga-1",
    "body": {"capability": "quote",
             "params": {"amount": 10.0, "ratio": 0.1, "big": 1e21, "note": "café", "10": 1, "9": 2}},
}
PINNED_CANONICAL = (
    '{"@context":["https://aroha-labs.com/contexts/v1","https://w3id.org/security/suites/ed25519-2020/v1"],'
    '"body":{"capability":"quote","params":{"9":2,"10":1,"amount":10,"big":1e+21,"note":"café","ratio":0.1}},'
    '"correlationId":"saga-1","created":"2026-01-01T00:00:00.000Z","expires":"2026-01-01T00:05:00.000Z",'
    '"from":"did:aroha:sender","id":"urn:uuid:00000000-0000-4000-8000-000000000001",'
    '"nonce":"abababababababababababababababababababababababababababababababab","to":"did:aroha:receiver",'
    '"type":"ArohaRequest"}'
)
PINNED_SIGNATURE = "NwIsk5N2gw4jrUaB8NJuUEXq7IudNP0s30ZFtfLWcnM6gtUvebFhqc0GoTs4Yn-rNIVQocyA60m4f-yQAEj7Dg"
PINNED_NOW = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_pinned_canonical_form_and_signature():
    assert canonicalize_message({**PINNED_ENVELOPE, "proof": {"ignored": True}}) == PINNED_CANONICAL
    assert b64u(PINNED_KEY.sign(PINNED_CANONICAL.encode())) == PINNED_SIGNATURE
    env = {**PINNED_ENVELOPE, "proof": {"type": "Ed25519Signature2020", "created": "2026-01-01T00:00:00.000Z",
                                        "verificationMethod": "did:aroha:sender#key-1",
                                        "proofPurpose": "authentication", "proofValue": PINNED_SIGNATURE}}
    assert validate_envelope(env, PINNED_PUB, "did:aroha:receiver", NonceRegistry(), now=PINNED_NOW) == (True, None)


def keypair():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return k, pub, "did:aroha:" + to_multibase(pub)


def test_all_19_message_types_build():
    assert len(MESSAGE_TYPES) == 19
    k, pub, did = keypair()
    for t in sorted(MESSAGE_TYPES):
        env = build_envelope(t, did, "did:aroha:r", {}, "c", k)
        assert validate_envelope(env, pub, "did:aroha:r", NonceRegistry())[0], t
    with pytest.raises(ValueError):
        build_envelope("ArohaNope", did, "did:aroha:r", {}, "c", k)


def test_error_codes_match_typescript_enum():
    values = {c.value for c in ArohaErrorCode}
    assert len(values) == 28  # ArohaErrorCode in aroha-core/src/messages/types.ts
    for v in ("CSN_NO_STRUCTURAL_MATCH", "Aroha_ACTION_LIMIT_EXCEEDED", "Aroha_COMMIT_DISPUTED",
              "Aroha_SETTLEMENT_RAIL_MISMATCH", "Aroha_CAPABILITY_NOT_PERMITTED"):
        assert v in values


def test_timestamps_use_typescript_iso_format():
    k, _, did = keypair()
    env = build_envelope("ArohaRequest", did, "did:aroha:r", {}, "c", k)
    for f in (env["created"], env["expires"], env["proof"]["created"]):
        assert f.endswith("Z") and len(f) == 24


def _signed(k, did, to="did:aroha:r", created=None, expires=None, nonce="n1", vm=None, body=None):
    now = datetime.now(timezone.utc)
    env = {
        "@context": [], "id": "urn:uuid:x", "type": "ArohaRequest", "from": did, "to": to,
        "created": created if created is not None else iso_ms(now),
        "expires": expires if expires is not None else iso_ms(now + timedelta(seconds=60)),
        "nonce": nonce, "correlationId": "c", "body": body or {},
    }
    env["proof"] = sign_message(env, k, vm or f"{did}#key-1")
    return env


def test_check_order_and_reasons():
    k, pub, did = keypair()
    reg = NonceRegistry()
    now = datetime.now(timezone.utc)
    assert "addressed to" in validate_envelope(_signed(k, did), pub, "did:aroha:other", reg)[1]
    assert validate_envelope(_signed(k, did, created="garbage"), pub, "did:aroha:r", reg)[1] == \
        "Malformed created/expires timestamp"
    assert "expired" in validate_envelope(
        _signed(k, did, expires=iso_ms(now - timedelta(seconds=1))), pub, "did:aroha:r", reg)[1]
    assert "in the future" in validate_envelope(
        _signed(k, did, created=iso_ms(now + timedelta(minutes=2)), expires=iso_ms(now + timedelta(minutes=3))),
        pub, "did:aroha:r", reg)[1]
    assert "exceeds maximum 300000ms" in validate_envelope(
        _signed(k, did, expires=iso_ms(now + timedelta(days=30))), pub, "did:aroha:r", reg)[1]
    assert validate_envelope(_signed(k, did, nonce=""), pub, "did:aroha:r", reg)[1] == "Missing nonce"
    # Longer TTL only against a receiver that opts in.
    assert validate_envelope(_signed(k, did, expires=iso_ms(now + timedelta(hours=1))), pub, "did:aroha:r", reg,
                             max_ttl_ms=3_600_000 + 5_000)[0]
    # Clock tolerance accepts a just-expired envelope.
    assert validate_envelope(_signed(k, did, nonce="late", expires=iso_ms(now - timedelta(seconds=1))),
                             pub, "did:aroha:r", reg, clock_tolerance_ms=5_000)[0]
    assert validate_envelope(_signed(k, did), pub, "did:aroha:r", reg, clock_tolerance_ms=-1)[1].startswith("Invalid")


def test_forged_envelope_cannot_pre_burn_a_nonce():
    k, pub, did = keypair()
    thief, _, _ = keypair()
    reg = NonceRegistry()
    forged = _signed(thief, did, nonce="shared")
    assert validate_envelope(forged, pub, "did:aroha:r", reg) == (False, "Signature verification failed")
    honest = _signed(k, did, nonce="shared")
    assert validate_envelope(honest, pub, "did:aroha:r", reg) == (True, None)
    assert validate_envelope(honest, pub, "did:aroha:r", reg) == (False, "Nonce replay detected")


def test_nonces_are_scoped_per_sender():
    k1, pub1, did1 = keypair()
    k2, pub2, did2 = keypair()
    reg = NonceRegistry()
    assert validate_envelope(_signed(k1, did1, nonce="same"), pub1, "did:aroha:r", reg)[0]
    assert validate_envelope(_signed(k2, did2, nonce="same"), pub2, "did:aroha:r", reg)[0]


def test_proof_key_must_belong_to_from():
    k, pub, did = keypair()
    env = _signed(k, did, vm="did:aroha:someone-else#key-1")
    ok, reason = validate_envelope(env, pub, "did:aroha:r", NonceRegistry())
    assert not ok and "different DID" in reason


def test_did_document_sender_key():
    agent = generate_did("sender-doc", "http://localhost")
    env = build_envelope("ArohaRequest", agent["did"], "did:aroha:r", {}, "c", agent["private_key"])
    doc = agent["document"]
    assert validate_envelope(env, doc, "did:aroha:r", NonceRegistry()) == (True, None)
    other = generate_did("other-doc", "http://localhost")["document"]
    assert "does not match" in validate_envelope(env, other, "did:aroha:r", NonceRegistry())[1]
    revoked = {**doc, "revokedKeys": [{"keyMultibase": doc["verificationMethod"][0]["publicKeyMultibase"],
                                       "revokedAt": "2026-01-01T00:00:00Z", "reason": "lost"}]}
    assert "revoked" in validate_envelope(env, revoked, "did:aroha:r", NonceRegistry())[1]


def test_skip_signature_still_records_nonce():
    k, _, did = keypair()
    reg = NonceRegistry()
    env = _signed(k, did)
    ack = {"skip_signature": True, "acknowledge_unauthenticated": True}
    assert validate_envelope(env, None, "did:aroha:r", reg, **ack) == (True, None)
    assert validate_envelope(env, None, "did:aroha:r", reg, **ack)[1] == "Nonce replay detected"


def test_skip_signature_is_refused_without_acknowledgement_or_dev_env(monkeypatch):
    from aroha.safety import DevModeNotPermitted

    k, _, did = keypair()
    env = _signed(k, did)
    monkeypatch.delenv("AROHA_DEV_MODE", raising=False)
    with pytest.raises(DevModeNotPermitted, match="AROHA_DEV_MODE"):
        validate_envelope(env, None, "did:aroha:r", NonceRegistry(), skip_signature=True)
    monkeypatch.setenv("AROHA_DEV_MODE", "true")  # only "1" opts in
    with pytest.raises(DevModeNotPermitted):
        validate_envelope(env, None, "did:aroha:r", NonceRegistry(), skip_signature=True)
    monkeypatch.setenv("AROHA_DEV_MODE", "1")
    assert validate_envelope(env, None, "did:aroha:r", NonceRegistry(), skip_signature=True) == (True, None)


def test_nonce_longer_than_128_chars_is_rejected():
    k, pub, did = keypair()
    for n, ok in (("a" * 128, True), ("a" * 129, False)):
        env = _signed(k, did, nonce=n)
        ok_, reason = validate_envelope(env, pub, "did:aroha:r", NonceRegistry())
        assert ok_ is ok, reason
        if not ok:
            assert reason == "Nonce too long (max 128 characters)"


def test_file_nonce_store_survives_a_restart(tmp_path):
    from aroha.messages import FileNonceStore

    path = tmp_path / "state" / "nonces.jsonl"
    k, pub, did = keypair()
    env = _signed(k, did)
    assert validate_envelope(env, pub, "did:aroha:r", NonceRegistry(FileNonceStore(str(path)))) == (True, None)
    # A fresh process (new store over the same file) still rejects the replay.
    again = validate_envelope(env, pub, "did:aroha:r", NonceRegistry(FileNonceStore(str(path))))
    assert again == (False, "Nonce replay detected")
    # Torn / expired lines are skipped on load.
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"k":"old","e":1}\n{"k":"torn",')
    store = FileNonceStore(str(path))
    assert len(store) == 1
    assert store.set_if_absent("old", 2**53)


def test_raw_private_key_bytes_and_tampering():
    raw = bytes(range(32))
    k = Ed25519PrivateKey.from_private_bytes(raw)
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    env = build_envelope("ArohaRequest", "did:aroha:s", "did:aroha:r", {"amount": 1.5}, "c", raw)
    env["body"]["amount"] = 2
    assert validate_envelope(env, pub, "did:aroha:r", NonceRegistry()) == (False, "Signature verification failed")
