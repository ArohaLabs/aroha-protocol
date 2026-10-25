# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

import pytest
from aroha.identity import generate_did, extract_public_key
from aroha.envelope import build_envelope, verify_envelope


def test_build_envelope_has_required_fields():
    agent = generate_did("sender", "http://localhost")
    env = build_envelope("ArohaRequest", agent["did"], "did:aroha:receiver",
                         {"capability": "ping", "params": {}}, "cid-1", agent["private_key"])
    assert env["type"] == "ArohaRequest"
    assert env["from"] == agent["did"]
    assert env["to"] == "did:aroha:receiver"
    assert "proof" in env
    assert env["proof"]["type"] == "Ed25519Signature2020"


def test_verify_envelope_roundtrip():
    sender = generate_did("sender2", "http://localhost")
    receiver_did = "did:aroha:receiver2"
    env = build_envelope("ArohaRequest", sender["did"], receiver_did,
                         {"capability": "ping", "params": {}}, "cid-2", sender["private_key"])
    pub = extract_public_key(sender["document"])
    assert verify_envelope(env, pub, receiver_did) is True


def test_verify_envelope_rejects_wrong_recipient():
    sender = generate_did("sender3", "http://localhost")
    env = build_envelope("ArohaRequest", sender["did"], "did:aroha:correct-recipient",
                         {"capability": "ping", "params": {}}, "cid-3", sender["private_key"])
    pub = extract_public_key(sender["document"])
    assert verify_envelope(env, pub, "did:aroha:wrong-recipient") is False


def test_verify_envelope_rejects_tampered_body():
    sender = generate_did("sender4", "http://localhost")
    receiver_did = "did:aroha:receiver4"
    env = build_envelope("ArohaRequest", sender["did"], receiver_did,
                         {"capability": "ping", "params": {}}, "cid-4", sender["private_key"])
    env["body"]["capability"] = "tampered"
    pub = extract_public_key(sender["document"])
    assert verify_envelope(env, pub, receiver_did) is False


def test_legacy_verify_envelope_now_rejects_replays():
    # aroha.envelope used to be a second verifier with no nonce check at all.
    sender = generate_did("sender5", "http://localhost")
    receiver_did = "did:aroha:receiver5"
    env = build_envelope("ArohaRequest", sender["did"], receiver_did,
                         {"capability": "ping", "params": {}}, "cid-5", sender["private_key"])
    pub = extract_public_key(sender["document"])
    assert verify_envelope(env, pub, receiver_did) is True
    assert verify_envelope(env, pub, receiver_did) is False
