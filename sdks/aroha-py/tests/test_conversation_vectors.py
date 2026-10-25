# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Conversation and Memory Profile vectors: spec-public/vectors/conversation-v1.json.

The verifiers in aroha.conversation were written from the spec text
(aroha-1.0 §12) and are checked here against the vectors the TypeScript
reference generated: every signing payload byte for byte, every valid object
accepted, every invalid one refused.

The vector file lives in the monorepo, not in the wheel: outside the repo
these tests are skipped. Set AROHA_CONVERSATION_VECTORS to point at a copy.
"""

import json
import os
from pathlib import Path

import pytest

from aroha.conversation import (
    check_disclosure,
    consent_event_signing_bytes,
    content_addressed_key,
    effective_consent,
    kel_resolver,
    signing_bytes,
    turn_content_hash,
    turn_signing_bytes,
    verify_action_receipt,
    verify_consent,
    verify_presented_hash,
    verify_room,
    verify_turn,
)
from aroha.jcs import js_stringify_sorted


def _find() -> Path | None:
    env = os.environ.get("AROHA_CONVERSATION_VECTORS")
    if env:
        return Path(env)
    for parent in Path(__file__).resolve().parents:
        cand = parent / "spec-public" / "vectors" / "conversation-v1.json"
        if cand.is_file():
            return cand
    return None


PATH = _find()
pytestmark = pytest.mark.skipif(PATH is None, reason="conversation-v1.json not found (outside the monorepo)")


@pytest.fixture(scope="module")
def V():
    return json.loads(PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def resolve(V):
    return kel_resolver(V["kels"])


def test_disclosure(V):
    assert check_disclosure(V["disclosure"]["value"]) is None


def test_room(V, resolve):
    room = V["room"]["value"]
    assert signing_bytes(room).decode() == V["room"]["expectedSigningPayload"]
    assert verify_room(room, resolve).ok
    for bad in V["room"]["invalid"]:
        assert not verify_room(bad["value"], resolve).ok, bad["name"]


def test_consent(V, resolve):
    room = V["room"]["value"]
    for k in ("given", "withdrawn"):
        c = V["consent"][k]
        for i, expected in enumerate(c["expectedEventSigningPayloads"]):
            assert consent_event_signing_bytes(c["value"], i).decode() == expected
        r = verify_consent(c["value"], resolve, room)
        assert r.ok, r.reason
        assert sorted(effective_consent(c["value"])) == c["effectivePurposes"]
    # A non-subject (withdrawal) event cannot be checked without the room.
    assert not verify_consent(V["consent"]["withdrawn"]["value"], resolve).ok
    for bad in V["consent"]["invalid"]:
        assert not verify_consent(bad["value"], resolve, room).ok, bad["name"]


def test_turn_and_speaker_kind(V, resolve):
    room = V["room"]["value"]
    t = V["turn"]
    assert turn_content_hash(t["value"]["content"]) == t["expectedContentHash"]
    assert turn_signing_bytes(t["value"]).decode() == t["expectedSigningPayload"]
    r = verify_turn(t["value"], resolve, room)
    assert r.ok, r.reason
    assert r.kind == t["expectedSpeakerKind"]
    for bad in t["invalid"]:
        assert not verify_turn(bad["value"], resolve, room).ok, bad["name"]


def test_receipts(V):
    for k in ("v1", "v2Executed", "v2Denied"):
        r = V["receipts"][k]
        assert signing_bytes(r["value"]).decode() == r["expectedSigningPayload"]
        res = verify_action_receipt(r["value"], content_addressed_key)
        assert res.ok, (k, res.reason)
    v2 = V["receipts"]["v2Executed"]
    assert verify_presented_hash(v2["value"], v2["presentedContent"]) is None
    assert verify_presented_hash(v2["value"], v2["mismatchedPresentedContent"]) is not None
    for bad in V["receipts"]["invalid"]:
        assert not verify_action_receipt(bad["value"], content_addressed_key).ok, bad["name"]


def test_envelope_with_disclosure_signing_payload(V):
    env = V["envelopeWithDisclosure"]
    unsigned = {k: v for k, v in env["value"].items() if k != "proof"}
    assert js_stringify_sorted(unsigned) == env["expectedSigningPayload"]
    assert check_disclosure(env["value"]["disclosure"], env["value"]["from"]) is None
