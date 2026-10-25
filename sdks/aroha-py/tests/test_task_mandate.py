# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""aroha.task_mandate — issue, attenuate, verify, enforce (pure Python).

Byte compatibility with TypeScript is checked in test_task_mandate_vectors.py
(shared vectors) and test_task_mandate_interop.py (live, both directions).
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.mandate import SpendingConstraints
from aroha.task_mandate import (
    TASK_MANDATE_PURPOSE,
    ComputeLimit,
    TaskActionRequest,
    TaskConstraints,
    TaskConstraintViolation,
    attenuate_task_mandate,
    check_task_constraints,
    check_task_data_access,
    check_task_narrowing,
    decode_task_mandate_token,
    enforce_task_constraints,
    issue_task_mandate,
    task_mandate_signing_payload_v2,
    verify_task_mandate,
)
from aroha.timeutil import now_ms, parse_iso_ms


class Party:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aroha:" + to_multibase(self.pub)


@pytest.fixture
def human():
    return Party()


@pytest.fixture
def agent():
    return Party()


@pytest.fixture
def vendor():
    return Party()


ROOM, GUEST = "room-1", "did:aroha:guest"


def _constraints(**kw) -> TaskConstraints:
    base = dict(
        action_limits={"send-email": 2, "web-search": 10},
        compute_limit=ComputeLimit(llm_tokens=1000, web_requests=5),
        data_access={"email": "read-write", "calendar": "read"},
        human_gates=["send-email"],
        on_behalf_of=GUEST,
        room_id=ROOM,
    )
    base.update(kw)
    return TaskConstraints(**base)


def _decode(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))


def _encode(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_issue_and_verify_round_trip(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["web-search", "send-email"], _constraints(), human.key)
    raw = _decode(s.token)
    assert raw["v"] == 2 and list(raw) == ["v", "mandate", "signature"]
    body = raw["mandate"]
    assert list(body) == ["mandateType", "mandateTier", "allowed", "taskConstraints", "grantee", "grantor",
                          "issuedAt", "expiresAt", "parentMandateId", "mandateId"]
    assert body["mandateType"] == "task" and body["mandateTier"] == "intent"
    assert body["taskConstraints"]["onBehalfOf"] == GUEST and body["taskConstraints"]["roomId"] == ROOM
    assert body["taskConstraints"]["computeLimit"] == {"llmTokens": 1000, "webRequests": 5}
    payload = task_mandate_signing_payload_v2(body)
    assert f'"purpose":"{TASK_MANDATE_PURPOSE}"' in payload

    r = verify_task_mandate(s.token, human.pub, agent.did)
    assert r.valid, r.reason
    valid, mandate, reason = r
    assert mandate.task_constraints.room_id == ROOM and mandate.task_constraints.compute_limit.llm_tokens == 1000
    assert decode_task_mandate_token(s.token).mandate == s.mandate


def test_hybrid_carries_spending_constraints(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["book"], {"reversibleOnly": True}, human.key,
                           spending_constraints=SpendingConstraints(300, allowed_merchants=["did:aroha:m"]))
    assert s.wire["mandateType"] == "hybrid"
    assert s.wire["spendingConstraints"] == {"spendLimitUsd": 300, "allowedMerchants": ["did:aroha:m"]}
    assert verify_task_mandate(s.token, human.key).valid


def test_issue_rejects_bad_shape(human, agent):
    with pytest.raises(ValueError, match="onBehalfOf must be a non-empty string"):
        issue_task_mandate(human.did, agent.did, ["x"], TaskConstraints(on_behalf_of=""), human.key)
    with pytest.raises(ValueError, match="actionLimits"):
        issue_task_mandate(human.did, agent.did, ["x"], {"actionLimits": {"x": -1}}, human.key)


def test_verify_rejections(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["web-search"], _constraints(), human.key, ttl_seconds=60)
    raw = _decode(s.token)

    widened = {**raw, "mandate": {**raw["mandate"], "allowed": ["web-search", "delete-files"]}}
    assert verify_task_mandate(_encode(widened), human.pub).reason == "Invalid signature"
    assert verify_task_mandate(s.token, agent.pub).reason == "Invalid signature"
    assert verify_task_mandate(s.token, human.pub, "did:aroha:other").reason == "Grantee mismatch: expected did:aroha:other"
    assert verify_task_mandate(s.token, human.pub, now=now_ms() + 61_000).reason == "Task mandate expired"
    assert "in the future" in verify_task_mandate(s.token, human.pub, now=now_ms() - 120_000).reason
    assert verify_task_mandate(_encode({**raw, "v": True}), human.pub).reason == \
        "Unsupported task mandate token version: true"
    assert verify_task_mandate("!!", human.pub).reason == "Malformed token"
    assert verify_task_mandate(_encode({"mandate": raw["mandate"]}), human.pub).reason == \
        "Malformed token: signature missing"
    # The v2 signature does not verify as a v1 token (version is inside the signed bytes).
    v1 = {k: v for k, v in raw.items() if k != "v"}
    assert verify_task_mandate(_encode(v1), human.pub).reason == "Invalid signature"


def test_revocation_hook_fails_closed(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["a"], {}, human.key)
    seen = []
    assert verify_task_mandate(s.token, human.pub, is_revoked=lambda mid, g: seen.append((mid, g)) or False).valid
    assert seen == [(s.mandate.mandate_id, human.did)]
    assert "has been revoked" in verify_task_mandate(s.token, human.pub, is_revoked=lambda *_: True).reason

    def boom(*_):
        raise RuntimeError("down")
    assert "Revocation check failed" in verify_task_mandate(s.token, human.pub, is_revoked=boom).reason


def test_attenuate_inherits_bindings_and_clamps_expiry(human, agent, vendor):
    root = issue_task_mandate(human.did, agent.did, ["web-search", "send-email"], _constraints(), human.key,
                              blocked=["delete"], spending_constraints=SpendingConstraints(100), ttl_seconds=600)
    child = attenuate_task_mandate(
        root, vendor.did, ["web-search"],
        TaskConstraints(action_limits={"web-search": 3}, compute_limit=ComputeLimit(llm_tokens=10, web_requests=1),
                        data_access={"email": "read"}),
        agent.key, ttl_seconds=10_000,
    )
    w = child.wire
    assert w["mandateTier"] == "cart" and w["parentMandateId"] == root.mandate.mandate_id
    assert w["grantor"] == agent.did and w["grantee"] == vendor.did
    assert w["blocked"] == ["delete"] and w["spendingConstraints"] == {"spendLimitUsd": 100}
    assert w["taskConstraints"]["roomId"] == ROOM and w["taskConstraints"]["onBehalfOf"] == GUEST
    assert w["expiresAt"] == root.wire["expiresAt"]
    assert check_task_narrowing(root, child) is None
    assert verify_task_mandate(child.token, agent.pub, vendor.did).valid

    grandchild = attenuate_task_mandate(child, "did:aroha:sub", ["web-search"], child.mandate.task_constraints,
                                        vendor.key, ttl_seconds=5)
    assert grandchild.wire["mandateTier"] == "execution"
    assert parse_iso_ms(grandchild.wire["expiresAt"]) <= now_ms() + 5_000


@pytest.mark.parametrize("narrowed, match", [
    (dict(action_limits={"send-email": 2, "web-search": 11}), r'actionLimits\["web-search"\] \(11\) exceeds parent \(10\)'),
    (dict(action_limits={"send-email": 2}), r'parent sets actionLimits\["web-search"\] \(10\) but child omits it'),
    (dict(room_id="room-2"), r"child roomId \(room-2\) does not keep the parent's roomId \(room-1\)"),
    (dict(on_behalf_of="did:aroha:mallory"), r"does not keep the parent's onBehalfOf"),
    (dict(data_access=None), "parent restricts dataAccess but child omits it"),
    (dict(data_access={"calendar": "read-write"}), r'dataAccess\["calendar"\] \(read-write\) exceeds parent \(read\)'),
    (dict(compute_limit=ComputeLimit(llm_tokens=10)), r"parent sets computeLimit.webRequests \(5\) but child omits it"),
    (dict(human_gates=[]), "drops parent's human gate"),
])
def test_attenuate_refuses_widening(human, agent, vendor, narrowed, match):
    root = issue_task_mandate(human.did, agent.did, ["web-search", "send-email"], _constraints(), human.key)
    with pytest.raises(ValueError, match=match):
        attenuate_task_mandate(root, vendor.did, ["web-search", "send-email"], _constraints(**narrowed), agent.key)


def test_attenuate_refuses_new_capability(human, agent, vendor):
    root = issue_task_mandate(human.did, agent.did, ["a"], {}, human.key)
    with pytest.raises(ValueError, match='child allowed includes "b"'):
        attenuate_task_mandate(root, vendor.did, ["a", "b"], {}, agent.key)


def test_check_task_constraints_codes(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["web-search", "send-email"], _constraints(reversible_only=True),
                           human.key, blocked=["send-email"])
    m = s.wire
    ok = dict(room_id=ROOM, on_behalf_of=GUEST, capability_reversibility="full")
    assert check_task_constraints(m, TaskActionRequest("web-search", **ok)) is None

    def code(**kw):
        v = check_task_constraints(m, TaskActionRequest(**{**ok, **kw}))
        return v.code if v else None

    assert code(requested_capability="web-search", room_id=None) == "CONTEXT_MISMATCH"
    assert code(requested_capability="web-search", on_behalf_of="did:aroha:x") == "CONTEXT_MISMATCH"
    assert code(requested_capability="post") == "CAPABILITY_NOT_PERMITTED"
    assert code(requested_capability="send-email") == "CAPABILITY_NOT_PERMITTED"   # blocked wins
    assert code(requested_capability="web-search", capability_reversibility=None) == "REVERSIBILITY_VIOLATION"
    assert code(requested_capability="web-search", current_action_counts={"web-search": 10}) == "ACTION_LIMIT_EXCEEDED"
    assert code(requested_capability="web-search", current_compute={"web_requests": 5}) == "COMPUTE_LIMIT_EXCEEDED"
    assert code(requested_capability="web-search", current_compute={"llmTokens": 999}) is None
    assert code(requested_capability="web-search", data_access={"email": "write"}) is None
    assert code(requested_capability="web-search", data_access={"drive": "read"}) == "DATA_ACCESS_VIOLATION"
    assert check_task_data_access(None, {"x": "read"}) is None
    assert check_task_data_access({"dataAccess": {"x": "write"}}, {"x": "read"}).code == "DATA_ACCESS_VIOLATION"


def test_human_gate(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["send-email"], TaskConstraints(human_gates=["send-email"]), human.key)
    v = check_task_constraints(s.mandate, TaskActionRequest("send-email"))
    assert v.code == "HUMAN_GATE_REQUIRED"
    assert check_task_constraints(s.mandate, TaskActionRequest("send-email", human_approved=True)) is None


def test_enforce(human, agent):
    s = issue_task_mandate(human.did, agent.did, ["web-search"], _constraints(), human.key)
    m = enforce_task_constraints(s.token, human.pub, requested_capability="web-search", room_id=ROOM,
                                 on_behalf_of=GUEST, expected_grantee=agent.did)
    assert m.mandate_id == s.mandate.mandate_id
    with pytest.raises(TaskConstraintViolation) as e:
        enforce_task_constraints(s.token, human.pub, TaskActionRequest("web-search", room_id="elsewhere",
                                                                       on_behalf_of=GUEST))
    assert e.value.code == "CONTEXT_MISMATCH"
    with pytest.raises(TaskConstraintViolation) as e:
        enforce_task_constraints(s.token, agent.pub, requested_capability="web-search")
    assert e.value.code == "MANDATE_INVALID" and "Invalid signature" in str(e.value)
    with pytest.raises(TaskConstraintViolation) as e:
        enforce_task_constraints(s.token, human.pub, requested_capability="web-search", room_id=ROOM,
                                 on_behalf_of=GUEST, current_action_counts={"web-search": 10})
    assert e.value.code == "ACTION_LIMIT_EXCEEDED"
