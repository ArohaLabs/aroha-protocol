# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Integration: task mandates, Python <-> TypeScript, live against the built TS packages.

TypeScript issues and attenuates; Python verifies (and rejects tampered,
widened, expired and over-limit cases). Python issues and attenuates;
TypeScript verifies and enforces. Same skip rules as test_cross_language.py
(node on PATH and built packages/aroha-credentials/dist, or AROHA_TS_PACKAGES).
"""

from __future__ import annotations

import base64
import json

import pytest

from aroha.mandate import SpendingConstraints
from aroha.task_mandate import (
    ComputeLimit,
    TaskActionRequest,
    TaskConstraints,
    TaskConstraintViolation,
    attenuate_task_mandate,
    check_task_narrowing,
    decode_task_mandate_token,
    enforce_task_constraints,
    issue_task_mandate,
    verify_task_mandate,
)
from aroha.timeutil import now_ms
from tests.test_cross_language import NODE, PKGS, Party, ts

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(NODE is None, reason="node is not on PATH"),
    pytest.mark.skipif(PKGS is None, reason="built TypeScript packages not found (see test_cross_language.py)"),
]

ROOM, GUEST = "room-42", "did:aroha:guest-carol"
ROOT_CONSTRAINTS = {
    "actionLimits": {"send-email": 2, "web-search": 10},
    "computeLimit": {"llmTokens": 5000, "webRequests": 20},
    "dataAccess": {"email": "read-write", "calendar": "read"},
    "humanGates": ["send-email"],
    "outputHandling": "user-only",
    "onBehalfOf": GUEST,
    "roomId": ROOM,
}
CHILD_CONSTRAINTS = {
    "actionLimits": {"web-search": 3},
    "computeLimit": {"llmTokens": 100, "webRequests": 2},
    "dataAccess": {"email": "read"},
    "outputHandling": "internal-only",
}


@pytest.fixture(scope="module")
def parties():
    return Party(0x31), Party(0x32), Party(0x33)


def _decode(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))


def _encode(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def ts_chain(parties):
    human, agent, vendor = parties
    return ts(
        "issueTaskChain", humanDid=human.did, agentDid=agent.did, humanPrivHex=human.priv_bytes.hex(),
        agentPrivHex=agent.priv_bytes.hex(), allowed=["web-search", "send-email", "read-calendar"],
        constraints=ROOT_CONSTRAINTS, ttlMs=3_600_000, options={"blocked": ["delete-files"]},
        child={"granteeDid": vendor.did, "allowed": ["web-search"], "constraints": CHILD_CONSTRAINTS, "ttlMs": 600_000},
    )


# ── TypeScript issues, Python verifies ────────────────────────────────────────

def test_python_verifies_ts_root_and_child(parties, ts_chain):
    human, agent, vendor = parties
    root = verify_task_mandate(ts_chain["root"], human.pub, agent.did)
    assert root.valid, root.reason
    assert root.mandate.task_constraints.on_behalf_of == GUEST and root.mandate.task_constraints.room_id == ROOM
    child = verify_task_mandate(ts_chain["child"], agent.pub, vendor.did)
    assert child.valid, child.reason
    # TS attenuation inherited the room / member binding and the blocked list.
    assert child.wire["taskConstraints"]["roomId"] == ROOM
    assert child.wire["taskConstraints"]["onBehalfOf"] == GUEST
    assert child.wire["blocked"] == ["delete-files"]
    assert child.wire["parentMandateId"] == root.wire["mandateId"]
    assert check_task_narrowing(root.wire, child.wire) is None
    # The snake_case view re-serialises to the exact body TypeScript signed.
    assert decode_task_mandate_token(ts_chain["child"]).mandate.to_wire() == child.wire


def test_python_rejects_tampered_and_wrong_key(parties, ts_chain):
    human, agent, _ = parties
    raw = _decode(ts_chain["root"])
    raw["mandate"]["taskConstraints"]["actionLimits"]["send-email"] = 99
    assert verify_task_mandate(_encode(raw), human.pub).reason == "Invalid signature"
    raw = _decode(ts_chain["root"])
    del raw["mandate"]["taskConstraints"]["roomId"]
    assert verify_task_mandate(_encode(raw), human.pub).reason == "Invalid signature"
    assert verify_task_mandate(ts_chain["root"], agent.pub).reason == "Invalid signature"


def test_python_rejects_expired_ts_token(parties, ts_chain):
    human, _, _ = parties
    r = verify_task_mandate(ts_chain["root"], human.pub, now=now_ms() + 3_600_000 + 1_000)
    assert r.reason == "Task mandate expired"


def test_python_refuses_a_ts_signed_widening_child(parties):
    """A TS-signed child that widens its parent verifies on its own signature,
    but check_task_narrowing (the verifier-side rule) refuses the link."""
    human, agent, vendor = parties
    issued = ts("issueTaskChain", humanDid=human.did, agentDid=agent.did, humanPrivHex=human.priv_bytes.hex(),
                agentPrivHex=agent.priv_bytes.hex(), allowed=["web-search"], constraints=ROOT_CONSTRAINTS,
                ttlMs=600_000)
    root = verify_task_mandate(issued["root"], human.pub)
    # The dishonest agent skips attenuateTaskMandate and signs a wider body directly.
    widened = ts("issueTaskChain", humanDid=agent.did, agentDid=vendor.did, humanPrivHex=agent.priv_bytes.hex(),
                 agentPrivHex=agent.priv_bytes.hex(), allowed=["web-search"],
                 constraints={**CHILD_CONSTRAINTS, "actionLimits": {"web-search": 50}},
                 ttlMs=60_000, options={"parentMandateId": root.wire["mandateId"], "tier": "cart"})
    child = verify_task_mandate(widened["root"], agent.pub, vendor.did)
    assert child.valid
    reason = check_task_narrowing(root.wire, child.wire)
    assert reason == 'Cannot attenuate task mandate: child actionLimits["web-search"] (50) exceeds parent (10)'
    assert ts("checkTaskNarrowing", parent=root.wire, child=child.wire)["reason"] == reason


def test_python_enforces_ts_token_limits(parties, ts_chain):
    human, _, _ = parties
    ctx = dict(room_id=ROOM, on_behalf_of=GUEST)
    enforce_task_constraints(ts_chain["root"], human.pub, TaskActionRequest("web-search", **ctx))
    for req, code in [
        (TaskActionRequest("web-search", current_action_counts={"web-search": 10}, **ctx), "ACTION_LIMIT_EXCEEDED"),
        (TaskActionRequest("web-search", current_compute={"web_requests": 20}, **ctx), "COMPUTE_LIMIT_EXCEEDED"),
        (TaskActionRequest("send-email", **ctx), "HUMAN_GATE_REQUIRED"),
        (TaskActionRequest("web-search", room_id="room-other", on_behalf_of=GUEST), "CONTEXT_MISMATCH"),
        (TaskActionRequest("delete-files", **ctx), "CAPABILITY_NOT_PERMITTED"),
        (TaskActionRequest("read-calendar", data_access={"calendar": "write"}, **ctx), "DATA_ACCESS_VIOLATION"),
    ]:
        with pytest.raises(TaskConstraintViolation) as e:
            enforce_task_constraints(ts_chain["root"], human.pub, req)
        assert e.value.code == code


# ── Python issues, TypeScript verifies ────────────────────────────────────────

@pytest.fixture(scope="module")
def py_chain(parties):
    human, agent, vendor = parties
    root = issue_task_mandate(
        human.did, agent.did, ["web-search", "send-email"], TaskConstraints.from_wire(ROOT_CONSTRAINTS), human.key,
        blocked=["delete-files"], spending_constraints=SpendingConstraints(250.5, allowed_merchants=["did:aroha:m"]),
        invariants={"payee": ["did:aroha:m"], "parameters": {"seats": 1, "refundable": True}},
    )
    child = attenuate_task_mandate(
        root, vendor.did, ["web-search"],
        TaskConstraints(action_limits={"web-search": 2.5}, compute_limit=ComputeLimit(llm_tokens=10, web_requests=1),
                        data_access={"email": "read"}, output_handling="internal-only"),
        agent.key, ttl_seconds=120,
        invariants={"payee": ["did:aroha:m"], "parameters": {"seats": 1, "refundable": True}},
    )
    return root, child


def test_ts_verifies_python_tokens(parties, py_chain):
    human, agent, vendor = parties
    root, child = py_chain
    r = ts("verifyTaskMandate", token=root.token, pubHex=human.pub.hex(), expectedGrantee=agent.did)
    assert r["valid"], r["reason"]
    assert r["mandate"] == root.wire
    c = ts("verifyTaskMandate", token=child.token, pubHex=agent.pub.hex(), expectedGrantee=vendor.did)
    assert c["valid"], c["reason"]
    assert c["mandate"]["taskConstraints"]["roomId"] == ROOM
    assert c["mandate"]["mandateType"] == "hybrid"
    assert ts("checkTaskNarrowing", parent=root.wire, child=child.wire)["reason"] is None


def test_ts_signing_payload_matches_python(py_chain):
    from aroha.task_mandate import task_mandate_signing_payload_v2
    for s in py_chain:
        assert ts("taskSigningPayload", mandate=s.wire)["out"] == task_mandate_signing_payload_v2(s.wire)


def test_ts_rejects_tampered_and_expired_python_tokens(parties, py_chain):
    human, _, _ = parties
    root, _ = py_chain
    raw = _decode(root.token)
    raw["mandate"]["allowed"].append("delete-files")
    assert ts("verifyTaskMandate", token=_encode(raw), pubHex=human.pub.hex())["reason"] == "Invalid signature"
    late = ts("verifyTaskMandate", token=root.token, pubHex=human.pub.hex(), now=now_ms() + 3_601_000)
    assert late["reason"] == "Task mandate expired"


def test_ts_enforces_python_token(parties, py_chain):
    human, _, _ = parties
    root, _ = py_chain
    ok = ts("enforceTaskConstraints", token=root.token, pubHex=human.pub.hex(),
            options={"requestedCapability": "web-search", "roomId": ROOM, "onBehalfOf": GUEST})
    assert ok == {"ok": True, "mandateId": root.mandate.mandate_id}
    over = ts("enforceTaskConstraints", token=root.token, pubHex=human.pub.hex(),
              options={"requestedCapability": "send-email", "roomId": ROOM, "onBehalfOf": GUEST,
                       "humanApproved": True, "currentActionCounts": {"send-email": 2}})
    assert over["code"] == "ACTION_LIMIT_EXCEEDED"
    with pytest.raises(TaskConstraintViolation) as e:
        enforce_task_constraints(root.token, human.pub, TaskActionRequest(
            "send-email", room_id=ROOM, on_behalf_of=GUEST, human_approved=True,
            current_action_counts={"send-email": 2}))
    assert str(e.value) == over["message"]
    no_room = ts("enforceTaskConstraints", token=root.token, pubHex=human.pub.hex(),
                 options={"requestedCapability": "web-search", "onBehalfOf": GUEST})
    assert no_room["code"] == "CONTEXT_MISMATCH"
