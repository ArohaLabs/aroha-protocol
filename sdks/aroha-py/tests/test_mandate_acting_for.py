# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Spending-mandate actingFor (PSD3 payer/payee side, spec §6.5): a declared
side is kept on every link; a child that drops or flips it is refused."""

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.jcs import canonicalize_jcs
from aroha.mandate import verify_mandate_chain


def _party():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return k, "did:aroha:" + to_multibase(pub)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sign(key, body):
    sig = key.sign(canonicalize_jcs({"mandate": body, "v": 2}).encode("utf-8"))
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def _chain(child_acting_for):
    (hk, human), (ak, agent), (_pk, provider) = _party(), _party(), _party()
    now = datetime.now(timezone.utc)
    root = {
        "mandateTier": "intent", "constraints": {"spendLimitUsd": 100}, "grantee": agent, "grantor": human,
        "issuedAt": _iso(now), "expiresAt": _iso(now + timedelta(hours=1)), "parentMandateId": None,
        "mandateId": "m-root", "actingFor": "payer",
    }
    child = {
        "mandateTier": "cart", "constraints": {"spendLimitUsd": 50}, "grantee": provider, "grantor": agent,
        "issuedAt": _iso(now), "expiresAt": _iso(now + timedelta(minutes=30)), "parentMandateId": "m-root",
        "mandateId": "m-child",
    }
    if child_acting_for is not None:
        child["actingFor"] = child_acting_for
    tok = {"v": 2, "mandate": child, "signature": _sign(ak, child),
           "chain": [{"v": 2, "mandate": root, "signature": _sign(hk, root)}]}
    return base64.urlsafe_b64encode(json.dumps(tok).encode()).decode().rstrip("=")


def test_kept_side_verifies():
    assert verify_mandate_chain(_chain("payer")).valid


def test_flipped_or_dropped_side_is_refused():
    for side in ("payee", None):
        r = verify_mandate_chain(_chain(side))
        assert not r.valid and "actingFor" in (r.reason or "")


def test_invalid_value_is_refused():
    r = verify_mandate_chain(_chain("both"))
    assert not r.valid
