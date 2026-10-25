# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Integration: Python <-> TypeScript, executed live against the built TS packages.

Runs tests/node/interop.mjs with node. Skipped (marked ``integration``) when
``node`` is not on PATH or the TypeScript packages have not been built
(``packages/aroha-core/dist`` and ``packages/aroha-credentials/dist``).
Set AROHA_TS_PACKAGES to a ``packages/`` directory that has built dists to
run them from elsewhere (e.g. a worktree without node_modules).
"""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.jcs import canonicalize_jcs
from aroha.kel import incept, revoke_agent, rotate_kel
from aroha.crypto import canonicalize_message
from aroha.mandate import (
    SpendingConstraints,
    attenuate_to_cart,
    attenuate_to_payment,
    issue_intent_mandate,
    verify_mandate_chain,
)
from aroha.messages import NonceRegistry, build_envelope, validate_envelope
from aroha.timeutil import now_ms

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "node" / "interop.mjs"


def _packages_dir() -> Path | None:
    env = os.environ.get("AROHA_TS_PACKAGES")
    cands = [Path(env)] if env else [p / "packages" for p in HERE.parents]
    for c in cands:
        if (c / "aroha-core" / "dist" / "index.js").is_file() and (c / "aroha-credentials" / "dist" / "index.js").is_file():
            return c
    return None


NODE = shutil.which("node")
PKGS = _packages_dir()
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(NODE is None, reason="node is not on PATH"),
    pytest.mark.skipif(
        PKGS is None,
        reason="built TypeScript packages not found (run `npm run build` in packages/aroha-core and "
        "packages/aroha-credentials, or set AROHA_TS_PACKAGES)",
    ),
]


def ts(op: str, **kw):
    out = subprocess.run(
        [NODE, str(SCRIPT), str(PKGS)],
        input=json.dumps({"op": op, **kw}),
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    if out.returncode != 0:
        raise AssertionError(f"node failed: {out.stderr}")
    return json.loads(out.stdout)


class Party:
    def __init__(self, seed_byte: int):
        self.priv_bytes = bytes([seed_byte]) * 32
        self.key = Ed25519PrivateKey.from_private_bytes(self.priv_bytes)
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aroha:" + to_multibase(self.pub)


HUMAN, AGENT, PROVIDER, PAYEE = Party(11), Party(12), Party(13), Party(14)
MERCHANTS = ["did:aroha:merchant-a", "did:aroha:merchant-ü"]


# ── Canonicalisation ──────────────────────────────────────────────────────────

AWKWARD = {
    "b": [10.0, 0.1, 1e21, 1e-7, -0.0, 333333333.33333329, 2 ** 60, 42, 42.5],
    "a": {"é": "naïve – “quotes” \u0007 \t\n 😀", "€": 1, "\U0001f600": 2, "דּ": 3},
    "10": "ten", "2": "two", "01": "zero-one", "x": None, "t": True,
}


def test_jcs_matches_typescript_byte_for_byte():
    assert canonicalize_jcs(AWKWARD) == ts("jcs", value=AWKWARD)["out"]


def test_envelope_canonical_form_matches_typescript():
    # Integer-like keys, floats, non-ASCII: every place json.dumps(sort_keys) used to differ.
    assert canonicalize_message({**AWKWARD, "proof": {"x": 1}}) == ts("canonicalizeMessage", value=AWKWARD)["out"]


# ── Mandates ──────────────────────────────────────────────────────────────────

def test_python_issued_v2_chain_verifies_in_typescript():
    intent = issue_intent_mandate(
        HUMAN.did, AGENT.did,
        SpendingConstraints(500.0, session_limit_usd=200.5, require_human_approval_above_usd=100.0,
                            allowed_merchants=MERCHANTS, currency="USD"),
        HUMAN.key,
    )
    cart = attenuate_to_cart(intent, PROVIDER.did, SpendingConstraints(42.07, allowed_merchants=MERCHANTS[:1]), AGENT.key)
    pay = attenuate_to_payment(cart, PAYEE.did, SpendingConstraints(10.0, allowed_merchants=MERCHANTS[:1]), PROVIDER.key)
    r = ts("verifyMandateChain", token=pay.token, now=now_ms())
    assert r["valid"], r["reason"]
    assert r["chainVerified"] and r["rootGrantor"] == HUMAN.did
    assert r["leafMandateId"] == pay.mandate.mandate_id


def test_typescript_issued_v2_chain_verifies_in_python():
    out = ts(
        "issueChain",
        humanDid=HUMAN.did, agentDid=AGENT.did, providerDid=PROVIDER.did,
        humanPrivHex=HUMAN.priv_bytes.hex(), agentPrivHex=AGENT.priv_bytes.hex(),
        intentConstraints={"spendLimitUsd": 500, "sessionLimitUsd": 200.5, "allowedMerchants": MERCHANTS,
                           "validUntil": "2099-01-01T00:00:00.000Z"},
        cartConstraints={"spendLimitUsd": 42.07, "allowedMerchants": MERCHANTS[:1]},
    )
    r = verify_mandate_chain(out["cart"], expected_root=HUMAN.did, expected_grantee=PROVIDER.did)
    assert r.valid, r.reason
    assert r.chain_verified and [m.mandate_tier for m in r.chain] == ["intent", "cart"]
    # And Python can attenuate a TS-issued token further; TS accepts the result.
    from aroha.mandate import decode_mandate_token
    pay = attenuate_to_payment(decode_mandate_token(out["cart"]), PAYEE.did,
                               SpendingConstraints(5, allowed_merchants=MERCHANTS[:1]), PROVIDER.key)
    assert ts("verifyMandateChain", token=pay.token, now=now_ms())["valid"]


# ── Envelopes ─────────────────────────────────────────────────────────────────

BODY = {"capability": "quote", "params": {"amount": 10.0, "ratio": 0.1, "note": "café – ünïcode", "10": 1, "9": 2}}


def test_python_envelope_validates_in_typescript():
    env = build_envelope("ArohaRequest", AGENT.did, PROVIDER.did, BODY, "saga-x", AGENT.key)
    r = ts("validateEnvelope", envelope=env, pubHex=AGENT.pub.hex(), myDid=PROVIDER.did)
    assert r["first"] == {"valid": True}
    assert r["replay"]["valid"] is False and "replay" in r["replay"]["reason"].lower()


def test_pinned_envelope_vector_matches_typescript():
    from tests.test_messages import PINNED_CANONICAL, PINNED_ENVELOPE
    assert ts("canonicalizeMessage", value=PINNED_ENVELOPE)["out"] == PINNED_CANONICAL


def test_typescript_envelope_validates_in_python():
    env = ts("buildEnvelope", type="ArohaSpendingMandate", **{"from": AGENT.did}, to=PROVIDER.did,
             body=BODY, cid="saga-y", privHex=AGENT.priv_bytes.hex())["envelope"]
    reg = NonceRegistry()
    assert validate_envelope(env, AGENT.pub, PROVIDER.did, reg) == (True, None)
    assert validate_envelope(env, AGENT.pub, PROVIDER.did, reg) == (False, "Nonce replay detected")


# ── Body encryption (ECDH-ES+A256GCM) ────────────────────────────────────────

ENC_BODY = {"amount": 10.5, "note": "héllo 😀", "nested": {"2": True, "10": [1, 2.25]}}


def test_python_encrypted_body_decrypts_in_typescript():
    from aroha.crypto import encrypt_body
    enc = encrypt_body(ENC_BODY, PROVIDER.pub)
    assert ts("decryptBody", encrypted=enc, privHex=PROVIDER.priv_bytes.hex())["plaintext"] == ENC_BODY


def test_typescript_encrypted_body_decrypts_in_python():
    from aroha.crypto import decrypt_body
    enc = ts("encryptBody", plaintext=ENC_BODY, pubHex=PROVIDER.pub.hex())["encrypted"]
    assert set(enc) == {"alg", "epk", "iv", "ciphertext", "tag"}
    assert decrypt_body(enc, PROVIDER.priv_bytes) == ENC_BODY


# ── did:aroha-web ─────────────────────────────────────────────────────────────

def _py_resolve(did, doc, txt, now):
    from aroha.web_did import resolve_web_did
    r = resolve_web_did(did, fetch=lambda u, t, m: json.dumps(doc).encode(), dns_resolver=lambda d: txt,
                        now=now, logger=lambda m: None)
    return {"dnsVerified": r.dns_verified, "keyTrusted": r.key_trusted, "deprecatedRotations": r.deprecated_rotations,
            "acceptedKeys": [{"verificationMethodId": k.verification_method_id,
                              "publicKeyMultibase": k.public_key_multibase, "role": k.role} for k in r.accepted_keys]}


def test_typescript_web_did_rotation_resolves_identically_in_python():
    out = ts("webDidRotated", domain="example.com", path="agents/fx", coolDownHours=24)
    after = out["after"]
    rotated_at = after["arohaWeb"]["keyHistory"][0]["rotatedAt"]
    from aroha.timeutil import parse_iso_ms
    t0 = parse_iso_ms(rotated_at)
    for txt in ([out["oldTxt"]], [out["newTxt"]], ["v=aroha1; path=agents/fx; keyhash=00"]):
        for now in (t0 + 1000, t0 + 25 * 3_600_000):
            want = ts("resolveWebDid", did=out["did"], document=after, txt=txt, now=now)
            assert want["ok"], want
            want.pop("ok")
            assert _py_resolve(out["did"], after, txt, now) == want, (txt, now)


def test_python_web_did_rotation_resolves_in_typescript():
    from aroha.web_did import generate_web_agent, rotate_key
    a = generate_web_agent("example.com", "agents/fx")
    b = rotate_key(a, 24)
    now = now_ms() + 1000
    want = ts("resolveWebDid", did=b.did, document=b.document, txt=[a.dns_txt_record], now=now)
    assert want.pop("ok"), want
    assert want["dnsVerified"] and not want["keyTrusted"]
    assert _py_resolve(b.did, b.document, [a.dns_txt_record], now) == want


# ── KELs ──────────────────────────────────────────────────────────────────────

def test_python_kel_verifies_in_typescript():
    person = incept("person")
    agent = incept("agent", controller=person.did)
    rotated = rotate_kel(agent)
    person2, agent_kel = revoke_agent(person, rotated.kel, reason="decommissioned")
    r = ts("verifyKel", did=agent.did, events=agent_kel, controllerEvents=person2.kel)
    assert r["ok"] and r["revoked"] and r["sequence"] == 2, r
    # Tampering is caught by TS too.
    bad = [dict(agent_kel[0], kind="person")] + agent_kel[1:]
    assert ts("verifyKel", did=agent.did, events=bad)["ok"] is False
