# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""v2 mandate chains: wire format, verifier-side checks, legacy v1 reading, KEL-backed roots."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import to_multibase
from aroha.jcs import js_stringify_sorted
from aroha.kel import incept, kel_source_from_logs, revoke_kel_self
from aroha.mandate import (
    SpendingConstraintViolation,
    SpendingConstraints,
    attenuate_to_cart,
    attenuate_to_payment,
    check_narrowing,
    create_mandate_key_resolver,
    decode_mandate_token,
    enforce_spending_constraints,
    issue_intent_mandate,
    mandate_signing_payload_v2,
    verify_mandate,
    verify_mandate_chain,
)
from aroha.timeutil import iso_ms


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token_of(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def untoken(tok: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))


class Party:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aroha:" + to_multibase(self.pub)


@pytest.fixture
def parties():
    return Party(), Party(), Party()


BASE = SpendingConstraints(
    spend_limit_usd=500.0,
    session_limit_usd=200.5,
    require_human_approval_above_usd=100,
    allowed_merchants=["did:aroha:merchant-a", "did:aroha:merchant-b"],
)


def build_chain(parties):
    human, agent, provider = parties
    intent = issue_intent_mandate(human.did, agent.did, BASE, human.key)
    cart = attenuate_to_cart(intent, provider.did, SpendingConstraints(42.07, allowed_merchants=["did:aroha:merchant-a"]), agent.key)
    return intent, cart


def test_wire_is_camel_case_v2_with_root_first_chain(parties):
    intent, cart = build_chain(parties)
    raw = untoken(cart.token)
    assert raw["v"] == 2
    assert set(raw["mandate"]) == {
        "mandateTier", "constraints", "grantee", "grantor", "issuedAt", "expiresAt", "parentMandateId", "mandateId",
    }
    assert raw["mandate"]["issuedAt"].endswith("Z") and len(raw["mandate"]["issuedAt"]) == 24
    assert "spendLimitUsd" in raw["mandate"]["constraints"]
    assert "currency" not in raw["mandate"]["constraints"]  # absent unless set
    assert [l["mandate"]["mandateId"] for l in raw["chain"]] == [intent.mandate.mandate_id]
    assert raw["chain"][0]["v"] == 2
    # Inheritance: omitted session / approval limits were copied from the parent.
    assert raw["mandate"]["constraints"]["sessionLimitUsd"] == 200.5
    assert raw["mandate"]["constraints"]["requireHumanApprovalAboveUsd"] == 100
    # The signature covers JCS({mandate, v:2}).
    payload = mandate_signing_payload_v2(raw["mandate"])
    assert payload.startswith('{"mandate":{"constraints":{"allowedMerchants"') and payload.endswith(',"v":2}')


def test_three_link_chain_verifies_offline(parties):
    human, agent, provider = parties
    intent, cart = build_chain(parties)
    payee = Party()
    pay = attenuate_to_payment(cart, payee.did, SpendingConstraints(10, allowed_merchants=["did:aroha:merchant-a"]), provider.key)
    r = verify_mandate_chain(pay.token, expected_root=human.did, expected_grantee=payee.did)
    assert r.valid and r.chain_verified, r.reason
    assert r.root_grantor == human.did
    assert [m.mandate_tier for m in r.chain] == ["intent", "cart", "payment"]
    # Re-attenuating a decoded token keeps the chain.
    again = attenuate_to_payment(decode_mandate_token(cart.token), payee.did,
                                 SpendingConstraints(5, allowed_merchants=["did:aroha:merchant-a"]), provider.key)
    assert verify_mandate_chain(again.token).valid


def _forge_child(parent_link: dict, parent_wire: dict, signer: Party, **constraint_overrides) -> str:
    """A dishonest agent skips the attenuation-time check and signs a widened child itself."""
    wire = {
        "mandateTier": "cart",
        "constraints": {"spendLimitUsd": 1000, **constraint_overrides},
        "grantee": "did:aroha:someone",
        "grantor": parent_wire["grantee"],
        "issuedAt": iso_ms(datetime.now(timezone.utc)),
        "expiresAt": parent_wire["expiresAt"],
        "parentMandateId": parent_wire["mandateId"],
        "mandateId": "forged-1",
    }
    sig = b64u(signer.key.sign(mandate_signing_payload_v2(wire).encode()))
    return token_of({"v": 2, "mandate": wire, "signature": sig, "chain": [parent_link]})


def test_verifier_rejects_widening_the_issuer_skipped(parties):
    human, agent, _ = parties
    intent, _ = build_chain(parties)
    link = {"v": 2, "mandate": intent.wire, "signature": intent.signature}
    tok = _forge_child(link, intent.wire, agent, allowedMerchants=["did:aroha:merchant-a"])
    r = verify_mandate_chain(tok)
    assert not r.valid and "spendLimitUsd" in r.reason
    # Omitting a limit the parent sets is widening too.
    tok2 = _forge_child(link, intent.wire, agent)
    assert not verify_mandate_chain(tok2).valid


def test_signature_by_wrong_key_and_broken_linkage(parties):
    human, agent, provider = parties
    intent, cart = build_chain(parties)
    raw = untoken(cart.token)
    raw["mandate"]["constraints"]["spendLimitUsd"] = 1  # tamper after signing
    assert "Invalid signature" in verify_mandate_chain(token_of(raw)).reason
    raw = untoken(cart.token)
    raw["chain"] = []  # drop the ancestry
    r = verify_mandate_chain(token_of(raw))
    assert not r.valid and "parentMandateId" in r.reason


def test_tier_order_and_outliving_parent(parties):
    human, agent, provider = parties
    intent, cart = build_chain(parties)
    pay = attenuate_to_payment(cart, "did:aroha:x", SpendingConstraints(1, allowed_merchants=["did:aroha:merchant-a"]), provider.key)
    with pytest.raises(ValueError, match="broader tier"):
        attenuate_to_cart(pay, "did:aroha:y", SpendingConstraints(1, allowed_merchants=["did:aroha:merchant-a"]), Ed25519PrivateKey.generate())
    # A forged child that outlives its parent.
    link = {"v": 2, "mandate": intent.wire, "signature": intent.signature}
    wire = dict(untoken(cart.token)["mandate"])
    wire["expiresAt"] = iso_ms(datetime.now(timezone.utc) + timedelta(days=3650))
    wire["mandateId"] = "long-lived"
    sig = b64u(agent.key.sign(mandate_signing_payload_v2(wire).encode()))
    r = verify_mandate_chain(token_of({"v": 2, "mandate": wire, "signature": sig, "chain": [link]}))
    assert not r.valid and "outlives" in r.reason


def test_revocation_applies_to_every_link_and_fails_closed(parties):
    intent, cart = build_chain(parties)
    seen = []

    def revoked(mid, grantor):
        seen.append((mid, grantor))
        return mid == intent.mandate.mandate_id and grantor == intent.mandate.grantor

    r = verify_mandate_chain(cart.token, is_revoked=revoked)
    assert not r.valid and "revoked" in r.reason
    # Every call receives the link's grantor alongside its id.
    assert seen[0] == (intent.mandate.mandate_id, intent.mandate.grantor)

    # A one-argument hook cannot answer the (grantor, mandateId) question: it fails closed.
    r = verify_mandate_chain(cart.token, is_revoked=lambda mid: False)
    assert not r.valid and "Revocation check failed" in r.reason

    def boom(_mid, _grantor):
        raise RuntimeError("down")
    r = verify_mandate_chain(cart.token, is_revoked=boom)
    assert not r.valid and "Revocation check failed" in r.reason


def test_look_alike_mandate_reusing_an_id_under_another_grantor_is_not_revoked(parties):
    """Revocation identity is (grantor, mandateId): reusing an id elsewhere revokes nothing."""
    human, agent, other = parties
    original = issue_intent_mandate(human.did, agent.did, BASE, human.key)
    revoked_keys = {f"{original.mandate.grantor}#{original.mandate.mandate_id}"}

    def is_revoked(mid, grantor):
        return f"{grantor}#{mid}" in revoked_keys

    assert not verify_mandate_chain(original.token, is_revoked=is_revoked).valid

    wire = dict(untoken(original.token)["mandate"])
    wire["grantor"] = other.did
    sig = b64u(other.key.sign(mandate_signing_payload_v2(wire).encode()))
    look_alike = token_of({"v": 2, "mandate": wire, "signature": sig, "chain": []})
    r = verify_mandate_chain(look_alike, is_revoked=is_revoked)
    assert r.valid, r.reason
    assert untoken(look_alike)["mandate"]["mandateId"] == original.mandate.mandate_id


def test_time_windows_and_clock_tolerance(parties):
    human, agent, _ = parties
    future = iso_ms(datetime.now(timezone.utc) + timedelta(seconds=20))
    m = issue_intent_mandate(human.did, agent.did, SpendingConstraints(10, valid_from=future), human.key)
    assert verify_mandate_chain(m.token).valid  # within the 30 s default tolerance
    r = verify_mandate_chain(m.token, clock_tolerance_ms=0)
    assert not r.valid and "not yet valid" in r.reason
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    assert "expired" in verify_mandate_chain(m.token, now=later).reason


def test_max_depth_and_repeated_ids(parties):
    intent, cart = build_chain(parties)
    assert "maximum is 1" in verify_mandate_chain(cart.token, max_depth=1).reason
    raw = untoken(cart.token)
    raw["chain"] = [raw["chain"][0], raw["chain"][0]]
    assert "repeats" in verify_mandate_chain(token_of(raw)).reason


def test_check_narrowing_matches_ts_rules():
    p = {"spendLimitUsd": 100, "allowedMerchants": [], "merchantCategory": "travel", "validFrom": "2026-01-01T00:00:00Z"}
    assert check_narrowing(p, {"spendLimitUsd": 1, "allowedMerchants": [], "merchantCategory": "travel",
                               "validFrom": "2026-01-01T00:00:00Z"}, "intent", "cart") is None
    assert "not in parent" in check_narrowing(p, {"spendLimitUsd": 1, "allowedMerchants": ["x"],
                                                  "merchantCategory": "travel", "validFrom": "2026-01-01T00:00:00Z"},
                                              "intent", "cart")
    assert "precedes" in check_narrowing(p, {"spendLimitUsd": 1, "allowedMerchants": [], "merchantCategory": "travel",
                                             "validFrom": "2025-01-01T00:00:00Z"}, "intent", "cart")
    assert "must not widen" in check_narrowing(p, {"spendLimitUsd": 1, "allowedMerchants": []}, "intent", "cart")
    assert "currency" in check_narrowing({"spendLimitUsd": 1}, {"spendLimitUsd": 1, "currency": "EUR"}, "a", "b")
    assert "finite" in check_narrowing({"spendLimitUsd": 1}, {"spendLimitUsd": float("nan")}, "a", "b")


def test_shape_check_rejects_bad_amounts_and_missing_fields(parties):
    human, agent, _ = parties
    m = issue_intent_mandate(human.did, agent.did, SpendingConstraints(10), human.key)
    raw = untoken(m.token)
    raw["mandate"]["constraints"]["sessionLimitUsd"] = None
    assert "sessionLimitUsd" in verify_mandate_chain(token_of(raw)).reason
    raw = untoken(m.token)
    del raw["mandate"]["issuedAt"]
    assert "issuedAt" in verify_mandate_chain(token_of(raw)).reason
    raw = untoken(m.token)
    raw["v"] = 3
    assert "Unsupported" in verify_mandate_chain(token_of(raw)).reason
    raw = untoken(m.token)
    del raw["v"]
    assert "chain present without v: 2" in verify_mandate_chain(token_of(raw)).reason
    with pytest.raises(ValueError):
        issue_intent_mandate(human.did, agent.did, SpendingConstraints(-1), human.key)


def test_enforce_spending_constraints(parties):
    human, agent, provider = parties
    intent, cart = build_chain(parties)
    m = enforce_spending_constraints(cart.token, agent.pub, proposed_amount_usd=40,
                                     merchant_did="did:aroha:merchant-a", require_chain=True)
    assert m.mandate_id == cart.mandate.mandate_id
    for amount, merchant, code in [(50, "did:aroha:merchant-a", "LIMIT_EXCEEDED"),
                                   (float("nan"), "did:aroha:merchant-a", "INVALID_AMOUNT"),
                                   (1, None, "MERCHANT_NOT_ALLOWED"),
                                   (1, "did:aroha:merchant-b", "MERCHANT_NOT_ALLOWED")]:
        with pytest.raises(SpendingConstraintViolation) as ei:
            enforce_spending_constraints(cart.token, agent.pub, proposed_amount_usd=amount, merchant_did=merchant)
        assert ei.value.code == code


# ── Legacy v1 (verification only) ─────────────────────────────────────────────

def _legacy_python_token(key, tier="intent", parent=None):
    """Byte-for-byte what aroha<=1.5 issued: snake_case, no issuedAt, json.dumps(sort_keys) signature."""
    body = {
        "mandate_tier": tier,
        "constraints": {"spend_limit_usd": 50.0, "currency": "USD"},
        "grantee": "did:aroha:grantee",
        "grantor": "did:aroha:grantor",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "parent_mandate_id": parent,
        "mandate_id": "legacy-1",
    }
    canonical = json.dumps(dict(sorted({**body, "constraints": dict(sorted(body["constraints"].items()))}.items())),
                           separators=(",", ":"))
    sig = b64u(key.sign(canonical.encode()))
    return token_of({"mandate": body, "signature": sig})


def test_legacy_python_v1_root_still_verifies():
    key = Ed25519PrivateKey.generate()
    tok = _legacy_python_token(key)
    r = verify_mandate(tok, key.public_key())
    assert r.valid, r.reason
    assert r.mandate.constraints.spend_limit_usd == 50.0
    assert r.mandate.issued_at is None
    resolver = lambda did: key.public_key()
    assert verify_mandate_chain(tok, resolver).valid  # a v1 ROOT is its own chain (TS parity)
    with pytest.raises(ValueError, match="legacy Python"):
        attenuate_to_cart(decode_mandate_token(tok), "did:aroha:x", SpendingConstraints(1), key)


def test_legacy_python_v1_child_is_not_chain_verified():
    key = Ed25519PrivateKey.generate()
    tok = _legacy_python_token(key, tier="cart", parent="some-parent")
    r = verify_mandate(tok, key.public_key())
    assert r.valid and r.chain_verified is False
    r = verify_mandate_chain(tok, lambda did: key.public_key())
    assert not r.valid and "no ancestry" in r.reason
    with pytest.raises(SpendingConstraintViolation):
        enforce_spending_constraints(tok, key.public_key(), proposed_amount_usd=1, require_chain=True)


def test_ts_v1_camel_case_token_verifies():
    key = Ed25519PrivateKey.generate()
    body = {
        "mandateTier": "cart",
        "constraints": {"spendLimitUsd": 10.5, "allowedMerchants": ["m"]},
        "grantee": "did:aroha:g", "grantor": "did:aroha:r",
        "issuedAt": iso_ms(datetime.now(timezone.utc)),
        "expiresAt": iso_ms(datetime.now(timezone.utc) + timedelta(hours=1)),
        "parentMandateId": "p", "mandateId": "c",
    }
    sig = b64u(key.sign(js_stringify_sorted(body).encode()))  # JSON.stringify(sortKeys(mandate))
    tok = token_of({"mandate": body, "signature": sig})
    r = verify_mandate(tok, key.public_key())
    assert r.valid and not r.chain_verified


# ── KEL-backed roots ──────────────────────────────────────────────────────────

def test_person_root_via_kel():
    person = incept("person")
    agent = Party()
    m = issue_intent_mandate(person.did, agent.did, SpendingConstraints(10), person.private_key)
    src = kel_source_from_logs(person.kel)
    r = verify_mandate_chain(m.token, kel_source=src, require_person_root=True, expected_root_person=person.did)
    assert r.valid, r.reason
    # Without kel_source the E-DID cannot be resolved by the default resolver.
    assert not verify_mandate_chain(m.token).valid
    assert verify_mandate_chain(m.token, create_mandate_key_resolver(kel_source=src)).valid
    # A content-addressed root is not a person.
    m2 = issue_intent_mandate(agent.did, person.did, SpendingConstraints(10), agent.key)
    assert "not a person" in verify_mandate_chain(m2.token, kel_source=src, require_person_root=True).reason
    # Revoking the person kills the mandate.
    revoked_src = kel_source_from_logs(revoke_kel_self(person))
    r = verify_mandate_chain(m.token, kel_source=revoked_src)
    assert not r.valid and "revoked" in r.reason


def _signed_link(wire: dict, signer: "Party") -> dict:
    sig = b64u(signer.key.sign(mandate_signing_payload_v2(wire).encode()))
    return {"v": 2, "mandate": wire, "signature": sig}


def test_caller_key_never_verifies_an_ancestor_naming_the_same_grantor():
    # A named DID whose real key is what the resolver returns. The attacker
    # forges a root AND a child both naming that DID, signs both with their own
    # key, and passes that key as the leaf key. The root must be checked against
    # the REAL key, so the chain fails. (Matching on DID used to lend the
    # caller's key to the root.)
    shop = "did:aroha:shop"
    real, attacker = Party(), Party()
    now = datetime.now(timezone.utc)
    root = {
        "mandateTier": "intent", "constraints": {"spendLimitUsd": 1000000},
        "grantor": shop, "grantee": shop, "issuedAt": iso_ms(now),
        "expiresAt": iso_ms(now + timedelta(hours=1)), "parentMandateId": None, "mandateId": "forged-root",
    }
    child = {**root, "mandateTier": "cart", "grantee": "did:aroha:payee",
             "parentMandateId": "forged-root", "mandateId": "forged-leaf"}
    root_link, leaf_link = _signed_link(root, attacker), _signed_link(child, attacker)
    tok = token_of({"v": 2, "mandate": child, "signature": leaf_link["signature"], "chain": [root_link]})
    r = verify_mandate(tok, attacker.pub, resolve_key=lambda did: real.pub if did == shop else None,
                       expected_root=shop)
    assert not r.valid


def test_caller_key_must_match_a_self_certifying_leaf_grantor(parties):
    _, cart = build_chain(parties)
    stranger = Party()
    assert not verify_mandate(cart.token, stranger.pub).valid
