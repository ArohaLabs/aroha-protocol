# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for aroha.mandate — narrowing enforcement and round-trip verification."""

import pytest
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aroha.mandate import (
    SpendingConstraints,
    issue_intent_mandate,
    attenuate_to_cart,
    attenuate_to_payment,
    verify_mandate,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()

BASE = SpendingConstraints(
    spend_limit_usd=500.0,
    session_limit_usd=200.0,
    require_human_approval_above_usd=100.0,
    allowed_merchants=["merchant-a", "merchant-b", "merchant-c"],
)


# ── issue_intent_mandate ──────────────────────────────────────────────────────

def test_issue_intent_fields():
    key = make_key()
    m = issue_intent_mandate("did:aroha:grantor", "did:aroha:grantee", BASE, key)
    assert m.mandate.mandate_tier == "intent"
    assert m.mandate.grantor == "did:aroha:grantor"
    assert m.mandate.grantee == "did:aroha:grantee"
    assert m.mandate.parent_mandate_id is None
    assert m.mandate.mandate_id
    assert m.token
    exp = datetime.fromisoformat(m.mandate.expires_at.replace("Z", "+00:00"))
    assert exp > datetime.now(timezone.utc)


def test_issue_intent_custom_ttl():
    key = make_key()
    before = datetime.now(timezone.utc)
    m = issue_intent_mandate("did:aroha:g", "did:aroha:e", BASE, key, ttl_seconds=10)
    exp = datetime.fromisoformat(m.mandate.expires_at.replace("Z", "+00:00"))
    delta = (exp - before).total_seconds()
    assert 9 < delta < 11


# ── verify_mandate ────────────────────────────────────────────────────────────

def test_verify_valid():
    key = make_key()
    pub = key.public_key()
    m = issue_intent_mandate("did:aroha:g", "did:aroha:e", BASE, key)
    valid, mandate, reason = verify_mandate(m.token, pub)
    assert valid
    assert mandate is not None
    assert mandate.mandate_id == m.mandate.mandate_id
    assert reason is None


def test_verify_wrong_key():
    key = make_key()
    other_key = make_key()
    m = issue_intent_mandate("did:aroha:g", "did:aroha:e", BASE, key)
    valid, _, reason = verify_mandate(m.token, other_key.public_key())
    assert not valid
    assert reason and "signature" in reason.lower()


def test_verify_expired():
    key = make_key()
    m = issue_intent_mandate("did:aroha:g", "did:aroha:e", BASE, key, ttl_seconds=10)
    later = datetime.now(timezone.utc) + timedelta(seconds=60)
    valid, _, reason = verify_mandate(m.token, key.public_key(), now=later)
    assert not valid
    assert reason and "expired" in reason.lower()


def test_verify_grantee_mismatch():
    key = make_key()
    m = issue_intent_mandate("did:aroha:g", "did:aroha:e", BASE, key)
    valid, _, reason = verify_mandate(m.token, key.public_key(), expected_grantee="did:aroha:other")
    assert not valid
    assert reason and "grantee" in reason.lower()


def test_verify_malformed_token():
    key = make_key()
    valid, _, reason = verify_mandate("not!!valid!!", key.public_key())
    assert not valid
    assert reason


# ── attenuate_to_cart — narrowing enforcement ─────────────────────────────────

def _intent():
    key = make_key()
    return issue_intent_mandate("did:aroha:user", "did:aroha:agent", BASE, key), key


def test_attenuate_cart_valid():
    parent, key = _intent()
    narrow = SpendingConstraints(
        spend_limit_usd=100.0,
        session_limit_usd=50.0,
        require_human_approval_above_usd=50.0,
        allowed_merchants=["merchant-a"],
    )
    cart = attenuate_to_cart(parent, "did:aroha:provider", narrow, key)
    assert cart.mandate.mandate_tier == "cart"
    assert cart.mandate.parent_mandate_id == parent.mandate.mandate_id


def test_attenuate_cart_rejects_spend_limit_widening():
    parent, key = _intent()
    with pytest.raises(ValueError, match="spendLimit"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(spend_limit_usd=9999.0),
            key,
        )


def test_attenuate_cart_rejects_session_limit_widening():
    parent, key = _intent()
    with pytest.raises(ValueError, match="sessionLimit"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(spend_limit_usd=100.0, session_limit_usd=9999.0),
            key,
        )


def test_attenuate_cart_rejects_approval_threshold_widening():
    parent, key = _intent()
    with pytest.raises(ValueError, match="approval threshold"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(spend_limit_usd=100.0, require_human_approval_above_usd=9999.0),
            key,
        )


def test_attenuate_cart_rejects_unlisted_merchant():
    parent, key = _intent()
    with pytest.raises(ValueError, match="allowedMerchants"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(
                spend_limit_usd=100.0,
                allowed_merchants=["merchant-a", "merchant-unknown"],
            ),
            key,
        )


def test_attenuate_cart_rejects_empty_merchants_when_parent_restricts():
    parent, key = _intent()
    with pytest.raises(ValueError, match="allowedMerchants"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(spend_limit_usd=100.0, allowed_merchants=[]),
            key,
        )


def test_attenuate_cart_rejects_no_merchants_when_parent_restricts():
    parent, key = _intent()
    with pytest.raises(ValueError, match="allowedMerchants"):
        attenuate_to_cart(
            parent, "did:aroha:p",
            SpendingConstraints(spend_limit_usd=100.0),
            key,
        )


# ── attenuate_to_payment ──────────────────────────────────────────────────────

def test_attenuate_payment_rejects_spend_widening():
    parent, key = _intent()
    cart = attenuate_to_cart(
        parent, "did:aroha:provider",
        SpendingConstraints(spend_limit_usd=100.0, allowed_merchants=["merchant-a"]),
        key,
    )
    with pytest.raises(ValueError, match="spendLimit"):
        attenuate_to_payment(
            cart, "did:aroha:processor",
            SpendingConstraints(spend_limit_usd=9999.0, allowed_merchants=["merchant-a"]),
            key,
        )


# ── Full chain ────────────────────────────────────────────────────────────────

def test_full_chain():
    # One key signs every link here, so every grantor resolves to it. Named
    # DIDs are not self-certifying: the ancestors of a v2 token are resolved
    # through resolve_key (default: content-addressed DIDs only).
    user_key = make_key()
    intent = issue_intent_mandate("did:aroha:user", "did:aroha:agent", BASE, user_key)
    resolve = lambda did: user_key.public_key()

    cart = attenuate_to_cart(
        intent, "did:aroha:provider",
        SpendingConstraints(spend_limit_usd=100.0, allowed_merchants=["merchant-a"]),
        user_key,
    )
    assert cart.mandate.mandate_tier == "cart"

    payment = attenuate_to_payment(
        cart, "did:aroha:processor",
        SpendingConstraints(spend_limit_usd=42.0, allowed_merchants=["merchant-a"]),
        user_key,
    )
    assert payment.mandate.mandate_tier == "payment"
    assert payment.mandate.parent_mandate_id == cart.mandate.mandate_id
    assert payment.mandate.constraints.spend_limit_usd == 42.0

    valid, mandate, reason = verify_mandate(
        payment.token, user_key.public_key(), expected_grantee="did:aroha:processor", resolve_key=resolve
    )
    assert valid, reason
    assert mandate.mandate_id == payment.mandate.mandate_id


# ── Omission must not widen ───────────────────────────────────────────────────

def test_omitted_approval_threshold_is_inherited_not_dropped():
    # A child that leaves the human-approval threshold out used to drop it.
    from aroha.mandate import _assert_narrowing, _inherit_omitted
    parent = SpendingConstraints(spend_limit_usd=100.0, require_human_approval_above_usd=20.0)
    child = _inherit_omitted(parent, SpendingConstraints(spend_limit_usd=50.0))
    assert child.require_human_approval_above_usd == 20.0
    _assert_narrowing(parent, child, "intent", "cart")


def test_child_without_parent_limit_is_rejected():
    import pytest
    from aroha.mandate import _assert_narrowing
    parent = SpendingConstraints(spend_limit_usd=100.0, session_limit_usd=40.0)
    with pytest.raises(ValueError, match="sessionLimit"):
        _assert_narrowing(parent, SpendingConstraints(spend_limit_usd=50.0), "intent", "cart")


def test_child_currency_and_category_must_match():
    import pytest
    from aroha.mandate import _assert_narrowing
    parent = SpendingConstraints(spend_limit_usd=100.0, currency="EUR", merchant_category="travel")
    with pytest.raises(ValueError, match="currency"):
        _assert_narrowing(parent, SpendingConstraints(spend_limit_usd=50.0, currency="USD",
                                                      merchant_category="travel"), "intent", "cart")
    with pytest.raises(ValueError, match="merchantCategory"):
        _assert_narrowing(parent, SpendingConstraints(spend_limit_usd=50.0, currency="EUR",
                                                      merchant_category="food"), "intent", "cart")


def test_child_validity_window_cannot_extend():
    import pytest
    from aroha.mandate import _assert_narrowing
    parent = SpendingConstraints(spend_limit_usd=100.0, valid_until="2030-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="validUntil"):
        _assert_narrowing(parent, SpendingConstraints(spend_limit_usd=50.0,
                                                      valid_until="2031-01-01T00:00:00Z"), "intent", "cart")
