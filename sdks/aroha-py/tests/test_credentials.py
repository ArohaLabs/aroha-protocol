# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aroha.credentials import (
    issue_credential, verify_credential, is_credential_expired,
    issue_corporate_identity_credential,
)


@pytest.fixture
def issuer_key():
    return Ed25519PrivateKey.generate()


def test_issue_and_verify_credential(issuer_key):
    credential = issue_credential(
        {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:aroha:acme",
            "issuanceDate": "2026-01-01T00:00:00+00:00",
            "credentialSubject": {"id": "did:aroha:acme.agent-a"},
        },
        issuer_key,
        "did:aroha:acme#key-1",
    )

    assert credential["id"].startswith("urn:uuid:")
    assert credential["proof"]["type"] == "Ed25519Signature2020"
    assert verify_credential(credential, issuer_key.public_key())


def test_verify_credential_rejects_tampered_subject(issuer_key):
    credential = issue_credential(
        {"issuer": "did:aroha:acme", "issuanceDate": "x", "credentialSubject": {"id": "did:aroha:agent"}},
        issuer_key, "did:aroha:acme#key-1",
    )
    credential["credentialSubject"]["id"] = "did:aroha:different-agent"
    assert verify_credential(credential, issuer_key.public_key()) is False


def test_verify_credential_rejects_wrong_key(issuer_key):
    other_key = Ed25519PrivateKey.generate()
    credential = issue_credential(
        {"issuer": "did:aroha:acme", "issuanceDate": "x", "credentialSubject": {"id": "did:aroha:agent"}},
        issuer_key, "did:aroha:acme#key-1",
    )
    assert verify_credential(credential, other_key.public_key()) is False


def test_verify_credential_returns_false_without_proof():
    assert verify_credential({"credentialSubject": {"id": "x"}}, Ed25519PrivateKey.generate().public_key()) is False


def test_is_credential_expired():
    assert is_credential_expired({}) is False
    assert is_credential_expired({"expirationDate": "2000-01-01T00:00:00+00:00"}) is True
    assert is_credential_expired({"expirationDate": "2999-01-01T00:00:00+00:00"}) is False


def test_issue_corporate_identity_credential(issuer_key):
    credential = issue_corporate_identity_credential(
        "did:aroha:acme-cpa", issuer_key, "did:aroha:acme-cpa.tax-agent",
        firm_name="Acme CPA", firm_domain="acme-cpa.com", valid_for_days=365,
    )

    assert credential["type"] == ["VerifiableCredential", "CorporateIdentityCredential"]
    assert credential["issuer"] == "did:aroha:acme-cpa"
    assert credential["credentialSubject"]["id"] == "did:aroha:acme-cpa.tax-agent"
    assert credential["credentialSubject"]["companyName"] == "Acme CPA"
    assert "expirationDate" in credential
    assert verify_credential(credential, issuer_key.public_key())


def test_issue_corporate_identity_credential_no_expiry_by_default(issuer_key):
    credential = issue_corporate_identity_credential("did:aroha:acme", issuer_key, "did:aroha:acme.agent")
    assert "expirationDate" not in credential


def test_canonical_bytes_match_typescript_json_stringify_sorted():
    from aroha.credentials import _canonical_json_bytes
    # Integer-like keys first (numerically), JS number formatting — not json.dumps(sort_keys).
    assert _canonical_json_bytes({"b": 10.0, "10": 1, "9": 2, "a": 1e21}) == b'{"9":2,"10":1,"a":1e+21,"b":10}'
