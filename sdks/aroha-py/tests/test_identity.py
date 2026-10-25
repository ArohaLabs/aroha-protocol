# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

import pytest
from aroha.identity import generate_did, extract_public_key


def test_generate_did_produces_correct_format():
    agent = generate_did("test-agent", "http://localhost:3000")
    assert agent["did"] == "did:aroha:test-agent"
    assert "private_key" in agent
    assert "public_key" in agent
    assert agent["document"]["id"] == "did:aroha:test-agent"


def test_generate_did_with_namespace():
    agent = generate_did("invoice-processor", "http://localhost", namespace="acme-corp")
    assert agent["did"] == "did:aroha:acme-corp.invoice-processor"


def test_extract_public_key_returns_bytes():
    agent = generate_did("key-test", "http://localhost:3001")
    pub = extract_public_key(agent["document"])
    assert isinstance(pub, bytes)
    assert len(pub) == 32


def test_extract_public_key_raises_for_revoked_key():
    agent = generate_did("revoke-test", "http://localhost:3002")
    doc = agent["document"]
    current_multibase = doc["verificationMethod"][0]["publicKeyMultibase"]
    doc["revokedKeys"] = [{"keyMultibase": current_multibase, "revokedAt": "2025-01-01T00:00:00+00:00", "reason": "test"}]
    with pytest.raises(ValueError, match="revoked"):
        extract_public_key(doc)


def test_generate_did_rejects_dot_in_agent_id():
    """Dots in agent_id would create a DID indistinguishable from a namespaced one."""
    with pytest.raises(ValueError, match="agent_id"):
        generate_did("acme.evil", "http://localhost")


def test_generate_did_rejects_special_chars_in_namespace():
    """Colons, hashes, and slashes are DID syntax — must not appear in namespace."""
    for bad in ["acme:corp", "acme#org", "acme/corp", "acme corp", ""]:
        with pytest.raises((ValueError, Exception)):
            generate_did("agent", "http://localhost", namespace=bad)


def test_generate_did_rejects_colon_injection_in_agent_id():
    """Colon in agent_id would break the DID method structure."""
    with pytest.raises(ValueError, match="agent_id"):
        generate_did("did:evil:agent", "http://localhost")
