# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

from aroha.identity import mint_local_identity, prepare_publish


def test_mint_local_identity_carries_private_key_tagged_local():
    identity = mint_local_identity("test-firm", "http://localhost:8010/aroha/v1")
    assert identity["kind"] == "local"
    assert identity["did"] == "did:aroha:test-firm"
    assert "private_key" in identity
    assert identity["document"]["id"] == identity["did"]


def test_mint_local_identity_supports_namespace():
    identity = mint_local_identity("agent-a", "http://localhost:8010/aroha/v1", namespace="acme")
    assert identity["did"] == "did:aroha:acme.agent-a"


def test_prepare_publish_strips_private_key_entirely():
    local = mint_local_identity("test-firm", "http://localhost:8010/aroha/v1")
    publishable = prepare_publish(local)

    assert publishable["kind"] == "publishable"
    assert publishable["did"] == local["did"]
    assert publishable["public_key"] == local["public_key"]
    assert "private_key" not in publishable
