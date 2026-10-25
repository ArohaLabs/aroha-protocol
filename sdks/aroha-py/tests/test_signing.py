# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
"""Security properties of aroha-sig, plus cross-language compatibility.

Every negative case here is an attack the scheme exists to stop; if one starts
passing, the guarantee it encodes is gone.

The vectors in TestCrossLanguage were produced by the TypeScript
implementation in @aroha-sdk/run. Without them, "the two SDKs are compatible"
is an assertion nobody checks — and canonicalisation drift between languages is
both easy to introduce and invisible until an integration fails in production.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aroha.signing import (
    DEFAULT_MAX_SKEW_MS,
    SIG_HEADERS,
    NonceGuard,
    canonical_string,
    sign_request,
    verify_signed_request,
)

ALICE = "did:aroha:alice"
MALLORY = "did:aroha:mallory"


def _keypair() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub


@pytest.fixture(scope="module")
def alice() -> tuple[bytes, bytes]:
    return _keypair()


@pytest.fixture(scope="module")
def mallory() -> tuple[bytes, bytes]:
    return _keypair()


@pytest.fixture
def resolver(alice, mallory):
    keys = {ALICE: alice[1], MALLORY: mallory[1]}
    return lambda did: keys.get(did)


class TestSignAndVerify:
    def test_accepts_a_correctly_signed_request(self, alice, resolver):
        body = '{"message":"Hello"}'
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is True
        assert result.did == ALICE

    def test_rejects_a_tampered_body(self, alice, resolver):
        body = '{"message":"Hello"}'
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body='{"message":"Goodbye"}',
            resolve_public_key=resolver,
        )
        assert result.ok is False

    def test_rejects_a_signature_replayed_against_another_path(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/admin",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is False

    def test_rejects_a_signature_replayed_with_another_method(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="DELETE",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is False

    def test_rejects_impersonation(self, mallory, resolver):
        """Mallory signs with her own key but claims to be Alice."""
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=mallory[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is False

    def test_rejects_missing_headers(self, resolver):
        result = verify_signed_request(
            headers={}, method="POST", path="/v1/run", resolve_public_key=resolver
        )
        assert result.ok is False
        assert result.reason == "Missing signature headers"

    def test_rejects_a_stale_timestamp(self, alice, resolver):
        old = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 3600))
        body = "{}"
        headers = sign_request(
            did=ALICE,
            private_key=alice[0],
            method="POST",
            path="/v1/run",
            body=body,
            timestamp=old,
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is False
        assert "window" in (result.reason or "")

    def test_headers_are_read_case_insensitively(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        upper = {k.title(): v for k, v in headers.items()}
        result = verify_signed_request(
            headers=upper,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
        )
        assert result.ok is True


class TestAllowList:
    def test_permits_a_listed_caller(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
            allowed_callers=[ALICE],
        )
        assert result.ok is True

    def test_rejects_an_unlisted_caller_with_a_valid_signature(self, mallory, resolver):
        body = "{}"
        headers = sign_request(
            did=MALLORY, private_key=mallory[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
            allowed_callers=[ALICE],
        )
        assert result.ok is False
        assert result.reason == "Caller not permitted"

    def test_an_empty_allow_list_permits_nobody(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
            allowed_callers=[],
        )
        assert result.ok is False

    def test_does_not_resolve_a_key_for_an_unlisted_caller(self, mallory):
        """Ordering is the security property, not just the outcome.

        Resolving before the allow-list check performs a registry lookup for an
        unauthorised caller, which makes the endpoint an oracle for whether a
        DID exists — observable through latency.
        """
        calls: list[str] = []

        def counting_resolver(did: str) -> bytes | None:
            calls.append(did)
            return mallory[1]

        body = "{}"
        headers = sign_request(
            did=MALLORY, private_key=mallory[0], method="POST", path="/v1/run", body=body
        )
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=counting_resolver,
            allowed_callers=[ALICE],
        )
        assert result.ok is False
        assert calls == []


class TestReplayProtection:
    def test_rejects_a_byte_identical_replay(self, alice, resolver):
        body = "{}"
        headers = sign_request(
            did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body=body
        )
        guard = NonceGuard()
        kwargs = dict(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=body,
            resolve_public_key=resolver,
            consume_nonce=guard,
        )
        assert verify_signed_request(**kwargs).ok is True
        assert verify_signed_request(**kwargs).ok is False

    def test_does_not_consume_a_nonce_for_a_failing_request(self, alice, mallory, resolver):
        """A bad-signature replay must not burn an honest caller's nonce.

        Otherwise the replay defence becomes a denial-of-service tool against
        the very caller it protects.
        """
        body = "{}"
        guard = NonceGuard()

        # Mallory signs badly but reuses a nonce Alice is about to use.
        forged = sign_request(
            did=ALICE,
            private_key=mallory[0],
            method="POST",
            path="/v1/run",
            body=body,
            nonce="shared-nonce",
        )
        assert (
            verify_signed_request(
                headers=forged,
                method="POST",
                path="/v1/run",
                body=body,
                resolve_public_key=resolver,
                consume_nonce=guard,
            ).ok
            is False
        )

        # Alice's genuine request with the same nonce must still be accepted.
        genuine = sign_request(
            did=ALICE,
            private_key=alice[0],
            method="POST",
            path="/v1/run",
            body=body,
            nonce="shared-nonce",
        )
        assert (
            verify_signed_request(
                headers=genuine,
                method="POST",
                path="/v1/run",
                body=body,
                resolve_public_key=resolver,
                consume_nonce=guard,
            ).ok
            is True
        )

    def test_allows_distinct_nonces_from_the_same_caller(self, alice, resolver):
        guard = NonceGuard()
        for _ in range(3):
            headers = sign_request(
                did=ALICE, private_key=alice[0], method="POST", path="/v1/run", body="{}"
            )
            assert (
                verify_signed_request(
                    headers=headers,
                    method="POST",
                    path="/v1/run",
                    body="{}",
                    resolve_public_key=resolver,
                    consume_nonce=guard,
                ).ok
                is True
            )


class TestCrossLanguage:
    """Vectors generated by @aroha-sdk/run (TypeScript).

    These pin wire compatibility. If canonicalisation, header names, or the
    base64url encoding drift apart between the SDKs, these fail here rather
    than in someone's integration.
    """

    SEED = bytes.fromhex("0707070707070707070707070707070707070707070707070707070707070707")
    PUBLIC_KEY = bytes.fromhex(
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    )
    BODY = '{"message":"Hello","n":1}'
    TIMESTAMP = "2026-07-28T00:00:00.000Z"
    NONCE = "fixed-nonce-0001"
    CANONICAL = (
        "POST\n/v1/run\n2026-07-28T00:00:00.000Z\nfixed-nonce-0001\n"
        "19e2e4383bf21a5dec0a6ca52bd9e04d39186edf08cb95eb4b8d7cf1e1d7c143"
    )
    SIGNATURE = (
        "xvU1TXK0kC1RfQKNsiaM_K3WA2InjlWQ9eYn8E34icOMqrW1XN0Wld5g6WXCDcQL-sjHRdB_RFnprWRG9RKBCQ"
    )

    def test_canonical_string_matches_typescript(self):
        assert (
            canonical_string("POST", "/v1/run", self.TIMESTAMP, self.NONCE, self.BODY)
            == self.CANONICAL
        )

    def test_python_reproduces_the_typescript_signature(self):
        """Ed25519 is deterministic, so the bytes must match exactly."""
        headers = sign_request(
            did=ALICE,
            private_key=self.SEED,
            method="POST",
            path="/v1/run",
            body=self.BODY,
            timestamp=self.TIMESTAMP,
            nonce=self.NONCE,
        )
        assert headers[SIG_HEADERS["signature"]] == self.SIGNATURE

    def test_python_verifies_a_typescript_signed_request(self):
        headers = {
            SIG_HEADERS["did"]: ALICE,
            SIG_HEADERS["timestamp"]: self.TIMESTAMP,
            SIG_HEADERS["nonce"]: self.NONCE,
            SIG_HEADERS["signature"]: self.SIGNATURE,
        }
        result = verify_signed_request(
            headers=headers,
            method="POST",
            path="/v1/run",
            body=self.BODY,
            resolve_public_key=lambda did: self.PUBLIC_KEY,
            # The vector has a fixed timestamp, so skew checking would reject it
            # purely for age. Widen the window rather than weaken the check.
            max_skew_ms=DEFAULT_MAX_SKEW_MS * 10**6,
        )
        assert result.ok is True
        assert result.did == ALICE

    def test_accepts_a_pkcs8_key_from_webcrypto(self):
        """WebCrypto exports PKCS#8; a key generated in TS must work here."""
        pkcs8 = bytes.fromhex("302e020100300506032b657004220420") + self.SEED
        headers = sign_request(
            did=ALICE,
            private_key=pkcs8,
            method="POST",
            path="/v1/run",
            body=self.BODY,
            timestamp=self.TIMESTAMP,
            nonce=self.NONCE,
        )
        assert headers[SIG_HEADERS["signature"]] == self.SIGNATURE
