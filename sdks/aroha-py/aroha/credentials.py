# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Verifiable Credentials

Mirrors aroha-core/src/identity/credentials.ts byte-for-byte: same canonical
JSON form (sorted keys, compact separators), same Ed25519Signature2020 proof
shape, same signed payload. A credential issued in either language verifies
in the other.

Previously this SDK had no Python equivalent of issueCredential/
verifyCredential at all, even though the package docstring already claimed
"Verifiable Credentials" as a Layer 1 feature — an app wanting to issue e.g.
a CorporateIdentityCredential (a firm vouching "this agent is operated by
us") from Python had nothing to call, and had to shell out to a Node helper
running @aroha-sdk/core instead. This closes that gap directly.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aroha.jcs import js_stringify_sorted

__all__ = [
    "VerifiableCredential",
    "issue_credential",
    "verify_credential",
    "is_credential_expired",
    "issue_corporate_identity_credential",
]

VerifiableCredential = dict[str, Any]


def _canonical_json_bytes(obj: dict) -> bytes:
    # Byte-exact TypeScript JSON.stringify(sortKeysDeep(obj)): json.dumps
    # differs on integer-like keys (JavaScript puts them first, numerically)
    # and on number formatting (10.0 vs 10, 1e21 vs 1e+21).
    return js_stringify_sorted(obj).encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _load_private_key(private_key: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    return (
        private_key
        if isinstance(private_key, Ed25519PrivateKey)
        else Ed25519PrivateKey.from_private_bytes(private_key)
    )


def _load_public_key(public_key: bytes | Ed25519PublicKey) -> Ed25519PublicKey:
    return (
        public_key
        if isinstance(public_key, Ed25519PublicKey)
        else Ed25519PublicKey.from_public_bytes(public_key)
    )


def issue_credential(
    credential: dict[str, Any],
    issuer_private_key: bytes | Ed25519PrivateKey,
    issuer_key_id: str,
) -> VerifiableCredential:
    """Issue a Verifiable Credential.

    `credential` must NOT include `id` or `proof` — both are added here.
    The issuer signs the credential's canonical JSON with their Ed25519 key.
    """
    unsigned = {**credential, "id": f"urn:uuid:{uuid.uuid4()}"}
    payload = _canonical_json_bytes(unsigned)

    key = _load_private_key(issuer_private_key)
    signature = key.sign(payload)

    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": issuer_key_id,
        "proofPurpose": "assertionMethod",
        "proofValue": _b64url_encode(signature),
    }
    return {**unsigned, "proof": proof}


def verify_credential(
    credential: VerifiableCredential,
    issuer_public_key: bytes | Ed25519PublicKey,
) -> bool:
    """Verify a Verifiable Credential's signature. Returns True if valid."""
    proof = credential.get("proof")
    if not proof:
        return False

    unsigned = {k: v for k, v in credential.items() if k != "proof"}
    payload = _canonical_json_bytes(unsigned)

    try:
        signature = _b64url_decode(proof["proofValue"])
        _load_public_key(issuer_public_key).verify(signature, payload)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def is_credential_expired(credential: VerifiableCredential) -> bool:
    expires = credential.get("expirationDate")
    if not expires:
        return False
    return datetime.fromisoformat(expires.replace("Z", "+00:00")) < datetime.now(timezone.utc)


def issue_corporate_identity_credential(
    firm_did: str,
    firm_private_key: bytes | Ed25519PrivateKey,
    agent_did: str,
    *,
    firm_name: str = "",
    firm_domain: str = "",
    firm_country: str = "",
    valid_for_days: Optional[int] = None,
    key_fragment: str = "key-1",
) -> VerifiableCredential:
    """Convenience wrapper: a firm vouching that `agent_did` is operated by it.

    Mirrors CorporateIdentityCredential from aroha-core/src/identity/
    credentials.ts. `key_fragment` defaults to "key-1" — the fragment
    generate_did() puts the primary key at.
    """
    now = datetime.now(timezone.utc)
    credential: dict[str, Any] = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "CorporateIdentityCredential"],
        "issuer": firm_did,
        "issuanceDate": now.isoformat(),
        "credentialSubject": {
            "id": agent_did,
            "companyName": firm_name or firm_did,
            "companyDomain": firm_domain,
            "registeredCountry": firm_country,
        },
    }
    if valid_for_days:
        credential["expirationDate"] = (now + timedelta(days=valid_for_days)).isoformat()

    return issue_credential(credential, firm_private_key, f"{firm_did}#{key_fragment}")
