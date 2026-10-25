# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Layer 1: Identity

Implements W3C DID generation with Ed25519 keypairs.
API mirrors the TypeScript aroha-core/src/identity/did.ts.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# Allowed charset for DID components: letters, digits, hyphens, underscores.
# Dots, colons, hashes, slashes and whitespace are DID syntax characters and
# must not appear inside agent_id or namespace to prevent injection / spoofing.
_DID_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _validate_did_component(value: str, name: str) -> None:
    if not _DID_COMPONENT_RE.match(value):
        raise ValueError(
            f"Invalid {name} {value!r}: must match [a-zA-Z0-9][a-zA-Z0-9_-]{{0,62}} "
            f"(no dots, colons, hashes, slashes, or whitespace)"
        )

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

# ── Base58 (multibase 'z' prefix) ─────────────────────────────────────────────

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _encode_base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    digits = []
    while n > 0:
        digits.append(_BASE58_ALPHABET[n % 58 : n % 58 + 1])
        n //= 58
    for byte in data:
        if byte != 0:
            break
        digits.append(b"1")
    return b"".join(reversed(digits)).decode("ascii")


def _decode_base58(s: str) -> bytes:
    """Textbook base58btc decode: round-trips anything _encode_base58 produces.

    The previous version always returned exactly 32 bytes, so a short input
    such as the suffix of the NAMED DID ``did:aroha:zebra`` decoded to a
    zero-padded "key", and inputs longer than 32 bytes lost bytes. Mirrors
    the fix in aroha-core/src/identity/did.ts (decodeBase58).
    """
    leading_zeros = 0
    while leading_zeros < len(s) and s[leading_zeros] == "1":
        leading_zeros += 1
    n = 0
    for c in s:
        idx = _BASE58_ALPHABET.find(c.encode()) if c.isascii() else -1
        if idx < 0:
            raise ValueError(f"Invalid base58 character {c!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * leading_zeros + body


def to_multibase(pub_bytes: bytes) -> str:
    """Encode public key bytes as multibase base58btc (prefix 'z')."""
    return "z" + _encode_base58(pub_bytes)


def from_multibase(multibase: str) -> bytes:
    """Decode a multibase base58btc string to bytes."""
    if not multibase.startswith("z"):
        raise ValueError("Only base58btc multibase (prefix 'z') is supported")
    return _decode_base58(multibase[1:])


# ── Types ──────────────────────────────────────────────────────────────────────

@dataclass
class VerificationMethod:
    id: str
    type: str = "Ed25519VerificationKey2020"
    controller: str = ""
    public_key_multibase: str = ""


@dataclass
class ServiceEndpoint:
    id: str
    type: str = "ArohaEndpoint"
    service_endpoint: str = ""


@dataclass
class DIDDocument:
    context: list[str]
    id: str
    verification_method: list[VerificationMethod]
    authentication: list[str]
    assertion_method: list[str]
    key_agreement: list[str]
    service: list[ServiceEndpoint]
    created: str
    updated: str

    def to_dict(self) -> dict:
        return {
            "@context": self.context,
            "id": self.id,
            "verificationMethod": [
                {
                    "id": vm.id,
                    "type": vm.type,
                    "controller": vm.controller,
                    "publicKeyMultibase": vm.public_key_multibase,
                }
                for vm in self.verification_method
            ],
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
            "keyAgreement": self.key_agreement,
            "service": [
                {"id": s.id, "type": s.type, "serviceEndpoint": s.service_endpoint}
                for s in self.service
            ],
            "created": self.created,
            "updated": self.updated,
        }


@dataclass
class AgentKeyPair:
    did: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    public_key_bytes: bytes
    document: DIDDocument


# ── DID Generation ─────────────────────────────────────────────────────────────

def generate_did(agent_id: str, endpoint: str, *, namespace: Optional[str] = None) -> dict:
    """
    Generate a new Aroha DID with a fresh Ed25519 keypair.

    Args:
        agent_id: Human-readable identifier (e.g. "expedia-flights-v2")
        endpoint: Aroha endpoint URL for the agent
        namespace: Optional org namespace prefix (e.g. "acme-corp")

    Returns:
        dict with keys: did, private_key, public_key, public_key_bytes, document
        where document is a plain dict matching the DID Document JSON schema.
    """
    _validate_did_component(agent_id, "agent_id")
    if namespace is not None:
        _validate_did_component(namespace, "namespace")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    qualified_id = f"{namespace}.{agent_id}" if namespace else agent_id
    did = f"did:aroha:{qualified_id}"
    now = datetime.now(timezone.utc).isoformat()
    key_id = f"{did}#key-1"
    multibase = to_multibase(pub_bytes)

    document: dict = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "keyAgreement": [key_id],
        "service": [
            {
                "id": f"{did}#aroha",
                "type": "ArohaEndpoint",
                "serviceEndpoint": endpoint,
            }
        ],
        "created": now,
        "updated": now,
    }

    return {
        "did": did,
        "private_key": private_key,
        "public_key": public_key,
        "public_key_bytes": pub_bytes,
        "document": document,
    }


# ── Local vs. publishable identity ─────────────────────────────────────────
#
# generate_did() returns a dict carrying the private key — right for that
# function, since something has to mint the key, but nothing about that dict
# stops it from being handed to a registry-publish call by mistake. An app
# that mints identities meant to stay local (the common case) previously had
# to remember, at every call site, to strip the private key and stamp
# visibility/published fields by hand — a convention, not a guarantee.
#
# mint_local_identity() + prepare_publish() make that structural: the dict
# prepare_publish() returns has no "private_key" key at all, so there is no
# way to accidentally forward it into a publish call. Mirrors LocalIdentity/
# PublishableIdentity in aroha-core/src/identity/local-identity.ts.

def mint_local_identity(agent_id: str, endpoint: str, *, namespace: Optional[str] = None) -> dict:
    """Mint a new identity, explicitly tagged as local. Same generation as generate_did()."""
    identity = generate_did(agent_id, endpoint, namespace=namespace)
    return {
        "kind": "local",
        "did": identity["did"],
        "private_key": identity["private_key"],
        "public_key": identity["public_key"],
        "public_key_bytes": identity["public_key_bytes"],
        "document": identity["document"],
    }


def prepare_publish(local_identity: dict) -> dict:
    """The only way to get a publishable identity dict — no private_key key
    at all, not just a convention of leaving it out. Call this at the one
    point an app actually decides to publish, not at every mint site."""
    return {
        "kind": "publishable",
        "did": local_identity["did"],
        "public_key": local_identity["public_key"],
        "public_key_bytes": local_identity["public_key_bytes"],
        "document": local_identity["document"],
    }


def extract_public_key(doc: dict) -> bytes:
    """
    Extract public key bytes from a DID Document dict.

    **Security contract:** this function checks `doc["revokedKeys"]` as a
    convenience, but it does NOT verify the authenticity of the document itself.
    You MUST ensure `doc` comes from a trusted source (e.g. a registry response
    that you have verified, or the output of your own `generate_did` call) before
    calling this function.  An attacker who can supply an arbitrary `doc` dict
    can both suppress revocation (by omitting `revokedKeys`) and inject a
    replacement key (by swapping `verificationMethod[0]`).

    For production agent-to-agent calls, resolve the DID through a trusted
    registry and verify any enclosing envelope proof BEFORE extracting the key.

    Raises ValueError if the key appears in doc["revokedKeys"].
    """
    multibase = doc["verificationMethod"][0]["publicKeyMultibase"]
    for revoked in doc.get("revokedKeys", []):
        if revoked.get("keyMultibase") == multibase:
            raise ValueError(
                f"Key {multibase[:12]}… was revoked at {revoked.get('revokedAt', 'unknown')}: "
                f"{revoked.get('reason', 'no reason given')}"
            )
    return from_multibase(multibase)


def extract_public_key_bytes(doc: DIDDocument) -> bytes:
    """Extract public key bytes from a DIDDocument dataclass (internal use)."""
    vm = doc.verification_method[0]
    return from_multibase(vm.public_key_multibase)


def extract_endpoint(doc: DIDDocument) -> str:
    """Extract the Aroha service endpoint URL from a DIDDocument dataclass."""
    for svc in doc.service:
        if svc.type == "ArohaEndpoint":
            return svc.service_endpoint
    raise ValueError(f"No ArohaEndpoint in DID Document {doc.id}")
