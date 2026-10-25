# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Crypto: Signing + Encryption

Ed25519 signing (per spec: canonical JSON, keys sorted, proof excluded).
ECDH-ES+A256GCM body encryption, byte-compatible with aroha-core.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.jcs import js_stringify_sorted
from aroha.timeutil import iso_ms


# ── Signing ────────────────────────────────────────────────────────────────────

def sign_message(
    message: dict[str, Any],
    private_key: Ed25519PrivateKey,
    verification_method_id: str,
) -> dict[str, str]:
    """
    Sign a Aroha message. Returns a proof dict to embed in the envelope.

    Per spec: signature covers canonical JSON with 'proof' field excluded,
    all keys sorted lexicographically at every nesting level.
    """
    canonical = canonicalize_message(message)
    signature = private_key.sign(canonical.encode("utf-8"))
    proof_value = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return {
        "type": "Ed25519Signature2020",
        "created": iso_ms(datetime.now(timezone.utc)),
        "verificationMethod": verification_method_id,
        "proofPurpose": "authentication",
        "proofValue": proof_value,
    }


def verify_message_signature(
    message: dict[str, Any],
    public_key: Ed25519PublicKey | bytes,
) -> bool:
    """
    Verify a Aroha message signature.
    Returns True if valid, False otherwise (never raises).
    """
    proof = message.get("proof")
    if not isinstance(proof, dict) or not isinstance(proof.get("proofValue"), str) or not proof["proofValue"]:
        return False

    try:
        canonical = canonicalize_message(message)
        proof_value = proof["proofValue"]
        signature = base64.urlsafe_b64decode(proof_value + "=" * (-len(proof_value) % 4))
        key = public_key if isinstance(public_key, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(bytes(public_key))
        key.verify(signature, canonical.encode("utf-8"))
        return True
    except Exception:
        return False


def canonicalize_message(message: dict[str, Any]) -> str:
    """
    Produce the canonical string an envelope signature covers.

    The 'proof' field is excluded and the rest is serialised EXACTLY as the
    TypeScript SDK's ``JSON.stringify(sortKeysDeep(message))`` does
    (aroha-core/src/crypto/signing.ts canonicalizeMessage): ECMAScript number
    formatting (``10`` not ``10.0``), UTF-8 text rather than ASCII escapes,
    UTF-16 key order, integer-like keys first. Earlier releases used
    ``json.dumps(sort_keys=True)``, whose bytes differ for floats, non-ASCII
    text and some keys — such envelopes failed verification across SDKs.

    Note this is NOT RFC 8785 JCS (mandates and KELs use JCS); it is the
    legacy envelope canonical form, kept byte-identical to TypeScript.
    """
    without_proof = {k: v for k, v in message.items() if k != "proof"}
    return js_stringify_sorted(without_proof)


# ── Low-level signing ─────────────────────────────────────────────────────────
#
# sign_message()/verify_message_signature() always wrap the result in a full
# proof object — right for message envelopes, more than you need for a
# one-off payload where all you want is "prove I hold this DID's key over
# this data" (e.g. an out-of-band API request, not an Aroha message
# envelope). These two are that: canonicalize + sign, canonicalize + verify,
# a bare hex signature, nothing else attached. Mirrors signCanonical /
# verifyCanonicalSignature in aroha-core/src/crypto/signing.ts exactly — a
# signature produced by one verifies in the other.
#
# In Python this is barely more than canonicalize_message() + private_key.
# sign() — the `cryptography` package is already a dependency, so unlike the
# TS SDK (which required pulling in @noble/ed25519 to get one step below
# signMessage()), there's no second crypto library to add here. Provided
# anyway for parity: matching names/shapes across languages is worth more
# than the one line it would save to skip it.

def sign_canonical(payload: dict[str, Any], private_key: bytes | Ed25519PrivateKey) -> str:
    """Sign a flat/nested payload's canonical JSON. Returns a hex-encoded signature."""
    canonical = canonicalize_message(payload)
    key = private_key if isinstance(private_key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(private_key)
    signature = key.sign(canonical.encode("utf-8"))
    return signature.hex()


def verify_canonical(
    payload: dict[str, Any],
    signature_hex: str,
    public_key: bytes | Ed25519PublicKey,
) -> bool:
    """Verify a signature produced by sign_canonical against the same payload and signer's public key."""
    canonical = canonicalize_message(payload)
    key = public_key if isinstance(public_key, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(public_key)
    try:
        signature = bytes.fromhex(signature_hex)
        if len(signature) != 64:
            return False
        key.verify(signature, canonical.encode("utf-8"))
        return True
    except Exception:
        return False


# ── Encryption (ECDH-ES+A256GCM, byte-compatible with aroha-core) ───────────
#
# Port of aroha-core/src/crypto/encryption.ts:
#   * the recipient's Ed25519 public key is mapped to X25519 (birational map
#     u = (1 + y) / (1 - y) mod p, as @noble/curves edwardsToMontgomeryPub);
#   * a fresh ephemeral X25519 key pair does ECDH with it;
#   * the AES-256-GCM key is SHA-256(shared secret) — no AAD;
#   * IV 12 random bytes, 16-byte tag carried separately;
#   * fields: alg "ECDH-ES+A256GCM", epk, iv, ciphertext, tag (base64url, no padding).
# The recipient maps its Ed25519 seed to X25519 as edwardsToMontgomeryPriv
# does: the first 32 bytes of SHA-512(seed), clamped.
# No key material other than the ephemeral PUBLIC key is ever emitted.

_P25519 = 2**255 - 19
ENCRYPTION_ALG = "ECDH-ES+A256GCM"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ed25519_public_to_x25519(ed_pub: bytes) -> bytes:
    """Map a 32-byte Ed25519 public key to its X25519 (Montgomery u) form."""
    if len(ed_pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    # Validate it is a real curve point (raises on an invalid encoding).
    Ed25519PublicKey.from_public_bytes(bytes(ed_pub))
    y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)
    if y >= _P25519 or (1 - y) % _P25519 == 0:
        raise ValueError("Ed25519 public key has no X25519 equivalent")
    u = (1 + y) * pow((1 - y) % _P25519, _P25519 - 2, _P25519) % _P25519
    return u.to_bytes(32, "little")


def ed25519_private_to_x25519(ed_seed: bytes | Ed25519PrivateKey) -> bytes:
    """Map an Ed25519 private key (32-byte seed) to the matching X25519 scalar."""
    if isinstance(ed_seed, Ed25519PrivateKey):
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        ed_seed = ed_seed.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    if len(ed_seed) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    import hashlib
    h = bytearray(hashlib.sha512(bytes(ed_seed)).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def encrypt_body(plaintext: dict[str, Any], recipient_pub_bytes: bytes | Ed25519PublicKey) -> dict[str, str]:
    """Encrypt a message body for a recipient (ECDH-ES+A256GCM; decrypts in aroha-core).

    ``recipient_pub_bytes`` is the recipient's Ed25519 public key (32 bytes or
    an Ed25519PublicKey). The body is serialised with JavaScript number and string formatting.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    if isinstance(recipient_pub_bytes, Ed25519PublicKey):
        recipient_pub_bytes = recipient_pub_bytes.public_bytes(Encoding.Raw, PublicFormat.Raw)
    recipient_x = X25519PublicKey.from_public_bytes(ed25519_public_to_x25519(bytes(recipient_pub_bytes)))
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(recipient_x)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared)
    aes_key = digest.finalize()
    iv = os.urandom(12)
    # Key order does not matter to the recipient (it parses JSON); sorted
    # output keeps numbers and strings formatted exactly as JSON.stringify.
    payload = js_stringify_sorted(plaintext).encode("utf-8")
    sealed = AESGCM(aes_key).encrypt(iv, payload, None)
    return {
        "alg": ENCRYPTION_ALG,
        "epk": _b64u(eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "iv": _b64u(iv),
        "ciphertext": _b64u(sealed[:-16]),
        "tag": _b64u(sealed[-16:]),
    }


def decrypt_body(encrypted: dict[str, str], private_key_bytes: bytes | Ed25519PrivateKey) -> dict[str, Any]:
    """Decrypt an ECDH-ES+A256GCM body with the recipient's Ed25519 private key (32-byte seed).

    Raises ValueError for any other ``alg`` (including the pre-2.0 Python
    format, which carried its own key and is no longer accepted) and
    ``cryptography.exceptions.InvalidTag`` if the ciphertext was altered.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    if encrypted.get("alg") != ENCRYPTION_ALG:
        raise ValueError(f"Unsupported encrypted body alg {encrypted.get('alg')!r}; expected {ENCRYPTION_ALG}")
    x_priv = X25519PrivateKey.from_private_bytes(ed25519_private_to_x25519(private_key_bytes))
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(_b64u_decode(encrypted["epk"])))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared)
    aes_key = digest.finalize()
    iv = _b64u_decode(encrypted["iv"])
    if len(iv) != 12:
        raise ValueError("Encrypted body iv must be 12 bytes")
    tag = _b64u_decode(encrypted["tag"])
    if len(tag) != 16:
        raise ValueError("Encrypted body tag must be 16 bytes")
    plaintext = AESGCM(aes_key).decrypt(iv, _b64u_decode(encrypted["ciphertext"]) + tag, None)
    return json.loads(plaintext.decode("utf-8"))
