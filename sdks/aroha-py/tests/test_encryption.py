# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""ECDH-ES+A256GCM body encryption, byte-compatible with aroha-core/src/crypto/encryption.ts.

TS_VECTOR was produced by the TypeScript ``encryptBody`` (packages/aroha-core
dist, @noble/curves 1.9.7) for a recipient whose Ed25519 seed is 32 bytes of
0x09; Python must decrypt it. test_cross_language.py checks both directions
live when node and the built TS packages are available.
"""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.crypto import (
    decrypt_body,
    ed25519_private_to_x25519,
    ed25519_public_to_x25519,
    encrypt_body,
)

SEED = bytes([9]) * 32
TS_VECTOR = {
    "recipientPublicKeyHex": "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    "plaintext": {"amount": 10.5, "note": "héllo 😀", "nested": {"2": True, "10": [1, 2.25]}},
    "encrypted": {
        "alg": "ECDH-ES+A256GCM",
        "epk": "ESD8db8bcWQ5_DcFzwqysk_v-SZyCXaZviTNmYdcW20",
        "iv": "ZZ40t9ssVRW__bVe",
        "ciphertext": "3nnruPHitEvAbmbgl1GCSpIrPYtWXlq_Mhn3tTkID-gtFliNP2c18XVGDgdvKb8GVJuDmXkHJWwqdSLYXu_pOtGTIgDeuA",
        "tag": "EC7kYlJ2VIwUA0SGHBj0Bg",
    },
}


def _pub(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_typescript_vector_decrypts():
    assert _pub(SEED).hex() == TS_VECTOR["recipientPublicKeyHex"]
    assert decrypt_body(TS_VECTOR["encrypted"], SEED) == TS_VECTOR["plaintext"]
    assert decrypt_body(TS_VECTOR["encrypted"], Ed25519PrivateKey.from_private_bytes(SEED)) == TS_VECTOR["plaintext"]


def test_key_conversion_agrees_between_public_and_private_forms():
    for seed in (SEED, bytes(range(32)), bytes([255]) * 32):
        x_priv = X25519PrivateKey.from_private_bytes(ed25519_private_to_x25519(seed))
        assert x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == ed25519_public_to_x25519(_pub(seed))


def test_round_trip_and_wire_shape_carry_no_key_material():
    enc = encrypt_body({"secret": "s3cret", "n": 1}, _pub(SEED))
    assert set(enc) == {"alg", "epk", "iv", "ciphertext", "tag"}
    assert enc["alg"] == "ECDH-ES+A256GCM"
    assert decrypt_body(enc, SEED) == {"secret": "s3cret", "n": 1}
    with pytest.raises(Exception):
        decrypt_body(enc, bytes([8]) * 32)  # wrong recipient


def test_tampering_and_legacy_format_are_rejected():
    enc = dict(TS_VECTOR["encrypted"])
    enc["tag"] = "A" + enc["tag"][1:]
    with pytest.raises(InvalidTag):
        decrypt_body(enc, SEED)
    legacy = {"alg": "A256GCM", "iv": "AAAAAAAAAAAAAAAA", "ciphertext": "", "tag": "", "_key": "AAAA"}
    with pytest.raises(ValueError, match="Unsupported encrypted body alg"):
        decrypt_body(legacy, SEED)
