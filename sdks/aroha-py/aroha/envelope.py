# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Deprecated compatibility shim — use :mod:`aroha.messages`.

This module used to carry its own envelope builder and verifier. The
verifier had no nonce (replay) check, no max-TTL or future-``created``
check, and signed over ``json.dumps(sort_keys=True)``, whose bytes differ
from the TypeScript SDK's. There is now exactly ONE envelope implementation
(:func:`aroha.messages.build_envelope` / :func:`aroha.messages.validate_envelope`);
the two functions below only delegate to it.
"""

from __future__ import annotations

from typing import Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aroha.messages import NonceRegistry, build_envelope as _build, validate_envelope

__all__ = ["build_envelope", "verify_envelope"]

# Process-wide replay memory for callers of the legacy verify_envelope()
# that do not pass their own registry.
_DEFAULT_NONCES = NonceRegistry()


def build_envelope(
    msg_type: str,
    from_did: str,
    to_did: str,
    body: dict,
    correlation_id: str,
    private_key: Union[Ed25519PrivateKey, bytes],
    *,
    ttl_seconds: int = 300,
) -> dict:
    """Build and sign an Aroha message envelope. Delegates to :func:`aroha.messages.build_envelope`."""
    return _build(msg_type, from_did, to_did, body, correlation_id, private_key, ttl_seconds)


def verify_envelope(
    envelope: dict,
    sender_public_key: Union[bytes, Ed25519PublicKey, dict[str, Any]],
    my_did: str,
    nonce_registry: Optional[NonceRegistry] = None,
    **options: Any,
) -> bool:
    """True if the envelope passes :func:`aroha.messages.validate_envelope` (including the nonce check).

    Without ``nonce_registry`` a module-level registry is used, so a replayed
    envelope is rejected within this process.
    """
    ok, _ = validate_envelope(
        envelope, sender_public_key, my_did, nonce_registry if nonce_registry is not None else _DEFAULT_NONCES,
        **options,
    )
    return ok
