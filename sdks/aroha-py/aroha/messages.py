# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Layer 3: Messaging

Envelope builder, the ONE envelope validator, nonce registry, all 19 message
types and the error codes. Mirrors aroha-core/src/messages/ (envelope.ts,
nonce.ts, types.ts) in the TypeScript SDK.

Envelope signatures cover ``canonicalize_message`` (aroha.crypto), which is a
byte-exact port of the TypeScript ``JSON.stringify(sortKeysDeep(envelope))``
with ``proof`` removed — so envelopes built here verify in TypeScript and
vice versa (including bodies with floats such as ``10.0`` and non-ASCII text).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aroha.crypto import sign_message, verify_message_signature
from aroha.identity import from_multibase
from aroha.nonce_store import FileNonceStore, MapNonceStore, NonceStore
from aroha.safety import require_dev_mode
from aroha.timeutil import iso_ms, now_ms, parse_iso_ms, to_ms

__all__ = [
    "MESSAGE_TYPES",
    "Aroha_MESSAGE_TYPES",
    "Aroha_CONTEXT",
    "ArohaErrorCode",
    "NonceRegistry",
    "NonceStore",
    "MapNonceStore",
    "FileNonceStore",
    "MAX_NONCE_LENGTH",
    "ArohaEnvelope",
    "DEFAULT_MAX_ENVELOPE_TTL_MS",
    "DEFAULT_MAX_FUTURE_SKEW_MS",
    "build_envelope",
    "validate_envelope",
    "new_correlation_id",
    "sender_did",
]

# ── Message Types ──────────────────────────────────────────────────────────────

#: The 19 message types of ``ArohaMessageType`` (aroha-core/src/messages/types.ts).
MESSAGE_TYPES: frozenset[str] = frozenset({
    "ArohaRequest", "ArohaResponse", "ArohaStream",
    "ArohaNegotiate", "ArohaCounterOffer", "ArohaAccept",
    "ArohaReserve", "ArohaReserveAck",
    "ArohaCommit", "ArohaCommitAck",
    "ArohaCancel", "ArohaCancelAck",
    "ArohaDelegate", "ArohaError", "ArohaSatisfactionSignal",
    "ArohaSpendingMandate", "ArohaTaskMandate",
    "ArohaDispute", "ArohaDisputeResolution",
})
#: Backward-compatible alias.
Aroha_MESSAGE_TYPES = MESSAGE_TYPES

Aroha_CONTEXT = [
    "https://aroha-labs.com/contexts/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]


class ArohaErrorCode(str, Enum):
    """
    Wire values for the "code" field of an ArohaError body.
    Values match the TypeScript ArohaErrorCode enum exactly so that agents
    implemented in different SDKs interoperate correctly.
    """
    # Auth / access
    UNAUTHORIZED             = "Aroha_UNAUTHORIZED"
    FORBIDDEN                = "Aroha_FORBIDDEN"

    # Protocol
    INVALID_SIGNATURE        = "Aroha_INVALID_SIGNATURE"
    EXPIRED_MESSAGE          = "Aroha_EXPIRED_MESSAGE"
    REPLAY_DETECTED          = "Aroha_REPLAY_DETECTED"
    UNKNOWN_CAPABILITY       = "Aroha_UNKNOWN_CAPABILITY"
    TRUST_LEVEL_INSUFFICIENT = "Aroha_TRUST_LEVEL_INSUFFICIENT"

    # Saga
    RESERVATION_FAILED       = "Aroha_RESERVATION_FAILED"
    RESERVATION_EXPIRED      = "Aroha_RESERVATION_EXPIRED"
    COMMIT_FAILED            = "Aroha_COMMIT_FAILED"
    CANCEL_FAILED            = "Aroha_CANCEL_FAILED"
    INVALID_TOKEN            = "Aroha_INVALID_TOKEN"

    # Availability
    NO_INVENTORY             = "Aroha_NO_INVENTORY"
    CAPACITY_EXCEEDED        = "Aroha_CAPACITY_EXCEEDED"
    SERVICE_UNAVAILABLE      = "Aroha_SERVICE_UNAVAILABLE"

    # Generic
    INTERNAL_ERROR           = "Aroha_INTERNAL_ERROR"
    INVALID_PARAMS           = "Aroha_INVALID_PARAMS"

    # Capability matching
    CSN_NO_STRUCTURAL_MATCH  = "CSN_NO_STRUCTURAL_MATCH"

    # Task-mandate enforcement
    ACTION_LIMIT_EXCEEDED     = "Aroha_ACTION_LIMIT_EXCEEDED"
    COMPUTE_LIMIT_EXCEEDED    = "Aroha_COMPUTE_LIMIT_EXCEEDED"
    REVERSIBILITY_VIOLATION   = "Aroha_REVERSIBILITY_VIOLATION"
    HUMAN_GATE_REQUIRED       = "Aroha_HUMAN_GATE_REQUIRED"
    DATA_ACCESS_VIOLATION     = "Aroha_DATA_ACCESS_VIOLATION"
    SANDBOX_REQUIRED          = "Aroha_SANDBOX_REQUIRED"
    DELEGATION_DEPTH_EXCEEDED = "Aroha_DELEGATION_DEPTH_EXCEEDED"
    CAPABILITY_NOT_PERMITTED  = "Aroha_CAPABILITY_NOT_PERMITTED"

    # Settlement / disputes
    SETTLEMENT_RAIL_MISMATCH  = "Aroha_SETTLEMENT_RAIL_MISMATCH"
    COMMIT_DISPUTED           = "Aroha_COMMIT_DISPUTED"


# ── Nonce Registry ─────────────────────────────────────────────────────────────

#: Longest nonce :func:`validate_envelope` accepts. Envelopes built by any
#: Aroha SDK carry 64 hex characters; the cap bounds what a sender can make
#: the replay store hold per message.
MAX_NONCE_LENGTH = 128


class NonceRegistry:
    """Replay prevention: remembers each key until its expiry, then forgets it.

    Backed by a pluggable :class:`~aroha.nonce_store.NonceStore`. The default
    :class:`~aroha.nonce_store.MapNonceStore` is in-memory, so a restart
    forgets every nonce — the envelope max-TTL (5 min by default) bounds that
    replay window. A single instance closes it with
    ``NonceRegistry(FileNonceStore("/var/lib/aroha/nonces.jsonl"))``;
    multi-instance deployments need a shared store implementing
    :class:`~aroha.nonce_store.NonceStore`.

    :func:`validate_envelope` passes sender-scoped keys (``"<from>:<nonce>"``)
    and only for envelopes whose signature already verified.
    """

    def __init__(self, store: Optional[NonceStore] = None) -> None:
        self._store: NonceStore = store if store is not None else MapNonceStore()

    @property
    def store(self) -> NonceStore:
        return self._store

    def check(self, nonce: str, expires_at: Union[str, int, float, datetime]) -> bool:
        """Record ``nonce`` and return True if it is fresh, False if it was already seen.

        ``expires_at`` is when the record may be dropped: an ISO 8601 string,
        Unix ms, or a datetime.
        """
        self._store.evict_expired()
        if isinstance(expires_at, datetime):
            expiry = to_ms(expires_at)
        elif isinstance(expires_at, str):
            parsed = parse_iso_ms(expires_at)
            expiry = parsed if parsed is not None else now_ms() + DEFAULT_MAX_ENVELOPE_TTL_MS
        else:
            expiry = int(expires_at)
        return self._store.set_if_absent(nonce, expiry)

    def __len__(self) -> int:
        try:
            return len(self._store)  # type: ignore[arg-type]
        except TypeError:
            return 0


# ── Envelope ───────────────────────────────────────────────────────────────────

ArohaEnvelope = dict[str, Any]

#: Default ceiling on ``expires - created`` (= build_envelope's default TTL).
DEFAULT_MAX_ENVELOPE_TTL_MS = 300_000
#: Default allowance for a sender's clock running ahead when checking ``created``.
DEFAULT_MAX_FUTURE_SKEW_MS = 30_000


def build_envelope(
    type_: str,
    from_did: str,
    to_did: str,
    body: dict[str, Any],
    correlation_id: str,
    private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: int = 300,
    *,
    traceparent: Optional[str] = None,
    routing_hint: Optional[dict[str, Any]] = None,
    key_id: Optional[str] = None,
) -> ArohaEnvelope:
    """
    Build and sign an outbound Aroha message envelope.

    Args:
        type_:          One of the 19 Aroha message types (MESSAGE_TYPES)
        from_did:       Sender DID
        to_did:         Recipient DID
        body:           Message body dict
        correlation_id: Saga or session ID linking related messages
        private_key:    Sender's Ed25519 private key (object or 32 raw bytes)
        ttl_seconds:    Validity window (default 300 s). Receivers reject an
                        envelope whose ``expires - created`` exceeds their
                        max TTL (default also 5 min).
        traceparent:    W3C Trace Context traceparent, included verbatim.
        routing_hint:   Model routing hint, e.g. {"complexity": "standard"}.
        key_id:         ``proof.verificationMethod`` (default ``<from>#key-1``).
                        Set it when the sender's DID document lists several keys.

    Timestamps use the TypeScript format (``2026-01-01T00:00:00.000Z``).
    """
    if type_ not in MESSAGE_TYPES:
        raise ValueError(f"Unknown Aroha message type: {type_}")
    key = private_key if isinstance(private_key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(bytes(private_key))

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)

    envelope: ArohaEnvelope = {
        "@context": list(Aroha_CONTEXT),
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": type_,
        "from": from_did,
        "to": to_did,
        "created": iso_ms(now),
        "expires": iso_ms(expires),
        "nonce": secrets.token_hex(32),
        "correlationId": correlation_id,
        "body": body,
    }
    if traceparent:
        envelope["traceparent"] = traceparent
    if routing_hint:
        envelope["routingHint"] = routing_hint

    envelope["proof"] = sign_message(envelope, key, key_id or f"{from_did}#key-1")
    return envelope


def _did_of_verification_method(vm_id: str) -> Optional[str]:
    if vm_id.startswith("#"):
        return None  # relative — belongs to whichever DID resolves it
    return vm_id.split("#", 1)[0]


def _select_verification_method(doc: dict[str, Any], vm_id: Optional[str]) -> dict[str, Any]:
    vms = doc.get("verificationMethod") or []
    if not vms:
        raise ValueError(f"DID {doc.get('id')} has no verification methods")
    first = vms[0]
    if not vm_id:
        return first
    absolute = f"{doc.get('id')}{vm_id}" if vm_id.startswith("#") else vm_id
    for vm in vms:
        vid = vm.get("id", "")
        if vid == absolute or (vid.startswith("#") and f"{doc.get('id')}{vid}" == absolute):
            return vm
    if absolute == f"{doc.get('id')}#key-1":
        return first
    raise ValueError(f"DID {doc.get('id')} has no verification method {vm_id}")


def _assert_not_revoked(doc: dict[str, Any], key_mb: str) -> None:
    for r in doc.get("revokedKeys") or []:
        if r.get("keyMultibase") == key_mb:
            raise ValueError(
                f"DID {doc.get('id')} key {key_mb[:12]}... was revoked at {r.get('revokedAt')}: {r.get('reason')}"
            )


def extract_public_key_for_proof(
    doc: dict[str, Any], verification_method_id: Optional[str] = None, now: Optional[int] = None
) -> bytes:
    """Key that should verify a signature from this DID document right now (port of TS extractPublicKey).

    Chooses the verification method named by the proof (multi-device keys),
    applies revocations, and during a rotation cool-down (``keyHistory``
    entry with ``trustAfter`` in the future) returns the PREDECESSOR key
    unless the controller installed the current one. The document's
    authenticity is the caller's responsibility (resolve it from a trusted
    source).
    """
    now = now_ms() if now is None else now
    vm = _select_verification_method(doc, verification_method_id)
    vms = doc.get("verificationMethod") or []
    is_primary = vm is vms[0]
    mb = vm.get("publicKeyMultibase", "")
    history = doc.get("keyHistory") or []

    recoveries = doc.get("controllerRecoveries") or []
    controller_installed = False
    if recoveries and recoveries[0].get("newKeyMultibase") == mb:
        if not history:
            controller_installed = True
        else:
            rec_at = parse_iso_ms(recoveries[0].get("recoveredAt"))
            rot_at = parse_iso_ms(history[0].get("rotatedAt"))
            controller_installed = rec_at is not None and rot_at is not None and rec_at >= rot_at

    if not is_primary or not history or controller_installed:
        _assert_not_revoked(doc, mb)
        return from_multibase(mb)

    candidate = mb
    for rotation in history:
        trust_after = parse_iso_ms(rotation.get("trustAfter"))
        # JavaScript compares an unparseable date (NaN) false, so it keeps
        # walking back rather than treating the rotation as past cool-down.
        if trust_after is not None and now >= trust_after:
            break
        candidate = rotation.get("predecessorKey", candidate)
    if candidate != mb:
        for r in doc.get("revokedKeys") or []:
            if r.get("keyMultibase") == candidate:
                raise ValueError(
                    f"DID {doc.get('id')} key rotation cool-down active until {history[0].get('trustAfter')} "
                    f"and the predecessor key was revoked at {r.get('revokedAt')} ({r.get('reason')}) — "
                    f"no key is trusted until the cool-down ends or the controller recovers the DID"
                )
    _assert_not_revoked(doc, candidate)
    return from_multibase(candidate)


def validate_envelope(
    envelope: ArohaEnvelope,
    sender_key: Union[Ed25519PublicKey, bytes, dict[str, Any], None],
    my_did: str,
    nonce_registry: NonceRegistry,
    *,
    skip_signature: bool = False,
    acknowledge_unauthenticated: bool = False,
    clock_tolerance_ms: int = 0,
    max_ttl_ms: int = DEFAULT_MAX_ENVELOPE_TTL_MS,
    max_future_skew_ms: Optional[int] = None,
    now: Optional[Union[int, datetime]] = None,
) -> tuple[bool, Optional[str]]:
    """
    Validate an inbound Aroha message envelope. Returns (True, None) or (False, reason).

    Same checks, same order and same reasons as validateEnvelope in
    aroha-core/src/messages/envelope.ts:

      1. Recipient: ``to`` must equal ``my_did``.
      2. Timestamps (no state touched): ``created``/``expires`` must parse;
         not expired (``clock_tolerance_ms``, default 0); ``created`` not more
         than ``max_future_skew_ms`` ahead (default max(tolerance, 30 s));
         ``expires - created`` <= ``max_ttl_ms`` (default 5 min); nonce present.
      3. Signature (unless ``skip_signature``): ``proof.verificationMethod``
         must belong to ``from``; ``sender_key`` is the sender's public key
         (object or raw bytes) or its DID document (dict), in which case the
         key is chosen by ``proof.verificationMethod`` with revocation and
         rotation cool-downs applied.
      4. Nonce: recorded ONLY NOW, keyed ``"<from>:<nonce>"`` and retained
         until expires + tolerance — so unauthenticated traffic can neither
         fill the store nor pre-burn another sender's nonce.

    ``skip_signature`` is for trusted meshes only: the nonce is still
    recorded under the CLAIMED ``from``, which nothing authenticates. It MUST
    be paired with a transport-level check that authenticates the peer (mTLS,
    a private network link, a signed-request layer); on its own it accepts
    any envelope from anyone who can reach the listener. It is refused
    (``DevModeNotPermitted``) unless the caller also passes
    ``acknowledge_unauthenticated=True`` — stating that such a check exists —
    or the environment sets ``AROHA_DEV_MODE=1`` (local development; a
    warning is printed to stderr once).

    Nonces longer than :data:`MAX_NONCE_LENGTH` (128) characters are rejected.
    """
    if skip_signature and not acknowledge_unauthenticated:
        require_dev_mode("validate_envelope(skip_signature=True)")

    # 1. Recipient
    if envelope.get("to") != my_did:
        return False, f"Message addressed to {envelope.get('to')}, not {my_did}"

    # 2. Timestamps
    tolerance = clock_tolerance_ms
    if tolerance < 0:
        return False, "Invalid clockToleranceMs: must be non-negative"
    created_ms = parse_iso_ms(envelope.get("created"))
    expires_ms = parse_iso_ms(envelope.get("expires"))
    if created_ms is None or expires_ms is None:
        return False, "Malformed created/expires timestamp"
    now_v = now_ms() if now is None else (to_ms(now) if isinstance(now, datetime) else int(now))
    if expires_ms + tolerance < now_v:
        return False, f"Message expired at {envelope.get('expires')} (outside tolerance window)"
    future_skew = max_future_skew_ms if max_future_skew_ms is not None else max(tolerance, DEFAULT_MAX_FUTURE_SKEW_MS)
    if created_ms > now_v + future_skew:
        return False, f"Message created at {envelope.get('created')} is in the future (beyond allowed clock skew)"
    if expires_ms - created_ms > max_ttl_ms:
        return False, f"Message lifetime {expires_ms - created_ms}ms exceeds maximum {max_ttl_ms}ms"
    nonce = envelope.get("nonce")
    if not isinstance(nonce, str) or len(nonce) == 0:
        return False, "Missing nonce"
    if len(nonce) > MAX_NONCE_LENGTH:
        return False, f"Nonce too long (max {MAX_NONCE_LENGTH} characters)"

    # 3. Signature — BEFORE the nonce is recorded.
    if not skip_signature:
        proof = envelope.get("proof")
        vm_id = proof.get("verificationMethod") if isinstance(proof, dict) else None
        if vm_id:
            vm_did = _did_of_verification_method(str(vm_id))
            if vm_did is not None and vm_did != envelope.get("from"):
                return False, "Signature verification failed: proof key belongs to a different DID than `from`"

        if isinstance(sender_key, dict):
            if sender_key.get("id") != envelope.get("from"):
                return False, "Signature verification failed: sender DID document does not match `from`"
            try:
                public_key: Union[Ed25519PublicKey, bytes] = extract_public_key_for_proof(sender_key, vm_id, now_v)
            except Exception as e:
                return False, f"Signature verification failed: {e}"
        elif sender_key is None:
            return False, "Signature verification failed"
        else:
            public_key = sender_key

        if not verify_message_signature(envelope, public_key):
            return False, "Signature verification failed"

    # 4. Nonce — only authenticated envelopes reach here.
    if not nonce_registry.check(f"{envelope.get('from')}:{nonce}", expires_ms + tolerance):
        return False, "Nonce replay detected"

    return True, None


def new_correlation_id() -> str:
    """Create a new correlationId for a saga or session."""
    return f"saga-{uuid.uuid4()}"


def sender_did(envelope: ArohaEnvelope) -> str:
    """The sender's DID (``from``)."""
    return envelope["from"]
