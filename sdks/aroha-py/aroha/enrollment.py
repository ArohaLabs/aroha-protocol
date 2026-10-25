# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Enrollment — how a server learns, with proof, which DID speaks for which of
its customer accounts. Port of packages/aroha-credentials/src/enrollment.ts;
same codes, same signing payload, same shared vectors
(test-vectors/enrollment-v1.json).

``verify_http_spend_request`` pins one root DID per request, taken from a
table the server keeps: account → DID. Whatever fills that table decides
whose mandates the server honours, so it must prove two things together:

- the ACCOUNT: the customer is signed in to THIS account with the server's
  own login. The library cannot check a login; the server passes the account
  it authenticated as ``authenticated_account_id`` — never a value from the
  request body.
- the KEY: the DID's private key signed a fresh, single-use, expiring
  challenge the server issued to that same account, for this service.

Protocol::

    # 1. signed-in customer asks for a challenge (server)
    c = issue_enrollment_challenge(store, authenticated_account_id=session.account_id)
    # 2. on the customer's device, with the DID's key
    proof = sign_enrollment(account_id=c.account_id, did=my_did, challenge=c.challenge,
                            audience="https://invoices.example.com", private_key=my_key)
    # 3. signed-in customer sends {did, challenge, proof} (server)
    r = complete_enrollment(store, authenticated_account_id=session.account_id,
                            audience="https://invoices.example.com",
                            did=body["did"], challenge=body["challenge"], proof=body["proof"])
    # 4. per request: expected_root=enrolled_did(store, customer_id)
    #    (None for an unknown customer → ROOT_NOT_PINNED, not a crash)

``proof`` is an Ed25519 signature (base64url, no padding) by the DID's key
over the UTF-8 bytes of the JCS canonicalisation of
``{purpose: "aroha.enrollment/v1", audience, accountId, did, challenge}``.
The challenge is consumed before anything else is checked, whatever the
outcome. A later enrollment for the same account replaces the DID (rotation).
"""

from __future__ import annotations

import base64
import re
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.jcs import canonicalize_jcs
from aroha.kel import KelSource, KelStore
from aroha.mandate import KeyResolver, _key_bytes, create_mandate_key_resolver, resolve_content_addressed_key
from aroha.timeutil import iso_ms, now_ms

__all__ = [
    "ENROLLMENT_PURPOSE",
    "ENROLLMENT_CHALLENGE_DEFAULT_TTL_MS",
    "ENROLLMENT_CHALLENGE_MAX_TTL_MS",
    "EnrollmentChallengeRecord",
    "EnrollmentStore",
    "InMemoryEnrollmentStore",
    "EnrollmentChallenge",
    "EnrollmentResult",
    "enrollment_signing_payload",
    "issue_enrollment_challenge",
    "complete_enrollment",
    "enrolled_did",
    "sign_enrollment",
]

ENROLLMENT_PURPOSE = "aroha.enrollment/v1"
ENROLLMENT_CHALLENGE_DEFAULT_TTL_MS = 5 * 60_000
ENROLLMENT_CHALLENGE_MAX_TTL_MS = 60 * 60_000

_CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
_MAX_DID_LENGTH = 512


@dataclass(frozen=True)
class EnrollmentChallengeRecord:
    """What a store keeps for an issued, unused challenge."""
    account_id: str
    expires_at_ms: int


class EnrollmentStore(Protocol):
    """Challenges and account → DID bindings.

    ``consume_challenge`` MUST be atomic: return the record AND delete it in
    one step (``DELETE … RETURNING``, Redis ``GETDEL``). An exception from any
    method refuses the enrollment (STORE_UNAVAILABLE).
    """

    def put_challenge(self, challenge: str, record: EnrollmentChallengeRecord, now_ms: int) -> None: ...

    def consume_challenge(self, challenge: str) -> Optional[EnrollmentChallengeRecord]: ...

    def get_binding(self, account_id: str) -> Optional[str]: ...

    def set_binding(self, account_id: str, did: str) -> None: ...


class InMemoryEnrollmentStore:
    """Thread-safe enrollment store for one process and for tests.

    Expired challenges are dropped; when full (default 100 000 outstanding
    challenges) it refuses to issue more rather than forgetting live ones.
    """

    def __init__(self, max_challenges: int = 100_000) -> None:
        self._challenges: dict[str, EnrollmentChallengeRecord] = {}
        self._bindings: dict[str, str] = {}
        self._max = max_challenges
        self._puts = 0
        self._lock = threading.Lock()

    def put_challenge(self, challenge: str, record: EnrollmentChallengeRecord, now_ms: int) -> None:
        with self._lock:
            self._puts += 1
            if self._puts % 64 == 0 or len(self._challenges) >= self._max:
                for c in [c for c, r in self._challenges.items() if r.expires_at_ms <= now_ms]:
                    del self._challenges[c]
            if challenge in self._challenges:
                raise ValueError("InMemoryEnrollmentStore: challenge already issued")
            if len(self._challenges) >= self._max:
                raise RuntimeError("InMemoryEnrollmentStore: too many outstanding challenges")
            self._challenges[challenge] = EnrollmentChallengeRecord(record.account_id, int(record.expires_at_ms))

    def consume_challenge(self, challenge: str) -> Optional[EnrollmentChallengeRecord]:
        with self._lock:
            return self._challenges.pop(challenge, None)

    def get_binding(self, account_id: str) -> Optional[str]:
        with self._lock:
            return self._bindings.get(account_id)

    def set_binding(self, account_id: str, did: str) -> None:
        with self._lock:
            self._bindings[account_id] = did

    @property
    def pending_challenges(self) -> int:
        return len(self._challenges)

    def __bool__(self) -> bool:
        # An empty store is still a store: ``store or default`` must not swap it out.
        return True


def enrollment_signing_payload(*, audience: str, account_id: str, did: str, challenge: str) -> str:
    """The exact string an enrollment proof signs (JCS of the five fields)."""
    return canonicalize_jcs({
        "purpose": ENROLLMENT_PURPOSE,
        "audience": audience,
        "accountId": account_id,
        "did": did,
        "challenge": challenge,
    })


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _require_str(fn: str, name: str, v: Any) -> None:
    if not isinstance(v, str) or not v:
        raise ValueError(f"{fn}: {name} must be a non-empty string")


def _require_store(fn: str, store: Any) -> None:
    if store is None or not all(
        callable(getattr(store, m, None)) for m in ("put_challenge", "consume_challenge", "get_binding", "set_binding")
    ):
        raise ValueError(f"{fn}: an EnrollmentStore is required")


def _clock(fn: str, now: Any) -> int:
    if now is None:
        return now_ms()
    if isinstance(now, bool) or not isinstance(now, (int, float)) or now != now or now in (float("inf"), float("-inf")):
        raise ValueError(f"{fn}: now must be a finite number (Unix ms)")
    return int(now)


# ── Server ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class EnrollmentChallenge:
    """A fresh challenge: send ``challenge`` and ``account_id`` to the signed-in customer."""
    challenge: str
    expires_at: str  # ISO 8601 UTC
    account_id: str


def issue_enrollment_challenge(
    store: EnrollmentStore,
    *,
    authenticated_account_id: str,
    ttl_ms: int = ENROLLMENT_CHALLENGE_DEFAULT_TTL_MS,
    now: Optional[int] = None,
) -> EnrollmentChallenge:
    """Issue a single-use, expiring challenge bound to the signed-in account.

    ``authenticated_account_id`` is the account the CURRENT REQUEST is signed
    in to, from YOUR authentication — never a value the client sends.
    ``ttl_ms`` defaults to 5 minutes, at most 1 hour.
    """
    fn = "issue_enrollment_challenge"
    _require_store(fn, store)
    _require_str(fn, "authenticated_account_id", authenticated_account_id)
    if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, (int, float)) or not 0 < ttl_ms <= ENROLLMENT_CHALLENGE_MAX_TTL_MS:
        raise ValueError(f"{fn}: ttl_ms must be a positive number of milliseconds, at most {ENROLLMENT_CHALLENGE_MAX_TTL_MS}")
    t = _clock(fn, now)
    challenge = _b64url(secrets.token_bytes(32))
    expires_at_ms = int(t + ttl_ms)
    store.put_challenge(challenge, EnrollmentChallengeRecord(authenticated_account_id, expires_at_ms), t)
    return EnrollmentChallenge(challenge=challenge, expires_at=iso_ms(expires_at_ms), account_id=authenticated_account_id)


@dataclass
class EnrollmentResult:
    """``ok`` with ``account_id`` / ``did`` (and ``replaced``, the previous DID on rotation), or ``code`` / ``reason`` / ``status``.

    Codes match the TypeScript SDK: MALFORMED, CHALLENGE_UNKNOWN,
    CHALLENGE_ACCOUNT_MISMATCH, CHALLENGE_EXPIRED, BAD_DID, BAD_PROOF,
    STORE_UNAVAILABLE. ``status`` suggests 400, 403 or 503.
    """
    ok: bool
    code: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[int] = None
    account_id: Optional[str] = None
    did: Optional[str] = None
    replaced: Optional[str] = None

    def __bool__(self) -> bool:
        return self.ok


def _refuse(code: str, reason: str, status: int) -> EnrollmentResult:
    return EnrollmentResult(False, code=code, reason=reason, status=status)


def complete_enrollment(
    store: EnrollmentStore,
    *,
    authenticated_account_id: str,
    audience: str,
    did: Any,
    challenge: Any,
    proof: Any,
    now: Optional[int] = None,
    resolve_public_key: Optional[KeyResolver] = None,
    kel_source: Optional[KelSource] = None,
    kel_store: Optional[KelStore] = None,
) -> EnrollmentResult:
    """Verify an enrollment and record account → DID, or refuse it.

    ``authenticated_account_id``: the account the current request is signed
    in to, from YOUR authentication — never from the body. ``audience``: this
    service's identifier, from your configuration. ``did`` / ``challenge`` /
    ``proof``: from the request body (untrusted). Raises ValueError only for
    server misconfiguration; every client problem is a refusal.

    Default key resolution accepts content-addressed ``did:aroha:z…`` DIDs
    (and ``did:aroha:E…`` with ``kel_source``); ``resolve_public_key``
    replaces it for every DID form.
    """
    fn = "complete_enrollment"
    _require_store(fn, store)
    _require_str(fn, "authenticated_account_id", authenticated_account_id)
    _require_str(fn, "audience", audience)
    t = _clock(fn, now)
    account_id = authenticated_account_id

    if not isinstance(challenge, str) or not _CHALLENGE_RE.fullmatch(challenge):
        return _refuse("MALFORMED", "challenge must be the string issued by issue_enrollment_challenge", 400)

    # First: spend the challenge, whatever happens next.
    try:
        record = store.consume_challenge(challenge)
    except Exception:  # noqa: BLE001
        return _refuse("STORE_UNAVAILABLE", "Enrollment store unavailable", 503)
    if record is None:
        return _refuse("CHALLENGE_UNKNOWN", "Challenge unknown or already used", 400)
    if record.account_id != account_id:
        return _refuse("CHALLENGE_ACCOUNT_MISMATCH", "Challenge was issued to a different account", 403)
    exp = record.expires_at_ms
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not exp > t:
        return _refuse("CHALLENGE_EXPIRED", "Challenge expired", 400)

    if not isinstance(did, str) or not did or len(did) > _MAX_DID_LENGTH:
        return _refuse("BAD_DID", "did must be a DID string", 400)
    resolver = resolve_public_key or (
        create_mandate_key_resolver(kel_source=kel_source, kel_store=kel_store) if kel_source is not None
        else resolve_content_addressed_key
    )
    try:
        key = _key_bytes(resolver(did))
    except Exception:  # noqa: BLE001
        key = None
    if key is None or len(key) != 32:
        return _refuse(
            "BAD_DID",
            f"Cannot resolve a key for {did}: enroll a content-addressed did:aroha:z… DID (or a did:aroha:E… DID with a KEL source)",
            400,
        )

    try:
        if not isinstance(proof, str) or not _BASE64URL_RE.fullmatch(proof):
            raise ValueError("proof")
        sig = base64.urlsafe_b64decode(proof + "=" * (-len(proof) % 4))
        if len(sig) != 64:
            raise ValueError("proof")
        Ed25519PublicKey.from_public_bytes(key).verify(sig, enrollment_signing_payload(
            audience=audience, account_id=account_id, did=did, challenge=challenge,
        ).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return _refuse("BAD_PROOF", "Proof does not verify: the DID's key did not sign this service, account and challenge", 403)

    try:
        previous = store.get_binding(account_id)
        store.set_binding(account_id, did)
    except Exception:  # noqa: BLE001
        return _refuse("STORE_UNAVAILABLE", "Enrollment store unavailable", 503)
    replaced = previous if isinstance(previous, str) and previous and previous != did else None
    return EnrollmentResult(True, account_id=account_id, did=did, replaced=replaced)


def enrolled_did(store: EnrollmentStore, account_id: str) -> Optional[str]:
    """The DID enrolled for ``account_id``, or None. Pass it straight to ``expected_root``:
    None refuses with ROOT_NOT_PINNED (403)."""
    _require_store("enrolled_did", store)
    _require_str("enrolled_did", "account_id", account_id)
    did = store.get_binding(account_id)
    return did if isinstance(did, str) and did else None


# ── Client ────────────────────────────────────────────────────────────────────

def sign_enrollment(
    *,
    account_id: str,
    did: str,
    challenge: str,
    audience: str,
    private_key: Union[Ed25519PrivateKey, bytes],
) -> str:
    """Sign an enrollment on the customer's device; returns the proof (base64url).

    ``account_id`` is your account at the service (returned with the
    challenge); ``audience`` the service's identifier exactly as it configures
    it. Refuses to sign a content-addressed DID with a key that is not its own.
    """
    fn = "sign_enrollment"
    for name, v in (("account_id", account_id), ("did", did), ("challenge", challenge), ("audience", audience)):
        _require_str(fn, name, v)
    if not _CHALLENGE_RE.fullmatch(challenge):
        raise ValueError(f"{fn}: challenge must be 16-128 base64url characters")
    if isinstance(private_key, Ed25519PrivateKey):
        priv = private_key
    else:
        raw = bytes(private_key)
        if len(raw) != 32:
            raise ValueError(f"{fn}: private_key must be a 32-byte Ed25519 private key")
        priv = Ed25519PrivateKey.from_private_bytes(raw)
    named = resolve_content_addressed_key(did)
    if named is not None:
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if pub != bytes(named):
            raise ValueError(f"{fn}: private_key is not the key of {did}")
    payload = enrollment_signing_payload(audience=audience, account_id=account_id, did=did, challenge=challenge)
    return _b64url(priv.sign(payload.encode("utf-8")))
