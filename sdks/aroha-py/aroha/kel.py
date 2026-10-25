# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Rotatable, self-certifying identifiers (``did:aroha:E…``) and their Key Event
Logs (KELs). Port of packages/aroha-core/src/identity/kel.ts.

    did:aroha:E<base58btc(sha256(JCS(inception event without "sig")))>

The identifier commits to the inception event (current key + a digest of the
NEXT key, i.e. pre-rotation). Later key changes are hash-chained events:

    event     | authorised by
    ----------+-----------------------------------------------------------
    inception | its own key (proof of possession)
    rotate    | the pre-committed next key, revealed and signing
    recover   | the controller person, by an ``anchor`` seal in the
              |   controller's own KEL (agents only; the event is unsigned)
    revoke    | the controller (anchored) OR the identity's own next key
    anchor    | the person's current key (persons only)

Every event is signed over RFC 8785 JCS of the event with ``sig`` removed, and
its digest is ``E`` + base58btc(sha256(same bytes)), so digests, DIDs and
signatures are byte-identical with the TypeScript SDK.

Verification is the required part of this module (``verify_kel``,
``kel_key_resolver``, ``resolve_kel_state``, ``accept_kel``). Issuing helpers
(``incept``, ``rotate_kel``, ``revoke_kel_self``, ``anchor_in_kel``,
``recover_agent``, ``revoke_agent``) are provided for tests and tooling.

Freshness caveat (same as TypeScript): a KEL is verifiable offline but its
freshness is not. Keep a ``KelStore`` (``InMemoryKelStore`` or your own
durable one) and resolve through ``accept_kel`` / ``resolve_kel_state`` so a
shorter (stale) or forked (duplicitous) log is refused.

All functions are synchronous; a ``KelSource`` is ``Callable[[did], list | None]``.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Optional, Protocol, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import _decode_base58, _encode_base58
from aroha.jcs import canonicalize_jcs
from aroha.timeutil import iso_ms, parse_iso_ms

__all__ = [
    "KEL_VERSION",
    "KelError",
    "KelState",
    "KelSeal",
    "KelIdentity",
    "KelStore",
    "InMemoryKelStore",
    "DuplicityEvidence",
    "sha256_digest",
    "key_digest",
    "event_digest",
    "did_from_inception",
    "is_inception_did",
    "inception_digest_from_did",
    "verify_kel",
    "keys_at_sequence",
    "verify_agent_controlled_by",
    "accept_kel",
    "kel_source_from_logs",
    "resolve_kel_state",
    "kel_key_resolver",
    "incept",
    "rotate_kel",
    "revoke_kel_self",
    "anchor_in_kel",
    "recover_agent",
    "revoke_agent",
    "generate_kel_key_material",
]

DID_PREFIX = "did:aroha:"
KEL_VERSION = 1

KelEvent = dict[str, Any]
KelSource = Callable[[str], Optional[list[KelEvent]]]
KelErrorCode = Literal["invalid", "stale", "duplicity", "controller-unavailable"]


class KelError(Exception):
    """A KEL failed verification. ``code`` is one of invalid / stale / duplicity / controller-unavailable."""

    def __init__(self, code: KelErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class KelSeal:
    did: str
    seq: int
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"did": self.did, "seq": self.seq, "digest": self.digest}


@dataclass
class KelState:
    did: str
    kind: Literal["person", "agent"]
    controller: Optional[str]
    current_keys: list[str]
    current_key: Optional[bytes]
    next_key_digest: Optional[str]
    revoked: bool
    sequence: int
    last_digest: str
    digests: list[str]
    key_history: list[tuple[int, list[str]]]
    seals: list[KelSeal]
    events: list[KelEvent]
    controller_state: Optional["KelState"] = None
    controller_revoked: bool = False


# ── Encoding helpers ──────────────────────────────────────────────────────────

def _b58(b: bytes) -> str:
    return _encode_base58(b)


def _unb58(s: str) -> bytes:
    return _decode_base58(s)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64url(s: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _pub_bytes(key: Union[Ed25519PrivateKey, Ed25519PublicKey, bytes]) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return bytes(key)


def _priv(key: Union[Ed25519PrivateKey, bytes]) -> Ed25519PrivateKey:
    return key if isinstance(key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(bytes(key))


def _to_multibase(b: bytes) -> str:
    return "z" + _b58(b)


# ── Digests and identifiers ───────────────────────────────────────────────────

def sha256_digest(data: bytes) -> str:
    """``E`` + base58btc(sha256(data)) — the digest encoding used throughout KELs."""
    return "E" + _b58(hashlib.sha256(data).digest())


def _decode_digest(digest: Any) -> Optional[bytes]:
    if not isinstance(digest, str) or not digest.startswith("E"):
        return None
    try:
        raw = _unb58(digest[1:])
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return raw if "E" + _b58(raw) == digest else None


def key_digest(public_key: Union[bytes, Ed25519PublicKey]) -> str:
    """Pre-rotation commitment for a public key: sha256 of its raw 32 bytes."""
    return sha256_digest(_pub_bytes(public_key))


def _signing_body(event: KelEvent) -> dict[str, Any]:
    return {k: v for k, v in event.items() if k != "sig"}


def event_digest(event: KelEvent) -> str:
    """Digest of an event: sha256 over JCS of the event with ``sig`` removed."""
    return sha256_digest(canonicalize_jcs(_signing_body(event)).encode("utf-8"))


def did_from_inception(inception: KelEvent) -> str:
    return DID_PREFIX + event_digest(inception)


def inception_digest_from_did(did: Any) -> Optional[bytes]:
    """The 32-byte inception digest an ``E`` DID commits to, or None for any other DID."""
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        return None
    suffix = did[len(DID_PREFIX):]
    if "." in suffix or ":" in suffix:
        return None
    return _decode_digest(suffix)


def is_inception_did(did: Any) -> bool:
    """True for the strict ``did:aroha:E<base58btc(32 bytes)>`` form (re-encodes to itself)."""
    return inception_digest_from_did(did) is not None


# ── Shape checks ──────────────────────────────────────────────────────────────

def _decode_key(k: Any) -> Optional[bytes]:
    if not isinstance(k, str) or not k.startswith("z"):
        return None
    try:
        raw = _unb58(k[1:])
    except ValueError:
        return None
    return raw if len(raw) == 32 and _to_multibase(raw) == k else None


def _single_key(keys: Any, where: str) -> tuple[str, bytes]:
    if not isinstance(keys, list) or len(keys) != 1:
        raise KelError("invalid", f"{where}: keys must be an array of exactly one Ed25519 key in KEL v1")
    raw = _decode_key(keys[0])
    if raw is None:
        raise KelError("invalid", f"{where}: keys[0] is not a multibase Ed25519 public key")
    return keys[0], raw


def _require_digest(d: Any, where: str, fld: str) -> str:
    if _decode_digest(d) is None:
        raise KelError("invalid", f"{where}: {fld} is not an E-digest")
    return d


def _require_time(t: Any, where: str, fld: str) -> None:
    if parse_iso_ms(t) is None:
        raise KelError("invalid", f"{where}: {fld} is not an ISO 8601 timestamp")


def _is_int(x: Any) -> bool:
    return (isinstance(x, int) and not isinstance(x, bool)) or (isinstance(x, float) and x.is_integer())


def _verify_sig(event: KelEvent, public_key: bytes) -> bool:
    sig = event.get("sig")
    if not isinstance(sig, str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _unb64url(sig), canonicalize_jcs(_signing_body(event)).encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _sign_event(unsigned: KelEvent, private_key: Union[Ed25519PrivateKey, bytes]) -> KelEvent:
    sig = _priv(private_key).sign(canonicalize_jcs(unsigned).encode("utf-8"))
    return {**unsigned, "sig": _b64url(sig)}


def _safe_digest(event: Any, where: str) -> str:
    try:
        return event_digest(event)
    except Exception as e:  # JcsError, AttributeError on non-dicts
        raise KelError("invalid", f"{where}: event cannot be canonicalised ({e})") from None


# ── Verification ──────────────────────────────────────────────────────────────

def verify_kel(
    did: str,
    events: list[KelEvent],
    resolve_controller_kel: Optional[KelSource] = None,
    *,
    require_controller: bool = False,
) -> KelState:
    """Replay a KEL and return the identity's current state. Raises :class:`KelError`.

    Same checks, in the same order, as ``verifyKel`` in aroha-core: the DID
    hashes to the inception; the inception is self-signed and its next-key
    commitment differs from its key; every later event names this DID, has
    ``seq`` = index and ``prior`` = digest of the previous event, and follows
    its type's authorisation rule; nothing follows a revoke; for agents with a
    controller, controller-authorised events must be sealed in the
    controller's verified KEL and every seal must match the log (a seal past
    the end = ``stale``, a different digest = ``duplicity``).
    """
    if not is_inception_did(did):
        raise KelError("invalid", f"{did} is not an inception (E-form) DID")
    if not isinstance(events, list) or len(events) == 0:
        raise KelError("invalid", "empty KEL")

    inception = events[0]
    if not isinstance(inception, dict) or inception.get("v") != KEL_VERSION or inception.get("type") != "inception":
        raise KelError("invalid", "event 0 is not a v1 inception event")
    if inception.get("kind") not in ("person", "agent"):
        raise KelError("invalid", 'inception: kind must be "person" or "agent"')
    where0 = "inception"
    k0_mb, k0 = _single_key(inception.get("keys"), where0)
    _require_digest(inception.get("nextKeyDigest"), where0, "nextKeyDigest")
    _require_time(inception.get("createdAt"), where0, "createdAt")
    if "controller" in inception:
        if inception["kind"] == "person":
            raise KelError("invalid", "inception: a person has no controller")
        if not isinstance(inception["controller"], str) or not is_inception_did(inception["controller"]):
            raise KelError("invalid", "inception: controller must be a person E-DID")

    inc_digest = _safe_digest(inception, where0)
    if DID_PREFIX + inc_digest != did:
        raise KelError(
            "invalid",
            f"inception digest does not match {did} — the inception event was altered or belongs to another DID",
        )
    if not _verify_sig(inception, k0):
        raise KelError("invalid", "inception: signature does not verify against its own key")
    if inception["nextKeyDigest"] == key_digest(k0):
        raise KelError(
            "invalid", "inception: next-key commitment equals the current key — pre-rotation would protect nothing"
        )

    state = KelState(
        did=did,
        kind=inception["kind"],
        controller=inception.get("controller") or None,
        current_keys=[k0_mb],
        current_key=k0,
        next_key_digest=inception["nextKeyDigest"],
        revoked=False,
        sequence=0,
        last_digest=inc_digest,
        digests=[inc_digest],
        key_history=[(0, [k0_mb])],
        seals=[],
        events=[inception],
    )

    needs_seal: list[tuple[int, str]] = []

    for i in range(1, len(events)):
        ev = events[i]
        where = f"event {i}"
        if not isinstance(ev, dict) or ev.get("v") != KEL_VERSION:
            raise KelError("invalid", f"{where}: not a v1 KEL event")
        if ev.get("type") == "inception":
            raise KelError("invalid", f"{where}: a second inception")
        if state.revoked:
            raise KelError("invalid", f"{where}: event after revocation")
        if ev.get("did") != did:
            raise KelError("invalid", f"{where}: names DID {ev.get('did')}, not {did}")
        seq = ev.get("seq")
        if not _is_int(seq) or isinstance(seq, bool) or seq != i:
            raise KelError("invalid", f"{where}: seq {seq} out of order")
        if ev.get("prior") != state.last_digest:
            raise KelError("invalid", f"{where}: prior digest does not chain to event {i - 1}")
        _require_time(ev.get("at"), where, "at")
        digest = _safe_digest(ev, where)
        etype = ev.get("type")

        if etype == "rotate":
            k_mb, k = _single_key(ev.get("keys"), where)
            _require_digest(ev.get("nextKeyDigest"), where, "nextKeyDigest")
            if key_digest(k) != state.next_key_digest:
                raise KelError("invalid", f"{where}: rotation key does not match the pre-rotation commitment")
            if not _verify_sig(ev, k):
                raise KelError("invalid", f"{where}: rotation is not signed by the pre-committed next key")
            if ev["nextKeyDigest"] == key_digest(k):
                raise KelError("invalid", f"{where}: next-key commitment equals the new current key")
            _set_keys(state, k_mb, k, ev["nextKeyDigest"], i)
        elif etype == "recover":
            if state.kind != "agent" or not state.controller:
                raise KelError("invalid", f"{where}: recover is only defined for agents with a controller")
            if ev.get("auth") != "controller":
                raise KelError("invalid", f"{where}: recover must be controller-authorised")
            if "sig" in ev:
                raise KelError("invalid", f"{where}: recover carries no signature (it is anchored)")
            k_mb, k = _single_key(ev.get("keys"), where)
            _require_digest(ev.get("nextKeyDigest"), where, "nextKeyDigest")
            if ev["nextKeyDigest"] == key_digest(k):
                raise KelError("invalid", f"{where}: next-key commitment equals the new current key")
            _set_keys(state, k_mb, k, ev["nextKeyDigest"], i)
            needs_seal.append((i, digest))
        elif etype == "revoke":
            if "reason" in ev and not isinstance(ev["reason"], str):
                raise KelError("invalid", f"{where}: reason must be a string")
            auth = ev.get("auth")
            if auth == "next-key":
                revealed = _decode_key(ev.get("revealedKey"))
                if revealed is None:
                    raise KelError("invalid", f"{where}: revealedKey is not an Ed25519 key")
                if key_digest(revealed) != state.next_key_digest:
                    raise KelError("invalid", f"{where}: revealed key does not match the pre-rotation commitment")
                if not _verify_sig(ev, revealed):
                    raise KelError("invalid", f"{where}: revocation is not signed by the pre-committed next key")
            elif auth == "controller":
                if state.kind != "agent" or not state.controller:
                    raise KelError("invalid", f"{where}: controller revocation on an identity with no controller")
                if "sig" in ev:
                    raise KelError(
                        "invalid", f"{where}: a controller revocation carries no signature (it is anchored)"
                    )
                needs_seal.append((i, digest))
            else:
                raise KelError("invalid", f"{where}: unknown revoke auth")
            state.revoked = True
            state.current_keys = []
            state.current_key = None
            state.next_key_digest = None
        elif etype == "anchor":
            if state.kind != "person":
                raise KelError("invalid", f"{where}: only persons anchor")
            seals = ev.get("seals")
            if not isinstance(seals, list):
                raise KelError("invalid", f"{where}: seals must be an array")
            for s in seals:
                if (
                    not isinstance(s, dict)
                    or not isinstance(s.get("did"), str)
                    or not is_inception_did(s["did"])
                    or not _is_int(s.get("seq"))
                    or isinstance(s.get("seq"), bool)
                    or s["seq"] < 1
                    or _decode_digest(s.get("digest")) is None
                ):
                    raise KelError("invalid", f"{where}: malformed seal")
            if state.current_key is None or not _verify_sig(ev, state.current_key):
                raise KelError("invalid", f"{where}: anchor is not signed by the current key")
            state.seals.extend(KelSeal(s["did"], int(s["seq"]), s["digest"]) for s in seals)
        else:
            raise KelError("invalid", f"{where}: unknown event type {etype}")

        state.sequence = i
        state.last_digest = digest
        state.digests.append(digest)
        state.events.append(ev)

    if state.controller:
        need_controller = len(needs_seal) > 0 or require_controller
        controller_events: Optional[list[KelEvent]] = None
        if resolve_controller_kel is not None:
            try:
                controller_events = resolve_controller_kel(state.controller)
            except KelError as e:
                if e.code != "controller-unavailable":
                    raise
                controller_events = None
            except Exception:
                controller_events = None
        if not controller_events:
            if need_controller:
                msg = (
                    f"{did} has controller-authorised events but the controller {state.controller}'s KEL is unavailable"
                    if needs_seal
                    else f"controller {state.controller}'s KEL is unavailable"
                )
                raise KelError("controller-unavailable", msg)
        else:
            ctl = verify_kel(state.controller, controller_events)
            if ctl.kind != "person":
                raise KelError("invalid", f"controller {state.controller} is not a person")
            mine = [s for s in ctl.seals if s.did == did]
            # Authorisation BEFORE comparison (see kel.ts): an unanchored
            # "controller" event is junk, not evidence of a fork.
            for need_seq, need_digest in needs_seal:
                if not any(s.seq == need_seq and s.digest == need_digest for s in mine):
                    raise KelError(
                        "invalid",
                        f"event {need_seq} claims controller authority but is not anchored in {state.controller}'s KEL",
                    )
            for seal in mine:
                if seal.seq > state.sequence:
                    raise KelError(
                        "stale",
                        f"controller anchored {did} event {seal.seq}, but the log provided ends at {state.sequence}",
                    )
                if state.digests[seal.seq] != seal.digest:
                    raise KelError(
                        "duplicity",
                        f"controller anchored a different event at {did} seq {seal.seq} than the log provided",
                    )
            state.controller_state = ctl
            state.controller_revoked = ctl.revoked

    return state


def _set_keys(state: KelState, mb: str, raw: bytes, nxt: str, seq: int) -> None:
    state.current_keys = [mb]
    state.current_key = raw
    state.next_key_digest = nxt
    state.key_history.append((seq, [mb]))


def keys_at_sequence(state: KelState, seq: int) -> list[str]:
    """The key(s) current at sequence ``seq`` of a verified log."""
    if not _is_int(seq) or seq < 0 or seq > state.sequence:
        raise KelError("invalid", f"seq {seq} is outside {state.did}'s log (0..{state.sequence})")
    keys = state.key_history[0][1]
    for est_seq, est_keys in state.key_history:
        if est_seq > seq:
            break
        keys = est_keys
    return keys


def verify_agent_controlled_by(
    agent_did: str, agent_kel: list[KelEvent], person_did: str, person_kel: list[KelEvent]
) -> tuple[bool, Optional[str]]:
    """(True, None) if ``person_did`` controls ``agent_did`` right now per both verified logs."""
    try:
        person = verify_kel(person_did, person_kel)
        if person.kind != "person":
            return False, f"{person_did} is not a person"
        if person.revoked:
            return False, f"{person_did} is revoked"
        agent = verify_kel(
            agent_did, agent_kel,
            lambda d: person_kel if d == person_did else None,
            require_controller=True,
        )
        if agent.kind != "agent":
            return False, f"{agent_did} is not an agent"
        if agent.controller != person_did:
            return False, f"{agent_did} names {agent.controller or 'no controller'}, not {person_did}"
        if agent.revoked:
            return False, f"{agent_did} has been revoked"
        return True, None
    except Exception as e:
        return False, str(e)


# ── Freshness: KelStore, duplicity, stale logs ────────────────────────────────

@dataclass
class DuplicityEvidence:
    did: str
    seq: int
    digests: tuple[str, str]
    detected_at: str


class KelStore(Protocol):
    def get(self, did: str) -> Optional[list[KelEvent]]: ...
    def put(self, did: str, events: list[KelEvent]) -> None: ...
    def record_duplicity(self, evidence: DuplicityEvidence) -> None: ...
    def get_duplicity(self, did: str) -> Optional[DuplicityEvidence]: ...


class InMemoryKelStore:
    """Highest-seen KEL memory. Use durable storage in long-lived verifiers."""

    def __init__(self) -> None:
        self._logs: dict[str, list[KelEvent]] = {}
        self._alarms: dict[str, DuplicityEvidence] = {}

    def get(self, did: str) -> Optional[list[KelEvent]]:
        return self._logs.get(did)

    def put(self, did: str, events: list[KelEvent]) -> None:
        self._logs[did] = list(events)

    def record_duplicity(self, evidence: DuplicityEvidence) -> None:
        self._alarms.setdefault(evidence.did, evidence)

    def get_duplicity(self, did: str) -> Optional[DuplicityEvidence]:
        return self._alarms.get(did)


def accept_kel(
    did: str,
    events: list[KelEvent],
    store: KelStore,
    resolve_controller_kel: Optional[KelSource] = None,
    *,
    require_controller: bool = False,
    on_stale: Literal["reject", "use-stored"] = "reject",
) -> KelState:
    """Verify ``events`` and reconcile them with what ``store`` has seen (see acceptKel in kel.ts)."""
    alarm = store.get_duplicity(did)
    if alarm:
        raise KelError(
            "duplicity", f"{did} has a recorded duplicity alarm at seq {alarm.seq} (since {alarm.detected_at})"
        )
    stored = store.get(did)
    use_stored = on_stale == "use-stored" and stored is not None and len(stored) > 0

    def _verify(evts: list[KelEvent]) -> KelState:
        return verify_kel(did, evts, resolve_controller_kel, require_controller=require_controller)

    try:
        state = _verify(events)
    except KelError as e:
        if e.code == "stale" and use_stored and len(stored) > len(events):  # type: ignore[arg-type]
            return _verify(stored)  # type: ignore[arg-type]
        raise

    if stored:
        common = min(len(stored), len(state.digests))
        for i in range(common):
            seen = event_digest(stored[i])
            if seen != state.digests[i]:
                store.record_duplicity(
                    DuplicityEvidence(did, i, (seen, state.digests[i]), iso_ms(datetime.now(timezone.utc)))
                )
                raise KelError("duplicity", f"{did}: two different events at seq {i} — the log was forked")
        if len(state.digests) < len(stored):
            if use_stored:
                return _verify(stored)
            raise KelError(
                "stale",
                f"{did}: offered log ends at seq {state.sequence}, but seq {len(stored) - 1} has already been seen",
            )
    if not stored or len(state.events) > len(stored):
        store.put(did, state.events)
    return state


def kel_source_from_logs(*logs: list[KelEvent]) -> KelSource:
    """A KelSource over logs you already hold, indexed by the DID each inception hashes to (longest wins)."""
    by_did: dict[str, list[KelEvent]] = {}
    for log in logs:
        if not log or not isinstance(log[0], dict) or log[0].get("type") != "inception":
            continue
        try:
            d = did_from_inception(log[0])
        except Exception:
            continue
        existing = by_did.get(d)
        if existing is None or len(log) > len(existing):
            by_did[d] = log
    return lambda d: by_did.get(d)


def resolve_kel_state(
    did: str,
    source: KelSource,
    *,
    store: Optional[KelStore] = None,
    require_controller: bool = False,
) -> Optional[KelState]:
    """Fetch, verify and (with a store) reconcile the KEL for an ``E`` DID and its controller.

    Returns None when ``did`` is not an E-DID or no log can be found; raises
    :class:`KelError` when a log is found but does not verify.
    """
    if not is_inception_did(did):
        return None

    def fetch(d: str) -> Optional[list[KelEvent]]:
        try:
            log = source(d)
        except Exception:
            log = None
        if not log and store is not None:
            log = store.get(d)
        return log if log else None

    events = fetch(did)
    if not events:
        return None

    def resolve_controller(cdid: str) -> Optional[list[KelEvent]]:
        log = fetch(cdid)
        if not log:
            return None
        if store is None:
            return log
        return accept_kel(cdid, log, store, on_stale="use-stored").events

    if store is not None:
        return accept_kel(
            did, events, store, resolve_controller, require_controller=require_controller, on_stale="use-stored"
        )
    return verify_kel(did, events, resolve_controller, require_controller=require_controller)


def kel_key_resolver(
    source: KelSource, *, store: Optional[KelStore] = None, require_controller: bool = False
) -> Callable[[str], Optional[bytes]]:
    """DID -> current raw Ed25519 key for E-DIDs; None (fail closed) for revoked/invalid/other DIDs.

    A ``#fragment`` on the DID is ignored (v1 KEL identities have one key).
    """
    def resolve(did: str) -> Optional[bytes]:
        try:
            base = did.split("#", 1)[0]
            state = resolve_kel_state(base, source, store=store, require_controller=require_controller)
            if state is None or state.revoked or state.controller_revoked or state.current_key is None:
                return None
            return state.current_key
        except Exception:
            return None

    return resolve


# ── Issuing (optional in this SDK; provided for tests and tooling) ────────────

@dataclass
class KelIdentity:
    did: str
    kind: Literal["person", "agent"]
    private_key: Ed25519PrivateKey
    public_key: bytes
    next_private_key: Ed25519PrivateKey
    next_public_key: bytes
    kel: list[KelEvent] = field(default_factory=list)
    controller: Optional[str] = None


def _keypair(priv: Optional[Union[Ed25519PrivateKey, bytes]]) -> tuple[Ed25519PrivateKey, bytes]:
    k = _priv(priv) if priv is not None else Ed25519PrivateKey.generate()
    return k, _pub_bytes(k)


def generate_kel_key_material() -> dict[str, Any]:
    """Fresh current + next key for a replacement device (agent recovery)."""
    cur, cur_pub = _keypair(None)
    nxt, nxt_pub = _keypair(None)
    return {
        "private_key": cur,
        "public_key": cur_pub,
        "next_private_key": nxt,
        "next_public_key": nxt_pub,
        "next_key_digest": key_digest(nxt_pub),
    }


def incept(
    kind: Literal["person", "agent"],
    *,
    controller: Optional[str] = None,
    private_key: Optional[Union[Ed25519PrivateKey, bytes]] = None,
    next_private_key: Optional[Union[Ed25519PrivateKey, bytes]] = None,
    now: Optional[datetime] = None,
) -> KelIdentity:
    """Create a new identity: build and sign its inception event."""
    if kind == "person" and controller:
        raise ValueError("a person has no controller")
    if controller is not None and not is_inception_did(controller):
        raise ValueError("controller must be a person E-DID (did:aroha:E…)")
    cur, cur_pub = _keypair(private_key)
    nxt, nxt_pub = _keypair(next_private_key)
    if key_digest(nxt_pub) == key_digest(cur_pub):
        raise ValueError("next key must differ from the current key")
    unsigned: KelEvent = {
        "v": KEL_VERSION,
        "type": "inception",
        "kind": kind,
        "keys": [_to_multibase(cur_pub)],
        "nextKeyDigest": key_digest(nxt_pub),
    }
    if controller:
        unsigned["controller"] = controller
    unsigned["createdAt"] = iso_ms(now or datetime.now(timezone.utc))
    inception = _sign_event(unsigned, cur)
    return KelIdentity(
        did=did_from_inception(inception), kind=kind, private_key=cur, public_key=cur_pub,
        next_private_key=nxt, next_public_key=nxt_pub, kel=[inception], controller=controller or None,
    )


def _next_position(kel: list[KelEvent], did: str) -> dict[str, Any]:
    if not kel:
        raise ValueError("empty KEL")
    last = kel[-1]
    if last.get("type") == "revoke":
        raise ValueError(f"{did} is revoked; its log is closed")
    return {"seq": len(kel), "prior": event_digest(last)}


def rotate_kel(
    identity: KelIdentity,
    *,
    next_private_key: Optional[Union[Ed25519PrivateKey, bytes]] = None,
    now: Optional[datetime] = None,
) -> KelIdentity:
    """Pre-rotate: the committed next key becomes current and a new next key is committed."""
    new_next, new_next_pub = _keypair(next_private_key)
    if key_digest(new_next_pub) == key_digest(identity.next_public_key):
        raise ValueError("the new next key must differ from the key being rotated in")
    event = _sign_event(
        {
            "v": KEL_VERSION,
            "type": "rotate",
            "did": identity.did,
            **_next_position(identity.kel, identity.did),
            "at": iso_ms(now or datetime.now(timezone.utc)),
            "keys": [_to_multibase(identity.next_public_key)],
            "nextKeyDigest": key_digest(new_next_pub),
        },
        identity.next_private_key,
    )
    return KelIdentity(
        did=identity.did, kind=identity.kind,
        private_key=identity.next_private_key, public_key=identity.next_public_key,
        next_private_key=new_next, next_public_key=new_next_pub,
        kel=[*identity.kel, event], controller=identity.controller,
    )


def revoke_kel_self(
    identity: KelIdentity, *, reason: Optional[str] = None, now: Optional[datetime] = None
) -> list[KelEvent]:
    """Abandon an identity with its own pre-committed next key. Returns the extended log."""
    unsigned: KelEvent = {
        "v": KEL_VERSION,
        "type": "revoke",
        "did": identity.did,
        **_next_position(identity.kel, identity.did),
        "at": iso_ms(now or datetime.now(timezone.utc)),
        "auth": "next-key",
        "revealedKey": _to_multibase(identity.next_public_key),
    }
    if reason is not None:
        unsigned["reason"] = reason
    return [*identity.kel, _sign_event(unsigned, identity.next_private_key)]


def anchor_in_kel(person: KelIdentity, seals: list[KelSeal], *, now: Optional[datetime] = None) -> KelIdentity:
    """Append an ``anchor`` event to a person's log sealing the given agent events."""
    if person.kind != "person":
        raise ValueError("only persons anchor")
    event = _sign_event(
        {
            "v": KEL_VERSION,
            "type": "anchor",
            "did": person.did,
            **_next_position(person.kel, person.did),
            "at": iso_ms(now or datetime.now(timezone.utc)),
            "seals": [s.to_dict() for s in seals],
        },
        person.private_key,
    )
    return KelIdentity(
        did=person.did, kind=person.kind, private_key=person.private_key, public_key=person.public_key,
        next_private_key=person.next_private_key, next_public_key=person.next_public_key,
        kel=[*person.kel, event], controller=person.controller,
    )


def _controlled_agent(person: KelIdentity, agent_kel: list[KelEvent]) -> str:
    inception = agent_kel[0] if agent_kel else None
    if not inception or inception.get("type") != "inception":
        raise ValueError("agent KEL has no inception")
    if inception.get("controller") != person.did:
        raise ValueError(f"agent's controller is {inception.get('controller') or 'none'}, not {person.did}")
    return did_from_inception(inception)


def recover_agent(
    person: KelIdentity,
    agent_kel: list[KelEvent],
    replacement_public_key: Union[bytes, Ed25519PublicKey],
    replacement_next_key_digest: str,
    *,
    now: Optional[datetime] = None,
) -> tuple[KelIdentity, list[KelEvent]]:
    """Controller recovery (stolen/lost device). Returns (updated person, extended agent KEL)."""
    agent_did = _controlled_agent(person, agent_kel)
    pub = _pub_bytes(replacement_public_key)
    if replacement_next_key_digest == key_digest(pub):
        raise ValueError("next-key commitment must differ from the new current key")
    when = now or datetime.now(timezone.utc)
    event: KelEvent = {
        "v": KEL_VERSION,
        "type": "recover",
        "did": agent_did,
        **_next_position(agent_kel, agent_did),
        "at": iso_ms(when),
        "auth": "controller",
        "keys": [_to_multibase(pub)],
        "nextKeyDigest": replacement_next_key_digest,
    }
    updated = anchor_in_kel(person, [KelSeal(agent_did, event["seq"], event_digest(event))], now=when)
    return updated, [*agent_kel, event]


def revoke_agent(
    person: KelIdentity,
    agent_kel: list[KelEvent],
    *,
    reason: Optional[str] = None,
    now: Optional[datetime] = None,
) -> tuple[KelIdentity, list[KelEvent]]:
    """The controlling person revokes one of their agents. Returns (updated person, extended agent KEL)."""
    agent_did = _controlled_agent(person, agent_kel)
    when = now or datetime.now(timezone.utc)
    event: KelEvent = {
        "v": KEL_VERSION,
        "type": "revoke",
        "did": agent_did,
        **_next_position(agent_kel, agent_did),
        "at": iso_ms(when),
        "auth": "controller",
    }
    if reason is not None:
        event["reason"] = reason
    updated = anchor_in_kel(person, [KelSeal(agent_did, event["seq"], event_digest(event))], now=when)
    return updated, [*agent_kel, event]
