# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Verifiers for the Conversation and Memory Profile (spec aroha-1.0 §12) and
for signed action receipts v1/v2 (§12.6).

Written from the specification text and the published vectors
(spec-public/vectors/conversation-v1.json), not ported from the TypeScript
code: the point of this module is to show that a second implementation can
verify these objects from the spec alone.

Every signature is Ed25519 over the UTF-8 bytes of the RFC 8785 JCS form of
the object with its ``signature`` field removed (rooms, consent records,
receipts), or of the turn signature payload (turns). Signatures are base64url
without padding.

Verification only. Nothing here signs; issuing belongs to the runtime.

Key resolution is the caller's: pass ``resolve(did) -> (public_key_bytes,
kind) | None``. ``kel_resolver`` builds one from Key Event Logs, which is
also where a speaker's kind (``person`` / ``agent``) comes from — never from
the message itself.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aroha.identity import from_multibase
from aroha.jcs import canonicalize_jcs
from aroha.kel import KelError, verify_kel

ROOM_PURPOSE = "aroha.room/v1"
CONSENT_PURPOSE = "aroha.consent/v1"
TURN_PURPOSE = "aroha.turn/v1"
RECEIPT_PURPOSE_V1 = "aroha.action-receipt/v1"
RECEIPT_PURPOSE_V2 = "aroha.action-receipt/v2"

CONSENT_PURPOSES = ("transcript_retention", "agent_use_of_messages", "memory_write", "provider_processing")

Resolved = tuple[bytes, str]  # (32-byte Ed25519 public key, "person" | "agent")
Resolver = Callable[[str], Optional[Resolved]]

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Verification:
    ok: bool
    reason: Optional[str] = None
    kind: Optional[str] = None  # the signer's resolved kind, when ok


def _fail(reason: str) -> Verification:
    return Verification(False, reason)


# ── helpers ───────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> Optional[bytes]:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s):
        return None
    try:
        return base64.urlsafe_b64decode(s.rstrip("=") + "=" * (-len(s.rstrip("=")) % 4))
    except Exception:
        return None


def _ed_verify(sig_b64: str, message: bytes, public_key: bytes) -> bool:
    sig = _b64url_decode(sig_b64)
    if sig is None or len(sig) != 64 or len(public_key) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _without(obj: dict, key: str) -> dict:
    return {k: v for k, v in obj.items() if k != key}


def signing_bytes(obj: dict) -> bytes:
    """JCS of the object without ``signature`` — rooms, consent records, receipts."""
    return canonicalize_jcs(_without(obj, "signature")).encode("utf-8")


def _is_str(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def _is_did(x: Any) -> bool:
    return _is_str(x) and x.startswith("did:")


def _is_epoch(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _is_iso(x: Any) -> bool:
    if not isinstance(x, str):
        return False
    try:
        datetime.fromisoformat(x.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _unknown(obj: dict, known: set[str]) -> Optional[str]:
    for k in obj:
        if k not in known:
            return k
    return None


def _resolve(resolve: Resolver, did: str) -> Optional[Resolved]:
    try:
        return resolve(did)
    except Exception:
        return None


def resolve_speaker_kind(kel_kind: Optional[str]) -> str:
    """Spec §12.2: the KEL inception's kind; anything unresolvable is an agent."""
    return "person" if kel_kind == "person" else "agent"


def kel_resolver(kels: dict[str, list], *, content_addressed_agents: bool = True) -> Resolver:
    """A resolver over a {did: events} map. E-form DIDs resolve through their
    verified KEL (kind from the inception); z-form DIDs, when allowed, resolve
    from the DID itself and are always ``agent``."""

    def resolve(did: str) -> Optional[Resolved]:
        if content_addressed_agents and did.startswith("did:aroha:z"):
            return from_multibase(did[len("did:aroha:"):]), "agent"
        events = kels.get(did)
        if not events:
            return None
        try:
            state = verify_kel(did, events)
        except KelError:
            return None
        if state.revoked or state.controller_revoked or state.current_key is None:
            return None
        return state.current_key, resolve_speaker_kind(state.kind)

    return resolve


# ── disclosure (§12.7) ────────────────────────────────────────────────────────

def check_disclosure(d: Any, expected_agent_did: Optional[str] = None) -> Optional[str]:
    if not isinstance(d, dict):
        return "disclosure is not an object"
    if d.get("v") != 1:
        return "unsupported disclosure version"
    extra = _unknown(d, {"v", "agentDid", "principalDid", "principalKind", "purpose", "hop", "aiGenerated"})
    if extra:
        return f'unknown field "{extra}"'
    if not _is_did(d.get("agentDid")) or not _is_did(d.get("principalDid")):
        return "agentDid and principalDid must be DIDs"
    if not _is_str(d.get("purpose")) or len(d["purpose"]) > 512:
        return "purpose must be a non-empty string of at most 512 characters"
    if d.get("principalKind") not in ("person", "organization"):
        return "principalKind is invalid"
    if not _is_epoch(d.get("hop")):
        return "hop must be a non-negative integer"
    if d.get("aiGenerated") is not True:
        return "aiGenerated must be true"
    if expected_agent_did is not None and d["agentDid"] != expected_agent_did:
        return "disclosure names a different agent"
    return None


# ── room (§12.1) ──────────────────────────────────────────────────────────────

_ROOM_FIELDS = {"v", "purpose", "roomId", "threadId", "ownerDid", "epoch", "members", "historyVisibility",
                "invocation", "memoryPolicy", "disclosure", "updatedAt", "signature"}
_MEMBER_FIELDS = {"did", "kind", "principalId", "displayName", "role", "joinedEpoch", "leftEpoch", "consentRef"}


def check_room(r: Any) -> Optional[str]:
    if not isinstance(r, dict):
        return "room is not an object"
    if r.get("v") != 1 or r.get("purpose") != ROOM_PURPOSE:
        return "not an aroha.room/v1 record"
    extra = _unknown(r, _ROOM_FIELDS)
    if extra:
        return f'unknown field "{extra}"'
    if not _is_str(r.get("roomId")) or not _is_str(r.get("threadId")):
        return "roomId and threadId must be non-empty strings"
    if not _is_did(r.get("ownerDid")) or not _is_epoch(r.get("epoch")):
        return "ownerDid / epoch invalid"
    if r.get("historyVisibility") not in ("joined", "shared") or r.get("invocation") not in ("explicit", "implicit"):
        return "historyVisibility / invocation invalid"
    if not _is_iso(r.get("updatedAt")) or not _is_str(r.get("signature")):
        return "updatedAt / signature invalid"
    mp = r.get("memoryPolicy")
    if not isinstance(mp, dict) or _unknown(mp, {"personalRead", "personalWrite", "roomMemory", "agentRead"}):
        return "memoryPolicy invalid"
    if not isinstance(mp.get("personalRead"), bool) or not isinstance(mp.get("personalWrite"), bool):
        return "memoryPolicy booleans invalid"
    if mp.get("roomMemory") not in ("off", "consented") or mp.get("agentRead", "none") not in ("none", "members"):
        return "memoryPolicy enums invalid"
    problem = check_disclosure(r.get("disclosure"))
    if problem:
        return f"disclosure: {problem}"
    members = r.get("members")
    if not isinstance(members, list) or not members:
        return "members must be a non-empty array"
    seen: set[str] = set()
    hosts = 0
    for i, m in enumerate(members):
        if not isinstance(m, dict) or _unknown(m, _MEMBER_FIELDS):
            return f"members[{i}] invalid"
        if not _is_did(m.get("did")) or m["did"] in seen:
            return f"members[{i}].did invalid or repeated"
        seen.add(m["did"])
        if m.get("kind") not in ("person", "agent") or m.get("role") not in ("host", "guest", "own", "invited", "delegated"):
            return f"members[{i}] kind/role invalid"
        if not isinstance(m.get("displayName"), str):
            return f"members[{i}].displayName invalid"
        if not _is_epoch(m.get("joinedEpoch")) or m["joinedEpoch"] > r["epoch"]:
            return f"members[{i}].joinedEpoch invalid"
        if "leftEpoch" in m and (not _is_epoch(m["leftEpoch"]) or not (m["joinedEpoch"] < m["leftEpoch"] <= r["epoch"])):
            return f"members[{i}].leftEpoch invalid"
        if m["role"] == "guest" and m["kind"] == "person" and not _is_str(m.get("consentRef")):
            return f"members[{i}]: a person guest requires a consentRef"
        if m["role"] == "host":
            hosts += 1
            if m["did"] != r["ownerDid"] or m["kind"] != "person":
                return "the host must be the owner, a person"
    if hosts != 1:
        return "exactly one member must have role host"
    return None


def verify_room(room: Any, resolve: Resolver) -> Verification:
    problem = check_room(room)
    if problem:
        return _fail(f"malformed room: {problem}")
    signer = _resolve(resolve, room["ownerDid"])
    if signer is None:
        return _fail("room owner has no resolvable key")
    if signer[1] != "person":
        return _fail("room owner is not a person")
    if not _ed_verify(room["signature"], signing_bytes(room), signer[0]):
        return _fail("room signature does not verify")
    return Verification(True, kind=signer[1])


def members_at(room: dict, epoch: int) -> list[dict]:
    return [m for m in room["members"] if m["joinedEpoch"] <= epoch and ("leftEpoch" not in m or epoch < m["leftEpoch"])]


# ── consent (§12.3) ───────────────────────────────────────────────────────────
#
# A consent record is a hash-chained list of events, each signed by its own
# actor. A record re-signed whole by the last appender would let that signer
# rewrite earlier events; per-event signatures make that impossible.

CONSENT_EVENT_PURPOSE = "aroha.consent-event/v1"


def _purpose_list(x: Any) -> bool:
    return isinstance(x, list) and len(x) > 0 and all(p in CONSENT_PURPOSES for p in x) and len(set(x)) == len(x)


def consent_event_hash(event: dict) -> str:
    """SHA-256 hex of JCS of a whole event (sig included) — the next event's prevHash."""
    return hashlib.sha256(canonicalize_jcs(event).encode("utf-8")).hexdigest()


def consent_event_signing_bytes(record: dict, index: int) -> bytes:
    entry = _without(record["events"][index], "sig")
    return canonicalize_jcs({
        "purpose": CONSENT_EVENT_PURPOSE,
        "recordId": record["recordId"],
        "subjectDid": record["subjectDid"],
        "roomId": record["roomId"],
        "purposes": record["purposes"],
        "withdrawalRoute": record["withdrawalRoute"],
        "index": index,
        "prevHash": None if index == 0 else consent_event_hash(record["events"][index - 1]),
        "entry": entry,
    }).encode("utf-8")


def check_consent(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "consent record is not an object"
    if c.get("v") != 1 or c.get("purpose") != CONSENT_PURPOSE:
        return "not an aroha.consent/v1 record"
    extra = _unknown(c, {"v", "purpose", "recordId", "subjectDid", "roomId", "purposes", "withdrawalRoute", "events"})
    if extra:
        return f'unknown field "{extra}"'
    if not (_is_str(c.get("recordId")) and _is_str(c.get("roomId")) and _is_str(c.get("withdrawalRoute"))):
        return "recordId / roomId / withdrawalRoute invalid"
    if not _is_did(c.get("subjectDid")):
        return "subjectDid invalid"
    if not _purpose_list(c.get("purposes")):
        return "purposes invalid"
    events = c.get("events")
    if not isinstance(events, list) or not events:
        return "events must be a non-empty array"
    last = None
    last_epoch = -1
    for i, e in enumerate(events):
        if not isinstance(e, dict) or _unknown(e, {"event", "purposes", "at", "actorDid", "epoch", "sig"}):
            return f"events[{i}] invalid"
        if e.get("event") not in ("given", "withdrawn") or not _purpose_list(e.get("purposes")):
            return f"events[{i}] event/purposes invalid"
        if any(p not in c["purposes"] for p in e["purposes"]):
            return f"events[{i}] names a purpose the record does not ask about"
        if not _is_iso(e.get("at")) or not _is_did(e.get("actorDid")) or not _is_str(e.get("sig")):
            return f"events[{i}] at/actorDid/sig invalid"
        if not _is_epoch(e.get("epoch")) or e["epoch"] < last_epoch:
            return f"events[{i}].epoch invalid or decreasing"
        last_epoch = e["epoch"]
        t = datetime.fromisoformat(e["at"].replace("Z", "+00:00"))
        if last is not None and t < last:
            return f"events[{i}] is out of order"
        last = t
        if e["event"] == "given" and e["actorDid"] != c["subjectDid"]:
            return f"events[{i}]: only the subject can give consent"
    if events[0]["event"] != "given":
        return 'the first event must be "given"'
    return None


def verify_consent(record: Any, resolve: Resolver, room: Optional[dict] = None) -> Verification:
    """Every event's signature is checked against its own actor (a person).
    A non-subject actor requires ``room`` and must be a member at the event's epoch."""
    problem = check_consent(record)
    if problem:
        return _fail(f"malformed consent record: {problem}")
    if room is not None and room.get("roomId") != record["roomId"]:
        return _fail("consent record is for a different room")
    for i, e in enumerate(record["events"]):
        if e["actorDid"] != record["subjectDid"]:
            if room is None:
                return _fail(f"events[{i}] is not by the subject; the room record is required")
            if e["epoch"] > room["epoch"] or not any(m["did"] == e["actorDid"] for m in members_at(room, e["epoch"])):
                return _fail(f"events[{i}]: actor was not a room member at epoch {e['epoch']}")
        signer = _resolve(resolve, e["actorDid"])
        if signer is None:
            return _fail(f"events[{i}]: actor has no resolvable key")
        if signer[1] != "person":
            return _fail(f"events[{i}]: actor is not a person")
        if not _ed_verify(e["sig"], consent_event_signing_bytes(record, i), signer[0]):
            return _fail(f"events[{i}]: signature does not verify")
    return Verification(True, kind="person")


def effective_consent(record: dict) -> set[str]:
    granted: set[str] = set()
    for e in record["events"]:
        for p in e["purposes"]:
            if e["event"] == "given":
                granted.add(p)
            else:
                granted.discard(p)
    return granted


# ── turns (§12.4) ─────────────────────────────────────────────────────────────

def turn_content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def turn_signing_bytes(turn: dict) -> bytes:
    return canonicalize_jcs({
        "purpose": TURN_PURPOSE,
        "threadId": turn["threadId"],
        "roomId": turn["roomId"],
        "epoch": turn["epoch"],
        "at": turn["at"],
        "contentHash": turn["contentHash"],
        "addressedTo": turn["addressedTo"],
    }).encode("utf-8")


def verify_turn(turn: Any, resolve: Resolver, room: Optional[dict] = None) -> Verification:
    if not isinstance(turn, dict):
        return _fail("turn is not an object")
    extra = _unknown(turn, {"threadId", "roomId", "epoch", "at", "contentHash", "addressedTo", "authorDid", "content", "authorSignature"})
    if extra:
        return _fail(f'unknown field "{extra}"')
    if not (_is_str(turn.get("threadId")) and _is_str(turn.get("roomId")) and _is_epoch(turn.get("epoch")) and _is_iso(turn.get("at"))):
        return _fail("malformed turn")
    if not isinstance(turn.get("contentHash"), str) or not _SHA256_HEX.match(turn["contentHash"]):
        return _fail("contentHash must be SHA-256 hex")
    if not isinstance(turn.get("addressedTo"), list) or not all(_is_did(a) for a in turn["addressedTo"]):
        return _fail("addressedTo must be a list of DIDs")
    if not _is_did(turn.get("authorDid")) or not isinstance(turn.get("content"), str) or not _is_str(turn.get("authorSignature")):
        return _fail("malformed turn author/content/signature")
    if turn_content_hash(turn["content"]) != turn["contentHash"]:
        return _fail("turn content does not match contentHash")
    if room is not None:
        if room["roomId"] != turn["roomId"] or room["threadId"] != turn["threadId"]:
            return _fail("turn is for a different room or thread")
        if not any(m["did"] == turn["authorDid"] for m in members_at(room, turn["epoch"])):
            return _fail("author was not a room member at the turn's epoch")
    signer = _resolve(resolve, turn["authorDid"])
    if signer is None:
        return _fail("turn author has no resolvable key")
    if not _ed_verify(turn["authorSignature"], turn_signing_bytes(turn), signer[0]):
        return _fail("turn signature does not verify")
    return Verification(True, kind=signer[1])


# ── action receipts v1 / v2 (§12.6) ───────────────────────────────────────────

_COMMON = {"v", "purpose", "agentDid", "action", "argsSha256", "at", "tainted", "provenance", "approval",
           "mandateId", "mandateGrantor", "correlationId", "signature"}
_V2_ONLY = {"requesterDid", "principalDid", "executorDid", "presentedHash", "traceparent", "outcome",
            "denialReason", "roomId", "onBehalfOf"}


def check_receipt(r: Any) -> Optional[str]:
    if not isinstance(r, dict):
        return "receipt is not an object"
    v1 = r.get("v") == 1 and r.get("purpose") == RECEIPT_PURPOSE_V1
    v2 = r.get("v") == 2 and r.get("purpose") == RECEIPT_PURPOSE_V2
    if not (v1 or v2):
        return "unknown receipt version"
    extra = _unknown(r, _COMMON | _V2_ONLY if v2 else _COMMON)
    if extra:
        return f'unknown field "{extra}" for this version'
    for k in ("agentDid", "action", "argsSha256", "at", "signature"):
        if not _is_str(r.get(k)):
            return f"{k} must be a non-empty string"
    if not isinstance(r.get("tainted"), bool):
        return "tainted must be a boolean"
    if "provenance" in r and not (isinstance(r["provenance"], list) and all(isinstance(p, str) for p in r["provenance"])):
        return "provenance must be a list of strings"
    for k in ("mandateId", "mandateGrantor", "correlationId"):
        if k in r and not isinstance(r[k], str):
            return f"{k} must be a string"
    if "approval" in r:
        a = r["approval"]
        allowed = {"approverDid", "approvedAt", "approvalId"} | ({"presentedHash", "approverSignature"} if v2 else set())
        if not isinstance(a, dict) or _unknown(a, allowed):
            return "approval invalid for this version"
        if not all(isinstance(a.get(k), str) for k in ("approverDid", "approvedAt", "approvalId")):
            return "approval fields must be strings"
        if "presentedHash" in a and not (isinstance(a["presentedHash"], str) and _SHA256_HEX.match(a["presentedHash"])):
            return "approval.presentedHash must be SHA-256 hex"
        if "approverSignature" in a and not isinstance(a["approverSignature"], str):
            return "approval.approverSignature must be a string"
    if v2:
        for k in ("requesterDid", "principalDid", "executorDid", "traceparent", "roomId", "onBehalfOf"):
            if k in r and not _is_str(r[k]):
                return f"{k} must be a non-empty string"
        if "presentedHash" in r and not (isinstance(r["presentedHash"], str) and _SHA256_HEX.match(r["presentedHash"])):
            return "presentedHash must be SHA-256 hex"
        outcome = r.get("outcome")
        if outcome not in ("executed", "denied"):
            return "outcome must be executed or denied"
        if outcome == "denied" and not _is_str(r.get("denialReason")):
            return "a denied receipt requires a denialReason"
        if outcome == "executed" and "denialReason" in r:
            return "an executed receipt must not carry a denialReason"
    return None


def verify_action_receipt(receipt: Any, resolve_key: Callable[[str], Optional[bytes]]) -> Verification:
    problem = check_receipt(receipt)
    if problem:
        return _fail(f"malformed receipt: {problem}")
    try:
        key = resolve_key(receipt["agentDid"])
    except Exception:
        key = None
    if not key:
        return _fail("the receipt's agent has no resolvable key")
    if not _ed_verify(receipt["signature"], signing_bytes(receipt), key):
        return _fail("receipt signature does not verify")
    return Verification(True)


def presented_hash(content: Any) -> str:
    return hashlib.sha256(canonicalize_jcs(content).encode("utf-8")).hexdigest()


def verify_presented_hash(receipt: dict, presented_content: Any) -> Optional[str]:
    """None when every presentedHash in a verified v2 receipt matches the content."""
    if receipt.get("v") != 2:
        return "a v1 receipt carries no presentedHash"
    hashes = [h for h in (receipt.get("presentedHash"), (receipt.get("approval") or {}).get("presentedHash")) if h is not None]
    if not hashes:
        return "the receipt carries no presentedHash"
    actual = presented_hash(presented_content)
    return None if all(h == actual for h in hashes) else "the presented content differs from what the receipt records"


def content_addressed_key(did: str) -> Optional[bytes]:
    if did.startswith("did:aroha:z"):
        return from_multibase(did[len("did:aroha:"):])
    return None


__all__ = [
    "ROOM_PURPOSE", "CONSENT_PURPOSE", "TURN_PURPOSE", "RECEIPT_PURPOSE_V1", "RECEIPT_PURPOSE_V2",
    "Verification", "kel_resolver", "resolve_speaker_kind", "check_disclosure",
    "check_room", "verify_room", "members_at", "check_consent", "verify_consent", "effective_consent",
    "CONSENT_EVENT_PURPOSE", "consent_event_hash", "consent_event_signing_bytes",
    "turn_content_hash", "turn_signing_bytes", "verify_turn", "signing_bytes",
    "check_receipt", "verify_action_receipt", "presented_hash", "verify_presented_hash", "content_addressed_key",
]
