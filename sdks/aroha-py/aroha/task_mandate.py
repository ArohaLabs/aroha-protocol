# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — task mandates (ArohaTaskMandate, v2 wire format).

Port of the task-mandate half of packages/aroha-credentials/src/mandate.ts
(issueTaskMandate, attenuateTaskMandate, verifyTaskMandate,
checkTaskMandateShape, checkTaskNarrowing, checkTaskConstraints,
checkTaskDataAccess, enforceTaskConstraints). A task mandate delegates
non-monetary work — which capabilities an agent may invoke, how often, with
what compute and data access — optionally alongside spending constraints
("hybrid").

Wire format (v2) — byte-compatible with the TypeScript SDK:
  token     = base64url(JSON({"v": 2, "mandate": <body>, "signature": <sig>}))
  signature = base64url(Ed25519(UTF-8(JCS({"mandate": <body>,
                                            "purpose": "aroha.task-mandate/v2",
                                            "v": 2}))))          (RFC 8785)
  body      = {"mandateType", "mandateTier", "allowed", "blocked"?,
               "taskConstraints", "spendingConstraints"?, "invariants"?,
               "grantee", "grantor", "issuedAt", "expiresAt",
               "parentMandateId", "mandateId"}                  (camelCase)

The ``purpose`` tag means a task-mandate signature verifies as nothing else
(not a spending mandate, not a v1 token) and nothing else verifies as one.
v1 tokens (no ``v``; signature over sorted-key JSON.stringify of the body)
are still accepted for verification.

A task token is a single link: unlike spending tokens it does not embed its
ancestry. Multi-hop chains are verified by @aroha-sdk/delegation's
verifyTaskMandateChain, which is not ported; ``check_task_narrowing`` is the
per-link rule that verifier applies, exposed here so a Python verifier that
holds the parent can run it.

The verification functions work on the decoded wire body (camelCase dicts),
exactly as the TypeScript ones do; the dataclasses are a snake_case
convenience for building mandates and reading results.

Conversation profile: ``TaskConstraints.on_behalf_of`` / ``room_id``
(``onBehalfOf`` / ``roomId`` on the wire) bind a guest grant to one room
member and one room. A child must keep a parent's value; a request that names
another room or member — or none — is refused (CONTEXT_MISMATCH).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Iterator, Literal, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aroha.jcs import canonicalize_jcs, js_stringify_sorted
from aroha.mandate import (
    DEFAULT_CLOCK_TOLERANCE_MS,
    PublicKeyLike,
    RevocationCheck,
    SpendingConstraints,
    TimeLike,
    _b64url,
    _check_constraints_shape,
    _fmt,
    _is_amount,
    _is_iso_date,
    _key_bytes,
    _now_value,
    _priv,
    _reject_constant,
    _unb64url,
    check_narrowing,
)
from aroha.timeutil import iso_ms, now_ms, parse_iso_ms

__all__ = [
    "TASK_MANDATE_TOKEN_VERSION",
    "TASK_MANDATE_PURPOSE",
    "ComputeLimit",
    "TaskConstraints",
    "TaskMandate",
    "SignedTaskMandate",
    "TaskMandateVerificationResult",
    "TaskActionRequest",
    "TaskConstraintViolation",
    "issue_task_mandate",
    "attenuate_task_mandate",
    "verify_task_mandate",
    "decode_task_mandate_token",
    "task_mandate_signing_payload_v2",
    "check_task_mandate_shape",
    "check_task_narrowing",
    "check_task_constraints",
    "assert_task_constraints",
    "check_task_data_access",
    "enforce_task_constraints",
]

TASK_MANDATE_TOKEN_VERSION = 2
TASK_MANDATE_PURPOSE = "aroha.task-mandate/v2"

TaskTier = Literal["intent", "cart", "execution"]
DataAccessLevel = Literal["none", "read", "read-write", "write"]


# ── Data structures ───────────────────────────────────────────────────────────

def _drop_none(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    return {k: v for k, v in pairs if v is not None}


@dataclass
class ComputeLimit:
    """Compute ceiling. Every field is an independent limit; None = not set."""
    llm_tokens: Optional[float] = None
    web_requests: Optional[float] = None
    execution_time_ms: Optional[float] = None
    cpu_seconds: Optional[float] = None

    def to_wire(self) -> dict[str, Any]:
        return _drop_none([
            ("llmTokens", self.llm_tokens),
            ("webRequests", self.web_requests),
            ("executionTimeMs", self.execution_time_ms),
            ("cpuSeconds", self.cpu_seconds),
        ])

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "ComputeLimit":
        return cls(d.get("llmTokens"), d.get("webRequests"), d.get("executionTimeMs"), d.get("cpuSeconds"))


@dataclass
class TaskConstraints:
    """Non-monetary limits (TaskConstraints in @aroha-sdk/core). None = not set.

    An unset field means "no limit on this resource" — which is why a child
    mandate must restate every limit its parent sets (check_task_narrowing).
    """
    action_limits: Optional[dict[str, float]] = None          # capability id -> max invocations
    compute_limit: Optional[ComputeLimit] = None
    data_access: Optional[dict[str, DataAccessLevel]] = None  # resource -> access; missing = none
    output_handling: Optional[Literal["internal-only", "user-only", "shareable"]] = None
    reversible_only: Optional[bool] = None
    human_gates: Optional[list[str]] = None
    checkpoint_interval_ms: Optional[float] = None
    require_sandbox: Optional[bool] = None
    max_delegation_depth: Optional[int] = None
    on_behalf_of: Optional[str] = None   # conversation profile: the room member this grant acts for
    room_id: Optional[str] = None        # conversation profile: the room this grant is bound to

    def to_wire(self) -> dict[str, Any]:
        return _drop_none([
            ("actionLimits", dict(self.action_limits) if self.action_limits is not None else None),
            ("computeLimit", self.compute_limit.to_wire() if self.compute_limit is not None else None),
            ("dataAccess", dict(self.data_access) if self.data_access is not None else None),
            ("outputHandling", self.output_handling),
            ("reversibleOnly", self.reversible_only),
            ("humanGates", list(self.human_gates) if self.human_gates is not None else None),
            ("checkpointIntervalMs", self.checkpoint_interval_ms),
            ("requireSandbox", self.require_sandbox),
            ("maxDelegationDepth", self.max_delegation_depth),
            ("onBehalfOf", self.on_behalf_of),
            ("roomId", self.room_id),
        ])

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "TaskConstraints":
        cl = d.get("computeLimit")
        return cls(
            action_limits=d.get("actionLimits"),
            compute_limit=ComputeLimit.from_wire(cl) if isinstance(cl, dict) else None,
            data_access=d.get("dataAccess"),
            output_handling=d.get("outputHandling"),
            reversible_only=d.get("reversibleOnly"),
            human_gates=d.get("humanGates"),
            checkpoint_interval_ms=d.get("checkpointIntervalMs"),
            require_sandbox=d.get("requireSandbox"),
            max_delegation_depth=d.get("maxDelegationDepth"),
            on_behalf_of=d.get("onBehalfOf"),
            room_id=d.get("roomId"),
        )


ConstraintsLike = Union[TaskConstraints, dict[str, Any]]


def _tc_wire(c: Optional[ConstraintsLike]) -> dict[str, Any]:
    if c is None:
        return {}
    return c.to_wire() if isinstance(c, TaskConstraints) else dict(c)


def _sc_wire(c: Union[SpendingConstraints, dict[str, Any], None]) -> Optional[dict[str, Any]]:
    if c is None:
        return None
    return c.to_wire() if isinstance(c, SpendingConstraints) else dict(c)


@dataclass
class TaskMandate:
    """A decoded task-mandate body (ArohaTaskMandateBody), snake_case."""
    mandate_type: Literal["task", "hybrid"]
    mandate_tier: TaskTier
    allowed: list[str]
    task_constraints: TaskConstraints
    grantee: str
    grantor: str
    issued_at: str
    expires_at: str
    parent_mandate_id: Optional[str]
    mandate_id: str
    blocked: Optional[list[str]] = None
    spending_constraints: Optional[SpendingConstraints] = None
    invariants: Optional[dict[str, Any]] = None   # MandateInvariants, wire (camelCase) form

    def to_wire(self) -> dict[str, Any]:
        """Wire body, keys in the order TypeScript's issueTaskMandate writes them."""
        return _drop_none([
            ("mandateType", self.mandate_type),
            ("mandateTier", self.mandate_tier),
            ("allowed", list(self.allowed)),
            ("blocked", list(self.blocked) if self.blocked is not None else None),
            ("taskConstraints", self.task_constraints.to_wire()),
            ("spendingConstraints", _sc_wire(self.spending_constraints)),
            ("invariants", self.invariants),
            ("grantee", self.grantee),
            ("grantor", self.grantor),
            ("issuedAt", self.issued_at),
            ("expiresAt", self.expires_at),
        ]) | {"parentMandateId": self.parent_mandate_id, "mandateId": self.mandate_id}

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "TaskMandate":
        sc = d.get("spendingConstraints")
        return cls(
            mandate_type=d["mandateType"],
            mandate_tier=d["mandateTier"],
            allowed=list(d["allowed"]),
            blocked=list(d["blocked"]) if d.get("blocked") is not None else None,
            task_constraints=TaskConstraints.from_wire(d.get("taskConstraints") or {}),
            spending_constraints=SpendingConstraints.from_wire(sc) if isinstance(sc, dict) else None,
            invariants=d.get("invariants"),
            grantee=d["grantee"],
            grantor=d["grantor"],
            issued_at=d["issuedAt"],
            expires_at=d["expiresAt"],
            parent_mandate_id=d.get("parentMandateId"),
            mandate_id=d["mandateId"],
        )


@dataclass
class SignedTaskMandate:
    mandate: TaskMandate
    signature: str                  # base64url Ed25519 signature
    token: str                      # base64url token
    v: int = TASK_MANDATE_TOKEN_VERSION
    wire: Optional[dict[str, Any]] = None   # the exact body that was signed


@dataclass
class TaskMandateVerificationResult:
    valid: bool
    mandate: Optional[TaskMandate] = None
    reason: Optional[str] = None
    wire: Optional[dict[str, Any]] = None   # the verified body, camelCase

    def __iter__(self) -> Iterator[Any]:
        """``valid, mandate, reason = verify_task_mandate(...)``."""
        return iter((self.valid, self.mandate, self.reason))

    def __bool__(self) -> bool:
        return self.valid


class TaskConstraintViolation(Exception):
    """Raised / returned by the constraint checks. ``code`` matches the TypeScript codes."""

    def __init__(
        self,
        message: str,
        code: Literal[
            "MANDATE_INVALID", "CAPABILITY_NOT_PERMITTED", "REVERSIBILITY_VIOLATION", "HUMAN_GATE_REQUIRED",
            "ACTION_LIMIT_EXCEEDED", "COMPUTE_LIMIT_EXCEEDED", "DATA_ACCESS_VIOLATION", "SANDBOX_REQUIRED",
            "DELEGATION_DEPTH_EXCEEDED", "CONTEXT_MISMATCH",
        ],
    ) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class TaskActionRequest:
    """One requested action, checked against a VERIFIED task mandate.

    ``current_compute`` keys: ``llm_tokens``, ``web_requests``,
    ``wall_clock_ms`` (the TypeScript camelCase keys are accepted too).
    ``capability_reversibility`` omitted = "irreversible" (fails closed under
    reversibleOnly). ``data_access`` declares what the action touches; with
    it omitted the dataAccess map is not consulted. ``room_id`` /
    ``on_behalf_of`` must come from the runtime's own room record, never from
    the request body.
    """
    requested_capability: str
    current_action_counts: Optional[dict[str, float]] = None
    current_compute: Optional[dict[str, float]] = None
    capability_reversibility: Optional[Literal["full", "semi", "irreversible"]] = None
    data_access: Optional[dict[str, Literal["read", "write", "read-write"]]] = None
    human_approved: bool = False
    room_id: Optional[str] = None
    on_behalf_of: Optional[str] = None


# ── Signing ───────────────────────────────────────────────────────────────────

def task_mandate_signing_payload_v2(mandate: Union[dict[str, Any], TaskMandate]) -> str:
    """The exact string a v2 task signature covers:
    JCS of ``{"mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2}``."""
    body = mandate.to_wire() if isinstance(mandate, TaskMandate) else mandate
    return canonicalize_jcs({"mandate": body, "purpose": TASK_MANDATE_PURPOSE, "v": 2})


def _signing_bytes(v: int, body: dict[str, Any]) -> bytes:
    s = task_mandate_signing_payload_v2(body) if v == 2 else js_stringify_sorted(body)
    return s.encode("utf-8")


def _verify_signature(v: int, body: dict[str, Any], signature: str, public_key: Optional[bytes]) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(  # type: ignore[arg-type]
            _unb64url(signature), _signing_bytes(v, body)
        )
        return True
    except (InvalidSignature, Exception):
        return False


# ── Issue / attenuate ─────────────────────────────────────────────────────────

def _new_id() -> str:
    return str(uuid.uuid4())


def issue_task_mandate(
    grantor_did: str,
    grantee_did: str,
    allowed: list[str],
    task_constraints: ConstraintsLike,
    private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: float = 3600,
    *,
    blocked: Optional[list[str]] = None,
    spending_constraints: Union[SpendingConstraints, dict[str, Any], None] = None,
    parent_mandate_id: Optional[str] = None,
    tier: Optional[TaskTier] = None,
    invariants: Optional[dict[str, Any]] = None,
    expires_at_ms: Optional[int] = None,
) -> SignedTaskMandate:
    """Issue a task mandate (root by default). Same as issueTaskMandate in mandate.ts.

    ``spending_constraints`` makes it a "hybrid" mandate. ``expires_at_ms``
    (absolute, Unix ms) overrides ``ttl_seconds``. The body is validated with
    check_task_mandate_shape before signing, so a mandate this function
    issues is one every SDK accepts.
    """
    issued = now_ms()
    expiry = expires_at_ms if expires_at_ms is not None else issued + int(ttl_seconds * 1000)
    sc = _sc_wire(spending_constraints)
    body = _drop_none([
        ("mandateType", "hybrid" if sc is not None else "task"),
        ("mandateTier", tier or "intent"),
        ("allowed", list(allowed)),
        ("blocked", list(blocked) if blocked is not None else None),
        ("taskConstraints", _tc_wire(task_constraints)),
        ("spendingConstraints", sc),
        ("invariants", invariants),
        ("grantee", grantee_did),
        ("grantor", grantor_did),
        ("issuedAt", iso_ms(issued)),
        ("expiresAt", iso_ms(expiry)),
    ]) | {"parentMandateId": parent_mandate_id, "mandateId": _new_id()}
    # Same normalisation as TypeScript's JSON round trip: what is signed is
    # exactly what a verifier will decode (no NaN/Infinity, plain JSON types).
    body = json.loads(json.dumps(body, allow_nan=False))
    shape = check_task_mandate_shape(body)
    if shape:
        raise ValueError(f"Invalid task mandate: {shape}")

    sig = _b64url(_priv(private_key).sign(_signing_bytes(2, body)))
    token = _b64url(json.dumps(
        {"v": TASK_MANDATE_TOKEN_VERSION, "mandate": body, "signature": sig},
        separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8"))
    return SignedTaskMandate(TaskMandate.from_wire(body), sig, token, 2, body)


def _merge_lists(a: Optional[list[str]], b: Optional[list[str]]) -> Optional[list[str]]:
    if a is None and b is None:
        return None
    out: list[str] = []
    for x in [*(a or []), *(b or [])]:
        if x not in out:
            out.append(x)
    return out


def attenuate_task_mandate(
    parent: SignedTaskMandate,
    grantee_did: str,
    narrowed_allowed: list[str],
    narrowed_constraints: ConstraintsLike,
    grantor_private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: Optional[float] = None,
    *,
    blocked: Optional[list[str]] = None,
    spending_constraints: Union[SpendingConstraints, dict[str, Any], None] = None,
    invariants: Optional[dict[str, Any]] = None,
) -> SignedTaskMandate:
    """Attenuate to a narrower child. Same rules as attenuateTaskMandate in mandate.ts.

    The parent's ``blocked`` list and spending constraints are inherited when
    omitted (inheriting is never a widening); so are its ``onBehalfOf`` /
    ``roomId`` bindings. Invariants are NOT inherited — restate them. Every
    other limit the parent sets must be restated equal-or-narrower, else
    ValueError (check_task_narrowing). The child's tier is cart under an
    intent parent, execution otherwise; it never outlives the parent.
    """
    p = parent.wire if parent.wire is not None else parent.mandate.to_wire()
    merged_blocked = _merge_lists(p.get("blocked"), blocked)
    sc = _sc_wire(spending_constraints)
    if sc is None:
        sc = p.get("spendingConstraints")
    ptc = p.get("taskConstraints") or {}
    ctc = _tc_wire(narrowed_constraints)
    for f in ("onBehalfOf", "roomId"):
        if ptc.get(f) is not None and ctc.get(f) is None:
            ctc[f] = ptc[f]

    reason = check_task_narrowing(p, _drop_none([
        ("allowed", list(narrowed_allowed)),
        ("blocked", merged_blocked),
        ("taskConstraints", ctc),
        ("spendingConstraints", sc),
        ("invariants", invariants),
    ]))
    if reason:
        raise ValueError(reason)

    # Absolute expiry: one clock read, so the child cannot land a tick past the parent.
    parent_expiry = parse_iso_ms(p["expiresAt"])
    if parent_expiry is None:
        raise ValueError("Parent task mandate has an unparseable expiresAt")
    expiry = min(parent_expiry, now_ms() + int(ttl_seconds * 1000)) if ttl_seconds else parent_expiry

    return issue_task_mandate(
        p["grantee"], grantee_did, narrowed_allowed, ctc, grantor_private_key,
        expires_at_ms=expiry,
        blocked=merged_blocked,
        spending_constraints=sc,
        parent_mandate_id=p["mandateId"],
        tier="cart" if p["mandateTier"] == "intent" else "execution",
        invariants=invariants,
    )


# ── Verify ────────────────────────────────────────────────────────────────────

def _parse(token: Any) -> Union[tuple[int, dict[str, Any], str], str]:
    if not isinstance(token, str) or not token:
        return "Malformed token"
    try:
        raw = json.loads(_unb64url(token).decode("utf-8"), parse_constant=_reject_constant)
    except Exception:
        return "Malformed token"
    if not isinstance(raw, dict):
        return "Malformed token"
    if not isinstance(raw.get("signature"), str) or not raw["signature"]:
        return "Malformed token: signature missing"
    v = raw.get("v")
    if "v" not in raw or (v == 1 and not isinstance(v, bool)):
        version = 1
    elif v == 2 and not isinstance(v, bool):
        version = 2
    else:
        return f"Unsupported task mandate token version: {_js_string(v)}"
    shape = check_task_mandate_shape(raw.get("mandate"))
    if shape:
        return f"Malformed token: {shape}"
    return version, raw["mandate"], raw["signature"]


def _js_string(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _fmt(v)
    return str(v)


def decode_task_mandate_token(token: str) -> SignedTaskMandate:
    """Decode a token WITHOUT verifying it (use verify_task_mandate for that). ValueError if malformed."""
    parsed = _parse(token)
    if isinstance(parsed, str):
        raise ValueError(parsed)
    v, body, sig = parsed
    return SignedTaskMandate(TaskMandate.from_wire(body), sig, token, v, body)


def verify_task_mandate(
    token: str,
    public_key: PublicKeyLike,
    expected_grantee: Optional[str] = None,
    *,
    now: Optional[TimeLike] = None,
    clock_tolerance_ms: int = DEFAULT_CLOCK_TOLERANCE_MS,
    is_revoked: Optional[RevocationCheck] = None,
) -> TaskMandateVerificationResult:
    """Verify a task-mandate token: shape, time window, grantee, signature, revocation.

    Same checks, order and reasons as verifyTaskMandate in mandate.ts. Expiry
    is strict; ``clock_tolerance_ms`` applies to the not-before check on
    issuedAt only. ``is_revoked(mandate_id, grantor)`` fails closed if it
    raises. Never raises; the result unpacks as ``valid, mandate, reason``.
    """
    parsed = _parse(token)
    if isinstance(parsed, str):
        return TaskMandateVerificationResult(False, reason=parsed)
    version, m, signature = parsed

    t = _now_value(now)
    expires, issued = parse_iso_ms(m["expiresAt"]), parse_iso_ms(m["issuedAt"])
    if expires < t:  # type: ignore[operator]  (shape guarantees both parse)
        return TaskMandateVerificationResult(False, reason="Task mandate expired")
    if issued > t + clock_tolerance_ms:  # type: ignore[operator]
        return TaskMandateVerificationResult(False, reason=f"Task mandate issuedAt {m['issuedAt']} is in the future")
    if expires < issued:  # type: ignore[operator]
        return TaskMandateVerificationResult(False, reason="Task mandate expires before it was issued")

    if expected_grantee and m["grantee"] != expected_grantee:
        return TaskMandateVerificationResult(False, reason=f"Grantee mismatch: expected {expected_grantee}")

    if not _verify_signature(version, m, signature, _key_bytes(public_key)):
        return TaskMandateVerificationResult(False, reason="Invalid signature")

    if is_revoked is not None:
        try:
            if is_revoked(m["mandateId"], m["grantor"]):
                return TaskMandateVerificationResult(False, reason=f"Task mandate {m['mandateId']} has been revoked")
        except Exception:
            return TaskMandateVerificationResult(
                False, reason=f"Revocation check failed for task mandate {m['mandateId']}"
            )

    return TaskMandateVerificationResult(True, TaskMandate.from_wire(m), None, m)


# ── Shape ─────────────────────────────────────────────────────────────────────

_DATA_ACCESS_RIGHTS: dict[str, tuple[bool, bool]] = {   # (read, write)
    "none": (False, False),
    "read": (True, False),
    "write": (False, True),
    "read-write": (True, True),
}
_OUTPUT_HANDLING_RANK = {"internal-only": 0, "user-only": 1, "shareable": 2}
_COMPUTE_FIELDS = ("llmTokens", "webRequests", "executionTimeMs", "cpuSeconds")


def _is_str_list(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(v, str) for v in x)


def check_task_mandate_shape(m: Any) -> Optional[str]:
    """Structural validation of a decoded task-mandate body. Same rules and messages as checkTaskMandateShape."""
    if not isinstance(m, dict):
        return "mandate is not an object"
    if m.get("mandateType") not in ("task", "hybrid"):
        return "mandateType is invalid"
    if m.get("mandateTier") not in ("intent", "cart", "execution"):
        return "mandateTier is invalid"
    for f in ("grantor", "grantee", "mandateId"):
        if not isinstance(m.get(f), str) or len(m[f]) == 0:
            return f"{f} is missing"
    if not _is_iso_date(m.get("issuedAt")):
        return "issuedAt is not a date"
    if not _is_iso_date(m.get("expiresAt")):
        return "expiresAt is not a date"
    # JavaScript: undefined !== null and is not a string, so a missing key is invalid.
    if "parentMandateId" not in m or (m["parentMandateId"] is not None and not isinstance(m["parentMandateId"], str)):
        return "parentMandateId is invalid"
    if not _is_str_list(m.get("allowed")):
        return "allowed must be an array of capability ids"
    if "blocked" in m and not _is_str_list(m["blocked"]):
        return "blocked must be an array of capability ids"

    tc = m.get("taskConstraints")
    if not isinstance(tc, dict):
        return "taskConstraints is not an object"
    if "actionLimits" in tc:
        if not isinstance(tc["actionLimits"], dict):
            return "taskConstraints.actionLimits must be an object"
        for cap, n in tc["actionLimits"].items():
            if not _is_amount(n):
                return f'taskConstraints.actionLimits["{cap}"] must be a finite, non-negative number'
    if "computeLimit" in tc:
        if not isinstance(tc["computeLimit"], dict):
            return "taskConstraints.computeLimit must be an object"
        for f in _COMPUTE_FIELDS:
            if f in tc["computeLimit"] and not _is_amount(tc["computeLimit"][f]):
                return f"taskConstraints.computeLimit.{f} must be a finite, non-negative number"
    if "dataAccess" in tc:
        if not isinstance(tc["dataAccess"], dict):
            return "taskConstraints.dataAccess must be an object"
        for res, a in tc["dataAccess"].items():
            if a not in _DATA_ACCESS_RIGHTS:
                return f'taskConstraints.dataAccess["{res}"] is invalid'
    if "reversibleOnly" in tc and not isinstance(tc["reversibleOnly"], bool):
        return "taskConstraints.reversibleOnly must be a boolean"
    for f in ("onBehalfOf", "roomId"):
        if f in tc and (not isinstance(tc[f], str) or len(tc[f]) == 0):
            return f"taskConstraints.{f} must be a non-empty string"

    if m["mandateType"] == "hybrid" or "spendingConstraints" in m:
        sc = _check_constraints_shape(m.get("spendingConstraints"))
        if sc:
            return f"spendingConstraints: {sc}"
    if "invariants" in m and not isinstance(m["invariants"], dict):
        return "invariants must be an object"
    return None


# ── Narrowing ─────────────────────────────────────────────────────────────────

MandateLike = Union[TaskMandate, SignedTaskMandate, dict[str, Any]]


def _body(m: MandateLike) -> dict[str, Any]:
    if isinstance(m, SignedTaskMandate):
        return m.wire if m.wire is not None else m.mandate.to_wire()
    if isinstance(m, TaskMandate):
        return m.to_wire()
    return m


def _rights(level: Any) -> Optional[tuple[bool, bool]]:
    return _DATA_ACCESS_RIGHTS.get(level) if isinstance(level, str) else None


def check_task_narrowing(parent: MandateLike, child: MandateLike) -> Optional[str]:
    """None when ``child`` is equal to or narrower than ``parent``, else the reason.

    Identical to checkTaskNarrowing in mandate.ts. For every constraint the
    PARENT sets, the child must set it too, equal or narrower — omission is
    widening. ``child`` may be a partial body (allowed, blocked,
    taskConstraints, spendingConstraints, invariants, expiresAt). Not checked
    here: maxDelegationDepth and grantor/grantee/parentMandateId linkage
    (the chain verifier's job).
    """
    pb, cb = _body(parent), _body(child)
    prefix = "Cannot attenuate task mandate"
    ptc: dict[str, Any] = pb.get("taskConstraints") or {}
    ctc: dict[str, Any] = cb.get("taskConstraints") or {}

    parent_allowed = set(pb.get("allowed") or [])
    for cap in cb.get("allowed") or []:
        if cap not in parent_allowed:
            return f"{prefix}: child allowed includes \"{cap}\" which is not in parent's allowed list"
    child_allowed = set(cb.get("allowed") or [])

    child_blocked = set(cb.get("blocked") or [])
    for cap in pb.get("blocked") or []:
        if cap not in child_blocked:
            return f"{prefix}: child drops parent's blocked capability \"{cap}\""

    if ptc.get("actionLimits"):
        c_limits = ctc.get("actionLimits") or {}
        for cap, parent_limit in ptc["actionLimits"].items():
            if cap not in child_allowed:
                continue
            if cap not in c_limits:
                return f'{prefix}: parent sets actionLimits["{cap}"] ({_fmt(parent_limit)}) but child omits it'
            child_limit = c_limits[cap]
            if not _is_amount(child_limit) or child_limit > parent_limit:
                return (
                    f'{prefix}: child actionLimits["{cap}"] ({_fmt(child_limit)}) exceeds parent ({_fmt(parent_limit)})'
                )

    if ptc.get("computeLimit"):
        c_compute = ctc.get("computeLimit") or {}
        for f in _COMPUTE_FIELDS:
            if f not in ptc["computeLimit"]:
                continue
            p = ptc["computeLimit"][f]
            if f not in c_compute:
                return f"{prefix}: parent sets computeLimit.{f} ({_fmt(p)}) but child omits it"
            c = c_compute[f]
            if not _is_amount(c) or c > p:
                return f"{prefix}: child {f} ({_fmt(c)}) exceeds parent ({_fmt(p)})"

    # Empty is NOT absent: an empty map is a deny-all grant, and in the
    # TypeScript reference `{}` is truthy. Only a MISSING map means no limit.
    if ptc.get("dataAccess") is not None:
        if ctc.get("dataAccess") is None:
            return f"{prefix}: parent restricts dataAccess but child omits it"
        for resource, child_access in ctc["dataAccess"].items():
            parent_access = ptc["dataAccess"].get(resource, "none")
            c, p = _rights(child_access), _rights(parent_access)
            if not c or not p or (c[0] and not p[0]) or (c[1] and not p[1]):
                return f'{prefix}: child dataAccess["{resource}"] ({child_access}) exceeds parent ({parent_access})'

    if ptc.get("reversibleOnly") is True and ctc.get("reversibleOnly") is not True:
        return f"{prefix}: parent requires reversibleOnly but child does not"
    if ptc.get("requireSandbox") is True and ctc.get("requireSandbox") is not True:
        return f"{prefix}: parent requires requireSandbox but child does not"

    for f in ("onBehalfOf", "roomId"):
        if ptc.get(f) is not None and ctc.get(f) != ptc[f]:
            shown = ctc.get(f) if ctc.get(f) is not None else "unset"
            return f"{prefix}: child {f} ({shown}) does not keep the parent's {f} ({ptc[f]})"

    if ptc.get("humanGates"):
        child_gates = set(ctc.get("humanGates") or [])
        for cap in ptc["humanGates"]:
            if cap in child_allowed and cap not in child_gates:
                return f"{prefix}: child drops parent's human gate on \"{cap}\""

    if ptc.get("outputHandling") is not None:
        p_rank = _OUTPUT_HANDLING_RANK.get(ptc["outputHandling"])
        c_val = ctc.get("outputHandling")
        c_rank = _OUTPUT_HANDLING_RANK.get(c_val) if c_val is not None else None
        if c_rank is None or p_rank is None or c_rank > p_rank:
            shown = c_val if c_val is not None else "unset"
            return f"{prefix}: child outputHandling ({shown}) is wider than parent ({ptc['outputHandling']})"

    if ptc.get("checkpointIntervalMs") is not None:
        c = ctc.get("checkpointIntervalMs")
        if c is None or not _is_amount(c) or c > ptc["checkpointIntervalMs"]:
            shown = _fmt(c) if c is not None else "unset"
            return (
                f"{prefix}: child checkpointIntervalMs ({shown}) is longer than parent "
                f"({_fmt(ptc['checkpointIntervalMs'])})"
            )

    if pb.get("spendingConstraints") is not None:
        if cb.get("spendingConstraints") is None:
            return f"{prefix}: parent sets spendingConstraints but child omits them"
        reason = check_narrowing(pb["spendingConstraints"], cb["spendingConstraints"], "task", "task")
        if reason:
            return f"{prefix}: spendingConstraints: {reason}"

    # Objects and lists follow TypeScript truthiness: present-but-empty is
    # still a restriction (an empty payee list pays nobody), so test for
    # presence, never for emptiness.
    pi = pb.get("invariants")
    if pi is not None:
        ci = cb.get("invariants")
        if ci is None:
            return f"{prefix}: parent has invariants but child drops them entirely"
        if pi.get("payee") is not None:
            if ci.get("payee") is None:
                return f"{prefix}: parent restricts payee but child has no payee invariant"
            parent_payees = set(pi["payee"])
            for p in ci["payee"]:
                if p not in parent_payees:
                    return f"{prefix}: child payee \"{p}\" is not in parent's payee list"
        if pi.get("maxAmount") is not None:
            cm, pm = ci.get("maxAmount"), pi["maxAmount"]
            if cm is None:
                return f"{prefix}: parent has maxAmount invariant but child has none"
            if cm.get("currency") != pm.get("currency"):
                return (
                    f"{prefix}: child maxAmount currency ({cm.get('currency')}) differs from parent "
                    f"({pm.get('currency')})"
                )
            if not _is_amount(cm.get("amount")) or cm["amount"] > pm["amount"]:
                return f"{prefix}: child maxAmount ({_fmt(cm.get('amount'))}) exceeds parent ({_fmt(pm['amount'])})"
        if pi.get("parameters"):
            child_params = ci.get("parameters") or {}
            for key, parent_value in pi["parameters"].items():
                if key not in child_params or not _js_strict_equal(child_params[key], parent_value):
                    return f"{prefix}: child parameter \"{key}\" does not match parent's fixed value"
        if pi.get("expiry"):
            if not ci.get("expiry"):
                return f"{prefix}: parent has expiry invariant but child has none"
            c = parse_iso_ms(ci["expiry"])
            p_exp = parse_iso_ms(pi["expiry"])
            # As in TypeScript: an unparseable child expiry fails; c > NaN is false.
            if c is None or (p_exp is not None and c > p_exp):
                return f"{prefix}: child expiry ({ci['expiry']}) exceeds parent ({pi['expiry']})"

    if cb.get("expiresAt") is not None:
        c = parse_iso_ms(cb["expiresAt"])
        p_exp = parse_iso_ms(pb.get("expiresAt"))
        if c is None or p_exp is None or c > p_exp:
            return f"{prefix}: child expiry ({cb['expiresAt']}) extends beyond parent ({pb.get('expiresAt')})"

    return None


def _js_strict_equal(a: Any, b: Any) -> bool:
    """JavaScript ``===`` on decoded JSON values: scalars by value (True is
    not 1), objects and arrays never (two decoded objects are distinct)."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


# ── Constraint enforcement ────────────────────────────────────────────────────

def _compute_used(req: TaskActionRequest, snake: str, camel: str) -> float:
    cc = req.current_compute or {}
    v = cc.get(snake, cc.get(camel, 0))
    return v if v is not None else 0


def check_task_data_access(
    task_constraints: Optional[ConstraintsLike],
    requested: Optional[dict[str, str]],
) -> Optional[TaskConstraintViolation]:
    """The dataAccess rule on its own: every requested resource must be granted
    with the rights asked for (a resource missing from the map is "none").
    No dataAccess map, or nothing requested, means no limit applies."""
    grants = _tc_wire(task_constraints).get("dataAccess")
    # `{}` grants nothing (every resource is "none"); only a missing map is
    # "no limit". Matches TypeScript, where an empty object is truthy.
    if grants is None or not requested:
        return None
    for resource, wanted in requested.items():
        granted = grants.get(resource, "none")
        g, w = _rights(granted), _rights(wanted)
        if not g or not w or (w[0] and not g[0]) or (w[1] and not g[1]):
            return TaskConstraintViolation(
                f'Data access "{wanted}" on "{resource}" exceeds the mandate\'s grant ({granted})',
                "DATA_ACCESS_VIOLATION",
            )
    return None


def check_task_constraints(mandate: MandateLike, request: TaskActionRequest) -> Optional[TaskConstraintViolation]:
    """Check one action against an ALREADY-VERIFIED task mandate; the violation, or None.

    Same checks, order, messages and codes as checkTaskConstraints: room /
    on-behalf-of binding, allowed / blocked, reversibleOnly, humanGates,
    actionLimits, computeLimit (when consumption is reported), dataAccess.
    """
    m = _body(mandate)
    tc: dict[str, Any] = m.get("taskConstraints") or {}
    cap = request.requested_capability

    if tc.get("roomId") is not None and request.room_id != tc["roomId"]:
        return TaskConstraintViolation(
            f"The mandate is bound to room {tc['roomId']}; the request is from {request.room_id or 'no room'}",
            "CONTEXT_MISMATCH",
        )
    if tc.get("onBehalfOf") is not None and request.on_behalf_of != tc["onBehalfOf"]:
        return TaskConstraintViolation(
            f"The mandate acts on behalf of {tc['onBehalfOf']}; the request is for "
            f"{request.on_behalf_of or 'nobody named'}",
            "CONTEXT_MISMATCH",
        )

    if cap not in (m.get("allowed") or []):
        return TaskConstraintViolation(f'Capability "{cap}" is not in the mandate\'s allowed list', "CAPABILITY_NOT_PERMITTED")
    if cap in (m.get("blocked") or []):
        return TaskConstraintViolation(f'Capability "{cap}" is explicitly blocked by the mandate', "CAPABILITY_NOT_PERMITTED")

    if tc.get("reversibleOnly"):
        if (request.capability_reversibility or "irreversible") == "irreversible":
            return TaskConstraintViolation(
                f'Capability "{cap}" is irreversible but mandate requires reversibleOnly', "REVERSIBILITY_VIOLATION"
            )

    gates = tc.get("humanGates")
    if gates is not None and not isinstance(gates, list):
        # TypeScript throws on a non-array here; fail closed rather than pass.
        return TaskConstraintViolation("Task mandate humanGates is not a list", "MANDATE_INVALID")
    if gates and cap in gates and request.human_approved is not True:
        return TaskConstraintViolation(f'Capability "{cap}" requires human approval (humanGate)', "HUMAN_GATE_REQUIRED")

    if tc.get("actionLimits"):
        limit = tc["actionLimits"].get(cap)
        if limit is not None:
            current = (request.current_action_counts or {}).get(cap, 0)
            if current >= limit:
                return TaskConstraintViolation(
                    f'Action limit exceeded for "{cap}": {_fmt(current)}/{_fmt(limit)}', "ACTION_LIMIT_EXCEEDED"
                )

    cl = tc.get("computeLimit")
    if cl and request.current_compute is not None:
        if cl.get("llmTokens") is not None and _compute_used(request, "llm_tokens", "llmTokens") >= cl["llmTokens"]:
            return TaskConstraintViolation(
                f"LLM token budget exhausted ({_fmt(cl['llmTokens'])} max)", "COMPUTE_LIMIT_EXCEEDED"
            )
        if cl.get("webRequests") is not None and _compute_used(request, "web_requests", "webRequests") >= cl["webRequests"]:
            return TaskConstraintViolation(
                f"Web request budget exhausted ({_fmt(cl['webRequests'])} max)", "COMPUTE_LIMIT_EXCEEDED"
            )
        if (
            cl.get("executionTimeMs") is not None
            and _compute_used(request, "wall_clock_ms", "wallClockMs") >= cl["executionTimeMs"]
        ):
            return TaskConstraintViolation(
                f"Execution time budget exhausted ({_fmt(cl['executionTimeMs'])}ms max)", "COMPUTE_LIMIT_EXCEEDED"
            )

    return check_task_data_access(tc, request.data_access)


def assert_task_constraints(mandate: MandateLike, request: TaskActionRequest) -> None:
    """Throwing form of check_task_constraints."""
    violation = check_task_constraints(mandate, request)
    if violation:
        raise violation


def enforce_task_constraints(
    token: str,
    grantor_public_key: PublicKeyLike,
    request: Optional[TaskActionRequest] = None,
    *,
    expected_grantee: Optional[str] = None,
    is_revoked: Optional[RevocationCheck] = None,
    now: Optional[TimeLike] = None,
    **request_fields: Any,
) -> TaskMandate:
    """Verify a task-mandate token AND check the requested action against it.

    Call at your capability gate before any side-effecting operation. Pass a
    TaskActionRequest, or its fields as keywords
    (``requested_capability="send-email", human_approved=True, ...``).
    Raises TaskConstraintViolation (code MANDATE_INVALID when the token
    itself does not verify).
    """
    if request is None:
        request = TaskActionRequest(**request_fields)
    elif request_fields:
        raise TypeError("pass either a TaskActionRequest or its fields as keywords, not both")
    result = verify_task_mandate(token, grantor_public_key, expected_grantee, is_revoked=is_revoked, now=now)
    if not result.valid:
        raise TaskConstraintViolation(f"Task mandate invalid: {result.reason}", "MANDATE_INVALID")
    assert result.wire is not None and result.mandate is not None
    assert_task_constraints(result.wire, request)
    return result.mandate
