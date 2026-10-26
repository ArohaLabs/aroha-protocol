# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — ArohaSpendingMandate tokens (v2 wire format).

Port of packages/aroha-credentials/src/mandate.ts. Issues, attenuates and
verifies spending mandates. The chain enforces:

  1. Provenance — every mandate traces back, link by link, to a root intent
     mandate signed by the human. A v2 token CARRIES its signed ancestry
     (root first, leaf excluded), so ``verify_mandate_chain`` checks it
     offline: each link signed by its grantor, each grantor is the previous
     link's grantee, each ``parentMandateId`` names the previous link.
  2. Monotonic narrowing — ``check_narrowing`` is re-run by the VERIFIER on
     every link (the attenuation-time check runs on the delegating agent's
     machine and a dishonest agent can skip it).
  3. Time windows, tier order (intent -> cart -> payment), revocation.

Wire format (v2) — identical bytes to the TypeScript SDK:
  token     = base64url(JSON({"v": 2, "mandate": <body>, "signature": <sig>, "chain": [<link>, ...]}))
  link      = {"v": 1|2, "mandate": <body>, "signature": <sig>}
  signature = base64url(Ed25519(UTF-8(JCS({"mandate": <body>, "v": 2}))))   (RFC 8785)
  body      = {"mandateTier", "constraints", "grantee", "grantor", "issuedAt",
               "expiresAt", "parentMandateId", "mandateId"}            (camelCase)
  constraints = {"spendLimitUsd", "sessionLimitUsd"?, "currency"?, "merchantCategory"?,
                 "requireHumanApprovalAboveUsd"?, "allowedMerchants"?, "validFrom"?, "validUntil"?}

BREAKING CHANGE (aroha 1.6 / this release): tokens issued by earlier Python
releases used snake_case field names, no ``issuedAt``, no chain, and a
signature over Python ``json.dumps(sort_keys)`` — no other SDK could verify
them. Every token this module issues is now v2. Legacy tokens (old Python
snake_case v1 and TypeScript camelCase v1) are still ACCEPTED FOR
VERIFICATION ONLY: a legacy root verifies as a one-link chain; a legacy child
carries no ancestry, so ``verify_mandate`` reports it with
``chain_verified=False`` and ``verify_mandate_chain`` rejects it. Old Python
snake_case tokens cannot be attenuated further — re-issue them.

The Python API keeps snake_case names (``spend_limit_usd`` …); only the wire
changed. Cumulative budget enforcement lives in ``aroha.spending_ledger``
(``SpendingLedger``, ``InMemorySpendingLedger``; durable ledgers in
``aroha.stores.postgres`` and ``aroha.stores.redis``), used by
``aroha.http_mandate.verify_http_spend_request``. Not ported: RedemptionStore
/ ``redeemPaymentMandate`` — use the TypeScript SDK for that. Task mandates
live in ``aroha.task_mandate``.
"""

from __future__ import annotations

import base64
import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Literal, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import from_multibase, to_multibase
from aroha.jcs import canonicalize_jcs, format_es_number, js_stringify_sorted
from aroha.kel import KelSource, KelState, KelStore, is_inception_did, kel_key_resolver, resolve_kel_state
from aroha.timeutil import iso_ms, now_ms, parse_iso_ms, to_ms

__all__ = [
    "MANDATE_TOKEN_VERSION",
    "SpendingConstraints",
    "SpendingMandate",
    "MandateChainLink",
    "SignedMandate",
    "MandateVerificationResult",
    "SpendingConstraintViolation",
    "issue_intent_mandate",
    "attenuate_to_cart",
    "attenuate_to_payment",
    "decode_mandate_token",
    "verify_mandate",
    "verify_mandate_chain",
    "enforce_spending_constraints",
    "mandate_redemption_key",
    "mandate_cumulative_limit_usd",
    "spend_amount_micros",
    "check_spend_amount",
    "check_spend_merchant",
    "check_spend_against_constraints",
    "check_narrowing",
    "check_mandate_shape",
    "mandate_signing_payload_v2",
    "resolve_content_addressed_key",
    "create_mandate_key_resolver",
]

MANDATE_TOKEN_VERSION = 2
DEFAULT_CLOCK_TOLERANCE_MS = 30_000
DEFAULT_MAX_DEPTH = 8

MandateTier = Literal["intent", "cart", "payment"]
TIER_RANK: dict[str, int] = {"intent": 0, "cart": 1, "payment": 2}

PublicKeyLike = Union[Ed25519PublicKey, bytes]
KeyResolver = Callable[[str], Optional[PublicKeyLike]]
# Revocation hook: ``is_revoked(mandate_id, grantor) -> bool``.
#
# A mandateId is chosen by whoever mints the mandate, so on its own it names
# nothing: anyone can mint a valid mandate of their own that reuses someone
# else's id. The grantor is what the signature binds, so (grantor, mandateId)
# is the identity a shared revocation list must be keyed by. A one-argument
# callable is not accepted: calling it raises, which fails closed.
RevocationCheck = Callable[[str, str], bool]
TimeLike = Union[int, float, datetime]


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SpendingConstraints:
    """Spending envelope. ``None`` means "not set" (the field is absent on the wire).

    ``currency`` defaults to None (absent), which every SDK reads as "USD".
    It used to default to the string "USD" and was always written to the
    wire; now it is written only when set, so a constraint object round-trips
    to the exact bytes a TypeScript issuer signed.
    """
    spend_limit_usd: float
    session_limit_usd: Optional[float]                = None
    currency: Optional[str]                           = None
    merchant_category: Optional[str]                  = None
    require_human_approval_above_usd: Optional[float] = None
    allowed_merchants: Optional[list[str]]            = None
    valid_from: Optional[str]                         = None
    valid_until: Optional[str]                        = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"spendLimitUsd": self.spend_limit_usd}
        for attr, key in _CONSTRAINT_FIELDS[1:]:
            v = getattr(self, attr)
            if v is not None:
                out[key] = list(v) if attr == "allowed_merchants" else v
        return out

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "SpendingConstraints":
        return cls(**{attr: d.get(key) for attr, key in _CONSTRAINT_FIELDS})


_CONSTRAINT_FIELDS: list[tuple[str, str]] = [
    ("spend_limit_usd", "spendLimitUsd"),
    ("session_limit_usd", "sessionLimitUsd"),
    ("currency", "currency"),
    ("merchant_category", "merchantCategory"),
    ("require_human_approval_above_usd", "requireHumanApprovalAboveUsd"),
    ("allowed_merchants", "allowedMerchants"),
    ("valid_from", "validFrom"),
    ("valid_until", "validUntil"),
]


def _new_id() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return iso_ms(datetime.now(timezone.utc))


@dataclass
class SpendingMandate:
    mandate_tier: MandateTier
    constraints: SpendingConstraints
    grantee: str                     # DID of recipient agent
    grantor: str                     # DID of issuing agent
    expires_at: str                  # ISO 8601
    parent_mandate_id: Optional[str]
    mandate_id: str = field(default_factory=_new_id)
    issued_at: Optional[str] = field(default_factory=_now_iso)  # None only on legacy Python v1 tokens

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "mandateTier": self.mandate_tier,
            "constraints": self.constraints.to_wire(),
            "grantee": self.grantee,
            "grantor": self.grantor,
        }
        if self.issued_at is not None:
            out["issuedAt"] = self.issued_at
        out["expiresAt"] = self.expires_at
        out["parentMandateId"] = self.parent_mandate_id
        out["mandateId"] = self.mandate_id
        return out

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "SpendingMandate":
        return cls(
            mandate_tier=d["mandateTier"],
            constraints=SpendingConstraints.from_wire(d["constraints"]),
            grantee=d["grantee"],
            grantor=d["grantor"],
            expires_at=d["expiresAt"],
            parent_mandate_id=d.get("parentMandateId"),
            mandate_id=d["mandateId"],
            issued_at=d.get("issuedAt"),
        )


@dataclass
class MandateChainLink:
    """One signed link of a chain as carried inside a v2 token. ``mandate`` is the wire body (camelCase)."""
    v: int
    mandate: dict[str, Any]
    signature: str

    def to_wire(self) -> dict[str, Any]:
        return {"v": self.v, "mandate": self.mandate, "signature": self.signature}


@dataclass
class SignedMandate:
    mandate: SpendingMandate
    signature: str                         # base64url Ed25519 signature
    token: str                             # base64url serialised token
    v: int = MANDATE_TOKEN_VERSION
    chain: Optional[list[MandateChainLink]] = None  # signed ancestry, root first, excluding this mandate
    wire: Optional[dict[str, Any]] = None   # the exact body that was signed
    legacy_python: bool = False             # decoded from an old snake_case Python token


@dataclass
class MandateVerificationResult:
    valid: bool
    mandate: Optional[SpendingMandate] = None
    reason: Optional[str] = None
    # True only when every link from a root intent mandate down to this one
    # verified. False for a legacy v1 child, which proves only that its
    # immediate grantor signed it — NOT that a human authorised the spend.
    chain_verified: bool = False
    chain: Optional[list[SpendingMandate]] = None   # root first, including the leaf
    root_grantor: Optional[str] = None

    def __iter__(self) -> Iterator[Any]:
        """Backward compatibility: ``valid, mandate, reason = verify_mandate(...)``."""
        return iter((self.valid, self.mandate, self.reason))

    def __bool__(self) -> bool:
        return self.valid


class SpendingConstraintViolation(Exception):
    """Raised by enforce_spending_constraints. ``code`` matches the TypeScript codes."""

    def __init__(
        self,
        message: str,
        code: Literal[
            "MANDATE_INVALID", "LIMIT_EXCEEDED", "MERCHANT_NOT_ALLOWED", "INVALID_AMOUNT", "REDEMPTION_LIMIT_EXCEEDED"
        ],
    ) -> None:
        super().__init__(message)
        self.code = code


# ── Key resolution ────────────────────────────────────────────────────────────

def _key_bytes(key: Any) -> Optional[bytes]:
    if key is None:
        return None
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return bytes(key)


def resolve_content_addressed_key(did: str) -> Optional[bytes]:
    """Key for a content-addressed ``did:aroha:z<base58btc(pubkey)>`` DID; None for any other form.

    The round-trip check keeps a named DID that merely starts with "z"
    (``did:aroha:zoo``) from decoding to a garbage key.
    """
    if not isinstance(did, str) or not did.startswith("did:aroha:z"):
        return None
    try:
        key = from_multibase(did[len("did:aroha:"):])
    except Exception:
        return None
    if len(key) != 32:
        return None
    return key if "did:aroha:" + to_multibase(key) == did else None


def create_mandate_key_resolver(
    *,
    kel_source: Optional[KelSource] = None,
    kel_store: Optional[KelStore] = None,
    fallback: Optional[KeyResolver] = None,
) -> Callable[[str], Optional[bytes]]:
    """Resolver covering all ``did:aroha:`` forms: ``E…`` via verified KEL, ``z…`` derived, else ``fallback``.

    Self-certifying forms never fall through to ``fallback`` (a registry must
    not be able to answer for a DID that carries its own proof).
    """
    kel = kel_key_resolver(kel_source, store=kel_store) if kel_source is not None else None

    def resolve(did: str) -> Optional[bytes]:
        if is_inception_did(did):
            return kel(did) if kel else None
        derived = resolve_content_addressed_key(did)
        if derived is not None:
            return derived
        return _key_bytes(fallback(did)) if fallback is not None else None

    return resolve


# ── Issue ─────────────────────────────────────────────────────────────────────

def issue_intent_mandate(
    grantor_did: str,
    grantee_did: str,
    constraints: SpendingConstraints,
    private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: int = 3600,
) -> SignedMandate:
    """Issue a root Intent Mandate (v2) from a user to their personal agent."""
    return _issue_mandate(
        "intent", grantor_did, grantee_did, constraints, None, private_key, now_ms() + int(ttl_seconds * 1000), []
    )


def attenuate_to_cart(
    parent: SignedMandate,
    grantee_did: str,
    narrowed: SpendingConstraints,
    grantor_private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: Optional[int] = None,
) -> SignedMandate:
    """Attenuate to a Cart Mandate. Inherits omitted limits, then rejects any widening (ValueError)."""
    return _attenuate("cart", parent, grantee_did, narrowed, grantor_private_key, ttl_seconds)


def attenuate_to_payment(
    parent: SignedMandate,
    grantee_did: str,
    narrowed: SpendingConstraints,
    grantor_private_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: Optional[int] = None,
) -> SignedMandate:
    """Attenuate to a single-transaction Payment Mandate. Same rules as attenuate_to_cart."""
    return _attenuate("payment", parent, grantee_did, narrowed, grantor_private_key, ttl_seconds)


def decode_mandate_token(token: str) -> SignedMandate:
    """Decode a token into a SignedMandate WITHOUT verifying it (use verify_mandate_chain for that)."""
    parsed = _parse_mandate_token(token)
    if isinstance(parsed, str):
        raise ValueError(parsed)
    leaf, ancestors = parsed
    return SignedMandate(
        mandate=SpendingMandate.from_wire(leaf.wire),
        signature=leaf.signature,
        token=token,
        v=leaf.v,
        chain=[MandateChainLink(a.v, a.wire, a.signature) for a in ancestors] if leaf.v == 2 else None,
        wire=leaf.wire,
        legacy_python=leaf.legacy_python,
    )


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_mandate(
    token: str,
    public_key: PublicKeyLike,
    expected_grantee: Optional[str] = None,
    *,
    resolve_key: Optional[KeyResolver] = None,
    is_revoked: Optional[RevocationCheck] = None,
    now: Optional[TimeLike] = None,
    clock_tolerance_ms: int = DEFAULT_CLOCK_TOLERANCE_MS,
    expected_root: Optional[str] = None,
    key_rotated_at: Optional[TimeLike] = None,
) -> MandateVerificationResult:
    """Verify a token against ONE caller-supplied key (the LEAF grantor's).

    For a v2 token the embedded chain is verified too (ancestor keys from
    ``resolve_key``, default: content-addressed DIDs) and ``chain_verified``
    is True. For a legacy v1 child there is no ancestry: the result is valid
    with ``chain_verified=False``. Gate money on ``verify_mandate_chain`` (or
    on ``chain_verified`` plus ``expected_root``), not on ``valid`` alone.

    The result unpacks as ``valid, mandate, reason`` for backward compatibility.
    """
    parsed = _parse_mandate_token(token)
    if isinstance(parsed, str):
        return MandateVerificationResult(False, reason=parsed)
    leaf, ancestors = parsed
    m = leaf.wire
    now_v = _now_value(now)

    problem = _check_time_window(m, now_v, clock_tolerance_ms)
    if problem:
        return MandateVerificationResult(False, reason=problem)

    if expected_grantee and m["grantee"] != expected_grantee:
        return MandateVerificationResult(False, reason=f"Mandate grantee mismatch: expected {expected_grantee}")

    if key_rotated_at is not None:
        issued = parse_iso_ms(m.get("issuedAt")) if m.get("issuedAt") else 0
        if issued is None or issued <= _now_value(key_rotated_at):
            return MandateVerificationResult(False, reason="Mandate was signed with a since-rotated key")

    leaf_key = _key_bytes(public_key)
    sig_problem = _check_link_signature(leaf, leaf_key)
    if sig_problem:
        return MandateVerificationResult(False, reason=sig_problem)

    rev_problem = _check_revocation(m, is_revoked)
    if rev_problem:
        return MandateVerificationResult(False, reason=rev_problem)

    mandate = SpendingMandate.from_wire(m)
    if leaf.v == 1:
        is_root = m["parentMandateId"] is None
        if expected_root is not None:
            if not is_root:
                return MandateVerificationResult(
                    False, reason="Legacy v1 token carries no ancestry; cannot prove the expected root"
                )
            if m["grantor"] != expected_root:
                return MandateVerificationResult(
                    False, reason=f"Chain root mismatch: expected {expected_root}, got {m['grantor']}"
                )
        if is_root and m["mandateTier"] != "intent":
            return MandateVerificationResult(
                False, reason=f"A root mandate must be an intent mandate, got {m['mandateTier']}"
            )
        if is_root:
            return MandateVerificationResult(True, mandate, None, True, [mandate], m["grantor"])
        return MandateVerificationResult(True, mandate, None, False)

    # The caller's key verifies the LEAF LINK ONLY — by position, never by DID.
    # Matching on DID handed it to any ancestor naming the same grantor, so a
    # forged root signed by the leaf key verified as the real root (see the
    # TS fix in @aroha-sdk/credentials).
    ancestor_resolver = resolve_key or resolve_content_addressed_key

    # A self-certifying leaf grantor carries its own key; a caller key that
    # disagrees with it is refused rather than trusted.
    try:
        derived = resolve_content_addressed_key(m["grantor"])
    except Exception:
        derived = None
    if derived is not None and _key_bytes(derived) != leaf_key:
        return MandateVerificationResult(
            False, reason="Supplied key does not match the key derived from the grantor DID"
        )

    return _verify_links(
        [*ancestors, leaf], ancestor_resolver,
        now=now_v, tolerance=clock_tolerance_ms, expected_root=expected_root, is_revoked=is_revoked,
        expected_grantee=expected_grantee, leaf_key=leaf_key,
    )


def verify_mandate_chain(
    token: str,
    resolve_key: Optional[KeyResolver] = None,
    expected_root: Optional[str] = None,
    is_revoked: Optional[RevocationCheck] = None,
    now: Optional[TimeLike] = None,
    clock_tolerance_ms: int = DEFAULT_CLOCK_TOLERANCE_MS,
    *,
    expected_grantee: Optional[str] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    kel_source: Optional[KelSource] = None,
    kel_store: Optional[KelStore] = None,
    require_person_root: bool = False,
    expected_root_person: Optional[str] = None,
) -> MandateVerificationResult:
    """Verify a token all the way back to its human root. Run this before moving money.

    For every link, root first: signature against ``resolve_key(grantor)``
    (default: content-addressed DIDs); root has no parent, is an intent and
    (if given) its grantor is ``expected_root``; each child's grantor is the
    parent's grantee, ``parentMandateId`` is the parent's id, tier is not
    broader, constraints narrow the parent's (``check_narrowing``), and it
    does not outlive the parent; time windows; ``is_revoked(mandate_id,
    grantor)`` (fails closed if it raises). A legacy v1 token is accepted only if it is itself a root.

    ``now`` is Unix ms or a datetime. ``clock_tolerance_ms`` applies to
    not-before checks only (issuedAt, validFrom), never to expiry.

    With ``kel_source``, every ``did:aroha:E…`` grantor/grantee is resolved
    through its verified KEL (current key; revoked identity or controller
    fails the link). ``require_person_root`` / ``expected_root_person``
    require the root grantor to be a person E-DID.
    """
    parsed = _parse_mandate_token(token)
    if isinstance(parsed, str):
        return MandateVerificationResult(False, reason=parsed)
    leaf, ancestors = parsed
    if leaf.v == 1 and leaf.wire["parentMandateId"] is not None:
        return MandateVerificationResult(
            False, reason="Legacy v1 token carries no ancestry; it cannot be verified back to a root"
        )
    return _verify_links(
        [*ancestors, leaf], resolve_key or resolve_content_addressed_key,
        now=_now_value(now), tolerance=clock_tolerance_ms, expected_root=expected_root, is_revoked=is_revoked,
        expected_grantee=expected_grantee, max_depth=max_depth, kel_source=kel_source, kel_store=kel_store,
        require_person_root=require_person_root, expected_root_person=expected_root_person,
    )


def enforce_spending_constraints(
    token: str,
    grantor_public_key: PublicKeyLike,
    *,
    proposed_amount_usd: float,
    expected_grantee: Optional[str] = None,
    merchant_did: Optional[str] = None,
    key_rotated_at: Optional[TimeLike] = None,
    resolve_key: Optional[KeyResolver] = None,
    is_revoked: Optional[RevocationCheck] = None,
    clock_tolerance_ms: int = DEFAULT_CLOCK_TOLERANCE_MS,
    now: Optional[TimeLike] = None,
    expected_root: Optional[str] = None,
    require_chain: bool = False,
) -> SpendingMandate:
    """Verify a token AND assert the proposed spend is within it. Raises SpendingConstraintViolation.

    Set ``require_chain=True`` at any gate that moves real money. This SDK has
    no redemption store: pair it with your own once-only redemption record.
    """
    result = verify_mandate(
        token, grantor_public_key, expected_grantee,
        resolve_key=resolve_key, is_revoked=is_revoked, now=now, clock_tolerance_ms=clock_tolerance_ms,
        expected_root=expected_root, key_rotated_at=key_rotated_at,
    )
    if not result.valid:
        raise SpendingConstraintViolation(f"Mandate invalid: {result.reason}", "MANDATE_INVALID")
    if require_chain and not result.chain_verified:
        raise SpendingConstraintViolation(
            "Mandate invalid: token does not carry a chain verifiable back to a root mandate", "MANDATE_INVALID"
        )
    assert result.mandate is not None
    c = result.mandate.constraints
    if not _is_amount(proposed_amount_usd):
        raise SpendingConstraintViolation(
            f"Proposed amount {proposed_amount_usd} is not a finite, non-negative number", "INVALID_AMOUNT"
        )
    if proposed_amount_usd > c.spend_limit_usd:
        raise SpendingConstraintViolation(
            f"Proposed ${_fmt(proposed_amount_usd)} exceeds mandate limit ${_fmt(c.spend_limit_usd)}", "LIMIT_EXCEEDED"
        )
    merchant_problem = check_spend_merchant(c, merchant_did)
    if merchant_problem is not None:
        raise SpendingConstraintViolation(merchant_problem, "MERCHANT_NOT_ALLOWED")
    return result.mandate


# ── Per-spend checks (shared by every spending gate) ──────────────────────────
#
# Port of the TypeScript helpers of the same names (mandate.ts). One
# definition of what a single spend must satisfy against one mandate's
# constraints. Pure: no signature or chain checks (run verify_mandate_chain
# first) and no running totals (that is the ledger's job).

_SPEND_MICROS_PER_USD = 1_000_000
_MAX_SAFE_INTEGER = 2**53 - 1


def mandate_redemption_key(mandate: Union[SpendingMandate, dict[str, Any]]) -> str:
    """``<grantor>#<mandateId>`` — the key a running total is kept under.

    Never the bare mandateId: the id is chosen by whoever mints the mandate,
    so a stranger can mint a mandate reusing yours. The grantor is fixed by
    the signature.
    """
    if isinstance(mandate, SpendingMandate):
        return f"{mandate.grantor}#{mandate.mandate_id}"
    return f"{mandate['grantor']}#{mandate['mandateId']}"


def mandate_cumulative_limit_usd(c: SpendingConstraints) -> float:
    """min(spend_limit_usd, session_limit_usd): the cap on everything spent under a mandate."""
    return c.spend_limit_usd if c.session_limit_usd is None else min(c.spend_limit_usd, c.session_limit_usd)


def spend_amount_micros(amount_usd: float) -> int:
    """USD to integer micro-USD, rounding half up like JavaScript's Math.round."""
    return math.floor(amount_usd * _SPEND_MICROS_PER_USD + 0.5)


def check_spend_amount(amount_usd: Any) -> Optional[str]:
    """Why ``amount_usd`` cannot be spent, or None: finite, > 0, at least 1 micro-USD, exactly representable."""
    if isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float)) \
            or not math.isfinite(amount_usd) or amount_usd <= 0:
        return f"Amount {amount_usd!r} must be a finite number greater than 0"
    micros = spend_amount_micros(amount_usd)
    if micros < 1:
        return f"Amount {amount_usd!r} is below the smallest unit (1 micro-USD)"
    if micros > _MAX_SAFE_INTEGER:
        return f"Amount {amount_usd!r} is too large to account for exactly"
    return None


def check_spend_merchant(c: SpendingConstraints, merchant: Optional[str]) -> Optional[str]:
    """Why paying ``merchant`` is outside ``allowed_merchants``, or None. A missing merchant refuses."""
    if c.allowed_merchants is None:
        return None
    if merchant is None:
        return "merchantDID is required when the mandate restricts allowedMerchants"
    if merchant not in c.allowed_merchants:
        return f"Merchant {merchant} is not in the mandate's allowed merchant list"
    return None


def check_spend_against_constraints(
    c: SpendingConstraints,
    *,
    amount_usd: float,
    currency: Optional[str] = None,
    merchant: Optional[str] = None,
    merchant_category: Optional[str] = None,
    human_approved: Optional[bool] = None,
) -> Optional[tuple[str, str]]:
    """Check one spend against ONE mandate's constraints; ``(code, reason)`` or None.

    Order (same as TypeScript): currency (default "USD" on both sides),
    allowed_merchants, merchant_category, require_human_approval_above_usd,
    then the amount against mandate_cumulative_limit_usd. A constraint whose
    input is missing refuses (fail closed). Codes: CURRENCY_MISMATCH,
    MERCHANT_NOT_ALLOWED, MERCHANT_CATEGORY_NOT_ALLOWED,
    HUMAN_APPROVAL_REQUIRED, OVER_LIMIT.
    """
    want = c.currency if c.currency is not None else "USD"
    got = currency if currency is not None else "USD"
    if got != want:
        return "CURRENCY_MISMATCH", f"Spend is in {got}; the mandate is in {want}"
    merchant_problem = check_spend_merchant(c, merchant)
    if merchant_problem is not None:
        return "MERCHANT_NOT_ALLOWED", merchant_problem
    if c.merchant_category is not None:
        if merchant_category is None:
            return "MERCHANT_CATEGORY_NOT_ALLOWED", "merchantCategory is required when the mandate restricts merchantCategory"
        if merchant_category != c.merchant_category:
            return ("MERCHANT_CATEGORY_NOT_ALLOWED",
                    f"Merchant category {merchant_category} is not the mandate's {c.merchant_category}")
    if c.require_human_approval_above_usd is not None and amount_usd > c.require_human_approval_above_usd \
            and human_approved is not True:
        return ("HUMAN_APPROVAL_REQUIRED",
                f"${_fmt(amount_usd)} is above the mandate's human-approval threshold of "
                f"${_fmt(c.require_human_approval_above_usd)}")
    limit = mandate_cumulative_limit_usd(c)
    if spend_amount_micros(amount_usd) > spend_amount_micros(limit):
        return "OVER_LIMIT", f"${_fmt(amount_usd)} exceeds the mandate's limit of ${_fmt(limit)}"
    return None


# ── Canonicalisation & signing ────────────────────────────────────────────────

def mandate_signing_payload_v2(mandate: Union[dict[str, Any], SpendingMandate]) -> str:
    """The exact string a v2 signature covers: RFC 8785 JCS of ``{"mandate": <body>, "v": 2}``."""
    body = mandate.to_wire() if isinstance(mandate, SpendingMandate) else mandate
    return canonicalize_jcs({"mandate": body, "v": 2})


@dataclass
class _Link:
    v: int
    wire: dict[str, Any]          # camelCase body (normalised for legacy Python tokens)
    signature: str
    raw: dict[str, Any]           # the body exactly as it appeared in the token
    legacy_python: bool = False


def _signing_bytes(link: _Link) -> bytes:
    if link.v == 2:
        return mandate_signing_payload_v2(link.wire).encode("utf-8")
    if link.legacy_python:
        # Old Python issuer: json.dumps over the key-sorted snake_case body.
        return json.dumps(_sort_keys(link.raw), separators=(",", ":")).encode("utf-8")
    # TypeScript v1: JSON.stringify(sortKeys(body)).
    return js_stringify_sorted(link.wire).encode("utf-8")


def _sort_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys(i) for i in obj]
    return obj


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _check_link_signature(link: _Link, public_key: Optional[bytes]) -> Optional[str]:
    try:
        sig = _unb64url(link.signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, _signing_bytes(link))  # type: ignore[arg-type]
        return None
    except InvalidSignature:
        return "Invalid signature"
    except Exception:
        return "Signature verification error"


def _check_revocation(m: dict[str, Any], is_revoked: Optional[RevocationCheck]) -> Optional[str]:
    if is_revoked is None:
        return None
    try:
        return f"Mandate {m['mandateId']} has been revoked" if is_revoked(m["mandateId"], m["grantor"]) else None
    except Exception:
        # A revocation service we cannot reach is not evidence of non-revocation.
        return f"Revocation check failed for mandate {m['mandateId']}"


def _lt(a: Optional[int], b: Optional[int]) -> bool:
    """``a < b`` with JavaScript NaN semantics (None compares false)."""
    return a is not None and b is not None and a < b


def _check_time_window(m: dict[str, Any], now: int, tolerance: int) -> Optional[str]:
    """Expiry checks are strict; not-before checks get ``tolerance`` ms of slack."""
    if _lt(parse_iso_ms(m.get("expiresAt")), now):
        return "Mandate expired"
    if _lt(now + tolerance, parse_iso_ms(m.get("issuedAt"))):
        return f"Mandate issuedAt {m.get('issuedAt')} is in the future"
    c = m["constraints"]
    if "validFrom" in c and _lt(now + tolerance, parse_iso_ms(c["validFrom"])):
        return f"Mandate not yet valid (validFrom {c['validFrom']})"
    if "validUntil" in c and _lt(parse_iso_ms(c["validUntil"]), now):
        return f"Mandate validity window has ended (validUntil {c['validUntil']})"
    return None


def _now_value(t: Optional[TimeLike]) -> int:
    if t is None:
        return now_ms()
    if isinstance(t, datetime):
        return to_ms(t)
    return int(t)


def _verify_links(
    links: list[_Link],
    resolve_key: KeyResolver,
    *,
    now: int,
    tolerance: int,
    expected_root: Optional[str],
    is_revoked: Optional[RevocationCheck],
    expected_grantee: Optional[str] = None,
    leaf_key: Optional[bytes] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    kel_source: Optional[KelSource] = None,
    kel_store: Optional[KelStore] = None,
    require_person_root: bool = False,
    expected_root_person: Optional[str] = None,
) -> MandateVerificationResult:
    if not links:
        return MandateVerificationResult(False, reason="Empty mandate chain")
    if len(links) > max_depth:
        return MandateVerificationResult(
            False, reason=f"Mandate chain has {len(links)} links; maximum is {max_depth}"
        )
    require_person = require_person_root or expected_root_person is not None
    if require_person and kel_source is None:
        return MandateVerificationResult(
            False, reason="requirePersonRoot needs a kelSource to verify the root person's KEL"
        )
    kel_state_of = _kel_lookup(kel_source, kel_store) if kel_source is not None else None

    seen: set[str] = set()
    for i, link in enumerate(links):
        m = link.wire
        where = f"chain link {i} ({m['mandateTier']} {m['mandateId']})"

        def fail(reason: str) -> MandateVerificationResult:
            return MandateVerificationResult(False, reason=f"{where}: {reason}")

        if m["mandateId"] in seen:
            return fail("mandateId repeats within the chain")
        seen.add(m["mandateId"])

        grantor_kel: Optional[KelState] = None
        if kel_state_of is not None and is_inception_did(m["grantor"]):
            state, err = kel_state_of(m["grantor"])
            if err:
                return fail(f"grantor {m['grantor']}: {err}")
            grantor_kel = state
            key = state.current_key  # type: ignore[union-attr]
        elif leaf_key is not None and i == len(links) - 1:
            key = leaf_key
        else:
            try:
                key = _key_bytes(resolve_key(m["grantor"]))
            except Exception:
                return fail(f"Key resolution failed for grantor {m['grantor']}")
        if not key:
            return fail(f"Cannot resolve public key for grantor {m['grantor']}")
        sig_problem = _check_link_signature(link, key)
        if sig_problem:
            return fail(sig_problem)

        if kel_state_of is not None and is_inception_did(m["grantee"]):
            _, err = kel_state_of(m["grantee"])
            if err:
                return fail(f"grantee {m['grantee']}: {err}")

        if i == 0:
            if m["parentMandateId"] is not None:
                return fail(
                    "first link has a parentMandateId — the token does not carry its full ancestry back to a root"
                )
            if m["mandateTier"] != "intent":
                return fail(f"a root mandate must be an intent mandate, got {m['mandateTier']}")
            if expected_root is not None and m["grantor"] != expected_root:
                return fail(f"Chain root mismatch: expected {expected_root}, got {m['grantor']}")
            if require_person:
                if grantor_kel is None:
                    return fail(f"root grantor {m['grantor']} is not a person identity (did:aroha:E…)")
                if grantor_kel.kind != "person":
                    return fail(f"root grantor {m['grantor']} is an {grantor_kel.kind}, not a person")
                if expected_root_person is not None and m["grantor"] != expected_root_person:
                    return fail(f"Chain root mismatch: expected person {expected_root_person}, got {m['grantor']}")
        else:
            p = links[i - 1].wire
            if m["grantor"] != p["grantee"]:
                return fail(f"grantor {m['grantor']} is not the parent's grantee {p['grantee']}")
            if m["parentMandateId"] != p["mandateId"]:
                return fail(
                    f"parentMandateId {m['parentMandateId']} does not match the parent's mandateId {p['mandateId']}"
                )
            if TIER_RANK[m["mandateTier"]] < TIER_RANK[p["mandateTier"]]:
                return fail(f"tier {m['mandateTier']} is broader than the parent's {p['mandateTier']}")
            narrowing = check_narrowing(p["constraints"], m["constraints"], p["mandateTier"], m["mandateTier"])
            if narrowing:
                return fail(narrowing)
            # PSD3 acting-for side (spec §6.5): a declared side is kept on every
            # child; dropping or flipping it would let one chain act for both.
            if p.get("actingFor") is not None and m.get("actingFor") != p["actingFor"]:
                return fail(f"actingFor {m.get('actingFor', 'unset')} does not match the parent's {p['actingFor']}")
            if _lt(parse_iso_ms(p["expiresAt"]), parse_iso_ms(m["expiresAt"])):
                return fail(f"expiresAt {m['expiresAt']} outlives the parent's {p['expiresAt']}")

        time_problem = _check_time_window(m, now, tolerance)
        if time_problem:
            return fail(time_problem)

        rev_problem = _check_revocation(m, is_revoked)
        if rev_problem:
            return fail(rev_problem)

    leaf = links[-1].wire
    if expected_grantee and leaf["grantee"] != expected_grantee:
        return MandateVerificationResult(False, reason=f"Mandate grantee mismatch: expected {expected_grantee}")

    chain = [SpendingMandate.from_wire(l.wire) for l in links]
    return MandateVerificationResult(True, chain[-1], None, True, chain, links[0].wire["grantor"])


def _kel_lookup(
    source: KelSource, store: Optional[KelStore]
) -> Callable[[str], tuple[Optional[KelState], Optional[str]]]:
    cache: dict[str, tuple[Optional[KelState], Optional[str]]] = {}

    def lookup(did: str) -> tuple[Optional[KelState], Optional[str]]:
        if did in cache:
            return cache[did]
        try:
            state = resolve_kel_state(did, source, store=store, require_controller=True)
            if state is None:
                r: tuple[Optional[KelState], Optional[str]] = (None, "no Key Event Log available")
            elif state.revoked:
                r = (None, "identity has been revoked")
            elif state.controller_revoked:
                r = (None, f"controller {state.controller} has been revoked")
            else:
                r = (state, None)
        except Exception as e:
            r = (None, f"Key Event Log rejected: {e}")
        cache[did] = r
        return r

    return lookup


# ── Token parsing & shape validation ──────────────────────────────────────────

def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def _parse_mandate_token(token: str) -> Union[tuple[_Link, list[_Link]], str]:
    try:
        raw = json.loads(_unb64url(token).decode("utf-8"), parse_constant=_reject_constant)
    except Exception:
        return "Malformed token"
    if not isinstance(raw, dict):
        return "Malformed token"

    v = raw.get("v", 1) if "v" in raw else 1
    if isinstance(v, bool) or v not in (1, 2):
        return f"Unsupported mandate token version: {raw.get('v')}"
    v = int(v)
    if v == 1 and "chain" in raw:
        return "Malformed token: chain present without v: 2"

    leaf = _to_link(v, raw, allow_legacy_python=(v == 1))
    if isinstance(leaf, str):
        return f"Malformed token: {leaf}"

    ancestors: list[_Link] = []
    if v == 2:
        chain = raw.get("chain")
        if not isinstance(chain, list):
            return "Malformed token: v2 token requires a chain array"
        for i, entry in enumerate(chain):
            ev = entry.get("v") if isinstance(entry, dict) else None
            if not isinstance(entry, dict) or isinstance(ev, bool) or ev not in (1, 2):
                return f"Malformed token: chain[{i}] is not a versioned link"
            link = _to_link(int(ev), entry, allow_legacy_python=False)
            if isinstance(link, str):
                return f"Malformed token: chain[{i}]: {link}"
            ancestors.append(link)
    return leaf, ancestors


_LEGACY_TOP = {
    "mandate_tier": "mandateTier",
    "grantee": "grantee",
    "grantor": "grantor",
    "expires_at": "expiresAt",
    "parent_mandate_id": "parentMandateId",
    "mandate_id": "mandateId",
}
_LEGACY_CONSTRAINTS = {
    "spend_limit_usd": "spendLimitUsd",
    "session_limit_usd": "sessionLimitUsd",
    "currency": "currency",
    "merchant_category": "merchantCategory",
    "require_human_approval_above_usd": "requireHumanApprovalAboveUsd",
    "allowed_merchants": "allowedMerchants",
    "valid_from": "validFrom",
    "valid_until": "validUntil",
}


def _normalise_legacy_python(m: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in m.items():
        if k == "constraints" and isinstance(v, dict):
            out["constraints"] = {_LEGACY_CONSTRAINTS.get(ck, ck): cv for ck, cv in v.items()}
        else:
            out[_LEGACY_TOP.get(k, k)] = v
    return out


def _to_link(v: int, raw: dict[str, Any], *, allow_legacy_python: bool) -> Union[_Link, str]:
    if not isinstance(raw.get("signature"), str):
        return "signature missing"
    body = raw.get("mandate")
    legacy_python = allow_legacy_python and isinstance(body, dict) and "mandate_tier" in body
    wire = _normalise_legacy_python(body) if legacy_python else body
    # Old Python tokens never had issuedAt; every other form must.
    shape = check_mandate_shape(wire, require_issued_at=not legacy_python)
    if shape:
        return shape
    return _Link(v, wire, raw["signature"], body, legacy_python)


def _is_iso_date(x: Any) -> bool:
    return isinstance(x, str) and parse_iso_ms(x) is not None


def _is_amount(x: Any) -> bool:
    return (
        isinstance(x, (int, float)) and not isinstance(x, bool) and not (isinstance(x, float) and not math.isfinite(x))
        and x >= 0
    )


def check_mandate_shape(m: Any, *, require_issued_at: bool = True) -> Optional[str]:
    """Structural validation of a decoded (camelCase) mandate body. Returns the problem, or None.

    Same rules and messages as checkMandateShape in mandate.ts.
    """
    if not isinstance(m, dict):
        return "mandate is not an object"
    # A task mandate is not a spending mandate (tiers overlap, and a v1 task
    # signature covers the same sorted-JSON bytes): refuse the type marker.
    if "mandateType" in m:
        return "mandateType present: this is a task mandate, not a spending mandate"
    if m.get("mandateTier") not in ("intent", "cart", "payment"):
        return "mandateTier is invalid"
    for f in ("grantor", "grantee", "mandateId"):
        if not isinstance(m.get(f), str) or len(m[f]) == 0:
            return f"{f} is missing"
    if (require_issued_at or "issuedAt" in m) and not _is_iso_date(m.get("issuedAt")):
        return "issuedAt is not a date"
    if not _is_iso_date(m.get("expiresAt")):
        return "expiresAt is not a date"
    if "parentMandateId" not in m:
        return "parentMandateId is invalid"  # undefined is neither null nor a string
    if m["parentMandateId"] is not None and not isinstance(m["parentMandateId"], str):
        return "parentMandateId is invalid"
    if "actingFor" in m and m["actingFor"] not in ("payer", "payee"):
        return "actingFor is invalid"
    return _check_constraints_shape(m.get("constraints"))


def _check_constraints_shape(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "constraints is not an object"
    if not _is_amount(c.get("spendLimitUsd")):
        return "constraints.spendLimitUsd must be a finite, non-negative number"
    for f in ("sessionLimitUsd", "requireHumanApprovalAboveUsd"):
        if f in c and not _is_amount(c[f]):
            return f"constraints.{f} must be a finite, non-negative number"
    if "currency" in c and not isinstance(c["currency"], str):
        return "constraints.currency must be a string"
    if c.get("merchantCategory") is not None and not isinstance(c["merchantCategory"], str):
        return "constraints.merchantCategory must be a string or null"
    am = c.get("allowedMerchants")
    if am is not None and (not isinstance(am, list) or not all(isinstance(x, str) for x in am)):
        return "constraints.allowedMerchants must be an array of DIDs or null"
    for f in ("validFrom", "validUntil"):
        if f in c and not _is_iso_date(c[f]):
            return f"constraints.{f} must be an ISO 8601 date"
    return None


# ── Narrowing ─────────────────────────────────────────────────────────────────

def _fmt(x: Any) -> str:
    try:
        return format_es_number(x)
    except Exception:
        return str(x)


def _as_wire_constraints(c: Union[dict[str, Any], SpendingConstraints]) -> dict[str, Any]:
    return c.to_wire() if isinstance(c, SpendingConstraints) else c


def check_narrowing(
    parent: Union[dict[str, Any], SpendingConstraints],
    child: Union[dict[str, Any], SpendingConstraints],
    parent_tier: str,
    child_tier: str,
) -> Optional[str]:
    """None if ``child`` is a subset of ``parent``, else the reason. Identical to checkNarrowing in mandate.ts.

    Rule for every optional field: if the PARENT sets it, the child must set
    it too, to an equal or narrower value. Accepts wire dicts or
    SpendingConstraints. This is the verifier-side security check.
    """
    p = _as_wire_constraints(parent)
    c = _as_wire_constraints(child)
    prefix = f"Cannot attenuate {parent_tier} → {child_tier}"

    if not _is_amount(c.get("spendLimitUsd")):
        return f"{prefix}: child spendLimitUsd must be a finite, non-negative number"
    if _is_amount(p.get("spendLimitUsd")) and c["spendLimitUsd"] > p["spendLimitUsd"]:
        return (
            f"{prefix}: child spendLimitUsd ({_fmt(c['spendLimitUsd'])}) exceeds parent ({_fmt(p['spendLimitUsd'])})"
        )

    if "sessionLimitUsd" in p:
        if "sessionLimitUsd" not in c:
            return f"{prefix}: parent sets sessionLimitUsd ({_fmt(p['sessionLimitUsd'])}) but child omits it"
        if not _is_amount(c["sessionLimitUsd"]) or (
            _is_amount(p["sessionLimitUsd"]) and c["sessionLimitUsd"] > p["sessionLimitUsd"]
        ):
            return f"{prefix}: child sessionLimitUsd exceeds parent"

    if "requireHumanApprovalAboveUsd" in p:
        if "requireHumanApprovalAboveUsd" not in c:
            return (
                f"{prefix}: parent sets an approval threshold (requireHumanApprovalAboveUsd "
                f"{_fmt(p['requireHumanApprovalAboveUsd'])}) but child omits it"
            )
        if not _is_amount(c["requireHumanApprovalAboveUsd"]) or (
            _is_amount(p["requireHumanApprovalAboveUsd"])
            and c["requireHumanApprovalAboveUsd"] > p["requireHumanApprovalAboveUsd"]
        ):
            return f"{prefix}: child approval threshold exceeds parent"

    c_cur = c.get("currency") if c.get("currency") is not None else "USD"
    p_cur = p.get("currency") if p.get("currency") is not None else "USD"
    if c_cur != p_cur:
        return f'{prefix}: child currency "{c_cur}" differs from parent "{p_cur}"'

    if p.get("allowedMerchants") is not None:
        cm = c.get("allowedMerchants")
        if cm is None:
            return f"{prefix}: parent restricts allowedMerchants but child sets none"
        if len(p["allowedMerchants"]) > 0 and len(cm) == 0:
            return f"{prefix}: parent restricts allowedMerchants but child sets none"
        parent_set = set(p["allowedMerchants"])
        for mer in cm:
            if mer not in parent_set:
                return f'{prefix}: child allowedMerchants contains "{mer}" not in parent'

    if p.get("merchantCategory") is not None:
        if c.get("merchantCategory") is None:
            return f"{prefix}: child merchantCategory must not widen parent's \"{p['merchantCategory']}\" restriction"
        if c["merchantCategory"] != p["merchantCategory"]:
            return (
                f'{prefix}: child merchantCategory "{c["merchantCategory"]}" does not match parent '
                f'"{p["merchantCategory"]}"'
            )

    if "validUntil" in p:
        if "validUntil" not in c:
            return f"{prefix}: parent sets validUntil ({p['validUntil']}) but child omits it"
        cu = parse_iso_ms(c["validUntil"])
        if cu is None or _lt(parse_iso_ms(p["validUntil"]), cu):
            return f"{prefix}: child validUntil ({c['validUntil']}) extends beyond parent ({p['validUntil']})"

    if "validFrom" in p:
        if "validFrom" not in c:
            return f"{prefix}: parent sets validFrom ({p['validFrom']}) but child omits it"
        cf = parse_iso_ms(c["validFrom"])
        if cf is None or _lt(cf, parse_iso_ms(p["validFrom"])):
            return f"{prefix}: child validFrom ({c['validFrom']}) precedes parent ({p['validFrom']})"

    return None


# Fields a child inherits from its parent when the caller omits them.
# merchant_category and allowed_merchants are NOT inherited: a merchant
# restriction must be restated explicitly (same as TypeScript).
_INHERITED = ("session_limit_usd", "require_human_approval_above_usd", "valid_from", "valid_until", "currency")


def _inherit_omitted(parent: SpendingConstraints, child: SpendingConstraints) -> SpendingConstraints:
    """A child that leaves an inheritable limit out inherits the parent's value. Returns a new object."""
    values = {attr: getattr(child, attr) for attr, _ in _CONSTRAINT_FIELDS}
    for attr in _INHERITED:
        if values[attr] is None and getattr(parent, attr) is not None:
            values[attr] = getattr(parent, attr)
    return SpendingConstraints(**values)


def _assert_narrowing(parent: Any, child: Any, parent_tier: str, child_tier: str) -> None:
    reason = check_narrowing(parent, child, parent_tier, child_tier)
    if reason:
        raise ValueError(reason)


# ── Internals: issuing ────────────────────────────────────────────────────────

def _priv(key: Union[Ed25519PrivateKey, bytes]) -> Ed25519PrivateKey:
    return key if isinstance(key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(bytes(key))


def _issue_mandate(
    tier: MandateTier,
    grantor_did: str,
    grantee_did: str,
    constraints: SpendingConstraints,
    parent_id: Optional[str],
    private_key: Union[Ed25519PrivateKey, bytes],
    expires_at_ms: int,
    chain: list[MandateChainLink],
) -> SignedMandate:
    c_wire = constraints.to_wire()
    shape = _check_constraints_shape(c_wire)
    if shape:
        raise ValueError(f"Invalid spending constraints: {shape}")
    mandate = SpendingMandate(
        mandate_tier=tier,
        constraints=SpendingConstraints.from_wire(c_wire),
        grantee=grantee_did,
        grantor=grantor_did,
        expires_at=iso_ms(expires_at_ms),
        parent_mandate_id=parent_id,
        issued_at=_now_iso(),
    )
    wire = mandate.to_wire()
    sig = _b64url(_priv(private_key).sign(mandate_signing_payload_v2(wire).encode("utf-8")))
    token_obj = {
        "v": MANDATE_TOKEN_VERSION,
        "mandate": wire,
        "signature": sig,
        "chain": [l.to_wire() for l in chain],
    }
    token = _b64url(
        json.dumps(token_obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    )
    return SignedMandate(mandate=mandate, signature=sig, token=token, v=2, chain=list(chain), wire=wire)


def _ancestry_including_parent(parent: SignedMandate) -> list[MandateChainLink]:
    version = parent.v
    ancestors = parent.chain
    wire = parent.wire
    legacy_python = parent.legacy_python
    if (ancestors is None or wire is None) and isinstance(parent.token, str):
        parsed = _parse_mandate_token(parent.token)
        if not isinstance(parsed, str) and parsed[0].wire["mandateId"] == parent.mandate.mandate_id:
            leaf, anc = parsed
            version = leaf.v
            wire = leaf.wire
            legacy_python = leaf.legacy_python
            if ancestors is None and leaf.v == 2:
                ancestors = [MandateChainLink(a.v, a.wire, a.signature) for a in anc]
    if legacy_python:
        raise ValueError(
            "Cannot attenuate a legacy Python (snake_case v1) mandate: no other SDK can verify its signature. "
            "Re-issue the mandate with this SDK version."
        )
    v = 2 if version == 2 else 1
    if ancestors is None or v == 1:
        if parent.mandate.parent_mandate_id is not None:
            raise ValueError(
                "Cannot attenuate a legacy v1 mandate that is not a root: its ancestry was never embedded, "
                "so the child could not be verified back to the human. Re-issue the chain from the root."
            )
        ancestors = []
    return [*ancestors, MandateChainLink(v, wire if wire is not None else parent.mandate.to_wire(), parent.signature)]


def _attenuate(
    tier: Literal["cart", "payment"],
    parent: SignedMandate,
    grantee_did: str,
    narrowed: SpendingConstraints,
    grantor_key: Union[Ed25519PrivateKey, bytes],
    ttl_seconds: Optional[int],
) -> SignedMandate:
    parent_tier = parent.mandate.mandate_tier
    if TIER_RANK[tier] < TIER_RANK[parent_tier]:
        raise ValueError(
            f"Cannot attenuate {parent_tier} → {tier}: a child cannot be a broader tier than its parent"
        )
    constraints = _inherit_omitted(parent.mandate.constraints, narrowed)
    _assert_narrowing(parent.mandate.constraints, constraints, parent_tier, tier)
    chain = _ancestry_including_parent(parent)

    # A child may never outlive its parent; pass the clamped expiry as an
    # absolute instant (no second clock read).
    parent_expiry = parse_iso_ms(parent.mandate.expires_at)
    if parent_expiry is None:
        raise ValueError("Parent mandate has an unparseable expiresAt")
    expiry = min(parent_expiry, now_ms() + int(ttl_seconds * 1000)) if ttl_seconds else parent_expiry

    return _issue_mandate(
        tier, parent.mandate.grantee, grantee_did, constraints, parent.mandate.mandate_id, grantor_key, expiry, chain
    )
