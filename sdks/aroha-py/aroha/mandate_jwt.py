# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""The JWT form of a mandate (spec §6.10): the same mandate, readable by a stock JWT library.

The Python counterpart of ``packages/aroha-credentials/src/mandate-jwt.ts``;
both are checked against ``test-vectors/mandate-jwt-v1.json``.

Each link of a mandate chain is one JSON Web Token::

    header   {"alg": "EdDSA", "typ": "aroha-mandate+jwt", "kid": <key id>}
    claims   {"iss": <grantor>, "sub": <grantee>, "jti": <mandateId>,
              "iat": <issuedAt, seconds>, "exp": <expiresAt, seconds>,
              "authorization_details": [{"type": <the mandate's type URI>,
                                         ...the rest of the mandate body...}]}

``authorization_details`` is the member OAuth Rich Authorization Requests
(RFC 9396) uses to say what a token is good for. A spending chain is its link
JWTs joined by "~", root first; a single link is a plain JWT.

What stays the same: the body a verifier acts on and every rule applied to
it. This module only maps between claims and the body, and signs and checks
the JWS. The chain rules live in ``aroha.mandate`` and run on both forms.

A stock library checks the signature, ``iss`` and ``exp`` of one link. It does
not check that a child narrows its parent or that the chain reaches the root
you trust; use ``verify_mandate_chain`` for that.

Strictness. Only the header members and claims above are allowed. An unknown
claim is refused, not ignored: a claim such as ``nbf`` or ``aud`` that a stock
library enforces and this verifier does not would let the two disagree about
one token. ``typ`` is required and checked (RFC 8725), so a token of another
kind signed by the same key is never read as a mandate. Times are whole
seconds.

A mandate is issued in one form. Its signature covers different bytes in each,
so a token cannot be converted. A spending token holds one form. A task chain
is a list of tokens, and the verifier takes each on its own.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.timeutil import iso_ms, parse_iso_ms

#: Small-order Ed25519 points and their non-canonical spellings. No real key is
#: one, and with such a key a signature can verify for many messages.
_WEAK_KEYS_HEX = frozenset({
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
})

__all__ = [
    "MANDATE_JWT_TYP",
    "SPENDING_MANDATE_DETAIL_TYPE",
    "TASK_MANDATE_DETAIL_TYPE",
    "MANDATE_JWT_SEPARATOR",
    "MANDATE_JWT_MAX_LENGTH",
    "DecodedMandateJwt",
    "MandateTokenSummary",
    "looks_like_mandate_jwt",
    "mandate_jwt_instant",
    "mandate_body_to_jwt_claims",
    "jwt_claims_to_mandate_body",
    "decode_mandate_jwt",
    "sign_mandate_jwt",
    "verify_mandate_jwt_signature",
    "split_mandate_jwt_chain",
    "peek_mandate_token",
]

MANDATE_JWT_TYP = "aroha-mandate+jwt"
SPENDING_MANDATE_DETAIL_TYPE = "https://aroha-labs.com/mandates/spending"
TASK_MANDATE_DETAIL_TYPE = "https://aroha-labs.com/mandates/task"
MANDATE_JWT_SEPARATOR = "~"
#: Longest single mandate JWT accepted, in characters.
MANDATE_JWT_MAX_LENGTH = 16 * 1024

_DETAIL_TYPES = {"spending": SPENDING_MANDATE_DETAIL_TYPE, "task": TASK_MANDATE_DETAIL_TYPE}
_HEADER_MEMBERS = {"alg", "typ", "kid"}
_CLAIMS = {"iss", "sub", "jti", "iat", "exp", "authorization_details"}
#: Body members that live in registered claims, never inside authorization_details.
_CLAIM_BACKED = ("grantor", "grantee", "mandateId", "issuedAt", "expiresAt")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
#: A 64-byte Ed25519 signature is exactly 86 base64url characters.
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
#: 9999-12-31T23:59:59Z: the last instant the body's date form can write.
_MAX_SECONDS = 253_402_300_799
#: Deepest nesting a claims set may have. Every SDK must stop at the same depth.
_MAX_DEPTH = 32
#: Largest magnitude every JSON parser reads exactly (RFC 8259 section 6, I-JSON).
_MAX_NUMBER = 2**53 - 1
#: RFC 7519 StringOrURI, ASCII only so every SDK reads it alike.
_STRING_OR_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+")
_EXACT_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
#: Members allowed in a detail, by kind, and in the objects it holds (spec §6.10 rule 4).
_DETAIL_MEMBERS = {
    "spending": {"mandateTier", "constraints", "parentMandateId", "actingFor"},
    "task": {"mandateType", "mandateTier", "allowed", "blocked", "taskConstraints", "spendingConstraints", "invariants", "parentMandateId"},
}
_SPENDING_CONSTRAINTS = {"spendLimitUsd", "sessionLimitUsd", "currency", "merchantCategory", "requireHumanApprovalAboveUsd", "allowedMerchants", "validFrom", "validUntil"}
_TASK_CONSTRAINTS = {"actionLimits", "computeLimit", "dataAccess", "outputHandling", "reversibleOnly", "humanGates", "checkpointIntervalMs", "requireSandbox", "maxDelegationDepth", "onBehalfOf", "roomId"}


@dataclass(frozen=True)
class DecodedMandateJwt:
    kind: str                       # "spending" | "task"
    header: dict[str, Any]
    body: dict[str, Any]            # the mandate body the claims decode to; NOT shape-checked here
    signing_input: str              # the ASCII text the signature covers: "<header>.<payload>" as received
    signature: str                  # base64url Ed25519 signature


@dataclass(frozen=True)
class MandateTokenSummary:
    kind: str                       # "spending" | "task"
    format: str                     # "jwt" | "native"
    mandate_id: str
    grantor: str
    grantee: str


def looks_like_mandate_jwt(token: Any) -> bool:
    """True for a token in the JWT form: only a JWT contains a "."."""
    return isinstance(token, str) and "." in token


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


_MISSING = object()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated member name: parsers disagree on which value wins."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k}")
        out[k] = v
    return out


def _decode_json_segment(segment: str) -> Any:
    """Decode one base64url JSON segment, or _MISSING. The encoding must be canonical and the text UTF-8."""
    if _SEGMENT.fullmatch(segment) is None:
        return _MISSING
    try:
        raw = _unb64u(segment)
        if _b64u(raw) != segment:
            return _MISSING
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)
    except Exception:
        return _MISSING


def _check_portable(value: Any, depth: int = 1) -> Optional[str]:
    """Why a parsed JSON value could read differently in another SDK, or None."""
    if depth > _MAX_DEPTH:
        return f"nested deeper than {_MAX_DEPTH} levels"
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return None
        except UnicodeEncodeError:
            return "a string is not well-formed Unicode"
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return None if value == value and abs(value) <= _MAX_NUMBER else "a number is outside the exact range"
    if isinstance(value, list):
        for v in value:
            why = _check_portable(v, depth + 1)
            if why:
                return why
    elif isinstance(value, dict):
        for k, v in value.items():
            why = _check_portable(k, depth) or _check_portable(v, depth + 1)
            if why:
                return why
    return None


def _is_exact_instant(x: Any) -> bool:
    """Date parsers disagree on nearly every other form, and some are local time."""
    if not isinstance(x, str) or _EXACT_INSTANT.fullmatch(x) is None:
        return False
    ms = parse_iso_ms(x)
    return ms is not None and iso_ms(ms) == x


def _unknown_member(value: Any, allowed: set[str]) -> Optional[str]:
    """The first member of ``value`` outside ``allowed``, or None. Leaves type checks to the shape check."""
    return next((k for k in value if k not in allowed), None) if isinstance(value, dict) else None


def _seconds(x: Any) -> Optional[int]:
    """A whole, non-negative number of seconds, or None. 1767225600.0 is accepted as JSON parsers in other SDKs read it."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    if isinstance(x, float) and (x != x or x in (float("inf"), float("-inf")) or x != int(x)):
        return None
    n = int(x)
    return n if 0 <= n <= _MAX_SECONDS else None


def mandate_jwt_instant(ms: int) -> int:
    """The instant a mandate JWT may carry for ``ms``: the whole second at or before it."""
    return (int(ms) // 1000) * 1000


def mandate_body_to_jwt_claims(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    """The claims of a mandate body. ValueError when ``issuedAt`` / ``expiresAt`` are not on whole seconds."""
    def seconds(field: str) -> int:
        ms = parse_iso_ms(body.get(field))
        if ms is None or ms % 1000 != 0 or ms < 0:
            raise ValueError(f"A mandate JWT needs {field} on a whole second")
        return ms // 1000

    detail: dict[str, Any] = {"type": _DETAIL_TYPES[kind]}
    for k, v in body.items():
        if k in _CLAIM_BACKED:
            continue
        if k == "type":
            raise ValueError('A mandate body may not have a member named "type"')
        detail[k] = v
    return {
        "iss": body.get("grantor"),
        "sub": body.get("grantee"),
        "jti": body.get("mandateId"),
        "iat": seconds("issuedAt"),
        "exp": seconds("expiresAt"),
        "authorization_details": [detail],
    }


def jwt_claims_to_mandate_body(claims: Any) -> Union[tuple[str, dict[str, Any]], str]:
    """``(kind, body)`` for a set of claims, or the reason they are not a mandate."""
    if not isinstance(claims, dict):
        return "claims are not an object"
    for k in claims:
        if k not in _CLAIMS:
            return f'unknown claim "{k}"'
    portable = _check_portable(claims)
    if portable:
        return portable
    for k in ("iss", "sub", "jti"):
        if not isinstance(claims.get(k), str) or not claims[k]:
            return f"{k} must be a non-empty string"
    # RFC 7519 StringOrURI: a value with a colon must be a URI.
    for k in ("iss", "sub"):
        if ":" in claims[k] and _STRING_OR_URI.fullmatch(claims[k]) is None:
            return f"{k} contains a colon and is not a URI"
    iat, exp = _seconds(claims.get("iat")), _seconds(claims.get("exp"))
    if iat is None:
        return "iat must be a whole number of seconds"
    if exp is None:
        return "exp must be a whole number of seconds"
    details = claims.get("authorization_details")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        return "authorization_details must hold exactly one object"
    detail = details[0]
    kind = next((k for k, t in _DETAIL_TYPES.items() if detail.get("type") == t and isinstance(detail.get("type"), str)), None)
    if kind is None:
        return f"authorization_details type {json.dumps(detail.get('type'))} is not a mandate"
    for k in _CLAIM_BACKED:
        if k in detail:
            return f"authorization_details must not carry {k}; it is a registered claim"
    body = {k: v for k, v in detail.items() if k != "type"}
    # Nothing here may be ignored: a member this verifier skips is one a
    # RAR-aware consumer may enforce, or a limit an older verifier would drop.
    stray = _unknown_member(body, _DETAIL_MEMBERS[kind])
    if stray:
        return f'authorization_details has an unknown member "{stray}"'
    constraints = detail.get("constraints") if kind == "spending" else detail.get("spendingConstraints")
    stray = _unknown_member(constraints, _SPENDING_CONSTRAINTS)
    if stray:
        return f'constraints has an unknown member "{stray}"'
    if isinstance(constraints, dict):
        for f in ("validFrom", "validUntil"):
            if f in constraints and not _is_exact_instant(constraints[f]):
                return f"constraints.{f} is not in the form YYYY-MM-DDTHH:mm:ss.sssZ"
    if kind == "task":
        stray = _unknown_member(detail.get("taskConstraints"), _TASK_CONSTRAINTS)
        if stray:
            return f'taskConstraints has an unknown member "{stray}"'
    body["grantee"] = claims["sub"]
    body["grantor"] = claims["iss"]
    body["issuedAt"] = iso_ms(iat * 1000)
    body["expiresAt"] = iso_ms(exp * 1000)
    body["mandateId"] = claims["jti"]
    return kind, body


def decode_mandate_jwt(jwt: Any) -> Union[DecodedMandateJwt, str]:
    """Decode one mandate JWT without verifying its signature, or return why it is not one.

    The body is not shape-checked.
    """
    if not isinstance(jwt, str):
        return "not a string"
    if len(jwt) > MANDATE_JWT_MAX_LENGTH:
        return f"longer than {MANDATE_JWT_MAX_LENGTH} characters"
    parts = jwt.split(".")
    if len(parts) != 3:
        return "not a compact JWS (three dot-separated parts)"
    header = _decode_json_segment(parts[0])
    if not isinstance(header, dict):
        return "header is not base64url JSON"
    for k in header:
        if k not in _HEADER_MEMBERS:
            return f'unknown header member "{k}"'
    # An allowlist, not "anything but none": the key is Ed25519, so no other
    # algorithm can be right, and naming one must not be a way to pick the check.
    if header.get("alg") not in ("EdDSA", "Ed25519") or not isinstance(header.get("alg"), str):
        return f"alg {json.dumps(header.get('alg'))} is not EdDSA"
    if header.get("typ") not in (MANDATE_JWT_TYP, f"application/{MANDATE_JWT_TYP}") or not isinstance(header.get("typ"), str):
        return f"typ {json.dumps(header.get('typ'))} is not {MANDATE_JWT_TYP}"
    if "kid" in header and (not isinstance(header["kid"], str) or not header["kid"]):
        return "kid must be a non-empty string"
    payload = _decode_json_segment(parts[1])
    mapped = jwt_claims_to_mandate_body(None if payload is _MISSING else payload)
    if isinstance(mapped, str):
        return mapped
    try:
        canonical_signature = _SIGNATURE.fullmatch(parts[2]) is not None and _b64u(_unb64u(parts[2])) == parts[2]
    except Exception:
        canonical_signature = False
    if not canonical_signature:
        return "signature is not a base64url Ed25519 signature"
    kind, body = mapped
    return DecodedMandateJwt(kind, header, body, f"{parts[0]}.{parts[1]}", parts[2])


def _private_key(key: Union[Ed25519PrivateKey, bytes]) -> Ed25519PrivateKey:
    return key if isinstance(key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(bytes(key))


def sign_mandate_jwt(kind: str, body: dict[str, Any], private_key: Union[Ed25519PrivateKey, bytes], kid: Optional[str] = None) -> str:
    """Sign a mandate body as a JWT. ``kid`` is the signer's key id, normally the key's RFC 7638 thumbprint."""
    header: dict[str, Any] = {"alg": "EdDSA", "typ": MANDATE_JWT_TYP}
    if kid is not None:
        header["kid"] = kid

    def encode(value: Any) -> str:
        return _b64u(json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"))

    claims = mandate_body_to_jwt_claims(kind, body)
    # Refused here so an issuer never mints what every verifier would reject.
    mapped = jwt_claims_to_mandate_body(claims)
    if isinstance(mapped, str):
        raise ValueError(f"Cannot issue this mandate as a JWT: {mapped}")
    signing_input = f"{encode(header)}.{encode(claims)}"
    # 87 = "." plus an 86-character signature. Refused here so that an issuer
    # never mints a mandate that every verifier would then reject.
    if len(signing_input) + 87 > MANDATE_JWT_MAX_LENGTH:
        raise ValueError(f"A mandate JWT cannot be longer than {MANDATE_JWT_MAX_LENGTH} characters")
    return f"{signing_input}.{_b64u(_private_key(private_key).sign(signing_input.encode('ascii')))}"


def verify_mandate_jwt_signature(jwt: str, public_key: Union[Ed25519PublicKey, bytes, None]) -> bool:
    """True when the JWT's signature verifies under ``public_key``. Never raises. Says nothing about the claims."""
    decoded = decode_mandate_jwt(jwt)
    if isinstance(decoded, str) or public_key is None:
        return False
    try:
        key = public_key if isinstance(public_key, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(bytes(public_key))
        if key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() in _WEAK_KEYS_HEX:
            return False
        key.verify(_unb64u(decoded.signature), decoded.signing_input.encode("ascii"))
        return True
    except (InvalidSignature, Exception):
        return False


def split_mandate_jwt_chain(token: str) -> Union[list[str], str]:
    """Split a JWT-form token into its link JWTs, root first, or return why it cannot be split."""
    links = token.split(MANDATE_JWT_SEPARATOR)
    if any(len(link) == 0 for link in links):
        return "empty link in the chain"
    return links


def peek_mandate_token(token: Any) -> Optional[MandateTokenSummary]:
    """Read a token's leaf without verifying anything, in either form. None when it is not a mandate token.

    For routing and error messages only: every field is unauthenticated until
    the token is verified.
    """
    if not isinstance(token, str) or not token:
        return None

    def summary(kind: str, fmt: str, m: dict[str, Any]) -> Optional[MandateTokenSummary]:
        mid, grantor, grantee = m.get("mandateId"), m.get("grantor"), m.get("grantee")
        if isinstance(mid, str) and isinstance(grantor, str) and isinstance(grantee, str):
            return MandateTokenSummary(kind, fmt, mid, grantor, grantee)
        return None

    if looks_like_mandate_jwt(token):
        decoded = decode_mandate_jwt(token.split(MANDATE_JWT_SEPARATOR)[-1])
        return None if isinstance(decoded, str) else summary(decoded.kind, "jwt", decoded.body)
    try:
        raw = json.loads(_unb64u(token).decode("utf-8"), parse_constant=_reject_constant)
    except Exception:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("mandate"), dict):
        return None
    m = raw["mandate"]
    return summary("task" if "mandateType" in m else "spending", "native", m)
