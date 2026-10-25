# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha did:aroha-web: — DNS-anchored web identity (port of aroha-core identity/web-did.ts)

Two channels must agree before a key is accepted:
  1. HTTPS   — GET https://{domain}/.well-known/aroha/agents/{path}/did.json
  2. DNS TXT — _aroha.{domain} IN TXT "v=aroha1; path={path}; keyhash={sha256hex(pubkey)}"

The document uses the TypeScript wire shape: ``verificationMethod[]`` with
base58btc ``publicKeyMultibase`` (prefix ``z``) and ``arohaWeb.{domain, path,
keyCommitmentHash, keyHistory}``, keyHistory newest first. Rotation records
are the TypeScript ``KeyRotationRecord`` (v2: JCS-signed and bound to the
DID; legacy v1: ``predecessorKey + newKeyHash + rotatedAt``).

Resolution follows resolveWebDID exactly (see :func:`resolve_web_did`):
the DID must name a hostname (no IP literal unless opted in) and a path
matching ``^[a-z0-9-]+(/[a-z0-9-]+)*$``; the document is fetched over https
without following redirects, capped at 64 KiB, with a timeout; the rotation
chain must link the current key to a key DNS commits to (the key is hashed
here — the document's self-declared hash is only cross-checked); and nothing
is accepted when DNS matches no key in the chain (fail closed).

DID format: did:aroha-web:{domain}[:{path}]   e.g. did:aroha-web:stripe.com:payments-agent
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.identity import from_multibase, to_multibase
from aroha.jcs import canonicalize_jcs
from aroha.timeutil import iso_ms, parse_iso_ms, to_ms

__all__ = [
    "MAX_WEB_DID_DOCUMENT_BYTES",
    "WEB_DID_PATH_PATTERN",
    "WebDIDError",
    "WebAgentKeyPair",
    "WebDIDAcceptedKey",
    "WebDIDResolutionResult",
    "assert_web_did_domain",
    "parse_web_did",
    "build_web_did",
    "is_web_did",
    "well_known_path",
    "well_known_url",
    "dns_txt_value",
    "parse_dns_txt",
    "key_commitment_hash",
    "rotation_signing_payload",
    "build_rotation_record",
    "check_key_rotation",
    "verify_key_rotation",
    "generate_web_agent",
    "rotate_key",
    "resolve_web_did",
    "web_did_public_keys",
    "select_web_did_key",
]

#: Default cap on a DID document's size (64 KiB).
MAX_WEB_DID_DOCUMENT_BYTES = 64 * 1024
#: The path grammar: lowercase segments of [a-z0-9-], "/"-separated.
WEB_DID_PATH_PATTERN = re.compile(r"^[a-z0-9-]+(/[a-z0-9-]+)*$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PREFIX = "did:aroha-web:"
_DEFAULT_LEGACY_COOLDOWN_HOURS = 24


class WebDIDError(ValueError):
    """A did:aroha-web identifier or document failed validation or resolution."""


# ── DID parsing ───────────────────────────────────────────────────────────────

def assert_web_did_domain(domain: str, *, allow_ip_literal: bool = False) -> None:
    """Raise unless ``domain`` is a DNS hostname (IPv4 literal only when opted in)."""
    d = domain.lower()
    if len(d) == 0 or len(d) > 253:
        raise WebDIDError(f"did:aroha-web domain has an invalid length: {domain}")
    if _IPV4.fullmatch(d):
        if allow_ip_literal and all(int(o) <= 255 for o in d.split(".")):
            return
        raise WebDIDError(f"did:aroha-web domain must be a hostname, not an IP literal: {domain}")
    labels = d.split(".")
    if not all(_LABEL.fullmatch(l) for l in labels):
        raise WebDIDError(f"did:aroha-web domain is not a valid hostname: {domain}")
    if labels[-1].isdigit():
        raise WebDIDError(f"did:aroha-web domain is not a valid hostname: {domain}")


def parse_web_did(did: str, *, allow_ip_literal: bool = False) -> tuple[str, str]:
    """``did:aroha-web:domain[:path]`` → ``(domain, path)``; path defaults to ``agent``."""
    if not did.startswith(_PREFIX):
        raise WebDIDError(f"Not a did:aroha-web: identifier: {did}")
    rest = did[len(_PREFIX):]
    i = rest.find(":")
    domain = rest if i == -1 else rest[:i]
    path = "agent" if i == -1 else rest[i + 1:].replace(":", "/")
    assert_web_did_domain(domain, allow_ip_literal=allow_ip_literal)
    if not WEB_DID_PATH_PATTERN.fullmatch(path):
        raise WebDIDError(f"did:aroha-web path must match {WEB_DID_PATH_PATTERN.pattern}: {path}")
    return domain, path


def build_web_did(domain: str, path: str) -> str:
    return f"{_PREFIX}{domain}:{path.replace('/', ':')}"


def is_web_did(did: str) -> bool:
    return did.startswith(_PREFIX)


def well_known_path(did: str, *, allow_ip_literal: bool = False) -> str:
    _, path = parse_web_did(did, allow_ip_literal=allow_ip_literal)
    return f"/.well-known/aroha/agents/{path}/did.json"


def well_known_url(did: str, *, allow_ip_literal: bool = False) -> str:
    domain, path = parse_web_did(did, allow_ip_literal=allow_ip_literal)
    return f"https://{domain}/.well-known/aroha/agents/{path}/did.json"


# ── DNS TXT / key commitment ──────────────────────────────────────────────────

def key_commitment_hash(public_key: bytes) -> str:
    return hashlib.sha256(bytes(public_key)).hexdigest()


def dns_txt_value(did: str, public_key: bytes) -> str:
    """The TXT value to publish at ``_aroha.{domain}``."""
    _, path = parse_web_did(did)
    return f"v=aroha1; path={path}; keyhash={key_commitment_hash(public_key)}"


def parse_dns_txt(txt: str) -> Optional[dict[str, str]]:
    """``{"path", "keyhash"}`` from a TXT value, or None if it is not an aroha1 record."""
    if "v=aroha1" not in txt:
        return None
    fields: dict[str, str] = {}
    for part in txt.split(";"):
        eq = part.find("=")
        if eq == -1:
            continue
        fields[part[:eq].strip()] = part[eq + 1:].strip()
    if not fields.get("path") or not fields.get("keyhash"):
        return None
    return {"path": fields["path"], "keyhash": fields["keyhash"]}


# ── Rotation records ──────────────────────────────────────────────────────────

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rotation_signing_payload(record: dict[str, Any]) -> bytes:
    """Exact bytes a rotation record's ``predecessorSignature`` covers (port of rotationSigningPayload).

    v2: JCS of ``{did, newKeyHash, predecessorKey, rotatedAt, trustAfter, v: 2}``.
    Legacy v1: ``predecessorKey + newKeyHash + rotatedAt``.
    """
    if record.get("v") == 2:
        did = record.get("did")
        if not isinstance(did, str) or not did:
            raise WebDIDError("v2 key rotation record is missing its did")
        return canonicalize_jcs({
            "did": did,
            "newKeyHash": record.get("newKeyHash"),
            "predecessorKey": record.get("predecessorKey"),
            "rotatedAt": record.get("rotatedAt"),
            "trustAfter": record.get("trustAfter"),
            "v": 2,
        }).encode("utf-8")
    def js(v: Any) -> str:  # JavaScript string concatenation of a field
        return "undefined" if v is None else v if isinstance(v, str) else json.dumps(v)

    return (js(record.get("predecessorKey")) + js(record.get("newKeyHash")) + js(record.get("rotatedAt"))).encode("utf-8")


def build_rotation_record(
    did: str, old_private_key: Ed25519PrivateKey, new_public_key: bytes, now: datetime, cool_down_hours: float,
) -> dict[str, Any]:
    """A signed v2 rotation record (port of buildRotationRecord)."""
    old_pub = old_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    record: dict[str, Any] = {
        "v": 2,
        "did": did,
        "rotatedAt": iso_ms(now),
        "trustAfter": iso_ms(now + timedelta(hours=cool_down_hours)),
        "predecessorKey": to_multibase(old_pub),
        "newKeyHash": key_commitment_hash(new_public_key),
        "predecessorSignature": "",
    }
    record["predecessorSignature"] = _b64u(old_private_key.sign(rotation_signing_payload(record)))
    return record


def check_key_rotation(rotation: dict[str, Any], expected_did: Optional[str] = None) -> tuple[bool, bool, Optional[str]]:
    """``(valid, deprecated, reason)`` — port of checkKeyRotation."""
    v = rotation.get("v")
    deprecated = v != 2
    if v is not None and v != 2:
        return False, deprecated, f"has unsupported version {v}"
    if v == 2 and expected_did is not None and rotation.get("did") != expected_did:
        return False, deprecated, f"was signed for {rotation.get('did')}, not {expected_did}"
    try:
        pub = Ed25519PublicKey.from_public_bytes(from_multibase(rotation["predecessorKey"]))
        pub.verify(_b64u_decode(rotation["predecessorSignature"]), rotation_signing_payload(rotation))
        return True, deprecated, None
    except Exception:
        return False, deprecated, "has invalid predecessor signature"


def verify_key_rotation(rotation: dict[str, Any], expected_did: Optional[str] = None) -> bool:
    return check_key_rotation(rotation, expected_did)[0]


# ── Generate / rotate ─────────────────────────────────────────────────────────

@dataclass
class WebAgentKeyPair:
    did: str
    private_key: Ed25519PrivateKey
    public_key: bytes
    #: The DID document (TypeScript WebDIDDocument wire shape) to serve.
    document: dict[str, Any]
    #: The TXT value to publish at ``_aroha.{domain}``.
    dns_txt_record: str
    well_known_url: str


def generate_web_agent(domain: str, path: str, endpoint: Optional[str] = None) -> WebAgentKeyPair:
    """New did:aroha-web identity: serve ``document`` at ``well_known_url``, publish ``dns_txt_record``."""
    did = build_web_did(domain, path)
    parse_web_did(did)  # validate the domain and path up front
    private_key = Ed25519PrivateKey.generate()
    pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = f"{did}#key-1"
    now = iso_ms(datetime.now(timezone.utc))
    doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://aroha-labs.com/contexts/aroha-web/v1",
        ],
        "id": did,
        "verificationMethod": [
            {"id": key_id, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": to_multibase(pub)},
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "keyAgreement": [key_id],
        "service": [{"id": f"{did}#aroha", "type": "ArohaEndpoint", "serviceEndpoint": endpoint or f"https://{domain}/aroha/v1"}],
        "created": now,
        "updated": now,
        "arohaWeb": {"domain": domain, "path": path, "keyCommitmentHash": key_commitment_hash(pub), "keyHistory": []},
    }
    return WebAgentKeyPair(did, private_key, pub, doc, dns_txt_value(did, pub), well_known_url(did))


def rotate_key(current: WebAgentKeyPair, cool_down_hours: float = 24, *, now: Optional[datetime] = None) -> WebAgentKeyPair:
    """Rotate the primary key; the old key signs a v2 rotation record prepended to keyHistory."""
    new_private = Ed25519PrivateKey.generate()
    new_pub = new_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    web = current.document["arohaWeb"]
    did = build_web_did(web["domain"], web["path"])
    when = now or datetime.now(timezone.utc)
    rotation = build_rotation_record(did, current.private_key, new_pub, when, cool_down_hours)
    vms = current.document.get("verificationMethod") or []
    key_id = vms[0]["id"] if vms else f"{did}#key-1"
    doc = dict(current.document)
    doc["verificationMethod"] = [
        {"id": key_id, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": to_multibase(new_pub)},
        *vms[1:],
    ]
    doc["updated"] = iso_ms(when)
    doc["arohaWeb"] = {**web, "keyCommitmentHash": key_commitment_hash(new_pub),
                       "keyHistory": [rotation, *web.get("keyHistory", [])]}
    return WebAgentKeyPair(did, new_private, new_pub, doc, dns_txt_value(did, new_pub), well_known_url(did))


# ── Resolve ───────────────────────────────────────────────────────────────────

@dataclass
class WebDIDAcceptedKey:
    verification_method_id: str
    public_key_multibase: str
    #: "current" | "predecessor" | "anchored" | "additional" (see aroha-core).
    role: str


@dataclass
class WebDIDResolutionResult:
    document: dict[str, Any]
    #: True only if a DNS TXT commitment matched a key in the verified chain.
    #: False whenever DNS was not checked.
    dns_verified: bool
    #: The CURRENT primary key is accepted and past its rotation cool-down.
    key_trusted: bool
    trust_reason: Optional[str] = None
    #: Every key a verifier may accept right now, newest first. Empty = nothing accepted.
    accepted_keys: list[WebDIDAcceptedKey] = field(default_factory=list)
    #: keyHistory holds legacy v1 (not DID-bound) rotation records.
    deprecated_rotations: bool = False


Fetcher = Callable[[str, float, int], bytes]
DnsResolver = Callable[[str], list[str]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise WebDIDError(f"DID document at {req.full_url} answered with a redirect ({code}); redirects are not followed")


def _default_fetch(url: str, timeout_s: float, max_bytes: int) -> bytes:
    """HTTPS GET with no redirects, a timeout, and a streamed size cap."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            declared = resp.headers.get("Content-Length")
            if declared is not None and declared.strip().isdigit() and int(declared) > max_bytes:
                raise WebDIDError(f"DID document at {url} is too large ({declared} bytes > {max_bytes})")
            body = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        raise WebDIDError(f"HTTP {e.code} from {url}") from None
    if len(body) > max_bytes:
        raise WebDIDError(f"DID document at {url} is too large (> {max_bytes} bytes)")
    return body


def _system_dns_resolver() -> Optional[DnsResolver]:
    """dnspython's TXT lookup when installed, else None (the standard library has no TXT lookup)."""
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except Exception:
        return None

    def resolve(domain: str) -> list[str]:
        answer = dns.resolver.resolve(f"_aroha.{domain}", "TXT")
        # A TXT record may arrive split into ≤255-byte strings; rejoin each one.
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]

    return resolve


def _absolute_vm_id(did: str, vid: str) -> str:
    return f"{did}{vid}" if vid.startswith("#") else vid


def _date_ms(value: Any) -> float:
    """Date.parse semantics: NaN (which compares false both ways) when unparseable."""
    ms = parse_iso_ms(value)
    return math.nan if ms is None else float(ms)


def resolve_web_did(
    did: str,
    *,
    verify_dns: bool = True,
    dns_resolver: Optional[DnsResolver] = None,
    use_system_dns: bool = True,
    allow_no_dns: bool = False,
    allow_ip_literal: bool = False,
    fetch: Optional[Fetcher] = None,
    fetch_timeout_s: float = 10.0,
    max_document_bytes: int = MAX_WEB_DID_DOCUMENT_BYTES,
    now: Optional[Union[datetime, int]] = None,
    legacy_min_cool_down_hours: float = _DEFAULT_LEGACY_COOLDOWN_HOURS,
    logger: Optional[Callable[[str], None]] = None,
) -> WebDIDResolutionResult:
    """Resolve a did:aroha-web identifier (port of aroha-core resolveWebDID). Raises WebDIDError.

    1. Fetch the document over https (no redirects, ``max_document_bytes``,
       ``fetch_timeout_s``); its ``id`` must equal ``did``; the primary key's
       SHA-256 must equal ``arohaWeb.keyCommitmentHash`` when that is present.
    2. Verify ``arohaWeb.keyHistory`` (newest first): every record's
       predecessor signature (v2 bound to ``did``); record 0 commits to the
       current key, record i to record i-1's predecessorKey; rotatedAt
       non-increasing. Any break raises.
    3. DNS: the NEWEST chain key whose hash ``_aroha.{domain}`` commits to is
       the anchor. No anchor → ``dns_verified=False`` and nothing accepted.
       ``verify_dns=False`` or ``allow_no_dns`` with no resolver resolves
       HTTPS-only (logged) and reports ``dns_verified=False``.
    4. Accepted keys and ``key_trusted`` follow the cool-down rules of
       aroha-core exactly (graceful cutover; keys DNS has not endorsed wait
       out their cool-down).

    ``dns_resolver(domain)`` returns the TXT strings of ``_aroha.{domain}``.
    Without one, dnspython is used if installed (``use_system_dns``); with no
    resolver at all resolution raises unless ``allow_no_dns``.
    ``fetch(url, timeout_s, max_bytes)`` replaces the HTTPS fetch (tests).
    """
    log = logger or (lambda m: print(m, file=sys.stderr))
    now_ms = (to_ms(now) if isinstance(now, datetime) else int(now)) if now is not None else to_ms(datetime.now(timezone.utc))
    url = well_known_url(did, allow_ip_literal=allow_ip_literal)

    # ── Step 1: fetch ─────────────────────────────────────────────────────────
    try:
        body = (fetch or _default_fetch)(url, fetch_timeout_s, max_document_bytes)
    except WebDIDError as e:
        raise WebDIDError(f"Failed to resolve {did}: {e}") from None
    except Exception as e:
        raise WebDIDError(f"Failed to resolve {did}: {e}") from None
    if len(body) > max_document_bytes:
        raise WebDIDError(f"DID document at {url} is too large (> {max_document_bytes} bytes)")
    try:
        doc = json.loads(body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body)
    except Exception:
        raise WebDIDError(f"Failed to resolve {did}: document at {url} is not JSON") from None
    if not isinstance(doc, dict):
        raise WebDIDError(f"Failed to resolve {did}: document at {url} is not an object")
    if doc.get("id") != did:
        raise WebDIDError(f"DID mismatch: document claims {doc.get('id')}, expected {did}")
    vms = doc.get("verificationMethod")
    if not isinstance(vms, list) or not vms or not isinstance(vms[0], dict):
        raise WebDIDError(f"DID {did}: document has no verification methods")
    primary = vms[0]
    current_key = primary.get("publicKeyMultibase")
    try:
        current_hash = key_commitment_hash(from_multibase(current_key))
    except Exception:
        raise WebDIDError(f"DID {did}: primary key is not a base58btc multibase key") from None
    web = doc.get("arohaWeb") if isinstance(doc.get("arohaWeb"), dict) else {}
    if web.get("keyCommitmentHash") is not None and web.get("keyCommitmentHash") != current_hash:
        raise WebDIDError(f"DID {did}: arohaWeb.keyCommitmentHash does not match the primary key")

    # ── Step 2: rotation chain ────────────────────────────────────────────────
    history = web.get("keyHistory") or []
    if not isinstance(history, list) or not all(isinstance(r, dict) for r in history):
        raise WebDIDError(f"DID {did}: arohaWeb.keyHistory is malformed")
    deprecated = False
    for i, r in enumerate(history):
        valid, dep, reason = check_key_rotation(r, did)
        if not valid:
            raise WebDIDError(f"DID {did}: key rotation record (rotatedAt {r.get('rotatedAt')}) {reason}")
        deprecated = deprecated or dep
        successor = current_key if i == 0 else history[i - 1].get("predecessorKey")
        try:
            successor_hash = key_commitment_hash(from_multibase(successor))
        except Exception:
            successor_hash = None
        if r.get("newKeyHash") != successor_hash:
            raise WebDIDError(
                f"DID {did}: keyHistory[0] does not commit to the current primary key" if i == 0 else
                f"DID {did}: keyHistory[{i}] does not commit to keyHistory[{i - 1}].predecessorKey — the rotation chain is broken"
            )
        if i > 0 and _date_ms(r.get("rotatedAt")) > _date_ms(history[i - 1].get("rotatedAt")):
            raise WebDIDError(f"DID {did}: keyHistory is not newest-first at index {i}")
    if deprecated:
        log(f"[aroha] {did}: keyHistory contains legacy v1 rotation records (not DID-bound); re-rotate to upgrade")

    n = len(history)
    chain: list[str] = [r["predecessorKey"] for r in reversed(history)] + [current_key]
    legacy_floor = legacy_min_cool_down_hours * 3_600_000

    def effective_trust_after(r: dict[str, Any]) -> float:
        signed = _date_ms(r.get("trustAfter"))
        if r.get("v") == 2:
            return signed
        # v1: trustAfter is unsigned — never let it shorten the default cool-down.
        floor = _date_ms(r.get("rotatedAt")) + legacy_floor
        if math.isnan(floor):
            return math.nan  # Math.max propagates NaN
        return max(0.0 if math.isnan(signed) else signed, floor)

    def introduced_by(j: int) -> dict[str, Any]:
        return history[n - j]

    # ── Step 3: DNS ───────────────────────────────────────────────────────────
    domain, path = parse_web_did(did, allow_ip_literal=allow_ip_literal)
    txt_records: Optional[list[str]] = None
    if verify_dns:
        resolver = dns_resolver or (_system_dns_resolver() if use_system_dns else None)
        if resolver is not None:
            try:
                txt_records = list(resolver(domain))
            except Exception:
                txt_records = []  # lookup failed — no commitment found, fail closed below
        elif not allow_no_dns:
            raise WebDIDError(
                f"Cannot verify {did}: no DNS resolver available for the _aroha.{domain} TXT key-commitment. "
                "Pass dns_resolver (or install dnspython), or allow_no_dns=True for tests/dev only."
            )
    if txt_records is None:
        log(f"[aroha] {did}: resolved HTTPS-only — DNS key-commitment NOT checked (allow_no_dns / verify_dns=False)")

    accepted: list[WebDIDAcceptedKey] = []
    primary_id = _absolute_vm_id(did, str(primary.get("id", "")))
    dns_verified = False
    if txt_records is None:
        anchor = len(chain) - 1
        for vm in vms[1:]:
            accepted.append(WebDIDAcceptedKey(_absolute_vm_id(did, vm["id"]), vm["publicKeyMultibase"], "additional"))
    else:
        hashes = set()
        for t in txt_records:
            parsed = parse_dns_txt(t)
            if parsed and parsed["path"] == path:
                hashes.add(parsed["keyhash"])
        anchor = -1
        for j in range(len(chain) - 1, -1, -1):
            if key_commitment_hash(from_multibase(chain[j])) in hashes:
                anchor = j
                break
        dns_verified = anchor >= 0
        if dns_verified:
            for vm in vms[1:]:
                try:
                    h = key_commitment_hash(from_multibase(vm["publicKeyMultibase"]))
                except Exception:
                    continue
                if h in hashes:
                    accepted.append(WebDIDAcceptedKey(_absolute_vm_id(did, vm["id"]), vm["publicKeyMultibase"], "additional"))

    # ── Step 4: primary-slot keys accepted now ────────────────────────────────
    key_trusted = False
    trust_reason: Optional[str] = None
    last = len(chain) - 1
    if anchor < 0:
        trust_reason = f"No DNS TXT key-commitment at _aroha.{domain} matches any key in the document's rotation chain"
    elif anchor == last:
        accepted.insert(0, WebDIDAcceptedKey(primary_id, current_key, "current"))
        if n > 0 and now_ms < effective_trust_after(history[0]):
            accepted.insert(1, WebDIDAcceptedKey(primary_id, chain[last - 1], "predecessor"))
            trust_reason = f"Key rotation cool-down active until {iso_ms(int(effective_trust_after(history[0])))}"
        else:
            key_trusted = True
    else:
        cur = anchor
        while cur < last and now_ms >= effective_trust_after(introduced_by(cur + 1)):
            cur += 1
        accepted.insert(0, WebDIDAcceptedKey(primary_id, chain[cur], "current" if cur == last else "anchored"))
        if cur == last:
            key_trusted = True
        else:
            ta = effective_trust_after(introduced_by(cur + 1))
            when = iso_ms(int(ta)) if not math.isnan(ta) else "Invalid Date"
            trust_reason = (
                "DNS commits to an earlier key; the newer key is not trusted until its rotation cool-down ends "
                f"({when}) or DNS is updated"
            )

    return WebDIDResolutionResult(doc, dns_verified, key_trusted, trust_reason, accepted, deprecated)


def web_did_public_keys(result: WebDIDResolutionResult, verification_method_id: Optional[str] = None) -> list[bytes]:
    """Keys that may verify a signature naming ``verification_method_id`` (default primary), newest first."""
    did = result.document["id"]
    vms = result.document.get("verificationMethod") or []
    primary_id = _absolute_vm_id(did, vms[0]["id"] if vms else f"{did}#key-1")
    wanted = _absolute_vm_id(did, verification_method_id) if verification_method_id else primary_id
    return [from_multibase(k.public_key_multibase) for k in result.accepted_keys if k.verification_method_id == wanted]


def select_web_did_key(result: WebDIDResolutionResult, verification_method_id: Optional[str] = None) -> bytes:
    """The newest accepted key; raises when none is accepted (map that to "unknown sender")."""
    keys = web_did_public_keys(result, verification_method_id)
    if not keys:
        raise WebDIDError(
            f"DID {result.document.get('id')}: no accepted key for "
            f"{verification_method_id or 'the primary verification method'}"
            + (f" ({result.trust_reason})" if result.trust_reason else "")
        )
    return keys[0]
