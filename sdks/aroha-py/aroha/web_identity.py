# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Web identities: an HTTPS URL as a mandate's grantor, grantee or holder (spec §4.7).

The Python counterpart of ``packages/aroha-credentials/src/web-identity.ts``;
both are checked against ``test-vectors/web-identity-v1.json``.

Why. A mandate says "this key may do that, within these limits". How the
key's owner is *named* is a separate question. ``did:aroha:`` identifiers
answer it with no lookup, but a verifier has to learn a new identifier scheme
to use them. Most agent platforms already name an agent by an HTTPS URL that
serves a small JSON document with the agent's public keys: the OAuth Client ID
Metadata Document (draft-ietf-oauth-client-id-metadata-document). A web
identity is that URL, so an agent that already publishes one can sign and hold
mandates under the name it already has.

What it is not. The OAuth draft defines the document for OAuth clients and
says nothing about mandates; reusing it as an Aroha identity is this profile's
choice. No OAuth flow runs here: the verifier fetches the document, reads the
key and checks the mandate signature with it.

Trust model, which differs from ``did:aroha`` on purpose:

- ``did:aroha:z…`` / ``E…`` identifiers are self-certifying: no network, no
  third party.
- A web identity is as trustworthy as HTTPS to that origin: whoever controls
  the host, its DNS or a certificate for it can publish a key. The key is the
  one published at *verification* time, so replacing it stops outstanding
  mandates verifying (the rule an E-form rotation already follows).
- The governed profile (§6.8) still requires a ``did:aroha:E…`` person root.

Fetch rules (from the OAuth draft, applied to the document and to a
``jwks_uri``): HTTPS only, no redirects followed, HTTP 200 only, a size cap, a
timeout, successes cached for a bounded time, failures never cached. Before
each request the host name is resolved and the request is refused if any of
its addresses is special-use (loopback, private, link-local, ...). That check
does not pin the connection; see ``_refusal`` for exactly what is covered, and
use ``allow_host``, a pinning ``fetch`` or an egress policy where it matters.

    resolve_key = create_mandate_key_resolver(web=True)
    result = verify_mandate_chain(token, resolve_key, expected_root="https://agents.example.com/shopper")
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import ipaddress
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "WEB_IDENTITY_MAX_LENGTH",
    "WEB_IDENTITY_MAX_DOCUMENT_BYTES",
    "WEB_IDENTITY_MAX_JWKS_BYTES",
    "WEB_IDENTITY_MAX_CACHE_S",
    "WEB_IDENTITY_FETCH_TIMEOUT_S",
    "WebIdentityResponse",
    "WebIdentityKeySelection",
    "WebIdentityResolution",
    "looks_like_web_identity",
    "check_web_identity",
    "is_web_identity",
    "ed25519_jwk_thumbprint",
    "ed25519_public_key_to_jwk",
    "jwk_to_ed25519_public_key",
    "select_web_identity_key",
    "is_special_use_address",
    "build_web_identity_document",
    "resolve_web_identity",
    "create_web_identity_resolver",
]

WEB_IDENTITY_MAX_LENGTH = 2048
#: Default size cap for the identity document: the OAuth draft's recommended 5 kilobytes.
WEB_IDENTITY_MAX_DOCUMENT_BYTES = 5 * 1024
#: Default size cap for a key set fetched from ``jwks_uri``.
WEB_IDENTITY_MAX_JWKS_BYTES = 16 * 1024
#: Default (and longest default) time a resolved key is reused: 5 minutes.
WEB_IDENTITY_MAX_CACHE_S = 300.0
#: Default timeout for each HTTPS request.
WEB_IDENTITY_FETCH_TIMEOUT_S = 5.0
_CACHE_MAX_ENTRIES = 500


# ── Identifier ────────────────────────────────────────────────────────────────

def looks_like_web_identity(identity: Any) -> bool:
    """True for anything a web-identity resolver should claim: an http(s) URL string."""
    return isinstance(identity, str) and (identity.startswith("https://") or identity.startswith("http://"))


# The grammar (spec §4.7), written out because identifiers are compared as
# plain strings and every SDK must agree on which strings are identifiers.
#
#   identity = "https://" host [ ":" port ] path
#   host     = label 1*( "." label )         ; lower case, the last label a TLD
#   label    = 1-63 of a-z 0-9 "-", not starting or ending with "-"
#   tld      = 2-63 letters a-z, or an "xn--" label; never "localhost"
#   port     = 1-65535 without leading zeros, and not the scheme's default
#   path     = 1*( "/" segment ) [ "/" ]     ; so never just "/"
#   segment  = 1*( unreserved / sub-delims / ":" / "@" / "%" HEX HEX )
#              and not "." or "..", also when a dot is written "%2e"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
_HOST = rf"(?:{_LABEL}\.)+{_TLD}"
_PCHAR = r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})"
_URL_RE = re.compile(
    rf"(https|http)://({_HOST}|localhost|127\.0\.0\.1)(?::([1-9][0-9]{{0,4}}))?((?:/{_PCHAR}+)*/?)(\?(?:{_PCHAR}|[/?])*)?"
)
_USERINFO_RE = re.compile(r"https?://[^/?]*@")


def _check_url(value: Any, *, loopback_http: bool, identity: bool) -> Optional[str]:
    if not isinstance(value, str) or len(value) == 0:
        return "is not a string"
    if len(value) > WEB_IDENTITY_MAX_LENGTH:
        return f"is longer than {WEB_IDENTITY_MAX_LENGTH} characters"
    if not value.startswith("https://") and not (loopback_http and value.startswith("http://")):
        return "must use the https scheme"
    if "#" in value:
        return "must not contain a fragment"
    if _USERINFO_RE.match(value):
        return "must not contain user information"
    m = _URL_RE.fullmatch(value)
    if m is None:
        return "is not a URL in the accepted form"
    scheme, host, port, path, query = m.groups()
    loopback = host in ("localhost", "127.0.0.1")
    # An IP literal never matches the host rule: an IP has no name to anchor
    # trust in, and accepting one turns the resolver into a fetcher of
    # arbitrary addresses. The two loopback names are for development only.
    if loopback != (scheme == "http"):
        return "loopback hosts are accepted over http only" if loopback else "must use the https scheme"
    if loopback and not loopback_http:
        return "must not name a loopback host"
    if len(host) > 253:
        return "host is too long"
    # RFC 6761: every name under "localhost" is loopback, whatever DNS says.
    if host.endswith(".localhost"):
        return "must not name a loopback host"
    if port is not None and (int(port) > 65535 or int(port) == (443 if scheme == "https" else 80)):
        return "port is out of range or is the default port, which must be omitted"
    if path == "":
        return "must have a path"
    for segment in path.split("/"):
        dots = re.sub(r"%2e", ".", segment, flags=re.IGNORECASE)
        if dots in (".", ".."):
            return "must not contain dot segments"
    if identity and path == "/":
        return "must have a path other than /"
    if identity and query is not None:
        return "must not contain a query"
    # An "xn--" label must be decodable Punycode, as the URL parsers of other
    # SDKs require; otherwise the SDKs would disagree on the same string.
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                codecs.decode(label[4:].encode("ascii"), "punycode")
            except (UnicodeError, ValueError):
                return "is not a URL"
    # Belt and braces: the standard library must read the string the same way
    # the grammar does, or the request would go somewhere the checks did not look.
    try:
        parts = urlsplit(value)
        if parts.hostname != host or (parts.port is not None) != (port is not None) or parts.username is not None:
            return "is not in normalised form"
    except ValueError:
        return "is not a URL"
    return None


def check_web_identity(identity: Any, *, allow_loopback_http: bool = False) -> Optional[str]:
    """Why ``identity`` is not a valid web identity, or None when it is one.

    Rules (the OAuth Client ID Metadata Document draft's, made stricter so one
    agent has exactly one name): the https scheme; a lower-case DNS hostname
    ending in a top-level domain (no IP literal, no localhost); an optional
    non-default port; a path other than "/" with no empty or dot segments; no
    user information, fragment or query. ``allow_loopback_http`` also accepts
    ``http://localhost[:port]/…`` and ``http://127.0.0.1[:port]/…`` and is for
    local development only.
    """
    why = _check_url(identity, loopback_http=allow_loopback_http, identity=True)
    return f"Web identity {why}" if why else None


def is_web_identity(identity: Any, *, allow_loopback_http: bool = False) -> bool:
    """True when ``identity`` is a valid web identity (see :func:`check_web_identity`)."""
    return check_web_identity(identity, allow_loopback_http=allow_loopback_http) is None


# ── Keys ──────────────────────────────────────────────────────────────────────

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_key(public_key: Union[Ed25519PublicKey, bytes, bytearray]) -> bytes:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise TypeError("An Ed25519 public key is 32 bytes")
    return bytes(public_key)


def ed25519_jwk_thumbprint(public_key: Union[Ed25519PublicKey, bytes]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of an Ed25519 public key.

    The hash of ``{"crv":"Ed25519","kty":"OKP","x":"<x>"}``. Used as the
    default ``kid``, so the same key always gets the same key id.
    """
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + _b64u(_raw_key(public_key)) + '"}'
    return _b64u(hashlib.sha256(canonical.encode("utf-8")).digest())


def ed25519_public_key_to_jwk(public_key: Union[Ed25519PublicKey, bytes], kid: Optional[str] = None) -> dict[str, str]:
    """Encode an Ed25519 public key as a signing JWK. ``kid`` defaults to its RFC 7638 thumbprint."""
    raw = _raw_key(public_key)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw), "kid": kid or ed25519_jwk_thumbprint(raw), "use": "sig", "alg": "EdDSA"}


#: Members that carry private or symmetric key material in a JWK (RFC 7518 §6).
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
_X_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def jwk_to_ed25519_public_key(jwk: Any) -> Optional[bytes]:
    """Decode a JWK to a raw Ed25519 public key, or None when it cannot verify a signature.

    Accepted: ``kty`` "OKP", ``crv`` "Ed25519", ``x`` exactly 32 bytes in
    canonical base64url, ``use`` absent or "sig", ``key_ops`` absent or
    containing "verify", ``alg`` absent or "EdDSA" / "Ed25519".
    """
    if not isinstance(jwk, dict):
        return None
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        return None
    if "use" in jwk and jwk["use"] != "sig":
        return None
    if "key_ops" in jwk and not (isinstance(jwk["key_ops"], list) and "verify" in jwk["key_ops"]):
        return None
    if "alg" in jwk and jwk["alg"] not in ("EdDSA", "Ed25519"):
        return None
    x = jwk["x"]
    if _X_RE.fullmatch(x) is None:
        return None
    key = base64.urlsafe_b64decode(x + "=")
    # Round-trip: 43 base64url characters can spell 32 bytes more than one
    # way. Only the canonical spelling is a key.
    return key if len(key) == 32 and _b64u(key) == x else None


@dataclass(frozen=True)
class WebIdentityKeySelection:
    ok: bool
    key: Optional[bytes] = None
    kid: Optional[str] = None
    reason: Optional[str] = None


def select_web_identity_key(jwks: Any) -> WebIdentityKeySelection:
    """Choose the signing key from a JWK Set: the FIRST key :func:`jwk_to_ed25519_public_key` accepts.

    The first and not "any" because a mandate token carries no key id and a
    resolver returns one key; one rule every implementation applies the same
    way matters more than flexibility. To rotate, publish the new key first.

    A set containing ANY private or symmetric key material is refused outright.
    """
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return WebIdentityKeySelection(False, reason="key set has no keys array")
    for k in jwks["keys"]:
        if isinstance(k, dict) and any(m in k for m in _PRIVATE_JWK_MEMBERS):
            return WebIdentityKeySelection(False, reason="key set contains private key material")
    for k in jwks["keys"]:
        key = jwk_to_ed25519_public_key(k)
        if key is not None:
            kid = k.get("kid")
            return WebIdentityKeySelection(True, key=key, kid=kid if isinstance(kid, str) else None)
    return WebIdentityKeySelection(False, reason="key set has no Ed25519 signing key")


# ── Document ──────────────────────────────────────────────────────────────────

_RESERVED_DOCUMENT_MEMBERS = ("client_id", "jwks", "jwks_uri", "client_secret", "client_secret_expires_at")


def build_web_identity_document(
    identity: str,
    public_key: Union[Ed25519PublicKey, bytes],
    *,
    kid: Optional[str] = None,
    name: Optional[str] = None,
    uri: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
    allow_loopback_http: bool = False,
) -> dict[str, Any]:
    """Build the JSON document to serve at a web identity's URL.

    Serve it as ``application/json`` with HTTP 200 and no redirect. Raises
    ValueError on an invalid identity or reserved ``extra`` member and
    TypeError on a bad key, so a document no verifier would accept is never
    produced.
    """
    why = check_web_identity(identity, allow_loopback_http=allow_loopback_http)
    if why:
        raise ValueError(why)
    for member in _RESERVED_DOCUMENT_MEMBERS:
        if extra and member in extra:
            raise ValueError(f"build_web_identity_document: extra must not set {member}")
    doc: dict[str, Any] = dict(extra or {})
    doc["client_id"] = identity
    if name is not None:
        doc["client_name"] = name
    if uri is not None:
        doc["client_uri"] = uri
    doc["jwks"] = {"keys": [ed25519_public_key_to_jwk(public_key, kid)]}
    return doc


# ── Resolution ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WebIdentityResponse:
    """What a fetch returns: the HTTP status, the body bytes and the Cache-Control header."""

    status: int
    body: bytes
    cache_control: Optional[str] = None


#: ``fetch(url, timeout_s, max_bytes) -> WebIdentityResponse``. Must not follow
#: redirects; may return at most ``max_bytes + 1`` body bytes.
WebIdentityFetch = Callable[[str, float, int], WebIdentityResponse]


@dataclass(frozen=True)
class WebIdentityResolution:
    ok: bool
    key: Optional[bytes] = None
    kid: Optional[str] = None
    document: Optional[dict[str, Any]] = None
    reason: Optional[str] = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None  # the 3xx is then reported as an HTTPError, i.e. "not HTTP 200"


def _default_fetch(url: str, timeout_s: float, max_bytes: int) -> WebIdentityResponse:
    """GET with no redirects, a timeout, and a streamed size cap."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            declared = resp.headers.get("Content-Length")
            if declared is not None and declared.strip().isdigit() and int(declared) > max_bytes:
                return WebIdentityResponse(resp.status, b"\0" * (max_bytes + 1))
            return WebIdentityResponse(resp.status, resp.read(max_bytes + 1), resp.headers.get("Cache-Control"))
    except urllib.error.HTTPError as e:
        return WebIdentityResponse(e.code, b"")


def _fetch_json(url: str, max_bytes: int, fetch: Optional[WebIdentityFetch], timeout_s: float) -> tuple[Any, Optional[str], Optional[str]]:
    """Returns (json, cache_control, None) or (None, None, reason)."""
    try:
        res = (fetch or _default_fetch)(url, timeout_s, max_bytes)
    except Exception:
        return None, None, f"GET {url} failed"
    if res.status != 200:
        return None, None, f"GET {url} did not return HTTP 200"
    if len(res.body) > max_bytes:
        return None, None, f"GET {url} returned more than {max_bytes} bytes"
    try:
        text = res.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, None, f"GET {url} returned a body that is not UTF-8"
    try:
        return json.loads(text), res.cache_control, None
    except ValueError:
        return None, None, f"GET {url} did not return JSON"


def _cache_lifetime(cache_control: Optional[str], ceiling_s: float) -> float:
    """How long a response may be reused, seconds, from its Cache-Control and the configured ceiling."""
    if ceiling_s <= 0:
        return 0.0
    if not cache_control:
        return ceiling_s
    directives = [d.strip() for d in cache_control.lower().split(",")]
    if "no-store" in directives or "no-cache" in directives:
        return 0.0
    for d in directives:
        m = re.fullmatch(r"max-age=(\d+)", d)
        if m:
            return min(ceiling_s, float(m.group(1)))
    return ceiling_s


# ── Address check ─────────────────────────────────────────────────────────────

_SPECIAL_USE_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
)]
_SPECIAL_USE_V6 = [ipaddress.ip_network(n) for n in (
    "::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
    "fc00::/7", "fe80::/10", "ff00::/8",
)]
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V4_STRICT = re.compile(r"(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})")


def is_special_use_address(address: Any) -> bool:
    """True when ``address`` is a special-use address a verifier must not fetch from.

    Loopback, private, link-local, shared, documentation, benchmarking,
    multicast, reserved and unspecified ranges (RFC 6890 and its registry),
    IPv6 unique-local and transition ranges, and IPv4-mapped or NAT64 forms of
    a special-use IPv4 address. Text that is not an address counts as
    special-use, so an unexpected resolver answer is refused, not fetched.

    The same list is in every SDK and pinned by ``addresses`` in
    ``test-vectors/web-identity-v1.json``.
    """
    if not isinstance(address, str):
        return True
    text = address.split("%")[0]
    if ":" not in text and _V4_STRICT.fullmatch(text) is None:
        return True  # leading zeros, wrong octet count, or not an address at all
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and (ip in _V4_MAPPED or ip in _NAT64):
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    nets = _SPECIAL_USE_V4 if isinstance(ip, ipaddress.IPv4Address) else _SPECIAL_USE_V6
    return any(ip in n for n in nets)


#: ``lookup(hostname) -> list of address strings``.
WebIdentityAddressLookup = Callable[[str], list[str]]


def _system_lookup(hostname: str) -> list[str]:
    """Every address the operating system's resolver returns for ``hostname``."""
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})


def _refusal(
    url: str,
    *,
    allow_host: Optional[Callable[[str], bool]],
    lookup: Union[WebIdentityAddressLookup, bool, None],
    custom_fetch: bool,
    allow_loopback_http: bool,
) -> Optional[str]:
    """Why ``url`` must not be fetched, or None.

    Two checks, in this order: the verifier's own ``allow_host``, then the
    addresses the host name resolves to. The address check is what keeps a
    hostile token from pointing a verifier at its own network:
    ``https://intranet.example.com/x`` is a well-formed identity, and only its
    DNS answer shows that it is 10.0.0.5. It runs with ``lookup`` when one is
    given; with the system resolver when the request will be made by the
    built-in fetch (a custom ``fetch`` owns its own network policy); and not
    at all when ``lookup`` is False. It refuses the request if ANY address is
    special-use, and if the lookup fails.

    It does not pin the connection to the vetted address: the request resolves
    the name again, so a resolver that changes its answer between the two can
    still get through. Deployments that need that closed use a pinning client
    (``fetch``) or an egress policy.
    """
    hostname = urlsplit(url).hostname or ""
    if allow_host is not None and allow_host(hostname) is not True:
        return f"Host of {url} is not allowed by this verifier"
    if lookup is False:
        return None
    if allow_loopback_http and hostname in ("localhost", "127.0.0.1"):
        return None
    resolver = lookup if callable(lookup) else (None if custom_fetch else _system_lookup)
    if resolver is None:
        return None
    try:
        addresses = resolver(hostname)
    except Exception:
        return f"Host of {url} could not be resolved"
    if not isinstance(addresses, (list, tuple)) or len(addresses) == 0:
        return f"Host of {url} could not be resolved"
    if any(is_special_use_address(a) for a in addresses):
        return f"Host of {url} resolves to a special-use address"
    return None


def _resolve_uncached(
    identity: str,
    *,
    fetch: Optional[WebIdentityFetch],
    timeout_s: float,
    max_document_bytes: int,
    max_jwks_bytes: int,
    max_cache_s: float,
    allow_loopback_http: bool,
    allow_host: Optional[Callable[[str], bool]],
    lookup: Union[WebIdentityAddressLookup, bool, None] = None,
) -> tuple[WebIdentityResolution, float]:
    def fail(reason: str) -> tuple[WebIdentityResolution, float]:
        return WebIdentityResolution(False, reason=reason), 0.0

    why = check_web_identity(identity, allow_loopback_http=allow_loopback_http)
    if why:
        return fail(why)
    refused = _refusal(identity, allow_host=allow_host, lookup=lookup, custom_fetch=fetch is not None, allow_loopback_http=allow_loopback_http)
    if refused:
        return fail(refused)

    doc, cache_control, reason = _fetch_json(identity, max_document_bytes, fetch, timeout_s)
    if reason:
        return fail(reason)
    if not isinstance(doc, dict):
        return fail("Identity document is not a JSON object")
    # Simple string comparison, as the OAuth draft requires: the document must
    # name the URL it was fetched from, or one host could serve another's.
    if doc.get("client_id") != identity or not isinstance(doc.get("client_id"), str):
        return fail("Identity document client_id does not equal the identity")
    if "client_secret" in doc or "client_secret_expires_at" in doc:
        return fail("Identity document carries a client secret")

    has_jwks = "jwks" in doc
    has_jwks_uri = "jwks_uri" in doc
    if has_jwks and has_jwks_uri:
        return fail("Identity document has both jwks and jwks_uri")
    if not has_jwks and not has_jwks_uri:
        return fail("Identity document publishes no keys (jwks or jwks_uri)")

    jwks = doc.get("jwks")
    lifetime = _cache_lifetime(cache_control, max_cache_s)
    if has_jwks_uri:
        jwks_uri = doc["jwks_uri"]
        uri_why = _check_url(jwks_uri, loopback_http=allow_loopback_http, identity=False)
        if uri_why:
            return fail(f"Identity document jwks_uri {uri_why}")
        keys_refused = _refusal(jwks_uri, allow_host=allow_host, lookup=lookup, custom_fetch=fetch is not None, allow_loopback_http=allow_loopback_http)
        if keys_refused:
            return fail(keys_refused)
        jwks, keys_cache_control, reason = _fetch_json(jwks_uri, max_jwks_bytes, fetch, timeout_s)
        if reason:
            return fail(reason)
        lifetime = min(lifetime, _cache_lifetime(keys_cache_control, max_cache_s))

    selected = select_web_identity_key(jwks)
    if not selected.ok:
        return fail(f"Identity document {selected.reason}")
    return WebIdentityResolution(True, key=selected.key, kid=selected.kid, document=doc), lifetime


def resolve_web_identity(
    identity: str,
    *,
    fetch: Optional[WebIdentityFetch] = None,
    timeout_s: float = WEB_IDENTITY_FETCH_TIMEOUT_S,
    max_document_bytes: int = WEB_IDENTITY_MAX_DOCUMENT_BYTES,
    max_jwks_bytes: int = WEB_IDENTITY_MAX_JWKS_BYTES,
    allow_loopback_http: bool = False,
    allow_host: Optional[Callable[[str], bool]] = None,
    lookup: Union[WebIdentityAddressLookup, bool, None] = None,
) -> WebIdentityResolution:
    """Resolve a web identity to its current Ed25519 public key, with the reason when it cannot be resolved.

    Does not cache (use :func:`create_web_identity_resolver`). Never raises.
    """
    try:
        return _resolve_uncached(
            identity, fetch=fetch, timeout_s=timeout_s, max_document_bytes=max_document_bytes,
            max_jwks_bytes=max_jwks_bytes, max_cache_s=0.0, allow_loopback_http=allow_loopback_http, allow_host=allow_host, lookup=lookup,
        )[0]
    except Exception as e:  # pragma: no cover - defensive: the contract is "never raises"
        return WebIdentityResolution(False, reason=f"Web identity resolution failed: {e}")


def create_web_identity_resolver(
    *,
    fetch: Optional[WebIdentityFetch] = None,
    timeout_s: float = WEB_IDENTITY_FETCH_TIMEOUT_S,
    max_document_bytes: int = WEB_IDENTITY_MAX_DOCUMENT_BYTES,
    max_jwks_bytes: int = WEB_IDENTITY_MAX_JWKS_BYTES,
    max_cache_s: float = WEB_IDENTITY_MAX_CACHE_S,
    allow_loopback_http: bool = False,
    allow_host: Optional[Callable[[str], bool]] = None,
    lookup: Union[WebIdentityAddressLookup, bool, None] = None,
    on_failure: Optional[Callable[[str, str], None]] = None,
    now: Optional[Callable[[], float]] = None,
) -> Callable[[str], Optional[bytes]]:
    """A key resolver for web identities, with a bounded in-memory cache.

    Returns None for anything that is not an http(s) URL, and None (after
    calling ``on_failure(identity, reason)``) for a web identity that cannot
    be resolved; a verifier then rejects the mandate (fail closed).

    ``max_cache_s`` is the longest time a resolved key is reused; a shorter
    ``Cache-Control: max-age`` is honoured and ``no-store`` / ``no-cache``
    disable reuse. It is also how long a key removed from the document keeps
    verifying. ``allow_host(hostname)`` is asked before each request.

    ``lookup(hostname)`` returns the addresses a host resolves to, so a
    request to a special-use address (see :func:`is_special_use_address`) is
    refused before it is made. Default: the system resolver when the built-in
    fetch makes the request; none when ``fetch`` is replaced. ``False`` turns
    the check off, for a verifier whose network already denies those ranges.
    """
    clock = now or time.monotonic
    cache: dict[str, tuple[float, bytes]] = {}
    lock = threading.Lock()

    def resolve(identity: str) -> Optional[bytes]:
        if not looks_like_web_identity(identity):
            return None
        with lock:
            hit = cache.get(identity)
            if hit is not None:
                if hit[0] > clock():
                    return hit[1]
                del cache[identity]
        try:
            result, lifetime = _resolve_uncached(
                identity, fetch=fetch, timeout_s=timeout_s, max_document_bytes=max_document_bytes,
                max_jwks_bytes=max_jwks_bytes, max_cache_s=max_cache_s, allow_loopback_http=allow_loopback_http, allow_host=allow_host, lookup=lookup,
            )
        except Exception as e:
            result, lifetime = WebIdentityResolution(False, reason=f"Web identity resolution failed: {e}"), 0.0
        if not result.ok or result.key is None:
            # Failures are never cached: a document that was briefly
            # unreachable must not lock an identity out for the cache lifetime.
            if on_failure is not None:
                try:
                    on_failure(identity, result.reason or "unknown")
                except Exception:
                    pass  # a logging hook that raises must not change the outcome
            return None
        if lifetime > 0:
            with lock:
                if len(cache) >= _CACHE_MAX_ENTRIES:
                    del cache[next(iter(cache))]
                cache[identity] = (clock() + lifetime, result.key)
        return result.key

    return resolve
