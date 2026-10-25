# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.safety — transport safety defaults shared by the server and client helpers.

* Dev-mode gate. Any switch that turns off envelope verification
  (``ArohaServer(dev_mode=True)``, ``validate_envelope(skip_signature=True)``)
  is refused unless the process environment sets ``AROHA_DEV_MODE=1``. When it
  is on, a one-time warning is printed to stderr. This mirrors the TypeScript
  server, which refuses ``devMode`` unless ``NODE_ENV=development``; the
  non-JavaScript SDKs use ``AROHA_DEV_MODE`` instead because ``NODE_ENV`` means
  nothing outside Node.
* HTTPS-only clients. Outbound helpers refuse a plain ``http://`` endpoint
  unless its host is loopback (``127.0.0.0/8``, ``::1``, ``localhost``) or the
  caller passes ``allow_insecure_http=True``.
* Request body cap. Servers reject request bodies larger than
  :data:`MAX_BODY_BYTES` (1 MiB) with HTTP 413 before any parsing.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

__all__ = [
    "DEV_MODE_ENV",
    "MAX_BODY_BYTES",
    "DevModeNotPermitted",
    "InsecureEndpointError",
    "dev_mode_permitted",
    "require_dev_mode",
    "is_loopback_host",
    "require_secure_url",
    "BodySizeLimitMiddleware",
]

#: Environment variable that must equal ``"1"`` for dev-mode switches to be accepted.
DEV_MODE_ENV = "AROHA_DEV_MODE"

#: Largest request body a server accepts (1 MiB); larger bodies get HTTP 413.
MAX_BODY_BYTES = 1 << 20

_warned: set[str] = set()
_warn_lock = threading.Lock()


class DevModeNotPermitted(RuntimeError):
    """A verification-disabling switch was requested without ``AROHA_DEV_MODE=1``."""


class InsecureEndpointError(ValueError):
    """An outbound endpoint is not https and is not explicitly allowed."""


def dev_mode_permitted() -> bool:
    """True when the environment explicitly opts in to dev mode (``AROHA_DEV_MODE=1``)."""
    return os.environ.get(DEV_MODE_ENV, "").strip() == "1"


def require_dev_mode(feature: str) -> None:
    """Refuse ``feature`` unless ``AROHA_DEV_MODE=1``; warn once on stderr when allowed."""
    if not dev_mode_permitted():
        current = os.environ.get(DEV_MODE_ENV)
        shown = repr(current) if current is not None else "(unset)"
        raise DevModeNotPermitted(
            f"[Aroha] {feature} can only be enabled when {DEV_MODE_ENV}=1. "
            f"Current {DEV_MODE_ENV}: {shown}. "
            f"Remove it before deploying."
        )
    with _warn_lock:
        if feature in _warned:
            return
        _warned.add(feature)
    print(
        f"[Aroha] WARNING: {feature} is ENABLED — cryptographic validation is bypassed. "
        "Never use dev mode in production.",
        file=sys.stderr,
        flush=True,
    )


def is_loopback_host(host: str | None) -> bool:
    """True for ``localhost`` (and ``*.localhost``), ``127.0.0.0/8`` and ``::1``."""
    if not host:
        return False
    h = host.strip("[]").rstrip(".").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def require_secure_url(url: str, *, allow_insecure_http: bool = False, what: str = "endpoint") -> str:
    """Return ``url`` if it is https (or http to a loopback host); raise otherwise.

    ``allow_insecure_http=True`` accepts plain http to any host — for a
    private network you control. It never accepts another scheme.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "https" and parts.hostname:
        return url
    if scheme == "http" and parts.hostname:
        if allow_insecure_http or is_loopback_host(parts.hostname):
            return url
        raise InsecureEndpointError(
            f"[Aroha] Refusing plain-http {what} {url!r}: messages and credentials would travel unencrypted. "
            "Use https, a loopback host, or pass allow_insecure_http=True for a network you control."
        )
    raise InsecureEndpointError(f"[Aroha] Unsupported {what} URL {url!r}: expected an https:// URL")


class BodySizeLimitMiddleware:
    """ASGI middleware: reject HTTP request bodies larger than ``max_bytes`` with 413.

    The body is buffered (up to the cap) before the application sees it, so a
    handler that parses JSON never receives an oversized payload. A declared
    ``Content-Length`` over the cap is rejected without reading the body.
    """

    def __init__(self, app: Callable[..., Awaitable[None]], max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        body = json.dumps({"error": "Payload too large"}).encode()
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Callable[[], Awaitable[dict[str, Any]]],
                       send: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or []:
            if name.lower() == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = -1
                if declared > self.max_bytes:
                    await self._reject(send)
                    return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"") or b""
            total += len(chunk)
            if total > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        data = b"".join(chunks)
        delivered = False

        async def replay() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": data, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
