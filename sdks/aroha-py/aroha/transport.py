# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Layer 0: Transport

HTTP server (FastAPI) and async HTTP client (httpx).
Mirrors aroha-core/src/transport/ from the TypeScript SDK.
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from aroha.identity import DIDDocument
from aroha.messages import (
    ArohaEnvelope,
    NonceRegistry,
    validate_envelope,
)
from aroha.safety import (
    MAX_BODY_BYTES,
    BodySizeLimitMiddleware,
    require_dev_mode,
    require_secure_url,
)

# ── Types ──────────────────────────────────────────────────────────────────────

MessageHandler = Callable[
    [ArohaEnvelope],
    Awaitable[Optional[ArohaEnvelope]],
]

PublicKeyResolver = Callable[
    [str],  # sender DID
    Awaitable[Any],  # Ed25519PublicKey | None
]

# ── Server ─────────────────────────────────────────────────────────────────────

class ArohaServer:
    """
    Aroha protocol server. Handles:
      - GET /.well-known/aroha-agent.json  → DID Document
      - POST /aroha/v1                     → inbound message dispatch

    Args:
        agent_did:          This agent's DID.
        did_document:       The DID Document served at the well-known endpoint.
        on_message:         Async callback invoked for every valid inbound envelope.
        resolve_public_key: Async function that returns the sender's public key
                            given their DID, or None if unknown.
        dev_mode:           Skip ALL cryptographic validation (signature, nonce
                            replay, expiry). Intended for local development and
                            hackathons — never set True in production. Refused
                            (DevModeNotPermitted) unless the environment sets
                            AROHA_DEV_MODE=1; prints a warning to stderr when on.
                            Flip to False and the full zero-trust pipeline
                            re-engages with no handler code changes required.
        nonce_registry:     Replay store (default: in-memory NonceRegistry).
                            Pass a FileNonceStore-backed registry or your own
                            shared store for restarts / multiple instances.
        max_body_bytes:     Request bodies above this are rejected with 413
                            before parsing (default 1 MiB).
    """

    def __init__(
        self,
        agent_did: str,
        did_document: DIDDocument,
        on_message: MessageHandler,
        resolve_public_key: PublicKeyResolver,
        dev_mode: bool = False,
        *,
        nonce_registry: Optional[NonceRegistry] = None,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        if dev_mode:
            require_dev_mode("ArohaServer dev_mode")
        self.agent_did = agent_did
        self.did_document = did_document
        self.on_message = on_message
        self.resolve_public_key = resolve_public_key
        self.dev_mode = dev_mode
        self.max_body_bytes = max_body_bytes
        self._nonce_registry = nonce_registry if nonce_registry is not None else NonceRegistry()
        self.app = self._build_app()

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Aroha Agent", docs_url=None, redoc_url=None)
        app.add_middleware(BodySizeLimitMiddleware, max_bytes=self.max_body_bytes)

        @app.get("/.well-known/aroha-agent.json")
        async def well_known():
            return self.did_document.to_dict()

        @app.post("/aroha/v1")
        async def receive_message(request: Request):
            try:
                envelope: ArohaEnvelope = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            # ── Dev mode: skip all crypto — localhost / hackathon mode ────────
            if self.dev_mode:
                reply = await self.on_message(envelope)
                if reply is not None:
                    return JSONResponse(reply, status_code=200)
                return Response(status_code=202)

            # Resolve sender public key
            sender_did = envelope.get("from", "")
            pub_key = await self.resolve_public_key(sender_did)
            if pub_key is None:
                return JSONResponse({"error": "Unknown sender DID"}, status_code=401)

            # Validate envelope
            valid, reason = validate_envelope(
                envelope, pub_key, self.agent_did, self._nonce_registry
            )
            if not valid:
                return JSONResponse({"error": reason}, status_code=401)

            # Dispatch to application handler
            reply = await self.on_message(envelope)

            if reply is not None:
                return JSONResponse(reply, status_code=200)
            return Response(status_code=202)  # Async — response via WebSocket

        return app

    def run(self, host: str = "127.0.0.1", port: int = 3001) -> None:
        """Run the server (blocking). For async use, pass self.app to uvicorn directly.

        Binds to loopback by default; pass ``host="0.0.0.0"`` (or a specific
        interface) to accept connections from other machines.
        """
        import uvicorn
        uvicorn.run(self.app, host=host, port=port)


# ── Client ─────────────────────────────────────────────────────────────────────

class ArohaClient:
    """Async Aroha message client using httpx.

    Endpoints must be https, except loopback hosts (127.0.0.0/8, ::1,
    localhost). Pass ``allow_insecure_http=True`` to permit plain http to
    other hosts on a network you control.
    """

    def __init__(self, timeout: float = 30.0, *, allow_insecure_http: bool = False) -> None:
        self._timeout = timeout
        self._allow_insecure_http = allow_insecure_http

    async def send(
        self,
        endpoint: str,
        envelope: ArohaEnvelope,
        timeout: Optional[float] = None,
    ) -> Optional[ArohaEnvelope]:
        """
        Send a Aroha message and await a synchronous response.

        Returns None on 202 (async capability — use WebSocket stream instead).
        Raises ArohaTransportError on HTTP errors and InsecureEndpointError for
        a non-https, non-loopback endpoint.
        """
        require_secure_url(endpoint, allow_insecure_http=self._allow_insecure_http)
        async with httpx.AsyncClient(timeout=timeout or self._timeout) as client:
            response = await client.post(
                endpoint,
                json=envelope,
                headers={"Content-Type": "application/json"},
            )

        if response.status_code == 202:
            return None

        if not response.is_success:
            raise ArohaTransportError(response.status_code, response.text)

        return response.json()

    async def fetch_did_document(self, base_url: str) -> dict[str, Any]:
        """Fetch the DID Document from an agent's well-known endpoint."""
        require_secure_url(base_url, allow_insecure_http=self._allow_insecure_http)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(f"{base_url}/.well-known/aroha-agent.json")
        response.raise_for_status()
        return response.json()


class ArohaTransportError(Exception):
    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Aroha transport error {status_code}: {body}")
        self.status_code = status_code
        self.body = body
