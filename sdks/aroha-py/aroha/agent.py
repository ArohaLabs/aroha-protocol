# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.agent — The /v1/run server decorator

Wraps any Python callable (or framework agent) into an Aroha-compliant
FastAPI server exposing:

  POST /v1/run                       — invoke the agent (stream:true for SSE)
  POST /v1/resume                    — resolve a pending HITL approval
  POST /mcp         (expose_mcp=True)— MCP JSON-RPC endpoint
  GET  /health                       — liveness probe
  GET  /.well-known/aroha-agent.json — manifest

Quick start:
    from aroha.agent import serve

    @serve(name="My Agent")
    async def my_agent(message: str, session_id: str | None, history: list, **kw) -> str:
        return "Hello!"

    if __name__ == "__main__":
        my_agent.start(port=8000)

Typed SSE events (stream=True):
    data: {"type":"token","delta":"..."}\n\n
    data: {"type":"tool_call","id":"...","name":"...","args":{...}}\n\n
    data: {"type":"final","message":"...","sessionId":"..."}\n\n
    data: {"type":"error","requestId":"...","message":"..."}\n\n
"""

from __future__ import annotations

import asyncio
import hmac
import hashlib
import inspect
import json as _json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .safety import MAX_BODY_BYTES, BodySizeLimitMiddleware
from .signing import (
    DEFAULT_MAX_SKEW_MS,
    NonceGuard,
    registry_key_resolver,
    verify_signed_request,
)

logger = logging.getLogger(__name__)

#: Key under which a handler's ``context`` carries the verified caller DID
#: (auth="aroha-sig" only). Set by the server, never taken from the request.
CALLER_CONTEXT_KEY = "arohaCaller"

# ── Wire types ─────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    message:   str
    sessionId: str | None = None
    history:   list[dict[str, str]] = []
    context:   dict[str, Any] = {}
    stream:    bool = False
    trust:     str = "trusted"   # "trusted" | "untrusted"

class RunResponse(BaseModel):
    message:   str
    sessionId: str
    artifacts: list[Any] = []
    usage:     dict[str, int] = {}

class ResumeRequest(BaseModel):
    sessionId:  str
    approvalId: str
    decision:   str   # "approve" | "edit" | "reject" | "respond"
    payload:    Any = None

# ── In-memory session store ────────────────────────────────────────────────────

class InMemorySessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, list[dict[str, str]]] = {}

    def load(self, session_id: str) -> list[dict[str, str]]:
        return list(self._sessions.get(session_id, []))

    def append(self, session_id: str, messages: list[dict[str, str]]) -> None:
        existing = self._sessions.get(session_id, [])
        self._sessions[session_id] = existing + messages

    def clear(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

# ── Typed SSE helpers ──────────────────────────────────────────────────────────

def _sse(event: dict[str, Any]) -> str:
    return f"data: {_json.dumps(event)}\n\n"

def _token(delta: str) -> str:
    return _sse({"type": "token", "delta": delta})

def _final(message: str, session_id: str, artifacts: list = [], usage: dict = {}) -> str:
    return _sse({"type": "final", "message": message, "sessionId": session_id,
                 **({"artifacts": artifacts} if artifacts else {}),
                 **({"usage": usage} if usage else {})})

def _error(request_id: str, message: str) -> str:
    return _sse({"type": "error", "requestId": request_id, "message": message})

def _approval_required(approval_id: str, action: Any) -> str:
    return _sse({"type": "approval_required", "id": approval_id, "action": action})

# ── ArohaAgent ─────────────────────────────────────────────────────────────────

@dataclass
class ArohaAgent:
    name:              str
    handler:           Callable[..., Awaitable[str] | str]
    description:       str        = ""
    provider:          str        = "anthropic"
    model:             str        = "claude-sonnet-4-6"
    system_prompt:     str        = ""
    memory:            str        = "none"
    # "aroha-sig" — per-caller identity (default): requests must be
    #               Ed25519-signed by the calling agent's DID key. Use with
    #               allowed_callers for a private agent only specific agents
    #               may call.
    # "bearer"    — shared secret; every holder is indistinguishable
    # "none"      — open to anyone who can reach the port; opt in explicitly
    auth:              str        = "aroha-sig"
    version:           str        = "1.0"
    bearer_tokens:     set[str]   = field(default_factory=set)
    verify_bearer:     Callable[[str], bool] | None = field(default=None, repr=False)
    #: DIDs permitted to call this agent (auth="aroha-sig"). None accepts any
    #: caller whose signature verifies — attribution rather than restriction.
    #: A caller outside the list is rejected before any key resolution happens.
    allowed_callers:   list[str] | None = None
    #: Resolves a caller DID to its raw Ed25519 public key. Defaults to the
    #: Aroha registry. Return None for unknown DIDs — those are rejected.
    resolve_caller_key: Callable[[str], bytes | None] | None = field(default=None, repr=False)
    #: Reject replayed (did, nonce) pairs. Defaults to an in-process guard.
    consume_nonce:     Callable[[str, str], bool] | None = field(default=None, repr=False)
    #: Accepted clock skew for signed requests, in milliseconds.
    max_skew_ms:       int        = DEFAULT_MAX_SKEW_MS
    expose_mcp:        bool       = False
    # Optional callable: (message, trust) -> {"blocked": bool, "reason": str | None}
    content_guard:     Callable[[str, str], dict] | None = field(default=None, repr=False)
    approval_timeout:  float      = 300.0   # seconds before HITL auto-rejects
    #: Browser origins allowed by CORS. None (default) adds no CORS headers, so
    #: browsers on other origins cannot call the agent. ["*"] opts in to any.
    cors_origins:      list[str] | None = None
    #: Request bodies above this many bytes are rejected with 413 (default 1 MiB).
    max_body_bytes:    int        = MAX_BODY_BYTES
    _did:              str | None = field(default=None, init=False, repr=False)

    def _resolve_tokens(self) -> set[str]:
        tokens = set(self.bearer_tokens)
        env_token = os.environ.get("AROHA_BEARER_TOKEN", "").strip()
        if env_token:
            tokens.add(env_token)
        return tokens

    def _build_app(self) -> FastAPI:
        if self.auth not in ("aroha-sig", "bearer", "none"):
            raise ValueError(f"auth must be 'aroha-sig', 'bearer' or 'none', not {self.auth!r}")
        if self.auth == "bearer":
            effective_tokens = self._resolve_tokens()
            if not effective_tokens and self.verify_bearer is None:
                raise RuntimeError(
                    "auth='bearer' requires bearer_tokens, verify_bearer, or AROHA_BEARER_TOKEN env var."
                )

        _effective_tokens = self._resolve_tokens() if self.auth == "bearer" else set()
        _session_store    = InMemorySessionStore() if self.memory != "none" else None
        _pending_approvals: dict[str, asyncio.Future] = {}

        # Built once per app so the nonce guard's memory persists across
        # requests — a fresh guard per request would accept every replay.
        _caller_key_resolver = self.resolve_caller_key or registry_key_resolver()
        _nonce_guard = self.consume_nonce or NonceGuard(self.max_skew_ms)

        app = FastAPI(title=self.name, version=self.version, docs_url="/docs", redoc_url=None)
        if self.cors_origins:
            app.add_middleware(
                CORSMiddleware, allow_origins=list(self.cors_origins), allow_methods=["*"], allow_headers=["*"],
            )
        # Added last so it is outermost: oversized bodies are refused before
        # CORS, auth or JSON parsing see them.
        app.add_middleware(BodySizeLimitMiddleware, max_bytes=self.max_body_bytes)

        # ── Auth helper ───────────────────────────────────────────────────────

        async def _check_auth(request: Request) -> str | None:
            """Return None when authorised, else the reason to report.

            Returning the reason rather than a bool lets a signed-mode failure
            say so, instead of telling the developer to find a bearer token
            that this agent does not even use.
            """
            if self.auth == "aroha-sig":
                # Starlette caches the body, so reading it here is safe even
                # though FastAPI has already parsed it into a model. The
                # signature covers a hash of these exact bytes, so the parsed
                # model is not a substitute — re-serialising it would produce
                # different bytes and fail verification.
                raw = (await request.body()).decode("utf-8")
                result = verify_signed_request(
                    headers=request.headers,
                    method=request.method,
                    path=request.url.path,
                    body=raw,
                    resolve_public_key=_caller_key_resolver,
                    allowed_callers=self.allowed_callers,
                    max_skew_ms=self.max_skew_ms,
                    consume_nonce=_nonce_guard,
                )
                if result.ok:
                    request.state.aroha_caller = result.did
                    return None
                return result.reason or "Signature rejected"

            if self.auth != "bearer":
                return None

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return "Bearer token required"
            token = auth_header[7:].strip()
            if self.verify_bearer is not None:
                return None if self.verify_bearer(token) else "Bearer token required"
            ok = any(hmac.compare_digest(token, t) for t in _effective_tokens)
            return None if ok else "Bearer token required"

        # ── Manifest ──────────────────────────────────────────────────────────

        @app.get("/health")
        async def health():
            return {"ok": True, "agent": self.name}

        @app.get("/.well-known/aroha-agent.json")
        async def manifest():
            return {
                "arohaProtocolVersion": "1.0",
                "name":        self.name,
                "description": self.description,
                "provider":    self.provider,
                "model":       self.model,
                "memory":      {"type": self.memory},
                "auth":        {"type": self.auth},
                **({"did": self._did} if self._did else {}),
            }

        # ── /v1/resume ────────────────────────────────────────────────────────

        @app.post("/v1/resume")
        async def resume(body: ResumeRequest, request: Request):
            denied = await _check_auth(request)
            if denied:
                return JSONResponse({"error": denied}, status_code=401)

            future = _pending_approvals.get(body.approvalId)
            if future is None:
                return JSONResponse({"error": "Unknown approvalId"}, status_code=404)

            _pending_approvals.pop(body.approvalId, None)
            if not future.done():
                future.set_result({
                    "sessionId":  body.sessionId,
                    "approvalId": body.approvalId,
                    "decision":   body.decision,
                    "payload":    body.payload,
                })
            return {"ok": True}

        # ── /mcp JSON-RPC ─────────────────────────────────────────────────────

        if self.expose_mcp:
            _mcp_run_tool = {
                "name":        "run",
                "description": self.description or f"Send a message to the {self.name} agent.",
                "inputSchema": {
                    "type":       "object",
                    "properties": {
                        "message":   {"type": "string", "description": "Message to send"},
                        "sessionId": {"type": "string", "description": "Session ID"},
                    },
                    "required": ["message"],
                },
            }

            @app.post("/mcp")
            async def mcp_endpoint(request: Request):
                denied = await _check_auth(request)
                if denied:
                    return JSONResponse({"error": denied}, status_code=401)

                body = await request.json()
                method = body.get("method", "")
                rpc_id = body.get("id")

                if method == "tools/list":
                    return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": [_mcp_run_tool]}}

                if method == "tools/call":
                    params   = body.get("params", {})
                    args     = params.get("arguments", {})
                    tool_name = params.get("name", "")

                    if tool_name != "run":
                        return {"jsonrpc": "2.0", "id": rpc_id,
                                "error": {"code": -32601, "message": f"Tool not found: {tool_name}"}}

                    message    = str(args.get("message", ""))
                    session_id = args.get("sessionId") or str(uuid.uuid4())

                    try:
                        reply = await _invoke_handler(message, session_id, [], _handler_context({}, request))
                        return {"jsonrpc": "2.0", "id": rpc_id,
                                "result": {"content": [{"type": "text", "text": reply}]}}
                    except Exception as exc:
                        return {"jsonrpc": "2.0", "id": rpc_id,
                                "result": {"content": [{"type": "text", "text": str(exc)}], "isError": True}}

                return JSONResponse(
                    {"jsonrpc": "2.0", "id": rpc_id,
                     "error": {"code": -32601, "message": f"Method not found: {method}"}},
                    status_code=404,
                )

        # ── Handler invocation helper ─────────────────────────────────────────

        def _session_key(request: Request, session_id: str) -> str:
            # Session history is partitioned by WHO is asking, not only by the
            # session id the client names: a session id is chosen by the
            # caller, so keying on it alone let a second caller read a first
            # caller's history by reusing their id. Verified DID with
            # aroha-sig; a digest of the bearer token with bearer auth (the
            # token itself is never stored). With auth="none" there is no
            # identity to partition by — that opt-in mode is unauthenticated.
            caller = getattr(request.state, "aroha_caller", None)
            if caller:
                return f"did:{caller}\x00{session_id}"
            header = request.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                digest = hashlib.sha256(header[7:].strip().encode("utf-8")).hexdigest()
                return f"bearer:{digest}\x00{session_id}"
            return session_id

        def _handler_context(client_context: dict, request: Request) -> dict:
            # The verified caller DID (auth="aroha-sig") reaches the handler as
            # context[CALLER_CONTEXT_KEY]. A client-supplied value under that
            # key is dropped first, so a handler can trust what it finds there.
            ctx = {k: v for k, v in (client_context or {}).items() if k != CALLER_CONTEXT_KEY}
            caller = getattr(request.state, "aroha_caller", None)
            if caller:
                ctx[CALLER_CONTEXT_KEY] = caller
            return ctx

        async def _invoke_handler(message: str, session_id: str, history: list, context: dict) -> str:
            if inspect.iscoroutinefunction(self.handler):
                return str(await self.handler(
                    message=message, session_id=session_id, history=history, context=context,
                ))
            loop = asyncio.get_event_loop()
            return str(await loop.run_in_executor(
                None,
                lambda: self.handler(  # type: ignore[arg-type]
                    message=message, session_id=session_id, history=history, context=context,
                ),
            ))

        # ── /v1/run ───────────────────────────────────────────────────────────

        @app.post("/v1/run")
        async def run(req: RunRequest, request: Request):
            # Content guard — runs before auth check
            if self.content_guard is not None:
                guard = self.content_guard(req.message, req.trust)
                if isinstance(guard, dict) and guard.get("blocked"):
                    return JSONResponse(
                        {"error": guard.get("reason") or "Request blocked by content guard"},
                        status_code=400,
                    )

            denied = await _check_auth(request)
            if denied:
                return JSONResponse({"error": denied}, status_code=401)

            session_id = req.sessionId or str(uuid.uuid4())
            request_id = str(uuid.uuid4())
            handler_context = _handler_context(req.context, request)

            # Merge stored session history
            stored_history: list[dict[str, str]] = []
            if _session_store is not None:
                stored_history = _session_store.load(_session_key(request, session_id))
            merged_history = stored_history + req.history

            is_agen   = inspect.isasyncgenfunction(self.handler)
            do_stream = req.stream or is_agen

            if do_stream:
                async def _sse_stream():
                    accumulated = ""
                    try:
                        if is_agen:
                            async for item in self.handler(  # type: ignore[union-attr]
                                message=req.message,
                                session_id=session_id,
                                history=merged_history,
                                context=handler_context,
                            ):
                                # Handler may yield strings (token) or dicts (typed events)
                                if isinstance(item, str):
                                    accumulated += item
                                    yield _token(item)
                                elif isinstance(item, dict):
                                    ev_type = item.get("type", "")
                                    if ev_type == "token":
                                        accumulated += item.get("delta", "")
                                    elif ev_type == "approval_required":
                                        approval_id = item.get("id") or str(uuid.uuid4())
                                        yield _approval_required(approval_id, item.get("action"))
                                        # Wait for /v1/resume or timeout
                                        loop = asyncio.get_event_loop()
                                        future: asyncio.Future = loop.create_future()
                                        _pending_approvals[approval_id] = future
                                        try:
                                            await asyncio.wait_for(
                                                asyncio.shield(future),
                                                timeout=self.approval_timeout,
                                            )
                                        except asyncio.TimeoutError:
                                            _pending_approvals.pop(approval_id, None)
                                            raise TimeoutError(
                                                f"Approval {approval_id} timed out after {self.approval_timeout}s"
                                            )
                                        continue
                                    elif ev_type == "final":
                                        accumulated = item.get("message", accumulated)
                                        yield _final(accumulated, session_id)
                                        return
                                    else:
                                        yield _sse(item)
                        else:
                            reply = await _invoke_handler(
                                req.message, session_id, merged_history, handler_context,
                            )
                            accumulated = reply
                            yield _token(reply)

                        yield _final(accumulated, session_id)

                        # Persist to session store
                        if _session_store is not None and accumulated:
                            _session_store.append(_session_key(request, session_id), [
                                {"role": "user",      "content": req.message},
                                {"role": "assistant", "content": accumulated},
                            ])

                    except Exception:
                        logger.exception("Handler error [requestId=%s]", request_id)
                        yield _error(request_id, "Internal error")

                return StreamingResponse(
                    _sse_stream(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )

            # Non-streaming path
            try:
                reply = await _invoke_handler(req.message, session_id, merged_history, handler_context)

                if _session_store is not None:
                    _session_store.append(_session_key(request, session_id), [
                        {"role": "user",      "content": req.message},
                        {"role": "assistant", "content": reply},
                    ])

                return RunResponse(message=reply, sessionId=session_id)
            except Exception:
                logger.exception("Handler error [requestId=%s]", request_id)
                return JSONResponse(
                    {"error": "Internal error", "requestId": request_id},
                    status_code=500,
                )

        return app

    def start(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        """Start the Aroha agent server (blocking).

        Binds to loopback by default; pass ``host="0.0.0.0"`` (or a specific
        interface) to accept connections from other machines.
        """
        app = self._build_app()
        logger.info("Starting %s on %s:%d", self.name, host, port)
        uvicorn.run(app, host=host, port=port)

    def app(self) -> FastAPI:
        """Return the FastAPI app (for ASGI deployment or testing)."""
        return self._build_app()

    def register(
        self,
        endpoint_url: str,
        registry_url: str | None = None,
        api_key: str | None = None,
        *,
        private_key: Any = None,
        manifest_cid: str | None = None,
    ) -> dict[str, Any]:
        """Register this agent on the Aroha Hub. Returns the registry response including didHash.

        ``private_key`` (the agent's Ed25519 key) proves key possession to the
        registry; ``manifest_cid`` is the pinned manifest CID. See
        :func:`aroha.hub.register_agent`.
        """
        import os
        from aroha.hub import register_agent

        key = api_key or os.environ.get("AROHA_API_KEY")
        if not key:
            raise ValueError("Pass api_key or set AROHA_API_KEY env var")

        manifest = {
            "arohaProtocolVersion": "1.0",
            "name":         self.name,
            "description":  self.description,
            "endpoint":     endpoint_url,
            "provider":     self.provider,
            "model":        self.model,
            "systemPrompt": self.system_prompt,
            "memory":       {"type": self.memory},
            "auth":         {"type": self.auth},
            "capabilities": [],
            **({"did": self._did} if self._did else {}),
            **({"cid": manifest_cid} if manifest_cid else {}),
        }
        return register_agent(manifest, endpoint_url, key, registry_url, private_key=private_key)


# ── @serve decorator ───────────────────────────────────────────────────────────

def serve(
    name: str,
    *,
    description:      str = "",
    provider:         str = "anthropic",
    model:            str = "claude-sonnet-4-6",
    system_prompt:    str = "",
    memory:           str = "none",
    auth:             str = "aroha-sig",
    bearer_tokens:    set[str] | list[str] | None = None,
    verify_bearer:    Callable[[str], bool] | None = None,
    allowed_callers:  list[str] | None = None,
    resolve_caller_key: Callable[[str], bytes | None] | None = None,
    consume_nonce:    Callable[[str, str], bool] | None = None,
    max_skew_ms:      int = DEFAULT_MAX_SKEW_MS,
    expose_mcp:       bool = False,
    content_guard:    Callable[[str, str], dict] | None = None,
    approval_timeout: float = 300.0,
    cors_origins:     list[str] | None = None,
    max_body_bytes:   int = MAX_BODY_BYTES,
) -> Callable:
    """
    Decorator that wraps a handler into an ArohaAgent with a full /v1/run server.

    New in v1.1:
      memory="session"   — auto-persists conversation history per sessionId
      expose_mcp=True    — mounts /mcp (MCP JSON-RPC, works with Claude Desktop)
      content_guard      — callable(message, trust) -> {"blocked": bool, "reason": ...}
      approval_timeout   — seconds before a pending HITL approval auto-rejects (default 300)
      trust field        — handlers receive trust:"trusted"|"untrusted" on RunRequest
      typed SSE events   — token | tool_call | approval_required | final | error

    Security defaults (2.0): auth="aroha-sig" is the default; pass
    auth="none" explicitly for an open agent. No CORS headers unless
    cors_origins is given. start() binds 127.0.0.1 unless host is given.
    Request bodies over max_body_bytes (1 MiB) get 413.

    Private agents: auth="aroha-sig" requires every request to be
    Ed25519-signed by the calling agent's DID key, so the agent knows *which*
    agent is calling rather than merely that a shared secret was presented.
    Pair it with allowed_callers to restrict access; omit allowed_callers to
    accept any verifiable caller when you only want attribution.

    Usage:
        @serve(name="My Agent", auth="bearer", bearer_tokens={"secret"}, memory="session")
        async def my_agent(message, session_id, history, context, **kw):
            return "Hello!"

        @serve(name="Private Agent", auth="aroha-sig",
               allowed_callers=["did:aroha:alice"])
        async def private_agent(message, **kw):
            return "Only Alice reaches this."

        my_agent.start(port=8000)
    """
    def decorator(fn: Callable) -> ArohaAgent:
        return ArohaAgent(
            name=name,
            handler=fn,
            description=description,
            provider=provider,
            model=model,
            system_prompt=system_prompt,
            memory=memory,
            auth=auth,
            bearer_tokens=set(bearer_tokens) if bearer_tokens else set(),
            verify_bearer=verify_bearer,
            allowed_callers=allowed_callers,
            resolve_caller_key=resolve_caller_key,
            consume_nonce=consume_nonce,
            max_skew_ms=max_skew_ms,
            expose_mcp=expose_mcp,
            content_guard=content_guard,
            approval_timeout=approval_timeout,
            cors_origins=cors_origins,
            max_body_bytes=max_body_bytes,
        )
    return decorator
