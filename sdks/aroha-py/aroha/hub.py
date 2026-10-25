# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.hub — Aroha Registry client

Synchronous helpers for registering and resolving agents, MCPs, and skills
on the Aroha Hub registry.

Usage:
    import os
    from aroha.hub import register_agent, resolve_agent

    # Register
    result = register_agent(
        manifest={"name": "My Agent", ...},
        endpoint_url="https://my-agent.fly.dev",
        api_key=os.environ["AROHA_API_KEY"],
    )
    print(result["didHash"])

    # Resolve
    agent = resolve_agent(did_hash="abc123")
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .identity import to_multibase

from .endpoints import AROHA_MANAGED_REGISTRY_URL, resolve_registry_url
from .safety import require_secure_url
from .signing import sign_request

#: Kept for backward compatibility; the default registry is resolved per call
#: (``registry_url`` argument → ``AROHA_REGISTRY_URL`` → this constant).
REGISTRY = AROHA_MANAGED_REGISTRY_URL


# ── Agents ─────────────────────────────────────────────────────────────────────

def registration_challenge_message(did: str, nonce: str) -> bytes:
    """Bytes a registrant signs to prove key possession.

    The registry verifies ``JSON.stringify({action: "prove-ownership", did, nonce})``
    — keys in exactly that order, compact separators.
    """
    return json.dumps(
        {"action": "prove-ownership", "did": did, "nonce": nonce}, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def register_agent(
    manifest:     dict[str, Any],
    endpoint_url: str,
    api_key:      str,
    registry_url: str | None = None,
    allow_insecure_http: bool = False,
    *,
    private_key:  bytes | Ed25519PrivateKey | None = None,
    kel:          list[dict[str, Any]] | None = None,
    controller_kel: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Register an agent on the Aroha Hub.

    ``manifest["cid"]`` is the pre-pinned manifest CID. The DID is
    ``manifest["did"]``, or — when absent — the content-addressed
    ``did:aroha:z…`` of ``private_key``'s public key.

    Proof of key possession (required by the registry for every DID except
    a rotatable ``did:aroha:E…``): the client requests a one-time nonce from
    ``POST /v1/agents/challenge`` and signs
    :func:`registration_challenge_message` with ``private_key``; the
    signature and nonce go in the registration body. ``publicKeyB64`` is the
    canonical base64url of that key (a ``did:aroha:z…`` DID must encode
    exactly this key).

    For a ``did:aroha:E…`` DID no challenge is made: pass its Key Event Log
    as ``kel`` (or post it to ``/v1/kel/{did}`` first); the registry takes
    the key from the log.

    Returns the registry record including didHash.
    """
    from .kel import is_inception_did

    registry_url = _registry(registry_url, allow_insecure_http)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    did = manifest.get("did")
    payload: dict[str, Any] = {
        "manifestCID": manifest.get("cid") or manifest.get("manifestCID"),
        "endpointUrl": endpoint_url,
    }
    if not payload["manifestCID"]:
        raise ValueError("manifest['cid'] (the pinned manifest CID) is required")

    if did and is_inception_did(did):
        payload["did"] = did
        if kel is not None:
            payload["kel"] = kel
        if controller_kel is not None:
            payload["controllerKel"] = controller_kel
        if private_key is not None:
            payload["publicKeyB64"] = _b64url(_public_bytes(private_key))
    else:
        if private_key is None:
            raise ValueError(
                "private_key is required: the registry needs proof that you hold the agent's key "
                "(POST /v1/agents/challenge, then sign the nonce)"
            )
        key = _load_key(private_key)
        pub = _public_bytes(key)
        did = did or "did:aroha:" + to_multibase(pub)
        challenge = httpx.post(
            f"{registry_url}/v1/agents/challenge", json={"did": did}, headers=headers, timeout=30,
        )
        challenge.raise_for_status()
        nonce = challenge.json()["nonce"]
        payload.update({
            "did": did,
            "publicKeyB64": _b64url(pub),
            "challengeNonce": nonce,
            "challengeSignature": _b64url(key.sign(registration_challenge_message(did, nonce))),
        })

    resp = httpx.post(f"{registry_url}/v1/agents", json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _load_key(private_key: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    return private_key if isinstance(private_key, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(bytes(private_key))


def _public_bytes(private_key: bytes | Ed25519PrivateKey) -> bytes:
    return _load_key(private_key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def resolve_agent(did_hash: str, registry_url: str | None = None, *, allow_insecure_http: bool = False) -> dict[str, Any]:
    """Resolve an agent by its didHash."""
    registry_url = _registry(registry_url, allow_insecure_http)
    resp = httpx.get(f"{registry_url}/v1/agents/{did_hash}", timeout=15)
    resp.raise_for_status()
    return resp.json()


def list_agents(
    org: str | None = None,
    limit: int = 50,
    registry_url: str | None = None,
    allow_insecure_http: bool = False,
) -> list[dict[str, Any]]:
    """List registered agents, optionally filtered by org.

    ``GET /v1/agents`` (apps/registry-server/src/routes/agents.ts) returns a
    bare JSON array of agent records. This used to read ``response["agents"]``,
    which raised AttributeError on every real response; the ``{"agents": [...]}``
    envelope is still accepted for older or proxying servers. The registry
    does not filter by ``org`` itself, so ``org`` is also applied here, against
    each record's ``publishedBy``.
    """
    params: dict[str, Any] = {"limit": limit}
    if org:
        params["org"] = org
    registry_url = _registry(registry_url, allow_insecure_http)
    resp = httpx.get(f"{registry_url}/v1/agents", params=params, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        data = data.get("agents", [])
    if not isinstance(data, list):
        return []
    agents = [a for a in data if isinstance(a, dict)]
    if org:
        agents = [a for a in agents if a.get("publishedBy", org) == org]
    return agents


def delete_agent(did_hash: str, api_key: str, registry_url: str | None = None, *, allow_insecure_http: bool = False) -> bool:
    """Delete an owned agent from the registry."""
    registry_url = _registry(registry_url, allow_insecure_http)
    resp = httpx.delete(
        f"{registry_url}/v1/agents/{did_hash}/admin",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=15,
    )
    return resp.is_success


# ── MCPs ───────────────────────────────────────────────────────────────────────

def register_mcp(
    name:         str,
    endpoint_url: str,
    description:  str = "",
    tools:        list[str] | list[dict[str, Any]] | None = None,
    did:          str | None = None,
    api_key:      str = "",
    registry_url: str | None = None,
    allow_insecure_http: bool = False,
) -> dict[str, Any]:
    """Register an MCP server on the Aroha Hub.

    Args:
        did: The MCP's did:aroha identifier. Auto-generated if omitted — pass
             one explicitly if you need it stable across re-registration.
        tools: Tool names, or full MCP tool definition dicts
               ([{"name": "search", "description": "...", "inputSchema": {...}}]).
               The registry currently indexes tool NAMES only (toolIds) — full
               schemas are accepted here for a future richer index but are not
               yet persisted server-side; don't rely on retrieving them back.
    """
    # POST /v1/mcps requires did, name, and endpointUrl — a request missing did
    # gets 400 Bad Request. Earlier versions of this function never sent one.
    did = did or f"did:aroha:studio:{_uuid()}"

    tool_ids = [t if isinstance(t, str) else t.get("name", "") for t in (tools or [])]
    tool_ids = [t for t in tool_ids if t]

    registry_url = _registry(registry_url, allow_insecure_http)

    resp = httpx.post(
        f"{registry_url}/v1/mcps",
        json={
            "did":         did,
            "name":        name,
            "description": description,
            "endpointUrl": endpoint_url,
            "toolIds":     tool_ids,
        },
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def resolve_mcp(did_hash: str, registry_url: str | None = None, *, allow_insecure_http: bool = False) -> dict[str, Any]:
    """Resolve an MCP by its didHash."""
    registry_url = _registry(registry_url, allow_insecure_http)
    resp = httpx.get(f"{registry_url}/v1/mcps/{did_hash}", timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── Skills ─────────────────────────────────────────────────────────────────────

def register_skill(
    name:         str,
    skill_type:   str,
    description:  str = "",
    endpoint_url: str | None = None,
    did:          str | None = None,
    api_key:      str = "",
    registry_url: str | None = None,
    allow_insecure_http: bool = False,
) -> dict[str, Any]:
    """Register a skill on the Aroha Hub.

    skill_type must be one of: rag, web-search, memory, code, data, custom.

    Args:
        did: The skill's did:aroha identifier. Auto-generated if omitted.
    """
    # POST /v1/skills requires did and name — a request missing did gets 400.
    did = did or f"did:aroha:studio:{_uuid()}"

    payload: dict[str, Any] = {
        "did":         did,
        "name":        name,
        "description": description,
        "skillType":   skill_type,
    }
    if endpoint_url:
        payload["endpointUrl"] = endpoint_url
    registry_url = _registry(registry_url, allow_insecure_http)
    resp = httpx.post(
        f"{registry_url}/v1/skills",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ── Invoke ─────────────────────────────────────────────────────────────────────

def call_agent(
    did_hash: str,
    message:  str,
    *,
    session_id:   str | None = None,
    history:      list[dict[str, str]] | None = None,
    bearer_token: str | None = None,
    sign_as:      tuple[str, bytes] | dict[str, Any] | None = None,
    registry_url: str | None = None,
    allow_insecure_http: bool = False,
) -> dict[str, Any]:
    """
    Call a registered agent by its didHash.

    Resolves the agent's endpoint from the registry, then POSTs to /v1/run.

    ``sign_as`` calls a private agent running ``auth="aroha-sig"``. Pass either
    ``(did, private_key)`` or ``{"did": ..., "private_key": ...}``. The request
    is signed with the DID's Ed25519 key, which proves *which* agent is calling
    — something a bearer token cannot do, since every holder of a shared token
    is indistinguishable.

    ``bearer_token`` and ``sign_as`` are different schemes; a callee runs one or
    the other.

    The registry URL and the resolved endpoint must be https (or loopback);
    ``allow_insecure_http=True`` permits plain http on a network you control.
    """
    agent = resolve_agent(did_hash, registry_url, allow_insecure_http=allow_insecure_http)
    endpoint = agent.get("endpointUrl") or agent.get("endpoint")
    if not endpoint:
        raise ValueError(f"Agent {did_hash} has no endpoint registered. It can only be called through the Aroha chat UI.")
    # The endpoint comes from registry data: refuse plain http to a remote host
    # so a signed request or bearer token is never sent unencrypted.
    require_secure_url(endpoint, allow_insecure_http=allow_insecure_http, what="agent endpoint")

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    payload = {
        "message":   message,
        "sessionId": session_id,
        "history":   history or [],
    }

    # Serialise ONCE. The signature covers a hash of the body bytes, so the
    # bytes that were signed must be the bytes that are sent — letting httpx
    # re-serialise via json= would produce a different hash and be rejected.
    body = json.dumps(payload)

    if sign_as is not None:
        did, private_key = _unpack_sign_as(sign_as)
        headers.update(
            sign_request(
                did=did,
                private_key=private_key,
                method="POST",
                # The signed path must match what the server verifies, which is
                # the URL path alone — no origin, no query string.
                path="/v1/run",
                body=body,
            )
        )

    resp = httpx.post(
        f"{endpoint}/v1/run",
        content=body,
        headers=headers,
        timeout=120,
    )

    if resp.status_code == 401 and sign_as is not None:
        raise RuntimeError(
            "Agent rejected the signature (401). The caller DID may not be on "
            "its allowed_callers list, its public key may not resolve from the "
            "registry, or the clock skew may exceed the accepted window."
        )
    resp.raise_for_status()
    return resp.json()


def _unpack_sign_as(sign_as: tuple[str, bytes] | dict[str, Any]) -> tuple[str, bytes]:
    """Accept either a (did, private_key) tuple or a mapping."""
    if isinstance(sign_as, dict):
        did = sign_as.get("did")
        private_key = sign_as.get("private_key") or sign_as.get("privateKey")
    else:
        did, private_key = sign_as
    if not did or private_key is None:
        raise ValueError("sign_as requires a DID and a private key")
    return did, private_key


# ── Internal ───────────────────────────────────────────────────────────────────

def _registry(registry_url: str | None, allow_insecure_http: bool) -> str:
    """Resolve the registry URL (see :mod:`aroha.endpoints`) and refuse an insecure one."""
    url = resolve_registry_url(registry_url)
    require_secure_url(url, allow_insecure_http=allow_insecure_http, what="registry URL")
    return url


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())
