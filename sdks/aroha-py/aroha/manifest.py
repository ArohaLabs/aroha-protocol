# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Manifest builders for the common entity kinds.

Mirrors packages/aroha-core/src/manifest/index.ts. generate_did() (see
identity.py) returns identity material and stops there — DID, keys, DID
document. Everything past that (what an agent/mcp/skill manifest looks
like, what "capability" and "trustLevel" mean) previously had to be
invented from scratch, even though arohaProtocolVersion versioning implies
the shape is meant to be somewhat standard. These builders are that shared
shape, optional to use — validate_manifest accepts any dict satisfying the
shape regardless of how it was built.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

__all__ = [
    "build_agent_manifest",
    "build_mcp_manifest",
    "build_skill_manifest",
    "validate_manifest",
]


def _base(did: str, kind: str, *, name: str, description: str = "",
          visibility: str = "private", published: bool = False,
          deploy_target: str = "local", aroha_protocol_version: str = "1.0",
          version: str = "1.0", created_at: Optional[str] = None) -> dict[str, Any]:
    return {
        "did": did,
        "arohaProtocolVersion": aroha_protocol_version,
        "version": version,
        "kind": kind,
        "name": name,
        "description": description,
        "visibility": visibility,
        "published": published,
        "deployTarget": deploy_target,
        "createdAt": created_at or datetime.now(timezone.utc).isoformat(),
    }


def build_agent_manifest(
    did: str, *, name: str, description: str = "",
    visibility: str = "private", published: bool = False, deploy_target: str = "local",
    capabilities: Optional[list[dict[str, Any]]] = None,
    model: Optional[str] = None, trigger: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None, **kwargs: Any,
) -> dict[str, Any]:
    manifest = _base(did, "agent", name=name, description=description,
                      visibility=visibility, published=published, deploy_target=deploy_target, **kwargs)
    manifest.update({
        "capabilities": capabilities or [],
        "model": model,
        "trigger": trigger,
        "extra": extra,
    })
    return manifest


def build_mcp_manifest(
    did: str, *, name: str, description: str = "",
    visibility: str = "private", published: bool = False, deploy_target: str = "local",
    endpoint: Optional[str] = None, tools: Optional[list[dict[str, Any]]] = None,
    auth_type: str = "none", extra: Optional[dict[str, Any]] = None, **kwargs: Any,
) -> dict[str, Any]:
    manifest = _base(did, "mcp", name=name, description=description,
                      visibility=visibility, published=published, deploy_target=deploy_target, **kwargs)
    manifest.update({
        "endpoint": endpoint,
        "auth": {"type": auth_type},
        "tools": tools or [],
        "extra": extra,
    })
    return manifest


def build_skill_manifest(
    did: str, *, name: str, description: str = "",
    visibility: str = "private", published: bool = False, deploy_target: str = "local",
    skill_type: str = "custom", instructions: str = "",
    endpoint: Optional[str] = None, extra: Optional[dict[str, Any]] = None, **kwargs: Any,
) -> dict[str, Any]:
    manifest = _base(did, "skill", name=name, description=description,
                      visibility=visibility, published=published, deploy_target=deploy_target, **kwargs)
    manifest.update({
        "skillType": skill_type,
        "instructions": instructions,
        "endpoint": endpoint,
        "extra": extra,
    })
    return manifest


def validate_manifest(manifest: Any) -> dict[str, Any]:
    """Structural check — not a full JSON-Schema validator, just enough to
    catch mistakes easy to make hand-building a manifest without the
    builders above. Returns {"ok": bool, "errors": [str, ...]}."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return {"ok": False, "errors": ["manifest must be a dict"]}

    did = manifest.get("did")
    if not isinstance(did, str) or not did.startswith("did:aroha:"):
        errors.append("did must be a string starting with 'did:aroha:'")

    kind = manifest.get("kind")
    if kind not in ("agent", "mcp", "skill"):
        errors.append('kind must be "agent", "mcp", or "skill"')

    name = manifest.get("name")
    if not isinstance(name, str) or len(name) == 0:
        errors.append("name must be a non-empty string")

    visibility = manifest.get("visibility")
    if visibility not in ("public", "unlisted", "private"):
        errors.append('visibility must be "public", "unlisted", or "private"')

    published = manifest.get("published")
    if not isinstance(published, bool):
        errors.append("published must be a bool")
    if published is True and visibility == "private":
        errors.append('published=True with visibility="private" is contradictory — a private manifest should not be published')

    deploy_target = manifest.get("deployTarget")
    if deploy_target not in ("local", "hosted"):
        errors.append('deployTarget must be "local" or "hosted"')

    if kind == "agent" and not isinstance(manifest.get("capabilities"), list):
        errors.append("agent manifest must have a capabilities list")
    if kind == "mcp" and not isinstance(manifest.get("tools"), list):
        errors.append("mcp manifest must have a tools list")
    if kind == "skill" and not isinstance(manifest.get("skillType"), str):
        errors.append("skill manifest must have a skillType string")

    return {"ok": len(errors) == 0, "errors": errors}
