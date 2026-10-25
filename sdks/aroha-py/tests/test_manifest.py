# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

from aroha.manifest import build_agent_manifest, build_mcp_manifest, build_skill_manifest, validate_manifest

DID = "did:aroha:test-agent"


def test_build_agent_manifest_defaults():
    m = build_agent_manifest(DID, name="Test Agent")
    assert m["visibility"] == "private"
    assert m["published"] is False
    assert m["deployTarget"] == "local"
    assert m["kind"] == "agent"
    assert m["capabilities"] == []
    assert validate_manifest(m)["ok"] is True


def test_build_mcp_manifest_defaults():
    m = build_mcp_manifest(DID, name="Test MCP")
    assert m["endpoint"] is None
    assert m["auth"] == {"type": "none"}
    assert m["tools"] == []
    assert validate_manifest(m)["ok"] is True


def test_build_skill_manifest_defaults():
    m = build_skill_manifest(DID, name="Test Skill")
    assert m["skillType"] == "custom"
    assert validate_manifest(m)["ok"] is True


def test_validate_manifest_rejects_non_dict():
    assert validate_manifest(None)["ok"] is False
    assert validate_manifest("x")["ok"] is False


def test_validate_manifest_flags_contradictory_publish_visibility():
    m = build_agent_manifest(DID, name="x", published=True, visibility="private")
    result = validate_manifest(m)
    assert result["ok"] is False
    assert any("contradictory" in e for e in result["errors"])


def test_validate_manifest_allows_published_public():
    m = build_agent_manifest(DID, name="x", published=True, visibility="public")
    assert validate_manifest(m)["ok"] is True


def test_validate_manifest_requires_capabilities_on_agent():
    m = build_agent_manifest(DID, name="x")
    del m["capabilities"]
    assert validate_manifest(m)["ok"] is False


def test_validate_manifest_requires_tools_on_mcp():
    m = build_mcp_manifest(DID, name="x")
    del m["tools"]
    assert validate_manifest(m)["ok"] is False
