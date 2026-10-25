# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
"""
aroha/__init__.py — the package root is the advertised public API surface.

register_mcp, resolve_mcp, and register_skill lived in aroha.hub but were never
re-exported from the package root, so `from aroha import register_mcp` raised
ImportError while the sibling `register_agent` worked fine — an inconsistency
with no reason behind it. This guards both directions: every name __all__
claims must actually be importable, and every hub function meant to be public
must be reachable from `aroha` directly, not just `aroha.hub`.
"""

from __future__ import annotations

import aroha


def test_all_declared_names_are_importable():
    missing = [name for name in aroha.__all__ if not hasattr(aroha, name)]
    assert missing == [], f"__all__ names not actually exported: {missing}"


def test_hub_registration_functions_reachable_from_package_root():
    # These are the functions a new user reaches for right after `serve` and
    # `call_agent` — registering an MCP or a skill should not require knowing
    # the internal module layout.
    for name in ["register_agent", "resolve_agent", "list_agents", "delete_agent",
                 "call_agent", "register_mcp", "resolve_mcp", "register_skill"]:
        assert hasattr(aroha, name), f"aroha.{name} is not exported from the package root"
        assert name in aroha.__all__, f"aroha.{name} is exported but missing from __all__"


def test_root_export_is_the_same_object_as_the_hub_module():
    # Guards against a future refactor accidentally re-defining a shadow
    # function at the root instead of re-exporting the real one.
    from aroha import hub

    assert aroha.register_mcp is hub.register_mcp
    assert aroha.resolve_mcp is hub.resolve_mcp
    assert aroha.register_skill is hub.register_skill
    assert aroha.list_agents is hub.list_agents
    assert aroha.delete_agent is hub.delete_agent
