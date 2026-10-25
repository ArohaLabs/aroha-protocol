# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""The one place the Python SDK names Aroha-operated hosts.

Mirrors ``@aroha-sdk/core/endpoints``. The registry URL used to be hard-coded
in several modules, and they disagreed: some named ``registry.aroha-labs.com``,
which does not resolve, others the workers.dev host that is actually deployed.
Every module now reads these constants (or the environment overrides) instead
of carrying its own copy.

Overrides, per process:

* ``AROHA_REGISTRY_URL`` — registry base URL
* ``AROHA_IPFS_GATEWAY`` — IPFS gateway base, including the ``/ipfs`` prefix

Each function that talks to the registry also takes an explicit
``registry_url``, which wins over both.
"""

from __future__ import annotations

import os

#: The Aroha-managed registry: the workers.dev host the registry Worker
#: (apps/registry-server) is deployed to. No custom domain is attached.
AROHA_MANAGED_REGISTRY_URL = "https://aroha-registry.aroha-labs.workers.dev"

#: The Aroha-operated IPFS gateway (apps/ipfs-gateway), including the
#: ``/ipfs`` prefix — append ``/<cid>``.
AROHA_DEFAULT_IPFS_GATEWAY = "https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs"


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def resolve_registry_url(override: str | None = None) -> str:
    """``override`` → ``AROHA_REGISTRY_URL`` → :data:`AROHA_MANAGED_REGISTRY_URL`. No trailing slash.

    Read at call time, so setting the environment variable after import works.
    """
    return (override or _env("AROHA_REGISTRY_URL") or AROHA_MANAGED_REGISTRY_URL).rstrip("/")


def resolve_ipfs_gateway(override: str | None = None) -> str:
    """``override`` → ``AROHA_IPFS_GATEWAY`` → :data:`AROHA_DEFAULT_IPFS_GATEWAY`. No trailing slash."""
    return (override or _env("AROHA_IPFS_GATEWAY") or AROHA_DEFAULT_IPFS_GATEWAY).rstrip("/")


__all__ = [
    "AROHA_MANAGED_REGISTRY_URL",
    "AROHA_DEFAULT_IPFS_GATEWAY",
    "resolve_registry_url",
    "resolve_ipfs_gateway",
]
