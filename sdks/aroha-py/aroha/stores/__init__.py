# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Durable, shared stores for the three things a verifying server must not
forget on restart: HTTP presentation nonces (replay protection), enrollment
challenges and bindings, and spending running totals.

- ``aroha.stores.postgres`` — psycopg 3 (``pip install "aroha[postgres]"``)
- ``aroha.stores.redis``    — redis-py 5+ (``pip install "aroha[redis]"``)

Each module provides the same three classes as the in-memory stores, with the
same semantics, and is safe to share between processes. Nothing here is
imported by ``import aroha``: the drivers are optional extras. Store errors
are never swallowed; they propagate so the verifiers refuse with
NONCE_STORE_UNAVAILABLE / STORE_UNAVAILABLE / LEDGER_UNAVAILABLE.
"""

__all__: list[str] = []
