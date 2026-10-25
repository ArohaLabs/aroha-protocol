# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

import uuid
import httpx
from .envelope import build_envelope
from .safety import require_secure_url


class ArohaClient:
    """Minimal async HTTP client for sending Aroha messages.

    Endpoints must be https, except loopback hosts; ``allow_insecure_http=True``
    permits plain http to other hosts on a network you control.
    """

    def __init__(self, agent: dict, *, timeout: float = 30.0, allow_insecure_http: bool = False):
        self.agent = agent
        self.timeout = timeout
        self.allow_insecure_http = allow_insecure_http

    async def request(
        self,
        endpoint: str,
        to_did: str,
        capability: str,
        params: dict,
        *,
        correlation_id: str | None = None,
    ) -> dict:
        require_secure_url(endpoint, allow_insecure_http=self.allow_insecure_http)
        cid = correlation_id or f"saga-{uuid.uuid4()}"
        envelope = build_envelope(
            "ArohaRequest",
            self.agent["did"],
            to_did,
            {"capability": capability, "params": params},
            cid,
            self.agent["private_key"],
        )
        async with httpx.AsyncClient(timeout=self.timeout) as http:
            res = await http.post(
                endpoint,
                json=envelope,
                headers={"Content-Type": "application/json"},
            )
            res.raise_for_status()
            return res.json()
