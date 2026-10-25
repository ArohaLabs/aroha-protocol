# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Layer 4: Orchestration

Saga execution engine and agent selector.
Mirrors aroha-orchestrator/src/ from the TypeScript SDK.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aroha.messages import build_envelope, new_correlation_id, ArohaEnvelope
from aroha.transport import ArohaClient

# ── Saga ───────────────────────────────────────────────────────────────────────

class SagaStepState(str, Enum):
    PENDING    = "PENDING"
    RESERVED   = "RESERVED"
    COMMITTED  = "COMMITTED"
    CANCELLED  = "CANCELLED"
    FAILED     = "FAILED"


@dataclass
class SagaStep:
    agent_did: str
    agent_endpoint: str
    capability: str
    params: dict[str, Any]
    hold_duration_ms: int = 300_000
    step_id: int = 0
    state: SagaStepState = SagaStepState.PENDING
    reservation_token: Optional[str] = None
    reservation_expires_at: Optional[str] = None
    commit_result: Optional[dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class SagaResult:
    success: bool
    saga_id: str
    results: dict[int, dict[str, Any]] = field(default_factory=dict)
    failures: list[dict[str, Any]] = field(default_factory=list)


class SagaEngine:
    """
    Implements the Aroha saga pattern:
      Phase 1 — RESERVE all participants in parallel
      Phase 2 — COMMIT all if all reserves succeeded
      Phase 3 — COMPENSATE (LIFO) if any commit fails
    """

    def __init__(
        self,
        client: ArohaClient,
        orchestrator_did: str,
        private_key: Ed25519PrivateKey,
        persist_log: Optional[Callable[[dict], Any]] = None,
    ) -> None:
        self.client = client
        self.orchestrator_did = orchestrator_did
        self.private_key = private_key
        self.persist_log = persist_log

    async def execute(self, participants: list[SagaStep]) -> SagaResult:
        saga_id = f"saga-{uuid.uuid4()}"
        correlation_id = new_correlation_id()

        for i, step in enumerate(participants):
            step.step_id = i

        # ── Phase 1: RESERVE ────────────────────────────────────────────────
        reserve_tasks = [self._reserve(step, correlation_id) for step in participants]
        reserve_results = await asyncio.gather(*reserve_tasks, return_exceptions=True)

        for i, result in enumerate(reserve_results):
            if isinstance(result, Exception):
                participants[i].state = SagaStepState.FAILED
                participants[i].error = str(result)
            else:
                participants[i].state = SagaStepState.RESERVED
                participants[i].reservation_token = result["reservationToken"]
                participants[i].reservation_expires_at = result.get("expiresAt")

        all_reserved = all(s.state == SagaStepState.RESERVED for s in participants)

        if not all_reserved:
            await self._compensate(participants, correlation_id)
            return SagaResult(
                success=False,
                saga_id=saga_id,
                failures=[
                    {"step_id": s.step_id, "reason": s.error or "Reserve failed"}
                    for s in participants
                    if s.state == SagaStepState.FAILED
                ],
            )

        # ── Phase 2: COMMIT ─────────────────────────────────────────────────
        for step in participants:
            try:
                ack = await self._commit(step, correlation_id)
                step.state = SagaStepState.COMMITTED
                step.commit_result = ack.get("result", {})
            except Exception as exc:
                step.state = SagaStepState.FAILED
                step.error = str(exc)
                await self._compensate(participants, correlation_id)
                return SagaResult(
                    success=False,
                    saga_id=saga_id,
                    failures=[{"step_id": step.step_id, "reason": step.error}],
                )

        return SagaResult(
            success=True,
            saga_id=saga_id,
            results={s.step_id: s.commit_result or {} for s in participants},
        )

    async def _reserve(self, step: SagaStep, correlation_id: str) -> dict:
        body = {
            "capability": step.capability,
            "params": step.params,
            "holdDurationMs": step.hold_duration_ms,
        }
        envelope = build_envelope(
            "ArohaReserve", self.orchestrator_did, step.agent_did,
            body, correlation_id, self.private_key,
        )
        response = await self.client.send(step.agent_endpoint, envelope)
        if not response:
            raise RuntimeError(f"No response from {step.agent_did}")
        if response.get("type") == "ArohaError":
            raise RuntimeError(response["body"].get("message", "Reserve failed"))
        return response["body"]

    async def _commit(self, step: SagaStep, correlation_id: str) -> dict:
        envelope = build_envelope(
            "ArohaCommit", self.orchestrator_did, step.agent_did,
            {"reservationToken": step.reservation_token},
            correlation_id, self.private_key,
        )
        response = await self.client.send(step.agent_endpoint, envelope)
        if not response:
            raise RuntimeError(f"No response from {step.agent_did}")
        if response.get("type") == "ArohaError":
            raise RuntimeError(response["body"].get("message", "Commit failed"))
        return response["body"]

    async def _compensate(self, steps: list[SagaStep], correlation_id: str) -> None:
        to_cancel = [
            s for s in reversed(steps)  # LIFO
            if s.state in (SagaStepState.RESERVED, SagaStepState.COMMITTED)
        ]
        for step in to_cancel:
            try:
                envelope = build_envelope(
                    "ArohaCancel", self.orchestrator_did, step.agent_did,
                    {"reservationToken": step.reservation_token,
                     "reason": "Saga compensation — rolling back"},
                    correlation_id, self.private_key,
                )
                await self.client.send(step.agent_endpoint, envelope)
                step.state = SagaStepState.CANCELLED
            except Exception as exc:
                print(f"[Aroha Saga] Cancel failed for step {step.step_id}: {exc}")


# ── Agent Selector ─────────────────────────────────────────────────────────────

@dataclass
class AgentOffer:
    agent_did: str
    agent_endpoint: str
    response: dict[str, Any]
    price: Optional[float]
    latency_ms: float
    score: float = 0.0


@dataclass
class SelectionResult:
    winner: AgentOffer
    ranked: list[AgentOffer]


DEFAULT_WEIGHTS = {
    "price": 0.35,
    "reputation": 0.30,
    "latency": 0.15,
    "preference": 0.15,
    "availability": 0.05,
}


class AgentSelector:
    """
    Fan out ArohaRequests to all candidates, score responses, return ranked list.
    """

    def __init__(
        self,
        client: ArohaClient,
        orchestrator_did: str,
        private_key: Ed25519PrivateKey,
    ) -> None:
        self.client = client
        self.orchestrator_did = orchestrator_did
        self.private_key = private_key

    async def select(
        self,
        capability: str,
        params: dict[str, Any],
        candidates: list[dict[str, Any]],  # [{"did": str, "endpoint": str, "reputation": int}]
        weights: Optional[dict[str, float]] = None,
        preference_scores: Optional[dict[str, float]] = None,
        blocked_agents: Optional[list[str]] = None,
        fan_out_timeout: float = 5.0,
    ) -> SelectionResult:
        w = {**DEFAULT_WEIGHTS, **(weights or {})}
        pref = preference_scores or {}
        blocked = set(blocked_agents or [])
        correlation_id = new_correlation_id()

        eligible = [c for c in candidates if c["did"] not in blocked]
        if not eligible:
            raise ValueError(f"No eligible agents for capability: {capability}")

        tasks = [
            self._send_request(c, capability, params, correlation_id, fan_out_timeout)
            for c in eligible
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        offers: list[AgentOffer] = []
        for i, result in enumerate(results):
            if not isinstance(result, Exception) and result is not None:
                offers.append(result)

        if not offers:
            raise ValueError(f"No agents responded for capability: {capability}")

        scored = self._score_offers(offers, eligible, w, pref)
        scored.sort(key=lambda o: o.score, reverse=True)
        return SelectionResult(winner=scored[0], ranked=scored)

    async def _send_request(
        self,
        agent: dict[str, Any],
        capability: str,
        params: dict[str, Any],
        correlation_id: str,
        timeout: float,
    ) -> Optional[AgentOffer]:
        envelope = build_envelope(
            "ArohaRequest", self.orchestrator_did, agent["did"],
            {"capability": capability, "params": params},
            correlation_id, self.private_key,
        )
        start = time.monotonic()
        try:
            response = await self.client.send(agent["endpoint"], envelope, timeout=timeout)
            if not response or response.get("type") == "ArohaError":
                return None
            latency_ms = (time.monotonic() - start) * 1000
            result = response.get("body", {}).get("result", {})
            price = result.get("price") or result.get("totalPrice")
            return AgentOffer(
                agent_did=agent["did"],
                agent_endpoint=agent["endpoint"],
                response=response,
                price=float(price) if price is not None else None,
                latency_ms=latency_ms,
            )
        except Exception:
            return None

    def _score_offers(
        self,
        offers: list[AgentOffer],
        candidates: list[dict],
        w: dict[str, float],
        pref: dict[str, float],
    ) -> list[AgentOffer]:
        prices = [o.price for o in offers if o.price is not None]
        min_price = min(prices, default=0)
        max_price = max(prices, default=0)
        latencies = [o.latency_ms for o in offers]
        min_lat = min(latencies)
        max_lat = max(latencies)
        rep_by_did = {c["did"]: c.get("reputation", 5000) for c in candidates}

        def norm(v: float, lo: float, hi: float) -> float:
            return 1.0 if hi == lo else (v - lo) / (hi - lo)

        for offer in offers:
            price_score = (
                1.0 if offer.price is None
                else norm(max_price - offer.price, 0, max_price - min_price)
            )
            rep = rep_by_did.get(offer.agent_did, 5000) / 10_000
            lat_score = norm(max_lat - offer.latency_ms, 0, max_lat - min_lat)
            pref_score = pref.get(offer.agent_did, 0.5)
            offer.score = (
                price_score  * w["price"]        +
                rep          * w["reputation"]   +
                lat_score    * w["latency"]      +
                pref_score   * w["preference"]   +
                1.0          * w["availability"]
            )
        return offers
