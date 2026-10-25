# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Python SDK — Bayesian Reputation Engine (v1.1)

Implements the 11-signal Beta-distribution reputation model described in
docs/reputation-model.md. Mirrors the TypeScript @aroha-sdk/reputation package.

Signals:
  1. baseline  — raw success/failure (μ=2)
  2. rhr       — recent hit rate, 30-day half-life
  3. pcr       — protocol compliance rate
  4. dsl       — deadline/SLA adherence (μ=2)
  5. cls       — cancellation liability
  6. sas       — ArohaSatisfactionSignal
  7. fss       — failure speed signal (μ=1.5)
  8. pas       — price accuracy signal (μ=2.5)
  9. rss       — reservation selectivity (quadratic penalty)
 10. rrs       — retry rate signal (μ=1.2)
 11. cs        — consistency/Sharpe via Welford online algorithm
 12. pps       — peer preference signal (weighted endorsements)

References:
  Jøsang & Ismail (2002) "The Beta Reputation System"
  Agrawal & Goyal (2012) "Analysis of Thompson Sampling for MAB" COLT
  Lai & Robbins (1985) "Asymptotically efficient adaptive allocation rules"
"""

from __future__ import annotations

import math
import random
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal, Optional


# ── Constants ─────────────────────────────────────────────────────────────────

JEFFREYS_PRIOR          = 0.5
SUCCESS_HALF_LIFE_DAYS  = 180
FAILURE_HALF_LIFE_DAYS  = 60
RHR_HALF_LIFE_DAYS      = 30
DORMANCY_HALF_LIFE_DAYS = 365
MS_PER_DAY              = 86_400_000

MU_BASELINE = 2.0
MU_RHR      = 2.0
MU_DSL      = 2.0
MU_FSS      = 1.5
MU_PAS      = 2.5
MU_RRS      = 1.2


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SignalPair:
    alpha: float = JEFFREYS_PRIOR
    beta: float  = JEFFREYS_PRIOR
    n: int       = 0
    last_updated: str = field(default_factory=lambda: _now_iso())


@dataclass
class WelfordStats:
    n: int     = 0
    mean: float = 0.0
    m2: float  = 0.0
    last_updated: str = field(default_factory=lambda: _now_iso())


@dataclass
class ReputationState:
    agent_did: str    = ""
    domain: str       = "general"
    # 11 signals
    baseline: SignalPair = field(default_factory=SignalPair)
    rhr:      SignalPair = field(default_factory=SignalPair)
    pcr:      SignalPair = field(default_factory=SignalPair)
    dsl:      SignalPair = field(default_factory=SignalPair)
    cls:      SignalPair = field(default_factory=SignalPair)
    sas:      SignalPair = field(default_factory=SignalPair)
    fss:      SignalPair = field(default_factory=SignalPair)
    pas:      SignalPair = field(default_factory=SignalPair)
    rss:      SignalPair = field(default_factory=SignalPair)
    rrs:      SignalPair = field(default_factory=SignalPair)
    cs:       WelfordStats = field(default_factory=WelfordStats)
    pps:      SignalPair = field(default_factory=SignalPair)
    # Metadata
    created_at: str            = field(default_factory=lambda: _now_iso())
    total_interactions: int    = 0
    composite_score: float     = 0.5


@dataclass
class CompositeWeights:
    baseline: float = 0.18
    rhr:      float = 0.18
    pcr:      float = 0.10
    dsl:      float = 0.08
    cls:      float = 0.07
    sas:      float = 0.05
    fss:      float = 0.10
    pas:      float = 0.08
    rss:      float = 0.06
    rrs:      float = 0.04
    cs:       float = 0.04
    pps:      float = 0.02


DEFAULT_WEIGHTS = CompositeWeights()


# ── Signal update functions ───────────────────────────────────────────────────

def decay_signal(pair: SignalPair, now: datetime) -> SignalPair:
    last = datetime.fromisoformat(pair.last_updated.replace("Z", "+00:00"))
    elapsed_days = (now - last).total_seconds() / 86400
    if elapsed_days <= 0:
        return pair
    lambda_s = math.log(2) / SUCCESS_HALF_LIFE_DAYS
    lambda_f = math.log(2) / FAILURE_HALF_LIFE_DAYS
    return SignalPair(
        alpha=max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (pair.alpha - JEFFREYS_PRIOR) * math.exp(-lambda_s * elapsed_days)),
        beta= max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (pair.beta  - JEFFREYS_PRIOR) * math.exp(-lambda_f * elapsed_days)),
        n=pair.n,
        last_updated=now.isoformat(),
    )


def dormancy_shrink(pair: SignalPair, now: datetime, threshold_days: float = 365.0) -> SignalPair:
    last = datetime.fromisoformat(pair.last_updated.replace("Z", "+00:00"))
    elapsed_days = (now - last).total_seconds() / 86400
    if elapsed_days <= threshold_days:
        return pair
    lambda_d = math.log(2) / threshold_days
    factor = math.exp(-lambda_d * (elapsed_days - threshold_days))
    return SignalPair(
        alpha=JEFFREYS_PRIOR + (pair.alpha - JEFFREYS_PRIOR) * factor,
        beta= JEFFREYS_PRIOR + (pair.beta  - JEFFREYS_PRIOR) * factor,
        n=pair.n,
        last_updated=pair.last_updated,
    )


def update_baseline(pair: SignalPair, success: bool, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    return SignalPair(d.alpha + (1 if success else 0), d.beta + (0 if success else MU_BASELINE), d.n + 1, now.isoformat())


def update_rhr(pair: SignalPair, success: bool, now: datetime) -> SignalPair:
    last = datetime.fromisoformat(pair.last_updated.replace("Z", "+00:00"))
    elapsed_days = (now - last).total_seconds() / 86400
    lam = math.log(2) / RHR_HALF_LIFE_DAYS
    da = max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (pair.alpha - JEFFREYS_PRIOR) * math.exp(-lam * elapsed_days))
    db = max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (pair.beta  - JEFFREYS_PRIOR) * math.exp(-lam * elapsed_days))
    return SignalPair(da + (1 if success else 0), db + (0 if success else MU_RHR), pair.n + 1, now.isoformat())


def update_pcr(pair: SignalPair, compliant: bool, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    return SignalPair(d.alpha + (1 if compliant else 0), d.beta + (0 if compliant else 3.0), d.n + 1, now.isoformat())


def update_dsl(pair: SignalPair, met_sla: bool, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    return SignalPair(d.alpha + (1 if met_sla else 0), d.beta + (0 if met_sla else MU_DSL), d.n + 1, now.isoformat())


def update_cls(pair: SignalPair, cancelled: bool, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    return SignalPair(d.alpha + (0 if cancelled else 1), d.beta + (2.5 if cancelled else 0), d.n + 1, now.isoformat())


def update_sas(pair: SignalPair, outcome: Literal["satisfied", "neutral", "dissatisfied"], now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    if outcome == "neutral":
        return SignalPair(d.alpha, d.beta, d.n, now.isoformat())
    return SignalPair(
        d.alpha + (1 if outcome == "satisfied" else 0),
        d.beta  + (1.5 if outcome == "dissatisfied" else 0),
        d.n + 1,
        now.isoformat(),
    )


def update_fss(pair: SignalPair, failure_ms: float, sla_ms: float, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    fast = failure_ms <= sla_ms * 0.10
    return SignalPair(d.alpha + (1 if fast else 0), d.beta + (0 if fast else MU_FSS), d.n + 1, now.isoformat())


def update_pas(pair: SignalPair, quoted: float, actual: float, now: datetime, threshold: float = 0.02) -> SignalPair:
    d = decay_signal(pair, now)
    if quoted <= 0:
        return d
    deviation = abs(actual - quoted) / quoted
    accurate = deviation <= threshold
    return SignalPair(d.alpha + (1 if accurate else 0), d.beta + (0 if accurate else MU_PAS), d.n + 1, now.isoformat())


def update_rss(pair: SignalPair, accepted: bool, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    return SignalPair(d.alpha + (1 if accepted else 0), d.beta + (0 if accepted else 1.0), d.n + 1, now.isoformat())


def update_rrs(pair: SignalPair, retry_count: int, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    triggered = retry_count > 0
    return SignalPair(
        d.alpha + (0 if triggered else 1),
        d.beta  + (MU_RRS * retry_count if triggered else 0),
        d.n + 1,
        now.isoformat(),
    )


def update_cs(stats: WelfordStats, quality: float, now: datetime) -> WelfordStats:
    n = stats.n + 1
    delta = quality - stats.mean
    mean = stats.mean + delta / n
    delta2 = quality - mean
    m2 = stats.m2 + delta * delta2
    return WelfordStats(n=n, mean=mean, m2=m2, last_updated=now.isoformat())


def update_pps(pair: SignalPair, endorser_score: float, now: datetime) -> SignalPair:
    d = decay_signal(pair, now)
    if endorser_score < 0.8:
        return d
    return SignalPair(d.alpha + endorser_score, d.beta, d.n + 1, now.isoformat())


# ── Score helpers ─────────────────────────────────────────────────────────────

def beta_mean(pair: SignalPair) -> float:
    return pair.alpha / (pair.alpha + pair.beta)


def cs_score(stats: WelfordStats) -> float:
    if stats.n < 2:
        return stats.mean
    variance = stats.m2 / (stats.n - 1)
    stddev = math.sqrt(variance)
    return stats.mean / (1.0 + stddev)


def compute_composite(state: ReputationState, weights: CompositeWeights = DEFAULT_WEIGHTS) -> float:
    return (
        beta_mean(state.baseline) * weights.baseline +
        beta_mean(state.rhr)      * weights.rhr      +
        beta_mean(state.pcr)      * weights.pcr      +
        beta_mean(state.dsl)      * weights.dsl      +
        beta_mean(state.cls)      * weights.cls      +
        beta_mean(state.sas)      * weights.sas      +
        beta_mean(state.fss)      * weights.fss      +
        beta_mean(state.pas)      * weights.pas      +
        beta_mean(state.rss)      * weights.rss      +
        beta_mean(state.rrs)      * weights.rrs      +
        cs_score(state.cs)        * weights.cs       +
        beta_mean(state.pps)      * weights.pps
    )


def wilson_lower_bound(pair: SignalPair, z: float = 1.96) -> float:
    n = pair.alpha + pair.beta - 1.0
    if n <= 0:
        return 0.0
    p = (pair.alpha - JEFFREYS_PRIOR) / n
    denom = 1 + (z * z) / n
    centre = p + (z * z) / (2 * n)
    spread = z * math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n)
    return max(0.0, (centre - spread) / denom)


# ── Thompson Sampling ─────────────────────────────────────────────────────────

def sample_beta(alpha: float, beta: float) -> float:
    """Sample θ ~ Beta(α,β) using Python's random.betavariate."""
    return random.betavariate(max(1e-6, alpha), max(1e-6, beta))


# ── Reputation engine ─────────────────────────────────────────────────────────

class BayesianReputationEngine:
    """
    In-memory Bayesian Beta reputation engine.

    Usage::

        engine = BayesianReputationEngine()
        engine.record_event({
            "type": "saga_complete",
            "saga_id": "saga-123",
            "agent_did": "did:aroha:my-agent",
            "domain": "travel",
            "success": True,
            "latency_ms": 320,
            "sla_duration_ms": 5000,
        })
        score = engine.composite_score("did:aroha:my-agent", "travel")
        winner = engine.thompson_select(candidates, "travel")[0]
    """

    def __init__(self, weights: Optional[CompositeWeights] = None) -> None:
        self._store: dict[str, ReputationState] = {}
        self._weights = weights or DEFAULT_WEIGHTS

    def _key(self, agent_did: str, domain: str) -> str:
        return f"{agent_did}::{domain}"

    def _get_or_create(self, agent_did: str, domain: str) -> ReputationState:
        key = self._key(agent_did, domain)
        if key not in self._store:
            self._store[key] = ReputationState(agent_did=agent_did, domain=domain)
        return self._store[key]

    def record_event(self, event: dict[str, Any]) -> None:
        domain = event.get("domain", "general")
        agent_did = event["agent_did"]
        now = datetime.now(timezone.utc)
        state = self._get_or_create(agent_did, domain)

        etype = event["type"]
        if etype == "saga_complete":
            ok = bool(event.get("success", False))
            state.baseline = update_baseline(state.baseline, ok, now)
            state.rhr = update_rhr(state.rhr, ok, now)
            lat = event.get("latency_ms")
            sla = event.get("sla_duration_ms")
            if lat is not None and sla is not None:
                state.dsl = update_dsl(state.dsl, lat <= sla, now)

        elif etype == "protocol_violation":
            state.pcr = update_pcr(state.pcr, False, now)

        elif etype == "cancellation":
            state.cls = update_cls(state.cls, True, now)

        elif etype == "satisfaction_signal":
            q = event.get("quality_score")
            if q is not None:
                outcome = "satisfied" if q >= 0.7 else ("dissatisfied" if q <= 0.3 else "neutral")
                state.sas = update_sas(state.sas, outcome, now)

        elif etype == "failure_speed":
            fail_ms = event.get("failure_fast_ms")
            sla_ms = event.get("sla_duration_ms")
            if fail_ms is not None and sla_ms is not None:
                state.fss = update_fss(state.fss, fail_ms, sla_ms, now)

        elif etype == "price_deviation":
            q = event.get("quoted_price")
            a = event.get("actual_price")
            if q is not None and a is not None:
                state.pas = update_pas(state.pas, q, a, now)

        elif etype == "reservation_attempt":
            state.rss = update_rss(state.rss, bool(event.get("reservation_accepted", False)), now)

        elif etype == "retry_triggered":
            state.rrs = update_rrs(state.rrs, int(event.get("retry_count", 1)), now)

        elif etype == "quality_observed":
            q = event.get("quality_score")
            if q is not None:
                state.cs = update_cs(state.cs, q, now)

        elif etype == "peer_endorsement":
            es = event.get("endorser_score")
            if es is not None:
                state.pps = update_pps(state.pps, es, now)

        state.total_interactions += 1
        state.composite_score = compute_composite(state, self._weights)
        self._store[self._key(agent_did, domain)] = state

    def composite_score(self, agent_did: str, domain: str = "general") -> float:
        key = self._key(agent_did, domain)
        if key not in self._store:
            return 0.5
        state = self._store[key]
        now = datetime.now(timezone.utc)
        _apply_dormancy(state, now)
        return compute_composite(state, self._weights)

    def get_state(self, agent_did: str, domain: str = "general") -> Optional[ReputationState]:
        key = self._key(agent_did, domain)
        return self._store.get(key)

    def thompson_select(
        self,
        candidates: list[dict[str, Any]],
        domain: str = "general",
        risk_gated: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Thompson Sampling selection over candidates.
        Adds "thompson_score", "mean", "lower_bound" to each candidate dict.
        Returns list sorted by thompson_score descending.
        """
        now = datetime.now(timezone.utc)
        scored = []
        for c in candidates:
            did = c["agent_did"]
            state = self._get_or_create(did, domain)
            _apply_dormancy(state, now)
            composite = compute_composite(state, self._weights)
            n = state.baseline.alpha + state.baseline.beta
            alpha_c = max(0.5, composite * n)
            beta_c  = max(0.5, (1 - composite) * n)
            ts = sample_beta(alpha_c, beta_c)
            lb = wilson_lower_bound(state.baseline)
            scored.append({**c, "thompson_score": ts, "mean": composite, "lower_bound": lb})

        if risk_gated:
            filtered = [s for s in scored if s["lower_bound"] >= 0.1]
            if filtered:
                return sorted(filtered, key=lambda x: x["thompson_score"], reverse=True)

        return sorted(scored, key=lambda x: x["thompson_score"], reverse=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_dormancy(state: ReputationState, now: datetime) -> None:
    for attr in ("baseline", "rhr", "pcr", "dsl", "cls", "sas", "fss", "pas", "rss", "rrs", "pps"):
        setattr(state, attr, dormancy_shrink(getattr(state, attr), now))
