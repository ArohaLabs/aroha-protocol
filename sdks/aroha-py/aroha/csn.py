# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Aroha Capability Schema Negotiation (CSN) — Python SDK

Better than ANP meta-protocol:
  ANP: LLM generates NEW protocol → both sides code-generate → fragile
  Aroha CSN:
    1. Structural JSON Schema matching first (deterministic, no LLM)
    2. LLM only when structurally ambiguous (score 0.5–0.85)
    3. Result maps to an EXISTING typed Aroha capability
    4. Transaction terms negotiated in the same round
    5. Agreed schema SHA-256 cached → zero-latency on repeat calls

── Requestor usage ──────────────────────────────────────────────────────────
  negotiator = CapabilityNegotiator(client, orchestrator_did, private_key)
  result = await negotiator.discover(
      agent_endpoint="https://fx.example.com/aroha/v1",
      agent_did="did:aroha:fx-agent",
      request=DiscoveryRequest(
          capability_intent="convert currency from USD to JPY",
          desired_schema={
              "input": {"type": "object", "properties": {
                  "amount": {"type": "number"},
                  "from":   {"type": "string"},
                  "to":     {"type": "string"},
              }, "required": ["amount", "from", "to"]},
          },
      ),
  )
  # result.resolved_capability == "fx-convert"

── Provider usage ────────────────────────────────────────────────────────────
  registry = CapabilityRegistry()
  registry.register(CapabilityEntry(name="fx-convert", ...))
  handler = CSNHandler(registry, agent_did=did, private_key=key)

  # In your server's on_message handler:
  if envelope["type"] == "ArohaNegotiate" and "csn" in envelope["body"]:
      reply = await handler.handle(envelope, sender_did)
      respond(reply)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


# ── Schema matching ───────────────────────────────────────────────────────────

def schema_compatibility_score(
    desired: dict[str, Any],
    available: dict[str, Any],
) -> float:
    """
    Structural compatibility score 0–1.
    ≥ 0.85  → confident match, no LLM needed
    0.5–0.85 → ambiguous, LLM fallback recommended
    < 0.5   → incompatible
    """
    desired_props   = desired.get("properties", {})
    available_props = available.get("properties", {})
    required        = set(desired.get("required", []))

    if not desired_props:
        return 1.0  # no constraints → anything matches

    match_score  = 0.0
    total_weight = 0.0

    for key, desired_field in desired_props.items():
        weight        = 1.0 if key in required else 0.4
        total_weight += weight

        if key not in available_props:
            continue

        d_type = desired_field.get("type")
        a_type = available_props[key].get("type")

        if not d_type or not a_type or d_type == a_type:
            match_score += weight
        elif _types_compatible(d_type, a_type):
            match_score += weight * 0.7

    return (match_score / total_weight) if total_weight > 0 else 1.0


def _types_compatible(desired: str, available: str) -> bool:
    numeric = {"number", "integer"}
    return desired in numeric and available in numeric


def schema_hash(schema: dict[str, Any]) -> str:
    """SHA-256 hex of the canonical schema — cache key."""
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Capability registry ───────────────────────────────────────────────────────

@dataclass
class CapabilityEntry:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    supports_saga: bool = True
    default_pricing: dict[str, Any] | None = None
    default_sla: dict[str, Any] | None = None


@dataclass
class CapabilityMatch:
    entry: CapabilityEntry
    score: float
    confident: bool  # score >= 0.85


CONFIDENT_THRESHOLD = 0.85


class CapabilityRegistry:
    def __init__(self) -> None:
        self._caps: dict[str, CapabilityEntry] = {}

    def register(self, entry: CapabilityEntry) -> None:
        self._caps[entry.name] = entry

    def get(self, name: str) -> CapabilityEntry | None:
        return self._caps.get(name)

    def list_all(self) -> list[CapabilityEntry]:
        return list(self._caps.values())

    def find_by_input_schema(
        self, desired: dict[str, Any]
    ) -> CapabilityMatch | None:
        best: CapabilityMatch | None = None
        for entry in self._caps.values():
            score = schema_compatibility_score(desired, entry.input_schema)
            if best is None or score > best.score:
                best = CapabilityMatch(entry, score, score >= CONFIDENT_THRESHOLD)
        return best

    def find_candidates(
        self, desired: dict[str, Any], min_score: float = 0.5
    ) -> list[CapabilityMatch]:
        results = []
        for entry in self._caps.values():
            score = schema_compatibility_score(desired, entry.input_schema)
            if score >= min_score:
                results.append(CapabilityMatch(entry, score, score >= CONFIDENT_THRESHOLD))
        return sorted(results, key=lambda m: m.score, reverse=True)


# ── Discovery cache ───────────────────────────────────────────────────────────

@dataclass
class CacheEntry:
    capability_name: str
    agreed_schema: dict[str, Any]
    match_method: str
    compatibility_score: float | None
    cached_at: str
    hit_count: int = 0


class DiscoveryCache:
    def __init__(self) -> None:
        self._store: dict[str, CacheEntry] = {}

    def _key(self, agent_did: str, h: str) -> str:
        return f"{agent_did}:{h}"

    def get(self, agent_did: str, h: str) -> CacheEntry | None:
        entry = self._store.get(self._key(agent_did, h))
        if entry:
            entry.hit_count += 1
        return entry

    def put(
        self,
        agent_did: str,
        h: str,
        capability_name: str,
        agreed_schema: dict[str, Any],
        match_method: str,
        compatibility_score: float | None = None,
    ) -> None:
        from datetime import datetime, timezone
        self._store[self._key(agent_did, h)] = CacheEntry(
            capability_name=capability_name,
            agreed_schema=agreed_schema,
            match_method=match_method,
            compatibility_score=compatibility_score,
            cached_at=datetime.now(timezone.utc).isoformat(),
        )

    def invalidate(self, agent_did: str, capability_name: str | None = None) -> None:
        prefix = f"{agent_did}:"
        to_del = [k for k in self._store if k.startswith(prefix)]
        if capability_name:
            to_del = [k for k in to_del
                      if self._store[k].capability_name == capability_name]
        for k in to_del:
            del self._store[k]


# ── LLM matcher protocol ──────────────────────────────────────────────────────

class ICapabilityMatcher(Protocol):
    async def match(
        self,
        intent: str,
        candidates: list[dict[str, Any]],  # [{name, description, input_schema}]
    ) -> str | None:
        ...


# ── Request / result types ────────────────────────────────────────────────────

@dataclass
class DiscoveryRequest:
    capability_intent: str | None = None
    desired_schema: dict[str, Any] | None = None   # {input: {...}, output?: {...}}
    proposed_terms: dict[str, Any] = field(default_factory=dict)
    request_capability_manifest: bool = False


@dataclass
class DiscoveryResult:
    resolved_capability: str
    agreed_schema: dict[str, Any]
    agreed_terms: dict[str, Any]
    match_method: str   # "schema" | "intent" | "cache"
    compatibility_score: float | None = None
    capability_manifest: dict[str, Any] | None = None
    rounds: int = 0


# ── Requestor: CapabilityNegotiator ──────────────────────────────────────────

class CapabilityNegotiator:
    """
    Requestor-side CSN.  Call discover() to find and agree on a capability
    with a remote provider agent.
    """

    def __init__(
        self,
        send: Callable[[str, dict[str, Any]], Any],  # async fn(endpoint, envelope) → envelope
        orchestrator_did: str,
        private_key: Any,
        cache: DiscoveryCache | None = None,
    ) -> None:
        self._send            = send
        self._orchestrator_did = orchestrator_did
        self._private_key     = private_key
        self._cache           = cache or DiscoveryCache()

    async def discover(
        self,
        agent_endpoint: str,
        agent_did: str,
        request: DiscoveryRequest,
    ) -> DiscoveryResult:
        from .messages import build_envelope, new_correlation_id  # type: ignore[import]
        import asyncio

        h = schema_hash(request.desired_schema) if request.desired_schema else None

        # ── 1. Cache lookup ───────────────────────────────────────────────────
        if h:
            cached = self._cache.get(agent_did, h)
            if cached:
                return DiscoveryResult(
                    resolved_capability=cached.capability_name,
                    agreed_schema=cached.agreed_schema,
                    agreed_terms={},
                    match_method="cache",
                    compatibility_score=cached.compatibility_score,
                    rounds=0,
                )

        # ── 2. Send ArohaNegotiate ─────────────────────────────────────────────
        correlation_id = new_correlation_id()
        body = {
            "capability":    request.capability_intent or "unknown",
            "proposedTerms": request.proposed_terms,
            "csn": {
                "capabilityIntent":          request.capability_intent,
                "desiredSchema":             request.desired_schema,
                "schemaHash":                h,
                "requestCapabilityManifest": request.request_capability_manifest,
            },
        }
        envelope  = build_envelope(
            "ArohaNegotiate",
            self._orchestrator_did,
            agent_did,
            body,
            correlation_id,
            self._private_key,
        )
        response  = await self._send(agent_endpoint, envelope)

        if not response:
            raise RuntimeError(f"No response from {agent_did} during CSN discovery")
        if response.get("type") == "ArohaError":
            raise RuntimeError(f"CSN failed: {response['body'].get('message')}")

        # ── 3. Process ArohaAccept ─────────────────────────────────────────────
        if response.get("type") == "ArohaAccept":
            accept = response["body"]
            csn    = accept.get("csn", {})
            resolved   = csn.get("resolvedCapability") or accept.get("capability")
            agreed_sch = csn.get("agreedSchema") or request.desired_schema or {}
            method     = csn.get("matchMethod", "schema")
            compat     = csn.get("compatibilityScore")

            if h and agreed_sch:
                self._cache.put(agent_did, h, resolved, agreed_sch, method, compat)

            return DiscoveryResult(
                resolved_capability=resolved,
                agreed_schema=agreed_sch,
                agreed_terms=accept.get("acceptedTerms", {}),
                match_method=method,
                compatibility_score=compat,
                capability_manifest=csn.get("capabilityManifest"),
                rounds=1,
            )

        # ── 4. Counter-offer ──────────────────────────────────────────────────
        if response.get("type") == "ArohaCounterOffer":
            counter  = response["body"]
            csn      = counter.get("csn", {})
            resolved = csn.get("resolvedCapability") or counter.get("capability")

            if resolved:
                accept_body = {
                    "capability":    resolved,
                    "acceptedTerms": counter.get("revisedTerms", {}),
                }
                accept_env = build_envelope(
                    "ArohaAccept",
                    self._orchestrator_did,
                    agent_did,
                    accept_body,
                    correlation_id,
                    self._private_key,
                )
                await self._send(agent_endpoint, accept_env)

                agreed_sch = csn.get("agreedSchema") or request.desired_schema or {}
                if h and agreed_sch:
                    self._cache.put(agent_did, h, resolved, agreed_sch, "schema")

                return DiscoveryResult(
                    resolved_capability=resolved,
                    agreed_schema=agreed_sch,
                    agreed_terms=counter.get("revisedTerms", {}),
                    match_method="schema",
                    capability_manifest=csn.get("capabilityManifest"),
                    rounds=2,
                )

        raise RuntimeError(
            f"CSN negotiation with {agent_did} did not produce a capability agreement"
        )


# ── Provider: CSNHandler ──────────────────────────────────────────────────────

class CSNHandler:
    """
    Provider-side CSN.  Mount inside your server's on_message handler.

    Example:
        handler = CSNHandler(registry, agent_did=did, private_key=key,
                             llm_matcher=my_llm_adapter)
        if env["type"] == "ArohaNegotiate" and "csn" in env["body"]:
            reply = await handler.handle(env, sender_did)
            respond(reply)
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        agent_did: str,
        private_key: Any,
        llm_matcher: ICapabilityMatcher | None = None,
        serve_manifest: bool = True,
    ) -> None:
        self._registry       = registry
        self._agent_did      = agent_did
        self._private_key    = private_key
        self._llm_matcher    = llm_matcher
        self._serve_manifest = serve_manifest

    async def handle(
        self,
        inbound: dict[str, Any],
        sender_did: str,
    ) -> dict[str, Any]:
        from .messages import build_envelope  # type: ignore[import]

        body = inbound["body"]
        csn  = body.get("csn", {})
        correlation_id = inbound.get("correlationId", "")

        match_method = "schema"
        matched: dict[str, Any] | None = None  # {name, score}

        # ── 1. Structural schema matching ─────────────────────────────────────
        desired_input = (csn.get("desiredSchema") or {}).get("input")
        if desired_input:
            result = self._registry.find_by_input_schema(desired_input)
            if result and result.score >= 0.5:
                matched      = {"name": result.entry.name, "score": result.score}
                match_method = "schema"

        # ── 2. LLM fallback (ambiguous range) ─────────────────────────────────
        if (not matched or matched["score"] < 0.85) and csn.get("capabilityIntent") and self._llm_matcher:
            candidates_raw = self._registry.find_candidates(desired_input or {}, 0.0)
            candidates = [
                {
                    "name":         c.entry.name,
                    "description":  c.entry.description,
                    "input_schema": c.entry.input_schema,
                }
                for c in candidates_raw
            ]
            if candidates:
                try:
                    llm_name = await self._llm_matcher.match(
                        csn["capabilityIntent"], candidates
                    )
                except Exception:
                    llm_name = None

                if llm_name and self._registry.get(llm_name):
                    matched      = {"name": llm_name, "score": 0.75}
                    match_method = "intent"

        # ── 3. Direct capability name lookup ──────────────────────────────────
        cap_name = body.get("capability", "unknown")
        if not matched and cap_name and cap_name != "unknown":
            entry = self._registry.get(cap_name)
            if entry:
                matched      = {"name": entry.name, "score": 1.0}
                match_method = "schema"

        # ── No match → ArohaError ──────────────────────────────────────────────
        if not matched:
            return build_envelope(
                "ArohaError",
                self._agent_did,
                sender_did,
                {
                    "code":      "Aroha_UNKNOWN_CAPABILITY",
                    "message":   "No capability matched the provided intent or schema",
                    "retryable": False,
                },
                correlation_id,
                self._private_key,
            )

        entry = self._registry.get(matched["name"])
        assert entry is not None

        # ── 4. Build agreed schema ─────────────────────────────────────────────
        agreed_schema: dict[str, Any] = {"input": entry.input_schema}
        if entry.output_schema:
            agreed_schema["output"] = entry.output_schema

        # ── 5. Capability manifest if requested ────────────────────────────────
        manifest = None
        if csn.get("requestCapabilityManifest") and self._serve_manifest:
            manifest = self._build_manifest()

        # ── 6. Pricing / SLA terms ─────────────────────────────────────────────
        accepted_terms: dict[str, Any] = {}
        if entry.default_pricing:
            accepted_terms["price"] = entry.default_pricing
        if entry.default_sla:
            accepted_terms["sla"] = entry.default_sla
        accepted_terms.update(body.get("proposedTerms") or {})

        accept_body = {
            "capability":    matched["name"],
            "acceptedTerms": accepted_terms,
            "csn": {
                "resolvedCapability": matched["name"],
                "agreedSchema":       agreed_schema,
                "schemaHash":         csn.get("schemaHash"),
                "matchMethod":        match_method,
                "compatibilityScore": matched["score"],
                "capabilityManifest": manifest,
            },
        }
        return build_envelope(
            "ArohaAccept",
            self._agent_did,
            sender_did,
            accept_body,
            correlation_id,
            self._private_key,
        )

    def _build_manifest(self) -> dict[str, Any]:
        from datetime import datetime, timezone
        return {
            "agentDID":     self._agent_did,
            "capabilities": [
                {
                    "name":         e.name,
                    "description":  e.description,
                    "inputSchema":  e.input_schema,
                    "outputSchema": e.output_schema,
                    "supportsSaga": e.supports_saga,
                }
                for e in self._registry.list_all()
            ],
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
