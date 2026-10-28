# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha — Aroha Protocol, Python SDK

Quick start (hosted agent):
    from aroha.agent import serve

    @serve(name="My Agent", system_prompt="Be helpful.")
    async def my_agent(message, session_id, history, context):
        return "Hello!"

    my_agent.start(port=8000)

Intelligent model routing (new in v1.2):
    from aroha.routing import ModelSession, ModelBudgetMandate, TaskType
    from aroha.routing.providers.anthropic import AnthropicProvider

    provider = AnthropicProvider(api_key="sk-ant-...")
    session  = ModelSession.create(
        provider=provider,
        mandate=ModelBudgetMandate(
            token_budget=20_000,
            cost_budget_usd=0.05,
            quality_threshold=0.80,
            task_type=TaskType.CODE,
        ),
    )
    response = await session.chat("refactor this function to be async...")
    print(session.tracker.summary())

Hub registration:
    from aroha import register_agent, call_agent, register_mcp, register_skill
    # (aroha.hub also exposes resolve_agent, list_agents, delete_agent, resolve_mcp)

Protocol layers (advanced):
    aroha.identity     → Layer 1 (DID, Ed25519 keypairs, local-vs-publishable identity)
    aroha.credentials  → Verifiable Credentials — issue_credential, CorporateIdentityCredential
    aroha.crypto       → Signing, verification, encryption, sign_canonical (bare signatures)
    aroha.manifest     → Manifest builders for agent/mcp/skill entity kinds
    aroha.messages     → Layer 3 (THE envelope builder/validator, 19 message types, error codes)
    aroha.jcs          → RFC 8785 canonical JSON (byte-identical to the TypeScript SDK)
    aroha.kel          → Rotatable did:aroha:E… identifiers and Key Event Logs (verification)
    aroha.transport    → Layer 0 (HTTP + WebSocket server/client — /aroha/v1)
    aroha.orchestrator → Layer 4 (saga engine, agent selector)
    aroha.csn          → Capability Specification Notation
    aroha.mandate      → Spending mandates, v2 wire format (verify_mandate_chain)
    aroha.task_mandate → Task mandates, v2 wire format (issue/attenuate/verify/enforce)
    aroha.http_mandate → Mandates on plain HTTP: Aroha-Mandate header with holder proof
    aroha.enrollment   → Account → DID enrollment (login + key proof over a single-use challenge)
    aroha.reputation   → Stake-weighted reputation engine
    aroha.routing      → Token-budget-aware model routing (v1.2+)
    aroha.consult      → Agent-to-agent consults — wire shapes + loop prevention
    aroha.policy       → Outbound PII screening for text leaving the agent

Framework bridges (install extras):
    aroha.bridges.langchain_v1      (pip install aroha[langchain] / aroha[langgraph])
    aroha.bridges.langchain_bridge  (pip install aroha[langchain])
    aroha.bridges.crewai_v1         (pip install aroha[crewai])
    aroha.bridges.crewai_bridge     (pip install aroha[crewai])
    aroha.bridges.google_adk        (pip install aroha[google-adk])
    aroha.bridges.openai_v1         (pip install aroha[openai] / aroha[openai-agents])
    aroha.bridges.autogen_bridge    (pip install aroha[autogen])
    aroha.routing.providers.anthropic  (pip install aroha[anthropic])
    aroha.routing.providers.openai     (pip install aroha[openai])
"""

# /v1/run layer — the standard invocation interface
from aroha.agent import serve, ArohaAgent
from aroha.hub   import (
    register_agent, resolve_agent, list_agents, delete_agent, call_agent,
    register_mcp, resolve_mcp,
    register_skill,
)

# Private agents — aroha-sig request signing
from aroha.signing import (
    sign_request,
    verify_signed_request,
    canonical_string,
    NonceGuard,
    registry_key_resolver,
)

# Protocol transport layer (advanced / A2A)
from aroha.identity  import generate_did, AgentKeyPair, DIDDocument, mint_local_identity, prepare_publish
from aroha.messages  import (
    build_envelope, validate_envelope, ArohaEnvelope, NonceRegistry, FileNonceStore, MapNonceStore,
    ArohaErrorCode, MESSAGE_TYPES,
)
from aroha.jcs       import canonicalize_jcs
from aroha.kel       import verify_kel, kel_key_resolver, is_inception_did, KelError
from aroha.mandate   import (
    verify_mandate, verify_mandate_chain, issue_intent_mandate, attenuate_to_cart, attenuate_to_payment,
    SpendingConstraints, MandateVerificationResult,
)
from aroha.http_mandate import (
    present_mandate_http, verify_http_presentation, verify_http_mandate_request,
    InMemoryHttpPresentationNonces, HTTP_MANDATE_HEADER, verify_http_spend_request,
)
from aroha.spending_ledger import (
    InMemorySpendingLedger, BudgetExhaustedError,
)
from aroha.enrollment import (
    issue_enrollment_challenge, complete_enrollment, enrolled_did, sign_enrollment,
    InMemoryEnrollmentStore, EnrollmentResult, ENROLLMENT_PURPOSE,
)
from aroha.task_mandate import (
    issue_task_mandate, attenuate_task_mandate, verify_task_mandate, enforce_task_constraints,
    check_task_constraints, check_task_narrowing,
    TaskConstraints, TaskActionRequest, TaskConstraintViolation,
)
from aroha.transport import ArohaServer, ArohaClient
from aroha.crypto     import sign_canonical, verify_canonical
from aroha.credentials import (
    issue_credential, verify_credential, is_credential_expired,
    issue_corporate_identity_credential,
)
from aroha.manifest import (
    build_agent_manifest, build_mcp_manifest, build_skill_manifest, validate_manifest,
)
from aroha.policy import (
    OutboundRule, OutboundRedaction, OutboundScreenResult, OutboundScreener,
    create_outbound_screener,
)
from aroha.consult import (
    CONSULT_CAPABILITY, DEFAULT_MAX_CONSULT_HOPS,
    ConsultParams, ConsultResult, ConsultSource,
    ConsultLoopState, ConsultLoopVerdict,
    check_consult_loop, next_consult_hop,
)

__version__ = "2.1.0"
__all__ = [
    # /v1/run layer
    "serve",
    "ArohaAgent",
    "register_agent",
    "resolve_agent",
    "list_agents",
    "delete_agent",
    "call_agent",
    "register_mcp",
    "resolve_mcp",
    "register_skill",
    # Private agents
    "sign_request",
    "verify_signed_request",
    "canonical_string",
    "NonceGuard",
    "registry_key_resolver",
    # Protocol transport layer
    "generate_did",
    "AgentKeyPair",
    "DIDDocument",
    "build_envelope",
    "validate_envelope",
    "ArohaEnvelope",
    "NonceRegistry",
    "FileNonceStore",
    "MapNonceStore",
    "ArohaErrorCode",
    "MESSAGE_TYPES",
    "canonicalize_jcs",
    "verify_kel",
    "kel_key_resolver",
    "is_inception_did",
    "KelError",
    "verify_mandate",
    "verify_mandate_chain",
    "issue_intent_mandate",
    "attenuate_to_cart",
    "attenuate_to_payment",
    "SpendingConstraints",
    "MandateVerificationResult",
    "present_mandate_http",
    "verify_http_presentation",
    "verify_http_mandate_request",
    "InMemoryHttpPresentationNonces",
    "HTTP_MANDATE_HEADER",
    "verify_http_spend_request",
    "issue_enrollment_challenge",
    "complete_enrollment",
    "enrolled_did",
    "sign_enrollment",
    "InMemoryEnrollmentStore",
    "EnrollmentResult",
    "ENROLLMENT_PURPOSE",
    "InMemorySpendingLedger",
    "BudgetExhaustedError",
    "issue_task_mandate",
    "attenuate_task_mandate",
    "verify_task_mandate",
    "enforce_task_constraints",
    "check_task_constraints",
    "check_task_narrowing",
    "TaskConstraints",
    "TaskActionRequest",
    "TaskConstraintViolation",
    "ArohaServer",
    "ArohaClient",
    "mint_local_identity",
    "prepare_publish",
    "sign_canonical",
    "verify_canonical",
    "issue_credential",
    "verify_credential",
    "is_credential_expired",
    "issue_corporate_identity_credential",
    "build_agent_manifest",
    "build_mcp_manifest",
    "build_skill_manifest",
    "validate_manifest",
    # Outbound PII screening
    "OutboundRule",
    "OutboundRedaction",
    "OutboundScreenResult",
    "OutboundScreener",
    "create_outbound_screener",
    # Consult (agent-to-agent question answering)
    "CONSULT_CAPABILITY",
    "DEFAULT_MAX_CONSULT_HOPS",
    "ConsultParams",
    "ConsultResult",
    "ConsultSource",
    "ConsultLoopState",
    "ConsultLoopVerdict",
    "check_consult_loop",
    "next_consult_hop",
]
