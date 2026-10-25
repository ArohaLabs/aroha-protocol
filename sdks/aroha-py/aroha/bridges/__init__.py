# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

# aroha.bridges — Framework adapters for the Aroha /v1/run protocol
#
# Two families:
#
# ── v1/run bridges (wrap a framework as an Aroha /v1/run server) ──────────────
#
#   langchain_v1     pip install aroha[langchain]       from_chain()
#                    pip install aroha[langgraph]       from_graph()
#   crewai_v1        pip install aroha[crewai]          from_crew()
#   openai_v1        pip install aroha[openai]          from_openai_client()
#                    pip install aroha[openai-agents]   from_openai_agent()
#   google_adk       pip install aroha[google-adk]      from_runner()
#
#   All factories accept:
#     expose_mcp=True            — mount /mcp JSON-RPC endpoint
#     content_guard=callable     — block prompt injection before handler runs
#     approval_timeout=300.0     — HITL auto-reject after N seconds
#     bearer_tokens={...}        — protect endpoint with Bearer auth
#     memory="session"           — auto-persist conversation history
#
# ── Protocol-layer bridges (Aroha capabilities as framework tools) ────────────
#
#   langchain_bridge   Aroha capabilities as LangChain tools   aroha_tools_for_agent()
#   crewai_bridge      Aroha capabilities as CrewAI tools      ArohaCrewTool, aroha_tools_for_crew()
#   autogen_bridge     Aroha capabilities as AutoGen tools     aroha_tools_for_autogen()
#
#   These send signed ArohaRequest envelopes (aroha.messages), not /v1/run.
#   Use them when integrating with agents that already speak the Aroha protocol.
#   Shared, framework-free logic lives in aroha.bridges._common.
#
# Versions each bridge was tested against are in its module docstring
# (tests/test_bridges_*.py; run them with the framework installed).
