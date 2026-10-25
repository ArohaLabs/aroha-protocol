// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Duck-typed interfaces for LangChain-style tools and OpenAI function tools.
 *
 * These interfaces are intentionally minimal — they match the public API surface
 * that matters for Aroha bridging without requiring a hard dependency on any
 * specific framework version.
 */

// ─── LangChain / LangGraph style ─────────────────────────────────────────────

export interface LangChainToolLike {
  name: string;
  description: string;
  /** JSON Schema for the tool's input. Optional — used for agent auto-binding. */
  schema?: Record<string, unknown>;
  /** Invoke the tool. Input may be a JSON string or an object. */
  call(input: string | Record<string, unknown>): Promise<string>;
}

// ─── OpenAI Chat Completions function tool ───────────────────────────────────

export interface OpenAIFunctionLike {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters?: Record<string, unknown>;
  };
  /** Invoke the function. */
  invoke(args: Record<string, unknown>): Promise<unknown>;
}

// ─── Aroha capability descriptor (for converting tools → Aroha capabilities) ───

export interface ArohaCapabilityDescriptor {
  capabilityId: string;
  description: string;
  inputSchema?: Record<string, unknown>;
}
