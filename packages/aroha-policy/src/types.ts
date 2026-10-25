// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Policy-as-Code — type definitions.
 *
 * Policies are deterministic JSON rules evaluated BEFORE the application
 * handler or LLM sees an inbound ArohaRequest. Violations are rejected by
 * the transport layer with a structured ArohaError — the LLM is never
 * involved in the security decision.
 *
 * This removes the "emergent liability" risk: an agent cannot hallucinate
 * its way past a maxSpend limit or attempt a blocked action because the
 * protocol rejects the envelope before the application layer runs.
 */

// ─── Capability policy ────────────────────────────────────────────────────────

export interface CapabilityPolicy {
  /** The capability this policy applies to. Supports "*" wildcard as a global default. */
  capabilityId: string;

  /**
   * Maximum spend per call in the specified currency.
   * Checked against params.amount, params.price, params.total, or any
   * top-level numeric field matching a configured amountField.
   */
  maxSpendPerCall?: {
    amount: number;
    currency: string;
    /** Param key to read the amount from (default: "amount") */
    paramKey?: string;
  };

  /**
   * Allow-list of permitted top-level param keys.
   * If set, any request containing a param key NOT in this list is rejected.
   * Use to prevent prompt-injection through unexpected fields.
   */
  allowedParamKeys?: string[];

  /**
   * Deny-list of param key → value combinations.
   * If the request contains any (key, value) pair matching an entry here,
   * it is rejected. Use for blocklist enforcement ("action": "delete", etc.).
   */
  blockedParamValues?: Array<{ key: string; value: unknown }>;

  /**
   * Required param keys — request is rejected if any listed key is absent.
   * Ensures structured payloads: agents cannot omit mandatory fields.
   */
  requiredParamKeys?: string[];

  /**
   * Allowed values for a specific param key.
   * If set, requests with any other value for that key are rejected.
   * Example: { key: "action", allowedValues: ["read", "list"] }
   */
  paramAllowedValues?: Array<{ key: string; allowedValues: unknown[] }>;

  /**
   * Rate limit per sender DID per minute.
   * Requires the policy engine to be initialized with rate-limit storage.
   */
  rateLimitPerMinute?: number;

  /**
   * If true, all calls to this capability require human approval
   * regardless of SagaEngine configuration.
   * This is a hard policy rule — not overridable by the orchestrator.
   */
  requiresHITLApproval?: boolean;
}

// ─── Policy result ────────────────────────────────────────────────────────────

export type PolicyOutcome = "allow" | "deny";

export interface PolicyResult {
  outcome: PolicyOutcome;
  /** The specific rule that caused the denial. */
  violatedRule?: string;
  /** Human-readable reason for logging and error responses. */
  reason?: string;
}

// ─── Policy engine interface ──────────────────────────────────────────────────

export interface IPolicyEngine {
  /** Evaluate a policy for an inbound ArohaRequest. */
  evaluate(
    capability: string,
    params: Record<string, unknown>,
    senderDID: string
  ): Promise<PolicyResult>;
  /** Register a policy rule. Later rules for the same capability overwrite earlier ones. */
  addPolicy(policy: CapabilityPolicy): void;
  /** Remove a policy by capability ID. */
  removePolicy(capabilityId: string): void;
}
