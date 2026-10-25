// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Policy Engine — deterministic, zero-inference policy enforcement.
 *
 * Rules are evaluated purely against JSON values. The LLM never participates
 * in the security decision. If a rule denies a request, the transport layer
 * rejects the envelope before any application code runs.
 */

import {
  type CapabilityPolicy,
  type PolicyResult,
  type IPolicyEngine,
} from "./types.js";

// ─── Rate limiter (in-process) ────────────────────────────────────────────────

class SlidingWindowCounter {
  private readonly windows = new Map<string, number[]>();

  check(key: string, limitPerMinute: number): boolean {
    const now = Date.now();
    const windowStart = now - 60_000;
    const calls = (this.windows.get(key) ?? []).filter((t) => t > windowStart);
    calls.push(now);
    this.windows.set(key, calls);
    return calls.length <= limitPerMinute;
  }
}

// ─── ArohaPolicyEngine ─────────────────────────────────────────────────────────

export class ArohaPolicyEngine implements IPolicyEngine {
  private readonly policies = new Map<string, CapabilityPolicy>();
  private readonly rateLimiter = new SlidingWindowCounter();

  addPolicy(policy: CapabilityPolicy): void {
    this.policies.set(policy.capabilityId, policy);
  }

  removePolicy(capabilityId: string): void {
    this.policies.delete(capabilityId);
  }

  async evaluate(
    capability: string,
    params: Record<string, unknown>,
    senderDID: string
  ): Promise<PolicyResult> {
    // Check specific policy first, then wildcard fallback
    const policy = this.policies.get(capability) ?? this.policies.get("*");
    if (!policy) return { outcome: "allow" };

    // 1. Required param keys
    if (policy.requiredParamKeys) {
      for (const key of policy.requiredParamKeys) {
        if (!(key in params)) {
          return {
            outcome: "deny",
            violatedRule: "requiredParamKeys",
            reason: `Required parameter "${key}" is missing`,
          };
        }
      }
    }

    // 2. Allowed param keys (blocklist of unknowns)
    if (policy.allowedParamKeys) {
      const allowed = new Set(policy.allowedParamKeys);
      for (const key of Object.keys(params)) {
        if (!allowed.has(key)) {
          return {
            outcome: "deny",
            violatedRule: "allowedParamKeys",
            reason: `Parameter "${key}" is not permitted for capability "${capability}"`,
          };
        }
      }
    }

    // 3. Blocked param values
    if (policy.blockedParamValues) {
      for (const { key, value } of policy.blockedParamValues) {
        if (key in params && deepEqual(params[key], value)) {
          return {
            outcome: "deny",
            violatedRule: "blockedParamValues",
            reason: `Parameter "${key}" value "${JSON.stringify(value)}" is blocked for capability "${capability}"`,
          };
        }
      }
    }

    // 4. Param allowed-values (allowlist for specific keys)
    if (policy.paramAllowedValues) {
      for (const { key, allowedValues } of policy.paramAllowedValues) {
        if (key in params) {
          const found = allowedValues.some((v) => deepEqual(params[key], v));
          if (!found) {
            return {
              outcome: "deny",
              violatedRule: "paramAllowedValues",
              reason: `Parameter "${key}" has value "${JSON.stringify(params[key])}" which is not in the allowed list for "${capability}"`,
            };
          }
        }
      }
    }

    // 5. Max spend
    if (policy.maxSpendPerCall) {
      const { amount, currency, paramKey = "amount" } = policy.maxSpendPerCall;
      const rawAmount = params[paramKey];
      if (typeof rawAmount === "number" && rawAmount > amount) {
        return {
          outcome: "deny",
          violatedRule: "maxSpendPerCall",
          reason: `Requested amount ${rawAmount} ${currency} exceeds policy limit of ${amount} ${currency}`,
        };
      }
    }

    // 6. Rate limiting
    if (policy.rateLimitPerMinute != null) {
      const key = `${senderDID}::${capability}`;
      if (!this.rateLimiter.check(key, policy.rateLimitPerMinute)) {
        return {
          outcome: "deny",
          violatedRule: "rateLimitPerMinute",
          reason: `Rate limit of ${policy.rateLimitPerMinute} calls/min exceeded for "${capability}" from ${senderDID}`,
        };
      }
    }

    return { outcome: "allow" };
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a === "object" && a !== null && b !== null) {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return false;
}
