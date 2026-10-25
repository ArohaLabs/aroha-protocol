// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Capability Taxonomy
 *
 * Defines the reversibility and risk tier of well-known capabilities.
 * Used by the SDK to enforce reversibleOnly mandates and guide personal agents
 * on appropriate gating policy.
 *
 * Vendor agents may register custom capabilities with custom reversibility/tier
 * via their capability manifest. This taxonomy covers the canonical built-in set.
 */

import type { CapabilityReversibility, RiskTier } from "../messages/types.js";

export interface CapabilityMeta {
  reversibility: CapabilityReversibility;
  tier: RiskTier;
  description: string;
  /** True if this capability can have financial cost implications. */
  hasFinancialImplication: boolean;
  /** Sub-capabilities — delegatable sub-actions within this capability. */
  subCapabilities?: string[];
}

/**
 * Canonical capability registry.
 * Keys are exact capability IDs as registered on the Hub.
 */
export const CAPABILITY_TAXONOMY: Record<string, CapabilityMeta> = {
  // ── Tier 1 — Read-only, no side effects ───────────────────────────────────

  "web-search": {
    reversibility: "full", tier: 1,
    description: "Search the web and return results",
    hasFinancialImplication: false,
  },
  "web-read": {
    reversibility: "full", tier: 1,
    description: "Fetch and read a web page",
    hasFinancialImplication: false,
  },
  "read-file": {
    reversibility: "full", tier: 1,
    description: "Read a file from the filesystem or cloud storage",
    hasFinancialImplication: false,
  },
  "query-database-read": {
    reversibility: "full", tier: 1,
    description: "Execute a read-only database query",
    hasFinancialImplication: false,
  },
  "summarise": {
    reversibility: "full", tier: 1,
    description: "Summarise provided content via an LLM",
    hasFinancialImplication: false,
  },
  "get-weather": {
    reversibility: "full", tier: 1,
    description: "Fetch current weather data",
    hasFinancialImplication: false,
  },
  "get-stock-price": {
    reversibility: "full", tier: 1,
    description: "Fetch financial instrument prices",
    hasFinancialImplication: false,
  },
  "check-availability": {
    reversibility: "full", tier: 1,
    description: "Check availability of a resource without reserving it",
    hasFinancialImplication: false,
  },
  "check-balance": {
    reversibility: "full", tier: 1,
    description: "Read an account balance",
    hasFinancialImplication: false,
  },
  "list-transactions": {
    reversibility: "full", tier: 1,
    description: "List historical transactions (read-only)",
    hasFinancialImplication: false,
  },
  "research": {
    reversibility: "full", tier: 1,
    description: "Multi-step web research (search + read + synthesise)",
    hasFinancialImplication: false,
    subCapabilities: ["web-search", "web-read", "summarise"],
  },
  "echo": {
    reversibility: "full", tier: 1,
    description: "Echo input back — used for testing and demos",
    hasFinancialImplication: false,
  },

  // ── Tier 2 — Creates artefacts; semi-reversible ───────────────────────────

  "draft-email": {
    reversibility: "semi", tier: 2,
    description: "Draft an email (not sent until send-email is called)",
    hasFinancialImplication: false,
  },
  "draft-document": {
    reversibility: "semi", tier: 2,
    description: "Create a draft document",
    hasFinancialImplication: false,
  },
  "create-calendar-event": {
    reversibility: "semi", tier: 2,
    description: "Create a calendar event (can be deleted)",
    hasFinancialImplication: false,
  },
  "write-file": {
    reversibility: "semi", tier: 2,
    description: "Write to a file (can be overwritten or deleted)",
    hasFinancialImplication: false,
  },
  "book-refundable": {
    reversibility: "semi", tier: 2,
    description: "Make a fully refundable reservation",
    hasFinancialImplication: true,
  },
  "create-draft-post": {
    reversibility: "semi", tier: 2,
    description: "Create a draft social media post (not published)",
    hasFinancialImplication: false,
  },

  // ── Tier 3 — Irreversible non-financial ───────────────────────────────────

  "send-email": {
    reversibility: "irreversible", tier: 3,
    description: "Send an email to one or more recipients",
    hasFinancialImplication: false,
  },
  "publish-post": {
    reversibility: "irreversible", tier: 3,
    description: "Publish a post to a public platform",
    hasFinancialImplication: false,
  },
  "submit-form": {
    reversibility: "irreversible", tier: 3,
    description: "Submit a form to an external service",
    hasFinancialImplication: false,
  },
  "delete-file": {
    reversibility: "irreversible", tier: 3,
    description: "Permanently delete a file",
    hasFinancialImplication: false,
  },
  "database-write": {
    reversibility: "irreversible", tier: 3,
    description: "Write to a database (INSERT / UPDATE / DELETE)",
    hasFinancialImplication: false,
  },
  "send-webhook": {
    reversibility: "irreversible", tier: 3,
    description: "Send an HTTP webhook to an external endpoint",
    hasFinancialImplication: false,
  },
  "invite-user": {
    reversibility: "irreversible", tier: 3,
    description: "Send a user invitation via email",
    hasFinancialImplication: false,
  },

  // ── Tier 4 — Financial transactions ──────────────────────────────────────

  "book-flight": {
    reversibility: "irreversible", tier: 4,
    description: "Book a non-refundable or partially refundable flight",
    hasFinancialImplication: true,
  },
  "book-hotel": {
    reversibility: "irreversible", tier: 4,
    description: "Book a hotel room",
    hasFinancialImplication: true,
  },
  "pay-bill": {
    reversibility: "irreversible", tier: 4,
    description: "Pay a utility or other bill",
    hasFinancialImplication: true,
  },
  "transfer-funds": {
    reversibility: "irreversible", tier: 4,
    description: "Transfer funds between accounts",
    hasFinancialImplication: true,
  },
  "charge-card": {
    reversibility: "irreversible", tier: 4,
    description: "Charge a payment card",
    hasFinancialImplication: true,
  },
  "place-order": {
    reversibility: "semi", tier: 4,
    description: "Place a purchase order (may be cancellable within a window)",
    hasFinancialImplication: true,
  },
  "subscribe": {
    reversibility: "irreversible", tier: 4,
    description: "Create a recurring subscription",
    hasFinancialImplication: true,
  },

  // ── Tier 5 — System-level meta-actions ───────────────────────────────────

  "deploy-code": {
    reversibility: "irreversible", tier: 5,
    description: "Deploy code to a live environment",
    hasFinancialImplication: true,
  },
  "run-code": {
    reversibility: "semi", tier: 5,
    description: "Execute arbitrary code (must be sandboxed)",
    hasFinancialImplication: false,
  },
  "create-agent": {
    reversibility: "semi", tier: 5,
    description: "Programmatically create and register a new agent",
    hasFinancialImplication: false,
  },
  "modify-permissions": {
    reversibility: "irreversible", tier: 5,
    description: "Modify access control or permission settings",
    hasFinancialImplication: false,
  },
  "modify-infrastructure": {
    reversibility: "irreversible", tier: 5,
    description: "Create, modify, or destroy cloud infrastructure",
    hasFinancialImplication: true,
  },
};

/**
 * Get the reversibility of a capability.
 * Returns "irreversible" for unknown capabilities (fail-closed).
 */
export function getReversibility(capabilityId: string): CapabilityReversibility {
  return CAPABILITY_TAXONOMY[capabilityId]?.reversibility ?? "irreversible";
}

/**
 * Get the risk tier of a capability.
 * Returns 5 for unknown capabilities (fail-closed — treat unknowns as highest risk).
 */
export function getRiskTier(capabilityId: string): RiskTier {
  return CAPABILITY_TAXONOMY[capabilityId]?.tier ?? 5;
}

/**
 * Returns true if the capability is safe to auto-execute (no human gate needed).
 * Only Tier 1 and Tier 2 capabilities qualify.
 */
export function isAutoExecutable(capabilityId: string): boolean {
  const tier = getRiskTier(capabilityId);
  return tier <= 2;
}

/**
 * Returns true if executing this capability from within a given mandate is allowed.
 * Checks:
 *   1. Capability is in the mandate's allowed list
 *   2. Capability is not in the mandate's blocked list
 *   3. If reversibleOnly is true, capability must not be irreversible
 */
export function isPermitted(
  capabilityId: string,
  allowed: string[],
  blocked?: string[],
  reversibleOnly?: boolean
): { permitted: boolean; reason?: string } {
  if (!allowed.includes(capabilityId)) {
    return { permitted: false, reason: `Capability "${capabilityId}" is not in the mandate's allowed list` };
  }
  if (blocked?.includes(capabilityId)) {
    return { permitted: false, reason: `Capability "${capabilityId}" is explicitly blocked by the mandate` };
  }
  if (reversibleOnly && getReversibility(capabilityId) === "irreversible") {
    return {
      permitted: false,
      reason: `Capability "${capabilityId}" is irreversible but mandate requires reversibleOnly`,
    };
  }
  return { permitted: true };
}
