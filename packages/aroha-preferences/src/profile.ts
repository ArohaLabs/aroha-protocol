// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Preferences — User Preference Profile (Layer 5)
 *
 * The PreferenceProfile is owned by the user's Personal Agent.
 * It is never shared without the user's explicit consent (consentToken).
 * It has no network presence — it lives entirely within the Personal Agent.
 *
 * Structure:
 *   static   — explicitly set by the user (budget, brands, accessibility)
 *   dynamic  — learned from past transactions (per-agent scores, capability preferences)
 *   consent  — controls what can be shared and with whom
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BudgetPreference {
  max: number;
  currency: string;
}

export interface QualityPreference {
  minRating?: number;
  preferQuality?: boolean;
  preferPrice?: boolean;
  preferSpeed?: boolean;
}

export interface StaticPreferences {
  budget: Record<string, BudgetPreference>;  // keyed by capability domain e.g. "travel"
  quality: Record<string, QualityPreference>; // keyed by capability id e.g. "book-flight"
  brands: {
    preferred: string[];  // agent DIDs the user explicitly prefers
    blocked:   string[];  // agent DIDs the user has blocked
  };
  accessibility: Record<string, boolean | string>;
  constraints: string[];  // e.g. ["direct-flights-only", "vegetarian-meals"]
}

export interface AgentDynamicScore {
  /** Satisfaction score 0–1 (EMA of past outcomes) */
  score: number;
  /** Number of completed transactions with this agent */
  transactions: number;
  /** ISO8601 timestamp of last interaction */
  lastUsed: string;
}

export interface CapabilityPreference {
  /** 0–1 EMA weight. Higher = user more strongly needs better price. */
  priceWeight:   number;
  /** 0–1 EMA weight. Higher = user more strongly needs better quality. */
  qualityWeight: number;
  /** 0–1 EMA weight. Higher = user more strongly needs better speed. */
  speedWeight:   number;
}

export interface DynamicPreferences {
  /** Per-agent satisfaction scores, keyed by agent DID */
  agentScores: Record<string, AgentDynamicScore>;
  /** Per-capability dimension preferences, keyed by capability id */
  capabilityPreferences: Record<string, CapabilityPreference>;
  /** Whether the user prefers bundled multi-capability agents */
  preferBundled: boolean;
  /** Agent DIDs trusted to offer bundles */
  trustedBundlers: string[];
}

export interface ConsentSettings {
  /** Agent DIDs allowed to receive a scoped preference context */
  allowPreferenceSharingWith: string[];
  /** Whether anonymized preference signals can be aggregated */
  allowAnonymizedAggregation: boolean;
  /** How long to retain preference history (days) */
  dataRetentionDays: number;
}

export interface PreferenceProfile {
  version: "1.0";
  /** DID of the Personal Agent that owns this profile */
  ownerDID: string;
  lastUpdated: string;
  static: StaticPreferences;
  dynamic: DynamicPreferences;
  consent: ConsentSettings;
}

// ─── Default factory ──────────────────────────────────────────────────────────

export function createDefaultProfile(ownerDID: string): PreferenceProfile {
  return {
    version: "1.0",
    ownerDID,
    lastUpdated: new Date().toISOString(),
    static: {
      budget: {},
      quality: {},
      brands: { preferred: [], blocked: [] },
      accessibility: {},
      constraints: [],
    },
    dynamic: {
      agentScores: {},
      capabilityPreferences: {},
      preferBundled: false,
      trustedBundlers: [],
    },
    consent: {
      allowPreferenceSharingWith: [],
      allowAnonymizedAggregation: false,
      dataRetentionDays: 365,
    },
  };
}

// ─── Profile mutations ────────────────────────────────────────────────────────

export function blockAgent(profile: PreferenceProfile, agentDID: string): PreferenceProfile {
  const blocked = new Set([...profile.static.brands.blocked, agentDID]);
  const preferred = profile.static.brands.preferred.filter((d) => d !== agentDID);
  return touch({
    ...profile,
    static: {
      ...profile.static,
      brands: { preferred, blocked: [...blocked] },
    },
  });
}

export function preferAgent(profile: PreferenceProfile, agentDID: string): PreferenceProfile {
  const preferred = new Set([...profile.static.brands.preferred, agentDID]);
  return touch({
    ...profile,
    static: {
      ...profile.static,
      brands: { ...profile.static.brands, preferred: [...preferred] },
    },
  });
}

export function setBudget(
  profile: PreferenceProfile,
  domain: string,
  max: number,
  currency = "USD"
): PreferenceProfile {
  return touch({
    ...profile,
    static: {
      ...profile.static,
      budget: { ...profile.static.budget, [domain]: { max, currency } },
    },
  });
}

function touch(profile: PreferenceProfile): PreferenceProfile {
  return { ...profile, lastUpdated: new Date().toISOString() };
}
