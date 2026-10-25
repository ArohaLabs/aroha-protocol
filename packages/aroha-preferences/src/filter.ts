// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { type PreferenceProfile } from "./profile.js";
import { type DiscoveredAgent } from "@aroha-sdk/registry";

// ─── Hard Filter ──────────────────────────────────────────────────────────────

export function filterAgents(
  agents: DiscoveredAgent[],
  profile: PreferenceProfile,
  capabilityId: string,
  options: FilterOptions = {}
): DiscoveredAgent[] {
  const { userTrustLevel = 1, domain } = options;
  const blocked = new Set(profile.static.brands.blocked);
  const budget = domain ? profile.static.budget[domain] : undefined;

  return agents.filter((agent) => {
    if (blocked.has(agent.manifest.did)) return false;

    const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
    if (cap && cap.requiredTrustLevel > userTrustLevel) return false;

    if (budget && cap?.pricing.model === "per-transaction" && cap.pricing.fee) {
      const fee = parseFloat(cap.pricing.fee);
      if (!isNaN(fee) && fee > budget.max) return false;
    }

    return true;
  });
}

export interface FilterOptions {
  userTrustLevel?: 0 | 1 | 2 | 3 | 4;
  domain?: string;
}

// ─── Scoring constants ────────────────────────────────────────────────────────

/** Exponential decay half-life in days. Score drifts toward 0.5 when unused. */
const DECAY_HALF_LIFE_DAYS = 180;

/** Starting score for agents with no history, keyed by required trust level. */
const TRUST_LEVEL_PRIORS: Record<0 | 1 | 2 | 3 | 4, number> = {
  0: 0.30,
  1: 0.45,
  2: 0.55,
  3: 0.70,
  4: 0.85,
};

// ─── Soft Scorer ─────────────────────────────────────────────────────────────

export function scoreAgents(
  agents: DiscoveredAgent[],
  profile: PreferenceProfile,
  capabilityId: string
): Record<string, number> {
  const scores: Record<string, number> = {};
  const preferred = new Set(profile.static.brands.preferred);
  const capPref = profile.dynamic.capabilityPreferences[capabilityId];

  for (const agent of agents) {
    const did = agent.manifest.did;
    const dynamic = profile.dynamic.agentScores[did];

    // Base score: time-decayed EMA or trust-level prior for unknown agents
    let score: number;
    if (dynamic) {
      score = decayScore(dynamic.score, dynamic.lastUsed);
    } else {
      const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
      const trustLevel = ((cap?.requiredTrustLevel ?? 1) as 0 | 1 | 2 | 3 | 4);
      score = TRUST_LEVEL_PRIORS[trustLevel];
    }

    // Preferred brand boost
    if (preferred.has(did)) score = Math.min(1, score + 0.15);

    // Trusted bundler boost
    if (profile.dynamic.preferBundled && profile.dynamic.trustedBundlers.includes(did)) {
      score = Math.min(1, score + 0.12);
    }

    // Dimension preference boost — small signal toward agents matching what the user needs
    if (capPref) {
      const cap = agent.manifest.capabilities.find((c) => c.id === capabilityId);
      if (cap) {
        // Price preference: boost free/low-fee agents
        if (capPref.priceWeight > 0.3 && cap.pricing.model === "free") {
          score = Math.min(1, score + capPref.priceWeight * 0.08);
        }
        // Speed preference: boost agents with low stated maxResponseMs
        if (capPref.speedWeight > 0.3 && cap.maxResponseMs < 1000) {
          score = Math.min(1, score + capPref.speedWeight * 0.08);
        }
      }
    }

    scores[did] = score;
  }

  return scores;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function decayScore(score: number, lastUsed: string): number {
  const daysSince = (Date.now() - new Date(lastUsed).getTime()) / 86_400_000;
  // Exponential decay toward neutral 0.5; half-life = DECAY_HALF_LIFE_DAYS
  const factor = Math.exp((-daysSince * Math.LN2) / DECAY_HALF_LIFE_DAYS);
  return 0.5 + (score - 0.5) * factor;
}
