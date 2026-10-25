// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Preferences — Satisfaction Signal Processor (Layer 5)
 *
 * Updates dynamic agent scores after each saga using an
 * Exponential Moving Average (EMA). Recent outcomes weigh more
 * than older ones — a single bad experience doesn't erase a good track record,
 * but a pattern of failures steadily reduces the score.
 *
 * Formula:  newScore = (oldScore × 0.85) + (signal × 0.15)
 *
 * Signal values:
 *   satisfied    = 1.0 + dimension bonuses
 *   neutral      = 0.5
 *   dissatisfied = 0.0 + penalties
 *
 * Per spec: satisfaction signals are PRIVATE — never sent to provider agents.
 */

import {
  type PreferenceProfile,
  type AgentDynamicScore,
  type CapabilityPreference,
} from "./profile.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type OutcomeDimension = "satisfied" | "neutral" | "dissatisfied";

export interface SatisfactionSignal {
  sagaId: string;
  agentDID: string;
  capability: string;
  outcome: OutcomeDimension;
  dimensions: {
    price:   OutcomeDimension;
    quality: OutcomeDimension;
    speed:   OutcomeDimension;
  };
  /** Whether the saga completed within stated SLA */
  withinSLA: boolean;
  /** Whether compensation (ArohaCancel) was needed */
  requiredCompensation: boolean;
}

// ─── EMA constants ────────────────────────────────────────────────────────────

const EMA_DECAY   = 0.85; // weight of existing score history
const EMA_NEW     = 0.15; // weight of new outcome
const INITIAL_SCORE = 0.5; // neutral starting score for new agents

// Outcome → raw signal value
const OUTCOME_SIGNAL: Record<OutcomeDimension, number> = {
  satisfied:    1.0,
  neutral:      0.5,
  dissatisfied: 0.0,
};

// ─── Processor ────────────────────────────────────────────────────────────────

/**
 * Apply a satisfaction signal to a preference profile.
 * Returns an updated (immutable) profile.
 */
export function applySatisfactionSignal(
  profile: PreferenceProfile,
  signal: SatisfactionSignal
): PreferenceProfile {
  const newProfile = { ...profile };
  newProfile.dynamic = { ...profile.dynamic };
  newProfile.dynamic.agentScores = { ...profile.dynamic.agentScores };
  newProfile.dynamic.capabilityPreferences = { ...profile.dynamic.capabilityPreferences };

  // ── Update agent score ────────────────────────────────────────────────────
  const existing: AgentDynamicScore = profile.dynamic.agentScores[signal.agentDID] ?? {
    score: INITIAL_SCORE,
    transactions: 0,
    lastUsed: new Date().toISOString(),
  };

  const rawSignal = computeSignal(signal);
  const newScore = ema(existing.score, rawSignal);

  newProfile.dynamic.agentScores[signal.agentDID] = {
    score: newScore,
    transactions: existing.transactions + 1,
    lastUsed: new Date().toISOString(),
  };

  // ── Update capability dimension preferences ────────────────────────────────
  // If the user was satisfied on "price" dimension, increase pricePreference
  // for this capability type. Gradually learns what the user values per domain.
  const capPref: CapabilityPreference = profile.dynamic.capabilityPreferences[
    signal.capability
  ] ?? { priceWeight: 0, qualityWeight: 0, speedWeight: 0 };

  const updatedCapPref = updateCapabilityPreference(capPref, signal);
  newProfile.dynamic.capabilityPreferences[signal.capability] = updatedCapPref;

  newProfile.lastUpdated = new Date().toISOString();
  return newProfile;
}

// ─── Preference EMA constants ─────────────────────────────────────────────────

const PREF_DECAY = 0.9;
const PREF_NEW   = 0.1;

// ─── Private helpers ──────────────────────────────────────────────────────────

function computeSignal(signal: SatisfactionSignal): number {
  let value = OUTCOME_SIGNAL[signal.outcome];

  // Bonuses / penalties
  if (signal.withinSLA) value = Math.min(1.0, value + 0.05);
  if (signal.requiredCompensation) value = Math.max(0.0, value - 0.10);
  if (signal.outcome === "dissatisfied") value = Math.max(0.0, value - 0.05);

  return value;
}

function ema(current: number, signal: number): number {
  return Math.min(1, Math.max(0, current * EMA_DECAY + signal * EMA_NEW));
}

function updateCapabilityPreference(
  current: CapabilityPreference,
  signal: SatisfactionSignal
): CapabilityPreference {
  // A dissatisfied dimension signals the user wants improvement there — weight increases.
  const priceSignal   = signal.dimensions.price   === "dissatisfied" ? 1 : 0;
  const qualitySignal = signal.dimensions.quality === "dissatisfied" ? 1 : 0;
  const speedSignal   = signal.dimensions.speed   === "dissatisfied" ? 1 : 0;

  return {
    priceWeight:   Math.min(1, current.priceWeight   * PREF_DECAY + priceSignal   * PREF_NEW),
    qualityWeight: Math.min(1, current.qualityWeight * PREF_DECAY + qualitySignal * PREF_NEW),
    speedWeight:   Math.min(1, current.speedWeight   * PREF_DECAY + speedSignal   * PREF_NEW),
  };
}
