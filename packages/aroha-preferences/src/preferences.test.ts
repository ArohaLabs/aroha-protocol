// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  createDefaultProfile,
  blockAgent,
  preferAgent,
  setBudget,
  type PreferenceProfile,
} from "./profile.js";
import { filterAgents, scoreAgents } from "./filter.js";
import { applySatisfactionSignal, type SatisfactionSignal } from "./satisfaction.js";
import type { DiscoveredAgent } from "@aroha-sdk/registry";
import type { AgentRecord, CapabilityManifest } from "@aroha-sdk/registry";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeAgent(id: string, opts: { requiredTrustLevel?: 0|1|2|3|4; fee?: string } = {}): DiscoveredAgent {
  const did = `did:aroha:${id}`;
  return {
    record: {
      didHash: "0x" + id,
      ownerAddress: "0xOwner",
      manifestCID: "QmTest",
      publicKeyB64: Buffer.alloc(32).toString("base64url"),
      stakedWei: 1_000_000_000_000_000_000n,
      reputationScore: 8000,
      active: true,
      registeredAt: Date.now() - 86400_000,
      lastUpdatedAt: Date.now(),
    },
    manifest: {
      aroha: "1.0",
      did,
      name: "Test Agent",
      version: "1.0.0",
      endpoint: `https://${id}.example.com`,
      capabilities: [
        {
          id: "search-flights",
          version: "1.0.0",
          inputSchema: {},
          outputSchema: {},
          async: false,
          maxResponseMs: 5000,
          requiredTrustLevel: opts.requiredTrustLevel ?? 1,
          pricing: opts.fee
            ? { model: "per-transaction", fee: opts.fee }
            : { model: "free" },
          sagaRole: "none",
        },
      ],
      protocols: ["aroha/1.0"],
      createdAt: new Date().toISOString(),
      signature: "dummy",
    },
    endpoint: `https://${id}.example.com`,
    publicKey: new Uint8Array(32),
  };
}

// ─── createDefaultProfile ─────────────────────────────────────────────────────

describe("createDefaultProfile", () => {
  it("creates a profile with the given ownerDID", () => {
    const profile = createDefaultProfile("did:aroha:my-agent");
    expect(profile.ownerDID).toBe("did:aroha:my-agent");
    expect(profile.version).toBe("1.0");
  });

  it("starts with empty budgets, brands, and scores", () => {
    const profile = createDefaultProfile("did:aroha:owner");
    expect(profile.static.budget).toEqual({});
    expect(profile.static.brands.blocked).toEqual([]);
    expect(profile.static.brands.preferred).toEqual([]);
    expect(profile.dynamic.agentScores).toEqual({});
  });
});

// ─── blockAgent / preferAgent / setBudget ────────────────────────────────────

describe("blockAgent", () => {
  it("adds the DID to the blocked list", () => {
    const p = blockAgent(createDefaultProfile("owner"), "did:aroha:bad-agent");
    expect(p.static.brands.blocked).toContain("did:aroha:bad-agent");
  });

  it("removes the DID from preferred if it was there", () => {
    let p = preferAgent(createDefaultProfile("owner"), "did:aroha:agent");
    p = blockAgent(p, "did:aroha:agent");
    expect(p.static.brands.preferred).not.toContain("did:aroha:agent");
    expect(p.static.brands.blocked).toContain("did:aroha:agent");
  });

  it("is idempotent — blocking twice doesn't duplicate", () => {
    let p = createDefaultProfile("owner");
    p = blockAgent(p, "did:aroha:x");
    p = blockAgent(p, "did:aroha:x");
    expect(p.static.brands.blocked.filter((d) => d === "did:aroha:x")).toHaveLength(1);
  });
});

describe("preferAgent", () => {
  it("adds the DID to the preferred list", () => {
    const p = preferAgent(createDefaultProfile("owner"), "did:aroha:good-agent");
    expect(p.static.brands.preferred).toContain("did:aroha:good-agent");
  });
});

describe("setBudget", () => {
  it("sets budget for a domain", () => {
    const p = setBudget(createDefaultProfile("owner"), "travel", 500, "EUR");
    expect(p.static.budget["travel"]).toEqual({ max: 500, currency: "EUR" });
  });

  it("defaults to USD", () => {
    const p = setBudget(createDefaultProfile("owner"), "entertainment", 100);
    expect(p.static.budget["entertainment"].currency).toBe("USD");
  });
});

// ─── filterAgents ─────────────────────────────────────────────────────────────

describe("filterAgents", () => {
  it("removes blocked agents", () => {
    const agents = [makeAgent("agent-1"), makeAgent("agent-2")];
    const profile = blockAgent(createDefaultProfile("owner"), "did:aroha:agent-1");
    const filtered = filterAgents(agents, profile, "search-flights");
    expect(filtered).toHaveLength(1);
    expect(filtered[0].manifest.did).toBe("did:aroha:agent-2");
  });

  it("removes agents whose trust level exceeds user's level", () => {
    const agents = [
      makeAgent("low-trust", { requiredTrustLevel: 1 }),
      makeAgent("high-trust", { requiredTrustLevel: 3 }),
    ];
    const profile = createDefaultProfile("owner");
    const filtered = filterAgents(agents, profile, "search-flights", { userTrustLevel: 2 });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].manifest.did).toBe("did:aroha:low-trust");
  });

  it("removes agents whose fee exceeds budget", () => {
    const agents = [
      makeAgent("cheap-agent", { fee: "5.00" }),
      makeAgent("expensive-agent", { fee: "50.00" }),
    ];
    let profile = createDefaultProfile("owner");
    profile = setBudget(profile, "travel", 10);
    const filtered = filterAgents(agents, profile, "search-flights", { domain: "travel" });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].manifest.did).toBe("did:aroha:cheap-agent");
  });

  it("passes all agents when nothing is blocked and within budget", () => {
    const agents = [makeAgent("a1"), makeAgent("a2"), makeAgent("a3")];
    const profile = createDefaultProfile("owner");
    const filtered = filterAgents(agents, profile, "search-flights");
    expect(filtered).toHaveLength(3);
  });
});

// ─── scoreAgents ─────────────────────────────────────────────────────────────

describe("scoreAgents", () => {
  it("starts at 0.45 for unknown agents (trust-level 1 default)", () => {
    const agents = [makeAgent("unknown-agent")];
    const profile = createDefaultProfile("owner");
    const scores = scoreAgents(agents, profile, "search-flights");
    expect(scores["did:aroha:unknown-agent"]).toBeCloseTo(0.45, 5);
  });

  it("adds 0.15 boost for preferred agents (capped at 1)", () => {
    const agents = [makeAgent("preferred-agent")];
    const profile = preferAgent(createDefaultProfile("owner"), "did:aroha:preferred-agent");
    const scores = scoreAgents(agents, profile, "search-flights");
    expect(scores["did:aroha:preferred-agent"]).toBeCloseTo(0.60);
  });

  it("uses dynamic score when agent has history", () => {
    const agents = [makeAgent("known-agent")];
    const profile: PreferenceProfile = {
      ...createDefaultProfile("owner"),
      dynamic: {
        agentScores: { "did:aroha:known-agent": { score: 0.8, transactions: 5, lastUsed: new Date().toISOString() } },
        capabilityPreferences: {},
        preferBundled: false,
        trustedBundlers: [],
      },
    };
    const scores = scoreAgents(agents, profile, "search-flights");
    expect(scores["did:aroha:known-agent"]).toBeCloseTo(0.8, 5);
  });
});

// ─── applySatisfactionSignal ──────────────────────────────────────────────────

describe("applySatisfactionSignal", () => {
  function makeSignal(outcome: "satisfied" | "neutral" | "dissatisfied", overrides: Partial<SatisfactionSignal> = {}): SatisfactionSignal {
    return {
      sagaId: "saga-1",
      agentDID: "did:aroha:provider",
      capability: "search-flights",
      outcome,
      dimensions: { price: outcome, quality: outcome, speed: outcome },
      withinSLA: true,
      requiredCompensation: false,
      ...overrides,
    };
  }

  it("increases score for a satisfied outcome", () => {
    const profile = createDefaultProfile("owner");
    const updated = applySatisfactionSignal(profile, makeSignal("satisfied"));
    const score = updated.dynamic.agentScores["did:aroha:provider"].score;
    expect(score).toBeGreaterThan(0.5); // started at INITIAL_SCORE=0.5
  });

  it("decreases score for a dissatisfied outcome", () => {
    const profile = createDefaultProfile("owner");
    const updated = applySatisfactionSignal(profile, makeSignal("dissatisfied"));
    const score = updated.dynamic.agentScores["did:aroha:provider"].score;
    expect(score).toBeLessThan(0.5);
  });

  it("increments transaction count", () => {
    const profile = createDefaultProfile("owner");
    let p = applySatisfactionSignal(profile, makeSignal("satisfied"));
    p = applySatisfactionSignal(p, makeSignal("neutral"));
    expect(p.dynamic.agentScores["did:aroha:provider"].transactions).toBe(2);
  });

  it("EMA smooths out over time — one bad signal doesn't crater a good score", () => {
    let profile = createDefaultProfile("owner");
    // 10 satisfied signals
    for (let i = 0; i < 10; i++) {
      profile = applySatisfactionSignal(profile, makeSignal("satisfied"));
    }
    const goodScore = profile.dynamic.agentScores["did:aroha:provider"].score;

    // One dissatisfied signal
    profile = applySatisfactionSignal(profile, makeSignal("dissatisfied"));
    const afterBad = profile.dynamic.agentScores["did:aroha:provider"].score;

    expect(afterBad).toBeGreaterThan(0.6); // still well above neutral
    expect(afterBad).toBeLessThan(goodScore);
  });

  it("score is always in [0, 1]", () => {
    let profile = createDefaultProfile("owner");
    for (let i = 0; i < 20; i++) {
      profile = applySatisfactionSignal(profile, makeSignal("dissatisfied"));
    }
    const score = profile.dynamic.agentScores["did:aroha:provider"].score;
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it("does not mutate the original profile (immutable update)", () => {
    const profile = createDefaultProfile("owner");
    const snapshot = JSON.stringify(profile);
    applySatisfactionSignal(profile, makeSignal("satisfied"));
    expect(JSON.stringify(profile)).toBe(snapshot);
  });

  it("updates lastUpdated timestamp", () => {
    const before = Date.now();
    const profile = createDefaultProfile("owner");
    const updated = applySatisfactionSignal(profile, makeSignal("satisfied"));
    expect(new Date(updated.lastUpdated).getTime()).toBeGreaterThanOrEqual(before);
  });
});

// ─── Time-decay scoring ───────────────────────────────────────────────────────

describe("scoreAgents — time decay", () => {
  it("decays a stale high score toward neutral over time", () => {
    const agents = [makeAgent("stale-agent")];
    const twoYearsAgo = new Date(Date.now() - 730 * 86400_000).toISOString();
    const profile: PreferenceProfile = {
      ...createDefaultProfile("owner"),
      dynamic: {
        agentScores: {
          "did:aroha:stale-agent": { score: 0.95, transactions: 50, lastUsed: twoYearsAgo },
        },
        capabilityPreferences: {},
        preferBundled: false,
        trustedBundlers: [],
      },
    };
    const scores = scoreAgents(agents, profile, "search-flights");
    // After 2 years, score should have decayed significantly toward 0.5
    expect(scores["did:aroha:stale-agent"]).toBeLessThan(0.75);
  });

  it("does not decay a recently-used high score much", () => {
    const agents = [makeAgent("recent-agent")];
    const yesterday = new Date(Date.now() - 86400_000).toISOString();
    const profile: PreferenceProfile = {
      ...createDefaultProfile("owner"),
      dynamic: {
        agentScores: {
          "did:aroha:recent-agent": { score: 0.9, transactions: 10, lastUsed: yesterday },
        },
        capabilityPreferences: {},
        preferBundled: false,
        trustedBundlers: [],
      },
    };
    const scores = scoreAgents(agents, profile, "search-flights");
    expect(scores["did:aroha:recent-agent"]).toBeGreaterThan(0.88);
  });
});

// ─── Trust-level cold-start priors ───────────────────────────────────────────

describe("scoreAgents — trust-level prior", () => {
  it("gives a higher starting score to a trust-level-2 agent vs trust-level-0", () => {
    const highTrust = makeAgent("high-trust", { requiredTrustLevel: 2 });
    const lowTrust  = makeAgent("low-trust",  { requiredTrustLevel: 0 });
    const profile = createDefaultProfile("owner");
    const scores = scoreAgents([highTrust, lowTrust], profile, "search-flights");
    expect(scores["did:aroha:high-trust"]).toBeGreaterThan(scores["did:aroha:low-trust"]);
  });

  it("trust-level-4 agent starts above 0.8", () => {
    const trusted = makeAgent("user-trusted", { requiredTrustLevel: 4 });
    const profile = createDefaultProfile("owner");
    const scores = scoreAgents([trusted], profile, "search-flights");
    expect(scores["did:aroha:user-trusted"]).toBeGreaterThan(0.8);
  });
});

// ─── Dimension preference EMA ─────────────────────────────────────────────────

describe("applySatisfactionSignal — dimension weight EMA", () => {
  it("increases priceWeight when price is dissatisfied", () => {
    const profile = createDefaultProfile("owner");
    const signal: SatisfactionSignal = {
      sagaId: "s1",
      agentDID: "did:aroha:p",
      capability: "book-flight",
      outcome: "neutral",
      dimensions: { price: "dissatisfied", quality: "satisfied", speed: "satisfied" },
      withinSLA: true,
      requiredCompensation: false,
    };
    const updated = applySatisfactionSignal(profile, signal);
    const pref = updated.dynamic.capabilityPreferences["book-flight"];
    expect(pref.priceWeight).toBeGreaterThan(0);
    expect(pref.qualityWeight).toBe(0);
    expect(pref.speedWeight).toBe(0);
  });

  it("accumulates priceWeight over multiple signals (does not overwrite)", () => {
    let profile = createDefaultProfile("owner");
    const signal: SatisfactionSignal = {
      sagaId: "s1",
      agentDID: "did:aroha:p",
      capability: "book-flight",
      outcome: "neutral",
      dimensions: { price: "dissatisfied", quality: "satisfied", speed: "satisfied" },
      withinSLA: true,
      requiredCompensation: false,
    };
    profile = applySatisfactionSignal(profile, signal);
    const afterOne = profile.dynamic.capabilityPreferences["book-flight"].priceWeight;
    profile = applySatisfactionSignal(profile, signal);
    const afterTwo = profile.dynamic.capabilityPreferences["book-flight"].priceWeight;
    expect(afterTwo).toBeGreaterThan(afterOne); // accumulated, not overwritten
  });

  it("starts at zero weights for a new capability", () => {
    const profile = createDefaultProfile("owner");
    const pref = profile.dynamic.capabilityPreferences["new-capability"];
    expect(pref).toBeUndefined(); // no entry yet
  });
});
