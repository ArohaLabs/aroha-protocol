# @aroha-sdk/preferences

User preference profiles for Aroha agents — preferences guide which agent is chosen and how it
acts, layered on top of mandate constraints, never below them.

## Install

```bash
npm install @aroha-sdk/preferences
```

## Quick example

```typescript
import {
  createDefaultProfile, setBudget, preferAgent, blockAgent,
  filterAgents, scoreAgents, applySatisfactionSignal,
} from "@aroha-sdk/preferences";

// Profiles are immutable values: every mutation returns a new profile
let profile = createDefaultProfile(personalAgentDID);
profile = setBudget(profile, "travel", 800, "NZD");
profile = preferAgent(profile, "did:aroha:air-nz-agent");
profile = blockAgent(profile, "did:aroha:spammy-agent");

// Given agents discovered from the registry (DiscoveredAgent[] from @aroha-sdk/registry):
const eligible = filterAgents(discovered, profile, "book-flight", { domain: "travel", userTrustLevel: 2 });
const scores = scoreAgents(eligible, profile, "book-flight"); // { [did]: 0–1 }

// After the saga completes, feed the outcome back
profile = applySatisfactionSignal(profile, {
  sagaId: result.sagaId,
  agentDID: "did:aroha:air-nz-agent",
  capability: "book-flight",
  outcome: "satisfied",
  dimensions: { price: "neutral", quality: "satisfied", speed: "satisfied" },
  withinSLA: true,
  requiredCompensation: false,
});
```

## Why this exists in the mandate chain

User preferences (preferred and blocked agents, budgets per domain, quality/price/speed trade-offs)
guide an agent's decisions but do not grant authority. Mandate constraints govern what the agent
is *allowed* to do; preferences guide *how* it does it within that envelope.

## API

- `PreferenceProfile` — `{ version, ownerDID, lastUpdated, static, dynamic, consent }`.
- `createDefaultProfile(ownerDID)`, `setBudget(profile, domain, max, currency?)`, `preferAgent`, `blockAgent`.
- `filterAgents(agents, profile, capabilityId, { userTrustLevel?, domain? })` — hard filter (blocked agents, trust level, budget).
- `scoreAgents(agents, profile, capabilityId)` — soft score per DID (decayed satisfaction history, preferred-brand boost, capability weights).
- `applySatisfactionSignal(profile, signal)` — EMA update from a `SatisfactionSignal`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
