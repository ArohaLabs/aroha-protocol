<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/preferences

Layer 5 — user preference profiles, consent tokens, and satisfaction learning.

```bash
npm install @aroha-sdk/preferences
```

---

## PreferenceProfile

A profile captures a user's constraints and learned preferences per capability and agent.

```typescript
import { createDefaultProfile } from "@aroha-sdk/preferences";

const profile = createDefaultProfile("did:aroha:personal-agent-alice");
```

---

## Filtering agents

Apply hard constraints (blocked brands, trust minimums) before scoring:

```typescript
import { filterAgents } from "@aroha-sdk/preferences";

const eligible = filterAgents(
  discoveredAgents,
  profile,
  "book-flight",
  { minTrustLevel: 2 }
);
```

---

## Scoring agents

Score eligible agents by price/reputation/satisfaction history:

```typescript
import { scoreAgents } from "@aroha-sdk/preferences";

const scores = scoreAgents(
  eligible,
  profile,
  "book-flight"
);
// scores: Map<agentDID, number>   — higher is better
```

Pass `scores` to `AgentSelector.select()` to weight the fan-out winner selection.

---

## Satisfaction signals

After each saga, record how satisfied the user was. The profile learns over time.

```typescript
import { applySatisfactionSignal } from "@aroha-sdk/preferences";

const updatedProfile = applySatisfactionSignal(profile, {
  sagaId: "saga-abc",
  agentDID: "did:aroha:flight-agent",
  outcome: "satisfied",                          // "satisfied" | "neutral" | "dissatisfied"
  dimensions: {
    price:   "satisfied",
    quality: "neutral",
    speed:   "satisfied",
  },
});
```

---

## PreferenceContext (Layer 5 in-message)

Carry user constraints inside any Aroha request body:

```typescript
const body: ArohaRequestBody = {
  capability: "search-flights",
  params: { origin: "LHR", destination: "NRT" },
  preferenceContext: {
    budget: { max: 500, currency: "USD" },
    quality: { minRating: 4 },
    constraints: ["no-budget-airlines", "direct-only"],
    consentToken: "<signed-VC>",   // optional — grants provider access to read context
  },
};
```

Providers that receive `preferenceContext` MAY use it to filter results or adjust pricing.
The `consentToken` is a Verifiable Credential signed by the orchestrator authorizing the provider
to read the context. Without it, providers MUST ignore the context.
