<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# aroha-reputation

> **Source not in this repository.** `@aroha-sdk/reputation` stays published on npm; its TypeScript
> source moved out of the protocol repository on 2026-10-25 and is not in a public repository.


**Package:** `@aroha-sdk/reputation` · **Version:** 1.4.1 · **License:** Apache-2.0

The Bayesian Beta reputation engine for Aroha agents. Implements the **Aroha Reputation Model v1.1** — 12-signal model with Thompson Sampling for Multi-Armed Bandit agent selection.

Implemented in all four SDKs: TypeScript, Python, Go, Java. The TypeScript package and the Python `aroha` package are published; the Go module and the Java SDK are not yet released.

---

## Installation

=== "TypeScript"

    ```bash
    npm install @aroha-sdk/reputation
    ```

=== "Python"

    ```bash
    # included in the aroha SDK — no extra install required
    from aroha.reputation import BayesianReputationEngine
    ```

=== "Go"

    ```go
    import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/reputation"
    ```

=== "Java"

    ```xml
    <!-- aroha-sdk includes com.arohalabs.reputation -->
    <dependency>
        <groupId>com.aroha-labs</groupId>
        <artifactId>aroha-sdk</artifactId>
        <version>1.0.0</version>
    </dependency>
    ```

---

## Quick Start

=== "TypeScript"

    ```typescript
    import { BayesianReputationEngine, BayesianReputationRecorder } from "@aroha-sdk/reputation";

    const engine = new BayesianReputationEngine();

    // Record a saga outcome
    await engine.recordEvent({
      type:          "saga_complete",
      sagaId:        "saga-abc",
      agentDID:      "did:aroha:hotel-agent",
      domain:        "travel",
      timestamp:     new Date().toISOString(),
      success:       true,
      latencyMs:     320,
      slaDurationMs: 5000,
    });

    // Read the composite score
    const score = await engine.compositeScore("did:aroha:hotel-agent", "travel");
    console.log(score); // ~0.62 after 1 success from Jeffreys prior

    // Thompson Sampling over candidates
    const ranked = await engine.thompsonSelect(
      [
        { agentDID: "did:aroha:hotel-a" },
        { agentDID: "did:aroha:hotel-b" },
        { agentDID: "did:aroha:hotel-c" },
      ],
      "travel"
    );
    console.log(ranked[0].agentDID); // winner
    ```

=== "Python"

    ```python
    from aroha.reputation import BayesianReputationEngine

    engine = BayesianReputationEngine()

    engine.record_event({
        "type":           "saga_complete",
        "saga_id":        "saga-abc",
        "agent_did":      "did:aroha:hotel-agent",
        "domain":         "travel",
        "success":        True,
        "latency_ms":     320,
        "sla_duration_ms": 5000,
    })

    score = engine.composite_score("did:aroha:hotel-agent", "travel")

    ranked = engine.thompson_select(
        [{"agent_did": "did:aroha:hotel-a"}, {"agent_did": "did:aroha:hotel-b"}],
        domain="travel",
    )
    print(ranked[0]["agent_did"])  # winner
    ```

=== "Go"

    ```go
    engine := reputation.New(nil)

    ok := true
    latency := 320.0
    sla := 5000.0
    engine.RecordEvent(reputation.ReputationEvent{
        Type:          reputation.EventSagaComplete,
        SagaID:        "saga-abc",
        AgentDID:      "did:aroha:hotel-agent",
        Domain:        "travel",
        Success:       &ok,
        LatencyMs:     &latency,
        SLADurationMs: &sla,
    })

    score := engine.CompositeScore("did:aroha:hotel-agent", "travel")

    ranked := engine.ThompsonSelect([]map[string]any{
        {"agentDID": "did:aroha:hotel-a"},
        {"agentDID": "did:aroha:hotel-b"},
    }, "travel", false)
    fmt.Println(ranked[0].AgentDID) // winner
    ```

=== "Java"

    ```java
    import com.arohalabs.reputation.ReputationEngine;

    var engine = new ReputationEngine();

    engine.recordEvent(ReputationEngine.ReputationEvent
        .builder("saga_complete", "saga-abc", "did:aroha:hotel-agent")
        .domain("travel").success(true).latencyMs(320).slaDurationMs(5000)
        .build());

    double score = engine.compositeScore("did:aroha:hotel-agent", "travel");

    var ranked = engine.thompsonSelect(List.of(
        Map.of("agentDID", "did:aroha:hotel-a"),
        Map.of("agentDID", "did:aroha:hotel-b")
    ), "travel", false);
    System.out.println(ranked.get(0).agentDID()); // winner
    ```

---

## The 12-Signal Model

| # | Signal | What it measures | Failure μ |
|---|--------|-----------------|-----------|
| 1 | **baseline** | Raw success/failure rate | 2.0 |
| 2 | **rhr** | Recent Hit Rate — 30-day exponential window | 2.0 |
| 3 | **pcr** | Protocol Compliance Rate — Ed25519/nonce/expiry | 3.0 |
| 4 | **dsl** | Deadline/SLA adherence | 2.0 |
| 5 | **cls** | Cancellation Liability — unexpected cancellations | 2.5 |
| 6 | **sas** | Satisfaction Signal — `ArohaSatisfactionSignal` feedback | 1.5 |
| 7 | **fss** | Failure Speed — fail fast ≤10% of SLA vs stall | 1.5 |
| 8 | **pas** | Price Accuracy — quoted vs actual price deviation | 2.5 |
| 9 | **rss** | Reservation Selectivity — quadratic accept-rate penalty | 1.0 |
| 10 | **rrs** | Retry Rate — downstream retry amplification | 1.2 |
| 11 | **cs** | Consistency / Sharpe — Welford mean/variance quality | — |
| 12 | **pps** | Peer Preference — endorsements from high-rep agents (≥0.8) | — |

### Composite Weights (sum = 1.00)

| baseline | rhr | pcr | dsl | cls | sas | fss | pas | rss | rrs | cs | pps |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.18 | 0.18 | 0.10 | 0.08 | 0.07 | 0.05 | 0.10 | 0.08 | 0.06 | 0.04 | 0.04 | 0.02 |

---

## Event Reference

Record any of these events to update the model:

```typescript
// 1. Saga complete — updates baseline, rhr, dsl
await engine.recordEvent({
  type: "saga_complete", sagaId, agentDID, domain, timestamp,
  success: true,        // required
  latencyMs: 320,       // optional — drives dsl signal
  slaDurationMs: 5000,  // optional — drives dsl signal
});

// 2. Protocol violation — updates pcr (Ed25519 fail, nonce replay, etc.)
await engine.recordEvent({ type: "protocol_violation", sagaId, agentDID, domain, timestamp });

// 3. Cancellation — updates cls
await engine.recordEvent({ type: "cancellation", sagaId, agentDID, domain, timestamp });

// 4. Satisfaction signal — updates sas
// qualityScore: 0–1 → maps to satisfied/neutral/dissatisfied
await engine.recordEvent({ type: "satisfaction_signal", ..., qualityScore: 0.85 });

// 5. Failure speed — updates fss (call alongside saga_complete when success=false)
await engine.recordEvent({
  type: "failure_speed", ...,
  failureFastMs: 180,    // how long until failure was returned
  slaDurationMs: 5000,   // SLA window — fss passes if failureFastMs ≤ 500
});

// 6. Price deviation — updates pas
await engine.recordEvent({
  type: "price_deviation", ...,
  quotedPrice: 100,
  actualPrice: 104,  // 4% deviation > 2% threshold → penalty
});

// 7. Reservation attempt — updates rss
await engine.recordEvent({
  type: "reservation_attempt", ...,
  reservationAccepted: true,
});

// 8. Retry triggered — updates rrs
await engine.recordEvent({ type: "retry_triggered", ..., retryCount: 2 });

// 9. Quality observed — updates cs (Welford running Sharpe)
await engine.recordEvent({ type: "quality_observed", ..., qualityScore: 0.9 });

// 10. Peer endorsement — updates pps (only endorsers with score ≥ 0.8 count)
await engine.recordEvent({
  type: "peer_endorsement", ...,
  endorserScore: 0.87,
});
```

---

## Thompson Sampling

Thompson Sampling implements the Multi-Armed Bandit exploration/exploitation tradeoff.
Instead of always picking the agent with the highest mean, it samples
`θ ~ Beta(α, β)` per candidate and returns `argmax θ`.

This naturally gives new agents a chance to compete (exploration) while
preferring proven agents over time (exploitation).
Regret bound: O(√KT · ln T) — Agrawal & Goyal (2012).

```typescript
// Basic Thompson select
const ranked = await engine.thompsonSelect(candidates, "travel");

// Risk-gated: filter out agents below Wilson-score floor of 0.1
// (prevents brand-new agents from winning on luck alone)
const safeRanked = await engine.thompsonSelect(candidates, "travel", true);
```

### Using Thompson Sampling in the AgentSelector

```typescript
import { AgentSelector } from "@aroha-sdk/orchestrator";
import { BayesianReputationEngine } from "@aroha-sdk/reputation";

const repEngine = new BayesianReputationEngine();
const selector  = new AgentSelector(client, myDID, privateKey);

const result = await selector.select("book-flight", params, candidates, {
  selectionMode:    "thompson",
  reputationEngine: repEngine,
  reputationDomain: "travel",
});

console.log(result.winner.agent.manifest.did);
```

---

## Integrating with SagaEngine

```typescript
import { SagaEngine } from "@aroha-sdk/orchestrator";
import { BayesianReputationEngine, BayesianReputationRecorder } from "@aroha-sdk/reputation";

const repEngine  = new BayesianReputationEngine();
const recorder   = new BayesianReputationRecorder(repEngine, "travel");

const sagaEngine = new SagaEngine(client, myDID, privateKey, {
  reputationRecorder: recorder,
});

// After each saga, the recorder automatically calls recordEvent for
// saga_complete, failure_speed, price_deviation, and retry_triggered.
```

---

## Custom Weights

Override any signal weight at construction time:

```typescript
import { BayesianReputationEngine } from "@aroha-sdk/reputation";

const engine = new BayesianReputationEngine(undefined, {
  baseline: 0.25,  // boost raw reliability
  pas:      0.12,  // boost price accuracy (finance domain)
  pps:      0.00,  // disable peer preference
  // remaining weights scale proportionally
});
```

---

## Time Decay & Dormancy

Scores decay automatically — no manual cleanup needed.

| Parameter | Value |
|---|---|
| Success half-life | 180 days |
| Failure half-life | 60 days |
| RHR window (half-life) | 30 days |
| Dormancy threshold | 365 days inactivity |
| Dormancy shrink half-life | 365 days |

Failure evidence decays 3× faster than success evidence — a recent failure
is more informative than an old one, so stale failure penalties fade quickly.

---

## On-Chain Sync (ERC-8004)

The composite score (0–1) is designed to be written to an on-chain reputation registry
(scaled to 0–10000) for cross-vendor portability. `@aroha-sdk/registry` does not currently
export a client for this: there is no `ArohaRegistryClient` or `updateReputationScore` in the
package. Write the score with your own contract client.

---

## API Reference

### `BayesianReputationEngine`

| Method | Returns | Description |
|---|---|---|
| `recordEvent(event)` | `Promise<void>` | Update model with a new event |
| `compositeScore(did, domain?)` | `Promise<number>` | Current composite score (0–1) |
| `getState(did, domain?)` | `Promise<ReputationState \| null>` | Full 12-signal state |
| `thompsonSelect(candidates, domain?, riskGated?)` | `Promise<ranked[]>` | Thompson Sampling selection |
| `listAll(domain?)` | `Promise<ReputationState[]>` | All states for a domain |

### `BayesianReputationRecorder`

Implements `IReputationRecorder` from `@aroha-sdk/settlement`. Inject into `SagaEngine.options.reputationRecorder`.

```typescript
const recorder = new BayesianReputationRecorder(engine, "travel");
// recorder.record(sagaId, agentDID, outcome, { latencyMs, slaDurationMs, ... })
```

### `IReputationStore`

Custom persistence backends implement this interface:

```typescript
interface IReputationStore {
  get(agentDID: string, domain: string): Promise<ReputationState | null>;
  set(state: ReputationState): Promise<void>;
  list(domain?: string): Promise<ReputationState[]>;
  delete(agentDID: string, domain: string): Promise<void>;
}

// Use with Redis, Postgres, or any KV store:
const engine = new BayesianReputationEngine(new RedisReputationStore(redis));
```

