<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Benchmark Methodology & Runbook

**Owner:** @projectmed99  
**Version:** 1.0 — 2026-05-28  
**Status:** Initial draft — baseline not yet established  
**Verification:** Benchmark is complete when: public artifact exists, reproduction steps verified by a third party, baseline numbers recorded.

---

## Purpose

Produce reproducible, externally verifiable performance benchmarks for the Aroha 1.0 reference implementation. Every published performance claim must link to a reproducible benchmark.

---

## Benchmark Scenarios

### B1 — Single-hop request/response

**What it measures:** End-to-end latency for a signed ArohaEnvelope sent from Agent A to Agent B with signature verification.  
**Why it matters:** Baseline overhead of Aroha's cryptographic layer vs. raw HTTP.

```
Agent A → (sign envelope) → Agent B → (verify signature) → Response
```

**Metrics:** p50, p95, p99 latency (ms); throughput (req/s)  
**Parameters:** 1,000 warm requests; 10 concurrent clients

---

### B2 — Capability discovery

**What it measures:** Time to resolve a capability query against the registry.  
**Why it matters:** Discovery latency affects agent startup time in multi-agent pipelines.

```
Agent → registry.query({ capability: "process-payment" }) → [agents]
```

**Metrics:** p50, p95, p99 latency (ms); registry size: 10, 100, 1,000 entries  
**Parameters:** 500 queries per registry size

---

### B3 — Two-party saga (happy path)

**What it measures:** Full Reserve → Commit round-trip across two agents.  
**Why it matters:** The saga pattern is the highest-value primitive — this is the number enterprise buyers want.

```
Coordinator → Reserve → Participant → ReserveAck
Coordinator → Commit → Participant → CommitAck
```

**Metrics:** p50, p95, p99 end-to-end saga latency (ms); saga throughput (sagas/s)  
**Parameters:** 500 sagas; 5 concurrent coordinators

---

### B4 — Saga rollback (Cancel path)

**What it measures:** Time from coordinator decision to Cancel to all-participants-acked.  
**Why it matters:** Rollback speed determines financial exposure window on failure.

```
Coordinator → Reserve (N participants) → Commit (partial) → Cancel (all)
```

**Metrics:** Cancel propagation time (ms) at N=2, N=5, N=10 participants  
**Parameters:** 200 rollback scenarios per participant count

---

### B5 — Ed25519 signing throughput

**What it measures:** Raw key operations — signing and verification per second.  
**Why it matters:** Establishes the cryptographic ceiling; identifies if crypto is the bottleneck.

**Metrics:** Signs/second; verifications/second  
**Parameters:** 10,000 operations, Node.js built-in crypto

### B6 — Mandate chain verification (offline)

**What it measures:** Time for an agent to verify a two-link mandate chain (person → agent → agent) before acting: every signature, every attenuation step, root and grantee binding.  
**Why it matters:** This is the check Aroha adds to every delegated action. It needs no network call: `did:aroha:z` DIDs commit to their key, so no registry or identity-provider round trip is made.

**Metrics:** p50 / p95 / p99 latency; token size in bytes  
**Parameters:** 200 warm-up, 2,000 measured verifications, no revocation hook (add your revocation check's own latency)  
**Run:** `npm run build && npm run benchmark:b6`

---

## Reproduction Runbook

### Prerequisites

```bash
node --version   # Must be ≥22.0.0
npm --version    # Must be ≥10.0.0
git clone https://github.com/ArohaLabs/aroha-protocol.git
cd aroha-protocol
npm install && npm run build
```

### Running the full benchmark suite

```bash
# All benchmarks, results written to benchmark-results/
npm run benchmark

# Individual scenarios
npm run benchmark:b1   # Single-hop latency
npm run benchmark:b2   # Capability discovery
npm run benchmark:b5   # Crypto throughput
npm run benchmark:b6   # Mandate chain verification (not part of `npm run benchmark`)
```

Scenarios B1, B2, and B5 are implemented in `scripts/benchmark/`. Run `npm run benchmark` to execute all three and produce a JSON artifact in `benchmark-results/`. Scenarios B3 (saga happy path) and B4 (saga rollback) require a live multi-agent network; they have no script yet and their manual runbook has not been written.

### Environment for reproducible results

- Dedicated machine (no background load)
- Linux preferred (Ubuntu 22.04 or later); macOS acceptable; Windows results noted separately
- 8 GB RAM minimum; results must note actual RAM and CPU
- All agents running on localhost (no network variability)
- Run at least 3 times; report median run

### Result format

After each run, results are written to `benchmark-results/benchmark-YYYY-MM-DD.json`. The target format is:

```json
{
  "date": "2026-05-28",
  "gitSha": "abc1234",
  "nodeVersion": "22.x.x",
  "platform": "linux/x64",
  "cpu": "...",
  "ram": "...",
  "scenarios": {
    "B1": { "p50": 0, "p95": 0, "p99": 0, "throughput": 0 },
    "B2": { "p50": 0, "p95": 0, "p99": 0 },
    "B3": { "p50": 0, "p95": 0, "p99": 0, "throughput": 0 },
    "B4": { "n2": 0, "n5": 0, "n10": 0 },
    "B5": { "signsPerSecond": 0, "verifiesPerSecond": 0 }
  }
}
```

---

## Baseline Report (Placeholder)

**ASSUMPTION:** B1–B5 have not been measured. B6 has one measurement on a developer laptop, which is indicative only; it must be re-run on the controlled environment below before it is quoted as a baseline.

| Scenario | p50 | p95 | p99 | Throughput | Date | SHA |
|----------|-----|-----|-----|-----------|------|-----|
| B1 Single-hop | — | — | — | — | — | — |
| B2 Discovery (100 entries) | — | — | — | — | — | — |
| B3 Saga happy path | — | — | — | — | — | — |
| B4 Cancel (N=5) | — | — | — | — | — | — |
| B5 Ed25519 sign | — | — | — | — | — | — |
| B6 Mandate chain, 2 links (single developer laptop, Windows 11, Node 24.14; not a controlled environment) | 3.64 ms | 4.38 ms | 5.26 ms | — | 2026-10-19 | 84003ae |

---

## External Verifiability

To allow third parties to reproduce results:

1. Benchmark scripts are in `scripts/benchmark/` (open source, Apache-2.0).
2. Environment spec is recorded in every result JSON.
3. Results are not yet published from CI: no workflow runs the benchmark suite. Runs write their results locally to `benchmark-results/`.
4. Discrepancies in third-party reproductions should be filed as GitHub Issues with the `benchmark` label.

---

## Benchmark Governance

- Benchmark methodology changes require a PR with maintainer approval.
- Results must not be selectively cherry-picked — publish the full scenario suite or nothing.
- If a regression is detected vs. prior baseline, a `perf:` issue must be filed within 24 hours.
