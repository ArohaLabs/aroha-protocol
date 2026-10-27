<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Agent Authorization & Reputation

*A research-grounded design for privacy-preserving spending delegation and dynamic trust scoring in Aroha.*

---

## Overview

Two open problems define whether an agent network is safe to deploy in production:

1. **Authorization** — How does a user grant an agent permission to act (including spend money) without handing over credentials that could be misused?
2. **Reputation** — How does an orchestrator know which provider agent to trust when routing a high-value task?

The academic literature on both problems has accelerated sharply in 2025–2026. This document surveys the state of the art, identifies the strongest design patterns, and specifies how Aroha implements them.

---

## Part I — Agent Authorization

### The Core Problem: Static Permissions in a Dynamic World

The fundamental tension in agent authorization is identified clearly by Shi et al. (2025) in their systematisation of 200+ papers through a **Belief-Intention-Permission (B-I-P) framework** [[1]](#ref-1): access control systems grant static permissions at authorization time, but agent trustworthiness is probabilistic and fluctuates with context. A travel-booking agent that has behaved perfectly for 200 bookings might be compromised, confused, or operating in an unexpected context on booking 201. Static role-based permissions cannot capture this.

The same paper proposes a shift from **role-based** to **risk-adaptive** authorization: permissions should be narrowed or expanded dynamically based on observed behavior, not fixed at deployment time.

This connects directly to the user scenario: an agent authorized to spend $50 for a dinner reservation should not be able to spend $50 on anything else, and should certainly not gain access to the underlying payment credential that funded the authorization.

### The Spending Mandate Pattern

The cleanest solution to "authorize an agent to spend without disclosing financial details" is the **mandate model**, defined and implemented in Google's Agent Payment Protocol v2 (AP2) [[2]](#ref-2), which Aroha adopts and extends.

The key insight is that a mandate is a **cryptographically signed capability token**, not a credential. It encodes:
- What the agent may purchase
- Up to what amount
- Under what conditions
- For how long

The user's bank account number or card number never leaves the user's wallet or the payment processor. The agent carries only the mandate.

AP2 defines three mandate types. Aroha adopts all three:

```
┌──────────────────────────────────────────────────────────────────────┐
│  USER                                                                 │
│                                                                       │
│  "I authorize my agent to spend up to $50 for dinner within 4 hours" │
│                          │                                            │
│                          ▼                                            │
│  ┌─────────────────────────────────────────┐                         │
│  │  INTENT MANDATE  (signed by user)        │                         │
│  │  spendLimit:   $50                       │                         │
│  │  category:     restaurant                │                         │
│  │  validFor:     4 hours                   │                         │
│  │  agentDid:     did:aroha:travel-agent     │                         │
│  └──────────────────────┬──────────────────┘                         │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          ▼  (agent receives mandate, not card number)
┌─────────────────────────────────────────────────────────────────────┐
│  TRAVEL AGENT                                                        │
│                                                                      │
│  Finds restaurant: "Sushi Nakazawa — $48 for two"                   │
│                          │                                           │
│                          ▼                                           │
│  ┌──────────────────────────────────────────┐                        │
│  │  CART MANDATE  (agent proposes)           │                        │
│  │  merchant:   did:aroha:sushi-nakazawa      │                        │
│  │  amount:     $48                          │                        │
│  │  items:      ["omakase x2"]               │                        │
│  │  parentMandate: <intent-mandate-hash>     │                        │
│  └──────────────────────┬───────────────────┘                        │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          ▼  (payment processor verifies chain, charges card)
┌─────────────────────────────────────────────────────────────────────┐
│  PAYMENT PROCESSOR                                                   │
│                                                                      │
│  Verifies: cartMandate ≤ intentMandate.spendLimit ✓                 │
│  Verifies: category matches ✓                                        │
│  Charges card: $48                                                   │
│  Returns: PAYMENT MANDATE (receipt / proof of payment)               │
└─────────────────────────────────────────────────────────────────────┘
```

The agent never saw the card number. It received an Intent Mandate, proposed a Cart Mandate, and the Payment Processor handled the actual charge. The cryptographic chain from user intent to final payment is auditable and non-repudiable — a requirement identified by Acharya (2025) [[3]](#ref-3).

### Attenuating Delegation Tokens

When an agent delegates part of its authority to a sub-agent (common in orchestrator→worker patterns), a new problem arises: how do you ensure the sub-agent cannot exceed the authority that was delegated?

The answer is **monotonic attenuation**, formalised in IETF draft `draft-niyikiza-oauth-attenuating-agent-tokens` [[4]](#ref-4): each derived token can only narrow scope, never expand it. A derived token cannot grant broader spending authority than the token it was derived from.

```
User signs:      Intent Mandate ($50, any restaurant, 4 hours)
                     │
                     ▼  assistant derives:
Assistant:       Attenuated Mandate ($50, Italian only, 2 hours)
                     │
                     ▼  sub-agent derives:
Sub-agent:       Attenuated Mandate ($30, one specific restaurant, 30 min)
                     │  ← cannot create a $60 mandate from a $50 parent
                     ▼
Payment:         Verified — each mandate checks its parent's constraints
```

This maps onto a UCAN (User Controlled Authorization Networks)-style chain where each link is cryptographically verified and scope can only decrease. The IETF draft formalizes this as **JWT-based Attenuating Authorization Tokens (AATs)** with a typed constraint vocabulary for tool-level argument restrictions.

Aroha implements this as the **ArohaSpendingMandate** credential type.

### OAuth 2.0 Extensions for Agents

For integrations with existing enterprise systems (where OAuth is already deployed), IETF draft `draft-oauth-ai-agents-on-behalf-of-user` [[5]](#ref-5) provides the mechanism:

- A new `requested_agent` parameter at the authorization endpoint names the specific agent receiving delegated authority
- A new `actor_token` parameter at the token endpoint authenticates the agent
- The resulting access token carries the user, agent, and client identities together — providing the audit trail required for compliance

The companion draft `draft-klrc-aiagent-auth` (Kasselman, Lombardo, Rosomakho, Campbell, Steele — authors from Defakto, AWS, Zscaler, Ping Identity, OpenAI) [[6]](#ref-6) consolidates WIMSE (Workload Identity and Minimal Secret Exposure) and OAuth 2.0 into a unified framework, arguing that new protocols are not needed — only gaps in existing standards need filling.

Aroha's `@aroha-sdk/credentials` package already implements the W3C DID and VC layer. The OAuth extension adds a bridge for enterprise systems that use OAuth rather than Aroha-native identity.

### Zero-Trust Identity for Fine-Grained Access

Huang et al. (2025) [[7]](#ref-7) propose a complete zero-trust identity framework for agentic AI using W3C DIDs and Verifiable Credentials with zero-knowledge proofs. Their key contribution for Aroha is the **Agent Naming Service**: a capability-aware directory that maps agent capabilities to DID Documents, enabling discovery that is scoped to authorization level.

This directly informs the `@aroha-sdk/registry` design: capability manifests should encode not just what an agent can do, but what authorization level is required to invoke each capability.

### The Aroha Authorization Model

Aroha synthesises these patterns into a layered authorization model:

| Layer | Mechanism | Aroha Component |
|---|---|---|
| **Identity** | `did:aroha:` Ed25519 signed envelopes | `@aroha-sdk/core` |
| **Delegation** | ArohaSpendingMandate (Intent → Cart → Payment) | `@aroha-sdk/credentials` |
| **Attenuation** | JWT AATs — scope can only narrow down the chain | `@aroha-sdk/credentials` |
| **Policy** | OPA-style rules enforced before handler runs | `@aroha-sdk/policy` |
| **Audit** | W3C traceparent across every hop | `@aroha-sdk/telemetry` |
| **OAuth bridge** | `draft-oauth-ai-agents-on-behalf-of-user` | `@aroha-sdk/credentials` |

#### `ArohaSpendingMandate` — Wire Format

```json
{
  "@context": ["https://aroha-labs.com/contexts/v1", "https://aroha-labs.com/contexts/authorization/v1"],
  "type": "ArohaSpendingMandate",
  "id": "urn:uuid:...",
  "issuerDid": "did:aroha:alice",
  "agentDid": "did:aroha:travel-agent",
  "issuedAt": "2026-05-05T10:00:00Z",
  "expiresAt": "2026-05-05T14:00:00Z",
  "constraints": {
    "spendLimitUsd": 50,
    "merchantCategory": "restaurant",
    "allowedMerchantDids": [],
    "blockedMerchantDids": [],
    "requireHumanApprovalAboveUsd": 40
  },
  "parentMandateId": null,
  "proof": { "type": "Ed25519Signature2020", "..." }
}
```

Key properties:
- `agentDid` — only this specific agent may use the mandate (not transferable)
- `spendLimitUsd` — hard ceiling enforced by payment processor, not by the agent
- `merchantCategory` — agent cannot spend at a merchant outside this category
- `requireHumanApprovalAboveUsd` — escalates to human approval above threshold
- `parentMandateId` — chain of custody for attenuated sub-mandates
- Ed25519 proof — mandate is signed by the user, not the agent; forgery is detectable

#### Using a Mandate in a Aroha Envelope

```typescript
import { issueIntentMandate, attenuateToPayment } from "@aroha-sdk/credentials";
import { buildEnvelope } from "@aroha-sdk/core";

// User creates the intent mandate (in their wallet/app)
const intentMandate = await issueIntentMandate(
  userDID,                         // grantor
  "did:aroha:travel-agent",         // grantee
  {
    spendLimitUsd:               50,
    merchantCategory:            "restaurant",
    requireHumanApprovalAboveUsd: 40,
  },
  userPrivateKey,
  4 * 60 * 60 * 1000               // 4 hours in ms
);

// Agent narrows it to a specific payment before transacting
const paymentMandate = await attenuateToPayment(
  intentMandate,
  "did:aroha:sushi-nakazawa",       // merchant DID
  { spendLimitUsd: 48, merchantCategory: "restaurant" },
  agentPrivateKey,
);

// Agent includes the mandate token in the ArohaRequest body
const envelope = await buildEnvelope("ArohaRequest", agentDID, merchantDID, {
  capability: "book-table",
  params: { date: "2026-05-05", partySize: 2 },
  mandateToken: paymentMandate.token,  // signed capability — not a card number
}, correlationId, agentPrivateKey);
```

The merchant agent validates:
1. The mandate signature (user signed it, not the requesting agent)
2. The mandate has not expired
3. The requested amount is within `spendLimitUsd`
4. The merchant's DID matches `merchantCategory` (validated against a category registry)
5. The `agentDid` in the mandate matches the envelope's `from` DID

---

## Part II — Agent Reputation

> Reputation scoring is an optional extension, not part of the core protocol ([positioning](positioning.md)). Its reference implementation, `@aroha-sdk/reputation`, is published on npm; its source is not in this repository. The on-chain contract `ArohaReputation.sol` is likewise optional.

### The Problem: Who Do You Trust?

When an orchestrator queries the registry and receives 12 agents all claiming to offer `currency-conversion`, it needs a signal beyond the capability name to choose between them. Price alone is not enough — a cheap agent that fails 30% of the time costs more in saga rollback overhead than an expensive agent with 99.9% reliability.

The academic literature identifies three failure modes in naive reputation systems:

1. **Cold start** — new agents have no reputation signal; they're excluded from high-value tasks [[8]](#ref-8)
2. **Reputation gaming** — agents manipulate their scores via fake interactions, Sybil attacks, or selective participation [[9]](#ref-9)
3. **Domain conflation** — an agent excellent at `flight-search` might be poor at `hotel-booking`; a single score obscures this [[10]](#ref-10)

### Current State of the Art

**RepuNet** (Ren et al., 2025, AAMAS 2026) [[8]](#ref-8) is the most directly applicable recent work. It introduces a dual-level reputation framework:
- **Agent-level**: individual performance tracking with EMA decay
- **Network-level**: reputation as a social graph signal — agents that cluster with consistently good actors inherit partial trust; agents that repeatedly transact with exploitative actors are progressively isolated

The emergent network behavior is notable: honest agents self-cluster, and dishonest agents are driven to the periphery without any central blacklist authority.

**AgentReputation** (Chishti, Oyinloye, Li, 2026) [[9]](#ref-9) proposes **context-specific reputation cards** — separate reputation scores per task category tied to agent metadata. This directly addresses domain conflation. Their policy engine escalates verification requirements when an agent's reputation in the requested domain is below a threshold, even if their global score is high.

**TRiSM for Agentic AI** (Raza et al., 2025) [[10]](#ref-10) introduces the **Component Synergy Score** — a metric for inter-agent collaboration quality, not just individual task success. An agent that consistently enables other agents to perform better in orchestrated workflows earns a higher collaboration score than one that technically succeeds but creates downstream friction.

**Inter-Agent Trust Models** (Hu and Rong, 2025) [[11]](#ref-11) provide a comparative analysis across six trust mechanisms and conclude that no single mechanism suffices for all scenarios:

| Mechanism | Best for | Weakness |
|---|---|---|
| **Cryptographic proof** | Identity verification | No information about past behaviour |
| **Stake/bond** | High-value irreversible transactions | Capital inefficient for small tasks |
| **Reputation** | Repeated, measurable interactions | Gameable; slow to respond to behaviour shifts |
| **Constraint** | Budget / policy enforcement | Cannot capture qualitative outcome quality |
| **Brief/claims** | Capability discovery | Self-reported; unverified |
| **ZK proof** | Privacy-sensitive verification | Computationally expensive |

The recommendation: **layer multiple mechanisms** based on transaction risk. Aroha adopts this directly.

### On-Chain Reputation Infrastructure

**ERC-8004: Trustless Agents** went live on Ethereum mainnet on January 29, 2026 [[12]](#ref-12). It defines three on-chain registries:
- **Identity Registry** — agent DID-to-address mapping
- **Reputation Registry** — standardized feedback recording from interactions
- **Validation Registry** — third-party attestations and verification status

The lightweight design leaves application logic off-chain, making it viable as a read/write layer for any agent protocol — including Aroha.

**Fetch.ai / ASI Alliance** (the merged Fetch.ai + Ocean Protocol + SingularityNET entity) [[13]](#ref-13) has been running production agent reputation in their Autonomous Economic Agent (AEA) network since 2023. Agents are discovered by reputation score weighted by service category and location. Their model demonstrates that reputation-based discovery reduces failed saga attempts by routing away from low-reliability agents before the saga begins.

### The Aroha Reputation Model

Aroha's reputation system is designed around five principles drawn from the literature:

1. **Domain-scoped scores** — separate scores per capability category (Chishti et al.) [[9]](#ref-9)
2. **EMA decay** — recent performance weighted more heavily than old performance; decay rate is configurable per capability (the existing `ArohaReputation.sol` implements this)
3. **Asymmetric updates** — failures penalise more than successes reward, preventing gradual score inflation (Mansa AI asymmetric mechanics: +5 success, -10 failure) [[14]](#ref-14)
4. **Network amplification** — agents whose partners consistently outperform the baseline get a synergy bonus (RepuNet dual-level model) [[8]](#ref-8)
5. **Stake escalation** — at each reputation tier, agents may optionally post a bond that increases their score weight and makes their commitments financially enforceable (Hu and Rong layered model) [[11]](#ref-11)

#### Reputation Score Structure

```typescript
interface ArohaReputationScore {
  did: string;

  // Global composite
  globalScore: number;       // 0–10000 (EMA-weighted composite)
  grade: "AAA"|"AA"|"A"|"B"|"C"|"D"|"F";
  totalInteractions: number;
  successRate: number;       // 0–1

  // Per-capability domain scores (prevents domain conflation)
  domains: {
    [capabilityCategory: string]: {
      score: number;
      interactions: number;
      avgLatencyMs: number;
      sagaCompletionRate: number;  // % of ArohaCommit following ArohaReserve
    }
  };

  // Collaboration quality (Component Synergy Score)
  synergyScore: number;      // 0–1000; measures how well this agent
                             // enables downstream agents in sagas

  // Financial trust layer (optional)
  stakedBondUsd: number;     // bond forfeited on malicious behaviour
  bondVerifiedAt: string;    // ISO timestamp

  // Data freshness
  lastUpdated: string;
  emaDecayRate: number;      // configurable per deployment
}
```

#### Reputation Update Events

Reputation updates are triggered by **saga lifecycle events** — not by self-report:

| Event | Score effect | Rationale |
|---|---|---|
| `ArohaCommitAck` received | +5 (capped at 100/day) | Task completed and committed |
| `ArohaCancelAck` received (saga cancelled by orchestrator) | 0 | Normal flow; no fault |
| `ArohaCancel` sent by provider (provider-initiated cancel) | −10 | Provider reneged on reservation |
| `ArohaError` with `Aroha_COMMITMENT_FAILED` | −10 | Commit failure |
| `ArohaSatisfactionSignal` (positive) | +8 | Human confirmed quality |
| `ArohaSatisfactionSignal` (negative) | −15 | Human flagged poor outcome |
| Saga timeout (no response within TTL) | −8 | Reliability signal |
| ERC-8004 negative attestation | −20 | Third-party verified failure |

#### Reputation-Gated Authorization

The `@aroha-sdk/policy` engine does not take reputation as an input. Its `CapabilityPolicy` covers request parameters, spend per call, rate limits and human approval only. Reputation gating happens on the caller's side, at discovery: registry `AgentRecord`s carry a `reputationScore` (0–10000), and `ArohaDiscovery.discover(capabilityIds, { minReputationScore })` in `@aroha-sdk/registry` drops agents below the threshold. The provider enforces its own capability policy:

```typescript
import { ArohaPolicyEngine, createPolicyMiddleware } from "@aroha-sdk/policy";

// Provider side: deterministic per-capability policy, enforced before the handler runs
const policy = new ArohaPolicyEngine();
policy.addPolicy({
  capabilityId: "book-flight",
  requiredParamKeys: ["origin", "dest", "date"],
  maxSpendPerCall: { amount: 500, currency: "USD" },
});
// new ArohaServer({ ..., middleware: [createPolicyMiddleware(policy)] })
```

A request the policy denies is rejected with `Aroha_FORBIDDEN` before any application code runs.

#### Cold-Start Bootstrapping

New agents with zero reputation history face the cold-start problem. Aroha addresses this with three mechanisms drawn from the literature:

1. **Bootstrapping bond** — a new agent can post a USD-denominated bond via `@aroha-sdk/settlement`. The bond doesn't grant reputation score directly, but it unlocks a `minInteractions` waiver for low-risk tasks. If the agent behaves well for 10 interactions, the bond is returned and normal reputation tracking begins.

2. **Delegated reputation** — an established agent (grade A or above) can cryptographically attest to a new agent's identity and vouch for it. The vouching agent accepts partial liability (their own score decreases if the vouched agent fails within the first 20 interactions). This mirrors the network trust model from RepuNet [[8]](#ref-8).

3. **Capability credential** — a third-party auditor (human or automated) can issue a Verifiable Credential attesting to a capability's implementation quality. This is the `Validation Registry` pattern from ERC-8004 [[12]](#ref-12). An agent with a verified VC for `book-flight` can bypass the `minInteractions` requirement for that specific capability.

#### Integration with ERC-8004

Aroha's on-chain reputation contract (`ArohaReputation.sol`) is designed to be ERC-8004 compatible. Aroha writes reputation updates to both its own registry and to the ERC-8004 Reputation Registry, enabling:
- Any ERC-8004-compatible agent network to read Aroha agent reputation
- Aroha agents to read reputation signals from non-Aroha agents that have ERC-8004 records
- Cross-protocol reputation portability — an agent that builds reputation on Aroha carries it into any other ERC-8004 network

---

## Part III — Putting It Together: Authorization + Reputation

The most powerful pattern emerges when authorization and reputation are coupled: **reputation-adaptive spending limits**.

A new agent with no reputation history receives an Intent Mandate with a low spending limit. As the agent accumulates positive reputation, the mandate ceiling can increase automatically:

```typescript
import { issueIntentMandate, attenuateToCart } from "@aroha-sdk/credentials";
import { BayesianReputationEngine } from "@aroha-sdk/reputation";

const engine = new BayesianReputationEngine();
const agentScore = await engine.compositeScore("did:aroha:travel-agent", "travel");

// Unlock higher limits as reputation grows
function spendLimitForScore(score: number): number {
  if (score >= 0.95) return 5000;
  if (score >= 0.85) return 1000;
  if (score >= 0.75) return 200;
  return 50;  // conservative default for new/unproven agents
}

const mandate = await issueIntentMandate(
  userDID,
  "did:aroha:travel-agent",
  { spendLimitUsd: spendLimitForScore(agentScore), currency: "USD" },
  userPrivateKey,
  4 * 60 * 60 * 1000   // 4 hours
);
```

The orchestrator checks the agent's current reputation score before issuing the mandate, applying the highest limit the agent has earned. Re-issue with a new score whenever the agent completes additional successful sagas. The mandate itself remains a narrow signed capability — not a payment credential.

This directly addresses the concern identified by Shi et al.'s B-I-P framework [[1]](#ref-1): static permissions are replaced with permissions that track agent trustworthiness dynamically.

---

## References

<a name="ref-1">[1]</a> Shi, G., Du, H., Wang, Z., Liang, X., Liu, W., Bian, S., & Guan, Z. (2025, rev. 2026). *SoK: Trust-Authorization Mismatch in LLM Agent Interactions*. arXiv:2512.06914. https://arxiv.org/abs/2512.06914

<a name="ref-2">[2]</a> Google. (2025). *Agent Payments Protocol v2 (AP2)*. Apache 2.0 License. https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol

<a name="ref-3">[3]</a> Acharya, V. (2025). *Secure Autonomous Agent Payments: Verifying Authenticity and Intent in a Trustless Environment*. arXiv:2511.15712. https://arxiv.org/abs/2511.15712

<a name="ref-4">[4]</a> Aimable, N. (2025). *Attenuating Authorization Tokens for Agentic Delegation Chains*. IETF Internet-Draft draft-niyikiza-oauth-attenuating-agent-tokens-00. https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens-00

<a name="ref-5">[5]</a> IETF OAuth Working Group. (2025). *OAuth 2.0 Extension: On-Behalf-Of User Authorization for AI Agents*. Internet-Draft draft-oauth-ai-agents-on-behalf-of-user-02. https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/

<a name="ref-6">[6]</a> Kasselman, P., Lombardo, J., Rosomakho, Y., Campbell, B., & Steele, N. (2025). *AI Agent Authentication and Authorization*. IETF Internet-Draft draft-klrc-aiagent-auth-01. https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/

<a name="ref-7">[7]</a> Huang, K., Narajala, V. S., Yeoh, J., Ross, J., Raskar, R., Harkati, Y., Huang, J., Habler, I., & Hughes, C. (2025). *A Novel Zero-Trust Identity Framework for Agentic AI: Decentralized Authentication and Fine-Grained Access Control*. arXiv:2505.19301. https://arxiv.org/abs/2505.19301

<a name="ref-8">[8]</a> Ren, S., Fu, W., Zou, X., Shen, C., Cai, Y., Chu, C., Wang, Z., & Hu, S. (2025). *Beyond the Tragedy of the Commons: Building A Reputation System for Generative Multi-agent Systems*. arXiv:2505.05029. AAMAS 2026. https://arxiv.org/abs/2505.05029

<a name="ref-9">[9]</a> Chishti, M. S., Oyinloye, D. P., & Li, J. (2026). *AgentReputation: A Decentralized Agentic AI Reputation Framework*. arXiv:2605.00073. https://arxiv.org/abs/2605.00073

<a name="ref-10">[10]</a> Raza, S., Sapkota, R., Karkee, M., & Emmanouilidis, C. (2025). *TRiSM for Agentic AI: A Review of Trust, Risk, and Security Management in LLM-based Agentic Multi-Agent Systems*. arXiv:2506.04133. https://arxiv.org/abs/2506.04133

<a name="ref-11">[11]</a> Hu, B. A., & Rong, H. (2025). *Inter-Agent Trust Models: A Comparative Study of Brief, Claim, Proof, Stake, Reputation and Constraint in Agentic Web Protocol Design*. arXiv:2511.03434. https://arxiv.org/abs/2511.03434

<a name="ref-12">[12]</a> De Rossi, M., Crapis, D., Ellis, J., & Reppel, E. (2026). *ERC-8004: Trustless Agents*. Ethereum Improvement Proposal. Live mainnet January 29, 2026. https://eips.ethereum.org/EIPS/eip-8004

<a name="ref-13">[13]</a> Fetch.ai / ASI Alliance. (2024). *Autonomous Economic Agents and the OEF Discovery Layer*. https://fetch.ai/blog/fetch-ai-ocean-collaboration

<a name="ref-14">[14]</a> Mansa AI. (2025). *Agent Reputation Framework: Team Trust Ratings*. https://www.cointrust.com/market-news/mansa-ai-advances-trust-with-agent-reputation-framework

<a name="ref-15">[15]</a> Bodea, T., Misono, M., Pritzi, J., Sabanic, P., Sommer, T., Unnibhavi, H., Schall, D., Santos, N., Stavrakakis, D., & Bhatotia, P. (2025). *Trusted AI Agents in the Cloud*. arXiv:2512.05951. https://arxiv.org/abs/2512.05951

<a name="ref-16">[16]</a> Garzon, S. R., Vaziry, A., Kuzu, E. M., Gehrmann, D. E., Varkan, B., Gaballa, A., & Küpper, A. (2025). *AI Agents with Decentralized Identifiers and Verifiable Credentials*. arXiv:2511.02841. https://arxiv.org/abs/2511.02841

<a name="ref-17">[17]</a> Wibowo, J. A., & Polyzos, G. C. (2025). *Toward a Safe Internet of Agents*. arXiv:2512.00520. https://arxiv.org/abs/2512.00520

<a name="ref-18">[18]</a> Alqithami, S. (2026). *Autonomous Agents on Blockchains: Standards, Execution Models, and Trust Boundaries*. arXiv:2601.04583. https://arxiv.org/abs/2601.04583

<a name="ref-19">[19]</a> Coinbase, Cloudflare, et al. (2025). *x402: Internet-Native Payment Protocol*. x402 Foundation. https://www.x402.org/

<a name="ref-20">[20]</a> W3C AI Agent Protocol Community Group. (2025). *Charter and Deliverables*. First meeting June 18, 2025. https://www.w3.org/community/agentprotocol/

<a name="ref-21">[21]</a> Anthropic. (2025). *Model Context Protocol: Authorization Specification*. https://modelcontextprotocol.io/specification/draft/basic/authorization

<a name="ref-22">[22]</a> KYA Network. (2025). *Know Your Agent: Trust Scoring Standard for Autonomous AI Systems*. https://knowyouragent.network/
