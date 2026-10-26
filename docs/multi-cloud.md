<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha as the Multi-Cloud Agent Bridge

> "How do you get your AWS Bedrock agent to negotiate a contract with your vendor's Azure Copilot Studio agent?"
> You use Aroha.

---

## Where A2A stops and Aroha starts

Agents on different clouds already have a common transport: **A2A (Agent2Agent)**. A2A was contributed by Google and is now an open project governed under the **Linux Foundation**, with support from many vendors (including Microsoft, AWS and Salesforce). It is not a single-vendor protocol, and Aroha does not compete with it.

A2A standardises how one agent discovers another (Agent Cards), sends it messages, and tracks tasks. It deliberately leaves some questions to extensions or to the application:

- **Delegated authority** — who authorised this agent to spend money or take this action on a human's behalf, within what limits, and can a verifier check the whole delegation chain?
- **Per-message accountability** — a signature over each message that the receiver can keep as evidence.
- **Atomic multi-agent transactions** — reserve / commit / cancel across several agents, with compensation when one step fails.

Platform agent products (Amazon Bedrock Agents, Salesforce Agentforce, Microsoft Copilot Studio, Vertex AI agents) each add their own authorisation and orchestration on top, and those do not carry across vendors.

**Aroha is complementary to A2A:** it adds authority (signed mandates and mandate chains), signed envelopes and, as an optional extension, sagas *on top of* A2A transport. `@aroha-sdk/a2a-bridge` maps Aroha requests to A2A messages and carries the Aroha mandate in A2A message metadata (`aroha.mandate`) and in an Agent Card extension declaration, so an A2A agent that does not understand Aroha can ignore it, and one that does can verify it.

---

## The architecture: Aroha as the spine

```
AWS Bedrock                   Azure OpenAI                 GCP Vertex AI
     │                              │                             │
ArohaWrapper (A2A bridge)   ArohaWrapper (A2A bridge)   ArohaWrapper (A2A bridge)
     │                              │                             │
     └──────────────────────────────┼─────────────────────────────┘
                                    │
                        ┌───────────┴───────────┐
                        │   Aroha Protocol Spine  │
                        │   did:aroha: identities │
                        │   Ed25519 every message│
                        │   Saga reserve/commit  │
                        └───────────────────────┘
                                    │
                        ┌───────────┴───────────┐
                        │   InMemoryRegistry     │ (enterprise, air-gapped)
                        │   Aroha Registry HTTP   │ (managed or self-hosted)
                        │   ArohaRegistry.sol     │ (optional, on-chain)
                        └───────────────────────┘
```

Each cloud's agent keeps its existing reasoning framework (LangChain, Semantic Kernel, Bedrock Converse API) unchanged. The Aroha bridge wraps it, giving it:

- A `did:aroha:` identity with an Ed25519 keypair
- The ability to publish signed capability manifests
- The ability to participate in cross-vendor atomic sagas (optional orchestration extension, `@aroha-sdk/orchestrator`)

---

## Concrete enterprise scenario

**Situation**: A Fortune 500 runs HR on Workday (Salesforce agents), engineering on GitHub (Azure Copilot), and finance on SAP (AWS Bedrock agents).

The procurement agent (Azure) needs to:
1. Check the candidate's hire status (Salesforce agent)
2. Create a GitHub seat (Azure Copilot)
3. Generate an invoice entry (Bedrock agent)

Without Aroha: three bespoke integrations, three different auth schemes, no atomic rollback if step 3 fails.

With Aroha (sagas use the optional orchestration extension, [`@aroha-sdk/orchestrator`](spec/extensions.md)):
```typescript
const result = await saga.execute([
  {
    agentDID: "did:aroha:workday-hr-agent",      // Salesforce-hosted
    capability: "check-hire-status",
    readOnly: true,                               // no saga lock
    ...
  },
  {
    agentDID: "did:aroha:github-seat-agent",      // Azure-hosted
    capability: "provision-github-seat",
    ...
  },
  {
    agentDID: "did:aroha:sap-finance-agent",      // AWS-hosted
    capability: "create-invoice-entry",
    requiresApproval: true,
    estimatedCost: 150,
    costCurrency: "USD",
    ...
  },
]);
```

If the SAP agent rejects the invoice, the GitHub seat is atomically rolled back. The human approval gate fires before any money moves. Every message is cryptographically signed — the Salesforce agent's response is verifiable by the Azure agent without a shared trust root.

---

## The "Switzerland" positioning

Aroha is positioned as an **inter-cloud authority and trust layer** that runs alongside A2A and MCP, not a replacement for any vendor's agent platform or for A2A itself.

| Claim | How Aroha supports it |
|-------|----------------------|
| **Vendor-neutral** | Apache-2.0-licensed; W3C CG not yet proposed; no vendor controls the spec |
| **Cloud-agnostic identity** | `did:aroha:` DIDs are not tied to any cloud account or IAM system |
| **Bridges existing frameworks** | `@aroha-sdk/a2a-bridge`, `@aroha-sdk/mcp-bridge`, `@aroha-sdk/langchain-bridge` — existing agents unchanged |
| **No blockchain required** | `InMemoryRegistry` + `PostgresSettlement` — zero cloud dependencies |
| **Works on every cloud** | Node.js 22+, runs on Vercel, Cloudflare Workers, AWS Lambda, Azure Functions, GCP Cloud Run |

The pitch to enterprise architects: "You already have Copilot Studio and Bedrock. Aroha is what makes them talk to each other — and to your own agents — without vendor lock-in."

---

## 1-Click deployment targets

### Cloudflare Workers (global edge, 200+ locations)

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd examples/cloudflare
npx wrangler secret put AROHA_PRIVATE_KEY
npx wrangler deploy
# Your agent is live at: https://aroha-agent.<your-subdomain>.workers.dev
```

Your agent gets a globally-distributed Aroha endpoint with <1ms cold starts and free-tier capacity of 100k requests/day. Every Aroha envelope is validated at the edge — no request reaches your application layer without a verified Ed25519 signature.

### Vercel (serverless, 40+ regions)

```bash
git clone https://github.com/ArohaLabs/aroha-protocol
cd examples/vercel
vercel env add AROHA_PRIVATE_KEY
vercel deploy
# Your agent is live at: https://your-project.vercel.app/aroha/v1
```

### AWS Lambda

```bash
npm install @aroha-sdk/core
# Use validateEnvelope() + buildEnvelope() directly in your Lambda handler
# No ArohaServer needed — just HTTP in, HTTP out
```

### Azure Functions / GCP Cloud Run

Same pattern — import `@aroha-sdk/core`, call `validateEnvelope()`, respond with `buildEnvelope()`. Aroha's transport layer is plain HTTPS POST — it works on any compute that can serve HTTP.

---

## Why this beats vendor-native solutions

| Concern | Vendor-native | Aroha |
|---------|--------------|------|
| Cross-cloud auth | OAuth 2.0 federation (complex) | Ed25519 DIDs (self-sovereign) |
| Cross-cloud discovery | Hardcoded URLs | Registry-based capability lookup |
| Cross-cloud atomic transactions | Not supported | Saga reserve/commit/cancel (optional extension) |
| Vendor portability | Locked to cloud IAM | Portable keypair, any cloud |
| Open governance | Vendor-controlled | Open draft specification (Apache-2.0); joining an existing W3C Community Group is planned, not started |
| Privacy / GDPR | Vendor data plane sees all | Signed envelopes, consent tokens |
