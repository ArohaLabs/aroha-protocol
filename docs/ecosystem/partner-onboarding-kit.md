<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Partner & Bridge Onboarding Kit

**Owner:** Ecosystem Agent  
**Version:** 1.0 — 2026-05-28  
**For:** External developers and organisations building bridges, agents, or integrations for the Aroha ecosystem

---

## Welcome

This kit gives you everything to go from zero to a listed Aroha ecosystem entry. The goal is fast — a basic bridge can be submitted in a day.

---

## What Can I Build?

| Type | Description | Example |
|------|-------------|---------|
| **Proxy Agent** | Wraps a REST API as an Aroha-capable agent | `@aroha-sdk/stripe-agent` |
| **Protocol Bridge** | Translates between Aroha and another agent protocol | `@aroha-sdk/mcp-bridge`, `@aroha-sdk/a2a-bridge` |
| **Framework Bridge** | Makes agents from another framework Aroha-compatible | `@aroha-sdk/langchain-bridge` |
| **SDK** | Aroha client library in another language | Python SDK, Go SDK |
| **Extension** | Adds capabilities on top of Aroha core | `@aroha-sdk/settlement`, `@aroha-sdk/reputation` |
| **Tool** | Dev tooling, observability, testing | Aroha inspector, registry explorer |

---

## Quickstart: Wrap Any REST API (~50 lines)

The fastest path: see [docs/wrap-any-rest-api.md](../wrap-any-rest-api.md).

This guide shows how to take any existing REST API and make it Aroha-callable in approximately 50 lines of TypeScript. The scaffolding handles envelope signing, DID management, and registry registration automatically.

```typescript
import { createProxyAgent } from '@aroha-sdk/micro';

const agent = createProxyAgent({
  capabilities: ['process-payment', 'refund'],
  handler: async (request) => {
    // Your existing REST API call here
    const result = await myApi.processPayment(request.payload);
    return { status: 'success', data: result };
  },
});

agent.listen(3000);
```

---

## Quickstart: Protocol Bridge

For bridging another agent protocol to Aroha, see the reference bridge implementations:

- [MCP bridge](../packages/mcp-bridge.md) — translate MCP tool calls into Aroha envelopes
- [A2A bridge](../packages/a2a-bridge.md) — translate A2A messages into Aroha envelopes
- [LangChain bridge](../packages/langchain-bridge.md) — make LangChain agents Aroha-compatible

Pattern:

```typescript
import { createBridge } from '@aroha-sdk/core';

const bridge = createBridge({
  inboundProtocol: 'mcp',
  outboundProtocol: 'aroha',
  translate: async (inbound) => toArohaEnvelope(inbound),
});
```

---

## Development Setup

```bash
# Prerequisites: Node.js ≥22, npm ≥10
git clone https://github.com/ArohaLabs/aroha-protocol.git
cd aroha-protocol
npm install && npm run build

# Scaffold a new agent/bridge
npx create-aroha-agent my-agent
npx @aroha-sdk/cli create-bridge --name my-bridge
```

---

## Testing Your Implementation

### Run the conformance suite locally

```bash
# From the aroha-protocol repo root
npm test

# Run only conformance tests (uses the dedicated conformance config)
npx vitest run --config vitest.conformance.config.ts
```

### Test against the reference implementation

```bash
# Start the reference registry and mock provider
npm run dev:mock-provider

# In another terminal, run your implementation against it
# and verify you can exchange signed envelopes and run a saga
```

For the full interoperability test procedure, see [conformance/implementer-packet.md](../conformance/implementer-packet.md).

---

## Submitting to the Ecosystem

### Step 1 — Choose your tier

| Goal | Tier | What's needed |
|------|------|---------------|
| Get listed, build an audience | Listed | Public repo, license, README |
| Show production readiness | Verified | Listed + conformance pass + CI green |
| Enterprise adoption signal | Certified | Verified + security review + 2 prod deployments |

Full criteria: [docs/ecosystem/quality-tiers.md](quality-tiers.md)

### Step 2 — Open a PR

Add your package to [docs/ecosystem.md](../ecosystem.md) using this template:

```markdown
## Submission

**Package name:** @yourorg/aroha-xxx
**Repository:** https://github.com/yourorg/aroha-xxx
**License:** MIT / Apache 2.0
**Tier requested:** Listed / Verified / Certified
**Layers implemented:** L0, L1, L2, L3, L4 (list applicable)
**Type:** Bridge / Agent / Extension / SDK / Tool
**Language:** TypeScript / Python / Rust / Go / other
**Conformance report issue:** #xxx (Verified tier only)
**Brief description (1–2 sentences):**
```

### Step 3 — Wait for review

The maintainer (see [MAINTAINERS.md](../../MAINTAINERS.md)) reviews within **10 business days**. They may request:
- Additional documentation
- Conformance evidence
- A bug fix before listing

### Step 4 — Get listed

Once approved, your entry is merged and you'll appear in the ecosystem docs. Verified and Certified entries get a badge in their README.

---

## Recognition & Incentives

| Achievement | Recognition |
|-------------|-------------|
| Listed | Ecosystem listing; monthly report mention |
| Verified | Verified badge; featured highlight |
| Certified | Certified badge; co-authored blog post |
| First implementation in a language | "Pioneer" recognition |

---

## Support

- **Questions about the protocol:** ask in [GitHub Discussions](https://github.com/ArohaLabs/aroha-protocol/discussions) or open a [GitHub Issue](https://github.com/ArohaLabs/aroha-protocol/issues)
- **Questions about your submission:** comment on your open PR
- **Conformance questions:** open a conformance report issue
- **Security issues:** see [SECURITY.md](../../SECURITY.md)

---

## Useful Links

| Resource | Link |
|----------|------|
| Protocol spec | [docs/spec/aroha-1.0.md](../spec/aroha-1.0.md) |
| DID method | [docs/spec/did-method.md](../spec/did-method.md) |
| Conformance test matrix | [docs/conformance/test-matrix.md](../conformance/test-matrix.md) |
| Wrap any REST API | [docs/wrap-any-rest-api.md](../wrap-any-rest-api.md) |
| Quickstart | [docs/quickstart.md](../quickstart.md) |
| Ecosystem quality tiers | [docs/ecosystem/quality-tiers.md](quality-tiers.md) |
| Trust page | [docs/trust.md](../trust.md) |
