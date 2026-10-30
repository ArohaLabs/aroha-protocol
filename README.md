<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

<div align="center">

# Aroha Protocol

**Cryptographically bounded authority for every agent in the chain.**

> Aroha Mandates let any agent that delegates keep cryptographically enforceable control over every agent it hands work to. No agent can exceed the scope it was granted.

[![CI](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/ci.yml)
[![Conformance](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml/badge.svg)](https://github.com/ArohaLabs/aroha-protocol/actions/workflows/conformance.yml)
[![npm](https://img.shields.io/npm/v/@aroha-sdk/core?label=%40aroha-sdk%2Fcore&color=0F6E56)](https://www.npmjs.com/package/@aroha-sdk/core)
[![npm](https://img.shields.io/npm/v/@aroha-sdk/mcp-bridge?label=%40aroha-sdk%2Fmcp-bridge&color=0F6E56)](https://www.npmjs.com/package/@aroha-sdk/mcp-bridge)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A522-brightgreen)](https://nodejs.org)
[![M8ven Score](https://m8ven.ai/badge/mcp/arohalabs-aroha-protocol-k1njlz?v=4c750af3e93a058514929b87e1ac420a)](https://m8ven.ai/mcp/arohalabs-aroha-protocol-k1njlz?s=readme)

[Docs](https://www.aroha-labs.com/docs/) · [Support matrix](docs/support-matrix.md) · [Local sandbox](docs/sandbox.md) · [Support](SUPPORT.md) · [Spec](docs/spec/aroha-1.0.md)

</div>

---

## Mandate-first agent authority

```typescript
import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, attenuateToPayment, verifyMandateChain } from "@aroha-sdk/credentials";

const human = await generateKeyPair();
const assistant = await generateKeyPair();
const flightAgent = await generateKeyPair();
// Content-addressed DIDs (did:aroha:z…) commit to their own public key,
// so a verifier needs no registry lookup to check signatures.
const humanDID = generateDid(human.publicKey);
const assistantDID = generateDid(assistant.publicKey);
const flightAgentDID = generateDid(flightAgent.publicKey);

// Human issues an intent mandate to the assistant ($500, 1 hour TTL)
const intent = await issueIntentMandate(
  humanDID, assistantDID,
  { spendLimitUsd: 500, merchantCategory: "4511" }, // MCC 4511 = airlines
  human.privateKey,
  3_600_000,
);

// The assistant attenuates scope downward to the flight agent ($300 of the $500).
// The child token embeds the signed chain back to the human.
const payment = await attenuateToPayment(
  intent, flightAgentDID,
  { spendLimitUsd: 300, merchantCategory: "4511" },
  assistant.privateKey,
);

// Flight agent verifies every link back to the human root before acting
const result = await verifyMandateChain(payment.token, undefined, {
  expectedRoot: humanDID,          // the human authority must come from
  expectedGrantee: flightAgentDID, // the flight agent itself
});
// result.valid === true, result.chainVerified === true,
// result.mandate?.constraints.spendLimitUsd === 300.
// A link that widens scope, or is signed by anyone but its grantor, fails.
```

---

## The problem

Agents now act for people and hand work to other agents and tools, often run by other companies. MCP and A2A connect them; identity providers name them. Nothing that travels with the work proves what each agent was allowed to do, stops the whole chain when the person changes their mind, or leaves a record anyone else can check.

| Approach | What you get today |
|----------|--------------------|
| **Per-hop credentials** (API keys, OAuth tokens) | Each hop enforces its own key. The person's limit, purpose and expiry are lost along the way. |
| **Framework guardrails** | Checks inside one codebase. Nothing survives the hop to another vendor's agent. |
| **Aroha Mandates** | A signed chain back to the person. Scope can only narrow. Any verifier checks it offline; revocation is pushed; every action, allowed or refused, gets a signed receipt. |

Aroha answers four questions for every action: **who is acting, what were they allowed to do, can it be stopped, and what actually happened.** It works with MCP, A2A and your identity provider rather than replacing them. See [what Aroha is (and is not)](docs/positioning.md).

---

## How it works

1. **Human issues a mandate** — signs an `IntentMandate` with authorized actions, a spending cap, and a TTL. Cryptographically bound to the receiving agent's DID.
2. **Any agent attenuates** — delegates a strict subset of that scope to the next agent, signed by the delegating agent. Scope narrows, never widens.
3. **Every agent verifies** — before acting, an agent verifies the mandate chain back to its human origin, offline. A forged, altered, widened or expired link fails verification.
4. **Revoke and prove** — the person can revoke at any time; the registry witness pushes the revocation to verifiers. Every allowed or refused action produces a signed receipt.
5. **Deploy in your existing stack** — bridges for MCP, LangChain, A2A, and Composio. Mandate verification drops in in two lines.

---

## Package architecture

```
Core — the four questions
├── @aroha-sdk/core           Identity (did:aroha), signed envelopes, receipts, conversation profile
├── @aroha-sdk/credentials  ★ Start here — mandates, attenuation, chain verification, revocation
├── @aroha-sdk/delegation     Multi-hop delegation with depth limits and stitched receipts
└── @aroha-sdk/policy         Deterministic limits checked before any model sees a request

Adapters (use Aroha from the stack you already run)
├── @aroha-sdk/mcp-server     Remote MCP server (2026 authorization spec)
├── @aroha-sdk/mcp-guard      Mandate checks in front of any MCP server
├── @aroha-sdk/mcp-bridge     MCP ↔ Aroha  (includes wrapMcp() one-liner)
├── @aroha-sdk/a2a-bridge     A2A ↔ Aroha
└── @aroha-sdk/langchain-bridge  LangChain / OpenAI functions ↔ Aroha

Extensions (maintained, optional; developed outside this repository)
└── orchestrator (sagas) · settlement · commerce · reputation

Tooling
├── @aroha-sdk/cli            scaffold · convert · doctor · dev sandbox
└── create-aroha-agent        npx create-aroha-agent — zero-config scaffolder
```

---

## Already building agents? Add mandate verification in 2 lines.

```typescript
import { verifyMandateChain } from "@aroha-sdk/credentials";

// In your agent's request handler. HUMAN_ROOT_DID is the human you accept authority from;
// MY_DID is this agent's own DID. The mandate travels in the signed Aroha envelope body
// (`credentialToken`); over MCP it travels in `_meta["aroha/mandate"]` with a holder proof
// (see @aroha-sdk/mcp-bridge). There is no mandate HTTP header.
const { valid, chainVerified, mandate, reason } = await verifyMandateChain(
  envelope.body.credentialToken,
  undefined, // default resolver: content-addressed did:aroha:z… DIDs
  { expectedRoot: process.env.HUMAN_ROOT_DID, expectedGrantee: MY_DID },
);
if (!valid || !chainVerified) {
  res.status(403).json({ error: reason });
} else {
  // mandate.constraints.spendLimitUsd, mandate.constraints.merchantCategory, etc.
}
```

**Already have an MCP server?** Add one import:

```typescript
import { wrapMcp, registryPublicKeyResolver } from "@aroha-sdk/mcp-bridge";

const agent = await wrapMcp(server.listTools(), {
  name: "my-tools",
  price: 0.01,
  resolvePublicKey: registryPublicKeyResolver(), // verifies who is calling
  handlers: { search: async (args) => ({ content: [{ type: "text", text: await search(args) }] }) },
});
await agent.start();
// ✓ did:aroha:my-tools  →  http://localhost:3001
```

**Using LangChain?** Call any mandate-aware Aroha agent as a native tool:

```typescript
import { createArohaLangChainTool } from "@aroha-sdk/langchain-bridge";

const tool = await createArohaLangChainTool(
  "http://localhost:3001",
  "search-flights",
  "Search available flights by origin, destination, and date"
);
// plug `tool` straight into AgentExecutor, createOpenAIFunctionsAgent, etc.
```

**Using an AI coding agent?** Point it at the [`aroha-integrate`](skills/aroha-integrate/SKILL.md) Agent Skill (or [`docs/llms.txt`](docs/llms.txt)): it picks the smallest integration path for your code, applies it, and checks that out-of-scope calls are refused.

**Scaffold a new agent pre-wired for mandate verification:**

```bash
npx create-aroha-agent my-agent
cd my-agent && npm install && npm run dev
# → [my-agent] did:aroha:my-agent  http://localhost:3001/aroha/v1  Ready ✓
```

---

## CLI reference

```bash
aroha init my-agent              # interactive scaffold
aroha init my-agent --yes        # zero-config: picks all defaults, writes .env
aroha convert --from mcp --dir . # wrap existing agent
aroha doctor [endpoint]          # check environment + connectivity
aroha dev                        # local dev registry + dashboard
```

---

## Deploy

One-click templates for fast deployment.

> **Note:** the Vercel and Cloudflare buttons clone from `github.com/ArohaLabs/aroha-protocol`. You can
> also copy the template directory from a checkout and deploy it with the platform CLI.

| Platform | Button |
|----------|--------|
| Vercel | [![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/vercel) |
| Cloudflare | [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ArohaLabs/aroha-protocol/tree/main/examples/cloudflare) |
| Railway | No published template yet; manual setup in [examples/railway](examples/railway/README.md) |
| Render | No one-click button (Render needs `render.yaml` at a repo root); Blueprint steps in [examples/render](examples/render/README.md) |

---

## What's in this repo

```
packages/               SDK packages (@aroha-sdk/*)
agents/mock-provider-agent/ Reference provider agent for interoperability tests
examples/               Deployment templates (Vercel, Cloudflare, Railway, Render)
examples/sandbox-agents/ Pre-built sandbox agents (flight, hotel, weather, web-search, summarizer)
contracts/              Solidity contracts (ArohaRegistry, ArohaEscrow, ArohaReputation)
docs/                   MkDocs documentation site
```

The Aroha runtime (desktop app) is developed in a separate, private repository and has not been released. The saga, settlement,
commerce and reputation extensions are also developed outside this repository; they stay published on npm.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Node.js | ≥ 22 |
| npm | ≥ 10 |

Foundry and Python are only needed for the smart contract demo and MkDocs docs site respectively.

---

## Contributing

Use [GitHub Issues](https://github.com/ArohaLabs/aroha-protocol/issues) for bugs and feature requests and
[GitHub Discussions](https://github.com/ArohaLabs/aroha-protocol/discussions) for questions and ideas,
or email the maintainer listed in [MAINTAINERS.md](MAINTAINERS.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) (commits need a DCO sign-off) and [SUPPORT.md](SUPPORT.md).
For security issues, see [SECURITY.md](SECURITY.md).

```bash
npm install && npm run build && npm test
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
