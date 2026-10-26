<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Ecosystem

> **Positioning note (2026-10-19).** Ecosystem entries below were collected under the earlier framing; the `Saga?` column describes an optional extension. Aroha now describes itself as the protocol for **bounded, verifiable agent authority** — who is acting, what a person allowed, how to stop it, and what happened. Discovery, sagas, settlement and commerce remain available as optional extensions and are documented here as such. See [What Aroha is (and is not)](positioning.md).

Community-built bridges, proxy agents, and extensions for the Aroha protocol.

> **Build it. Publish it. List it here.**
> The goal is a world where any AI agent can discover and transact with any other — regardless of vendor, cloud, or framework. Every community bridge brings that closer.

---

## Proxy Agents (Web2 API wrappers)

Proxy agents translate Aroha envelopes into existing REST API calls, making any SaaS service Aroha-capable without vendor involvement.

| Agent | API | Capabilities | Saga? |
|-------|-----|-------------|-------|
| [`@aroha-sdk/stripe-agent`](packages/settlement.md) | Stripe | payments, customers, invoices, subscriptions | ✓ |
| [`@aroha-sdk/salesforce-agent`](wrap-any-rest-api.md) | Salesforce | leads, accounts, opportunities, cases | ✓ |
| [`@aroha-sdk/zendesk-agent`](wrap-any-rest-api.md) | Zendesk | tickets, users, organizations, comments | ✓ |
| [`@aroha-sdk/github-agent`](architecture.md) | GitHub | issues, PRs, comments, merge | ✓ |
| [`@aroha-sdk/jira-agent`](architecture.md) | Jira Cloud | issues, transitions, assignments, comments | ✓ |

**Want to add Slack, HubSpot, Notion, Linear, or your internal API?**
See [Wrap Any REST API in ~50 Lines →](wrap-any-rest-api.md)

---

## Protocol Bridges

Bridges translate between Aroha and other agent frameworks so existing agents can participate in Aroha sagas without rewriting.

| Bridge | Protocol | Direction |
|--------|----------|-----------|
| [`@aroha-sdk/mcp-bridge`](packages/mcp-bridge.md) | Model Context Protocol | MCP ↔ Aroha |
| [`@aroha-sdk/a2a-bridge`](packages/a2a-bridge.md) | A2A (Agent2Agent, Linux Foundation) | A2A ↔ Aroha |
| [`@aroha-sdk/langchain-bridge`](packages/langchain-bridge.md) | LangChain / OpenAI function tools | Framework ↔ Aroha |

---

## Extensions

| Package | What it adds |
|---------|-------------|
| [`@aroha-sdk/telemetry`](packages/telemetry.md) | W3C Trace Context propagation |
| [`@aroha-sdk/trusted-mesh`](packages/trusted-mesh.md) | VPC/mTLS signature bypass |
| [`@aroha-sdk/cache`](packages/cache.md) | Semantic ArohaRequest deduplication |
| [`@aroha-sdk/policy`](packages/policy.md) | Policy-as-Code JSON enforcement |

---

## Scaffold your own bridge in 30 seconds

```bash
npm install -g @aroha-sdk/cli
aroha create-bridge --name my-api --sdk "My API" -y
cd aroha-my-api-bridge
# Edit src/bridge.ts — implement handleCapability()
npm run build && npm publish --access public
```

The `aroha create-bridge` command generates a fully-structured, ready-to-publish npm package following the [duck-typed bridge pattern](packages/langchain-bridge.md#duck-typed-interfaces) — no hard dependencies on any specific SDK version.

---

## Submit to the registry

Add your package to [`community/registry.json`](https://github.com/ArohaLabs/aroha-protocol/blob/main/community/registry.json) via pull request:

```json
{
  "id": "aroha-my-api-agent",
  "type": "proxy-agent",
  "name": "My API Agent",
  "description": "Short description of what this wraps",
  "package": "@aroha-sdk/my-api-agent",
  "repository": "https://github.com/your-org/aroha-my-api-agent",
  "capabilities": ["list-items", "create-item"],
  "sagaCapable": true,
  "author": "your-github-username",
  "license": "Apache-2.0",
  "tags": ["your-api", "saas"]
}
```

**Requirements:**
- Apache-2.0 or MIT license
- Published to npm as a public package
- README with a working code example
- At least one capability with a test

---

## Community governance

A W3C Community Group charter is drafted (`CHARTER.md`) but has not been submitted, and no W3C Community Group has been proposed. The current plan is to join the existing Agent Identity Registry Protocol Community Group and offer `did:aroha` as input. The protocol spec is in `docs/spec/` and governed by the principles in [`docs/governance.md`](governance.md).

Bridge packages are community-owned — the Aroha project team reviews registry submissions for protocol compliance, not implementation details. Bridge authors own and maintain their packages.
