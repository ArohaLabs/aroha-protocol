# @aroha-sdk/run

![Stable](https://img.shields.io/badge/status-stable-brightgreen) ![npm](https://img.shields.io/npm/v/@aroha-sdk/run)

Lightweight HTTP runtime for Aroha agents — the server layer that mandate-carrying requests travel over.

## Install

```bash
npm install @aroha-sdk/run
```

## Quick example

```typescript
import { serve } from "@aroha-sdk/run";
import { verifyMandateChain } from "@aroha-sdk/credentials";

const agent = serve("flight-agent", async (ctx) => {
  // ctx: { message, sessionId?, history?, context?, caller, requestApproval() }
  const token = ctx.context?.mandateToken;
  if (typeof token !== "string") return "No spending mandate supplied.";

  // Verify every link back to the human you accept authority from
  const { valid, chainVerified, mandate, reason } = await verifyMandateChain(token, undefined, {
    expectedRoot: process.env.AROHA_MANDATE_ROOT_DID,
    expectedGrantee: process.env.AROHA_AGENT_DID,
  });
  if (!valid || !chainVerified || !mandate) return `Mandate rejected: ${reason}`;

  // Act within mandate.constraints.spendLimitUsd
  return bookFlight(ctx.message, mandate.constraints);
}, { description: "Books flights within a spending mandate" });

agent.start(3001);
// Or, on Workers / Vercel Edge / Bun: export default { fetch: agent.fetch };
```

## Why this exists in the mandate chain

The HTTP layer is where mandate-carrying requests arrive and where enforcement happens.
`@aroha-sdk/run` provides `serve()`, which wires up the `/v1/run` endpoint (JSON or SSE), so a
handler can verify the mandate chain before any agent logic executes.

## API

- `serve(name, handler, options?)` → `{ start(port?, host?), fetch(request), register(endpointUrl, options?) }`.
  - `handler(ctx)` returns a string, or is an async generator yielding tokens / `RunEvent`s (tool calls, approvals).
  - `ServeOptions` include `description`, `memory` (`none` / `session` / `persistent`), `sessionStore`, `auth` / `bearerTokens`, `resolveCaller`, `pendingApprovals`.
- `createClaudeHandler(options)` — a ready-made handler backed by the Anthropic API.
- `InMemorySessionStore` — default session store.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
