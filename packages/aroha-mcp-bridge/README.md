# @aroha-sdk/mcp-bridge

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/mcp-bridge)

Translate between MCP tool definitions and Aroha agents, in both directions:
wrap an MCP tool server as a callable Aroha agent, or call a discovered Aroha
agent's capabilities as MCP tools.

## Install

```bash
npm install @aroha-sdk/mcp-bridge
```

## Quick example

```typescript
import { wrapMcp, registryPublicKeyResolver } from "@aroha-sdk/mcp-bridge";

// Expose your MCP tools as an Aroha agent
const agent = await wrapMcp(server.listTools(), {
  name: "weather-tools",
  resolvePublicKey: registryPublicKeyResolver(), // verifies who's actually calling
  handlers: {
    // One entry per tool name returned by listTools(). Each must return the
    // tool's real result — wrapMcp() has no way to run your tool for you.
    get_weather: async (args) => ({
      content: [{ type: "text", text: await getWeather(args) }],
    }),
  },
});

await agent.start(); // throws if any tool in the list has no handler entry
// ✓ did:aroha:weather-tools  →  http://localhost:3001
```

Every incoming request is verified before any tool runs: signature (against
the sender DID `resolvePublicKey` resolves), expiry, and nonce replay — the
same `validateEnvelope()` every other Aroha transport in the SDK uses, not a
bridge-specific check. A caller `resolvePublicKey` can't resolve, or whose
signature doesn't match, never reaches a tool handler.

## Requiring a spending mandate

```typescript
import { httpRevocationCheck, httpRedemptionStore } from "@aroha-sdk/credentials";
import { httpKelSource } from "@aroha-sdk/registry";

const agent = await wrapMcp(server.listTools(), {
  name: "weather-tools",
  capabilityPrices: { forecast: 0.01 },          // or `price` for every tool
  resolvePublicKey: registryPublicKeyResolver(),
  requireMandate: true,
  kelSource: httpKelSource(REGISTRY),            // roots must be verified PERSONS (default with a kelSource)
  // …or expectedRoot: "did:aroha:…" / trustedRoots: [...] without KELs
  isRevoked: httpRevocationCheck(REGISTRY),
  redemption: httpRedemptionStore(REGISTRY, API_KEY),
  handlers: { /* ... */ },
});
```

With `requireMandate: true`, every request must carry a spending mandate (in
`body.credentialToken`) whose chain `verifyMandateChain` verifies back to a
**trusted root**, whose leaf grants the calling agent's DID, and which no link
of has been revoked. `start()` refuses to run with `requireMandate` unless a
root policy is set (`kelSource` → person roots, `expectedRoot`, or
`trustedRoots`): without one, any agent could sign itself a root mandate.

A priced call (`price` / `capabilityPrices`) additionally needs a
**payment**-tier mandate, and its price is redeemed against the mandate's
cumulative limit (`redeemPaymentMandate`, merchant = this agent's DID) before
the tool runs; a call that would exceed the limit gets HTTP 402. Without a
`redemption` store a per-process `InMemoryRedemptionStore` is used (logged).

A price needs the mandate gate: `start()` refuses when any tool has a price
above zero and `requireMandate` is off, because the price would be advertised
and never charged. Set `allowUnchargedPricing: true` only when payment is
collected some other way.

## MCP on the wire

Set `mcp` to also serve the wrapped tools as an MCP server on the same port:
Streamable HTTP at `/mcp` (MCP revision 2026-07-28, with a stateless fallback
for 2025-era clients). Any MCP client can list and call the tools; calls pass
the same mandate gate (and are charged the same way) as Aroha envelopes.

```typescript
const agent = await wrapMcp(server.listTools(), {
  name: "weather-tools",
  resolvePublicKey: registryPublicKeyResolver(),
  requireMandate: true,
  kelSource: httpKelSource(REGISTRY),
  isRevoked: httpRevocationCheck(REGISTRY),
  mcp: { path: "/mcp" },
  handlers: { /* ... */ },
});
```

### Mandate carriage convention: `_meta["aroha/mandate"]`

An MCP `tools/call` carries its mandate in the request `_meta`, never in a
header and never as a tool argument:

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_weather",
    "arguments": { "city": "Auckland" },
    "_meta": {
      "aroha/mandate": {
        "token": "<mandate token>",
        "holder": "did:aroha:…",
        "nonce": "<single use>",
        "expires": "<ISO 8601, at most 5 minutes ahead>",
        "proof": "<base64url Ed25519 signature by the holder>"
      }
    }
  }
}
```

`proof` signs the RFC 8785 (JCS) form of
`{ purpose: "aroha.mcp-mandate-presentation/v1", audience, tool, argsSha256, mandateId, holder, nonce, expires }`,
where `audience` is the wrapped agent's DID and `argsSha256` is SHA-256 of
the JCS arguments. The bridge resolves `holder` with `resolvePublicKey`,
checks the proof, refuses a reused nonce, then verifies the mandate chain
with `holder` as the expected grantee. A token without a valid proof is
refused: on its own it would be a bearer credential anyone who saw it could
replay. Build the `_meta` with `presentMandate()`:

```typescript
import { presentMandate } from "@aroha-sdk/mcp-bridge";

const _meta = await presentMandate({
  token, holderDid: MY_DID, holderPrivateKey: MY_KEY,
  audience: AGENT_DID, tool: "get_weather", args,
});
await client.callTool({ name: "get_weather", arguments: args, _meta });
```

The Aroha-envelope endpoint (`POST /aroha/v1`) keeps carrying the mandate in
the signed envelope body as `credentialToken`. There is no `x-aroha-mandate`
HTTP header convention.

Without `requireMandate`, the MCP endpoint authenticates no one, so `start()`
refuses to serve it on a non-loopback host unless `mcp.allowUnauthenticated`
is set (put your own authentication in front). Host and Origin headers are
checked against loopback names plus `mcp.allowedHosts`.

## Governed mode

```typescript
const agent = await wrapMcp(server.listTools(), {
  name: "weather-tools",
  governed: true,
  resolvePublicKey: registryPublicKeyResolver(),
  kelSource: httpKelSource(REGISTRY),
  trustedRoots: [ALICE_DID],                     // or expectedRoot
  isRevoked: httpRevocationCheck(REGISTRY),
  redemption: httpRedemptionStore(REGISTRY, API_KEY),
  handlers: { /* ... */ },
});
```

`governed: true` turns every mandate check on: a mandate on every call,
person roots verified through their Key Event Logs, a revocation check on
every link, and a pinned root (`governedVerification()` from
`@aroha-sdk/credentials`). `start()` refuses to run without `isRevoked`,
`kelSource`, a root pin and a durable `redemption` store; an
`InMemoryRedemptionStore` is refused.

**Breaking (2.x):** `requireMandate` without a root policy now fails at
`start()`; unknown capabilities answer 404 before the mandate check; priced
calls with `requireMandate` are charged.

## API

- `wrapMcp(tools, opts)` — wrap an array of MCP tool definitions as an Aroha agent. Returns `{ did, port, endpoint, capabilities, start() }`.
- `opts.name` — agent name (used to generate the DID).
- `opts.handlers` — **required.** Real tool implementations, keyed by tool name, each returning `{ content: [{ type: "text", text }], isError? }`.
- `opts.resolvePublicKey` — **required.** Resolves a caller DID to its Ed25519 public key, used to verify every request's signature. Use `registryPublicKeyResolver()` for the common case, or supply your own.
- `opts.requireMandate` — when `true`, reject any request without a mandate chain to a trusted root granting the caller. Default `false`.
- `opts.expectedRoot` / `opts.trustedRoots` / `opts.requirePersonRoot` + `opts.kelSource` (+ `kelStore`) — the root policy (one is required with `requireMandate`).
- `opts.isRevoked` — revocation hook for every link (e.g. `httpRevocationCheck`).
- `opts.price` / `opts.capabilityPrices` — per-call price in USD (all tools / per tool name or capability id); advertised in pricing metadata and redeemed against payment mandates.
- `opts.redemption` — `RedemptionStore` priced calls are charged to.
- `opts.governed` — governed mode (see above).
- `opts.allowUnchargedPricing` — allow priced tools without `requireMandate`.
- `opts.maxTtlMs` / `opts.maxFutureSkewMs` / `opts.clockToleranceMs` — forwarded to `validateEnvelope`.
- `opts.did` / `opts.port` / `opts.privateKey` — override the auto-generated identity/port.
- `registryPublicKeyResolver(baseUrl?)` — a `resolvePublicKey` implementation backed by the Aroha registry.
- `arohaAgentToMcpTools(agent, orchestratorDID, orchestratorPrivateKey, client, correlationId, options?)` — the other direction: call a discovered Aroha agent's capabilities as MCP tools. Returns `{ tools, handleToolCall }`. `options.mandateToken` (a token, or a function per call) is sent in `body.credentialToken`; `options.resolvePublicKey` turns on verification of every response envelope (signer, recipient, expiry, replay, correlationId; `verifyResponse: false` turns it off).
- `opts.mcp` — `{ path?, allowUnauthenticated?, allowedHosts? }`: also serve the tools as an MCP server (see above).
- `presentMandate({ token, holderDid, holderPrivateKey, audience, tool, args, ttlMs? })` — build `_meta["aroha/mandate"]` for an MCP call; `verifyPresentation()` is the server-side check.
- `mcpToolsToArohaCapabilities(tools)` — convert MCP tool definitions into Aroha capability definitions, used internally by `wrapMcp()`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).