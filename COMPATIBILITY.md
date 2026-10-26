# Backwards Compatibility Policy

This document defines the stability guarantees for the Aroha Protocol and SDK.

## Stability Tiers

Every npm package published in release `npm-v2026.10.19` (2026-10-19) is listed below, at the version published then. Packages are versioned **independently**. `@aroha-sdk/orchestrator`, `@aroha-sdk/settlement`, `@aroha-sdk/commerce` and `@aroha-sdk/reputation` are no longer developed in this repository; they stay on npm at the versions shown. `@aroha-sdk/store-postgres` and `@aroha-sdk/store-redis` (0.1.0) are in `packages/` but not yet published.

### Stable (semver-protected)

These packages follow [Semantic Versioning](https://semver.org). Breaking changes require a major version bump and should go through the deprecation process below.

| Package | Version | Notes |
|---------|---------|-------|
| `@aroha-sdk/core` | 2.0.0 | Identity, crypto, envelopes, transport |
| `@aroha-sdk/credentials` | 2.0.0 | Mandates, human credentials, RBAC |
| `@aroha-sdk/registry` | 2.0.0 | Registry clients and discovery |
| `@aroha-sdk/run` | 2.0.0 | `/v1/run` server and client |
| `@aroha-sdk/cli` | 1.3.0 | `aroha` CLI |
| `create-aroha-agent` | 1.3.0 | `npx create-aroha-agent` scaffolder |
| `@aroha-sdk/mcp-bridge` | 3.0.0 | See the 2.0.0 migration note below |

**What "stable" means:**

- Public TypeScript APIs (exported interfaces, function signatures) will not change in an incompatible way within a major version
- The `did:aroha:` DID format is stable
- The Aroha envelope schema (`ArohaEnvelope`, `ArohaMessage`) is stable
- Mandate token format (`ArohaSpendingMandateBody`) is stable — issued tokens remain verifiable across SDK versions
- `arohaProtocolVersion: "1.0"` will be accepted by all future 1.x servers

### Beta (usable; API may still change in a minor release)

| Package | Version | Notes |
|---------|---------|-------|
| `@aroha-sdk/orchestrator` | 1.4.0 | Saga engine, agent selector, negotiator |
| `@aroha-sdk/settlement` | 2.0.0 | Settlement hooks are called by SagaEngine but **spending limits are not enforced at the transport layer**. Includes null, API-key, quota, escrow, Stripe and Postgres backends in one package; the escrow backend depends on contracts that are not deployed. |
| `@aroha-sdk/audit` | 1.4.1 | Tamper-evident audit log; schema not finalised |
| `@aroha-sdk/policy` | 1.3.1 | Declarative request policy |
| `@aroha-sdk/mcp-guard` | 0.2.1 | Policy wrapper for MCP servers |
| `@aroha-sdk/hermes-bridge` | 1.2.5 | Exposes Aroha agents as MCP stdio servers |
| `@aroha-sdk/langchain-bridge` | 2.0.0 | LangChain ↔ Aroha |
| `@aroha-sdk/micro` | 2.0.0 | Express-style one-file agent API |

### Experimental / labs (no stability guarantees)

These may change shape or be removed in any release. Do not use them for production financial flows.

| Package | Version | Notes |
|---------|---------|-------|
| `@aroha-sdk/a2a-bridge` | 2.0.0 | A2A 1.0 mapping, JSON-RPC client, mandate carriage (2.0.0 changes the wire shapes; see its README) |
| `@aroha-sdk/bbs` | 0.2.0 | BBS signatures — selective-disclosure primitives |
| `@aroha-sdk/cache` | 1.2.2 | Semantic request cache |
| `@aroha-sdk/chaos` | 1.2.2 | Fault injection for testing — development only |
| `@aroha-sdk/commerce` | 1.2.3 | B2B/B2C/C2B patterns — API may consolidate with core |
| `@aroha-sdk/composio-bridge` | 1.2.3 | Composio bridge |
| `@aroha-sdk/delegation` | 0.3.0 | Multi-hop delegation, mandate-chain verification |
| `@aroha-sdk/evals` | 1.2.3 | Evaluation harness (`aroha-evals` binary) |
| `@aroha-sdk/gmail-mcp` | 0.1.1 | Gmail MCP server |
| `@aroha-sdk/mcp-server` | 2.0.0 | MCP server: stdio and remote (Streamable HTTP + OAuth) connector |
| `@aroha-sdk/openclaw-bridge` | 2.0.0 | OpenClaw bridge |
| `@aroha-sdk/preferences` | 1.2.3 | Preference profile, filter, scoring |
| `@aroha-sdk/reputation` | 1.4.1 | Reputation engine — API not finalised |
| `@aroha-sdk/resilience` | 1.2.2 | Circuit breaker, bulkhead, retry |
| `@aroha-sdk/telemetry` | 1.2.3 | W3C Trace Context propagation |
| `@aroha-sdk/trust` | 0.1.1 | Caller-uniqueness / nullifier proofs — prototype |
| `@aroha-sdk/trusted-mesh` | 2.0.0 | Skips signature verification inside a trusted mesh — prototype |
| `examples/books-mcp` | — | Demo code, not an npm package (moved from `packages/aroha-books-mcp`) |

There are no `@aroha-sdk/escrow`, `@aroha-sdk/postgres` or `@aroha-sdk/stripe` packages; those backends live inside `@aroha-sdk/settlement`.

---

## Migration notes

### `@aroha-sdk/mcp-bridge` 1.2.2 → 2.0.0

Released in commit `b27e866` (`fix(mcp-bridge)!`, in the private development history; not in this repository's public history). This was a security fix and shipped **without** the deprecation period described below.

- **`handlers` is now required** on `WrapMcpOptions`, keyed by MCP tool name. In 1.x, `wrapMcp()` never called the tool: it returned a placeholder `{ _note: "Handled by MCP tool: X" }`. `start()` now throws if any tool has no handler.
- **`resolvePublicKey` is now required.** Every inbound request is now checked by `validateEnvelope()` (signature, expiry, nonce replay). In 1.x no verification ran. Use `registryPublicKeyResolver()` for the common case.
- **New optional `requireMandate`.** When `true`, each request must carry a valid spending mandate in `body.credentialToken` granted to the caller's DID; otherwise it is rejected with 403 before any tool runs.
- The `onMandate` option and `.register()` method that 1.x documentation described **never existed** and are not part of 2.0.
- Auto-generated keys are now real 32-byte Ed25519 seeds; in 1.x every signed reply from an auto-generated identity threw.

## What is NOT guaranteed

Even within stable packages, the following are considered internal implementation details and may change:

- Private class members (anything not in the exported TypeScript interfaces)
- Internal error message strings (check `err.code` / `err instanceof X`, not `err.message`)
- The shape of `dist/` build artifacts beyond the declared `exports` map
- Test utilities in `*/src/__tests__/` directories

## Breaking Change Process

For stable packages, breaking changes follow this process:

1. **Deprecation**: The old API is marked `@deprecated` with a JSDoc comment pointing to the replacement. A minor-version release ships with both old and new APIs.
2. **Notice period**: At least **6 months** between the deprecation release and the breaking major-version release.
3. **Migration guide**: A `MIGRATION.md` is published alongside the major-version release with a step-by-step upgrade path.
4. **Changelog**: Every breaking change is listed in `CHANGELOG.md` under a `### Breaking` heading.

## Protocol Versioning

The Aroha protocol itself is versioned separately from the SDK packages.

- Protocol version is declared in every envelope: `"arohaProtocolVersion": "1.0"`
- The SDK will accept envelopes from any 1.x protocol version
- Protocol 2.0 would require a new major SDK version with a migration guide
- The `did:aroha:` DID method identifier and key derivation scheme are protocol-level and considered **permanently stable**

## Registry Stability

- Agent DIDs registered with the Aroha HTTP Registry are intended to remain resolvable; there is no formal retention guarantee yet
- The registry REST API (`/v1/agents/*`) is stable and versioned independently
- There is no published uptime SLA for any hosted registry

## Mandate Token Stability

Signed mandate tokens (`ArohaSpendingMandateBody` + Ed25519 signature) issued by any SDK ≥ 1.0.0 will:

- Verify correctly with any future SDK 1.x release
- Produce the same signature for the same inputs (deterministic)
- Be rejected by `verifyMandate()` if tampered with, regardless of SDK version

The token encoding (JSON body → UTF-8 bytes → Ed25519 sign) is stable and documented in the protocol specification.

---

*Last updated: 2026-10-25*
