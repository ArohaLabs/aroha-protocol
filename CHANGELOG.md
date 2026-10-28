<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Aroha are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Changed

- **Specification scope (protocol change):** the core specification now covers Layers 0–3 (Transport, Identity, Registry, Messaging). §7 (orchestration, sagas) and §8 (preference context) moved unchanged to a companion [extensions document](spec-public/spec/extensions.md); §7 and §8 remain as pointers so section numbers do not shift. §11 conformance items 4 and 5 now apply to implementations that adopt those extensions.
- **Repository scope:** this repository now holds the protocol, its SDKs and its adapters. Moved out (history kept in the private archive):
  - `apps/aroha-runtime`, `apps/aroha-desktop`, `apps/aroha-ui` and `packaging/` → a private repository (the `runtime-v*` tags and their release workflow go with them).
  - `@aroha-sdk/orchestrator`, `@aroha-sdk/settlement`, `@aroha-sdk/commerce`, `@aroha-sdk/reputation` → a private repository. They stay published on npm at their current versions.
  - The demo agents in `agents/` removed, except `agents/mock-provider-agent`, kept as the reference agent for the implementer packet's interoperability test. `services/rag-engine` removed. `scripts/test-e2e.mjs` and `scripts/demo-server.mjs`, which drove the demo agents, removed with them.
- **`@aroha-sdk/delegation` and Appendix A (wire change, spec addition):** `createDelegationMiddleware` sent its remaining rejections with the misspelled `ARHOA_` prefix and no canonical code. Seven codes are added to the specification's Appendix A, core's `ArohaErrorCode` and the Python, Go and Java code lists (35 codes in all), and the middleware now sends them, with the same HTTP statuses: `Aroha_NO_MANDATE` (400), `Aroha_CHAIN_INVALID` (400), `Aroha_UNTRUSTED_ROOT` (403), `Aroha_ROOT_KEY_MISMATCH` (403), `Aroha_CHAIN_REJECTED` (403), `Aroha_SCOPE_UNKNOWN` (403) and `Aroha_CONTEXT_MISMATCH` (403, a room-bound or `onBehalfOf`-bound mandate presented without a matching request). Clients matching `ARHOA_*` codes must update; no `ARHOA_` code is sent any more.

### Added

- **Durable stores** for presentation nonces, enrollment (challenges and bindings) and the spending ledger, so replay protection and running totals survive restarts and are shared between processes:
  - `@aroha-sdk/store-postgres` (`migrate`, `PostgresNonceStore`, `PostgresEnrollmentStore`, `PostgresSpendingLedger`) and `@aroha-sdk/store-redis` (`RedisNonceStore`, `RedisEnrollmentStore`, `RedisSpendingLedger`; ioredis). Not yet published.
  - Python: `aroha.stores.postgres` and `aroha.stores.redis` (released in PyPI `aroha` 2.1.0, below).
  - One table/key layout for both languages: same migration lock, budget expiry (`expires_at_ms` / `expires`) honoured by both, checked by a CI job against Postgres 16 and Redis 7 that fails if any backend test is skipped.

### Fixed

- **`@aroha-sdk/telemetry`:** `TracingArohaClient.send()` added `traceparent` to envelopes after they were signed. `traceparent` is part of the signed envelope, so receivers rejected those envelopes. `send()` now passes signed envelopes through unchanged and adds `traceparent` only to unsigned trusted-mesh envelopes. The new `TracingArohaClient.buildEnvelope(...)` (same arguments as core's `buildEnvelope`) puts the active span's `traceparent` into the envelope before signing. Code that sent signed envelopes through `send()` and relied on tracing should build them with `buildEnvelope()` instead.
- **`@aroha-sdk/registry`:** the `createArohaRegistryServer()` handle's `port` now reports the port actually bound once `listen()` has resolved, so `port: 0` (OS-assigned port) is usable. Before, it echoed the configured value. The package's own tests now bind port 0 instead of fixed ports, which failed with `EADDRINUSE` where that range is reserved (e.g. Windows). Not wire-visible.
- **`@aroha-sdk/delegation` (wire change):** `createDelegationMiddleware` sent mandate-constraint violations with a misspelled `ARHOA_` prefix. They now carry the canonical Appendix A codes (`ArohaErrorCode`): `Aroha_CAPABILITY_NOT_PERMITTED`, `Aroha_ACTION_LIMIT_EXCEEDED`, `Aroha_DATA_ACCESS_VIOLATION`, `Aroha_REVERSIBILITY_VIOLATION`, `Aroha_HUMAN_GATE_REQUIRED`, `Aroha_COMPUTE_LIMIT_EXCEEDED`, `Aroha_SANDBOX_REQUIRED` and `Aroha_DELEGATION_DEPTH_EXCEEDED`. Clients matching the misspelled codes must update. The remaining `ARHOA_*` rejections now have canonical codes too (see Changed).
- **`@aroha-sdk/micro`:** outside dev mode, an agent resolved only its own DID's public key, so every peer's signed envelope was rejected with 401 `Unknown sender DID`, and there was no way to change that. `createAgent` now takes an optional `resolvePublicKey` (core's `PublicKeyResolver`, the same option `ArohaServer` takes) for peers' keys. The agent's own DID still resolves. Without the option, behaviour is unchanged (peers are rejected). Dev mode is unchanged.
- **`@aroha-sdk/trusted-mesh`:** `TrustedMeshClient` called `super()` with no options, so it could not use a plain `http://` mesh endpoint on a non-loopback host or a connection pool. It now takes an optional third argument, `ArohaClientOptions` (`pool`, `allowInsecureHttp`), passed to `ArohaClient` unchanged; `createTrustedZone(...).createClient()` passes it through too. `allowInsecureHttp` stays off by default and the loopback rules are unchanged. Not wire-visible; existing callers are unaffected.
- **examples/quickstart:** `--register` without `AROHA_REGISTRY_URL` fell back to the Aroha-managed registry URL, which is offline. It now exits with an error (exit code 1) asking for the URL of a self-hosted registry, before any network call. Example only; the SDK's default registry resolution is unchanged.
- **`@aroha-sdk/cli`:** `aroha doctor <endpoint>` reported "valid DID document" for any JSON at `/.well-known/aroha-agent.json`. It now checks the document the way core consumes it: `id` must be a DID equal to `AROHA_AGENT_DID` from `.env` (when set), and `verificationMethod` must hold a key `extractPublicKey` accepts (32-byte Ed25519). Failures name the problem (missing `id`, id mismatch, no verification method, no usable key) and exit 1. The passing line is now labelled `DID document`. An `@aroha-sdk/run` manifest (served at that path instead of a DID document) is reported as a warning, not a failure. Endpoints that previously passed with an incomplete document now fail `aroha doctor`.
- **`ArohaReputation.sol`:** `recordOutcome` accepted calls from any address. It is now restricted to the contract `owner` (the deploying address, the same account that `scripts/setup-chain.mjs` and the demo use to record outcomes) and reverts with the existing `Unauthorized()` error for any other caller. Contracts that are already deployed are not affected and keep the old behaviour; redeploy `ArohaReputation` (and point `ArohaRegistry.setReputationOracle` at the new address) to get the check. New Foundry test `test/ArohaReputation.t.sol` (run locally with forge 1.8.5; CI has no Foundry job).
- **`script/Deploy.s.sol`:** the Foundry deploy script never deployed anything. It did not start a broadcast, and it ended in `require(false, ...)` to print the addresses for `setup-chain.mjs`, which deploys through ethers and does not run or parse this script. The revert aborted `forge script ... --broadcast` before any transaction was sent. The script now wraps the deployment in `startBroadcast()`/`stopBroadcast()` (no forge-std dependency) and logs the addresses instead of reverting. Run it with `--private-key` and `--broadcast` (see `docs/contracts/overview.md`). Checked locally against Anvil with forge 1.8.5; CI has no Foundry job.
- **`ArohaReputation.sol` / `scripts/chat-demo.mjs`:** the reputation owner could never be changed, and the chat demo declared `recordOutcome` with 3 parameters (selector `0x45c4a4dd`) while the contract takes 4 (`0xf5a3e22d`), so every on-chain outcome call reverted. The contract adds a two-step ownership transfer (`transferOwnership(newOwner)` by the owner, rejecting `address(0)` with `ZeroAddress()`, then `acceptOwnership()` by the pending owner; events `OwnershipTransferStarted` / `OwnershipTransferred`), and the demo now passes `qualityStars = 0` (unrated). New contract functions require a redeploy; existing deployments keep a fixed owner.
- **`@aroha-sdk/micro`:** the package entry did not export `PublicKeyResolver`, the type of `createAgent`'s `resolvePublicKey` option, so callers had to import it from `@aroha-sdk/core`. It is now re-exported (type-only) from `@aroha-sdk/micro`. Not wire-visible.
- **`@aroha-sdk/cli`:** `aroha doctor` read `.env` line by line and kept quotes, so `AROHA_AGENT_DID="did:aroha:..."` (or single quotes, or a trailing `# comment`) was reported as not matching the served DID document, and an `export `-prefixed or indented line was reported as not set. It now parses `.env` with Node's built-in `util.parseEnv` (the parser behind `node --env-file`). If a key appears twice, the last value now wins (before, the first). The `src/identity.ts` that the provider and `create-app` templates generate had the same problem with `AROHA_PRIVATE_KEY` (a quoted key failed with "must be 64 hex characters"; an `export`-prefixed one was ignored and a new key generated). It now reads each line with `util.parseEnv` too (generated projects require Node ≥22). Not wire-visible.
- **`@aroha-sdk/mcp-bridge` (wire-visible, additive):** the DID document `wrapMcp()` serves at `/.well-known/aroha-agent.json` had no `verificationMethod`, so core's resolver (`extractPublicKey`) could not get the key the bridge signs its replies with, and `aroha doctor` failed it. It is now built with core's `buildDIDDocument`: it adds the bridge's Ed25519 key as `verificationMethod` `<did>#key-1` (the id its envelope proofs already name), with `authentication`, `assertionMethod`, `keyAgreement`, `created`, `updated` and the Ed25519-2020 `@context`. It also adds an `ArohaEndpoint` service entry (`<did>#aroha-endpoint`, pointing at the bridge's endpoint) so core's `extractEndpoint` finds it. Existing fields (`did`, `capabilities`, `endpoint`, `id`) and the existing `ArohaAgent` service entry are unchanged.

## [Python 2.1.0] — 2026-10-28

Release tag: python-v2.1.0 — PyPI `aroha` 2.1.0. Only the Python SDK is released; the npm packages above stay unreleased.

### Added

- **Durable stores:** `aroha.stores.postgres` and `aroha.stores.redis` (nonces, enrollment and the spending ledger, shared between processes and kept across restarts), with the extras `aroha[postgres]` (`psycopg[binary]>=3.1`) and `aroha[redis]` (`redis>=5`). Same table/key layout as the TypeScript stores.
- **`ArohaErrorCode`:** seven mandate-chain admission codes from Appendix A: `NO_MANDATE`, `CHAIN_INVALID`, `UNTRUSTED_ROOT`, `ROOT_KEY_MISMATCH`, `CHAIN_REJECTED`, `SCOPE_UNKNOWN` and `CONTEXT_MISMATCH`.

### Changed

- **PyPI page:** the package description and README now describe the SDK as it is (spending and task mandates, A2A transport, framework bridges); the old text described token-budget model routing. `Repository`, `Documentation`, `Changelog` and `Issues` links point at `ArohaLabs/aroha-protocol` and the live docs.

## [2.0.0] — 2026-10-19

Release tags (the publish workflows act on these):

- npm-v2026.10.19 — batch: every npm package below
- python-v2.0.0 — PyPI `aroha` 2.0.0

npm packages in this release:

- @aroha-sdk/a2a-bridge@2.0.0
- @aroha-sdk/audit@1.4.1
- @aroha-sdk/bbs@0.2.0
- @aroha-sdk/cache@1.2.2
- @aroha-sdk/chaos@1.2.2
- @aroha-sdk/cli@1.3.0
- @aroha-sdk/commerce@1.2.3
- @aroha-sdk/composio-bridge@1.2.3
- @aroha-sdk/core@2.0.0
- @aroha-sdk/credentials@2.0.0
- @aroha-sdk/delegation@0.3.0
- @aroha-sdk/evals@1.2.3
- @aroha-sdk/gmail-mcp@0.1.1
- @aroha-sdk/hermes-bridge@1.2.5
- @aroha-sdk/langchain-bridge@2.0.0
- @aroha-sdk/mcp-bridge@3.0.0
- @aroha-sdk/mcp-guard@0.2.1
- @aroha-sdk/mcp-server@2.0.0
- @aroha-sdk/micro@2.0.0
- @aroha-sdk/openclaw-bridge@2.0.0
- @aroha-sdk/orchestrator@1.4.0
- @aroha-sdk/policy@1.3.1
- @aroha-sdk/preferences@1.2.3
- @aroha-sdk/registry@2.0.0
- @aroha-sdk/reputation@1.4.1
- @aroha-sdk/resilience@1.2.2
- @aroha-sdk/run@2.0.0
- @aroha-sdk/settlement@2.0.0
- @aroha-sdk/telemetry@1.2.3
- @aroha-sdk/trust@0.1.1
- @aroha-sdk/trusted-mesh@2.0.0
- create-aroha-agent@1.3.0

Not released here: the Java SDK (no Maven Central credentials are configured) and the Go module (the repository is private, so a Go tag would not be fetchable).

The notes below describe this release.

### Remediation branch (`fix/audit-remediation`) — summary

High-level summary of the audit remediation work; see the individual commits for detail.

- **Protocol:** mandate-chain verification (including a revocation hook), envelope replay hardening, key recovery.
- **Runtime:** peer-chat taint tracking, safer guard defaults, sealed replies, key export.
- **Docs truth sweep:** licence statements made consistent (first to MIT, then — see the Licence entry below — to Apache-2.0 everywhere when the project was relicensed); status claims (W3C CG, DID method registration, SDK parity, stable release) corrected to match the repository; new [SDK feature matrix](docs/sdks/feature-matrix.md); [docs/trust.md](docs/trust.md) is the canonical status page; package stability tiers and the `@aroha-sdk/mcp-bridge` 2.0.0 migration note in [COMPATIBILITY.md](COMPATIBILITY.md); invented contacts, commands and links removed.
- **CI:** Python, Go and Java SDK test jobs; publish workflows run tests first; internal link checking.
- **Scaffolders:** generated agents keep a stable identity across runs and verify the mandate carried in the envelope body (`credentialToken`); dependency ranges track workspace versions.
- **Licence: relicensed from MIT to Apache-2.0** (2026-10-07) — code, SDKs and specification. `LICENSE` and `spec-public/LICENSE` carry the Apache License 2.0 text, a `NOTICE` file is added, every source header and package manifest says `Apache-2.0`, and every published package ships `LICENSE` and `NOTICE`. Third-party material keeps its own terms in `LICENSES/third-party/` (now including React and Tabler Icons, which are compiled into the runtime binary).
- **Identity:** rotatable inception-based DIDs (`did:aroha:E…`) with a pre-committed next key and a signed Key Event Log; a person principal that controls its agents and can recover or revoke them; migration from legacy `did:aroha:z…` DIDs with a doubly signed linkage. The registry serves Key Event Logs and linkages; the runtime gives each user a person identity with a one-time recovery code and migrates existing agents on startup (`identityMigrate = false` opts out).
- **Packaging:** Java SDK coordinates renamed to `com.aroha-labs:aroha-sdk` (packages `com.arohalabs.*`) — not yet published to Maven Central; CLI telemetry has no built-in endpoint; GTM, launch and pitch material moved to a private repository.
- **Engines:** every package now declares `node >=22`.
- **Security remediation (2026-10-09):** fixes from a full review of controls, hardcoded values and leaks — see [Security remediation](#security-remediation-2026-10-09) below.
- **Release process:** releases are named by per-product tags (`@aroha-sdk/<name>@<version>`, `python-v<version>`, `java-v<version>`, `sdks/go/v<version>`, `runtime-v<version>`); publish workflows act only on their own tags, and the release gate requires this file to mention the exact tag. See [CONTRIBUTING.md → Releasing](CONTRIBUTING.md#releasing).

### Added — spend enforcement and enrollment in the library (usability runs 2–3)

- **`verifyHttpSpendRequest`** (TypeScript and Python): one server call checks the amount, the holder proof, the chain to the pinned customer, every limit on every link (currency, merchants, merchant category, approval threshold, spend and session limits), then charges the running total against every link, keyed by grantor + id, all or nothing; `charge.release()` returns it if the side effect fails. Vectors `test-vectors/http-spend-v1.json`.
- **Enrollment** (`issueEnrollmentChallenge`, `completeEnrollment`, `enrolledDid`, `signEnrollment`; Python `aroha.enrollment`): binds a customer's DID to their account with a single-use, account-bound, expiring challenge signed by the DID's own key for this service. Vectors `test-vectors/enrollment-v1.json`.
- An empty pin (unknown customer) is a 403 `ROOT_NOT_PINNED` refusal, not a thrown error; an explicit `isRevoked: null` no longer warns; `now` governs presentation, nonce and mandate expiry together.
- `@aroha-sdk/credentials/testing`: test-only builders for hostile presentations.
- The `aroha-integrate` skill bundles a runnable example (`examples/invoice-api`: enrollment, separate customer and agent keys, every refusal tested) and per-path proof checklists.

### Added — holder proof for plain HTTP APIs; usability-test fixes

- **`Aroha-Mandate` HTTP header (spec §6.9.2):** an agent presents a mandate to a plain HTTP API with a holder proof — its own signature over method, path and query, body hash, audience, a single-use nonce and a ≤5-minute expiry — so a copied token cannot be used by anyone else. `presentMandateHttp` / `verifyHttpPresentation` / `verifyHttpMandateRequest` in `@aroha-sdk/credentials`, and the same in Python (`aroha.http_mandate`), byte-identical, with shared vectors `test-vectors/http-presentation-v1.json`. `verifyHttpMandateRequest` refuses to run without a pinned root and an explicit revocation choice. Spec §6.9 now also writes down the existing MCP binding.
- **Task mandates are never accepted as spending mandates** in any SDK (a legacy v1 `hybrid` token carrying `constraints` was) — TypeScript, Python, Go, Java.
- **mcp-guard** says why a gated call was refused (declined, dismissed, timed out, client cannot show prompts) instead of always "the human declined", and refuses at once when the client cannot ask.
- **`aroha-integrate` skill** rewritten from a cold-start usability test: list real tool names before writing rules, GitHub and filesystem rules checked against them, a way to prove Path A, the HTTP holder proof in Paths B/C, keys, trust and running totals.

### Added — support gaps closed (see docs/support-matrix.md)

- **Runtime models:** Google Gemini as a hosted provider (streaming, tool calls, thought signatures); any OpenAI-compatible endpoint (`openaiCompatibleBaseUrl`) and a custom local engine URL (`engineUrl`), validated (https, or http to loopback; private and metadata addresses refused). Configurable in the Providers screen. Tested against local stubs, not the live services.
- **MCP server:** enterprise-managed authorization (ID-JAG / Cross App Access) on the resource-server side — the enterprise identity selects the per-user key and is reported as the mandate root; and the MCP Tasks extension for `aroha_call` (per-user scoped, bounded, cancellable).
- **SDK parity:** task mandates in Python, Go and Java; conversation-profile verification and a registry client in Go and Java. Task-mandate vectors `packages/aroha-credentials/test-vectors/task-mandate-v2.json` and `task-mandate-v2-cases.json`, generated from TypeScript, plus live interop in both directions for each language.
- **Python framework bridges** (LangChain/LangGraph, CrewAI, AutoGen, Google ADK, OpenAI / Agents SDK) are now tested against the real frameworks, which exposed and fixed bugs that made several unusable: the AutoGen bridge could not be imported, the Google ADK bridge failed on every new session, the async OpenAI path was never awaited, a CrewAI crew never received the message, and LangChain tools hid their input schema. Optional extras per framework in `pyproject.toml`. AutoGen support is autogen-core 0.4+.
- **A2A:** CI interop with the official `@a2a-js/sdk` in both directions; `GetTask` / `CancelTask`.

### Fixed

- **Python `ArohaAgent` session memory is partitioned by caller.** History was keyed by the client-chosen session id alone, so a second caller reusing an id could read the first caller's conversation. Now keyed by the verified DID (aroha-sig) or a digest of the bearer token.
- **Python `hub.list_agents`** raised on every real response (the registry returns a bare array); both shapes are accepted.
- **A2A bridge, spec conformance (A2A 1.0):** agent-card signatures use the §8.4.1 canonical form (old-form signatures still verify); streaming and push methods answer "unsupported operation" (-32004 / -32003) instead of "method not found"; `returnImmediately` accepted alongside the deprecated `blocking`. **Behaviour change:** a request without an `A2A-Version` header now gets -32009 (a missing header means 0.3 under §3.6.2); the bridge's own client always sends it.
- **LangChain bridge:** capability ids longer than 64 characters produce valid OpenAI tool names; empty ids and non-object schemas are refused. The AutoGen / Semantic Kernel claim is reworded to "OpenAI function-tool compatible", which is what is tested.

### Changed — runtime asks before tools it cannot vouch for; standing permissions

- **Local MCP tools now ask first** unless Aroha can vouch for them (a known-safe read: a tier ≤ 2, fully reversible taxonomy entry, or the local server's own read-only declaration). Remote tools already asked. Set `mcpAskBeforeLocalTools = false` in `config.toml` to restore running local tools without asking. **Behaviour change on upgrade:** an install that relied on local tools running unasked will see approval prompts, and a run with nobody to answer (a peer's consult) refuses those tools.
- **Approving a call no longer silently remembers it.** A "yes" used to become a permanent, invisible allow for a remote tool (`mcp/<server>/trust.json`). The approval card now offers *just this time* (default), *for this conversation*, *for the next 24 hours* or *always (a year)*, optionally at most N times. A kept answer is a **standing permission**: a task mandate signed with the agent controller's person key, verified against that person's current key before every use, with the use limit enforced as signed `actionLimits` (`apps/aroha-runtime/src/host/permissions.ts`).
- A standing permission answers only the "Aroha cannot vouch for this tool" prompt. It never answers an operator's always-ask rule or a call shaped by content the agent has just read, is never used for a room guest's turn, a peer's run or another person on the install, and cannot be saved for a payment.
- **Settings → Permissions** lists what each of your agents may do without asking, with a Revoke button on every line (`GET /v1/permissions`, `DELETE /v1/permissions/:slug/:mandateId`). Approvals remembered in `trust.json` before this change are still honoured, listed as legacy and revocable by an admin; no new ones are written.
- Audit log: `permission_granted` and `permission_revoked`.

### Added — remote MCP connector (MCP 2026-07-28)

- **`@aroha-sdk/mcp-server`: remote connector.** `--http` (or `AROHA_MCP_TRANSPORT=http`) serves Streamable HTTP on MCP revision 2026-07-28 through `@modelcontextprotocol/server` 2.3.1 (`server/discover`, Multi Round-Trip Requests, `Mcp-Method`/`Mcp-Name`, `ttlMs`/`cacheScope`; stateless fallback for 2025-era clients), as an OAuth 2.1 protected resource: RFC 9728 metadata, `WWW-Authenticate` with `resource_metadata` on `401`, audience-bound JWT validation against the issuer's JWKS (pluggable verifier), no token passthrough, Client ID Metadata Document client ids (no Dynamic Client Registration; optional allowlist). Binds `127.0.0.1` by default. Configuration by environment or an `AROHA_MCP_CONFIG` JSON file. Guide: [docs/integrations/remote-mcp-connector.md](docs/integrations/remote-mcp-connector.md).
- **`@aroha-sdk/mcp-server`: one signing key per user.** Each token subject gets its own Ed25519 key from a pluggable `PrincipalKeyStore` (default: one `0600` file per user); stdio keeps the existing per-install key.
- **`@aroha-sdk/mcp-server`: new tools** `verify_mandate` (governed profile when configured), `revoke_mandate`, `check_revocation_status` (signed answers only, needs `AROHA_MCP_REGISTRY_KEYS`), `verify_receipt`, `lookup_kel`. `aroha_call` takes a `mandateToken`, verifies the agent's response envelope, forwards `traceparent` and returns a signed action receipt.
- **`@aroha-sdk/mcp-server`: approvals by MRTR.** Mandate issuance and spending calls answer `input_required` with an approval form; approval and mandate ids travel in an HMAC `requestState` bound to the user and method (`AROHA_MCP_APPROVAL_TOOLS`, `AROHA_MCP_STATE_KEY`).
- **`@aroha-sdk/mcp-server`: outbound endpoint vetting.** Registry-supplied agent endpoints are refused when any resolved address is private, loopback, link-local or reserved (`AROHA_ALLOW_PRIVATE_ENDPOINTS=1` for development); the connection is pinned to the checked address, redirects are refused, bodies capped, and bodies of failed or unverifiable responses are no longer returned to the caller.
- **`@aroha-sdk/mcp-guard`: MRTR human gates.** Calls from 2026-07-28 clients are gated with `input_required` and a signed `requestState` (approval id, tool, argument hash); older clients keep server-initiated elicitation. A tool whose definition changed since it was first seen needs re-approval, and an expired `ttlMs` tool list is refreshed before a call is decided. New `GuardSession` export; `AROHA_GUARD_STATE_KEY`.
- **`@aroha-sdk/mcp-bridge`: MCP on the wire.** `wrapMcp({ mcp: {} })` also serves the wrapped tools as a Streamable HTTP MCP server behind the same mandate gate. Over MCP the mandate travels in `_meta["aroha/mandate"]` with a holder proof bound to the agent, tool, arguments and a single-use nonce (`presentMandate()` / `verifyPresentation()`). The README no longer claims an `x-aroha-mandate` header, which no code reads.

### Changed — MCP packages

- **`@aroha-sdk/mcp-server`:** depends on `@modelcontextprotocol/server` 2.x instead of `@modelcontextprotocol/sdk` 1.x; the `aroha-mcp-server` binary is now `dist/cli.js`, and importing the package no longer starts a server (it exports the building blocks). `aroha_call` now verifies agent response envelopes by default (`AROHA_MCP_VERIFY_RESPONSES=0` disables it for development).

### Versions in this release

Release tags (each must appear here for `release-gate.yml`):

- @aroha-sdk/core@2.0.0
- @aroha-sdk/credentials@2.0.0
- @aroha-sdk/registry@2.0.0
- @aroha-sdk/mcp-bridge@3.0.0
- @aroha-sdk/trusted-mesh@2.0.0
- @aroha-sdk/a2a-bridge@2.0.0
- @aroha-sdk/delegation@0.3.0
- @aroha-sdk/run@2.0.0
- @aroha-sdk/micro@2.0.0
- @aroha-sdk/mcp-server@2.0.0
- @aroha-sdk/langchain-bridge@2.0.0
- @aroha-sdk/settlement@2.0.0
- @aroha-sdk/orchestrator@1.4.0
- @aroha-sdk/bbs@0.2.0
- @aroha-sdk/openclaw-bridge@2.0.0
- @aroha-sdk/chaos@1.2.2
- @aroha-sdk/cli@1.3.0
- create-aroha-agent@1.3.0
- python-v2.0.0
- runtime-v0.2.0

Not released in this cycle: the Java SDK stays at 1.0.0 (unpublished; its changes ship when a
`java-v*` tag is cut), and the Go module has no version tag yet.

### Breaking

- **`@aroha-sdk/credentials` 2.0.0 — mandate token v2.**
  - Every issuing function now produces **v2 tokens**: the signature covers the RFC 8785 (JCS)
    canonicalisation of `{ mandate, v: 2 }`, and the token carries its signed ancestry
    (`chain`, root first). Verifiers built on older releases cannot verify v2 tokens; legacy v1
    tokens still verify, but a v1 child (non-root) token can no longer be attenuated.
  - `issuedAt` is **required** on every mandate body.
  - `chainVerified` semantics: `verifyMandate` returns `chainVerified: true` only when every link
    back to a root intent mandate verified. A v1 child token yields `valid: true,
    chainVerified: false` — it proves only that its immediate grantor signed it. Gate money on
    `verifyMandateChain` (with `expectedRoot`), or on `enforceSpendingConstraints(…, { requireChain: true })`,
    never on `valid` alone.
  - A mandate is identified by **(grantor, mandateId)**, not the bare id, which its minter chooses.
    `MandateRevocationCheck` is now `(mandateId, grantor) => Promise<boolean>`, and every
    `RedemptionStore` total is keyed by `mandateRedemptionKey(mandate)` (`<grantor>#<mandateId>`) —
    read totals back with `store.redeemedMicros(mandateRedemptionKey(mandate))`. The registry's
    `GET /v1/mandates/:id/revoked` and `…/redemptions` require `?grantor=`.
  - **Omitted limits inherit, and omission is no longer widening.** `attenuateToCart` /
    `attenuateToPayment` copy `sessionLimitUsd`, `requireHumanApprovalAboveUsd`, `validFrom`,
    `validUntil` and `currency` from the parent when the caller omits them; verifiers reject a
    child that omits a limit its parent sets. Callers that relied on omission meaning "no limit"
    get narrower children (or a rejection) instead.
  - Spec: [Aroha 1.0 §6.5](docs/spec/aroha-1.0.md#65-spending-mandate-token-format-v2); vectors:
    `packages/aroha-credentials/test-vectors/mandate-v2.json`.
- **`@aroha-sdk/core` 2.0.0 — `validateEnvelope`.**
  - Envelopes whose lifetime (`expires - created`) exceeds **5 minutes** are rejected (option
    `maxTtlMs`); `created` more than 30 s in the future is rejected; unparseable timestamps are
    rejected; the proof's `verificationMethod` must belong to `from`.
  - The **signature is verified before the nonce store** is consulted, and nonces are keyed
    **per sender** (`<from>:<nonce>`). Custom `NonceStore` implementations see the new key shape.
  - `revokeKey` no longer makes the replacement key trusted immediately.
  - **Key Event Logs and E-DIDs added:** rotatable `did:aroha:E…` identifiers, person
    controllers, recovery, revocation and z→E migration linkages (`@aroha-sdk/core/identity`).
    Additive for most callers, but mandate verifiers given a `kelSource` now fail closed on a
    missing, stale or forked log.
- **`@aroha-sdk/registry` 2.0.0 — subpath exports.** The
  on-chain contract client, the IPFS helpers and the registry server are not exported from the
  package root; import them from `@aroha-sdk/registry/contract`, `/ipfs` and `/server`
  (`/discover`, `/sar` and `/personal-name` are also available as subpaths).
- **`@aroha-sdk/delegation` 0.3.0 — deprecated alias removed.**
  The task-mandate chain verifier is `verifyTaskMandateChain`; the old `verifyMandateChain` alias
  (which clashed with the spending-mandate `verifyMandateChain` in `@aroha-sdk/credentials`) is
  gone.
- **`@aroha-sdk/mcp-bridge` 3.0.0 — mandate gate.** With
  `requireMandate: true`, the bridge requires a configured root policy (`expectedRoot`,
  `trustedRoots` or `requirePersonRoot`), verifies the whole chain, honours `isRevoked`, and
  redeems priced calls through a `redemption` store; a mandate merely signed by a resolvable key
  is no longer enough.
- **`@aroha-sdk/trusted-mesh` 2.0.0** — a signature is skipped only for an allow-listed DID whose
  request arrives over a trusted network (loopback by default; `trustedNetworks` CIDR ranges,
  optional `isTrustedTransport`). `createTrustedMeshOptions(…)` now returns
  `bypassSignatureForRequest` instead of the DID-only `bypassSignatureFor`.
- **`@aroha-sdk/a2a-bridge` 2.0.0** — A2A 1.0 wire shapes
  (JSON-RPC `SendMessage`, `ROLE_USER` / `ROLE_AGENT`, `metadata["aroha.mandate"]`); 1.x message
  shapes are only accepted on input by `a2aToAroha`. See its README.
- **Java SDK** (unreleased; 1.0.0 on disk) — groupId `com.aroha-labs`, Java packages `com.arohalabs.*`
  (previously `io.aroha`). Update imports and dependency coordinates.
- **Python SDK 2.0.0, Go and Java SDKs** — mandate wire format v2 (with chain
  verification), the envelope rules above and E-DID / Key Event Log verification, matching the
  TypeScript reference and its test vectors. Mandates they issue are v2; code that built or
  parsed v1 mandate objects must be updated. `did:aroha-web` in these SDKs still follows the
  earlier schema. See [docs/sdks/feature-matrix.md](docs/sdks/feature-matrix.md).
- **`@aroha-sdk/cli` 1.3.0 / `create-aroha-agent` 1.3.0 — telemetry endpoint removed.** The CLI has
  no built-in telemetry destination and no longer prompts at startup; `aroha telemetry`
  explains this, and telemetry exists only when `AROHA_TELEMETRY_ENDPOINT` is set. Scaffolded
  providers now read `AROHA_MANDATE_ROOT_DID` and verify the full mandate chain; a leftover
  `AROHA_MANDATE_ISSUER_PUBLIC_KEY` stops the scaffolded agent at startup.
- **Runtime 0.2.0** — **identity migration**: on first boot, agents with
  legacy `did:aroha:z…` DIDs move to rotatable E-DIDs, which changes each agent's DID and personal
  name (the old DID is kept as an alias, with a doubly signed linkage). Peers that pinned an old
  DID must re-trust the new one.
- **Runtime peer protocol — sealed replies.** Replies between runtimes are sealed to the peer;
  a runtime on an older release cannot read them (see "Upgrading the runtime").

### Security remediation (2026-10-09)

Fixes from a full review of controls, hardcoded values and leaks. Breaking changes are listed per
product; everything else is hardening that keeps existing callers working.

**Breaking**

- **`@aroha-sdk/core` 2.0.0**
  - `ArohaClient` refuses `http://`/`ws://` to non-loopback hosts unless `allowInsecureHttp`. New `@aroha-sdk/core/endpoints`: `assertSecureEndpoint`, `AROHA_MANAGED_REGISTRY_URL`, `AROHA_DEFAULT_IPFS_GATEWAY`, `resolveRegistryUrl`, `resolveIpfsGateway`.
  - `ArohaServer` binds `127.0.0.1` by default (`host` option; LAN listeners pass `"0.0.0.0"`) and sets Node server timeouts.
  - `bypassSignatureFor` throws unless `bypassSignatureForRequest` is also set, and both must agree.
  - `validateEnvelope` rejects nonces over 128 characters; `MapNonceStore` is bounded (`maxEntries`); `NonceRegistry.check` shares the async store and throws with a custom store.
  - `did:aroha-web`: hostname and path validated, no redirects, 64 KiB document cap, system DNS used by default on Node.
  - `ArohaDisputeResolutionBody` requires `purpose`, `arbiterDid` and `issuedAt`.
  - New `ArohaServerOptions.beforeRequest(req)` admission hook: runs before the body is read for every HTTP request; a returned `{ status, body?, headers? }` is sent and processing stops; a throwing hook fails closed with 500. `FileNonceStore` (package root) writes its file `0600`.
- **`@aroha-sdk/credentials` 2.0.0**
  - `MandateRevocationCheck` is `(mandateId, grantor)`; redemption totals are keyed by `mandateRedemptionKey(mandate)` (`<grantor>#<mandateId>`).
  - `attenuateTaskMandate` treats an omitted parent constraint as widening; new `checkTaskNarrowing` and `checkTaskMandateShape`.
  - Credential registry routes and the RBAC credential path fail closed without `resolveIssuerPublicKey` (`allowUnverifiedCredentials` for tests); unknown roles are rejected.
  - Registry clients require an https `registryUrl` outside loopback.
- **`@aroha-sdk/delegation` 0.3.0** — `verifyTaskMandateChain` enforces full narrowing on every link; `parseTaskMandateToken` throws `TaskMandateTokenError`; `serveDelegated` and `createDelegationMiddleware` require `trustAnchors` or `resolveRootKey` (`allowUnpinnedRoot` for development).
- **`@aroha-sdk/run` 2.0.0** — `serve()` defaults to `auth: "aroha-sig"`, binds `127.0.0.1`, sends no CORS headers unless `cors: { origins }`, and caps bodies at 1 MiB; callers refuse non-https registry-supplied endpoints; `register()` requires `did`, `manifestCID` and a signer.
- **`@aroha-sdk/registry` 2.0.0** — `AROHA_MANAGED_REGISTRY_URL` is `https://aroha-registry.aroha-labs.workers.dev`; `ArohaHttpRegistry.register()` requires `options.signer` and proves key possession; `createArohaRegistryServer` binds `127.0.0.1` and requires `apiKey` off loopback.
- **`@aroha-sdk/micro` 2.0.0** — `devMode` defaults to false; new `endpoint` (or `AGENT_ENDPOINT`) and `host` options.
- **`@aroha-sdk/mcp-server` 2.0.0** — per-install Ed25519 identity (`AROHA_MCP_IDENTITY_DIR`), signed envelopes and mandate tokens, https-only endpoints.
- **`@aroha-sdk/mcp-bridge` 3.0.0** — `wrapMcp` binds `127.0.0.1` by default and caps bodies at 1 MiB before authentication.
- **`@aroha-sdk/langchain-bridge` 2.0.0** — throws when the agent DID cannot be determined (`opts.agentDID`); https-only outside loopback.
- **`@aroha-sdk/openclaw-bridge` 2.0.0** — `openClawSkillToArohaHandler(skill, { agentDID, agentPrivateKey })` requires the serving identity and throws without it; every `ArohaResponse` and `ArohaError` reply is a signed envelope from `agentDID` (replies were previously unsigned).
- **`@aroha-sdk/settlement` 2.0.0** — Stripe, Postgres and AP2 settlement throw without `acknowledgeAlpha: true`; `WalletService` requires `mode` and receipts carry `simulated`; `resolveDispute` requires the new signed fields and applies one resolution per saga. New `requireMandate` wrapper.
- **`@aroha-sdk/bbs` 0.2.0** — `ProveOptions.unsafeRandomScalars` removed.
- **Registry service**
  - `POST /v1/agents` requires a signed challenge for every DID except `did:aroha:E…`, and a `did:aroha:z…` must be registered with the key it encodes.
  - Capabilities are indexed only from a CID-verified raw manifest block.
  - `POST /v1/signals` is admin-only; `GET /v1/grants/check` requires a key and answers only parties to the grant.
  - Admin routes answer 503 when `ADMIN_SECRET` is unset or shorter than 32 characters.
  - Bodies over 64 KiB get 413 (256 KiB for KEL, linkage and SAR).
  - Relay-connect proofs are single-use.
  - Credential JWTs are signed with a newly derived key, so earlier tokens no longer verify.
  - Migration `017` adds relay-proof storage and scopes `redemptionId` per mandate.
  - New required secret `REGISTRY_SIGNING_KEY` (32-byte Ed25519 seed, hex or base64url). Without it, `GET /v1/mandates/:id/revoked`, `POST /v1/audit-anchors` and `/.well-known/aroha-registry-keys.json` answer 503; there is no fallback key.
  - `GET /v1/mandates/:id/revoked` answers are signed: new `checkedAt`, `statusSignature` (Ed25519 over JCS of `{ purpose: "aroha.revocation-status/v1", mandateId, grantor, revoked, revokedAt?, checkedAt }`) and `statusKeyId`.
  - `POST /v1/spending/budgets` takes the mandate `token` instead of `limitUsd`. The limit is now min(spendLimitUsd, sessionLimitUsd) of the verified leaf, the expiry is the chain's earliest, and budgets are keyed by `<grantor>#<mandateId>`. `allocate` and `release` require `grantor`, and `status` requires `?grantor=`. Budgets created before migration `018` are not served; re-create them with the token.
  - Migration `018` adds `audit_anchors`, plus `spending_budgets.limit_source` and `chain_keys`.
- **Python SDK 2.0.0** — `is_revoked(mandate_id, grantor)`; dev mode and `skip_signature` refused unless `AROHA_DEV_MODE=1`; clients refuse `http://` off loopback; servers default to `auth="aroha-sig"`, no CORS and `127.0.0.1`; `encrypt_body` is ECDH-ES+A256GCM compatible with `@aroha-sdk/core` and no longer emits its key; `aroha.web_did` is a port of the TypeScript resolver; `register_agent` proves key possession.
- **Go and Java SDKs (unreleased)** — revocation hook takes `(mandateId, grantor)`; dev mode gated on `AROHA_DEV_MODE=1`; https-only clients; loopback bind and 1 MiB body cap; Java `Encryption` now interoperates with `@aroha-sdk/core`; both `did:aroha-web` APIs replaced by ports of the TypeScript resolver.
- **Bridge agents (`agents/*`, private)** — every agent needs `AGENT_ENDPOINT` unless `NODE_ENV=development`; bridges refuse reservations until `AROHA_PEER_CAPABILITIES` grants the peer; the personal-agent control API moved to port 3090, binds `127.0.0.1` and requires `AROHA_PERSONAL_API_TOKEN`.
- **`@aroha-sdk/credentials` — task-mandate v2** — `issueTaskMandate`/`attenuateTaskMandate` issue `{ v: 2, mandate, signature }` tokens signed over JCS of `{ mandate, purpose: "aroha.task-mandate/v2", v: 2 }` (`taskMandateSigningPayloadV2`, `TASK_MANDATE_PURPOSE`); v1 tokens still verify. A verifier older than this release rejects v2 task tokens. `enforceTaskConstraints` now enforces `dataAccess` (new `dataAccess` request field; `DATA_ACCESS_VIOLATION`) and accepts `humanApproved` and `isRevoked`; new `checkTaskConstraints`, `assertTaskConstraints`, `checkTaskDataAccess`, `verifyTaskMandateSignature`, `checkTaskRevocation`, `createKelLookup`.
- **`@aroha-sdk/delegation`**
  - `verifyTaskMandateChain` caps chains at 8 links by default (`maxDepth`, `DEFAULT_TASK_CHAIN_MAX_DEPTH`) even when no `maxDelegationDepth` is set, and accepts `isRevoked` (every link, fail closed) and `kelSource`/`kelStore` (E-DID grantors checked against their current key; revoked identities refused).
  - `createDelegationMiddleware` enforces the leaf mandate's constraints before the handler: by default the request body's `capability` must be allowed and not blocked, within `actionLimits`, reversible under `reversibleOnly` and not human-gated; an envelope with no determinable capability gets 403 `ARHOA_SCOPE_UNKNOWN`. `requestScope` adds `dataAccess`, reversibility and approval.
  - `serveDelegated`: new `requestScope` enforces the same before the handler (400). `ctx.assertCapability(cap, opts?)` now also enforces `actionLimits`, `reversibleOnly` (unknown reversibility counts as irreversible), `humanGates` (only an `approve` decision opens one) and `dataAccess`; new `ctx.assertDataAccess`. `ctx.delegate` refuses to grow a chain past `maxDepth`. New `isRevoked`, `kelSource`, `kelStore`, `maxDepth` options.
- **`@aroha-sdk/mcp-bridge`** — `wrapMcp().start()` refuses when any tool has a price above zero and `requireMandate` is off (the price was advertised and never charged); set `allowUnchargedPricing: true` only when payment is collected elsewhere.

**Security**

- **Runtime**
  - 1 MiB JSON body cap (`uploadMaxBytes` for documents).
  - Hash-based CSP, plus frame, COOP/CORP and Permissions-Policy headers.
  - `config.toml` is `0600`; the registry API key, MCP OAuth secret and MCP environment values move into the OS keystore. The plaintext fallback is opt-in via `allowPlaintextCredentials`.
  - Audit coverage for library, skills, memory, threads, publishing, CLI admin and key export/import; a signed CLI journal; checkpoints every 100 entries, every 5 minutes and at shutdown.
  - Approvals can be answered only by the person they were shown to; OIDC allow-lists (`oidcAllowedDomains`, `oidcAllowedSubjects`); `?token=` honoured only on page loads.
  - One outbound-URL rule for registry, peer and hub endpoints.
  - LAN per-IP rate limit, persistent replay protection and bounded turns; `aroha kel duplicity list|clear`.
  - `/v1/admin/status` reports `kelIntake` (`foreignCapRefusals`, `maxForeignStored`, quarantine size) while the LAN listener runs.
  - `AROHA_ADDON_DEV` is ignored in release builds.
  - Revocation reaches live sessions. The LAN listener, the relay connection and peer chat check the agent's current status on every inbound request, so a revoked, orphaned, moved or deleted agent stops answering at once, without a restart. A revoked agent is no longer advertised on the LAN, and its relay connection closes.
  - Before acting on an inbound action, the runtime refreshes the peer's key event log from the registry when the cached copy is older than `peerKelMaxAgeSeconds` (default 600). It refuses the action when the registry reports `controllerRevoked` or serves a newer revoked log. Once a revocation is seen, every capability refuses that peer. Consults and chat still run on the cached log. An unreachable registry does not block actions.
  - The operator kill switch now survives a restart. It is saved to `kill-switch.json` (`0600`) in the workspace, the startup banner reports it, and `/v1/admin/status` shows it as `killSwitch` with the time it was set and who set it.
  - The kill switch has four states: `running`, `throttled`, `paused` and `stopped`. Read or set it with `GET`/`POST /v1/admin/kill-switch` (`{ mode, throttlePerMinute?, reason? }`). Every change is audited (`admin_consults_toggled` with `detail.mode`) and kept in `kill-switch.json`. The startup banner reports any state other than `running`, and `/v1/admin/status` reports `killSwitchMode`.
    - `throttled` admits at most `throttlePerMinute` requests (default 30) in any rolling minute. The limit is shared by inbound consults, actions, chat and invitations and by this install's outbound actions. Requests above it are refused as retryable `CapacityExceeded` with a retry-after.
    - `paused` refuses inbound actions and this install's own outbound actions: peer action requests and consequential MCP tool calls. Consults and chat still answer.
    - `stopped` refuses all of these. It is what `/v1/admin/consults/disable` sets. A cancel of an outbound request is always allowed.
    - A state file without `mode` is read from `consultsDisabled`, and `consultsDisabled: true` always reads as `stopped`.
  - Receipts for denied actions. The refusing agent signs an `aroha.action-receipt/v2` receipt with `outcome: "denied"` and the reason when it refuses one of these:
    - an inbound action on the LAN or relay, because of the kill switch, policy, a receipt, a missing approval, a mandate, peer freshness or the taint rule;
    - a consequential MCP tool call that the guard, a person or the kill switch refused;
    - an outbound peer action that the kill switch refused.

    The receipt hash and the receipt are recorded in the audit trail as `action_refused` with `detail.kind: "denied_receipt"`. Inbound requesters receive the receipt in `details.receipt` of the error. An execution failure (`InternalError`) is not treated as a denial.
  - Receipts carry `traceparent` when the request envelope had one. Outbound peer actions and consults now start a W3C trace, which is carried on the envelope and recorded in the receipt.
  - Per-hop disclosure (EU AI Act Art. 50). Every request and reply envelope the runtime sends carries an `ArohaDisclosure`, signed with the envelope: the agent DID, its controlling person as principal, the purpose, and the hop. The hop is 0 when the agent's own principal asked, and the peer's hop + 1 on replies.
    - Agents on a legacy DID with no controller send no disclosure rather than an invented one.
    - An inbound disclosure must be well formed and name the sender. Otherwise the request is refused and audited as `envelope_rejected`. A valid disclosure is recorded as `envelope_received` with `detail.kind: "disclosure"`.
  - Evidence preservation. `POST /v1/admin/evidence` snapshots the following into a bundle (`aroha.evidence-bundle/v1`) signed by the install key:
    - the audit trail and its verification result;
    - SHA-256 hashes of every file in `logs/`;
    - the witnessed anchors;
    - the kill-switch state;
    - an index of receipt hashes.

    A copy is written to `<workspace>/evidence/` (`0600`), and the export is audited. Verify a bundle with `verifyEvidenceBundle` (host/admin.ts).
  - Signed action receipts. `@aroha-sdk/core` adds `ArohaActionReceipt` (`aroha.action-receipt/v1`, Ed25519 over JCS), which records the taint flag, provenance, approver and mandate.
    - The acting agent's key signs a receipt for every gated or non-low-risk MCP tool call and every outbound peer action. The receipt hash goes into the audit trail.
    - Outbound action requests carry the receipt as params `receipt`. Inbound requests verify it against the caller's key and the request. A receipt that fails verification is refused.
    - `requireUntaintedOrApproved` (default `false`) refuses inbound actions that have no receipt, or whose receipt is tainted with no approval.
  - External audit anchoring. When `auditAnchorUrl` is set (default: off), each signed head checkpoint is sent to a registry witness through a retry outbox. The witnessed anchors are kept in `logs/audit-anchors.jsonl` (`0600`) and pulled back at startup.
    - Audit-trail verification now fails when a witnessed anchor is beyond the log head (tail truncation) or its hash no longer matches the log (rewrite). Witness signatures are checked against a cached key file, so verification also works offline.
    - `/v1/admin/status` shows `auditAnchors.lastAnchoredSeq`.
    - With both `auditAnchorUrl` and `refuseStartOnAuditFailure` set, a gated or consequential action is refused when its audit record cannot be written.
- **Registry service — signing and witness**
  - `/.well-known/aroha-registry-keys.json` publishes the registry keys (`keyId` is the first 16 hex characters of SHA-256 of the public key). `REGISTRY_SIGNING_KEY_PREVIOUS` stays published as `retired` after a rotation.
  - `POST /v1/audit-anchors` acts as an external witness for runtime audit heads. It verifies the install's live-head checkpoint signature (`did:aroha:z…` only), accepts only increasing `seq` values, chains each anchor with `prevAnchorHash` and countersigns it. Rate limits apply per IP and per install. Anchors are permanent and are not pruned by retention.
  - `GET /v1/audit-anchors/:installDid` returns the signed anchors, paged.
  - Spending-budget creation and every allocation are written to the admin audit log. `allocate` answers 410 `MANDATE_REVOKED` once any link of the budget's chain is revoked at the registry.
- **Registry service — Shared Signals, client metadata and agent tier** (migration 019; run `node scripts/migrate.mjs --remote` before deploying)
  - OpenID Shared Signals transmitter. `/.well-known/ssf-configuration` and `/.well-known/jwks.json` publish the transmitter. Receivers holding an API key manage streams through `/v1/ssf/streams`, `/v1/ssf/status` and `/v1/ssf/verify`. Delivery is push (RFC 8935) or poll (`/v1/ssf/poll/:streamId`, RFC 8936).
    - A new mandate revocation emits CAEP `session-revoked` and Aroha `mandate-revoked`.
    - A KEL revocation that `POST /v1/kel/:did` newly accepts emits CAEP `credential-change` (`credential_type: aroha-did-key`) and Aroha `did-revoked`, for the DID and for each registered agent that person controls.
    - An event about a registered agent reaches a stream only if that stream's API key could see the agent with a GET: the agent is public, or the key owns it or holds a live grant. Unlisted agents are treated like private ones here. The registry checks this when it queues the event, and again before every push retry and every poll.
    - Events are SETs signed with `REGISTRY_SIGNING_KEY` (EdDSA). Each is queued in a durable D1 outbox and pushed within the request, with a 5 s timeout per attempt. The hourly cron retries failed pushes with backoff, up to 10 attempts. Outbox rows are pruned after 30 days.
  - `GET /v1/agents/:didHash/client-metadata.json` serves an OAuth Client ID Metadata Document (draft -02) per agent. Its URL is usable as an OAuth `client_id`. It uses `private_key_jwt` and a `jwks_uri` (`/v1/agents/:didHash/jwks.json`) that follows key rotation, with E-DID keys read from the verified KEL.
  - `GET /v1/agents/:didHash/monitoring` returns a signed summary (`aroha.agent-monitoring/v1`). It holds registry-recorded counts (revocations, rotated keys, KEL events, duplicity, linkage conflicts, attestations), `lastSeenAt` and a certification tier (`unverified` | `domain_verified` | `kel_person_rooted` | `audited`) with the facts it was derived from. It is not a reputation claim. Operators record or clear an audit with `POST /v1/agents/:didHash/audited` (admin secret, written to the admin audit log).
  - Registry keys now list the purposes `ssf-set` and `agent-monitoring`.
- **`@aroha-sdk/credentials`** — `httpRevocationCheck({ registryKeys })` verifies the signed revocation status: signature, the mandate and grantor it names, and freshness (`maxStatusAgeMs`, default 60 s). An unsigned or invalid answer throws `RevocationStatusVerificationError` even with `failOpen`. Without `registryKeys`, unsigned answers are still accepted, but pinning the keys is recommended. New exports: `revocationStatusPayload`, `REVOCATION_STATUS_PURPOSE` and `registryKeyId`.
- **Registry service** — constant-time admin comparison; private agents hidden on credential, revoked-key, analytics and relay-status routes; relay limits charged to the authenticated key; atomic invite redemption and key rotation; deactivated agents' caller signatures refused; clamped `limit`/`offset` and per-IP limits on expensive routes; `/health` no longer returns database errors; hourly retention job; `migrate.mjs` probes every column and stamps each file as it succeeds.
- **Bridge agents**
  - Stripe validates amount, currency and ids before creating a PaymentIntent and sends an `Idempotency-Key` on every write.
  - Stripe refuses commits above `STRIPE_APPROVAL_THRESHOLD_CENTS` (default $100) with `Aroha_HUMAN_GATE_REQUIRED`, and caps each payment at `STRIPE_MAX_AMOUNT_CENTS` (default $500).
  - Salesforce escapes every SOQL literal; GitHub merges are human-gated; Jira searches can be project-scoped.
  - Reservation tokens are 128-bit and bound to the reserving DID; upstream errors are mapped to generic codes.
- **CI and release** — every publish runs the release gate first on the same commit, in the `release` environment; npm 403/404 fails the job; actions pinned to commit SHAs; Dependabot; an `npm audit` job; installers fail closed without checksums; runtime releases carry a CycloneDX SBOM.
- **Documentation** — compliance, governance, hardening and incident-response documents state which controls are enforced and which are manual or unsupported on the repository's current plan; new [key-management runbook](docs/security/key-management.md); local paths and deployment identifiers removed.
- **`@aroha-sdk/credentials` — governed verifier profile** — new `governedVerification({ kelSource, isRevoked, expectedRoot | expectedRootPerson | trustedRoots })` returns options with person root, KEL, revocation and `requireChain` all on, and throws `GovernedProfileError` when a prerequisite is missing. `verifyMandateChain`, `verifyMandate` and `enforceSpendingConstraints` accept it unchanged and fail any verification whose `governed: true` options lack one of those prerequisites. New `trustedRoots` option on all three; `verifyMandate`/`enforceSpendingConstraints` now honour `kelSource`, `requirePersonRoot` and `expectedRootPerson`. `verifyMandateChain` logs a one-time warning when called without `isRevoked` (defaults otherwise unchanged).
- **`@aroha-sdk/mcp-bridge` — governed mode and outbound checks** — `wrapMcp({ governed: true })` forces `requireMandate`, verifies chains with `governedVerification()`, and refuses to start without `isRevoked`, `kelSource`, a root pin (`expectedRoot`/`trustedRoots`) and a durable `redemption` store (an `InMemoryRedemptionStore` is refused). `arohaAgentToMcpTools(..., options)` can attach a mandate to each request (`mandateToken`) and verifies every response envelope's signer, recipient, expiry, nonce and correlationId when `resolvePublicKey` is given (`verifyResponse`).
- **`@aroha-sdk/a2a-bridge` — inbound mandates verified** — new `verifyA2aMandate(message, policy)` and `a2aToArohaVerified(...)` run `verifyMandateChain` (passed in by the caller) with a required root policy and reject unverifiable, untrusted, revoked or over-limit (`proposedAmountUsd`) mandates (`A2AMandateError`). Documentation and the extension description now point to chain verification instead of single-link `verifyMandate`.

**Other fixes**

- **`@aroha-sdk/chaos`** — `FaultInjector` honours `randomSeed`: probabilistic rules draw from a seeded PRNG (mulberry32), so a seed reproduces the same faults; `reset()` rewinds it. Without a seed, `Math.random` is used as before.

### Conversation and memory profile

- **Runtime — authored and addressed turns (step A).** User turns record `authorId`, `authorName`, `authorDid` and `turnOrigin` (host | guest | peer | agent) from the signed-in caller, never from the request body, plus `epoch` and the declared `addressedTo`. Assistant turns record `requesterId`/`requesterDid`, `addresseeDid` and `principalDid`. Non-principal turns reach the model with a structured JSON author label, while `turnOrigin` (not the label) drives enforcement; a guest's turn in history taints the next turn. Every assistant turn is audited as `turn_answered` with the declared addressee. Threads written before this read as the owner's (`GET /v1/threads/:id` returns every turn with an author, and `viewerId`). Both interfaces name the author of a turn the viewer did not write.
- **Runtime — rooms, person invitations and consent (step B).** A thread can have a `Room` (`host/rooms.ts`, stored under `<workspace>/rooms/`): members of kind person or agent with roles host, guest, own, invited or delegated, an `epoch` bumped on every membership change, `historyVisibility: joined`, `invocation: explicit` and `memoryPolicy` fully off by default, and an `ArohaDisclosure`-shaped `disclosure`. The room is signed by the owner's person key (`aroha.room/v1`) when this install holds one; a room file whose signature does not verify reads as absent. Invitations gain `kind: "person"`: never auto-accepted, held pending until the invitee — a named user of this install — accepts as themselves (`POST /v1/invitations/:id/accept|decline`, `GET /v1/invitations`), with an ISO 27560-shaped consent record signed by their person key (`aroha.consent/v1`) and referenced from the `invite_accepted` audit entry. A current member can read the host's thread within their epochs and write turns; guests cannot invite, append raw turns, delete or change settings (403 `host_only`). Guest turns run untrusted with `GUEST_PROVENANCE`: any tool not known to be low-risk is gated, and the approval binds to the host (`approval_not_yours` for the guest); the host lists it at `GET /v1/threads/:id/approvals`. Withdrawing `agent_use_of_messages` (`POST /v1/threads/:id/room/consent`) makes that member's turns display-only from the next request; a guest whose words may not go to a hosted provider is not sent. Under explicit invocation the agent answers only a turn addressed to it (`addressedTo` naming an agent, or an @mention). No personal memory is read or written in a room. Leave, remove, withdraw, expiry and thread deletion end a seat and call the memory cascade. Orchestrated steps now bind their approvals too. Both interfaces can invite a person, accept or decline, list members and leave. Not yet: guests on another install, and OIDC users who are not in `users.json` (the data is keyed by DID so it fits).
- **Runtime — rooms and consent use the core conversation module.** The room file now holds the core `aroha.room/v1` `RoomRecord` fields signed with core `signRoom` and checked on every read with core `verifyRoom` against the host's key event log; an unsigned room is refused when its owner has a resolvable key, so stripping a signature does not downgrade it. Consent records are core `aroha.consent/v1` records whose every event is signed by its own actor and hash-chained (`createConsent`/`appendConsentEvent`/`verifyConsent`); a record that fails verification is dropped and reads as no consent. A person with no key on this install gets a local placeholder DID and unsigned events, accepted only while their DID resolves to no key.
- **Runtime — signed turns, guest grants, four-identity receipts (step C).** A member's turn in a room is signed with their person key (core `signTurn`, `aroha.turn/v1`, addressees as DIDs) and `GET /v1/threads/:id` reports each user turn's `signature` (`valid` | `invalid` | `unsigned`) and KEL-derived `speakerKind`; an altered body reads `invalid`. The host can lend a guest a room-scoped task mandate (`POST /v1/threads/:id/room/grants`, `DELETE …/grants/:mandateId`): grantor the host's person DID, grantee the agent, `onBehalfOf` the guest, `roomId`, `reversibleOnly`, expiring no later than the seat; `checkTaskNarrowing` refuses a grant wider than the agent's tools (`grant_widens_host`). A guest may then answer a gate for a granted capability; the gateway checks it with `enforceTaskConstraints` (its first production caller) before forwarding. Payer rule: the runtime forms no carts, so it is enforced at the approval layer — a capability that names a payment can be neither granted to nor approved by a guest (`payment_needs_host`). `approval_required` frames carry `presentedHash` (core `hashPresentedContent` of what is shown); both interfaces echo it on resume and show it, and an approval naming different content is treated as a rejection. Action receipts are v2 with `requesterDid`, `principalDid`, `executorDid`, `roomId`, `onBehalfOf`, `mandateId`/`mandateGrantor` and `presentedHash`; refused and declined calls are receipted with `outcome: "denied"` and a `denialReason`.
- **Runtime — scoped memory for a mixed roster of people and agents (step D).** `MemoryFact` gains the core memory-record fields — `speakerDid`, `speakerKind` (from the speaker's key event log, never the message), `speakerName`, `subjectDid`, `scope` (`private` | `room:<id>`), `audience`, `epoch`, `origin` (hash of the signed turn), `derivedFrom`, `status` (`fact` | `claim`), `consentRef`, `taint` — plus `ownerId` on private facts. Existing facts are migrated on first read (speaker = owner, scope private, subject self, status fact) and written back. A room keeps its own bucket per agent (`MemoryStore.forRoom`); with `memoryPolicy.roomMemory: "consented"` the agent writes there only from a signed turn whose author granted `memory_write`, and drops a fact naming another member who has not (subject-consent check). An agent's assertion is always stored as a claim; only the person it is about (or the host, for a claim about the room) can adopt it (`POST /v1/agents/:slug/memory/rooms/:roomId/:factId/promote`, optionally into their own private bucket), audited as `memory_claim_promoted`. Recall is gated after retrieval per fact (`memory-scope.ts gateRecall`): private facts only to their owner outside rooms; room facts only to current members; invited agents only room facts with audience `members` from speakers who granted `agent_use_of_messages`, while `agentRead` allows; a delegated sub-agent only what its task mandate's `dataAccess` grants (`memory:room:<id>`). Facts reach the model with their speaker; a recalled fact carries its lineage taint into the turn. Leaving, removal, consent withdrawal, invitation expiry and thread deletion cascade-delete every room fact the member spoke or is the subject of and everything derived from those, audited as `memory_forgotten`. `GET /v1/agents/:slug/memory` adds `roomFacts` by or about the caller (deletable by them); `GET /v1/agents/:slug/memory/export` returns a hash-chained export signed by the caller's person key (`memory_exported`). The memory panel shows who said a fact, offers Adopt for claims and a signed export.
- **Runtime — fix: room consent rules now hold on orchestrated turns.** The planner and every plan step were given the room history without the consent filter, so a member who withdrew `agent_use_of_messages` still had their turns read there, and a guest's text could be forwarded to a hosted sub-agent they had not agreed to. One filtered history (`modelVisibleHistory`: no display-only turns, no turns by excluded authors) now feeds the single agent, the planner and every step, and one rule (`providerRefusal`) decides for the routed agent and for each sub-agent; a refused step is skipped with a visible "not sent" step and nothing is sent.
- **Runtime — conversation-profile evaluation harness (step F).** `src/eval/conversation-harness.ts` measures the controls with a mixed roster (host and guest people, an invited and a delegated agent) against the real stores and gates, without a model: asker-bound recall, cross-member spillage, pooled-retrieval leakage (every bucket pooled, then gated) and a guest-authority control (a guest's request for a host-only payment is tainted, gated rather than run, unapprovable by the guest, and receipted as denied). `node scripts/conversation-eval.mjs [out.json]` writes timestamped JSON results (default `scratch/`); the same harness runs as a test. Current result: recall 9/9, spillage 0 of 15 returned, leakage 0 outside scope across 20 queries, guest-authority 5/5 checks.
- **`@aroha-sdk/core` — `ArohaDisclosure`** — new `{ v: 1, agentDid, principalDid, principalKind: "person" | "organization", purpose, hop, aiGenerated: true }` object with `buildDisclosure` and `validateDisclosure`. It can be attached to an envelope as an optional `disclosure` field (`buildEnvelope(..., { disclosure })`). The envelope signature covers it. `validateEnvelope` refuses a malformed disclosure, or one whose `agentDid` is not the envelope's `from`.
- **`@aroha-sdk/core` — action receipt v2** — `signActionReceipt` now issues `aroha.action-receipt/v2`. v2 adds optional `requesterDid`, `principalDid`, `executorDid`, `presentedHash`, `traceparent`, `roomId` and `onBehalfOf`. `approval` gains optional `presentedHash` and `approverSignature`. A required `outcome` (`"executed"` | `"denied"`) records refusals as well as actions; a `"denied"` receipt must carry a `denialReason`. `verifyActionReceipt` accepts v1 and v2, and each version refuses fields it does not define. New: `verifyPresentedHash(receipt, presentedContent)`, `hashPresentedContent`, and `signActionReceiptV1` (deprecated, for vectors and interop).
- **`@aroha-sdk/core` — `UserApproval.presentedHash`** — optional SHA-256 hex of the JCS form of exactly what the approver was shown. When present, `userSignature` covers JCS of `{ invariants, presentedHash, purpose: "aroha.user-approval/v2" }`. When absent, it covers the key-sorted invariants as before, so legacy approvals still verify. New helpers: `userApprovalSigningBytes`, `signUserApprovalPayload` and `verifyUserApprovalSignature`.
- **`@aroha-sdk/credentials` — task-mandate room bindings** — `TaskConstraints` gains optional `onBehalfOf` (DID) and `roomId`. `checkTaskNarrowing` requires a child to keep the parent's values, so dropping one counts as widening. `attenuateTaskMandate` inherits them when the caller leaves them out. `checkTaskConstraints` and `enforceTaskConstraints` accept request `roomId` and `onBehalfOf` and refuse a mismatch, or a missing value, with the new code `CONTEXT_MISMATCH`.
- **`@aroha-sdk/credentials` — spending mandate `actingFor`** — an optional `actingFor: "payer" | "payee"` on the mandate body declares which side of a payment the agent acts for (PSD3/PSR). Set it with `issueIntentMandate(..., { actingFor })`. Children inherit it, and `verifyMandateChain` refuses a link that drops or flips it. The field is signed only when present, so existing tokens and vectors are unchanged. The Python chain verifier (`aroha.mandate.verify_mandate_chain`) enforces it too.
- **`@aroha-sdk/core` — conversation objects** — new `conversation` module with verifiers for signed rooms (`aroha.room/v1`, signed by the owner's person key, with membership epochs) and consent records (`aroha.consent/v1`). Every consent event is signed by its own actor and hash-chained (`aroha.consent-event/v1`). Only the subject can give consent. A withdrawal by anyone else requires the room record, and that actor must have been a member at the event's epoch. Also added: authored-turn signatures (`aroha.turn/v1`), the `MemoryFact` type, `kelConversationResolver`, and the rule that speaker kind is read from the Key Event Log, never from the message.
- **Spec** — `aroha-1.0` adds §12 Conversation and Memory Profile, §6.6 task-mandate token v2 (with `onBehalfOf` and `roomId`), §6.7 signed revocation status, §6.8 governed verifier profile, `actingFor` in §6.5 and the optional envelope `disclosure`. Both spec copies are updated and the parity check passes. New JSON Schemas are in `spec-public/schemas/`. Deterministic vectors (RFC 8032 test keys) are in `spec-public/vectors/conversation-v1.json`, with the generator `packages/aroha-core/scripts/gen-conversation-vectors.ts`.
- **Python SDK (`aroha`)** — new `aroha.conversation` verifies rooms, consent records, turns, action receipts v1/v2, `presentedHash` and disclosures. It was written from the spec and checked against the shared vectors.
- **`@aroha-sdk/telemetry`** — `OtlpHttpExporter` sends spans to an OTLP/HTTP collector as JSON over `fetch`. It is best-effort, keeps a bounded queue and adds no dependency. `withReceiptTraceparent` and `annotateSpanWithReceipt` link action receipts and spans. `SpanRecord` gains `startTimeMs`, `endTimeMs` and `attributes`.
- **`@aroha-sdk/a2a-bridge` — A2A server side** — `createA2aRequestHandler` serves an EdDSA-JWS-signed Agent Card at `/.well-known/agent-card.json` and a JSON-RPC `SendMessage` endpoint. Every message passes `a2aToArohaVerified` before the handler runs, and a rejected mandate returns JSON-RPC `-32010`. New: `signAgentCard`, `verifyAgentCardSignature` and `fetchAgentCard`. A one-off interop run with the `@a2a-js/sdk` 1.3.0 client is recorded in the README.
- **Agent Skills** — new `skills/` directory with `aroha-mandates`, `aroha-receipts` and `aroha-python-sdk`. Each passes `agentskills validate` (skills-ref 0.1.1).
- **Documentation**
  - Drafts: [UCP `$requestConstraints` mapping](docs/integrations/ucp-mapping.md) and [mandate-to-ID-JAG profile](docs/integrations/id-jag-profile.md).
  - Threat model T8 and hardening §11 state the credential-vault rule, with how the runtime enforces it and its gaps.
  - New [evidence-preservation runbook](docs/security/evidence-preservation.md).
  - `docs/trust.md` lists which of these features are enforced in the SDK and which in the runtime, and records "W3C Agent Identity Registry CG: owner to join".

### Upgrading the runtime

1. **Back up `~/.aroha`** (the whole workspace directory) before the first start of the new
   version. Several migrations below rewrite files in place.
2. **Migrations run on first boot, in this order** (each is a no-op once done):
   1. **Knowledge** — per-agent `agents/<slug>/knowledge.json` documents move into the shared
      workspace library.
   2. **Threads** — per-agent conversation files move into the workspace thread store.
   3. **Connector IDs** — every agent with no tool selection gets an explicit one (the servers
      installed at that moment), recorded by a marker file so it runs once.
   4. **Owner person** — the install's owner person identity is created.
   5. **Identity** — legacy agent DIDs move to rotatable E-DIDs controlled by the owner person.
   The **credential vault** is not migrated at boot: each stored credential is migrated the
   first time it is read.
3. **Opting out of the identity migration:** set `identityMigrate = false` in
   `~/.aroha/config.toml` **before** starting the new version to keep the old DIDs. (Agents on
   legacy DIDs cannot rotate or be recovered.)
4. **Recovery code:** when the owner person is created, the runtime prints a one-time recovery
   code in the terminal (in `--json` mode it is available once from the interface instead).
   Store it offline — it is the only way to recover the person identity, and it is not shown
   again.
5. **Peers must upgrade together.** Because replies are now sealed, two runtimes that consult
   each other must both run this release; an older peer cannot read the new replies. Agents whose
   DIDs changed must be re-trusted by their peers.

### Known gap — releases without changelog entries

Package versions **1.4 through 1.9** were published without entries in this file (this changelog was last versioned at 1.3.0, while packages moved on independently — for example `@aroha-sdk/core` 1.9.0, `@aroha-sdk/registry` 1.8.0, `@aroha-sdk/run` 1.6.0, `@aroha-sdk/audit` / `settlement` / `reputation` 1.4.0). Their contents are not reconstructed here. Until they are, use `git log --oneline -- packages/<package>` as the record of what changed.


### Added — integration feedback (real-world usage of @aroha-sdk/core and @aroha-sdk/delegation)

Findings from building a production Python app (aroha-doc-intel) against
these SDKs. Every item below is additive — no breaking changes.

- **`@aroha-sdk/core@1.3.0`**:
  - `signCanonical(payload, privateKey)` / `verifyCanonicalSignature(payload, signature, publicKey)`
    — a bare hex Ed25519 signature over canonical JSON, with no `MessageProof`
    wrapper. `signMessage()` always produces a full DID-document-shaped proof
    object; callers proving DID control to an external API (no envelope, no
    proof block) previously had to bypass this package and pull in a second
    Ed25519 library to get one step below `signMessage()`. This is that step.
  - `buildAgentManifest` / `buildMcpManifest` / `buildSkillManifest` /
    `validateManifest` — manifest builders for the three common entity kinds.
    `generateDID()` returns identity material and stops there; every
    implementer was independently inventing the manifest shape
    (`capabilities`, `trustLevel`, `visibility`/`published`/`deployTarget`)
    despite `arohaProtocolVersion` implying it's meant to be standard.
  - `mintLocalIdentity()` / `preparePublish()` — a `LocalIdentity` type that
    carries a private key, and a `PublishableIdentity` type that structurally
    cannot (no `privateKey` field at all, not just a convention of omitting
    it). Nothing previously stopped a locally-minted identity from being
    handed to a registry-publish call by mistake.
  - `defineSkill` / `SkillRegistry` — a minimal Skills primitive. There was no
    "Skill" concept in the SDK at all; apps building reusable, named,
    independently-invocable units of behavior had to invent the vocabulary
    from scratch.
  - `LocalScheduler` / `TriggerConfig` — a minimal scheduler primitive.
    `trigger: "auto"` on an agent manifest was previously inert metadata; this
    gives it real (in-process, dependency-free) behavior for "manual" and
    "interval" triggers. Cron parsing is deliberately out of scope — represented
    as a config shape apps can wire to their own cron library.

- **`@aroha-sdk/delegation@0.2.0`**: `createDelegationMiddleware()` /
  `getVerifiedMandate()` — mandate-chain verification as an `ArohaMiddleware`,
  the same composability pattern `@aroha-sdk/credentials`'
  `createRbacMiddleware()` already uses. `serveDelegated()` wraps
  `@aroha-sdk/run`'s `serve()` end to end — the right choice for its
  streaming/receipt machinery, but it meant adopting delegation-based auth
  required standing up a `@aroha-sdk/run` server specifically. This mounts
  directly into an existing `ArohaServer`'s `middleware` array instead, no
  `@aroha-sdk/run` dependency required.

- **`aroha` (Python SDK) `1.4.0`**: parity for the above where it didn't
  already exist — `sign_canonical`/`verify_canonical` (cross-language tested
  against real `@aroha-sdk/core` output), `aroha.manifest`'s builders,
  `mint_local_identity`/`prepare_publish`. Also newly added:
  `aroha.credentials` — `issue_credential`/`verify_credential`/
  `issue_corporate_identity_credential`, mirroring
  `aroha-core/src/identity/credentials.ts` byte-for-byte. This SDK's
  docstring already claimed "Verifiable Credentials" as a Layer 1 feature;
  there was previously no Python code backing that claim, so an app issuing a
  `CorporateIdentityCredential` from Python had nothing to call and had to
  shell out to a Node helper running `@aroha-sdk/core` instead.

- **CI**: `scripts/check-readme-examples.mjs`, wired into `.github/workflows/ci.yml`.
  Checks every named import a README's TypeScript code examples take from an
  `@aroha-sdk/*` package against that package's real built exports.
  `mcp-bridge`'s `wrapMcp()` stub and `registry`'s stale README both shipped
  and were only caught by an integrator hitting them — this is the "does the
  README's own example actually match the package" check that would have
  caught the second of those before release. Running it for the first time
  surfaced 21 more pre-existing mismatches across other packages, baselined
  in the script (`KNOWN_MISMATCHES`) rather than blind-fixed, since each
  needs a human call on whether the README or the export is the stale side.

### Added — private agents

- **Registry visibility** on agents, MCP servers, and skills: `public` (default),
  `unlisted` (hidden from capability search, still resolvable by `didHash`), and
  `private` (owner and grant-holders only). Existing records are unaffected.
- **Access grants** (`POST/GET/DELETE /v1/grants`) scoped by API key for
  discovery and by DID for invocation, with optional expiry and capability
  subsetting. Revocation is a soft delete so the audit trail survives.
- **`aroha-sig`** request signing — `@aroha-sdk/run` 1.3.0 and `aroha` 1.3.0.
  Agents set `auth: "aroha-sig"` with `allowedCallers` / `allowed_callers`;
  callers pass `signAs` / `sign_as` and the SDK signs each request. The Python
  SDK gained signing in both directions (it previously had none). The wire
  format is identical across languages and is pinned by cross-language test
  vectors, so either SDK can call the other.
- Spec: §3.5 `aroha-sig` and §5.4 visibility and access grants, plus
  conformance rows L1-07..L1-11 and L2-07..L2-13.

### Fixed

- **Registry schema drift.** `schema.sql` was missing five tables and every
  column added by migrations 001 and 002, so a fresh bootstrap produced a
  broken database; production had never had those columns either and every
  discovery endpoint began returning 500 once code read them. `/health` now
  verifies the schema this build requires and names the exact missing table or
  column, `scripts/migrate.mjs` tracks applied migrations in
  `schema_migrations`, and `npm run deploy` refuses to ship ahead of the
  schema. Migration 004 reconciles the remaining pre-migrations baseline.
- Docs: `callAgent` examples in the Fly.io blog, the playground, and the
  registry pricing page passed a capability/params object as the second
  argument. The real signature is `callAgent(didHash, message, options)`.
- Go and Java SDKs are marked "coming soon" throughout the spec and README —
  neither is published, and the documented Go module path pointed at a
  private repository.

---

## [1.3.0] — 2026-07-05

### Breaking — `@aroha-sdk/settlement` 1.3.0

- **`EscrowSettlement`**: Constructor now **throws** unless `{ acknowledgeAlpha: true }` is passed. `ArohaEscrow.sol` has not been deployed to any public network; the previous behaviour silently accepted construction and would fail at the first RPC call. Callers testing against a local hardhat/anvil deployment must opt-in explicitly.
- **`StripeSettlement`**: Constructor now emits `console.warn` unless `{ acknowledgeAlpha: true }` is passed or `NODE_ENV === "test"`. The class has not been audited for production financial use.
- **`PostgresSettlement`**: Same `console.warn` guard as `StripeSettlement`.

### Fixed — `@aroha-sdk/registry` 1.3.5

- **`createArohaRegistryServer` BigInt serialization**: `sendJSON` was calling plain `JSON.stringify` on `AgentRecord` objects which contain `stakedWei: bigint`. `JSON.stringify` throws on `bigint` values — every `GET /v1/agents` and `GET /v1/agents/:didHash` call returned HTTP 500 silently. Fixed with a replacer that serialises `bigint` as a decimal string.
- **OpenAPI spec added** (`openapi.yaml`): All 6 registry endpoints documented with request/response schemas, auth model, and examples. Included in the published npm tarball via `files`.

### Added

- `apps/website/.env.example`: Documents all required environment variables for local development (`AUTH_SECRET`, `AUTH_GITHUB_ID/SECRET`, `AUTH_GOOGLE_ID/SECRET`, `REGISTRY_URL`, `REGISTRY_ADMIN_SECRET`).
- `packages/aroha-registry/src/http-server.test.ts`: 15 integration tests covering all 6 HTTP endpoints in both unauthenticated (dev) and Bearer-authenticated modes.
- `packages/aroha-trusted-mesh/src/mesh.test.ts`: 17 smoke tests for CIDR helpers, `createTrustedMeshOptions`, and `createTrustedZone`.
- Registry pricing page: SLA & service status section (uptime commitment, p95 latency, rate limits, maintenance windows, failover guidance).
- Protocol page: link to `docs/spec/did-method.md` from the DID disclosure box.
- Roadmap: escrow entry corrected from "testnet only" to `NOT_DEPLOYED` status with third-party audit requirement noted.
- Python SDK page: "Live on PyPI" and "Open Beta" status chips in the page header.
- `@aroha-sdk/evals` bumped from 1.1.1 → 1.2.2 to align with the rest of the ecosystem.

### Security

- `apps/website/src/app/keys/page.tsx`: `<img>` replaced with Next.js `<Image>` — eliminates an unoptimised image load on the API key management page.

### Added
- CI quality gate workflow (build, test, lint, typecheck on every PR)
- Release quality gate workflow (version consistency, CHANGELOG check, dependency audit)
- Conformance test runner workflow (daily cron, scorecard artifact)
- Public trust page (`docs/trust.md`) — CI status, standards status, security posture, compatibility matrix
- Conformance test matrix (`docs/conformance/test-matrix.md`) — 30 testable requirements across L0–L4
- Independent implementer onboarding packet (`docs/conformance/implementer-packet.md`)
- Threat model (`docs/security/threat-model.md`)
- Security review scope (`docs/security/review-scope.md`)
- Ecosystem quality tiers — Listed / Verified / Certified (`docs/ecosystem/quality-tiers.md`)
- ICP messaging matrix and wedge vertical briefs (`docs/gtm/messaging-matrix.md`)
- GTM trust signal backlog (`docs/gtm/trust-signal-backlog.md`)
- Weekly GTM report template (`docs/gtm/weekly-report-template.md`)
- `CONTRIBUTING.md`, `MAINTAINERS.md`, `SECURITY.md`
- Maintainer governance sections added to `docs/governance.md`

---

## [1.2.5] — 2026-07-03

### Fixed — Node SDK and docs

- **`@aroha-sdk/core` 1.2.2**: Added `generateDid(publicKey: Uint8Array): string` — derives a content-addressed `did:aroha:` DID from an existing Ed25519 public key without generating a new keypair. Paired with the existing `generateDID()` (full keypair + DID Document) and `generateKeyPair()` (raw keypair only).
- **`@aroha-sdk/evals` 1.1.1**: Package was published without running the TypeScript build step — `dist/` was absent from the tarball so `import "@aroha-sdk/evals"` threw `Cannot find module '...dist/index.js'`. Root cause: `packages/aroha-evals` was missing from `scripts/build-ordered.mjs`. Added to Layer 1 and republished.
- **TypeScript docs** (`apps/website/.../typescript/page.tsx`): Corrected credentials section — `issueIntentMandate`, `attenuateToCart`, and `attenuateToPayment` use positional arguments (not an options object); `verifyMandate` returns `{ valid, mandate?, reason? }` (not a destructured tuple); `SpendingConstraints` does not have `allowedCapabilities` or `exactAmountUsd` fields; `createRbacMiddleware` takes `{ resolveAgentRoles, resolveIssuerPublicKey }` (not `{ requiredTrustLevel }`).

---

## [1.2.4] — 2026-07-03

### Fixed — Node SDK packages (pre-rollout smoke test)

- **`@aroha-sdk/core` 1.2.1**: Added `generateKeyPair()` — raw Ed25519 keypair generation. Was documented in UI but missing from the package export surface. `generateDID()` still returns a full DID + keypair; `generateKeyPair()` returns just `{ privateKey, publicKey }` for callers who manage DIDs separately.
- **`@aroha-sdk/micro` 1.2.1**: Exported `createMicroAgent` as an alias for `createAgent` — UI docs referenced `createMicroAgent` throughout.
- **`@aroha-sdk/hermes-bridge` 1.2.1**: Fixed CLI-on-import packaging bug — `server.ts` called `startFromCli()` at module top level with no ESM main guard. Any `import "@aroha-sdk/hermes-bridge"` triggered the MCP server CLI and exited with code 1. Fixed with `fileURLToPath(import.meta.url)` guard.
- **`@aroha-sdk/registry` 1.3.1**: Removed eager re-export of `contract.ts` (which imports `ethers`) from the main package index. `ethers` is an optional peer dep for blockchain deployments; non-blockchain users shouldn't need it. Blockchain registry still available via `import "@aroha-sdk/registry/contract"`.
- **`@aroha-sdk/run` 1.2.1**: Package was published at 1.2.0 without running the TypeScript build step — only `src/` was present in the tarball, so `require("@aroha-sdk/run")` threw `Cannot find module '...dist/index.js'`. Republished with `dist/`.

---

## [1.2.3] — 2026-07-03

### Security — Python SDK (`aroha` 1.1.3)

- **[HIGH] Identity Spoofing / Namespace Collision**: `generate_did` now validates `agent_id` and `namespace` against `[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}` and raises `ValueError` on dots, colons, hashes, slashes, or whitespace. Without this, `generate_did("acme.evil", ...)` produced a DID indistinguishable from `generate_did("evil", ..., namespace="acme")`.
- **[MEDIUM] DID Syntax Injection**: Same charset guard prevents injecting DID-syntactic characters (`:`, `#`, `/`) into the generated DID string.
- **[MEDIUM] Revocation Trust Boundary**: `extract_public_key` now carries an explicit security docstring: it is a local-document convenience that trusts `revokedKeys` as-is. Production callers must resolve and authenticate the DID Document through a trusted registry before passing it to this function.

---

## [1.2.2] — 2026-07-03

### Fixed — Python SDK (`aroha` 1.1.2)

- **`generate_did` API**: returns a plain `dict` instead of the internal `AgentKeyPair` dataclass — callers now use `identity["did"]`, `identity["document"]` etc. (JSON-serialisable without `.to_dict()`)
- **`generate_did` namespace**: added optional `namespace` kwarg → `did:aroha:acme.agent-id`
- **`extract_public_key`**: new public function with revocation checking (`ValueError` if key appears in `doc["revokedKeys"]`); the old `extract_public_key_bytes` is kept for internal dataclass use
- **`build_envelope`**: now accepts `Ed25519PrivateKey | bytes` — was bytes-only, which forced callers to re-serialise a key they already had in memory
- **`verify_mandate` expiry**: changed `expires_at < now` to `expires_at <=` so `ttl_seconds=0` is immediately rejected
- **Test location**: `aroha/test_mandate.py` moved to `tests/test_mandate.py` — was shipping inside the installed package
- **`__version__`**: bumped `1.1.0` → `1.1.2` to match `pyproject.toml`
- **Docs**: Python SDK reference (`docs/sdks/python.md`) updated — all `identity.X` attribute access → `identity["X"]` dict access, added `@serve` section, fixed `verify_mandate` return signature (tuple, not object), fixed `ttl_ms` → `ttl_seconds` in mandate example

---

## [1.2.1] — 2026-07-01

### Added
- `@aroha-sdk/evals@1.1.0`: `vitest` test script and `--did`/`--reputation-url`/`--reputation-key` CLI flags — post eval results directly to the reputation service after a run

---

## [1.2.0] — 2026-06-23

### Added
- `@aroha-sdk/hermes-bridge` — Aroha ↔ Hermes Agent / ZeroClaw bridge (MCP stdio server)
- `@aroha-sdk/openclaw-bridge` — Aroha ↔ OpenClaw bridge (skill ↔ capability adapter)
- `@aroha-sdk/composio-bridge` — Aroha ↔ Composio / TrustClaw bridge (custom action adapter)
- Python SDK documentation page with accurate API signatures (`generate_did`, `build_envelope`, `validate_envelope`, `NonceRegistry`)
- TypeScript SDK install notes: npm audit guidance, build-from-source instructions
- All 23 npm packages now include `"files": ["dist", "src"]` — dist/ is correctly shipped on publish

### Fixed
- **Critical:** All npm packages were missing `dist/` from published tarballs — `main: ./dist/index.js` would 404 after install (`.gitignore` excluded `dist/` with no `files` field override)
- **Security (hermes-bridge):** Broken identity-key binding — bridge DID and signing key were generated from separate keypairs; verifiers would always reject signatures. Fixed to use a single `generateDID()` call for both.
- **BOM corruption:** PowerShell `System.Text.Encoding.UTF8` writes a BOM; Vite's JSON loader threw `SyntaxError: Unexpected token '﻿'` on all 21 affected `package.json` files. Stripped all BOMs.
- Conformance runner (`vitest.conformance.config.ts`) failing on transitive workspace imports (`orchestrator → core`) due to Vite SSR bare-specifier resolution on Windows paths with spaces. Fixed with explicit `resolve.alias` entries pointing to absolute `dist/index.js` paths.
- Python SDK docs: wrong function name (`generate_keypair` → `generate_did(agent_id, endpoint)`), wrong return type for `validate_envelope` (dict → `(bool, Optional[str])` tuple), missing `NonceRegistry` requirement, missing `type_` vs `type` note, missing venv step.
- `aroha-hermes-bridge` TypeScript errors: `generateDid` → `generateDID`, `CapabilityDefinition.pricing` type, `DiscoveredAgent` shape.
- Build ordering: added `aroha-audit`, `aroha-chaos`, `aroha-resilience`, `aroha-openclaw-bridge`, `aroha-composio-bridge`, `aroha-hermes-bridge` to `scripts/build-ordered.mjs`.

---

## [1.1.0] — 2026-06-12

### Added
- Resilience layer: circuit breaker, bulkhead, retry, health checks, speculative execution, chaos engineering (`@aroha-sdk/resilience`, `@aroha-sdk/chaos`, `@aroha-sdk/audit`)
- Scalability and latency enhancements across 6 packages
- Website rebranded to Aroha Protocol with green palette

---

## [1.0.0] — 2026-05-28

### Added
- `@aroha-sdk/core` — DID generation (`did:aroha:`), Ed25519 keypair management, key rotation
- `@aroha-sdk/credentials` — Verifiable credential issuance and verification (W3C VC Data Model 2.0)
- `@aroha-sdk/registry` — Capability registry: publish, discover, deregister
- `@aroha-sdk/orchestrator` — Saga coordinator: Reserve → Commit → Cancel with automatic rollback
- `@aroha-sdk/policy` — Access control and policy enforcement
- `@aroha-sdk/settlement` — Payment envelopes, escrow, and refund on rollback
- `@aroha-sdk/trusted-mesh` — Trust mesh composition for multi-party agent graphs
- `@aroha-sdk/reputation` — Capability-level reputation scoring
- `@aroha-sdk/telemetry` — W3C Trace Context compliant telemetry
- `@aroha-sdk/cache` — Request/response cache for saga participants
- `@aroha-sdk/preferences` — Agent preference storage
- `@aroha-sdk/micro` — Lightweight Aroha agent scaffolding
- `@aroha-sdk/commerce` — Commerce layer primitives
- `@aroha-sdk/cli` — `aroha` CLI: `create-agent`, `create-bridge`, `did`, `registry`, `saga`
- `@aroha-sdk/mcp-bridge` — MCP ↔ Aroha bidirectional bridge
- `@aroha-sdk/a2a-bridge` — Google A2A ↔ Aroha bridge
- `@aroha-sdk/langchain-bridge` — LangChain / AutoGen / Semantic Kernel ↔ Aroha bridge
- Reference agents: GitHub, Jira, Salesforce, Stripe, Zendesk, Personal, Mock Provider
- Protocol specification: `docs/spec/aroha-1.0.md`
- DID method specification: `docs/spec/did-method.md` (`did:aroha:` W3C DID method)
- Demo scripts: `demo:vc` (travel saga + hedge fund analyst), `demo:browser`, `demo:chat`

### Protocol
- Aroha 1.0 protocol frozen — Layers 0–4 stable
- `did:aroha:` DID method v1.0
- Signed envelope format: Ed25519Signature2020 over ArohaEnvelope
- Saga pattern: Reserve/ReserveAck/Commit/CommitAck/Cancel/CancelAck
- Capability manifest schema v1.0
