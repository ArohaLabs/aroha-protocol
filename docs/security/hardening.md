<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Production Hardening Guide

**Owner:** Security Agent (human owner — to assign)  
**Version:** 1.2 — 2026-10-10 (1.1: 2026-10-09; 1.0: 2026-05-28)  
**Audience:** Operators deploying Aroha agents in production  
**Verification:** every API name and option in this guide was checked against the exported source in `packages/*/src` on 2026-10-09; §10 (runtime) was checked against `apps/aroha-runtime/src` on 2026-10-10. Where the SDK does not provide a control, the guide says so.

This guide covers the controls you must configure before running Aroha agents in a production environment. The defaults are tuned for development convenience, not production security.

How to read this guide:

- **SDK control** — enforced by code in `@aroha-sdk/*` when you set the named option.
- **Application layer** — not provided by the SDK; you must implement or configure it yourself (reverse proxy, secrets manager, rate limiter, etc.).

---

## 1. Key Management

### Generate keys securely

Key generation in `@aroha-sdk/core` uses `@noble/ed25519`'s cryptographically secure random source. There is no separate "development" generator.

```typescript
import { generateKeyPair, generateDid, generateDID } from '@aroha-sdk/core';

// Raw Ed25519 keypair (no DID document): { privateKey, publicKey } as Uint8Array
const { privateKey, publicKey } = await generateKeyPair();
const did = generateDid(publicKey); // content-addressed did:aroha:z...

// Or a named DID with a DID document and service endpoint:
// generateDID(agentId, endpoint, options?) → { did, privateKey, publicKey, document }
const agent = await generateDID('payments-agent', 'https://agent.example.com');
```

### Store private keys securely

*Application layer.* The SDK returns private keys as `Uint8Array`; it does not store them for you.

**Do not** store private keys in:
- Environment variables directly (they can leak into logs and process listings)
- Plain files on disk without OS-level protection
- Source code or git history

**Do** use one of:
- A cloud secrets manager (AWS Secrets Manager, Azure Key Vault, Google Cloud Secret Manager)
- HashiCorp Vault
- Kubernetes Secrets encrypted at rest with KMS
- Hardware Security Modules (HSMs) for high-value agents

```typescript
// Illustrative: fetch the key from your secrets manager at startup — never hard-code.
// `secretsManager` is your own client, not an Aroha API.
const privateKeyHex = await secretsManager.getSecret('aroha/agent-key');
```

### Key rotation

*SDK control* for producing the rotation; *application layer* for publishing it and for scheduling. Recommended target: rotate at least annually, and immediately if compromise is suspected. There is no automatic rotation schedule in the SDK.

The SDK offers one rotation function per identity type. Each keeps the DID unchanged, has the outgoing key sign a rotation record embedded in the new DID document, and applies a cool-down (default 24 hours) before the new key is trusted:

```typescript
import { rotateDIDKey, rotateKey, rotateKel } from '@aroha-sdk/core';

// did:aroha (AgentKeyPair from generateDID): returns a new AgentKeyPair
const next = await rotateDIDKey(current, /* coolDownHours */ 24);

// did:aroha-web (WebAgentKeyPair): returns a new WebAgentKeyPair, including
// the webDocument to publish at wellKnownUrl and the dnsTXTRecord to update
const nextWeb = await rotateKey(currentWeb, 24);

// KEL-based identity (pre-rotation): the committed next key becomes current
const nextKel = await rotateKel(identity);
```

After rotating, you must publish the new DID document (and, for `did:aroha-web`, update the DNS TXT record). Until the cool-down elapses, resolvers continue to use the previous key. `verifyKeyRotation()` and `checkKeyRotation()` are available to validate a received rotation record.

---

## 2. Transport Security

### Enforce TLS 1.3+

*Application layer.* `ArohaServer` (from `@aroha-sdk/core`) listens on **plain HTTP** (`node:http`); it does not terminate TLS. Put it behind a TLS-terminating reverse proxy or load balancer, or wrap it yourself.

- Reverse proxy (nginx, Caddy, cloud load balancer): allow TLS 1.3 only (for example `ssl_protocols TLSv1.3;` in nginx) and do not expose the plaintext port publicly.
- Bind the agent's own port to a private interface or loopback.

If a listener is reachable **without** TLS (LAN socket, relay hop), set `requireEncryption: true` with `privateKey` on `ArohaServerOptions` (*SDK control*): unsealed envelope bodies are then rejected.

### Certificate management

*Application layer.*

- Use certificates from a trusted CA (Let's Encrypt is acceptable).
- Set certificate expiry alerts — expired certificates break agent-to-agent connections.
- Rotate certificates before expiry.

---

## 3. Nonce & Replay Protection

*SDK control.* `ArohaServer` validates envelope signatures, the `expires` field, and nonce uniqueness on every inbound envelope unless `devMode` is set. `devMode` is refused at `start()` unless `NODE_ENV=development`. The relevant `ArohaServerOptions` (there is no `createAgent({ replayWindowSeconds, … })` API):

```typescript
import { ArohaServer, FileNonceStore } from '@aroha-sdk/core';

const server = new ArohaServer({
  agentDID, didDocument, port, onMessage, resolvePublicKey,
  nonceStore: new FileNonceStore('/var/lib/aroha/nonces.log'), // survives restarts
  clockToleranceMs: 5_000,   // expiry tolerance; default 0 (strict)
  maxTtlMs: 300_000,         // max envelope lifetime; default 5 minutes
  maxFutureSkewMs: 30_000,   // how far `created` may be in the future; default max(clockToleranceMs, 30s)
  maxBodyBytes: 1_048_576,   // default 1 MiB; requests above this get HTTP 413
});
await server.start();
```

Nonce stores:

- `MapNonceStore` (default) — in-process; forgotten on restart.
- `FileNonceStore(filePath, { fsync?, compactAfterEvictions? })` — single instance; persists across restarts.
- **Multi-instance deployments:** the SDK does not ship a shared (e.g. Redis) store. Implement the `NonceStore` interface (`setIfAbsent(nonce, expiryMs)`, `evictExpired()`) against a shared backend at the application layer. An in-process store will not detect a replay across instances.
- Raise `maxTtlMs` only together with a nonce store whose retention is at least as long.

`@aroha-sdk/micro`'s `createAgent({ name, port, devMode?, registryUrl?, endpoint?, host? })` defaults `devMode` to **false** (since `@aroha-sdk/micro` 2.0.0; it previously defaulted to true). Do not set `devMode: true` outside development — core refuses it unless `NODE_ENV=development`.

---

## 4. Registry Security

### Use an authenticated registry in production

`InMemoryRegistry` (from `@aroha-sdk/registry`) has no persistence or authentication — development only.

Options that exist in the SDK:

- `ArohaHttpRegistry` — client for an HTTP registry service.
- `createArohaRegistryServer({ registry?, apiKey?, port?, hostname? })` (import from `@aroha-sdk/registry/server`) — a Node HTTP server exposing a registry backend. Mutating routes require a bearer token **only if `apiKey` is set**; without it every operation is unauthenticated. It defaults to an in-memory backend and binds `0.0.0.0`. It does **not** provide TLS or mTLS — terminate TLS (and mTLS, if required) at a reverse proxy.
- `ArohaRegistryContract` (import from `@aroha-sdk/registry/contract`) — on-chain registry client.

Operator controls (*application layer*):
- Always set `apiKey` (or front the server with an authenticating proxy).
- Pass a persistent `IArohaRegistry` implementation; the SDK does not ship a database-backed one.
- Do not expose registry administrative routes publicly.

### Capability validation

*Application layer.* The SDK has no `verifyCapability()` function. Registry lookups (`resolveByDID(did)`, `queryByCapability(capabilityIds)`) return what agents have registered — a capability listing is a claim, not proof. Before routing a saga to an agent:

- Validate the agent's manifest structure with `validateManifest()` from `@aroha-sdk/core`.
- If you require proof of authorisation, check a signed credential with `verifyCredential()` (`@aroha-sdk/core`) against an issuer you trust.
- Prefer content-addressed DIDs, whose key is bound to the DID itself, over named DIDs whose key is only as trustworthy as the resolver.

---

## 5. Saga Configuration

Sagas run through `SagaEngine` from `@aroha-sdk/orchestrator` (there is no `createOrchestrator()`):

```typescript
import { SagaEngine } from '@aroha-sdk/orchestrator';

const engine = new SagaEngine(client, orchestratorDID, orchestratorPrivateKey, {
  reserveTimeoutMs: 5_000,   // per-step RESERVE timeout; default 10_000
  sagaDeadlineMs: 30_000,    // total saga budget across all steps
  persistLog: async (log) => { /* write SagaLog to durable storage */ },
});
```

Not provided by the SDK:

- **Separate commit / cancel timeouts** — only `reserveTimeoutMs` and the overall `sagaDeadlineMs` exist.
- **A participant limit** (`maxParticipants`) — enforce a maximum number of steps at the application layer before calling `execute()`.

### Durable saga state

*SDK hook, application-layer storage.* There is no `PostgresSagaStateStore` or other built-in durable store. Supply a `persistLog(log)` callback that writes each `SagaLog` to your own durable store (it is called after every state transition). On restart, load the stored logs and pass them to `SagaRecoveryEngine` (`new SagaRecoveryEngine(client, orchestratorDID, orchestratorPrivateKey).recover(logs)`), which resumes sagas left in `COMMITTING` or `COMPENSATING`.

Related resilience options on `SagaEngineOptions`: `circuitBreaker`, `healthChecker` + `abortOnUnhealthy`, `compensationDLQ`, `approvalGate`, `intentGate`.

---

## 6. Rate Limiting & DoS Protection

*Application layer, with an SDK hook.* `ArohaServer` does not rate-limit on its own. Its only built-in size control is `maxBodyBytes` (default 1 MiB). Apply rate limits at the load balancer and/or in your own HTTP layer.

`ArohaServerOptions.beforeRequest(req)` is the place for an in-process limit: it runs first for every HTTP request — before the body is read, decrypted or signature-checked — and a returned `{ status, body?, headers? }` is sent as the response with no further processing. It sees only the request line, headers and socket (`req.socket.remoteAddress`). A hook that throws fails closed (HTTP 500). It does not run for WebSocket upgrades. The Aroha runtime's LAN listener uses it for its per-IP limit (§10).

```typescript
const server = new ArohaServer({
  /* … */
  beforeRequest: (req) =>
    limiter.allow(req.socket.remoteAddress ?? 'unknown')
      ? undefined
      : { status: 429, body: { error: 'rate_limited' }, headers: { 'retry-after': '1' } },
});
```

Example using the third-party `express-rate-limit` package in an Express app you operate (not an Aroha API):

```typescript
import rateLimit from 'express-rate-limit';

app.use('/register', rateLimit({ windowMs: 60_000, max: 10 }));
app.use('/invoke', rateLimit({ windowMs: 1_000, max: 100 }));
app.use(express.json({ limit: '64kb' }));
```

Choose body limits to fit your largest legitimate envelope.

---

## 7. Secrets & Configuration

*Application layer.* Never commit secrets to git. Load configuration from a secrets manager. The variable names below are examples for your own application, not names the SDK reads:

```bash
# .env — local development only, never commit
AROHA_PRIVATE_KEY_PATH=/run/secrets/aroha-key
AROHA_REGISTRY_URL=https://registry.example.com
```

Validate configuration at startup and fail fast:

```typescript
const required = ['AROHA_PRIVATE_KEY_PATH', 'AROHA_REGISTRY_URL'];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing required env: ${key}`);
}
```

For secrets held by the Aroha project itself (publishing tokens, Worker secrets, signing keys), see [key-management.md](key-management.md).

---

## 8. Logging & Monitoring

*Application layer.* The SDK does not ship an alerting pipeline; `SagaEngineOptions.metrics` accepts a metrics recorder for saga lifecycle events.

### What to log

- Every inbound envelope (DID, capability, timestamp — not payload if sensitive)
- Signature verification failures
- Saga state transitions (Reserve, Commit, Cancel) with saga ID and participant DIDs
- Registry queries and registrations
- Key rotation events

### What NOT to log

- Private keys
- Full envelope payloads if they contain PII or financial data
- Raw authentication tokens

### Alerting

Suggested alert thresholds (targets, tune to your traffic):
- Signature verification failure rate > 1%
- Saga rollback rate > 10%
- Registry query latency p99 > 500ms
- Certificate expiry < 30 days

---

## 9. Compliance Checklist

Before going to production, confirm:

- [ ] Private keys stored in a secrets manager or HSM (not env vars or plain files)
- [ ] TLS 1.3+ enforced at the proxy in front of every `ArohaServer` and registry server; plaintext ports not public
- [ ] `devMode` is off (the default in `@aroha-sdk/core` and, since 2.0.0, `@aroha-sdk/micro`)
- [ ] Nonce store survives restarts (`FileNonceStore`) and is shared across instances (custom `NonceStore`) where applicable
- [ ] Registry server runs with `apiKey` set and a persistent backend (not `InMemoryRegistry`)
- [ ] Saga logs persisted via `persistLog` and `SagaRecoveryEngine` run on startup
- [ ] Participant count limited at the application layer
- [ ] Rate limiting applied at the load balancer and/or application layer
- [ ] Logging captures security-relevant events without logging secrets
- [ ] Alerts configured for signature failure rate, saga rollback rate, cert expiry
- [ ] Key rotation schedule established (annual target) and rotation publication tested
- [ ] Responsible disclosure policy published and linked (see [SECURITY.md](../../SECURITY.md))

---

## 10. Runtime controls added in this release

*Runtime control.* These apply to the Aroha runtime (the `aroha` binary; its source is not in this repository), not to agents built directly on the SDK. Settings are keys in the workspace's `config.toml` (`~/.aroha/config.toml` by default) unless marked as a command-line flag or environment variable. Each was checked against the runtime source on 2026-10-10; the source file is named so it can be re-checked.

| Control | Setting | Default | Source |
|---|---|---|---|
| Request body limits | `uploadMaxBytes` (bytes; values below 1 MiB are ignored) | JSON bodies 1 MiB (fixed); documents 50 MiB | `gateway/bridge.ts`, `workspace/config.ts` |
| Hash-based CSP and response headers | none (always on) | on | `gateway/ui-security.ts` |
| Config secrets in the OS keystore | `allowPlaintextCredentials` | `false` | `workspace/secrets.ts`, `host/credentials.ts` |
| Audit head checkpoints | none (fixed) | every 100 entries, every 5 minutes, at shutdown | `host/audit-rotate.ts` |
| Signed CLI audit journal | none (always on) | on | `host/audit-events.ts` |
| Refuse to start on audit failure | `refuseStartOnAuditFailure` | `false` | `main.ts` |
| Approvals bound to a person | none (multi-user installs) | on | `gateway/server.ts` |
| OIDC sign-in allow-lists | `oidcAllowedDomains`, `oidcAllowedSubjects` | empty (startup warning) | `gateway/auth-api.ts` |
| `?token=` only on page loads | none (always on) | on | `gateway/guard.ts` |
| One outbound-URL rule | none (always on) | on | `host/outbound-url.ts` |
| LAN bind address | `--lan-host <addr>` flag | `0.0.0.0` (only with `--lan`) | `main.ts` |
| LAN per-IP rate limit | none (fixed) | 30-request burst, 2/s refill per source IP | `transport/lan-server.ts` |
| Persistent replay protection | none (always on) | on | `main.ts`, `@aroha-sdk/core` `FileNonceStore` |
| KEL intake store cap | none (fixed) | 2000 foreign logs | `transport/peer-keys.ts` |
| `AROHA_ADDON_DEV` ignored in release builds | `AROHA_ADDON_DEV=1` (environment) | ignored in release builds and with `NODE_ENV=production` | `host/build-info.ts` |

**Request body limits.** Every JSON request to the gateway is limited to 1 MiB. A declared `Content-Length` above the limit is refused before any of the body is read, and a chunked body is refused as soon as it passes the limit. Either way the response is HTTP 413 with `connection: close`. Document uploads and pasted text use `uploadMaxBytes` instead. It is read on every request, so a change takes effect without a restart. The LAN listener keeps `ArohaServer`'s 1 MiB `maxBodyBytes`.

**Content-Security-Policy and headers.** Every HTML page (both UIs, status pages and sign-in pages) gets a CSP that lists the SHA-256 hash of each inline `<script>` and `<style>` block in the page as served. Inline script that is not in that list does not run. The policy also sets `default-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-src 'none'` and `frame-ancestors 'none'`. One allowance is documented in the source: `style-src-attr 'unsafe-inline'`, for `style="…"` attributes. HTML responses also carry `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and a `Permissions-Policy` that disables camera, microphone, geolocation, payment, USB, serial, Bluetooth, HID, MIDI and display capture. Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

**Secrets in the OS keystore.** `config.toml` is written with mode `0600`. If `registryApiKey` or `mcpOauthSecret` lines are added to it, the runtime moves them into the OS keystore at the next start, reads them back to confirm, and rewrites the file without them. If the keystore refuses, the file is left unchanged, the value keeps working, and a warning is printed. Provider keys, OAuth tokens and MCP server environment values are also stored in the keystore. When the keystore refuses one of these, the runtime refuses to save it unless `allowPlaintextCredentials = true`. With that setting it writes a `0600` plaintext file and logs that it did so. `/v1/admin/status` reports `keystore: "file"` when private keys are held in plaintext files because no OS keystore is available.

**Audit integrity.** The install key signs the head of the audit hash chain into `logs/audit-checkpoints.jsonl` at startup, after every 100 appended entries (`CHECKPOINT_EVERY`), every 5 minutes if entries were added (`CHECKPOINT_INTERVAL_MS`), and at shutdown. `/v1/admin/status` reports `entriesSinceLastCheckpoint`, which is the number of entries not yet covered by a signature. CLI commands run while the runtime is live write to `logs/audit-pending.jsonl`, and each line is signed with the install key. The runtime folds that journal into the chain at startup and every 30 seconds. A line without a valid signature, or whose type does not match the event it claims to be, is recorded only as `pending_audit_unverified` together with the line's hash. The full trail (rotation seams, archives, live chain and signed checkpoints) is verified at startup and on every audit-health read. A failure prints a warning. With `refuseStartOnAuditFailure = true` the runtime exits instead of starting.

**Approvals bound to the person.** On a multi-user install, each approval prompt in a run stream is bound to the person the stream was sent to. A `/v1/resume` answer from anyone else gets HTTP 403 `approval_not_yours`. The `approvedBy` recorded with the decision comes from the authenticated caller, and any value in the request body is overwritten. A personal install has only one person, so no comparison is made there.

**OIDC allow-lists.** With `authMode = "oidc"`, a sign-in is admitted when it matches either list. `oidcAllowedDomains` is a comma-separated list of email domains; a domain match also requires `email_verified` to be exactly `true`. `oidcAllowedSubjects` is a comma-separated list of exact `sub` values. If both lists are empty, any account the issuer authenticates can sign in, and a warning is printed at every start. Set at least one list for a multi-tenant issuer such as Google.

**Install token in the URL.** The `?token=` query parameter is accepted only on `GET /` and `GET /app`, the two page loads the launch URL points to. All other requests must send the token in the `Authorization` header (or have a session cookie).

**Outbound URLs.** Registry, peer and hub endpoints taken from request bodies, invitations or registry responses all go through one check. The rule is `https:` only, except plain `http:` to loopback. Private-range, link-local, CGNAT, `.local` and unspecified addresses are refused unless the caller is a LAN-peer path. Fetches do not follow redirects, time out after 10 s, and read at most 4 MiB of the response. Known limit (stated in the source): a public DNS name that resolves to a private address is not caught.

**LAN listener.** The LAN listener runs only with `--lan`. It binds `0.0.0.0` by default, and `--lan-host <addr>` binds one interface instead. The port is set with `--lan-port` (default: the gateway port + 1). Every inbound envelope must be encrypted. `POST /aroha/v1` is limited per source IP to a 30-request burst refilled at 2 per second (`inbound-guards.ts` `TokenBucket`). The check runs in `ArohaServer`'s `beforeRequest` hook, before any decryption or signature work. A request over the limit gets HTTP 429 with `retry-after: 1` and `connection: close`. Accepted nonces are persisted (`@aroha-sdk/core` `FileNonceStore`, mode `0600`) to `<workspace>/transport/lan-nonces.jsonl`, and the relay connection uses `<workspace>/transport/relay-nonces.jsonl`. As a result, a restart does not reopen the replay window for unexpired envelopes. Key event logs that peers introduce are held in a bounded in-memory quarantine until a signed request from that peer verifies. The durable store keeps at most 2000 foreign logs (`KEL_INTAKE_DEFAULTS.maxForeignStored`). When that limit is reached and no log can be evicted without losing rollback protection, new peers are verified from memory only. `/v1/admin/status` reports this as `kelIntake.foreignCapRefusals`, together with `maxForeignStored` and the quarantine size, while the LAN listener runs.

**Add-on development override.** `AROHA_ADDON_DEV=1` enables the Document Intelligence add-on without a licence, for developing the add-on itself. It is ignored, with a warning, in release builds and in any process run with `NODE_ENV=production`.

**Verification:** confirm `config.toml` has mode `0600` and contains no `registryApiKey`/`mcpOauthSecret` values after a start. Confirm `GET /v1/admin/status` shows `audit.intact: true` and an expected `keystore` value, and, with `--lan`, a `kelIntake.foreignCapRefusals` of 0. Confirm that an HTML response carries the `content-security-policy` header and that a `?token=` on an API path is refused with 401.

## 11. Credential vault rule

**Rule:** the model never has access to credentials. The runtime holds every credential and attaches it to outbound requests outside the model. This is threat [T8](threat-model.md#t8--credential-exposure-to-the-model).

**How the Aroha runtime enforces it** (checked against the runtime source in the private development repository on 2026-10-15):

| Credential | Held in | Reaches | Never reaches |
|---|---|---|---|
| MCP server API key or OAuth token | OS keystore (`host/mcp-credentials.ts`, `host/keystore.ts`); a `0600` file only with `allowPlaintextCredentials = true` | Remote server: an HTTP header on the MCP transport (`mcp/client.ts`). Local server: the server subprocess's environment. | Prompts, tool schemas, tool arguments, the UI (which gets a four-character hint) |
| Model-provider API key or OAuth token | OS keystore (`host/credentials.ts`) | The engine's HTTP requests to the provider | The model's context |
| Agent and person private keys | OS keystore, or `0600` files when none is available (`/v1/admin/status` reports `keystore`) | Signing inside the runtime process (envelopes, approvals, receipts) | Any tool or model input |

**What you must do as the operator:**
- Keep `allowPlaintextCredentials = false` (the default) on any machine with an OS keystore.
- Give MCP servers credentials through the runtime's credential store or the server's `env`. Do not put them in a prompt, a skill or a system instruction.
- Use scoped, short-lived tokens for MCP servers. The runtime does not narrow a token's scope.
- Do not install a local MCP server you do not trust: it receives its own credential in its environment.

**Not enforced (manual or open):**
- No general filter removes secrets from tool **results** before they reach the model. A tool that echoes a secret exposes it.
- A secret a person types into a chat goes to the model. The memory extractor refuses to store credential-shaped text (`host/secret-patterns.ts`), but the turn itself is not filtered.
- SDK-only agents (built directly on `@aroha-sdk/*` without the runtime) get no vault. They must apply this rule themselves.

**Verification:** run a test workspace with one MCP credential configured, capture the requests to the model provider (for example through a logging proxy), and search them for the credential value. Expected: no match. Then confirm `/v1/admin/status` shows a keystore other than `file` on a desktop OS.

---

*Questions? See the [threat model](threat-model.md) for the reasoning behind each control.*
