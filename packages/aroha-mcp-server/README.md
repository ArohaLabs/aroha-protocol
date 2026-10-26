# @aroha-sdk/mcp-server

MCP server that exposes an Aroha agent registry to Claude Desktop and any other MCP-compatible personal agent — over stdio locally, or as a **remote connector** (Streamable HTTP, MCP 2026-07-28, OAuth 2.1 protected resource) for platforms such as Meta Muse custom connectors and OpenAI plugins. Once configured, Claude can search the registry for registered vendor agents, issue task and spending mandates, call those agents directly, and retrieve the full audit receipt — all through natural conversation.

The registry is the reference deployment by default, or your own self-hosted registry via `AROHA_REGISTRY_URL`. A hosted Hub service with sign-up and API keys is not currently offered.

---

## Installation — Claude Desktop

Add the following block to your `claude_desktop_config.json` (on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aroha": {
      "command": "npx",
      "args": ["-y", "@aroha-sdk/mcp-server"],
      "env": {
        "AROHA_REGISTRY_URL": "https://registry.example.internal"
      }
    }
  }
}
```

Restart Claude Desktop. The tools below will appear in the tool list automatically.

**Optional environment variables**

| Variable | Default | Purpose |
|---|---|---|
| `AROHA_REGISTRY_URL` | `https://aroha-registry.aroha-labs.workers.dev` (reference deployment) | Registry endpoint — set it to your self-hosted registry |
| `AROHA_API_KEY` | `""` | Bearer token for authenticated registry calls, issued by your registry's operator |
| `AROHA_MCP_IDENTITY_DIR` / `AROHA_MCP_KEY_DIR` | `~/.aroha/mcp-server` | Where signing keys live |

---

## Remote connector (Streamable HTTP + OAuth)

```bash
AROHA_MCP_TRANSPORT=http \
AROHA_MCP_PUBLIC_URL=https://mcp.example.com/mcp \
AROHA_MCP_AUTH_ISSUER=https://auth.example.com \
AROHA_MCP_STATE_KEY=$(openssl rand -hex 32) \
npx -y @aroha-sdk/mcp-server --http
```

- MCP protocol revision 2026-07-28 via `@modelcontextprotocol/server` 2.3.1
  (`server/discover`, Multi Round-Trip Requests, `Mcp-Method`/`Mcp-Name`
  headers, `ttlMs`/`cacheScope`), with the SDK's stateless fallback for
  2025-era clients.
- OAuth 2.1 protected resource: RFC 9728 metadata at
  `/.well-known/oauth-protected-resource/mcp`; a request without a valid token
  gets `401` with `WWW-Authenticate: Bearer resource_metadata="…"`. Access
  tokens are JWTs checked against the issuer's JWKS (signature, `iss`,
  `aud` = the public URL, `exp`, `sub`). The token is never forwarded. Clients
  identify with Client ID Metadata Documents; there is no Dynamic Client
  Registration endpoint.
- Every user (token `iss` + `sub`) signs with their own Ed25519 key, created
  on first use in a pluggable key store (default: one `0600` file per user
  under `<key dir>/principals/<sha256>/`).
- Tools that grant or spend authority (`aroha_issue_task_mandate`,
  `aroha_issue_spending_mandate`, and `aroha_call` with `spendLimitUsd > 0` or
  a `mandateToken`) first ask the user: the server answers `input_required`
  with an approval form and an HMAC-protected `requestState` carrying the
  approval id (and mandate id); the client retries with `inputResponses`.
- Agent endpoints read from the registry are resolved and refused when any
  address is private, loopback or link-local; the connection is pinned to the
  checked address, redirects are refused and response size is capped.
- MCP Tasks (`io.modelcontextprotocol/tasks`, 2026-07-28): a client that
  declares the extension on its request gets a task handle for `aroha_call`
  (after any approval round trip) and polls `tasks/get`; `tasks/cancel` aborts
  the outbound call. Tasks belong to the user and client that created them,
  expire after their TTL and are capped per user and per process. In memory,
  per process; no `notifications/tasks`.
- Enterprise-Managed Authorization (ID-JAG), resource-server side: with
  `AROHA_MCP_ENTERPRISE_IDPS` set, an access token your authorization server
  issued from an ID-JAG is mapped to the enterprise user (IdP issuer, tenant,
  subject), who gets their own signing key; mandates they issue report that
  identity as their root. The authorization server must copy the ID-JAG's
  `iss`, `sub` and `jti` into an `id_jag` claim object (an Aroha convention;
  the specs do not define one). The token exchange and ID-JAG validation are
  the authorization server's job, not this server's. Raw ID-JAGs are refused.

Deployment and platform registration: [docs/integrations/remote-mcp-connector.md](../../docs/integrations/remote-mcp-connector.md).

### Configuration

Environment variables win over the JSON file named by `AROHA_MCP_CONFIG`
(shape: `ArohaMcpConfigFile`, exported from this package).

| Variable | File field | Default | Purpose |
|---|---|---|---|
| `AROHA_MCP_TRANSPORT` / `--http` | `transport` | `stdio` | `stdio` or `http` |
| `AROHA_MCP_HOST` / `AROHA_MCP_PORT` | `http.host` / `http.port` | `127.0.0.1` / `8787` | Bind address |
| `AROHA_MCP_PUBLIC_URL` | `http.publicUrl` | `http://<host>:<port>/mcp` | Canonical resource URL (token audience) |
| `AROHA_MCP_ALLOWED_HOSTS` / `AROHA_MCP_ALLOWED_ORIGINS` | `http.allowedHosts` / `http.allowedOrigins` | loopback + public host | Host/Origin allowlists |
| `AROHA_MCP_AUTH_ISSUER` | `auth.issuer` | — (required for `http`) | Authorization server issuer |
| `AROHA_MCP_AUTH_JWKS_URL` | `auth.jwksUrl` | from issuer metadata | JWKS location |
| `AROHA_MCP_AUTH_AUDIENCE` | `auth.audience` | public URL | Required `aud` |
| `AROHA_MCP_AUTH_SCOPES` / `AROHA_MCP_AUTH_SCOPES_SUPPORTED` | `auth.requiredScopes` / `auth.scopesSupported` | none | Required / advertised scopes |
| `AROHA_MCP_AUTH_ALGS` | `auth.algorithms` | `RS256,ES256,EdDSA` | Accepted JWS algorithms |
| `AROHA_MCP_AUTH_ALLOWED_CLIENTS` | `auth.allowedClientIds` | any | Allowed client ids (CIMD URLs) |
| `AROHA_MCP_AUTH_REQUIRE_CIMD=1` | `auth.requireClientIdMetadataDocument` | off | Refuse non-URL client ids |
| `AROHA_MCP_ENTERPRISE_IDPS` | `auth.enterprise.trustedIdps` | none | Enterprise IdP issuers (ID-JAG `iss`) whose users are accepted; the file form can pin `tenants` |
| `AROHA_MCP_ENTERPRISE_REQUIRED=1` | `auth.enterprise.required` | off | Refuse tokens not issued from an ID-JAG |
| `AROHA_MCP_ENTERPRISE_CLAIM` | `auth.enterprise.claim` | `id_jag` | Access-token claim carrying the ID-JAG provenance |
| `AROHA_MCP_TASKS=0` | `tasks.enabled` | on | Turn the MCP Tasks extension off |
| `AROHA_MCP_TASK_TTL_SECONDS` | `tasks.ttlSeconds` | `900` | Task lifetime from creation (1–86400) |
| `AROHA_MCP_TASKS_PER_USER` / `AROHA_MCP_TASKS_MAX` | `tasks.maxPerUser` / `tasks.maxTotal` | `32` / `1000` | Task caps per user+client and per process |
| `AROHA_MCP_APPROVAL_TOOLS` | `approvals.tools` | http: the three above; stdio: none | Gated tools, or `none` |
| `AROHA_MCP_STATE_KEY` | `approvals.stateKey` | random per process | HMAC key for `requestState` (≥ 32 bytes); required for several instances |
| `AROHA_MCP_KEY_DIR` | `keys.dir` | `~/.aroha/mcp-server` | Key store directory |
| `AROHA_MCP_REGISTRY_KEYS` | `registry.keys` | none | Registry signing keys (JSON or file) for signed revocation status |
| `AROHA_MCP_GOVERNED=1` + `AROHA_MCP_EXPECTED_ROOT` / `AROHA_MCP_TRUSTED_ROOTS` | `governed.*` | off | `verify_mandate` uses the governed profile |
| `AROHA_MCP_VERIFY_RESPONSES=0` | `verifyResponses` | on | DEVELOPMENT ONLY: skip agent response verification |
| `AROHA_ALLOW_PRIVATE_ENDPOINTS=1` | `allowPrivateEndpoints` | off | DEVELOPMENT ONLY: allow private/loopback agent endpoints |
| `AROHA_MCP_ALLOW_UNAUTHENTICATED=1` | `http.allowUnauthenticated` | off | DEVELOPMENT ONLY, loopback only: HTTP without OAuth |

---

## Tools

### `aroha_discover`
Search the configured registry for agents by capability ID or free-text query. Returns up to 10 matching agents with their DIDs, names, capabilities, reputation scores, and endpoints.

```
aroha_discover(capability?: string, query?: string)
```

### `aroha_call`
Call a vendor agent with a signed envelope from the user's DID. Pass `mandateToken` to present a signed mandate (`body.credentialToken`); without one, `spendLimitUsd`/`purpose` travel only as a sandbox hint. The agent's response envelope is verified (signer, recipient, expiry, replay, correlation id) before its result is returned; failed or unverifiable bodies are not returned. A `traceparent` in the request `_meta` is forwarded. Returns a `receiptId` and a signed action receipt.

```
aroha_call(agentDid, capability, params, spendLimitUsd?, purpose?, taskDescription?, mandateToken?)
```

### `aroha_issue_task_mandate`
Issue a fine-grained task mandate specifying exactly which capabilities the agent may invoke, how many times, whether they must be reversible, and which require a human gate before execution.

```
aroha_issue_task_mandate(agentDid, allowed[], blocked[]?, actionLimits?, reversibleOnly?, humanGates[]?, maxLlmTokens?, maxWebRequests?, ttlMinutes?)
```

### `aroha_issue_spending_mandate`
Issue a monetary spending mandate capping the agent at a specified USD amount for a single capability. Optionally restrict to a list of approved merchant DIDs.

```
aroha_issue_spending_mandate(agentDid, capability, spendLimitUsd, allowedMerchants[]?, ttlMinutes?)
```

### `aroha_get_receipt`
Retrieve the task receipt for a completed `aroha_call`. Shows the full audit trail: actions taken, resources consumed, mandate bounds check, and agent outputs.

```
aroha_get_receipt(receiptId)
```

### `verify_mandate`
Verify a mandate token: spending chains link by link to the root (governed profile when configured), task mandates against their grantor's key; time window, revocation and expected grantee.

### `revoke_mandate`
Revoke a spending mandate the user granted (or one beneath it), signed with the user's key and recorded at the registry.

### `check_revocation_status`
Registry revocation status, accepted only when signed by a pinned registry key (`AROHA_MCP_REGISTRY_KEYS`) and fresh.

### `verify_receipt`
Verify a signed action receipt, optionally against an expected agent, action and arguments, and report the tainted-input approval policy.

### `lookup_kel`
Fetch and verify the Key Event Log of a `did:aroha:E…` identity and its controller.

---

## Worked example — Book a flight via an airline agent

The airline, agent and values below are illustrative.

> **User:** Find an Example Air agent that can book flights, then book me on the cheapest Auckland to Wellington flight tomorrow.

**Step 1 — Claude calls `aroha_discover`**

```json
{ "capability": "book-flight", "query": "Example Air" }
```

Result (truncated):
```json
[{
  "did": "did:aroha:example-air-booking-agent",
  "name": "Example Air Booking Agent",
  "capabilities": ["book-flight", "check-flight-status", "cancel-booking"],
  "reputation": 4.9,
  "endpoint": "https://agents.example-air.example/aroha"
}]
```

**Step 2 — Claude calls `aroha_issue_spending_mandate`**

```json
{
  "agentDid": "did:aroha:example-air-booking-agent",
  "capability": "book-flight",
  "spendLimitUsd": 150,
  "ttlMinutes": 10
}
```

Result:
```json
{
  "mandateId": "spend-mandate-1749123456-abc123",
  "summary": "Spending mandate: up to $150 USD for book-flight with did:aroha:example-air-booking-agent",
  "validUntil": "2026-07-13T09:30:00.000Z"
}
```

**Step 3 — Claude calls `aroha_call`**

```json
{
  "agentDid": "did:aroha:example-air-booking-agent",
  "capability": "book-flight",
  "params": {
    "origin": "AKL",
    "destination": "WLG",
    "date": "2026-07-14",
    "cabin": "economy",
    "passengers": 1,
    "preferCheapest": true
  },
  "spendLimitUsd": 150,
  "purpose": "Book cheapest AKL-WLG flight for user"
}
```

Result:
```json
{
  "success": true,
  "result": {
    "bookingRef": "EX-X9K3M",
    "flight": "EX409",
    "departure": "07:00",
    "arrival": "08:05",
    "fareUsd": 89.00,
    "confirmationEmail": "sent"
  },
  "receiptId": "rcpt-aroha-mcp-1749123456-xyz789",
  "durationMs": 1243
}
```

**Step 4 — Retrieve audit receipt**

```json
{ "receiptId": "rcpt-aroha-mcp-1749123456-xyz789" }
```

The receipt confirms the agent stayed within the $150 mandate, made 1 web request, and produced a confirmed booking reference.

---

## License

Apache-2.0 — see [LICENSE](../../LICENSE).