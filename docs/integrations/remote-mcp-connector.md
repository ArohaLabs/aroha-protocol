<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Remote MCP connector

`@aroha-sdk/mcp-server` can run as a **remote MCP server**: Streamable HTTP,
MCP protocol revision **2026-07-28**, acting as an **OAuth 2.1 protected
resource**. This is the shape agent platforms use for user-added connectors.
This page covers deploying it and what is and is not verified about
registering it with Meta Muse, Claude and Duet, and OpenAI.

Owner: @projectmed99 · Last reviewed: 2026-10-25 · Status: published to npm
as `@aroha-sdk/mcp-server` 2.0.0 (see [trust page](../trust.md)). Not yet
tested against any hosted assistant.

## What the server implements

| Area | Behaviour | Verified by |
|---|---|---|
| Transport | Streamable HTTP at `POST /mcp`; MCP 2026-07-28 (stateless, `server/discover`, `Mcp-Method`/`Mcp-Name` headers, `ttlMs`/`cacheScope` on list results) with the SDK's stateless fallback for 2025-era clients; stdio still available | `packages/aroha-mcp-server/src/http.test.ts` (stock `@modelcontextprotocol/client` 2.3.1) |
| Protected resource | `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728); `401` with `WWW-Authenticate: Bearer resource_metadata="…"` | same |
| Tokens | JWT access tokens checked against the authorization server's JWKS: signature, `iss`, `aud` = this server's URL, `exp`, `sub`. Tokens for another audience are refused. The token is never forwarded anywhere (no passthrough). Pluggable verifier for introspection | same |
| Client identity | Clients identified by Client ID Metadata Documents (an https URL as `client_id`); no Dynamic Client Registration endpoint. Optional allowlist (`AROHA_MCP_AUTH_ALLOWED_CLIENTS`) and CIMD-only mode (`AROHA_MCP_AUTH_REQUIRE_CIMD=1`) | same (fake AS advertising `client_id_metadata_document_supported` and RFC 9207 `iss`) |
| Users | Each token subject (`iss` + `sub`) gets its own Ed25519 signing key from a pluggable key store (default: one `0600` file per user). No shared grantor key | same |
| Approvals | Mandate issuance and spending calls ask the user through an MRTR `input_required` round trip; approval and mandate ids travel in an HMAC-protected `requestState` bound to the user | same |
| Outbound calls | Agent endpoints from the registry are resolved and refused if any address is private, loopback or link-local; the connection is pinned to the checked address; no redirects; capped bodies; error bodies are not returned to the caller | `src/safe-fetch.test.ts`, `src/call.test.ts` |
| Tasks extension (`io.modelcontextprotocol/tasks`, [2026-07-28](https://github.com/modelcontextprotocol/ext-tasks/blob/main/specification/2026-07-28/tasks.md)) | **Implemented in this server** (the SDK 2.3.1 routes the methods but has no task runtime). Advertised in `server/discover`; `aroha_call` returns a `CreateTaskResult` only when the request declares the extension, and only after its approval round trip; `tasks/get`, `tasks/update` (acknowledged, no effect: tasks never need input) and `tasks/cancel` (aborts the outbound call); `-32021` for undeclared clients, including task subscriptions on `subscriptions/listen`; `-32602` for unknown and expired tasks. Tasks are bound to the user **and** client that made them, 256-bit ids, TTL 900 s, 32 per user, 1000 per process (configurable). Not implemented: `notifications/tasks`; state is in memory per process, so several instances must route on `Mcp-Name` (the task id) | `src/tasks.test.ts`: raw JSON-RPC against the HTTP transport with OAuth — task result equals the synchronous result, cross-user and cross-client get/update/cancel refused as "not found", cancellation aborts the agent request and stays `cancelled`, TTL expiry aborts a running task, per-user and process caps, a declined or mismatched approval creates no task and sends nothing. Not tested against any third-party Tasks client |
| Enterprise-Managed Authorization (ID-JAG) | **Resource-server side implemented** (see [below](#enterprise-managed-authorization-id-jag)). Access tokens your authorization server issued from an ID-JAG are accepted when they carry the enterprise identity in an `id_jag` claim from a trusted IdP; the user is keyed by IdP issuer, tenant and subject; mandates report that identity as their root (`grantorRoot`). Optional enforcement (`AROHA_MCP_ENTERPRISE_REQUIRED=1`) refuses every other token. Raw ID-JAGs, untrusted IdPs or tenants, tokens with no client and unenforceable profile claims are refused. The token exchange and ID-JAG validation belong to the IdP and the authorization server: this repository ships neither (a reference pair exists for tests only) | `src/enterprise.test.ts`: verifier cases (expired, wrong audience, wrong issuer, foreign key, raw ID-JAG, untrusted IdP and tenant, malformed claim, guest claims) and an end-to-end run with the stock SDK `CrossAppAccessProvider` + `requestJwtAuthorizationGrant` against the test IdP and authorization server. **Not tested against a real IdP** (Okta, Entra, Keycloak) or a real authorization server |

## Enterprise-Managed Authorization (ID-JAG)

Specs: the MCP extension `io.modelcontextprotocol/enterprise-managed-authorization`
([ext-auth, specification/stable](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx),
status Stable, last changed 2026-06-18) and
[draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
(2026-05-21).

| Step | Who | In this repository |
|---|---|---|
| User signs in to the client through the enterprise IdP | Client, IdP | — |
| Token exchange: ID Token → ID-JAG (`typ: oauth-id-jag+jwt`, `aud` = the authorization server's issuer, `resource` = this server) | Client, IdP | — (the SDK client has `requestJwtAuthorizationGrant`) |
| JWT bearer grant: validate the ID-JAG (draft §4.4.1: `typ`, `aud`, `client_id`, IdP signature, expiry, single use) and issue an access token for `resource` | Your authorization server | — (test-only reference: `src/test-utils/fake-enterprise.ts`) |
| Copy the enterprise identity into the access token | Your authorization server | Required by this server: an `id_jag` object claim with `iss`, `sub`, `jti` (optional `tenant`, `email`, `aroha_mandate_id`). **ASSUMPTION:** neither spec defines this transcription; the claim name is configurable. Owner @projectmed99, due 2027-01-21 |
| Validate the access token (signature, `iss`, `aud`, `exp`, `sub`, `client_id`) and the `id_jag` claim (trusted IdP, tenant pin) | This server | `src/auth.ts`, `src/enterprise.ts` |
| Map the enterprise subject to a signing key; mandates name it as their root | This server | `src/server.ts` (`grantorRoot` on issued mandates, `enterpriseRoot` on receipts) |

Configure it with `AROHA_MCP_ENTERPRISE_IDPS` (the IdP issuer, exactly as in
the ID-JAG `iss`), and `AROHA_MCP_ENTERPRISE_REQUIRED=1` to refuse anything
else. Your authorization server should advertise
`authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]`
in its metadata; this server does not check that. The root binding
(`grantorRoot`) is asserted by this server, not signed by the IdP.

Verification criterion: with a real IdP and authorization server, a user who
signs in through the IdP gets the same `grantorDid` in two sessions, another
user gets a different one, and an ordinary token is refused with
`AROHA_MCP_ENTERPRISE_REQUIRED=1`. Not yet run.

## Deploy

1. **Authorization server.** Use an OAuth 2.1 / OIDC provider that issues JWT
   access tokens with `aud` set to the resource (RFC 8707 `resource`
   parameter) and publishes RFC 8414 or OIDC discovery metadata with a
   `jwks_uri`. For the platforms below it must accept the clients they use;
   Client ID Metadata Document support avoids per-client registration.
   ASSUMPTION: not every provider supports CIMD yet; check yours.
2. **Run the server** behind HTTPS (a reverse proxy or a platform that
   terminates TLS). It binds `127.0.0.1` by default; set `AROHA_MCP_HOST`
   only when the proxy is on another host.

   ```bash
   AROHA_MCP_TRANSPORT=http \
   AROHA_MCP_PUBLIC_URL=https://mcp.example.com/mcp \
   AROHA_MCP_AUTH_ISSUER=https://auth.example.com \
   AROHA_MCP_AUTH_SCOPES_SUPPORTED="aroha" \
   AROHA_MCP_STATE_KEY=$(openssl rand -hex 32) \
   AROHA_MCP_KEY_DIR=/var/lib/aroha-mcp/keys \
   AROHA_REGISTRY_URL=https://registry.example.com \
   AROHA_MCP_REGISTRY_KEYS=/etc/aroha/registry-keys.json \
   npx -y @aroha-sdk/mcp-server --http
   ```

   The same settings can live in a JSON file named by `AROHA_MCP_CONFIG`
   (shape: `ArohaMcpConfigFile` in `src/config.ts`; see the package README).
3. **Check it.**
   - `curl -i -X POST https://mcp.example.com/mcp` → `401` with a
     `WWW-Authenticate` header naming `resource_metadata`.
   - `curl https://mcp.example.com/.well-known/oauth-protected-resource/mcp`
     → `resource` equals the public URL and `authorization_servers` names your
     issuer.
   - Connect with MCP Inspector or a stock SDK client and complete the OAuth
     flow; `server/discover` should list `2026-07-28`.
4. **Keys.** The key directory holds one private key per user. Back it up,
   restrict it to the service account, or replace `FilePrincipalKeyStore`
   with a KMS-backed `PrincipalKeyStore`.
5. **Several instances** need the same `AROHA_MCP_STATE_KEY` (an approval
   can come back to any instance) and a shared key store.

Verification criterion for a deployment: all three checks in step 3 pass and
two different test users see different `grantorDid` values from
`aroha_issue_task_mandate`.

## Register with Meta Muse (custom connector)

What is documented publicly (secondary sources only; Meta has published no
primary connector specification): Muse lets a user add a remote MCP server
over Streamable HTTP with OAuth as a **custom connector**, without Meta
review; a reviewed directory exists separately.

UNVERIFIED — not tested against Muse from this repository:

- the exact form fields (server URL; whether Muse uses CIMD, DCR or a
  pre-registered client id);
- the protocol revision Muse's client negotiates (the server also serves
  2025-era clients);
- whether Muse renders MRTR `input_required` approval forms (if it does not,
  approval-gated tools fail closed; set `AROHA_MCP_APPROVAL_TOOLS` to adjust).

Steps that follow from the documented model: deploy as above, add
`https://mcp.example.com/mcp` as the connector URL, complete sign-in at your
authorization server, then call `aroha_discover`. If Muse identifies itself
with a CIMD URL, add it to `AROHA_MCP_AUTH_ALLOWED_CLIENTS` to restrict the
server to it.

## Register with Claude (custom connector) and Duet

Claude lets a user add a remote MCP server as a **custom connector**: a
server URL, then sign-in at the server's authorization server. Duet is
available by waitlist only; this project does not have access yet.

UNVERIFIED — not tested against Claude or Duet from this repository:

- which client registration method Claude uses with your authorization
  server (CIMD, DCR or a pre-registered client id);
- the protocol revision Claude's client negotiates, and whether it renders
  MRTR `input_required` approval forms (if it does not, approval-gated tools
  fail closed; set `AROHA_MCP_APPROVAL_TOOLS` to adjust);
- anything about how Duet attaches connectors.

Steps that follow from the documented model: deploy as above, add
`https://mcp.example.com/mcp` as the custom connector URL, complete sign-in,
then call `aroha_discover`.

## Register as an OpenAI plugin (ChatGPT, Codex, dots)

What is documented publicly (secondary sources): OpenAI routes ChatGPT,
Codex and dots through MCP-backed plugins; Developer Mode accepts an unlisted
MCP server; listing requires review with a production `/mcp` URL, domain
verification, declared CSP domains, reviewer credentials and positive and
negative test cases.

UNVERIFIED — not tested against ChatGPT from this repository:

- Developer Mode connection end to end, including which client registration
  method ChatGPT uses with your authorization server;
- MRTR support in ChatGPT's client;
- the current review checklist (re-check OpenAI's documentation before
  submitting).

Material this repository can supply for a review: the tool annotations
(`readOnlyHint`, `destructiveHint`, `openWorldHint`) on every tool; the
positive and negative cases in `src/http.test.ts` and `src/call.test.ts`
(successful flow, wrong audience, expired token, forged approval state,
declined approval, private-range endpoint, unverifiable agent response) as a
starting point for the required test cases. A reviewer account must exist at
your authorization server.

## Risks and assumptions

- ASSUMPTION: platform clients support Client ID Metadata Documents; the
  server does not offer Dynamic Client Registration (deprecated in
  2026-07-28), so an authorization server that needs DCR must provide it
  itself.
- Receipts are kept in memory per user and process; they do not survive a
  restart.
- `aroha_call` marks every action receipt `tainted: true`, because the
  server cannot see the model context that chose the call.
- Per-user keys are content-addressed (`did:aroha:z…`), not person-rooted
  KEL identities; mandates they issue do not satisfy the governed profile's
  person-root requirement. Linking a user to a person KEL is follow-up work.
