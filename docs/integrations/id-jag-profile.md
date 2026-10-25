<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Draft profile: Aroha mandate to MCP Enterprise-Managed Authorization (ID-JAG)

**Status:** draft profile. The mandate → ID-JAG direction below is documentation only: nothing in this repository issues an ID-JAG. The resource-server side (an MCP server accepting access tokens issued from an ID-JAG, and rooting the user's mandates in the enterprise identity) is implemented in `@aroha-sdk/mcp-server`; see [Implemented: the resource-server side](#implemented-the-resource-server-side). No real identity provider has been tested against either.
**Owner:** @projectmed99 (sole named maintainer, per `MAINTAINERS.md`). **Date:** 2026-10-19 (first written 2026-10-15).
**Verification criterion:** a Keycloak (or other IdP) Enterprise-Managed Authorization test issues an ID-JAG from a verified Aroha mandate as specified here, the MCP authorization server exchanges it for an access token, and a request outside the mandate's `allowed` list is refused. Not yet run.

## Purpose

MCP's Enterprise-Managed Authorization extension lets an enterprise identity provider decide which clients reach which MCP servers for which users. It does this with an Identity Assertion JWT Authorization Grant (ID-JAG): the IdP signs a JWT that the client presents to the MCP server's authorization server in exchange for an access token. An Aroha task mandate says the same thing in Aroha terms: this person lets this agent use these capabilities, under these limits, until this time. This profile describes how an IdP that trusts Aroha mandates could mint an ID-JAG from one, so that an enterprise can reuse its existing MCP authorization path.

Re-checked on 2026-10-19 against [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (2026-05-21) and the [MCP Enterprise-Managed Authorization extension](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx) (Stable): `typ: oauth-id-jag+jwt`; required claims `iss`, `sub`, `aud` (the authorization server's issuer), `client_id`, `jti`, `exp`, `iat`; optional `resource` (MUST be the MCP server's resource identifier when present, EMA §4.3), `scope`, `authorization_details`, `sub_id`, `tenant`, `aud_tenant`, `aud_sub`, `email`, `auth_time`, `acr`, `amr`, `cnf`. The names used below match.

## Flow

1. The agent holds an Aroha task mandate whose chain is rooted in a person (`did:aroha:E…`, Key Event Log kind `person`).
2. The agent sends the mandate token to the enterprise IdP's token endpoint (RFC 8693 token exchange), authenticated as the agent's OAuth client.
3. The IdP verifies the chain with the governed verifier profile (spec §6.8): person root, current keys from the Key Event Log, revocation consulted for every link, and a root pinned to a person the IdP knows. The IdP must refuse the exchange if any of these checks fails.
4. The IdP maps the person DID to its own user (`sub`), and mints an ID-JAG for the requested MCP server.
5. The client presents the ID-JAG to the MCP server's authorization server (JWT bearer grant), receives an access token, and calls the MCP server.

## Claim mapping

| ID-JAG claim | Source in the verified mandate | Rule |
|---|---|---|
| `iss` | The IdP | The IdP signs, not the agent. The mandate is input to the IdP's decision. |
| `sub` | Root grantor (person DID) mapped to the IdP's user id | No mapping means no token. |
| `client_id` | The leaf `grantee` (agent DID), mapped to the agent's registered OAuth client | The mapping is per IdP. A Client ID Metadata Document per agent DID is a possible future source. |
| `aud` | The MCP server's authorization server | One token per server. |
| `resource` | The MCP server URL | |
| `scope` | `allowed` minus `blocked`, mapped to the server's scope names | A capability without a scope mapping is dropped, never widened. |
| `exp` | `min(mandate expiresAt, IdP policy maximum)` | It never outlives the mandate. |
| `jti` | Fresh per token | Replay protection at the authorization server. |
| `aroha_mandate_id` (private claim, proposed) | Leaf `mandateId` | Joins the token to Aroha receipts and revocation. |
| `aroha_on_behalf_of`, `aroha_room_id` (private claims, proposed) | `taskConstraints.onBehalfOf`, `roomId` | Present only for guest grants. A resource server that cannot enforce them should refuse such tokens. |

## Constraints that do not map

`actionLimits`, `computeLimit`, `dataAccess`, `humanGates`, `reversibleOnly` and invariants have no ID-JAG equivalent. The MCP server (or a proxy in front of it, such as `@aroha-sdk/mcp-guard`) must still run `enforceTaskConstraints` with the mandate itself. The ID-JAG grants reach. It does not carry the limits.

## Revocation

An ID-JAG is short-lived and cannot be recalled once issued. The IdP should cap `exp` at a few minutes, and the authorization server should re-check mandate revocation when it issues an access token. Event-driven revocation (OpenID Shared Signals/CAEP) is not implemented in Aroha. See `docs/trust.md`.

## Implemented: the resource-server side

The specs put the token exchange and the ID-JAG checks on the IdP and the MCP server's authorization server; the MCP server itself never sees an ID-JAG (draft §6: the resource server has no trust relationship with the IdP). `@aroha-sdk/mcp-server` implements the part that belongs to the resource server:

1. It validates the access token as for any OAuth client (its own authorization server's JWKS, `iss`, `aud`, `exp`, `sub`) and refuses a raw ID-JAG presented as a bearer token.
2. It reads the enterprise identity the authorization server copied into the token. **ASSUMPTION:** the specs define no transcription, so the server reads one object claim, `id_jag` by default: `{ "iss": <IdP>, "sub": <IdP subject>, "jti": <ID-JAG jti>, "tenant"?, "email"?, "aroha_mandate_id"? }`. Owner: @projectmed99. Due: 2027-01-21.
3. The IdP must be on the operator's list (`AROHA_MCP_ENTERPRISE_IDPS`, optionally pinned to tenants), the token must name its client, and the claims `aroha_on_behalf_of` / `aroha_room_id` are refused because this server cannot enforce them (see the claim mapping above).
4. The enterprise identity (IdP issuer, tenant, subject), not the authorization server's own account id, selects the user's Ed25519 key. Every mandate that user issues has that key's DID as its grantor, and the tool output reports the binding as `grantorRoot` (`kind: "enterprise"`, IdP issuer, subject, tenant, ID-JAG `jti`, authorization server, client). Call receipts carry the same as `enterpriseRoot`. This is the reverse of the flow above: the enterprise identity is the root of the chain, and Aroha mandates attenuate from it.

The binding is asserted by the MCP server, not signed by the IdP; a verifier outside the deployment has to trust the server's statement that the grantor key belongs to that enterprise subject. The per-user keys are content-addressed `did:aroha:z…` keys, not `person` Key Event Logs, so the governed profile (§6.8) does not accept them as roots.

Verified by `packages/aroha-mcp-server/src/enterprise.test.ts` against a test-only IdP and authorization server (`src/test-utils/fake-enterprise.ts`), driven by the stock MCP SDK client (`CrossAppAccessProvider`). Not verified against a real IdP or authorization server.
