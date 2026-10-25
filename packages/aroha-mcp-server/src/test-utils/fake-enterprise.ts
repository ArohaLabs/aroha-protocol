// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * TEST ONLY: a reference enterprise IdP and an ID-JAG-capable authorization
 * server, so the resource-server side can be exercised end to end. Neither is
 * shipped (package.json excludes test-utils) and neither is a production
 * implementation.
 *
 *   - startFakeIdp: RFC 8414 metadata, JWKS, and an RFC 8693 token exchange
 *     that turns an ID Token into an ID-JAG (draft-ietf-oauth-identity-
 *     assertion-authz-grant-04 §4.3; MCP EMA §4.2–4.3).
 *   - startFakeIdJagAs: the MCP server's authorization server. Accepts the JWT
 *     bearer grant with an ID-JAG (draft §4.4.1: typ, aud = this issuer,
 *     client_id = the authenticated client, signature against a trusted IdP,
 *     expiry, single use) and issues an access token audience-restricted to the
 *     ID-JAG's `resource` (EMA §5.1). It copies the enterprise identity into the
 *     `id_jag` claim this repository's resource server reads (enterprise.ts),
 *     and gives the user its own account id as `sub` (account linking), so a
 *     test can tell the two apart.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWK, type JWTPayload } from "jose";
import { ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE, ID_JAG_TYP, JWT_BEARER_GRANT } from "../enterprise.js";

const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";

interface Listening { server: Server; issuer: string }

async function listen(handler: (req: IncomingMessage, res: ServerResponse, issuer: string) => Promise<void>): Promise<Listening> {
  let issuer = "";
  const server = createServer((req, res) => {
    handler(req, res, issuer).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const addr = server.address();
  issuer = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return { server, issuer };
}

async function form(req: IncomingMessage): Promise<URLSearchParams> {
  let raw = "";
  for await (const c of req) raw += c;
  return new URLSearchParams(raw);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

function close(server: Server): Promise<void> {
  return new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections?.(); });
}

/** Client authentication: HTTP Basic (client_secret_basic) or form fields (client_secret_post). */
function clientCredentials(req: IncomingMessage, body: URLSearchParams): { id: string; secret: string } | null {
  const h = req.headers.authorization;
  if (h?.startsWith("Basic ")) {
    const decoded = Buffer.from(h.slice(6), "base64").toString("utf8");
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { id: decodeURIComponent(decoded.slice(0, i)), secret: decodeURIComponent(decoded.slice(i + 1)) };
  }
  const id = body.get("client_id");
  const secret = body.get("client_secret");
  return id && secret ? { id, secret } : null;
}

// ─── IdP ──────────────────────────────────────────────────────────────────────

export interface IdJagClaims {
  sub: string;
  aud: string | string[];
  client_id: string;
  resource?: string;
  scope?: string;
  tenant?: string;
  email?: string;
  jti?: string;
  expSec?: number;
  iatOffsetSec?: number;
  typ?: string;
  extra?: Record<string, unknown>;
}

export interface FakeIdp {
  issuer: string;
  /** An ID Token for `sub`, as single sign-on would have produced, for the IdP client `clientId`. */
  idToken(sub: string, clientId: string): Promise<string>;
  /** Mint an ID-JAG directly (bypassing policy) — for negative tests. */
  mintIdJag(claims: IdJagClaims): Promise<string>;
  /** Token-exchange requests received (audience values). */
  exchanges: string[];
  close(): Promise<void>;
}

export interface FakeIdpOptions {
  /** IdP OAuth clients: secret, and the client id the same app has at each resource authorization server. */
  clients: Record<string, { secret: string; clientIdAt: Record<string, string> }>;
  /** Authorization servers (issuer identifiers) the IdP will issue ID-JAGs for. */
  allowedAudiences: string[];
  tenant?: string;
}

export async function startFakeIdp(opts: FakeIdpOptions): Promise<FakeIdp> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "idp-1", alg: "ES256", use: "sig" };
  const exchanges: string[] = [];
  let issuer = "";

  const mintIdJag = (c: IdJagClaims) => {
    const now = Math.floor(Date.now() / 1000) + (c.iatOffsetSec ?? 0);
    return new SignJWT({
      client_id: c.client_id,
      ...(c.resource ? { resource: c.resource } : {}),
      ...(c.scope ? { scope: c.scope } : {}),
      ...(c.tenant ? { tenant: c.tenant } : {}),
      ...(c.email ? { email: c.email } : {}),
      ...(c.extra ?? {}),
    })
      .setProtectedHeader({ alg: "ES256", kid: "idp-1", typ: c.typ ?? ID_JAG_TYP })
      .setIssuer(issuer)
      .setSubject(c.sub)
      .setAudience(c.aud)
      .setIssuedAt(now)
      .setExpirationTime(now + (c.expSec ?? 300))
      .setJti(c.jti ?? randomUUID())
      .sign(privateKey);
  };

  const { server, issuer: iss } = await listen(async (req, res, issuerNow) => {
    const url = new URL(req.url ?? "/", issuerNow);
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return send(res, 200, {
        issuer: issuerNow,
        token_endpoint: `${issuerNow}/token`,
        jwks_uri: `${issuerNow}/jwks`,
        grant_types_supported: [TOKEN_EXCHANGE_GRANT],
        identity_chaining_requested_token_types_supported: [ID_JAG_TOKEN_TYPE],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      });
    }
    if (url.pathname === "/jwks") return send(res, 200, { keys: [jwk] });
    if (url.pathname !== "/token" || req.method !== "POST") return send(res, 404, { error: "not_found" });

    const body = await form(req);
    const creds = clientCredentials(req, body);
    const client = creds ? opts.clients[creds.id] : undefined;
    if (!creds || !client || client.secret !== creds.secret) return send(res, 401, { error: "invalid_client" });
    if (body.get("grant_type") !== TOKEN_EXCHANGE_GRANT || body.get("requested_token_type") !== ID_JAG_TOKEN_TYPE) {
      return send(res, 400, { error: "unsupported_grant_type" });
    }
    if (body.get("subject_token_type") !== ID_TOKEN_TYPE) return send(res, 400, { error: "invalid_request" });
    let idTokenPayload: JWTPayload;
    try {
      ({ payload: idTokenPayload } = await jwtVerify(body.get("subject_token") ?? "", publicKey, { issuer: issuerNow, audience: creds.id }));
    } catch {
      return send(res, 400, { error: "invalid_grant", error_description: "subject token rejected" });
    }
    const audience = body.get("audience") ?? "";
    exchanges.push(audience);
    // Policy: only listed authorization servers, and only clients registered there.
    const clientIdAtAs = client.clientIdAt[audience];
    if (!opts.allowedAudiences.includes(audience) || !clientIdAtAs) {
      return send(res, 400, { error: "invalid_grant", error_description: "policy does not allow this audience" });
    }
    const resource = body.get("resource") ?? undefined;
    const scope = body.get("scope") ?? undefined;
    const idJag = await mintIdJag({
      sub: String(idTokenPayload.sub),
      aud: audience,
      client_id: clientIdAtAs,
      resource,
      scope,
      tenant: opts.tenant,
      email: `${String(idTokenPayload.sub)}@corp.example`,
    });
    return send(res, 200, {
      issued_token_type: ID_JAG_TOKEN_TYPE,
      access_token: idJag,
      token_type: "N_A",
      expires_in: 300,
      ...(scope ? { scope } : {}),
    });
  });
  issuer = iss;

  return {
    issuer,
    idToken: (sub, clientId) =>
      new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: "idp-1" }).setIssuer(issuer).setSubject(sub)
        .setAudience(clientId).setIssuedAt().setExpirationTime("10m").sign(privateKey),
    mintIdJag,
    exchanges,
    close: () => close(server),
  };
}

// ─── Resource authorization server ────────────────────────────────────────────

export interface AccessTokenClaims {
  sub: string;
  aud: string;
  iss?: string;
  client_id?: string;
  scope?: string;
  expSec?: number;
  typ?: string;
  /** The enterprise claim object (omit for an ordinary token). */
  id_jag?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface FakeIdJagAs {
  issuer: string;
  /** Mint an access token directly — for negative tests at the resource server. */
  mint(claims: AccessTokenClaims): Promise<string>;
  /** Grant types seen at /token. */
  grants: string[];
  /** Map an IdP subject to this server's own account id (account linking). */
  linkAccount(idpIssuer: string, idpSub: string, accountId: string): void;
  close(): Promise<void>;
}

export interface FakeIdJagAsOptions {
  /** OAuth clients registered here (client_secret_basic). */
  clients: Record<string, string>;
  /** IdPs this authorization server trusts, by issuer (JWKS discovered from `<issuer>/jwks`). */
  trustedIdps: string[];
  /** MCP servers (resource identifiers) this authorization server issues tokens for. */
  resources: string[];
  /** Access-token claim name for the enterprise identity. Default "id_jag". */
  claim?: string;
}

export async function startFakeIdJagAs(opts: FakeIdJagAsOptions): Promise<FakeIdJagAs> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "as-1", alg: "ES256", use: "sig" };
  const idpKeys = new Map(opts.trustedIdps.map((i) => [i, createRemoteJWKSet(new URL(`${i}/jwks`))]));
  const usedJti = new Set<string>();
  const links = new Map<string, string>();
  const grants: string[] = [];
  const claimName = opts.claim ?? "id_jag";
  let issuer = "";

  const mint = (c: AccessTokenClaims) =>
    new SignJWT({
      ...(c.client_id !== undefined ? { client_id: c.client_id } : {}),
      ...(c.scope ? { scope: c.scope } : {}),
      ...(c.id_jag ? { [claimName]: c.id_jag } : {}),
      ...(c.extra ?? {}),
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-1", typ: c.typ ?? "at+jwt" })
      .setIssuer(c.iss ?? issuer)
      .setSubject(c.sub)
      .setAudience(c.aud)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + (c.expSec ?? 600))
      .setJti(randomUUID())
      .sign(privateKey);

  const invalidGrant = (res: ServerResponse, why: string) => send(res, 400, { error: "invalid_grant", error_description: why });

  const { server, issuer: iss } = await listen(async (req, res, issuerNow) => {
    const url = new URL(req.url ?? "/", issuerNow);
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return send(res, 200, {
        issuer: issuerNow,
        // No user-facing authorization endpoint is served; listed because
        // RFC 8414 metadata parsers expect one.
        authorization_endpoint: `${issuerNow}/authorize`,
        token_endpoint: `${issuerNow}/token`,
        jwks_uri: `${issuerNow}/jwks`,
        response_types_supported: ["code"],
        grant_types_supported: [JWT_BEARER_GRANT],
        authorization_grant_profiles_supported: [ID_JAG_GRANT_PROFILE],
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
      });
    }
    if (url.pathname === "/jwks") return send(res, 200, { keys: [jwk] });
    if (url.pathname !== "/token" || req.method !== "POST") return send(res, 404, { error: "not_found" });

    const body = await form(req);
    grants.push(body.get("grant_type") ?? "");
    const creds = clientCredentials(req, body);
    if (!creds || opts.clients[creds.id] === undefined || opts.clients[creds.id] !== creds.secret) {
      return send(res, 401, { error: "invalid_client" });
    }
    if (body.get("grant_type") !== JWT_BEARER_GRANT) return send(res, 400, { error: "unsupported_grant_type" });
    const assertion = body.get("assertion") ?? "";

    // draft §4.4.1 processing rules.
    let header: { typ?: string };
    let unverified: JWTPayload;
    try {
      header = decodeProtectedHeader(assertion);
      unverified = decodeJwt(assertion);
    } catch {
      return invalidGrant(res, "assertion is not a JWT");
    }
    if (header.typ !== ID_JAG_TYP) return invalidGrant(res, "assertion is not an ID-JAG");
    const keys = typeof unverified.iss === "string" ? idpKeys.get(unverified.iss) : undefined;
    if (!keys) return invalidGrant(res, "assertion issuer is not trusted");
    let idJag: JWTPayload;
    try {
      ({ payload: idJag } = await jwtVerify(assertion, keys, {
        issuer: unverified.iss as string,
        typ: ID_JAG_TYP,
        requiredClaims: ["sub", "aud", "client_id", "jti", "exp", "iat"],
        clockTolerance: 5,
        maxTokenAge: "10m",
      }));
    } catch {
      return invalidGrant(res, "assertion did not verify");
    }
    // aud: exactly this issuer, as a string or a one-element array.
    const aud = Array.isArray(idJag.aud) ? (idJag.aud.length === 1 ? idJag.aud[0] : undefined) : idJag.aud;
    if (aud !== issuerNow) return invalidGrant(res, "assertion audience is not this authorization server");
    if (idJag.client_id !== creds.id) return invalidGrant(res, "assertion was issued to another client");
    if (usedJti.has(String(idJag.jti))) return invalidGrant(res, "assertion already used");
    usedJti.add(String(idJag.jti));
    // EMA §5.1: the access token is audience-restricted to the ID-JAG's resource.
    const resource = typeof idJag.resource === "string" ? idJag.resource : undefined;
    if (!resource || !opts.resources.includes(resource)) return send(res, 400, { error: "invalid_target" });

    const idpSub = String(idJag.sub);
    const linkKey = `${String(idJag.iss)}\0${idpSub}`;
    const accountId = links.get(linkKey) ?? `acct-${createHash("sha256").update(linkKey).digest("hex").slice(0, 16)}`;
    const scope = typeof idJag.scope === "string" ? idJag.scope : undefined;
    const access_token = await mint({
      sub: accountId,
      aud: resource,
      client_id: creds.id,
      scope,
      id_jag: {
        iss: idJag.iss,
        sub: idpSub,
        jti: idJag.jti,
        ...(typeof idJag.tenant === "string" ? { tenant: idJag.tenant } : {}),
        ...(typeof idJag.email === "string" ? { email: idJag.email } : {}),
      },
    });
    // draft §4.4.2: no refresh token; the client re-presents a fresh ID-JAG.
    return send(res, 200, { access_token, token_type: "Bearer", expires_in: 600, ...(scope ? { scope } : {}) });
  });
  issuer = iss;

  return {
    issuer,
    mint,
    grants,
    linkAccount: (idpIssuer, idpSub, accountId) => { links.set(`${idpIssuer}\0${idpSub}`, accountId); },
    close: () => close(server),
  };
}
