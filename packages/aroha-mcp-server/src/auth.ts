// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * OAuth 2.1 resource-server pieces for the HTTP transport.
 *
 *   - `jwtAccessTokenVerifier`: validates JWT access tokens against the
 *     configured authorization server's JWKS — signature, `iss`, `aud`
 *     (audience-bound: a token minted for any other resource is refused),
 *     `exp`/`nbf`, and a `sub`. Pluggable: anything implementing the SDK's
 *     `OAuthTokenVerifier` can replace it (introspection, opaque tokens).
 *   - `protectedResourceMetadata`: the RFC 9728 document.
 *
 * No token passthrough: the bearer token authenticates the caller to THIS
 * server only. It is never forwarded to the registry or to agents; outbound
 * calls use the server's own credentials and the principal's signing key.
 *
 * Client identity: clients are expected to identify with a Client ID Metadata
 * Document (an https URL as `client_id`). The server offers no Dynamic
 * Client Registration endpoint. `allowedClientIds` / `requireClientIdMetadataDocument`
 * let an operator restrict which clients may call.
 *
 * Enterprise-Managed Authorization: with `enterprise` set, a token the
 * authorization server issued from an ID-JAG is mapped to the enterprise
 * identity it carries (see enterprise.ts), and `enterprise.required` refuses
 * every other token. An ID-JAG itself (`typ: oauth-id-jag+jwt`) is a grant
 * for the authorization server and is always refused here.
 */

import { createRemoteJWKSet, customFetch, jwtVerify, errors as joseErrors, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { OAuthError, OAuthErrorCode, type AuthInfo, type OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { ID_JAG_TYP, readEnterpriseIdentity, type EnterpriseAuthOptions } from "./enterprise.js";

export interface JwtVerifierOptions {
  /** Expected `iss` (exact string). */
  issuer: string;
  /** Expected `aud` — this server's canonical resource URL. */
  audience: string;
  /** JWKS URL; discovered from the issuer's metadata when omitted. */
  jwksUrl?: string;
  /** Accepted JWS algorithms. */
  algorithms?: string[];
  /** Only these client ids may call (exact match). */
  allowedClientIds?: string[];
  /** Refuse client ids that are not https URLs with a path (CIMD form). */
  requireClientIdMetadataDocument?: boolean;
  /** Clock tolerance in seconds. Default 30. */
  clockToleranceSec?: number;
  /** Accept access tokens issued from an ID-JAG (Enterprise-Managed Authorization). */
  enterprise?: EnterpriseAuthOptions;
  /** Inject a key source (tests) instead of fetching the JWKS. */
  keySource?: JWTVerifyGetKey;
  fetch?: typeof fetch;
}

/** Whether `clientId` has the Client ID Metadata Document form: an https URL with a non-root path. */
export function isClientIdMetadataDocumentUrl(clientId: string): boolean {
  try {
    const u = new URL(clientId);
    return u.protocol === "https:" && u.pathname.length > 1 && !u.hash;
  } catch {
    return false;
  }
}

/**
 * RFC 8414 well-known locations for an issuer (path-aware), then the OIDC
 * discovery locations.
 */
export function authorizationServerMetadataUrls(issuer: string): string[] {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/+$/, "");
  const origin = u.origin;
  return path
    ? [
        `${origin}/.well-known/oauth-authorization-server${path}`,
        `${origin}/.well-known/openid-configuration${path}`,
        `${origin}${path}/.well-known/openid-configuration`,
      ]
    : [`${origin}/.well-known/oauth-authorization-server`, `${origin}/.well-known/openid-configuration`];
}

async function discoverJwksUrl(issuer: string, doFetch: typeof fetch): Promise<string> {
  for (const url of authorizationServerMetadataUrls(issuer)) {
    let res: Response;
    try {
      res = await doFetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
    } catch {
      continue;
    }
    if (!res.ok) continue;
    const meta = (await res.json().catch(() => null)) as { issuer?: unknown; jwks_uri?: unknown } | null;
    if (!meta) continue;
    // RFC 8414 §3.3: the metadata must name the issuer it was fetched for.
    if (meta.issuer !== issuer) throw new Error(`authorization server metadata at ${url} names issuer ${String(meta.issuer)}, expected ${issuer}`);
    if (typeof meta.jwks_uri !== "string") throw new Error(`authorization server metadata at ${url} has no jwks_uri`);
    return meta.jwks_uri;
  }
  throw new Error(`could not discover authorization server metadata for ${issuer}`);
}

function invalid(message: string): OAuthError {
  return new OAuthError(OAuthErrorCode.InvalidToken, message);
}

function scopesOf(payload: JWTPayload): string[] {
  const scope = payload.scope;
  if (typeof scope === "string") return scope.split(" ").filter(Boolean);
  const scp = (payload as { scp?: unknown }).scp;
  if (Array.isArray(scp)) return scp.filter((s): s is string => typeof s === "string");
  return [];
}

/**
 * A JWT access-token verifier for the SDK's bearer-auth gate. The returned
 * AuthInfo carries `resource` (from `aud`, so the gate's `expectedResource`
 * comparison runs) and `extra.sub` / `extra.iss` (the principal), plus
 * `extra.enterprise` for a token issued from an ID-JAG.
 */
export function jwtAccessTokenVerifier(options: JwtVerifierOptions): OAuthTokenVerifier {
  const doFetch = options.fetch ?? fetch;
  const algorithms = options.algorithms ?? ["RS256", "ES256", "EdDSA"];
  let keySource: Promise<JWTVerifyGetKey> | null = options.keySource ? Promise.resolve(options.keySource) : null;
  const getKeySource = (): Promise<JWTVerifyGetKey> => {
    if (!keySource) {
      keySource = (async () => {
        const jwksUrl = options.jwksUrl ?? (await discoverJwksUrl(options.issuer, doFetch));
        return createRemoteJWKSet(new URL(jwksUrl), { [customFetch]: doFetch });
      })();
      // Do not pin a failed discovery: retry on the next request.
      keySource.catch(() => { keySource = null; });
    }
    return keySource;
  };

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      let payload: JWTPayload;
      let typ: string | undefined;
      try {
        const keys = await getKeySource();
        let protectedHeader: { typ?: string };
        ({ payload, protectedHeader } = await jwtVerify(token, keys, {
          issuer: options.issuer,
          audience: options.audience,
          algorithms,
          clockTolerance: options.clockToleranceSec ?? 30,
          requiredClaims: ["exp", "sub"],
        }));
        typ = protectedHeader.typ;
      } catch (err) {
        if (err instanceof joseErrors.JOSEError) throw invalid(`access token rejected: ${err.code}`);
        if (err instanceof OAuthError) throw err;
        // Key discovery failed: we could not check the token. 401 still — a
        // token that cannot be verified is not accepted.
        throw invalid("access token could not be verified");
      }
      if (typeof payload.sub !== "string" || payload.sub.length === 0) throw invalid("access token has no subject");
      if (typeof payload.exp !== "number") throw invalid("access token has no expiry");
      // An ID-JAG is presented to the authorization server, never to a
      // resource server (draft-ietf-oauth-identity-assertion-authz-grant §4.4).
      if (typeof typ === "string" && typ.toLowerCase().replace(/^application\//, "") === ID_JAG_TYP) {
        throw invalid("an identity assertion grant is not an access token");
      }

      const clientId = typeof (payload as { client_id?: unknown }).client_id === "string"
        ? (payload as { client_id: string }).client_id
        : typeof payload.azp === "string" ? payload.azp : "";
      if (options.requireClientIdMetadataDocument && !isClientIdMetadataDocumentUrl(clientId)) {
        throw invalid("client is not identified by a Client ID Metadata Document URL");
      }
      if (options.allowedClientIds && !options.allowedClientIds.includes(clientId)) {
        throw invalid("client is not allowed at this resource");
      }

      let enterprise: Record<string, unknown> | undefined;
      if (options.enterprise) {
        const outcome = readEnterpriseIdentity(payload as Record<string, unknown>, { authorizationServer: options.issuer, clientId }, options.enterprise);
        if (outcome.kind === "refused") throw invalid(`enterprise token rejected: ${outcome.reason}`);
        if (outcome.kind === "absent" && options.enterprise.required) {
          throw invalid("this server requires Enterprise-Managed Authorization (a token issued from an ID-JAG)");
        }
        if (outcome.kind === "enterprise") enterprise = { ...outcome.identity };
      }

      return {
        token,
        clientId,
        scopes: scopesOf(payload),
        expiresAt: payload.exp,
        // jwtVerify already required `aud` to include our audience; surface it
        // so the SDK gate's expectedResource comparison also holds.
        resource: new URL(options.audience),
        extra: { sub: payload.sub, iss: payload.iss, ...(enterprise ? { enterprise } : {}) },
      };
    },
  };
}

/** RFC 9728 protected-resource metadata for this server. */
export function protectedResourceMetadata(opts: {
  resource: string;
  issuer: string;
  scopesSupported?: string[];
  resourceName?: string;
  documentationUrl?: string;
}): Record<string, unknown> {
  return {
    resource: opts.resource,
    authorization_servers: [opts.issuer],
    bearer_methods_supported: ["header"],
    ...(opts.scopesSupported && opts.scopesSupported.length > 0 ? { scopes_supported: opts.scopesSupported } : {}),
    resource_name: opts.resourceName ?? "Aroha MCP connector",
    ...(opts.documentationUrl ? { resource_documentation: opts.documentationUrl } : {}),
  };
}
