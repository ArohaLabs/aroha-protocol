// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal OAuth 2.1 authorization server for tests: RFC 8414 metadata,
 * JWKS, an auto-approving /authorize (PKCE S256 required, RFC 9207 `iss` on
 * the redirect), and /token issuing audience-bound JWT access tokens.
 * Clients identify with Client ID Metadata Documents: the `client_id` is an
 * https URL looked up in `clientDocuments` (standing in for fetching it).
 * There is deliberately no registration endpoint.
 */

import { createServer, type Server } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

export interface FakeAs {
  issuer: string;
  close(): Promise<void>;
  /** Mint a token directly (bypassing the flow) — for negative tests. */
  mint(claims: { sub: string; aud: string; client_id?: string; scope?: string; expSec?: number }): Promise<string>;
  /** The `sub` the next /authorize approval will be issued for. */
  setUser(sub: string): void;
  requests: string[];
}

export async function startFakeAs(clientDocuments: Record<string, { redirect_uris: string[] }>): Promise<FakeAs> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };
  const codes = new Map<string, { clientId: string; challenge: string; resource: string; redirectUri: string; sub: string; scope?: string }>();
  let user = "alice";
  const requests: string[] = [];
  let issuer = "";

  const mint = (claims: { sub: string; aud: string; client_id?: string; scope?: string; expSec?: number }) =>
    new SignJWT({ client_id: claims.client_id ?? "https://client.example/cimd.json", ...(claims.scope ? { scope: claims.scope } : {}) })
      .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "at+jwt" })
      .setIssuer(issuer)
      .setSubject(claims.sub)
      .setAudience(claims.aud)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + (claims.expSec ?? 600))
      .setJti(randomUUID())
      .sign(privateKey);

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", issuer);
    requests.push(`${req.method} ${url.pathname}`);
    const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...headers });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return send(200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        client_id_metadata_document_supported: true,
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (url.pathname === "/jwks") return send(200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
      const clientId = url.searchParams.get("client_id") ?? "";
      const doc = clientDocuments[clientId];
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      if (!doc || !doc.redirect_uris.includes(redirectUri)) return send(400, { error: "invalid_client" });
      if (url.searchParams.get("code_challenge_method") !== "S256") return send(400, { error: "invalid_request" });
      const code = randomUUID();
      codes.set(code, {
        clientId,
        challenge: url.searchParams.get("code_challenge") ?? "",
        resource: url.searchParams.get("resource") ?? "",
        redirectUri,
        sub: user,
        scope: url.searchParams.get("scope") ?? undefined,
      });
      const loc = new URL(redirectUri);
      loc.searchParams.set("code", code);
      loc.searchParams.set("iss", issuer);
      const state = url.searchParams.get("state");
      if (state) loc.searchParams.set("state", state);
      res.writeHead(302, { Location: loc.href });
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let raw = "";
      for await (const c of req) raw += c;
      const form = new URLSearchParams(raw);
      const entry = codes.get(form.get("code") ?? "");
      if (!entry) return send(400, { error: "invalid_grant" });
      codes.delete(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (challenge !== entry.challenge || form.get("client_id") !== entry.clientId) return send(400, { error: "invalid_grant" });
      const resource = form.get("resource") ?? entry.resource;
      if (!resource) return send(400, { error: "invalid_target" });
      const access_token = await mint({ sub: entry.sub, aud: resource, client_id: entry.clientId, scope: entry.scope });
      return send(200, { access_token, token_type: "Bearer", expires_in: 600, ...(entry.scope ? { scope: entry.scope } : {}) });
    }
    send(404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const addr = server.address();
  issuer = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return {
    issuer,
    mint,
    setUser: (s) => { user = s; },
    requests,
    close: () => new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections?.(); }),
  };
}

/** A free loopback port (listen on 0, read it, close). */
export async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const addr = s.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}
