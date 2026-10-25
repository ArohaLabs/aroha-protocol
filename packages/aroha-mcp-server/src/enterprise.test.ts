// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Enterprise-Managed Authorization (ID-JAG), resource-server side:
 *   - the access-token verifier: enterprise tokens accepted and mapped to the
 *     enterprise subject; expired, wrong-audience, wrong-issuer, untrusted-IdP,
 *     malformed and unenforceable tokens refused; a raw ID-JAG refused;
 *     ordinary tokens unchanged unless enterprise mode is required
 *   - configuration fails closed
 *   - end to end with a stock SDK client (CrossAppAccessProvider): IdP token
 *     exchange → ID-JAG → JWT bearer grant at the authorization server →
 *     access token → MCP calls signed with the enterprise user's own key,
 *     and mandates that report the enterprise subject as their root
 *   - the test-only reference authorization server applies the draft's
 *     §4.4.1 checks to the ID-JAG (expired, wrong audience, untrusted issuer,
 *     wrong client, wrong typ, replay)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { OAuthError, type AuthInfo } from "@modelcontextprotocol/server";
import {
  Client,
  CrossAppAccessProvider,
  StreamableHTTPClientTransport,
  exchangeJwtAuthGrant,
  requestJwtAuthorizationGrant,
} from "@modelcontextprotocol/client";
import { jwtAccessTokenVerifier } from "./auth.js";
import { loadConfig } from "./config.js";
import { ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION, ID_JAG_TYP, enterprisePrincipal, type EnterpriseAuthOptions } from "./enterprise.js";
import { FilePrincipalKeyStore, principalFromToken } from "./keystore.js";
import { createRuntime, principalFromAuthInfo } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { freePort } from "./test-utils/fake-as.js";
import { startFakeIdJagAs, startFakeIdp, type FakeIdJagAs, type FakeIdp } from "./test-utils/fake-enterprise.js";

// ─── verifier ─────────────────────────────────────────────────────────────────

const AS = "https://auth.example.com";
const RES = "https://mcp.example.com/mcp";
const IDP = "https://idp.corp.example";
const CLIENT = "https://client.example/cimd.json";

describe("access-token verifier with Enterprise-Managed Authorization", () => {
  let sign: (claims: Record<string, unknown>, opts?: { iss?: string; aud?: string; expSec?: number; typ?: string; key?: "as" | "other" }) => Promise<string>;
  let keySource: ReturnType<typeof createLocalJWKSet>;

  beforeAll(async () => {
    const as = await generateKeyPair("ES256");
    const other = await generateKeyPair("ES256");
    const jwk: JWK = { ...(await exportJWK(as.publicKey)), kid: "as-1", alg: "ES256" };
    keySource = createLocalJWKSet({ keys: [jwk] });
    sign = (claims, o = {}) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "ES256", kid: "as-1", typ: o.typ ?? "at+jwt" })
        .setIssuer(o.iss ?? AS)
        .setAudience(o.aud ?? RES)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + (o.expSec ?? 600))
        .sign(o.key === "other" ? other.privateKey : as.privateKey);
  });

  const verifier = (enterprise?: EnterpriseAuthOptions) => jwtAccessTokenVerifier({ issuer: AS, audience: RES, keySource, enterprise });
  const ent = (over: Partial<EnterpriseAuthOptions> = {}): EnterpriseAuthOptions =>
    ({ trustedIdps: [{ issuer: IDP }], required: false, claim: "id_jag", ...over });
  const idJag = (over: Record<string, unknown> = {}) => ({ iss: IDP, sub: "U019488227", jti: "jag-1", ...over });
  const refused = async (p: Promise<AuthInfo>, pattern: RegExp) => {
    const err = await p.then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthError);
    expect((err as Error).message).toMatch(pattern);
  };

  it("maps an enterprise token to the enterprise subject, not the authorization server's account id", async () => {
    const info = await verifier(ent()).verifyAccessToken(await sign({ sub: "acct-1", client_id: CLIENT, id_jag: idJag() }));
    const e = info.extra?.enterprise as Record<string, unknown>;
    expect(e).toMatchObject({ idpIssuer: IDP, subject: "U019488227", idJagId: "jag-1", authorizationServer: AS, clientId: CLIENT });
    const principal = principalFromAuthInfo(info);
    expect(principal).toBe(enterprisePrincipal({ idpIssuer: IDP, subject: "U019488227" }));
    expect(principal).not.toBe(principalFromToken(AS, "acct-1"));

    // The same employee after the authorization server re-links the account: same principal (same key).
    const relinked = await verifier(ent()).verifyAccessToken(await sign({ sub: "acct-2", client_id: CLIENT, id_jag: idJag({ jti: "jag-2" }) }));
    expect(principalFromAuthInfo(relinked)).toBe(principal);
    // Another employee: another principal.
    const other = await verifier(ent()).verifyAccessToken(await sign({ sub: "acct-1", client_id: CLIENT, id_jag: idJag({ sub: "U2" }) }));
    expect(principalFromAuthInfo(other)).not.toBe(principal);
  });

  it("keeps ordinary tokens unchanged unless enterprise mode is required", async () => {
    const token = await sign({ sub: "alice", client_id: CLIENT });
    const plain = await verifier().verifyAccessToken(token);
    expect(plain.extra).toEqual({ sub: "alice", iss: AS });
    expect(principalFromAuthInfo(plain)).toBe(principalFromToken(AS, "alice"));
    const optional = await verifier(ent()).verifyAccessToken(token);
    expect(principalFromAuthInfo(optional)).toBe(principalFromToken(AS, "alice"));
    await refused(verifier(ent({ required: true })).verifyAccessToken(token), /requires Enterprise-Managed Authorization/);
    // Without enterprise configuration the claim is not interpreted at all.
    const ignored = await verifier().verifyAccessToken(await sign({ sub: "alice", client_id: CLIENT, id_jag: idJag() }));
    expect(ignored.extra?.enterprise).toBeUndefined();
  });

  it("refuses expired, wrong-audience, wrong-issuer and foreign-key enterprise tokens", async () => {
    const v = verifier(ent({ required: true }));
    const claims = { sub: "acct-1", client_id: CLIENT, id_jag: idJag() };
    await refused(v.verifyAccessToken(await sign(claims, { expSec: -120 })), /rejected/);
    await refused(v.verifyAccessToken(await sign(claims, { aud: "https://other.example/mcp" })), /rejected/);
    await refused(v.verifyAccessToken(await sign(claims, { iss: "https://evil.example" })), /rejected/);
    await refused(v.verifyAccessToken(await sign(claims, { key: "other" })), /rejected/);
  });

  it("refuses a raw ID-JAG presented as an access token, even one aimed at this server", async () => {
    const raw = await sign({ sub: "U019488227", client_id: CLIENT, jti: "j", id_jag: idJag() }, { typ: ID_JAG_TYP });
    await refused(verifier(ent()).verifyAccessToken(raw), /not an access token/);
    await refused(verifier().verifyAccessToken(raw), /not an access token/);
    const mediaType = await sign({ sub: "U", client_id: CLIENT }, { typ: `application/${ID_JAG_TYP}` });
    await refused(verifier().verifyAccessToken(mediaType), /not an access token/);
  });

  it("refuses untrusted IdPs, untrusted tenants and malformed enterprise claims", async () => {
    const v = verifier(ent());
    const t = (id_jag: unknown, extra: Record<string, unknown> = {}) => sign({ sub: "acct-1", client_id: CLIENT, id_jag, ...extra });
    await refused(v.verifyAccessToken(await t(idJag({ iss: "https://idp.attacker.example" }))), /not trusted/);
    await refused(v.verifyAccessToken(await t(idJag({ sub: "" }))), /sub is missing/);
    await refused(v.verifyAccessToken(await t(idJag({ jti: undefined }))), /jti is missing/);
    await refused(v.verifyAccessToken(await t("U019488227")), /not an object/);
    await refused(v.verifyAccessToken(await sign({ sub: "acct-1", id_jag: idJag() })), /does not name its client/);

    const pinned = verifier(ent({ trustedIdps: [{ issuer: IDP, tenants: ["acme"] }] }));
    await refused(pinned.verifyAccessToken(await t(idJag())), /tenant is not trusted/);
    await refused(pinned.verifyAccessToken(await t(idJag({ tenant: "globex" }))), /tenant is not trusted/);
    const ok = await pinned.verifyAccessToken(await t(idJag({ tenant: "acme" })));
    expect(principalFromAuthInfo(ok)).toBe(enterprisePrincipal({ idpIssuer: IDP, tenant: "acme", subject: "U019488227" }));
    // Tenants partition subjects: the same sub in another tenant is another principal.
    expect(principalFromAuthInfo(ok)).not.toBe(enterprisePrincipal({ idpIssuer: IDP, subject: "U019488227" }));
  });

  it("refuses guest-grant claims this server cannot enforce (profile: aroha_on_behalf_of, aroha_room_id)", async () => {
    const v = verifier(ent());
    await refused(v.verifyAccessToken(await sign({ sub: "a", client_id: CLIENT, id_jag: idJag(), aroha_on_behalf_of: "did:aroha:x" })), /cannot enforce/);
    await refused(v.verifyAccessToken(await sign({ sub: "a", client_id: CLIENT, id_jag: idJag({ aroha_room_id: "r1" }) })), /cannot be enforced/);
    const withMandate = await v.verifyAccessToken(await sign({ sub: "a", client_id: CLIENT, id_jag: idJag({ aroha_mandate_id: "m-1" }) }));
    expect((withMandate.extra?.enterprise as { mandateId?: string }).mandateId).toBe("m-1");
  });
});

// ─── configuration ────────────────────────────────────────────────────────────

describe("enterprise configuration", () => {
  const base = { AROHA_MCP_TRANSPORT: "http", AROHA_MCP_ALLOW_UNAUTHENTICATED: "1", AROHA_REGISTRY_URL: "http://127.0.0.1:9/r" };

  it("fails closed", () => {
    expect(() => loadConfig({ ...base, AROHA_MCP_ENTERPRISE_IDPS: IDP })).toThrow(/needs an authorization server/);
    expect(() => loadConfig({ ...base, AROHA_MCP_AUTH_ISSUER: AS, AROHA_MCP_ENTERPRISE_REQUIRED: "1" })).toThrow(/at least one trusted identity provider/);
    expect(() => loadConfig({ ...base, AROHA_MCP_AUTH_ISSUER: AS, AROHA_MCP_ENTERPRISE_IDPS: IDP, AROHA_MCP_ENTERPRISE_CLAIM: "sub" })).toThrow(/not a usable claim/);
    expect(() => loadConfig({ ...base, AROHA_MCP_AUTH_ISSUER: AS }, { file: { auth: { issuer: AS, enterprise: { trustedIdps: [{ issuer: IDP, tenants: [] }] } } } })).toThrow(/tenants/);
    const c = loadConfig({ ...base, AROHA_MCP_AUTH_ISSUER: AS, AROHA_MCP_ENTERPRISE_IDPS: `${IDP} https://idp2.example`, AROHA_MCP_ENTERPRISE_REQUIRED: "1" });
    expect(c.auth?.enterprise).toEqual({ trustedIdps: [{ issuer: IDP }, { issuer: "https://idp2.example" }], required: true, claim: "id_jag" });
    expect(loadConfig({ ...base, AROHA_MCP_AUTH_ISSUER: AS }).auth?.enterprise).toBeUndefined();
  });
});

// ─── end to end ───────────────────────────────────────────────────────────────

const IDP_CLIENT = "chat-app-at-idp";
const IDP_SECRET = "idp-secret";
const AS_CLIENT = "chat-app-at-as";
const AS_SECRET = "as-secret";

describe("Enterprise-Managed Authorization end to end (stock SDK client, reference IdP and authorization server)", () => {
  let idp: FakeIdp;
  let as: FakeIdJagAs;
  let mcp: RunningHttpServer;
  let keysDir: string;
  let publicUrl: string;

  beforeAll(async () => {
    const port = await freePort();
    publicUrl = `http://127.0.0.1:${port}/mcp`;
    // The IdP's policy names the authorization server, which only has an
    // issuer once it listens: start the IdP, then fill its policy in.
    const policy = { clients: { [IDP_CLIENT]: { secret: IDP_SECRET, clientIdAt: {} as Record<string, string> } }, allowedAudiences: [] as string[] };
    idp = await startFakeIdp(policy);
    as = await startFakeIdJagAs({ clients: { [AS_CLIENT]: AS_SECRET }, trustedIdps: [idp.issuer], resources: [publicUrl] });
    policy.allowedAudiences.push(as.issuer);
    policy.clients[IDP_CLIENT].clientIdAt[as.issuer] = AS_CLIENT;

    keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-ema-"));
    const config = loadConfig({
      AROHA_MCP_TRANSPORT: "http",
      AROHA_MCP_PORT: String(port),
      AROHA_MCP_PUBLIC_URL: publicUrl,
      AROHA_MCP_AUTH_ISSUER: as.issuer,
      AROHA_MCP_ENTERPRISE_IDPS: idp.issuer,
      AROHA_MCP_ENTERPRISE_REQUIRED: "1",
      AROHA_MCP_KEY_DIR: keysDir,
      AROHA_REGISTRY_URL: "http://127.0.0.1:9/registry",
    });
    mcp = await startHttpServer({ runtime: createRuntime(config, new FilePrincipalKeyStore(config.keysDir)), log: () => {} });
  });

  afterAll(async () => {
    await mcp?.close();
    await as?.close();
    await idp?.close();
    // keysDir came from mkdtempSync above.
    if (keysDir) rmSync(keysDir, { recursive: true, force: true });
  });

  async function connectAs(employee: string): Promise<Client> {
    const idToken = await idp.idToken(employee, IDP_CLIENT);
    const provider = new CrossAppAccessProvider({
      clientId: AS_CLIENT,
      clientSecret: AS_SECRET,
      expectedIssuer: as.issuer,
      assertion: async (ctx) => (await requestJwtAuthorizationGrant({
        tokenEndpoint: `${idp.issuer}/token`,
        audience: ctx.authorizationServerUrl,
        resource: ctx.resourceUrl,
        idToken,
        clientId: IDP_CLIENT,
        clientSecret: IDP_SECRET,
        scope: ctx.scope,
        fetchFn: ctx.fetchFn,
      })).jwtAuthGrant,
    });
    const client = new Client({ name: "ema-client", version: "1" }, { capabilities: { elicitation: { form: {} } }, versionNegotiation: { mode: { pin: "2026-07-28" } } });
    client.setRequestHandler("elicitation/create", async () => ({ action: "accept", content: { approve: true } }));
    await client.connect(new StreamableHTTPClientTransport(new URL(publicUrl), { authProvider: provider }));
    return client;
  }

  const issueMandate = async (c: Client) => JSON.parse(((await c.callTool({
    name: "aroha_issue_task_mandate", arguments: { agentDid: "did:aroha:x", allowed: ["read"] },
  })).content[0] as { text: string }).text) as { grantorDid: string; grantorRoot?: Record<string, unknown> };

  it("signs as the enterprise user, rooted in the IdP subject", async () => {
    const alice = await connectAs("U-alice");
    expect(idp.exchanges).toContain(as.issuer); // ID-JAG audience = the authorization server's issuer
    expect(as.grants).toContain("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const discover = await alice.discover();
    expect(discover.capabilities.extensions?.[ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION]).toEqual({});

    const m1 = await issueMandate(alice);
    expect(m1.grantorDid).toMatch(/^did:aroha:z/);
    expect(m1.grantorRoot).toMatchObject({ kind: "enterprise", grantorDid: m1.grantorDid, idpIssuer: idp.issuer, subject: "U-alice", authorizationServer: as.issuer, clientId: AS_CLIENT });
    expect(typeof m1.grantorRoot?.idJagId).toBe("string");
    await alice.close();

    // The key is the one the store holds for the enterprise principal.
    const store = new FilePrincipalKeyStore(keysDir);
    expect((await store.get(enterprisePrincipal({ idpIssuer: idp.issuer, subject: "U-alice" }))).did).toBe(m1.grantorDid);

    // Same employee, new session, account re-linked at the AS: same key.
    as.linkAccount(idp.issuer, "U-alice", "acct-renamed");
    const again = await connectAs("U-alice");
    expect((await issueMandate(again)).grantorDid).toBe(m1.grantorDid);
    await again.close();

    const bob = await connectAs("U-bob");
    expect((await issueMandate(bob)).grantorDid).not.toBe(m1.grantorDid);
    await bob.close();
  });

  it("refuses ordinary, expired, wrong-audience and wrong-issuer tokens and raw ID-JAGs with 401", async () => {
    const post = (token: string) => fetch(publicUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    const idJagClaim = { iss: idp.issuer, sub: "U-x", jti: "j-1" };
    const cases = [
      await as.mint({ sub: "plain-user", aud: publicUrl, client_id: AS_CLIENT }), // not from an ID-JAG
      await as.mint({ sub: "a", aud: publicUrl, client_id: AS_CLIENT, id_jag: idJagClaim, expSec: -120 }),
      await as.mint({ sub: "a", aud: "https://other.example/mcp", client_id: AS_CLIENT, id_jag: idJagClaim }),
      await as.mint({ sub: "a", aud: publicUrl, iss: "https://not-our-as.example", client_id: AS_CLIENT, id_jag: idJagClaim }),
      await as.mint({ sub: "a", aud: publicUrl, client_id: AS_CLIENT, id_jag: { ...idJagClaim, iss: "https://idp.attacker.example" } }),
      await idp.mintIdJag({ sub: "U-x", aud: publicUrl, client_id: AS_CLIENT, resource: publicUrl }),
    ];
    for (const token of cases) {
      const res = await post(token);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toMatch(/invalid_token/);
    }
  });

  it("reference authorization server applies the ID-JAG processing rules (test helper)", async () => {
    const exchange = (jwtAuthGrant: string, client = AS_CLIENT, secret = AS_SECRET) =>
      exchangeJwtAuthGrant({ tokenEndpoint: `${as.issuer}/token`, jwtAuthGrant, clientId: client, clientSecret: secret });
    const good = { sub: "U-y", aud: as.issuer, client_id: AS_CLIENT, resource: publicUrl };
    await expect(exchange(await idp.mintIdJag({ ...good, expSec: -120, iatOffsetSec: -600 }))).rejects.toThrow(/invalid_grant/);
    await expect(exchange(await idp.mintIdJag({ ...good, aud: "https://another-as.example" }))).rejects.toThrow(/invalid_grant/);
    await expect(exchange(await idp.mintIdJag({ ...good, aud: [as.issuer, "https://another-as.example"] }))).rejects.toThrow(/invalid_grant/);
    await expect(exchange(await idp.mintIdJag({ ...good, client_id: "someone-else" }))).rejects.toThrow(/invalid_grant/);
    await expect(exchange(await idp.mintIdJag({ ...good, typ: "JWT" }))).rejects.toThrow(/invalid_grant/);
    await expect(exchange(await idp.mintIdJag({ ...good, resource: "https://other.example/mcp" }))).rejects.toThrow(/invalid_target/);
    // An ID-JAG signed by an IdP this authorization server does not trust.
    const rogue = await startFakeIdp({ clients: {}, allowedAudiences: [] });
    try {
      await expect(exchange(await rogue.mintIdJag(good))).rejects.toThrow(/invalid_grant/);
    } finally {
      await rogue.close();
    }
    const once = await idp.mintIdJag({ ...good, aud: [as.issuer] });
    const tokens = await exchange(once);
    expect(tokens.access_token).toBeTruthy();
    await expect(exchange(once)).rejects.toThrow(/invalid_grant/); // single use
  });
});
