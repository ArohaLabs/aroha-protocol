// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * createRbacMiddleware and credentialRegistryRoutes. The middleware is a
 * plain (envelope, reject) function, so it is called directly; the routes are
 * mounted on a bare node:http server so the real request/response plumbing
 * (readBody, headers, status codes) is exercised.
 */

import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import type { ArohaEnvelope, ArohaHttpRoute } from "@aroha-sdk/core";
import { createRbacMiddleware, credentialRegistryRoutes } from "./middleware.js";
import { issueHumanCredential, serializeCredential } from "./credentials.js";
import { CredentialRegistry, buildRevokeProof } from "./registry.js";
import { ArohaRole } from "./types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const ISSUER = "did:aroha:issuer";
let issuerPriv: Uint8Array;
let issuerPub: Uint8Array;
beforeAll(async () => {
  issuerPriv = ed.utils.randomPrivateKey();
  issuerPub = await ed.getPublicKeyAsync(issuerPriv);
});
const resolveIssuer = async (did: string) => (did === ISSUER ? issuerPub : null);

function env(type: string, body: Record<string, unknown>, from = "did:aroha:caller"): ArohaEnvelope {
  return { type, from, to: "did:aroha:me", body } as unknown as ArohaEnvelope;
}

async function run(mw: ReturnType<typeof createRbacMiddleware>, e: ArohaEnvelope) {
  let rejected: { status: number; code: string; reason: string } | null = null;
  await mw(e, ((status: number, code: string, reason: string) => { rejected = { status, code, reason }; }) as never);
  return rejected as { status: number; code: string; reason: string } | null;
}

describe("createRbacMiddleware", () => {
  it("allows an agent whose resolved roles permit the action", async () => {
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [ArohaRole.AgentOrchestrator] });
    expect(await run(mw, env("ArohaCommit", {}))).toBeNull();
  });

  it("403s an agent whose roles do not permit the action, 403s an agent with no roles", async () => {
    const mw = createRbacMiddleware({ resolveAgentRoles: (did) => (did === "did:aroha:reader" ? [ArohaRole.AgentObserver] : []) });
    expect(await run(mw, env("ArohaCommit", {}, "did:aroha:reader"))).toMatchObject({ status: 403, code: "Aroha_FORBIDDEN" });
    expect(await run(mw, env("ArohaRequest", {}, "did:aroha:nobody"))).toMatchObject({ status: 403 });
  });

  it("skips RBAC for responses / acks", async () => {
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [] });
    expect(await run(mw, env("ArohaResponse", {}))).toBeNull();
  });

  it("uses a valid human credentialToken's roles", async () => {
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [], resolveIssuerPublicKey: resolveIssuer });
    expect(await run(mw, env("ArohaCommit", { credentialToken: serializeCredential(cred) }))).toBeNull();
    expect(await run(mw, env("ArohaDelegate", { credentialToken: serializeCredential(cred) }))).toMatchObject({ status: 403 });
  });

  it("401s a credentialToken from an unknown issuer, a malformed one, or a tampered one", async () => {
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [], resolveIssuerPublicKey: resolveIssuer });
    const other = ed.utils.randomPrivateKey();
    const foreign = await issueHumanCredential("u1", [ArohaRole.HumanAdmin], "did:aroha:stranger", other);
    expect(await run(mw, env("ArohaRequest", { credentialToken: serializeCredential(foreign) }))).toMatchObject({ status: 401 });
    expect(await run(mw, env("ArohaRequest", { credentialToken: "garbage" }))).toMatchObject({ status: 401 });
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanReadonly], ISSUER, issuerPriv);
    const tampered = serializeCredential({ ...cred, roles: [ArohaRole.HumanAdmin] });
    expect(await run(mw, env("ArohaRequest", { credentialToken: tampered }))).toMatchObject({ status: 401 });
  });

  it("401s a credentialToken when the server accepts no human credentials", async () => {
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [ArohaRole.AgentOrchestrator] });
    expect(await run(mw, env("ArohaRequest", { credentialToken: serializeCredential(cred) }))).toMatchObject({ status: 401 });
  });

  it("credentialId: resolves via the registry and re-verifies the signature", async () => {
    const registry = new CredentialRegistry();
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    expect(await registry.register(cred, issuerPub)).toBe(true);
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [], resolveIssuerPublicKey: resolveIssuer, credentialRegistry: registry });
    expect(await run(mw, env("ArohaCommit", { credentialId: cred.credentialId }))).toBeNull();
    expect(await run(mw, env("ArohaCommit", { credentialId: "nope" }))).toMatchObject({ status: 401 });
  });

  it("credentialId: an UNKNOWN issuer is rejected, not waved through (regression)", async () => {
    const registry = new CredentialRegistry();
    const forged = await issueHumanCredential("u1", [ArohaRole.HumanAdmin], "did:aroha:stranger", ed.utils.randomPrivateKey());
    registry.registerTrusted(forged);
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [], resolveIssuerPublicKey: resolveIssuer, credentialRegistry: registry });
    expect(await run(mw, env("ArohaCommit", { credentialId: forged.credentialId }))).toMatchObject({ status: 401, reason: expect.stringMatching(/Unknown credential issuer/) });
  });

  it("credentialId without a configured registry is refused", async () => {
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [] });
    expect(await run(mw, env("ArohaRequest", { credentialId: "x" }))).toMatchObject({ status: 401 });
  });
});

describe("credentialRegistryRoutes", () => {
  let server: Server | undefined;
  afterEach(() => { server?.close(); server = undefined; });

  async function serve(routes: ArohaHttpRoute[]): Promise<string> {
    server = createServer(async (req, res) => {
      const route = routes.find((r) => r.method === req.method && r.test(req.url ?? ""));
      if (!route) { res.writeHead(404); res.end(); return; }
      await route.handle(req, res);
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const addr = server.address() as { port: number };
    return `http://127.0.0.1:${addr.port}`;
  }

  it("registers a correctly signed credential, resolves and lists it", async () => {
    const registry = new CredentialRegistry();
    const base = await serve(credentialRegistryRoutes(registry, { resolveIssuerPublicKey: resolveIssuer }));
    const cred = await issueHumanCredential("user-7", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const post = await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify(cred) });
    expect(post.status).toBe(201);
    expect(await post.json()).toEqual({ credentialId: cred.credentialId, stored: true });
    const got = await fetch(`${base}/aroha/credentials/${cred.credentialId}`);
    expect((await got.json()).userId).toBe("user-7");
    const list = await fetch(`${base}/aroha/credentials?userId=user-7`);
    expect(((await list.json()) as unknown[]).length).toBe(1);
  });

  it("rejects a bad signature (400), unknown issuer (401), bad JSON (400), list without userId (400)", async () => {
    const base = await serve(credentialRegistryRoutes(new CredentialRegistry(), { resolveIssuerPublicKey: resolveIssuer }));
    const cred = await issueHumanCredential("u", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify({ ...cred, roles: [ArohaRole.HumanAdmin] }) })).status).toBe(400);
    const foreign = await issueHumanCredential("u", [ArohaRole.HumanUser], "did:aroha:stranger", ed.utils.randomPrivateKey());
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify(foreign) })).status).toBe(401);
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: "{" })).status).toBe(400);
    expect((await fetch(`${base}/aroha/credentials`)).status).toBe(400);
    expect((await fetch(`${base}/aroha/credentials/missing`)).status).toBe(404);
  });

  it("revocation needs a valid X-Revoke-Proof from the issuer", async () => {
    const registry = new CredentialRegistry();
    const base = await serve(credentialRegistryRoutes(registry, { resolveIssuerPublicKey: resolveIssuer }));
    const cred = await issueHumanCredential("u", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    await registry.register(cred, issuerPub);
    const url = `${base}/aroha/credentials/${cred.credentialId}`;
    expect((await fetch(url, { method: "DELETE" })).status).toBe(401);
    const wrong = await buildRevokeProof(cred.credentialId, ed.utils.randomPrivateKey());
    expect((await fetch(url, { method: "DELETE", headers: { "X-Revoke-Proof": wrong } })).status).toBe(403);
    const proof = await buildRevokeProof(cred.credentialId, issuerPriv);
    const ok = await fetch(url, { method: "DELETE", headers: { "X-Revoke-Proof": proof } });
    expect(ok.status).toBe(200);
    expect(registry.resolve(cred.credentialId)).toBeNull();
  });
});

describe("fail closed without an issuer key resolver (M5)", () => {
  let server: Server | undefined;
  afterEach(() => { server?.close(); server = undefined; });

  async function serve(routes: ArohaHttpRoute[]): Promise<string> {
    server = createServer(async (req, res) => {
      const route = routes.find((r) => r.method === req.method && r.test(req.url ?? ""));
      if (!route) { res.writeHead(404); res.end(); return; }
      await route.handle(req, res);
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  }

  it("register and revoke answer 401 when resolveIssuerPublicKey is not configured", async () => {
    const registry = new CredentialRegistry();
    const cred = await issueHumanCredential("u", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    registry.registerTrusted(cred);
    const base = await serve(credentialRegistryRoutes(registry));
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify(cred) })).status).toBe(401);
    expect((await fetch(`${base}/aroha/credentials/${cred.credentialId}`, { method: "DELETE" })).status).toBe(401);
    expect(registry.resolve(cred.credentialId)).not.toBeNull();
  });

  it("allowUnverifiedCredentials restores the old dev behaviour", async () => {
    const registry = new CredentialRegistry();
    const cred = await issueHumanCredential("u", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const base = await serve(credentialRegistryRoutes(registry, { allowUnverifiedCredentials: true }));
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify(cred) })).status).toBe(201);
    expect((await fetch(`${base}/aroha/credentials/${cred.credentialId}`, { method: "DELETE" })).status).toBe(200);
  });

  it("refuses a credential with an unknown role (400)", async () => {
    const base = await serve(credentialRegistryRoutes(new CredentialRegistry(), { resolveIssuerPublicKey: resolveIssuer }));
    const cred = await issueHumanCredential("u", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const bad = { ...cred, roles: ["human:superuser"] };
    expect((await fetch(`${base}/aroha/credentials`, { method: "POST", body: JSON.stringify(bad) })).status).toBe(400);
  });

  it("checkRbac refuses a registry credentialId with no resolver unless allowUnverifiedCredentials", async () => {
    const registry = new CredentialRegistry();
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    registry.registerTrusted(cred);
    const strict = createRbacMiddleware({ resolveAgentRoles: () => [], credentialRegistry: registry });
    expect(await run(strict, env("ArohaCommit", { credentialId: cred.credentialId }))).toMatchObject({ status: 401 });
    const dev = createRbacMiddleware({ resolveAgentRoles: () => [], credentialRegistry: registry, allowUnverifiedCredentials: true });
    expect(await run(dev, env("ArohaCommit", { credentialId: cred.credentialId }))).toBeNull();
  });

  it("an unparseable expiry is treated as expired (M4)", async () => {
    const cred = await issueHumanCredential("u1", [ArohaRole.HumanUser], ISSUER, issuerPriv);
    const mw = createRbacMiddleware({ resolveAgentRoles: () => [], resolveIssuerPublicKey: resolveIssuer });
    const bad = serializeCredential({ ...cred, expiresAt: "not-a-date" });
    expect(await run(mw, env("ArohaRequest", { credentialToken: bad }))).toMatchObject({ status: 401, reason: expect.stringMatching(/expir/) });
    const registry = new CredentialRegistry();
    registry.registerTrusted({ ...cred, expiresAt: "not-a-date" });
    expect(registry.resolve(cred.credentialId)).toBeNull();
  });
});
