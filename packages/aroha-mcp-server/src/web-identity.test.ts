// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * verify_mandate and web identities (spec §4.7): off unless the operator
 * turns them on; when on, the grantor's key comes from the document at its
 * https URL, fetched through safeFetch (no private addresses) and limited to
 * the configured hosts.
 */

import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { buildWebIdentityDocument, issueIntentMandate, issueTaskMandate } from "@aroha-sdk/credentials/mandates";
import { loadConfig } from "./config.js";
import { FilePrincipalKeyStore } from "./keystore.js";
import { createRuntime } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { freePort } from "./test-utils/fake-as.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const HUMAN = "https://accounts.example.com/people/kiri";
const ASSISTANT = "https://agents.example.com/assistant";

const servers: RunningHttpServer[] = [];
const dirs: string[] = [];

afterAll(async () => {
  for (const s of servers) await s.close();
  // Every entry came from mkdtempSync below.
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function start(env: Record<string, string>, opts: Parameters<typeof createRuntime>[2] = {}): Promise<Client> {
  const keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-webid-"));
  dirs.push(keysDir);
  const config = loadConfig({
    AROHA_MCP_TRANSPORT: "http",
    AROHA_MCP_PORT: String(await freePort()),
    AROHA_MCP_ALLOW_UNAUTHENTICATED: "1",
    AROHA_MCP_KEY_DIR: keysDir,
    AROHA_REGISTRY_URL: "http://127.0.0.1:9/registry", // never reached: isRevoked is supplied
    ...env,
  });
  const mcp = await startHttpServer({ runtime: createRuntime(config, new FilePrincipalKeyStore(config.keysDir), { isRevoked: async () => false, log: () => {}, ...opts }), log: () => {} });
  servers.push(mcp);
  const c = new Client({ name: "t", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  await c.connect(new StreamableHTTPClientTransport(new URL(mcp.url)));
  return c;
}

/** A fetch serving one identity document per URL, 404 otherwise. */
function serve(identities: Record<string, Uint8Array>) {
  const calls: string[] = [];
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const publicKey = identities[url];
    if (!publicKey) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(buildWebIdentityDocument({ identity: url, publicKey })), { status: 200 });
  };
  return { fetch: impl as typeof fetch, calls };
}

async function verify(c: Client, token: string, expectedGrantee?: string) {
  const r = await c.callTool({ name: "verify_mandate", arguments: { token, ...(expectedGrantee ? { expectedGrantee } : {}) } });
  return JSON.parse((r.content as { text: string }[])[0].text) as { valid: boolean; kind?: string; reason?: string; rootGrantor?: string };
}

describe("loadConfig: web identities", () => {
  const base = { AROHA_MCP_TRANSPORT: "stdio" };

  it("is off by default and on by environment or file", () => {
    expect(loadConfig(base).webIdentities).toBeUndefined();
    expect(loadConfig({ ...base, AROHA_MCP_WEB_IDENTITIES: "1" }).webIdentities).toEqual({});
    expect(loadConfig(base, { file: { webIdentities: { enabled: true } } }).webIdentities).toEqual({});
    expect(loadConfig({ ...base, AROHA_MCP_WEB_IDENTITIES: "0" }, { file: { webIdentities: { enabled: true } } }).webIdentities).toBeUndefined();
  });

  it("reads the host allowlist, lower-cased", () => {
    expect(loadConfig({ ...base, AROHA_MCP_WEB_IDENTITIES: "1", AROHA_MCP_WEB_IDENTITY_HOSTS: "Accounts.Example.com, agents.example.com" }).webIdentities)
      .toEqual({ allowedHosts: ["accounts.example.com", "agents.example.com"] });
    expect(loadConfig(base, { file: { webIdentities: { enabled: true, allowedHosts: ["accounts.example.com"] } } }).webIdentities)
      .toEqual({ allowedHosts: ["accounts.example.com"] });
    // A list without the switch turns nothing on.
    expect(loadConfig({ ...base, AROHA_MCP_WEB_IDENTITY_HOSTS: "accounts.example.com" }).webIdentities).toBeUndefined();
  });
});

describe("verify_mandate with web identities", () => {
  it("verifies spending and task mandates whose grantor is a web identity, when turned on", async () => {
    const priv = ed.utils.randomPrivateKey();
    const { fetch, calls } = serve({ [HUMAN]: await ed.getPublicKeyAsync(priv) });
    const c = await start({ AROHA_MCP_WEB_IDENTITIES: "1" }, { webIdentityFetch: fetch });

    const spending = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 100, currency: "USD" }, priv);
    const s = await verify(c, spending.token, ASSISTANT);
    expect(s.valid, s.reason).toBe(true);
    expect(s.kind).toBe("spending");
    expect(s.rootGrantor).toBe(HUMAN);
    expect((await verify(c, spending.token, "https://agents.example.com/someone-else")).valid).toBe(false);

    const task = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], {}, priv);
    const t = await verify(c, task.token, ASSISTANT);
    expect(t.valid, t.reason).toBe(true);
    expect(t.kind).toBe("task");

    // One document request served every verification above.
    expect(calls).toEqual([HUMAN]);
  });

  it("refuses a mandate signed by a key the identity does not publish", async () => {
    const real = ed.utils.randomPrivateKey();
    const thief = ed.utils.randomPrivateKey();
    const { fetch } = serve({ [HUMAN]: await ed.getPublicKeyAsync(real) });
    const c = await start({ AROHA_MCP_WEB_IDENTITIES: "1" }, { webIdentityFetch: fetch });
    const forged = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 5000, currency: "USD" }, thief);
    expect((await verify(c, forged.token)).valid).toBe(false);
  });

  it("makes no request and refuses the mandate when web identities are off", async () => {
    const priv = ed.utils.randomPrivateKey();
    const { fetch, calls } = serve({ [HUMAN]: await ed.getPublicKeyAsync(priv) });
    const c = await start({}, { webIdentityFetch: fetch });
    const spending = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 100, currency: "USD" }, priv);
    expect((await verify(c, spending.token)).valid).toBe(false);
    const task = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], {}, priv);
    const t = await verify(c, task.token);
    expect(t.valid).toBe(false);
    expect(t.reason).toMatch(/cannot resolve the grantor key/);
    expect(calls).toHaveLength(0);
  });

  it("fetches only the configured hosts", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const { fetch, calls } = serve({ [HUMAN]: pub, [ASSISTANT]: pub });
    const c = await start({ AROHA_MCP_WEB_IDENTITIES: "1", AROHA_MCP_WEB_IDENTITY_HOSTS: "accounts.example.com" }, { webIdentityFetch: fetch });

    const allowed = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 10, currency: "USD" }, priv);
    expect((await verify(c, allowed.token)).valid).toBe(true);
    const other = await issueIntentMandate(ASSISTANT, HUMAN, { spendLimitUsd: 10, currency: "USD" }, priv);
    expect((await verify(c, other.token)).valid).toBe(false);
    expect(calls).toEqual([HUMAN]);
  });

  it("by default fetches through safeFetch, which refuses a host that resolves to a private address", async () => {
    const priv = ed.utils.randomPrivateKey();
    const looked: string[] = [];
    const c = await start({ AROHA_MCP_WEB_IDENTITIES: "1" }, {
      lookup: async (hostname) => { looked.push(hostname); return [{ address: "10.0.0.5", family: 4 }]; },
    });
    const spending = await issueIntentMandate(HUMAN, ASSISTANT, { spendLimitUsd: 100, currency: "USD" }, priv);
    expect((await verify(c, spending.token)).valid).toBe(false);
    expect(looked).toEqual(["accounts.example.com"]);
  });
});
