// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * verify_mandate and the JWT form of a mandate (spec §6.10): the tool takes
 * a token of either form and gives the same answer for the same mandate.
 */

import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { generateDid } from "@aroha-sdk/core/identity";
import { attenuateToCart, issueIntentMandate, issueTaskMandate, signMandateJwt } from "@aroha-sdk/credentials/mandates";
import { loadConfig } from "./config.js";
import { FilePrincipalKeyStore } from "./keystore.js";
import { createRuntime } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { freePort } from "./test-utils/fake-as.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let mcp: RunningHttpServer;
let keysDir: string;
let c: Client;

beforeAll(async () => {
  keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-jwt-"));
  const config = loadConfig({
    AROHA_MCP_TRANSPORT: "http",
    AROHA_MCP_PORT: String(await freePort()),
    AROHA_MCP_ALLOW_UNAUTHENTICATED: "1",
    AROHA_MCP_KEY_DIR: keysDir,
    AROHA_REGISTRY_URL: "http://127.0.0.1:9/registry", // never reached: isRevoked is supplied
  });
  mcp = await startHttpServer({ runtime: createRuntime(config, new FilePrincipalKeyStore(config.keysDir), { isRevoked: async () => false, log: () => {} }), log: () => {} });
  c = new Client({ name: "t", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  await c.connect(new StreamableHTTPClientTransport(new URL(mcp.url)));
});

afterAll(async () => {
  await c?.close();
  await mcp?.close();
  // keysDir came from mkdtempSync above.
  if (keysDir) rmSync(keysDir, { recursive: true, force: true });
});

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

async function verify(token: string, expectedGrantee?: string) {
  const r = await c.callTool({ name: "verify_mandate", arguments: { token, ...(expectedGrantee ? { expectedGrantee } : {}) } });
  const first = (r.content as { text: string }[])[0].text;
  try {
    return JSON.parse(first) as { valid: boolean; kind?: string; reason?: string; rootGrantor?: string; chainVerified?: boolean; mandate?: { mandateId: string } };
  } catch {
    return { valid: false, reason: first };
  }
}

describe("verify_mandate with JWT-form tokens", () => {
  it("verifies a JWT spending chain link by link to its root", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);
    const r = await verify(cart.token, shop.did);
    expect(r.valid, r.reason).toBe(true);
    expect(r).toMatchObject({ kind: "spending", chainVerified: true, rootGrantor: human.did });
    expect(r.mandate?.mandateId).toBe(cart.mandate.mandateId);
    expect((await verify(cart.token, assistant.did)).valid).toBe(false);
  });

  it("verifies a JWT task mandate against its grantor's key", async () => {
    const human = await party(), assistant = await party();
    const task = await issueTaskMandate(human.did, assistant.did, ["inbox.read"], {}, human.priv, 3_600_000, { format: "jwt" });
    const r = await verify(task.token, assistant.did);
    expect(r.valid, r.reason).toBe(true);
    expect(r.kind).toBe("task");
  });

  it("refuses a widened child, a wrong signer and a malformed JWT", async () => {
    const human = await party(), assistant = await party(), shop = await party();
    const intent = await issueIntentMandate(human.did, assistant.did, { spendLimitUsd: 500 }, human.priv, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, shop.did, { spendLimitUsd: 300 }, assistant.priv);
    const widened = await signMandateJwt("spending", { ...cart.mandate, constraints: { spendLimitUsd: 5000 }, mandateId: crypto.randomUUID() } as unknown as Record<string, unknown>, assistant.priv);
    expect((await verify(`${intent.jwt}~${widened}`)).valid).toBe(false);

    const wrongSigner = await signMandateJwt("spending", intent.mandate as unknown as Record<string, unknown>, assistant.priv);
    expect((await verify(wrongSigner)).valid).toBe(false);
    expect((await verify("a.b.c")).valid).toBe(false);
  });
});
