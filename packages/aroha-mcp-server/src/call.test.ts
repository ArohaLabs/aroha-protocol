// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * aroha_call: attaches a mandate token, verifies the agent's response
 * envelope, and returns a signed action receipt that verify_receipt accepts.
 * Runs over the HTTP transport in loopback development mode (no OAuth).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { buildEnvelope, type ArohaEnvelope } from "@aroha-sdk/core/messages";
import { generateDid } from "@aroha-sdk/core/identity";
import { loadConfig } from "./config.js";
import { FilePrincipalKeyStore } from "./keystore.js";
import { createRuntime } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { freePort } from "./test-utils/fake-as.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let agentKey: Uint8Array;
let agentDid: string;
let forge = false;
let failWith: number | undefined;
let lastRequest: ArohaEnvelope | undefined;
let lastTraceparent: string | undefined;
let backend: Server;
let mcp: RunningHttpServer;
let keysDir: string;

beforeAll(async () => {
  agentKey = ed.utils.randomPrivateKey();
  agentDid = generateDid(await ed.getPublicKeyAsync(agentKey));
  const forgerKey = ed.utils.randomPrivateKey();
  // One loopback server plays both the registry and the agent.
  backend = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname.startsWith("/v1/agents/")) {
      const addr = backend.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ did: agentDid, endpoint: `http://127.0.0.1:${port}/agent` }));
      return;
    }
    if (req.method === "POST" && url.pathname === "/agent/aroha/v1") {
      let raw = "";
      for await (const c of req) raw += c;
      lastRequest = JSON.parse(raw) as ArohaEnvelope;
      lastTraceparent = req.headers.traceparent as string | undefined;
      if (failWith) {
        res.writeHead(failWith, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ secret: "INTERNAL-ONLY-DETAIL" }));
        return;
      }
      const reply = await buildEnvelope(
        "ArohaResponse", agentDid, lastRequest.from,
        { capability: "echo", result: { echoed: true } } as never,
        lastRequest.correlationId, forge ? forgerKey : agentKey,
      );
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(reply));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => backend.listen(0, "127.0.0.1", () => r()));
  const addr = backend.address();
  const backendPort = typeof addr === "object" && addr ? addr.port : 0;

  keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-call-"));
  const port = await freePort();
  const config = loadConfig({
    AROHA_MCP_TRANSPORT: "http",
    AROHA_MCP_PORT: String(port),
    AROHA_MCP_ALLOW_UNAUTHENTICATED: "1",
    AROHA_ALLOW_PRIVATE_ENDPOINTS: "1", // the test agent listens on loopback
    AROHA_MCP_KEY_DIR: keysDir,
    AROHA_REGISTRY_URL: `http://127.0.0.1:${backendPort}`,
  });
  mcp = await startHttpServer({ runtime: createRuntime(config, new FilePrincipalKeyStore(config.keysDir)), log: () => {} });
});

afterAll(async () => {
  await mcp?.close();
  await new Promise<void>((r) => { backend?.close(() => r()); backend?.closeAllConnections?.(); });
  // keysDir came from mkdtempSync above.
  if (keysDir) rmSync(keysDir, { recursive: true, force: true });
});

async function client(): Promise<Client> {
  const c = new Client({ name: "t", version: "1" }, { capabilities: { elicitation: { form: {} } }, versionNegotiation: { mode: { pin: "2026-07-28" } } });
  c.setRequestHandler("elicitation/create", async () => ({ action: "accept", content: { approve: true } }));
  await c.connect(new StreamableHTTPClientTransport(new URL(mcp.url)));
  return c;
}

const textOf = (r: { content: unknown[] }) => (r.content[0] as { text: string }).text;

describe("aroha_call", () => {
  it("attaches the mandate, verifies the signed response and emits a verifiable action receipt", async () => {
    const c = await client();
    const issued = JSON.parse(textOf(await c.callTool({
      name: "aroha_issue_task_mandate", arguments: { agentDid, allowed: ["echo"] },
    }))) as { token: string; mandateId: string; grantorDid: string };

    forge = false;
    const r = await c.callTool({
      name: "aroha_call",
      arguments: { agentDid, capability: "echo", params: { q: 1 }, mandateToken: issued.token },
      _meta: { traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" },
    });
    expect(r.isError).toBeFalsy();
    const out = JSON.parse(textOf(r)) as { result: unknown; actionReceipt: Record<string, unknown> };
    expect(out.result).toEqual({ echoed: true });
    expect((lastRequest!.body as { credentialToken?: string }).credentialToken).toBe(issued.token);
    expect(lastRequest!.from).toBe(issued.grantorDid);
    expect(lastTraceparent).toBe("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
    expect(out.actionReceipt.mandateId).toBe(issued.mandateId);
    expect((out.actionReceipt.approval as { approvalId?: string })?.approvalId).toBeTruthy();

    const v = JSON.parse(textOf(await c.callTool({
      name: "verify_receipt",
      arguments: { receipt: out.actionReceipt, expectedAction: "echo", expectedArgs: { q: 1 } },
    }))) as { ok: boolean; approvalPolicy: string };
    expect(v.ok).toBe(true);
    expect(v.approvalPolicy).toBe("satisfied");

    const tampered = { ...out.actionReceipt, action: "transfer" };
    const bad = JSON.parse(textOf(await c.callTool({ name: "verify_receipt", arguments: { receipt: tampered } }))) as { ok: boolean };
    expect(bad.ok).toBe(false);
    await c.close();
  });

  it("rejects a response signed by a key other than the agent's", async () => {
    const c = await client();
    forge = true;
    const r = await c.callTool({ name: "aroha_call", arguments: { agentDid, capability: "echo", params: {} } });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/Response rejected/);
    await c.close();
  });

  it("does not echo the body of a failed response, here or in the receipt", async () => {
    const c = await client();
    forge = false;
    failWith = 500;
    try {
      const r = await c.callTool({ name: "aroha_call", arguments: { agentDid, capability: "echo", params: {} } });
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/HTTP 500/);
      expect(textOf(r)).not.toMatch(/INTERNAL-ONLY-DETAIL/);
      const receiptId = (JSON.parse(textOf(r)) as { receiptId: string }).receiptId;
      const receipt = textOf(await c.callTool({ name: "aroha_get_receipt", arguments: { receiptId } }));
      expect(receipt).not.toMatch(/INTERNAL-ONLY-DETAIL/);
    } finally {
      failWith = undefined;
      await c.close();
    }
  });

  it("refuses to revoke a mandate the caller did not grant, and reports lookup_kel for a non-KEL DID", async () => {
    const c = await client();
    const r = await c.callTool({ name: "revoke_mandate", arguments: { token: "e30" } });
    expect(r.isError).toBe(true);
    const k = JSON.parse(textOf(await c.callTool({ name: "lookup_kel", arguments: { did: agentDid } }))) as { kelBacked: boolean };
    expect(k.kelBacked).toBe(false);
    const s = await c.callTool({ name: "check_revocation_status", arguments: { mandateId: "m", grantor: agentDid } });
    expect(s.isError).toBe(true);
    expect(textOf(s)).toMatch(/registry's signing keys/);
    await c.close();
  });
});
