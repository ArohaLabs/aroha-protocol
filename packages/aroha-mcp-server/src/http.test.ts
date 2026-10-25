// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Remote connector, end to end with a stock MCP SDK client (2026-07-28):
 *   - 401 → RFC 9728 metadata → authorization (CIMD client id, PKCE, iss) → token → success
 *   - server/discover and a gated call completed through input_required + inputResponses
 *   - a token minted for another audience is refused
 *   - two principals sign with different keys
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Client,
  StreamableHTTPClientTransport,
  UnauthorizedError,
  type OAuthClientProvider,
} from "@modelcontextprotocol/client";
import { loadConfig } from "./config.js";
import { FilePrincipalKeyStore } from "./keystore.js";
import { createRuntime } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { startFakeAs, freePort, type FakeAs } from "./test-utils/fake-as.js";

const CLIENT_ID = "https://client.example/oauth/cimd.json";
const REDIRECT = "http://127.0.0.1:1/callback";

let as: FakeAs;
let mcp: RunningHttpServer;
let keysDir: string;
let publicUrl: string;

beforeAll(async () => {
  as = await startFakeAs({ [CLIENT_ID]: { redirect_uris: [REDIRECT] } });
  keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-http-"));
  const port = await freePort();
  publicUrl = `http://127.0.0.1:${port}/mcp`;
  const config = loadConfig({
    AROHA_MCP_TRANSPORT: "http",
    AROHA_MCP_PORT: String(port),
    AROHA_MCP_PUBLIC_URL: publicUrl,
    AROHA_MCP_AUTH_ISSUER: as.issuer,
    AROHA_MCP_AUTH_SCOPES_SUPPORTED: "aroha",
    AROHA_MCP_KEY_DIR: keysDir,
    AROHA_REGISTRY_URL: "http://127.0.0.1:9/registry", // unused here; loopback http is allowed
  });
  const runtime = createRuntime(config, new FilePrincipalKeyStore(config.keysDir));
  mcp = await startHttpServer({ runtime, log: () => {} });
});

afterAll(async () => {
  await mcp?.close();
  await as?.close();
  // keysDir came from mkdtempSync above — never a computed or user path.
  if (keysDir) rmSync(keysDir, { recursive: true, force: true });
});

/** An OAuth client provider that drives the authorization redirect itself. */
class TestProvider implements OAuthClientProvider {
  private _tokens: Parameters<OAuthClientProvider["saveTokens"]>[0] | undefined;
  private _verifier = "";
  callback: URL | undefined;
  clientMetadataUrl = CLIENT_ID;
  get redirectUrl() { return REDIRECT; }
  get clientMetadata() {
    return { client_name: "test", redirect_uris: [REDIRECT], grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none" };
  }
  private _client: Parameters<NonNullable<OAuthClientProvider["saveClientInformation"]>>[0] | undefined;
  private _discovery: Parameters<NonNullable<OAuthClientProvider["saveDiscoveryState"]>>[0] | undefined;
  clientInformation() { return this._client; }
  // With a CIMD client id the SDK records the URL itself as the client id here.
  saveClientInformation(info: Parameters<NonNullable<OAuthClientProvider["saveClientInformation"]>>[0]) { this._client = info; }
  saveDiscoveryState(s: Parameters<NonNullable<OAuthClientProvider["saveDiscoveryState"]>>[0]) { this._discovery = s; }
  discoveryState() { return this._discovery; }
  tokens() { return this._tokens; }
  saveTokens(t: Parameters<OAuthClientProvider["saveTokens"]>[0]) { this._tokens = t; }
  async redirectToAuthorization(url: URL) {
    // The "user agent": follow the authorization request; the fake AS approves.
    const res = await fetch(url, { redirect: "manual" });
    this.callback = new URL(res.headers.get("location") ?? "");
  }
  saveCodeVerifier(v: string) { this._verifier = v; }
  codeVerifier() { return this._verifier; }
}

interface Wire { requests: Array<{ headers: Headers; body: unknown }>; responses: unknown[] }

function recordingFetch(wire: Wire): typeof fetch {
  return async (input, init) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    wire.requests.push({ headers: new Headers(init?.headers), body });
    const res = await fetch(input, init);
    const clone = res.clone();
    if ((res.headers.get("content-type") ?? "").includes("application/json")) {
      wire.responses.push(await clone.json().catch(() => null));
    }
    return res;
  };
}

async function connectAs(sub: string): Promise<{ client: Client; wire: Wire; provider: TestProvider }> {
  as.setUser(sub);
  const provider = new TestProvider();
  const wire: Wire = { requests: [], responses: [] };
  const opts = { authProvider: provider, fetch: recordingFetch(wire) };
  const makeClient = () => {
    const client = new Client(
      { name: "stock-client", version: "1.0.0" },
      { capabilities: { elicitation: { form: {} } }, versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    client.setRequestHandler("elicitation/create", async () => ({ action: "accept", content: { approve: true } }));
    return client;
  };
  let client = makeClient();
  let transport = new StreamableHTTPClientTransport(new URL(publicUrl), opts);
  try {
    await client.connect(transport);
  } catch (err) {
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(provider.callback?.searchParams.get("iss")).toBe(as.issuer);
    await transport.finishAuth(provider.callback!.searchParams);
    expect(provider.clientInformation()?.client_id).toBe(CLIENT_ID);
    client = makeClient();
    transport = new StreamableHTTPClientTransport(new URL(publicUrl), opts);
    await client.connect(transport);
  }
  return { client, wire, provider };
}

describe("remote MCP connector (Streamable HTTP, 2026-07-28, OAuth resource server)", () => {
  it("answers 401 with resource_metadata and serves RFC 9728 metadata", async () => {
    const res = await fetch(publicUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate") ?? "";
    expect(challenge).toMatch(/^Bearer /);
    const m = /resource_metadata="([^"]+)"/.exec(challenge);
    expect(m).not.toBeNull();
    const meta = await (await fetch(m![1])).json() as Record<string, unknown>;
    expect(meta.resource).toBe(publicUrl);
    expect(meta.authorization_servers).toEqual([as.issuer]);
    expect(meta.bearer_methods_supported).toEqual(["header"]);
  });

  it("completes discovery → CIMD authorization → token, server/discover, and a gated call via input_required", async () => {
    const { client, wire } = await connectAs("alice");
    expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
    expect(as.requests).toContain("GET /authorize");
    expect(as.requests.some((r) => r.includes("register"))).toBe(false); // no DCR

    const discover = await client.discover();
    expect(discover.capabilities.tools).toBeDefined();
    expect(client.getServerVersion()?.name).toBe("aroha-hub"); // from the result _meta serverInfo
    expect(discover.supportedVersions).toContain("2026-07-28");

    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "aroha_call", "aroha_discover", "aroha_get_receipt", "aroha_issue_spending_mandate", "aroha_issue_task_mandate",
      "check_revocation_status", "lookup_kel", "revoke_mandate", "verify_mandate", "verify_receipt",
    ]);
    const listResult = wire.responses.find((r) => (r as { result?: { tools?: unknown } })?.result?.tools) as { result: { ttlMs: number; cacheScope: string } };
    expect(listResult.result.ttlMs).toBeGreaterThan(0);
    expect(listResult.result.cacheScope).toBe("public");

    wire.requests.length = 0;
    wire.responses.length = 0;
    const result = await client.callTool({
      name: "aroha_issue_spending_mandate",
      arguments: { agentDid: "did:aroha:shop", capability: "buy", spendLimitUsd: 25 },
    });
    expect(result.isError).toBeFalsy();
    const out = JSON.parse((result.content[0] as { text: string }).text) as { grantorDid: string; token: string; mandateId: string };
    expect(out.grantorDid).toMatch(/^did:aroha:z/);

    // On the wire: an input_required answer, then a retry carrying inputResponses
    // and the opaque requestState, with the standard MCP routing headers.
    const interim = wire.responses.find((r) => (r as { result?: { resultType?: string } })?.result?.resultType === "input_required") as
      { result: { inputRequests: Record<string, { method: string }>; requestState: string } } | undefined;
    expect(interim).toBeDefined();
    expect(interim!.result.inputRequests.aroha_approval.method).toBe("elicitation/create");
    const calls = wire.requests.filter((r) => (r.body as { method?: string })?.method === "tools/call");
    expect(calls.length).toBe(2);
    const retry = calls[1].body as { params: { inputResponses?: Record<string, unknown>; requestState?: string } };
    expect(retry.params.requestState).toBe(interim!.result.requestState);
    expect(retry.params.inputResponses?.aroha_approval).toMatchObject({ action: "accept", content: { approve: true } });
    expect(calls[0].headers.get("mcp-method")).toBe("tools/call");
    expect(calls[0].headers.get("mcp-name")).toBe("aroha_issue_spending_mandate");

    // The issued mandate verifies through the server's own verify_mandate tool.
    const verified = await client.callTool({ name: "verify_mandate", arguments: { token: out.token, expectedGrantee: "did:aroha:shop" } });
    const v = JSON.parse((verified.content[0] as { text: string }).text) as { kind: string; reason?: string };
    expect(v.kind).toBe("spending");
    // Revocation is fail-closed: the test registry is unreachable, so the chain is refused for that reason.
    expect(v.reason ?? "").toMatch(/revocation|revoked|registry|fetch|ECONNREFUSED|failed/i);
    await client.close();
  });

  it("refuses a declined approval", async () => {
    const { client } = await connectAs("carol");
    client.setRequestHandler("elicitation/create", async () => ({ action: "accept", content: { approve: false } }));
    const r = await client.callTool({
      name: "aroha_issue_task_mandate",
      arguments: { agentDid: "did:aroha:x", allowed: ["read"] },
    });
    expect(r.isError).toBe(true);
    expect((r.content[0] as { text: string }).text).toMatch(/declined/);
    await client.close();
  });

  it("refuses a token minted for another audience, an expired token, and a forged requestState", async () => {
    const wrongAud = await as.mint({ sub: "mallory", aud: "https://other.example/mcp" });
    const res = await fetch(publicUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${wrongAud}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/invalid_token/);

    const expired = await as.mint({ sub: "mallory", aud: publicUrl, expSec: -120 });
    const res2 = await fetch(publicUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${expired}` },
      body: "{}",
    });
    expect(res2.status).toBe(401);

    // A valid token, but a requestState the server never minted: refused before the handler runs.
    const good = await as.mint({ sub: "mallory", aud: publicUrl });
    const res3 = await fetch(publicUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${good}`,
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "aroha_issue_spending_mandate",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 7, method: "tools/call",
        params: {
          name: "aroha_issue_spending_mandate",
          arguments: { agentDid: "did:aroha:shop", capability: "buy", spendLimitUsd: 1 },
          inputResponses: { aroha_approval: { action: "accept", content: { approve: true } } },
          requestState: "v1.forged.forged",
          _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { name: "raw", version: "0" },
            "io.modelcontextprotocol/clientCapabilities": { elicitation: { form: {} } },
          },
        },
      }),
    });
    const body = await res3.text();
    expect(body).toMatch(/Invalid or expired requestState/);
    expect(body).not.toMatch(/grantorDid/);
  });

  it("gives two principals different signing keys", async () => {
    const issue = async (sub: string) => {
      const { client } = await connectAs(sub);
      const r = await client.callTool({
        name: "aroha_issue_task_mandate",
        arguments: { agentDid: "did:aroha:x", allowed: ["read"] },
      });
      await client.close();
      return (JSON.parse((r.content[0] as { text: string }).text) as { grantorDid: string }).grantorDid;
    };
    const a1 = await issue("alice");
    const b = await issue("bob");
    const a2 = await issue("alice");
    expect(a1).toMatch(/^did:aroha:z/);
    expect(b).toMatch(/^did:aroha:z/);
    expect(a1).not.toBe(b);
    expect(a2).toBe(a1);

    const store = new FilePrincipalKeyStore(keysDir);
    const aliceDir = store.dirFor(`${as.issuer}|alice`);
    const bobDir = store.dirFor(`${as.issuer}|bob`);
    expect(aliceDir).not.toBe(bobDir);
    expect(aliceDir).not.toContain("alice"); // the principal never appears in the path
    if (process.platform !== "win32") {
      expect(statSync(join(aliceDir, "identity.key")).mode & 0o777).toBe(0o600);
    }
    expect((await store.get(`${as.issuer}|alice`)).did).toBe(a1);
  });
});
