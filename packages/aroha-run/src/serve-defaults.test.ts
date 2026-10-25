// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * T5/N3/F7/N4: serve() is closed by default (aroha-sig, no CORS, loopback,
 * 1 MiB body cap) and the client refuses cleartext registry-supplied
 * endpoints.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { serve } from "./serve.js";
import { callAgent } from "./client.js";

afterEach(() => { vi.unstubAllGlobals(); });

const run = (body: unknown, headers: Record<string, string> = {}) =>
  new Request("http://agent.local/v1/run", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

describe("serve() defaults", () => {
  it("requires a signed request by default (auth: aroha-sig)", async () => {
    const agent = serve("closed", () => "secret", { resolveCallerKey: () => null });
    expect((await agent.fetch(run({ message: "hi" }))).status).toBe(401);
  });

  it("auth: 'none' is an explicit opt-in", async () => {
    const agent = serve("open", () => "ok", { auth: "none" });
    expect((await agent.fetch(run({ message: "hi" }))).status).toBe(200);
  });

  it("sends no CORS headers unless configured", async () => {
    const agent = serve("nocors", () => "ok", { auth: "none" });
    const res = await agent.fetch(run({ message: "hi" }, { Origin: "https://evil.example" }));
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const pre = await agent.fetch(new Request("http://agent.local/v1/run", { method: "OPTIONS" }));
    expect(pre.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("cors: { origins } echoes only listed origins; cors: false sends none", async () => {
    const agent = serve("cors", () => "ok", { auth: "none", cors: { origins: ["https://app.example"] } });
    const ok = await agent.fetch(run({ message: "hi" }, { Origin: "https://app.example" }));
    expect(ok.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example");
    const no = await agent.fetch(run({ message: "hi" }, { Origin: "https://evil.example" }));
    expect(no.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const off = serve("off", () => "ok", { auth: "none", cors: false });
    expect((await off.fetch(run({ message: "hi" }, { Origin: "https://app.example" }))).headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("refuses bodies over maxBodyBytes with 413", async () => {
    const agent = serve("small", () => "ok", { auth: "none", maxBodyBytes: 1024 });
    const big = JSON.stringify({ message: "x".repeat(2048) });
    expect((await agent.fetch(run(big))).status).toBe(413);
    // No content-length header: streamed bytes are still counted.
    const stream = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(new TextEncoder().encode(big)); c.close(); },
    });
    const req = new Request("http://agent.local/v1/run", {
      method: "POST", body: stream, headers: { "content-type": "application/json" },
      duplex: "half",
    } as RequestInit);
    expect((await agent.fetch(req)).status).toBe(413);
  });
});

describe("callAgent endpoint policy (N4)", () => {
  it("refuses a registry-supplied http:// endpoint on a remote host", async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ endpointUrl: "http://agent.example.com" })));
    vi.stubGlobal("fetch", f);
    await expect(callAgent("abc", "hi", { registryUrl: "https://reg.example.com" })).rejects.toThrow(/http:\/\/ to a non-loopback/);
    expect(f).toHaveBeenCalledTimes(1); // the registry lookup only — the agent was never called
  });

  it("refuses an http:// registry on a remote host", async () => {
    vi.stubGlobal("fetch", vi.fn());
    await expect(callAgent("abc", "hi", { registryUrl: "http://reg.example.com" })).rejects.toThrow(/registryUrl/);
  });
});

describe("agent.register() — registry proof-of-possession contract", () => {
  /**
   * A fetch double implementing the registry's exact contract
   * (apps/registry-server routes/agents.ts): POST /v1/agents/challenge {did}
   * → {nonce}; POST /v1/agents verifies challengeSignature over
   * JSON.stringify({ action: "prove-ownership", did, nonce }) with publicKeyB64.
   */
  function contractRegistry() {
    const nonces = new Map<string, string>();
    const registered: Record<string, unknown>[] = [];
    const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
      if (url.endsWith("/v1/agents/challenge")) {
        const nonce = crypto.randomUUID();
        nonces.set(nonce, body.did);
        return new Response(JSON.stringify({ nonce, expiresAt: Date.now() + 300_000 }));
      }
      if (url.endsWith("/v1/agents")) {
        if (!body.challengeNonce || !body.challengeSignature) return new Response("{}", { status: 400 });
        if (nonces.get(body.challengeNonce) !== body.did) return new Response("{}", { status: 403 });
        nonces.delete(body.challengeNonce);
        // The server accepts base64url or standard base64 (Node's decoder takes both).
        const b64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
        const key = await crypto.subtle.importKey("raw", b64(body.publicKeyB64), { name: "Ed25519" }, false, ["verify"]);
        const msg = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did: body.did, nonce: body.challengeNonce }));
        const ok = await crypto.subtle.verify("Ed25519", key, b64(body.challengeSignature), msg);
        if (!ok) return new Response("{}", { status: 403 });
        registered.push(body);
        return new Response(JSON.stringify({ didHash: "0x1" }), { status: 201 });
      }
      return new Response("{}", { status: 404 });
    });
    return { fetchFn, registered };
  }

  it("registers with a signed challenge and the exact body shape", async () => {
    const { fetchFn, registered } = contractRegistry();
    vi.stubGlobal("fetch", fetchFn);
    const agent = serve("reg", () => "ok", { auth: "none" });
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    await agent.register("https://agent.example.com", {
      apiKey: "k", registryUrl: "https://reg.example.com", did: "did:aroha:reg-agent", manifestCID: "QmM", privateKey,
    });
    expect(registered).toHaveLength(1);
    expect(Object.keys(registered[0]).sort()).toEqual(
      ["challengeNonce", "challengeSignature", "did", "endpointUrl", "manifestCID", "publicKeyB64"],
    );
  });

  it("refuses with a clear error when no signer is given", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const agent = serve("reg2", () => "ok", { auth: "none" });
    await expect(agent.register("https://a.example.com", { apiKey: "k", did: "did:aroha:x", manifestCID: "Qm" }))
      .rejects.toThrow(/signer is required/);
  });
});
