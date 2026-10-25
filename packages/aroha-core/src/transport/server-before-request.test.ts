// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ArohaServer's `beforeRequest` admission hook.
 *
 * The point of the hook is that it runs BEFORE any envelope work — body
 * read, JSON parse, key resolution, signature check — so a refusal there
 * (a rate limit, an allow-list) costs nothing. These tests pin that order,
 * the response it produces, pass-through when it returns nothing, and the
 * fail-closed behaviour when it throws.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { generateDID } from "../identity/did.js";
import { buildEnvelope } from "../messages/envelope.js";
import { ArohaServer, type ArohaServerOptions } from "./server.js";

let server: ArohaServer | undefined;
afterEach(async () => {
  if (server) { await server.stop(); server = undefined; }
  vi.restoreAllMocks();
});

async function startServer(extra: Partial<ArohaServerOptions>) {
  const me = await generateDID("br-recv", "http://127.0.0.1");
  const sender = await generateDID("br-send", "http://127.0.0.1");
  const port = 21000 + Math.floor(Math.random() * 1000);
  const resolvePublicKey = vi.fn(async (did: string) => (did === sender.did ? sender.publicKey : null));
  const onMessage = vi.fn(async (env: Parameters<ArohaServerOptions["onMessage"]>[0], respond: (r: typeof env) => void) => { respond(env); });
  server = new ArohaServer({
    agentDID: me.did,
    didDocument: me.document,
    port,
    resolvePublicKey,
    onMessage,
    ...extra,
  });
  vi.spyOn(console, "log").mockImplementation(() => {});
  await server.start();
  const base = `http://127.0.0.1:${port}`;
  const post = (body: string) => fetch(`${base}/aroha/v1`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  const signed = async (cid: string) => JSON.stringify(
    await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, cid, sender.privateKey),
  );
  return { base, post, signed, resolvePublicKey, onMessage };
}

describe("ArohaServer beforeRequest", () => {
  it("answers with the hook's response and does no envelope work", async () => {
    const { post, signed, resolvePublicKey, onMessage } = await startServer({
      beforeRequest: () => ({ status: 429, body: { error: "rate_limited" }, headers: { "retry-after": "1" } }),
    });
    const res = await post(await signed("c1"));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("1");
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await res.json()).toEqual({ error: "rate_limited" });
    expect(resolvePublicKey).not.toHaveBeenCalled();
    expect(onMessage).not.toHaveBeenCalled();
  });

  it("runs before the body is read: an oversize body is refused by the hook, not the 413 path", async () => {
    const { post } = await startServer({ maxBodyBytes: 16, beforeRequest: () => ({ status: 403 }) });
    const res = await post("x".repeat(1024));
    expect(res.status).toBe(403);
    expect(await res.text()).toBe("");
  });

  it("lets the request through when it returns nothing (sync or async)", async () => {
    const seen: string[] = [];
    const { base, post, signed, onMessage } = await startServer({
      beforeRequest: async (req) => { seen.push(`${req.method} ${req.url} ${req.socket.remoteAddress}`); },
    });
    expect((await post(await signed("c2"))).status).toBe(200);
    expect(onMessage).toHaveBeenCalledTimes(1);
    expect((await fetch(`${base}/.well-known/aroha-agent.json`)).status).toBe(200);
    expect(seen[0]).toMatch(/^POST \/aroha\/v1 (::ffff:)?127\.0\.0\.1$/);
    expect(seen[1]).toMatch(/^GET \/\.well-known\/aroha-agent\.json /);
  });

  it("runs for every route, including httpRoutes and the well-known document", async () => {
    const handle = vi.fn(async (_req, res: import("http").ServerResponse) => { res.end("ok"); });
    const { base } = await startServer({
      httpRoutes: [{ method: "GET", test: (u) => u === "/extra", handle }],
      beforeRequest: (req) => (req.url === "/aroha/v1" ? undefined : { status: 503, body: { error: "closed" } }),
    });
    expect((await fetch(`${base}/extra`)).status).toBe(503);
    expect((await fetch(`${base}/.well-known/aroha-agent.json`)).status).toBe(503);
    expect(handle).not.toHaveBeenCalled();
  });

  it("fails closed with 500 when the hook throws", async () => {
    const { post, signed, onMessage } = await startServer({
      beforeRequest: async () => { throw new Error("policy store down"); },
    });
    const res = await post(await signed("c3"));
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("policy store down");
    expect(onMessage).not.toHaveBeenCalled();
  });
});
