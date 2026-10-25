// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Signature-bypass decision on ArohaServer: default deny, transport-aware
 * `bypassSignatureForRequest`, deprecated DID-only `bypassSignatureFor`,
 * and resolvePublicKey receiving the proof's verificationMethod id.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import type { IncomingMessage } from "http";
import { generateDID } from "../identity/did.js";
import { buildEnvelope, buildUnsignedEnvelope } from "../messages/envelope.js";
import { ArohaServer, type ArohaServerOptions } from "./server.js";

let server: ArohaServer | undefined;
afterEach(async () => {
  if (server) { await server.stop(); server = undefined; }
  vi.restoreAllMocks();
});

function freePort(): number {
  return 19000 + Math.floor(Math.random() * 1000);
}

async function startServer(extra: Partial<ArohaServerOptions>) {
  const me = await generateDID("bypass-recv", "http://127.0.0.1");
  const port = freePort();
  const seen: string[] = [];
  server = new ArohaServer({
    agentDID: me.did,
    didDocument: me.document,
    port,
    resolvePublicKey: async () => new Uint8Array(32),
    onMessage: async (env, respond) => { seen.push(env.from); respond(env); },
    ...extra,
  });
  vi.spyOn(console, "log").mockImplementation(() => {});
  await server.start();
  const post = (body: unknown) => fetch(`http://127.0.0.1:${port}/aroha/v1`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { me, post, seen };
}

describe("ArohaServer signature bypass", () => {
  it("defaults to deny: an unsigned envelope is rejected", async () => {
    const { me, post } = await startServer({});
    const env = await buildUnsignedEnvelope("ArohaRequest", "did:aroha:mesh-peer", me.did, { capability: "x", params: {} }, "c1");
    const res = await post(env);
    expect(res.status).toBe(401);
  });

  it("bypassSignatureForRequest receives the request and the claimed DID", async () => {
    let gotReq: IncomingMessage | undefined;
    let gotDid: string | undefined;
    const { me, post } = await startServer({
      bypassSignatureForRequest: (req, did) => {
        gotReq = req; gotDid = did;
        return req.socket.remoteAddress === "127.0.0.1" || req.socket.remoteAddress === "::ffff:127.0.0.1";
      },
    });
    const env = await buildUnsignedEnvelope("ArohaRequest", "did:aroha:mesh-peer", me.did, { capability: "x", params: {} }, "c2");
    const res = await post(env);
    expect(res.status).toBe(200);
    expect(gotDid).toBe("did:aroha:mesh-peer");
    expect(gotReq?.socket).toBeDefined();
  });

  it("with both set, a request bypasses only if BOTH predicates agree", async () => {
    const { me, post } = await startServer({
      bypassSignatureForRequest: () => false,
      bypassSignatureFor: () => true,
    });
    const env = await buildUnsignedEnvelope("ArohaRequest", "did:aroha:mesh-peer", me.did, { capability: "x", params: {} }, "c3");
    expect((await post(env)).status).toBe(401);
  });

  it("T7: bypassSignatureFor alone is refused at construction", async () => {
    const me = await generateDID("bypass-legacy", "http://127.0.0.1");
    expect(() => new ArohaServer({
      agentDID: me.did, didDocument: me.document, port: freePort(),
      resolvePublicKey: async () => null, onMessage: async () => {},
      bypassSignatureFor: () => true,
    })).toThrow(/refused on its own/);
  });

  it("bypassSignatureFor narrows bypassSignatureForRequest (warns once)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { me, post } = await startServer({
      bypassSignatureForRequest: () => true,
      bypassSignatureFor: (did) => did === "did:aroha:mesh-peer",
    });
    for (const cid of ["c4", "c5"]) {
      const env = await buildUnsignedEnvelope("ArohaRequest", "did:aroha:mesh-peer", me.did, { capability: "x", params: {} }, cid);
      expect((await post(env)).status).toBe(200);
    }
    const other = await buildUnsignedEnvelope("ArohaRequest", "did:aroha:outsider", me.did, { capability: "x", params: {} }, "c5b");
    expect((await post(other)).status).toBe(401);
    const deprecations = warn.mock.calls.filter((c) => String(c[0]).includes("bypassSignatureFor is deprecated"));
    expect(deprecations).toHaveLength(1);
  });

  it("N3: binds loopback by default", async () => {
    const { me } = await startServer({});
    const addr = (server as unknown as { server: { address(): { address: string } } }).server.address();
    expect(addr.address).toBe("127.0.0.1");
    expect(me.did).toBeTruthy();
  });

  it("passes proof.verificationMethod to resolvePublicKey", async () => {
    const sender = await generateDID("vm-sender", "http://127.0.0.1");
    const calls: Array<[string, string | undefined]> = [];
    const { me, post } = await startServer({
      resolvePublicKey: async (did, vmId) => { calls.push([did, vmId]); return sender.publicKey; },
    });
    const env = await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, "c6", sender.privateKey, { keyId: `${sender.did}#device-9` });
    expect((await post(env)).status).toBe(200);
    expect(calls).toEqual([[sender.did, `${sender.did}#device-9`]]);
  });

  it("reports a replay as Aroha_REPLAY_DETECTED", async () => {
    const sender = await generateDID("replay-sender", "http://127.0.0.1");
    const { me, post } = await startServer({ resolvePublicKey: async () => sender.publicKey });
    const env = await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, "c7", sender.privateKey);
    expect((await post(env)).status).toBe(200);
    const res = await post(env);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { code: string }).code).toBe("Aroha_REPLAY_DETECTED");
  });
});
