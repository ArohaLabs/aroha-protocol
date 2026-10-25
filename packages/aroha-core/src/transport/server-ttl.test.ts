// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ArohaServer forwards maxTtlMs / maxFutureSkewMs to validateEnvelope.
 *
 * Before these options existed on the server, the envelope TTL cap could only
 * be tuned by callers of validateEnvelope itself — the server always used the
 * 5-minute default, so a deployment with a longer, deliberately-sized nonce
 * retention had no supported way to accept longer-lived envelopes.
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
  const me = await generateDID("ttl-recv", "http://127.0.0.1");
  const sender = await generateDID("ttl-send", "http://127.0.0.1");
  const port = 20000 + Math.floor(Math.random() * 1000);
  server = new ArohaServer({
    agentDID: me.did,
    didDocument: me.document,
    port,
    resolvePublicKey: async (did) => (did === sender.did ? sender.publicKey : null),
    onMessage: async (env, respond) => { respond(env); },
    ...extra,
  });
  vi.spyOn(console, "log").mockImplementation(() => {});
  await server.start();
  const post = (body: unknown) => fetch(`http://127.0.0.1:${port}/aroha/v1`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { me, sender, post };
}

describe("ArohaServer envelope lifetime options", () => {
  it("rejects a 10-minute envelope under the default 5-minute cap", async () => {
    const { me, sender, post } = await startServer({});
    const env = await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, "c1", sender.privateKey, 600);
    const res = await post(env);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toMatch(/lifetime/);
  });

  it("accepts it when maxTtlMs is raised", async () => {
    const { me, sender, post } = await startServer({ maxTtlMs: 15 * 60_000 });
    const env = await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, "c2", sender.privateKey, 600);
    const res = await post(env);
    expect(res.status).toBe(200);
  });

  it("a lowered maxTtlMs rejects an envelope the default would accept", async () => {
    const { me, sender, post } = await startServer({ maxTtlMs: 60_000 });
    const env = await buildEnvelope("ArohaRequest", sender.did, me.did, { capability: "x", params: {} }, "c3", sender.privateKey, 120);
    const res = await post(env);
    expect(res.status).toBe(401);
  });
});
