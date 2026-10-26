// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Outside devMode, a micro agent's key resolver used to know only its own
 * ephemeral DID, so every peer's correctly signed envelope got 401
 * "Unknown sender DID". `resolvePublicKey` lets callers say how peer keys are
 * resolved; without it the old behaviour (own DID only) is kept.
 *
 * Uses the real @aroha-sdk/core (agent.test.ts mocks it).
 */

import { createServer } from "node:net";
import { describe, it, expect, afterEach, vi } from "vitest";
import { generateDID, buildEnvelope } from "@aroha-sdk/core";
import { createAgent, type MicroAgent, type MicroAgentOptions } from "./agent.js";

let agent: MicroAgent | undefined;
afterEach(async () => {
  if (agent) { await agent.stop(); agent = undefined; }
  vi.restoreAllMocks();
});

/** A port the OS reports free right now (micro takes a fixed port, not 0). */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
  });
}

async function startAgent(extra: Partial<MicroAgentOptions>) {
  const port = await freePort();
  agent = createAgent({ name: "micro-peer", port, devMode: false, ...extra });
  agent.on("echo", ({ msg }) => ({ msg }));
  vi.spyOn(console, "log").mockImplementation(() => {});
  await agent.start();
  const peer = await generateDID("micro-peer-sender", "http://127.0.0.1");
  const post = async () => {
    const env = await buildEnvelope(
      "ArohaRequest", peer.did, agent!.did, { capability: "echo", params: { msg: "hi" } },
      `c-${Math.random()}`, peer.privateKey,
    );
    return fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(env),
    });
  };
  return { peer, post };
}

describe("MicroAgent peer key resolution (devMode: false)", () => {
  it("rejects a signed envelope from a peer DID by default", async () => {
    const { post } = await startAgent({});
    const res = await post();
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("Unknown sender DID");
  });

  it("accepts a correctly signed peer envelope when resolvePublicKey knows the peer", async () => {
    let peerKey: { did: string; publicKey: Uint8Array } | undefined;
    const resolvePublicKey = vi.fn(async (did: string) => (did === peerKey?.did ? peerKey.publicKey : null));
    const { peer, post } = await startAgent({ resolvePublicKey });
    peerKey = peer;
    const res = await post();
    expect(res.status).toBe(200);
    const body = (await res.json()) as { type: string; body: { result: { msg: string } } };
    expect(body.type).toBe("ArohaResponse");
    expect(body.body.result.msg).toBe("hi");
    expect(resolvePublicKey).toHaveBeenCalledWith(peer.did, expect.anything());
  });

  it("still rejects a peer the supplied resolver does not know", async () => {
    const { post } = await startAgent({ resolvePublicKey: async () => null });
    const res = await post();
    expect(res.status).toBe(401);
  });
});
