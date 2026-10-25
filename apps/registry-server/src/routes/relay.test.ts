// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for POST /v1/relay/connect — the key-possession proof gating a
 * relay WebSocket connect (M10, design spec §6.3). Real Ed25519 keys and
 * real WebCrypto verification throughout, not mocks.
 *
 * The Durable Object itself (agent-relay.ts) is verified separately against
 * a real `wrangler dev` process — see the M10 verification notes — since a
 * genuine DurableObjectState/WebSocket Hibernation environment can't be
 * constructed inside this plain-Node/sqlite test harness.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { makeApp } from "../test-utils/make-app.js";
import { postAgent } from "../test-utils/register.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)));
}
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stubFetch() {
  return vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
}
afterEach(() => vi.unstubAllGlobals());

async function realKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

async function signConnect(privateKey: Uint8Array, did: string, timestamp: number): Promise<string> {
  const message = new TextEncoder().encode(JSON.stringify({ action: "relay-connect", did, timestamp }));
  return toHex(await ed.signAsync(message, privateKey));
}

describe("POST /v1/relay/connect", () => {
  it("issues a connect token for a genuine signature from the agent's registered key", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:relay-test-agent";

    await postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey) }, kp.privateKey);

    const timestamp = Date.now();
    const signatureHex = await signConnect(kp.privateKey, did, timestamp);

    const res = await app.request("/v1/relay/connect", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp, signatureHex }),
    }, env);

    expect(res.status).toBe(200);
    const body = await res.json() as { token: string; socketUrl: string };
    expect(body.token).toBeTruthy();
    expect(body.socketUrl).toContain(body.token);
  });

  it("rejects a signature from a key OTHER than the one registered for this DID — the whole point", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const owner = await realKeypair();
    const attacker = await realKeypair();
    const did = "did:aroha:relay-impersonation-target";

    await postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(owner.publicKey) }, owner.privateKey);

    const timestamp = Date.now();
    const signatureHex = await signConnect(attacker.privateKey, did, timestamp);

    const res = await app.request("/v1/relay/connect", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp, signatureHex }),
    }, env);

    expect(res.status).toBe(403);
  });

  it("rejects a stale timestamp outside the freshness window", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:relay-stale-target";

    await postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey) }, kp.privateKey);

    const timestamp = Date.now() - 10 * 60_000; // 10 min old
    const signatureHex = await signConnect(kp.privateKey, did, timestamp);

    const res = await app.request("/v1/relay/connect", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp, signatureHex }),
    }, env);

    expect(res.status).toBe(400);
  });

  it("404s for a DID that was never registered", async () => {
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:never-registered";
    const timestamp = Date.now();
    const signatureHex = await signConnect(kp.privateKey, did, timestamp);

    const res = await app.request("/v1/relay/connect", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp, signatureHex }),
    }, env);

    expect(res.status).toBe(404);
  });

  it("a connect token is genuinely single-use at the repository layer (D1Repository.consumeRelayConnectToken)", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:relay-single-use";

    await postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey) }, kp.privateKey);

    const timestamp = Date.now();
    const signatureHex = await signConnect(kp.privateKey, did, timestamp);
    const connectRes = await app.request("/v1/relay/connect", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp, signatureHex }),
    }, env);
    const { token, socketUrl } = await connectRes.json() as { token: string; socketUrl: string };
    const didHash = socketUrl.split("/")[3];

    const { D1Repository } = await import("../d1-repository.js");
    const repo = new D1Repository(env.DB as never);

    const first = await repo.consumeRelayConnectToken(token, didHash, Date.now());
    const second = await repo.consumeRelayConnectToken(token, didHash, Date.now());
    expect(first).toBe(true);
    expect(second).toBe(false); // already consumed — the /socket route relies on exactly this
  });
});

describe("relay connect proofs are single-use (M12)", () => {
  it("refuses the same signed proof a second time inside the freshness window", async () => {
    stubFetch();
    const { app, apiKey, env } = await makeApp();
    const kp = await realKeypair();
    const did = "did:aroha:relay-replay";
    await postAgent(app, env, apiKey, { did, manifestCID: "QmAbc", publicKeyB64: toB64(kp.publicKey) }, kp.privateKey);

    const timestamp = Date.now();
    const body = JSON.stringify({ did, timestamp, signatureHex: await signConnect(kp.privateKey, did, timestamp) });
    const connect = () => app.request("/v1/relay/connect", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` }, body,
    }, env);

    expect((await connect()).status).toBe(200);
    expect((await connect()).status).toBe(409);

    // A fresh proof (new timestamp) still works.
    const t2 = timestamp + 1;
    const again = await app.request("/v1/relay/connect", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ did, timestamp: t2, signatureHex: await signConnect(kp.privateKey, did, t2) }),
    }, env);
    expect(again.status).toBe(200);
  });
});

// ─── Inbox exhaustion (H2) ───────────────────────────────────────────────────

/** Minimal in-memory DurableObjectState: enough storage API for AgentRelay.handleSend. */
function fakeState(opts: { failPuts?: boolean } = {}) {
  const data = new Map<string, unknown>();
  const storage = {
    async get<T>(key: string) { return data.get(key) as T | undefined; },
    async put(keyOrEntries: string | Record<string, unknown>, value?: unknown) {
      if (opts.failPuts) throw new Error("storage unavailable");
      if (typeof keyOrEntries === "string") data.set(keyOrEntries, value);
      else for (const [k, v] of Object.entries(keyOrEntries)) data.set(k, v);
    },
    async delete(key: string) { return data.delete(key); },
    async list(o: { prefix: string }) {
      return new Map([...data].filter(([k]) => k.startsWith(o.prefix)));
    },
  };
  return { data, state: { storage, getWebSockets: () => [], acceptWebSocket: () => {} } };
}

function sendTo(relay: { fetch(r: Request): Promise<Response> }, sender: string | null, from: string) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (sender) headers["X-Aroha-Relay-Sender"] = sender;
  return relay.fetch(new Request("https://relay/v1/relay/0xabc/send", {
    method: "POST", headers, body: JSON.stringify({ from, body: "hi" }),
  }));
}

describe("AgentRelay per-sender limit (H2)", () => {
  it("charges the authenticated sender, so rotating envelope.from does not reset the budget", async () => {
    const { AgentRelay } = await import("../relay/agent-relay.js");
    const { state } = fakeState();
    const relay = new AgentRelay(state as never, {});
    const statuses: number[] = [];
    for (let i = 0; i < 61; i++) statuses.push((await sendTo(relay, "key-hash-a", `did:aroha:invented-${i}`)).status);
    expect(statuses.slice(0, 60).every((s) => s === 202)).toBe(true);
    expect(statuses[60]).toBe(429);
    // Another authenticated sender has its own budget.
    expect((await sendTo(relay, "key-hash-b", "did:aroha:x")).status).toBe(202);
  });

  it("refuses a send with no authenticated sender", async () => {
    const { AgentRelay } = await import("../relay/agent-relay.js");
    const { state } = fakeState();
    expect((await sendTo(new AgentRelay(state as never, {}), null, "did:aroha:x")).status).toBe(400);
  });

  it("a failed put does not charge the sender or advance the sequence", async () => {
    const { AgentRelay } = await import("../relay/agent-relay.js");
    const { state, data } = fakeState({ failPuts: true });
    await expect(sendTo(new AgentRelay(state as never, {}), "key-hash-a", "did:aroha:x")).rejects.toThrow();
    expect(data.size).toBe(0);
  });
});

describe("POST /v1/relay/:didHash/send forwarding (H2)", () => {
  function captureNamespace() {
    const seen: Request[] = [];
    const ns = {
      idFromName: (n: string) => n,
      get: () => ({ fetch: async (url: string, init: Request) => { seen.push(new Request(url, init)); return new Response("{}", { status: 202 }); } }),
    };
    return { seen, ns };
  }

  it("sets the sender header from the verified API key, overwriting a caller-supplied value", async () => {
    const { app, apiKey, keyHash, env } = await makeApp();
    const { seen, ns } = captureNamespace();
    const res = await app.request("/v1/relay/0xabc/send", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}`, "X-Aroha-Relay-Sender": "forged" },
      body: JSON.stringify({ from: "did:aroha:x" }),
    }, { ...env, AGENT_RELAY: ns });
    expect(res.status).toBe(202);
    expect(seen[0].headers.get("X-Aroha-Relay-Sender")).toBe(keyHash);
    expect(seen[0].headers.get("Authorization")).toBeNull();
  });

  it("413s an envelope over 64 KiB", async () => {
    const { app, apiKey, env } = await makeApp();
    const { ns } = captureNamespace();
    const res = await app.request("/v1/relay/0xabc/send", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ from: "did:aroha:x", pad: "x".repeat(65 * 1024) }),
    }, { ...env, AGENT_RELAY: ns });
    expect(res.status).toBe(413);
  });
});
