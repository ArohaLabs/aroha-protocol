// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Conformance: wrapMcp governed mode.
 *
 * Claim under test: with `governed: true`, every mandate check is on and
 * start() FAILS CLOSED when any prerequisite is missing — revocation hook,
 * KEL source, root pin, durable redemption store — and when a caller tries
 * to switch a check back off. A governed bridge then refuses unmandated and
 * unverifiable calls and charges priced ones.
 */

import { createServer } from "node:net";
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, incept, type KelEvent, type KelSource, type KelIdentity, type PublicKeyResolver } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  InMemoryRedemptionStore,
  type MandateRevocationCheck,
  type RedemptionStore,
} from "@aroha-sdk/credentials";
import { wrapMcp, type McpToolDefinition, type WrapMcpOptions } from "./index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const BRIDGE_DID = "did:aroha:governed-bridge";

/** A port the OS reports free right now (wrapMcp takes a fixed port and does not report the bound one). */
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

const tool: McpToolDefinition = { name: "aroha_quote", description: "q", inputSchema: { type: "object", properties: {} } };
const handlers = { aroha_quote: async () => ({ content: [{ type: "text" as const, text: "quoted" }] }) };
const notRevoked: MandateRevocationCheck = async () => false;

/** A store that is not the in-memory one — stands in for httpRedemptionStore / D1RedemptionStore. */
function durableStore(): RedemptionStore {
  const inner = new InMemoryRedemptionStore();
  return { tryRedeem: (...a) => inner.tryRedeem(...a), redeemedMicros: (id) => inner.redeemedMicros(id) };
}

let alice: KelIdentity, shopper: KelIdentity, caller: KelIdentity;
let kelSource: KelSource;
let resolver: PublicKeyResolver;
beforeAll(async () => {
  alice = await incept({ kind: "person" });
  shopper = await incept({ kind: "agent", controller: alice.did });
  caller = await incept({ kind: "agent", controller: alice.did });
  const logs = new Map<string, KelEvent[]>([alice, shopper, caller].map((i) => [i.did, i.kel]));
  kelSource = async (did) => logs.get(did) ?? null;
  const callerPub = await ed.getPublicKeyAsync(caller.privateKey);
  resolver = async (did) => (did === caller.did ? callerPub : null);
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterAll(() => { vi.restoreAllMocks(); });

function governedOpts(extra: Partial<WrapMcpOptions> = {}): WrapMcpOptions {
  return {
    name: "gov", port: 0, did: BRIDGE_DID, resolvePublicKey: resolver, handlers,
    governed: true, kelSource, isRevoked: notRevoked, trustedRoots: [alice.did], redemption: durableStore(), price: 1,
    ...extra,
  };
}

async function startFails(opts: WrapMcpOptions, pattern: RegExp) {
  const agent = await wrapMcp([tool], opts);
  await expect(agent.start()).rejects.toThrow(pattern);
}

describe("wrapMcp governed: start() fails closed on each missing prerequisite", () => {
  it("without isRevoked", () => startFails(governedOpts({ isRevoked: undefined }), /isRevoked is required/));
  it("without kelSource", () => startFails(governedOpts({ kelSource: undefined }), /kelSource/));
  it("without a root pin", () => startFails(governedOpts({ trustedRoots: undefined }), /root pin is required/));
  it("with an empty trustedRoots", () => startFails(governedOpts({ trustedRoots: [] }), /root pin is required/));
  it("without a redemption store", () => startFails(governedOpts({ redemption: undefined }), /durable `redemption` store/));
  it("with an InMemoryRedemptionStore", () =>
    startFails(governedOpts({ redemption: new InMemoryRedemptionStore() }), /refuses an InMemoryRedemptionStore/));
  it("with requireMandate: false", () => startFails(governedOpts({ requireMandate: false }), /requires a mandate on every call/));
  it("with requirePersonRoot: false", () => startFails(governedOpts({ requirePersonRoot: false }), /requires person roots/));
});

describe("wrapMcp governed: a running bridge", () => {
  async function payment(limit = 5) {
    const intent = await issueIntentMandate(alice.did, shopper.did, { spendLimitUsd: 100 }, alice.privateKey);
    const cart = await attenuateToCart(intent, caller.did, { spendLimitUsd: 50 }, shopper.privateKey);
    return attenuateToPayment(cart, caller.did, { spendLimitUsd: limit }, caller.privateKey);
  }

  async function call(port: number, token?: string) {
    const env = await buildEnvelope(
      "ArohaRequest", caller.did, BRIDGE_DID,
      { capability: "quote", params: {}, ...(token ? { credentialToken: token } : {}) },
      `c-${Math.random()}`, caller.privateKey,
    );
    const res = await fetch(`http://localhost:${port}/aroha/v1`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env),
    });
    return { status: res.status, body: (await res.json()) as { error?: string } };
  }

  it("requires a mandate even though requireMandate was not set, and charges a valid person-rooted one", async () => {
    const opts = governedOpts({ port: await freePort() });
    const agent = await wrapMcp([tool], opts);
    const { stop } = await agent.start();
    try {
      expect((await call(opts.port!)).status).toBe(403);
      const p = await payment(1);
      expect((await call(opts.port!, p.token)).status).toBe(200);
      expect((await call(opts.port!, p.token)).status).toBe(402); // $1 limit spent
    } finally { stop(); }
  });

  it("refuses when the revocation source is unreachable (no fail-open)", async () => {
    const opts = governedOpts({ port: await freePort(), isRevoked: async () => { throw new Error("registry down"); } });
    const agent = await wrapMcp([tool], opts);
    const { stop } = await agent.start();
    try {
      const r = await call(opts.port!, (await payment()).token);
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/Revocation check failed/);
    } finally { stop(); }
  });

  it("refuses a chain rooted in a person who is not pinned", async () => {
    const mallory = await incept({ kind: "person" });
    const opts = governedOpts({ port: await freePort(), trustedRoots: [mallory.did] });
    const agent = await wrapMcp([tool], opts);
    const { stop } = await agent.start();
    try {
      const r = await call(opts.port!, (await payment()).token);
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/not a trusted root/);
    } finally { stop(); }
  });
});
