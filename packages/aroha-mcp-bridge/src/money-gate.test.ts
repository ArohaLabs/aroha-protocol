// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * wrapMcp's money gate: root policy (no self-issued roots), revocation,
 * per-capability prices redeemed against a payment mandate, and the envelope
 * TTL options. Real server, real signed requests, real mandate chains.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, generateDid, type PublicKeyResolver } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  InMemoryRedemptionStore,
  mandateRedemptionKey,
} from "@aroha-sdk/credentials";
import { wrapMcp, type McpToolDefinition, type WrapMcpOptions } from "./index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const BRIDGE_DID = "did:aroha:gate-agent";
const CALLER_DID = "did:aroha:gate-caller";
const HUMAN_DID = "did:aroha:gate-human";
let nextPort = 35761;

let callerPriv: Uint8Array, callerPub: Uint8Array, humanPriv: Uint8Array, humanPub: Uint8Array;
beforeAll(async () => {
  callerPriv = ed.utils.randomPrivateKey();
  callerPub = await ed.getPublicKeyAsync(callerPriv);
  humanPriv = ed.utils.randomPrivateKey();
  humanPub = await ed.getPublicKeyAsync(humanPriv);
});

const resolver: PublicKeyResolver = async (did) => (did === CALLER_DID ? callerPub : did === HUMAN_DID ? humanPub : null);

const tool: McpToolDefinition = { name: "aroha_quote", description: "q", inputSchema: { type: "object", properties: {} } };
const free: McpToolDefinition = { name: "aroha_ping", description: "p", inputSchema: { type: "object", properties: {} } };

async function start(extra: Partial<WrapMcpOptions>) {
  const port = nextPort++;
  vi.spyOn(console, "log").mockImplementation(() => {});
  const agent = await wrapMcp([tool, free], {
    name: "gate", port, did: BRIDGE_DID, resolvePublicKey: resolver,
    handlers: {
      aroha_quote: async () => ({ content: [{ type: "text", text: "quoted" }] }),
      aroha_ping: async () => ({ content: [{ type: "text", text: "pong" }] }),
    },
    ...extra,
  });
  const { stop } = await agent.start();
  return { port, stop };
}

async function call(port: number, capability: string, token?: string, ttlSeconds = 300) {
  const env = await buildEnvelope(
    "ArohaRequest", CALLER_DID, BRIDGE_DID,
    { capability, params: {}, ...(token ? { credentialToken: token } : {}) },
    `c-${Math.random()}`, callerPriv, ttlSeconds,
  );
  const res = await fetch(`http://localhost:${port}/aroha/v1`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env),
  });
  return { status: res.status, body: (await res.json()) as { error?: string } };
}

async function z() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
}

/** human → A (intent) → B (cart) → caller (payment, spendLimit $limit). */
async function paymentChain(limit: number) {
  const a = await z();
  const b = await z();
  const intent = await issueIntentMandate(HUMAN_DID, a.did, { spendLimitUsd: 100 }, humanPriv);
  const cart = await attenuateToCart(intent, b.did, { spendLimitUsd: 50 }, a.priv);
  return { intent, payment: await attenuateToPayment(cart, CALLER_DID, { spendLimitUsd: limit }, b.priv) };
}

describe("wrapMcp root policy", () => {
  it("refuses to start with requireMandate and no expectedRoot / trustedRoots / kelSource", async () => {
    const agent = await wrapMcp([tool], {
      name: "gate", port: nextPort++, did: BRIDGE_DID, resolvePublicKey: resolver, requireMandate: true,
      handlers: { aroha_quote: async () => ({ content: [] }) },
    });
    await expect(agent.start()).rejects.toThrow(/no root policy/);
  });

  it("refuses requirePersonRoot without a kelSource", async () => {
    const agent = await wrapMcp([tool], {
      name: "gate", port: nextPort++, did: BRIDGE_DID, resolvePublicKey: resolver, requireMandate: true,
      requirePersonRoot: true, handlers: { aroha_quote: async () => ({ content: [] }) },
    });
    await expect(agent.start()).rejects.toThrow(/kelSource/);
  });

  it("rejects a self-issued root (the caller granting itself) — the hole this gate closes", async () => {
    const { port, stop } = await start({ requireMandate: true, expectedRoot: HUMAN_DID });
    try {
      const self = await issueIntentMandate(CALLER_DID, CALLER_DID, { spendLimitUsd: 1_000_000 }, callerPriv);
      const r = await call(port, "ping", self.token);
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/root mismatch/i);
    } finally { stop(); }
  });

  it("trustedRoots accepts a listed root and rejects others", async () => {
    const { port, stop } = await start({ requireMandate: true, trustedRoots: [HUMAN_DID] });
    try {
      const ok = await issueIntentMandate(HUMAN_DID, CALLER_DID, { spendLimitUsd: 5 }, humanPriv);
      expect((await call(port, "ping", ok.token)).status).toBe(200);
      const self = await issueIntentMandate(CALLER_DID, CALLER_DID, { spendLimitUsd: 5 }, callerPriv);
      const r = await call(port, "ping", self.token);
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/not a trusted root/);
    } finally { stop(); }
  });

  it("consults isRevoked on the chain", async () => {
    const m = await issueIntentMandate(HUMAN_DID, CALLER_DID, { spendLimitUsd: 5 }, humanPriv);
    const { port, stop } = await start({
      requireMandate: true, expectedRoot: HUMAN_DID, isRevoked: async (id) => id === m.mandate.mandateId,
    });
    try {
      const r = await call(port, "ping", m.token);
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/revoked/);
    } finally { stop(); }
  });
});

describe("wrapMcp priced calls", () => {
  it("charges each priced call against the payment mandate and refuses past its limit", async () => {
    const redemption = new InMemoryRedemptionStore();
    const { port, stop } = await start({
      requireMandate: true, expectedRoot: HUMAN_DID, redemption, capabilityPrices: { aroha_quote: 4 },
    });
    try {
      const { payment } = await paymentChain(10);
      expect((await call(port, "quote", payment.token)).status).toBe(200);
      expect((await call(port, "quote", payment.token)).status).toBe(200);
      const third = await call(port, "quote", payment.token);
      expect(third.status).toBe(402);
      expect(third.body.error).toMatch(/exceed/);
      expect(await redemption.redeemedMicros(mandateRedemptionKey(payment.mandate))).toBe(8_000_000);
      expect(redemption.history(mandateRedemptionKey(payment.mandate)).every((r) => r.merchant === BRIDGE_DID)).toBe(true);
      // An unpriced tool is not charged.
      expect((await call(port, "ping", payment.token)).status).toBe(200);
      expect(await redemption.redeemedMicros(mandateRedemptionKey(payment.mandate))).toBe(8_000_000);
    } finally { stop(); }
  });

  it("a priced call needs a payment mandate, not an intent", async () => {
    const { port, stop } = await start({
      requireMandate: true, expectedRoot: HUMAN_DID, redemption: new InMemoryRedemptionStore(), price: 1,
    });
    try {
      const direct = await issueIntentMandate(HUMAN_DID, CALLER_DID, { spendLimitUsd: 10 }, humanPriv);
      const r = await call(port, "quote", direct.token);
      expect(r.status).toBe(402);
      expect(r.body.error).toMatch(/payment mandate/);
    } finally { stop(); }
  });

  it("does not run the tool when the redemption store fails", async () => {
    const handler = vi.fn(async () => ({ content: [{ type: "text" as const, text: "x" }] }));
    const port = nextPort++;
    const agent = await wrapMcp([tool], {
      name: "gate", port, did: BRIDGE_DID, resolvePublicKey: resolver, requireMandate: true, expectedRoot: HUMAN_DID,
      price: 1, handlers: { aroha_quote: handler },
      redemption: { tryRedeem: async () => { throw new Error("store down"); }, redeemedMicros: async () => 0 },
    });
    const { stop } = await agent.start();
    try {
      const { payment } = await paymentChain(10);
      const r = await call(port, "quote", payment.token);
      expect(r.status).toBe(402);
      expect(r.body.error).toMatch(/store down/);
      expect(handler).not.toHaveBeenCalled();
    } finally { stop(); }
  });

  it("advertises per-capability prices", async () => {
    const agent = await wrapMcp([tool, free], {
      name: "gate", port: nextPort++, did: BRIDGE_DID, resolvePublicKey: resolver, capabilityPrices: { quote: 2 },
      handlers: { aroha_quote: async () => ({ content: [] }), aroha_ping: async () => ({ content: [] }) },
    });
    expect(agent.capabilities.find((c) => c.id === "quote")?.pricing).toEqual({ model: "per-call", priceUsd: 2 });
    expect(agent.capabilities.find((c) => c.id === "ping")?.pricing).toEqual({ model: "free" });
  });
});

describe("wrapMcp envelope TTL options", () => {
  it("rejects a 10-minute envelope by default and accepts it with maxTtlMs raised", async () => {
    const a = await start({});
    try {
      expect((await call(a.port, "ping", undefined, 600)).status).toBe(401);
    } finally { a.stop(); }
    const b = await start({ maxTtlMs: 15 * 60_000 });
    try {
      expect((await call(b.port, "ping", undefined, 600)).status).toBe(200);
    } finally { b.stop(); }
  });
});
