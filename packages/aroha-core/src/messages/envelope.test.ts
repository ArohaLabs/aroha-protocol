// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, validateEnvelope, newCorrelationId, senderDID } from "./envelope.js";
import { NonceRegistry } from "./nonce.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeKeyPair(id: string) {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { did: `did:aroha:${id}`, priv, pub };
}

describe("buildEnvelope", () => {
  it("builds a signed envelope with all required fields", async () => {
    const sender = await makeKeyPair("sender");
    const cid = newCorrelationId();
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:recipient",
      { capability: "search", params: {} },
      cid,
      sender.priv
    );

    expect(env.type).toBe("ArohaRequest");
    expect(env.from).toBe(sender.did);
    expect(env.to).toBe("did:aroha:recipient");
    expect(env.correlationId).toBe(cid);
    expect(env.id).toMatch(/^urn:uuid:/);
    expect(env.proof).toBeDefined();
    expect(env.proof!.type).toBe("Ed25519Signature2020");
    expect(env.nonce).toBeTruthy();
  });

  it("sets expiry in the future", async () => {
    const sender = await makeKeyPair("sender2");
    const env = await buildEnvelope(
      "ArohaResponse",
      sender.did,
      "did:aroha:other",
      { capability: "search", result: {} },
      newCorrelationId(),
      sender.priv,
      60
    );
    expect(new Date(env.expires) > new Date()).toBe(true);
  });
});

describe("validateEnvelope", () => {
  it("accepts a valid, freshly-built envelope", async () => {
    const sender = await makeKeyPair("valid-sender");
    const myDID = "did:aroha:receiver";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "do-thing", params: {} },
      newCorrelationId(),
      sender.priv
    );

    const result = await validateEnvelope(env, sender.pub, myDID, reg);
    expect(result.valid).toBe(true);
  });

  it("rejects when addressed to the wrong recipient", async () => {
    const sender = await makeKeyPair("wrong-to-sender");
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:someone-else",
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv
    );

    const result = await validateEnvelope(env, sender.pub, "did:aroha:me", reg);
    expect(result.valid).toBe(false);
    expect((result as { valid: false; reason: string }).reason).toMatch(/addressed to/);
  });

  it("rejects an expired envelope", async () => {
    const sender = await makeKeyPair("expired-sender");
    const myDID = "did:aroha:me";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv,
      -10 // already expired
    );

    const result = await validateEnvelope(env, sender.pub, myDID, reg);
    expect(result.valid).toBe(false);
    expect((result as { valid: false; reason: string }).reason).toMatch(/expired/);
  });

  it("rejects a replayed envelope", async () => {
    const sender = await makeKeyPair("replay-sender");
    const myDID = "did:aroha:me";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv
    );

    await validateEnvelope(env, sender.pub, myDID, reg); // first — accepted
    const result = await validateEnvelope(env, sender.pub, myDID, reg); // second — replay
    expect(result.valid).toBe(false);
    expect((result as { valid: false; reason: string }).reason).toMatch(/[Rr]eplay/);
  });

  it("rejects a tampered signature", async () => {
    const sender = await makeKeyPair("tamper-sender");
    const myDID = "did:aroha:me";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv
    );

    const tampered = {
      ...env,
      proof: { ...env.proof!, proofValue: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    };

    const result = await validateEnvelope(tampered, sender.pub, myDID, reg);
    expect(result.valid).toBe(false);
  });
});

describe("newCorrelationId", () => {
  it("generates unique IDs each call", () => {
    const a = newCorrelationId();
    const b = newCorrelationId();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^saga-/);
  });
});

describe("senderDID", () => {
  it("returns the from field", async () => {
    const sender = await makeKeyPair("sid");
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:other",
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv
    );
    expect(senderDID(env)).toBe(sender.did);
  });
});

describe("validateEnvelope clock tolerance", () => {
  it("rejects an expired envelope with no tolerance", async () => {
    const sender = await makeKeyPair("expired-no-tolerance-sender");
    const myDID = "did:aroha:me";
    const reg = new NonceRegistry();

    // Build a normal envelope
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv,
      300
    );

    // Mutate expires to the past
    const expiredEnv = {
      ...env,
      expires: new Date(Date.now() - 5000).toISOString(), // 5 seconds ago
    };

    // Validate with skipSignature to avoid needing to re-sign
    const result = await validateEnvelope(
      expiredEnv,
      sender.pub,
      myDID,
      reg,
      { skipSignature: true }
    );
    expect(result.valid).toBe(false);
    expect((result as { valid: false; reason: string }).reason).toMatch(/expired/);
  });

  it("accepts a slightly-expired envelope within clock tolerance", async () => {
    const sender = await makeKeyPair("expired-within-tolerance-sender");
    const myDID = "did:aroha:me";
    const reg = new NonceRegistry();

    // Build a normal envelope
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv,
      300
    );

    // Mutate expires to 3 seconds ago
    const expiredEnv = {
      ...env,
      expires: new Date(Date.now() - 3000).toISOString(),
    };

    // Validate with 10 second tolerance
    const result = await validateEnvelope(
      expiredEnv,
      sender.pub,
      myDID,
      reg,
      { skipSignature: true, clockToleranceMs: 10_000 }
    );
    expect(result.valid).toBe(true);
  });

  it("respects exact tolerance boundary", async () => {
    const sender = await makeKeyPair("tolerance-boundary-sender");
    const myDID = "did:aroha:me";
    const regA = new NonceRegistry();
    const regB = new NonceRegistry();

    // Build a normal envelope
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "x", params: {} },
      newCorrelationId(),
      sender.priv,
      300
    );

    // Mutate expires to exactly 5 seconds ago
    const expiredEnv = {
      ...env,
      expires: new Date(Date.now() - 5000).toISOString(),
    };

    // Test just below tolerance boundary (4999ms ago, 5000ms tolerance) — should accept
    const resultBelowBoundary = await validateEnvelope(
      { ...expiredEnv, expires: new Date(Date.now() - 4999).toISOString() },
      sender.pub,
      myDID,
      regA,
      { skipSignature: true, clockToleranceMs: 5000 }
    );
    expect(resultBelowBoundary.valid).toBe(true);

    // Test just above tolerance boundary (5001ms ago, 5000ms tolerance) — should reject
    const resultAboveBoundary = await validateEnvelope(
      { ...expiredEnv, expires: new Date(Date.now() - 5001).toISOString() },
      sender.pub,
      myDID,
      regB,
      { skipSignature: true, clockToleranceMs: 5000 }
    );
    expect(resultAboveBoundary.valid).toBe(false);
  });
});
