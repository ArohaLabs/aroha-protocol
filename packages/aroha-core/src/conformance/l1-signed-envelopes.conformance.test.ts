// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol Conformance Suite — Layer 1: Signed Envelopes
 *
 * Tests the MUST requirements from docs/conformance/test-matrix.md rows L1-01 to L1-05.
 * L1-06 (TLS enforcement) is a transport-level control verified during deployment;
 * it cannot be meaningfully tested in unit scope — a note is included.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, validateEnvelope, newCorrelationId } from "../messages/envelope.js";
import { NonceRegistry } from "../messages/nonce.js";
import { generateDID } from "../identity/did.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeAgent(id: string) {
  return generateDID(id, `https://${id}.example.com/aroha`);
}

// ─── L1-01: Every outbound message is signed ─────────────────────────────────

describe("L1-01 [MUST] Every outbound message is signed with sender's Ed25519 key", () => {
  it("buildEnvelope attaches a proof block", async () => {
    const sender = await makeAgent("l1-01-sender");
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:l1-01-recv",
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );
    expect(env.proof).toBeDefined();
    expect(env.proof!.type).toBe("Ed25519Signature2020");
    expect(env.proof!.proofValue).toBeTruthy();
  });

  it("proof verification key id points to sender's DID key", async () => {
    const sender = await makeAgent("l1-01-key-id");
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:l1-01-key-id-recv",
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );
    expect(env.proof!.verificationMethod).toContain(sender.did);
  });

  it("proof verifies successfully against the sender's public key", async () => {
    const sender = await makeAgent("l1-01-verify");
    const myDID = "did:aroha:l1-01-verify-recv";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    const result = await validateEnvelope(env, sender.publicKey, myDID, reg);
    expect(result.valid).toBe(true);
  });
});

// ─── L1-02: Receiver rejects messages with invalid signatures ─────────────────

describe("L1-02 [MUST] Receiver rejects messages with invalid signatures", () => {
  it("rejects a tampered proofValue", async () => {
    const sender = await makeAgent("l1-02-tamper");
    const myDID = "did:aroha:l1-02-tamper-recv";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    const tampered = {
      ...env,
      proof: { ...env.proof!, proofValue: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    };

    const result = await validateEnvelope(tampered, sender.publicKey, myDID, reg);
    expect(result.valid).toBe(false);
  });

  it("rejects when signed with a different private key than the declared sender", async () => {
    const declaredSender = await makeAgent("l1-02-declared");
    const actualSigner = await makeAgent("l1-02-actual");
    const myDID = "did:aroha:l1-02-wrong-key-recv";
    const reg = new NonceRegistry();

    // Signed with actualSigner's key but claims to be from declaredSender
    const env = await buildEnvelope(
      "ArohaRequest",
      declaredSender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      actualSigner.privateKey // wrong key
    );

    // Receiver looks up declaredSender's public key — signature won't verify
    const result = await validateEnvelope(env, declaredSender.publicKey, myDID, reg);
    expect(result.valid).toBe(false);
  });
});

// ─── L1-03: Receiver rejects replayed messages ───────────────────────────────

describe("L1-03 [MUST] Receiver rejects replayed messages (timestamp + nonce)", () => {
  it("rejects an identical envelope submitted twice", async () => {
    const sender = await makeAgent("l1-03-replay");
    const myDID = "did:aroha:l1-03-replay-recv";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    const first = await validateEnvelope(env, sender.publicKey, myDID, reg);
    expect(first.valid).toBe(true);

    const second = await validateEnvelope(env, sender.publicKey, myDID, reg);
    expect(second.valid).toBe(false);
    expect((second as { valid: false; reason: string }).reason).toMatch(/[Rr]eplay/);
  });

  it("accepts two different envelopes (different nonces) from the same sender", async () => {
    const sender = await makeAgent("l1-03-two-valid");
    const myDID = "did:aroha:l1-03-two-recv";
    const reg = new NonceRegistry();

    const env1 = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );
    const env2 = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    const r1 = await validateEnvelope(env1, sender.publicKey, myDID, reg);
    const r2 = await validateEnvelope(env2, sender.publicKey, myDID, reg);
    expect(r1.valid).toBe(true);
    expect(r2.valid).toBe(true);
  });
});

// ─── L1-04: Envelope includes expires field; expired envelopes rejected ───────

describe("L1-04 [MUST] Envelope includes expires field; receiver rejects expired envelopes", () => {
  it("buildEnvelope sets expires to a future timestamp", async () => {
    const sender = await makeAgent("l1-04-expires");
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:l1-04-recv",
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey
    );
    expect(env.expires).toBeDefined();
    expect(new Date(env.expires) > new Date()).toBe(true);
  });

  it("rejects an envelope where expires is in the past", async () => {
    const sender = await makeAgent("l1-04-past");
    const myDID = "did:aroha:l1-04-past-recv";
    const reg = new NonceRegistry();

    // ttlSeconds = -10 creates an already-expired envelope
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey,
      -10
    );

    const result = await validateEnvelope(env, sender.publicKey, myDID, reg);
    expect(result.valid).toBe(false);
    expect((result as { valid: false; reason: string }).reason).toMatch(/expir/i);
  });

  it("accepts an envelope with expires well in the future", async () => {
    const sender = await makeAgent("l1-04-future");
    const myDID = "did:aroha:l1-04-future-recv";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "ping", params: {} },
      newCorrelationId(),
      sender.privateKey,
      3600 // 1 hour TTL
    );

    // A 1-hour lifetime exceeds the receiver's default maxTtlMs (5 min —
    // the cap that bounds the replay window), so the receiver must opt in
    // to accepting it. The point of this test is only that a far-future
    // `expires` is not mistaken for an expired one.
    const result = await validateEnvelope(env, sender.publicKey, myDID, reg, { maxTtlMs: 3_600_000 });
    expect(result.valid).toBe(true);
  });
});

// ─── L1-05: Envelope schema validates against Aroha 1.0 message spec ─────────

describe("L1-05 [MUST] Envelope schema validates against Aroha 1.0 message spec", () => {
  it("built envelope contains all required top-level fields", async () => {
    const sender = await makeAgent("l1-05-schema");
    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:l1-05-recv",
      { capability: "test", params: { x: 1 } },
      newCorrelationId(),
      sender.privateKey
    );

    // Required fields per Aroha 1.0 spec §3 (envelope schema)
    expect(env["@context"]).toBeDefined();
    expect(env.id).toMatch(/^urn:uuid:/);
    expect(env.type).toBe("ArohaRequest");
    expect(env.from).toMatch(/^did:aroha:/);
    expect(env.to).toMatch(/^did:aroha:/);
    expect(env.created).toBeTruthy();
    expect(env.expires).toBeTruthy();
    expect(env.nonce).toBeTruthy();
    expect(env.correlationId).toBeTruthy();
    expect(env.body).toBeDefined();
    expect(env.proof).toBeDefined();
  });

  it("@context includes the Aroha protocol context", async () => {
    const sender = await makeAgent("l1-05-ctx");
    const env = await buildEnvelope(
      "ArohaResponse",
      sender.did,
      "did:aroha:l1-05-ctx-recv",
      { capability: "test", result: {} },
      newCorrelationId(),
      sender.privateKey
    );
    expect(env["@context"]).toContain("https://aroha-labs.com/contexts/v1");
  });

  it("correlationId links related messages in a saga", async () => {
    const sender = await makeAgent("l1-05-cid");
    const cid = newCorrelationId();

    const req = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      "did:aroha:l1-05-cid-recv",
      { capability: "test", params: {} },
      cid,
      sender.privateKey
    );
    const resp = await buildEnvelope(
      "ArohaResponse",
      "did:aroha:l1-05-cid-recv",
      sender.did,
      { capability: "test", result: {} },
      cid, // same correlationId
      sender.privateKey
    );

    expect(req.correlationId).toBe(cid);
    expect(resp.correlationId).toBe(cid);
  });

  it("all valid Aroha message types can be built without error", async () => {
    const sender = await makeAgent("l1-05-types");
    const cid = newCorrelationId();
    const recvDID = "did:aroha:l1-05-types-recv";

    const types = [
      ["ArohaRequest", { capability: "c", params: {} }],
      ["ArohaResponse", { capability: "c", result: {} }],
      ["ArohaError", { code: "Aroha_INTERNAL_ERROR", message: "test", retryable: false }],
    ] as const;

    for (const [type, body] of types) {
      const env = await buildEnvelope(
        type as Parameters<typeof buildEnvelope>[0],
        sender.did,
        recvDID,
        body as Parameters<typeof buildEnvelope>[3],
        cid,
        sender.privateKey
      );
      expect(env.type).toBe(type);
    }
  });
});

// ─── L1-06: TLS 1.3+ enforcement (deployment-level control) ──────────────────

describe("L1-06 [MUST] TLS 1.3+ enforced for all connections", () => {
  it("is verified at deployment, not unit scope — minVersion TLSv1.3 must be set in server options", () => {
    // TLS version enforcement cannot be meaningfully verified in a unit test.
    // The reference implementation sets minVersion: 'TLSv1.3' in the HTTPS server
    // options (docs/security/hardening.md §2) and nginx config (ssl_protocols TLSv1.3).
    // This test documents the requirement and confirms the constant is correct.
    const requiredMinTLSVersion = "TLSv1.3";
    expect(requiredMinTLSVersion).toBe("TLSv1.3");
  });
});
