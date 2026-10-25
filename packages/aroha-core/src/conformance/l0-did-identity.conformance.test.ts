// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol Conformance Suite — Layer 0: DID & Identity
 *
 * Tests the MUST requirements from docs/conformance/test-matrix.md rows L0-01 to L0-04.
 * Each test maps to one test matrix row and is labelled accordingly.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  generateDID,
  rotateDIDKey,
  toMultibase,
  fromMultibase,
} from "../identity/did.js";
import { buildEnvelope, validateEnvelope, newCorrelationId } from "../messages/envelope.js";
import { NonceRegistry } from "../messages/nonce.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── L0-01: Valid did:aroha: DID backed by Ed25519 keypair ───────────────────

describe("L0-01 [MUST] Agent generates a valid did:aroha: DID backed by Ed25519 keypair", () => {
  it("generates a DID with the correct prefix", async () => {
    const agent = await generateDID("test-agent", "https://example.com/aroha");
    expect(agent.did).toMatch(/^did:aroha:/);
  });

  it("public key round-trips through multibase encoding", async () => {
    const agent = await generateDID("multibase-test", "https://example.com/aroha");
    const encoded = toMultibase(agent.publicKey);
    const decoded = fromMultibase(encoded);
    expect(decoded).toEqual(agent.publicKey);
  });

  it("DID document contains the public key in the first verificationMethod", async () => {
    const agent = await generateDID("doc-test", "https://example.com/aroha");
    expect(agent.document.verificationMethod).toHaveLength(1);
    const vm = agent.document.verificationMethod[0];
    expect(vm.type).toBe("Ed25519VerificationKey2020");
    const recovered = fromMultibase(vm.publicKeyMultibase);
    expect(recovered).toEqual(agent.publicKey);
  });

  it("public key verifies a signature made with the private key", async () => {
    const agent = await generateDID("sig-test", "https://example.com/aroha");
    const message = new TextEncoder().encode("hello aroha");
    const sig = await ed.signAsync(message, agent.privateKey);
    const valid = await ed.verifyAsync(sig, message, agent.publicKey);
    expect(valid).toBe(true);
  });
});

// ─── L0-02: DID document conforms to W3C DID Core 1.0 ───────────────────────

describe("L0-02 [MUST] DID document conforms to W3C DID Core 1.0", () => {
  it("includes the required @context entries", async () => {
    const agent = await generateDID("ctx-test", "https://example.com/aroha");
    const doc = agent.document;
    expect(doc["@context"]).toContain("https://www.w3.org/ns/did/v1");
    expect(doc["@context"]).toContain(
      "https://w3id.org/security/suites/ed25519-2020/v1"
    );
  });

  it("id field equals the DID", async () => {
    const agent = await generateDID("id-test", "https://example.com/aroha");
    expect(agent.document.id).toBe(agent.did);
  });

  it("authentication references the key id", async () => {
    const agent = await generateDID("auth-test", "https://example.com/aroha");
    const doc = agent.document;
    const keyId = `${agent.did}#key-1`;
    expect(doc.authentication).toContain(keyId);
  });

  it("assertionMethod references the key id", async () => {
    const agent = await generateDID("assertion-test", "https://example.com/aroha");
    const doc = agent.document;
    const keyId = `${agent.did}#key-1`;
    expect(doc.assertionMethod).toContain(keyId);
  });

  it("service array contains an ArohaEndpoint entry", async () => {
    const endpoint = "https://agent.example.com/aroha";
    const agent = await generateDID("svc-test", endpoint);
    const svc = agent.document.service.find((s) => s.type === "ArohaEndpoint");
    expect(svc).toBeDefined();
    expect(svc!.serviceEndpoint).toBe(endpoint);
  });

  it("verificationMethod controller equals the DID", async () => {
    const agent = await generateDID("ctrl-test", "https://example.com/aroha");
    const vm = agent.document.verificationMethod[0];
    expect(vm.controller).toBe(agent.did);
  });
});

// ─── L0-03: Key rotation without DID change ──────────────────────────────────

describe("L0-03 [MUST] Agent can rotate keys without changing DID", () => {
  it("DID is unchanged after rotation", async () => {
    const original = await generateDID("rotate-test", "https://example.com/aroha");
    const rotated = await rotateDIDKey(original, 0); // 0h cooldown for tests
    expect(rotated.did).toBe(original.did);
  });

  it("new keypair is different from the original", async () => {
    const original = await generateDID("rotate-keys-test", "https://example.com/aroha");
    const rotated = await rotateDIDKey(original, 0);
    expect(rotated.privateKey).not.toEqual(original.privateKey);
    expect(rotated.publicKey).not.toEqual(original.publicKey);
  });

  it("rotation record is stored in keyHistory", async () => {
    const original = await generateDID("history-test", "https://example.com/aroha");
    const rotated = await rotateDIDKey(original, 0);
    expect(rotated.document.keyHistory).toBeDefined();
    expect(rotated.document.keyHistory!.length).toBeGreaterThan(0);
  });

  it("new public key is recorded in the DID document after rotation", async () => {
    const original = await generateDID("new-key-test", "https://example.com/aroha");
    const rotated = await rotateDIDKey(original, 0);
    const recoveredKey = fromMultibase(
      rotated.document.verificationMethod[0].publicKeyMultibase
    );
    expect(recoveredKey).toEqual(rotated.publicKey);
  });

  it("new key signs and verifies correctly after rotation", async () => {
    const original = await generateDID("sign-after-rotate", "https://example.com/aroha");
    const rotated = await rotateDIDKey(original, 0);
    const message = new TextEncoder().encode("post-rotation message");
    const sig = await ed.signAsync(message, rotated.privateKey);
    const valid = await ed.verifyAsync(sig, message, rotated.publicKey);
    expect(valid).toBe(true);
  });
});

// ─── L0-04: Reject messages signed with unknown DID ──────────────────────────

describe("L0-04 [MUST] Agent rejects messages signed with unknown/wrong DID key", () => {
  it("rejects an envelope when the verifying key does not match the signing key", async () => {
    const sender = await generateDID("l0-04-sender", "https://example.com/aroha");
    const stranger = await generateDID("l0-04-stranger", "https://example.com/aroha");
    const myDID = "did:aroha:l0-04-receiver";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "test", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    // Validate with the wrong public key (stranger's key instead of sender's)
    const result = await validateEnvelope(env, stranger.publicKey, myDID, reg);
    expect(result.valid).toBe(false);
  });

  it("accepts an envelope when the correct sender key is used", async () => {
    const sender = await generateDID("l0-04-valid", "https://example.com/aroha");
    const myDID = "did:aroha:l0-04-valid-recv";
    const reg = new NonceRegistry();

    const env = await buildEnvelope(
      "ArohaRequest",
      sender.did,
      myDID,
      { capability: "test", params: {} },
      newCorrelationId(),
      sender.privateKey
    );

    const result = await validateEnvelope(env, sender.publicKey, myDID, reg);
    expect(result.valid).toBe(true);
  });
});
