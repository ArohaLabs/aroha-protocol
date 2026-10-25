// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { signMessage, verifyMessageSignature, canonicalizeMessage, signCanonical, verifyCanonicalSignature } from "./signing.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeKeyPair() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub };
}

describe("canonicalizeMessage", () => {
  it("excludes the proof field", () => {
    const msg = { a: 1, proof: { proofValue: "sig" }, b: 2 };
    const canon = canonicalizeMessage(msg);
    expect(JSON.parse(canon)).not.toHaveProperty("proof");
  });

  it("sorts keys lexicographically", () => {
    const msg = { z: 3, a: 1, m: 2 };
    const canon = canonicalizeMessage(msg);
    expect(canon).toBe(JSON.stringify({ a: 1, m: 2, z: 3 }));
  });

  it("sorts nested object keys", () => {
    const msg = { outer: { z: 1, a: 2 } };
    const canon = canonicalizeMessage(msg);
    expect(JSON.parse(canon).outer).toEqual({ a: 2, z: 1 });
  });

  it("preserves arrays", () => {
    const msg = { list: [3, 1, 2] };
    const canon = canonicalizeMessage(msg);
    expect(JSON.parse(canon).list).toEqual([3, 1, 2]);
  });
});

describe("signMessage / verifyMessageSignature", () => {
  it("produces a valid signature that verifies", async () => {
    const { priv, pub } = await makeKeyPair();
    const msg = { id: "test-msg", body: { hello: "world" } };
    const proof = await signMessage(msg, priv, "did:aroha:test#key-1");

    expect(proof.type).toBe("Ed25519Signature2020");
    expect(proof.proofPurpose).toBe("authentication");
    expect(proof.verificationMethod).toBe("did:aroha:test#key-1");
    expect(proof.proofValue).toBeTruthy();

    const valid = await verifyMessageSignature({ ...msg, proof }, pub);
    expect(valid).toBe(true);
  });

  it("rejects a tampered message", async () => {
    const { priv, pub } = await makeKeyPair();
    const msg = { id: "test-msg", body: { hello: "world" } };
    const proof = await signMessage(msg, priv, "did:aroha:test#key-1");

    const tampered = { id: "TAMPERED", body: { hello: "world" }, proof };
    const valid = await verifyMessageSignature(tampered, pub);
    expect(valid).toBe(false);
  });

  it("rejects a message with wrong public key", async () => {
    const { priv } = await makeKeyPair();
    const { pub: wrongPub } = await makeKeyPair();
    const msg = { id: "test-msg" };
    const proof = await signMessage(msg, priv, "did:aroha:test#key-1");
    const valid = await verifyMessageSignature({ ...msg, proof }, wrongPub);
    expect(valid).toBe(false);
  });

  it("returns false when proof is missing", async () => {
    const { pub } = await makeKeyPair();
    const valid = await verifyMessageSignature({ id: "no-proof" }, pub);
    expect(valid).toBe(false);
  });
});

describe("signCanonical / verifyCanonicalSignature", () => {
  it("produces a bare hex signature, not a proof-wrapped object", async () => {
    const { priv, pub } = await makeKeyPair();
    const payload = { firmDid: "did:aroha:acme", subdomain: "acme", timestamp: "2026-01-01T00:00:00.000Z" };

    const sig = await signCanonical(payload, priv);

    expect(typeof sig).toBe("string");
    expect(sig).toMatch(/^[0-9a-f]{128}$/); // 64 bytes, hex
    expect(await verifyCanonicalSignature(payload, sig, pub)).toBe(true);
  });

  it("verifies against the exact same canonicalization signMessage uses (same signer, same key, cross-checked)", async () => {
    const { priv, pub } = await makeKeyPair();
    const payload = { z: 1, a: 2 };

    const sig = await signCanonical(payload, priv);
    // canonicalizeMessage(payload) with no `proof` field present is what
    // signCanonical actually signs — reproducing that by hand here proves
    // the two functions agree on what bytes got signed.
    const expectedBytes = new TextEncoder().encode(canonicalizeMessage(payload));
    const ed = await import("@noble/ed25519");
    const sigBytes = Buffer.from(sig, "hex");
    expect(await ed.verifyAsync(sigBytes, expectedBytes, pub)).toBe(true);
  });

  it("rejects a tampered payload", async () => {
    const { priv, pub } = await makeKeyPair();
    const payload = { amount: 100 };
    const sig = await signCanonical(payload, priv);

    const valid = await verifyCanonicalSignature({ amount: 999 }, sig, pub);
    expect(valid).toBe(false);
  });

  it("rejects a signature from the wrong key", async () => {
    const { priv } = await makeKeyPair();
    const { pub: wrongPub } = await makeKeyPair();
    const payload = { x: 1 };
    const sig = await signCanonical(payload, priv);

    expect(await verifyCanonicalSignature(payload, sig, wrongPub)).toBe(false);
  });

  it("rejects a malformed hex signature without throwing", async () => {
    const { pub } = await makeKeyPair();
    expect(await verifyCanonicalSignature({ x: 1 }, "not-hex", pub)).toBe(false);
    expect(await verifyCanonicalSignature({ x: 1 }, "ab", pub)).toBe(false); // too short
  });
});
