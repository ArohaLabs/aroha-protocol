// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope } from "../messages/envelope.js";
import { validateEnvelope } from "../messages/envelope.js";
import { NonceRegistry } from "../messages/nonce.js";
import { sealEnvelope, unsealEnvelope, isSealedEnvelope } from "./seal.js";
import type { ArohaRequestBody } from "../messages/types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function keypair() {
  const privateKey = ed.utils.randomPrivateKey();
  return { privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
}

describe("sealEnvelope / unsealEnvelope (spec §6.1 — mandatory off-TLS encryption)", () => {
  it("round-trips: unseal(seal(x)) is byte-for-byte the original envelope", async () => {
    const sender = await keypair();
    const recipient = await keypair();
    const body: ArohaRequestBody = { capability: "book-flight", params: { origin: "JFK" } };

    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", "did:aroha:recipient", body, "corr-1", sender.privateKey);

    const sealed = await sealEnvelope(envelope, recipient.publicKey);
    expect(isSealedEnvelope(sealed)).toBe(true);
    // The wire body is genuinely ciphertext — not just the plaintext relabeled.
    expect(sealed.body).not.toEqual(body);
    expect((sealed.body as { ciphertext: string }).ciphertext).toBeTruthy();

    const opened = await unsealEnvelope(sealed, recipient.privateKey);
    expect(opened).toEqual(envelope);
  });

  it("a sealed envelope still passes validateEnvelope after unsealing — signature covers the real plaintext", async () => {
    const sender = await keypair();
    const recipient = await keypair();
    const body: ArohaRequestBody = { capability: "book-flight", params: {} };

    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", "did:aroha:recipient", body, "corr-1", sender.privateKey);
    const sealed = await sealEnvelope(envelope, recipient.publicKey);
    const opened = await unsealEnvelope(sealed, recipient.privateKey);

    const result = await validateEnvelope(opened, sender.publicKey, "did:aroha:recipient", new NonceRegistry());
    expect(result.valid).toBe(true);
  });

  it("cannot be unsealed with the wrong private key", async () => {
    const sender = await keypair();
    const recipient = await keypair();
    const attacker = await keypair();
    const body: ArohaRequestBody = { capability: "book-flight", params: {} };

    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", "did:aroha:recipient", body, "corr-1", sender.privateKey);
    const sealed = await sealEnvelope(envelope, recipient.publicKey);

    await expect(unsealEnvelope(sealed, attacker.privateKey)).rejects.toThrow();
  });

  it("tampering with the ciphertext on the wire is detected (AES-GCM auth tag)", async () => {
    const sender = await keypair();
    const recipient = await keypair();
    const body: ArohaRequestBody = { capability: "book-flight", params: {} };

    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", "did:aroha:recipient", body, "corr-1", sender.privateKey);
    const sealed = await sealEnvelope(envelope, recipient.publicKey);

    const tampered = { ...sealed, body: { ...sealed.body, ciphertext: sealed.body.ciphertext.slice(0, -4) + "abcd" } };

    await expect(unsealEnvelope(tampered, recipient.privateKey)).rejects.toThrow();
  });

  it("unsealEnvelope refuses an envelope not marked sealed — a channel that was supposed to be encrypted but wasn't must not be silently accepted", async () => {
    const recipient = await keypair();
    const plainLooking = { body: { alg: "ECDH-ES+A256GCM", epk: "x", iv: "x", ciphertext: "x", tag: "x" } } as never;

    await expect(unsealEnvelope(plainLooking, recipient.privateKey)).rejects.toThrow(/not marked sealed/);
  });

  it("isSealedEnvelope distinguishes a sealed envelope from a plain one", async () => {
    const sender = await keypair();
    const recipient = await keypair();
    const body: ArohaRequestBody = { capability: "book-flight", params: {} };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", "did:aroha:recipient", body, "corr-1", sender.privateKey);

    expect(isSealedEnvelope(envelope)).toBe(false);
    expect(isSealedEnvelope(await sealEnvelope(envelope, recipient.publicKey))).toBe(true);
  });
});
