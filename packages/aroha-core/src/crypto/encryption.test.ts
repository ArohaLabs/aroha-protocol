// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { encryptBody, decryptBody } from "./encryption.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

describe("encryptBody / decryptBody", () => {
  it("round-trips a plaintext object", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const plaintext = { capability: "book-flight", params: { origin: "JFK", dest: "LAX" } };

    const encrypted = await encryptBody(plaintext, pub);

    expect(encrypted.alg).toBe("ECDH-ES+A256GCM");
    expect(encrypted.ciphertext).toBeTruthy();
    expect(encrypted.tag).toBeTruthy();

    const decrypted = await decryptBody(encrypted, priv);
    expect(decrypted).toEqual(plaintext);
  });

  it("produces different ciphertext each time (random IV)", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const plaintext = { hello: "world" };

    const a = await encryptBody(plaintext, pub);
    const b = await encryptBody(plaintext, pub);

    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.iv).not.toBe(b.iv);
  });

  it("fails to decrypt with a different private key", async () => {
    const priv1 = ed.utils.randomPrivateKey();
    const pub1 = await ed.getPublicKeyAsync(priv1);
    const priv2 = ed.utils.randomPrivateKey();

    const encrypted = await encryptBody({ secret: "data" }, pub1);

    await expect(decryptBody(encrypted, priv2)).rejects.toThrow();
  });
});
