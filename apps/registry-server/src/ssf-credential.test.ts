// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { sealPushCredential, openPushCredential } from "./ssf-credential.js";

const SEED_A = "11".repeat(32);
const SEED_B = "22".repeat(32);
const SECRET = "Bearer receiver-secret";

describe("SSF push credential sealing", () => {
  it("round-trips and never stores the plaintext", async () => {
    const env = { REGISTRY_SIGNING_KEY: SEED_A };
    const sealed = await sealPushCredential(env, "stream-1", SECRET);
    expect(sealed.startsWith("enc:v1:")).toBe(true);
    expect(sealed).not.toContain("receiver-secret");
    expect(await openPushCredential(env, "stream-1", sealed)).toEqual({ value: SECRET });
  });

  it("is bound to its stream: a value copied onto another stream does not open", async () => {
    const env = { REGISTRY_SIGNING_KEY: SEED_A };
    const sealed = await sealPushCredential(env, "stream-1", SECRET);
    expect((await openPushCredential(env, "stream-2", sealed)).value).toBeNull();
  });

  it("opens under the previous key after a rotation and offers a re-seal under the current one", async () => {
    const sealed = await sealPushCredential({ REGISTRY_SIGNING_KEY: SEED_A }, "s", SECRET);
    const rotated = { REGISTRY_SIGNING_KEY: SEED_B, REGISTRY_SIGNING_KEY_PREVIOUS: SEED_A };
    const opened = await openPushCredential(rotated, "s", sealed);
    expect(opened.value).toBe(SECRET);
    expect(opened.resealed).toBeDefined();
    expect(await openPushCredential({ REGISTRY_SIGNING_KEY: SEED_B }, "s", opened.resealed!)).toEqual({ value: SECRET });
  });

  it("opens to null when the sealing key is no longer configured, rather than guessing", async () => {
    const sealed = await sealPushCredential({ REGISTRY_SIGNING_KEY: SEED_A }, "s", SECRET);
    expect((await openPushCredential({ REGISTRY_SIGNING_KEY: SEED_B }, "s", sealed)).value).toBeNull();
  });

  it("refuses a tampered ciphertext", async () => {
    const env = { REGISTRY_SIGNING_KEY: SEED_A };
    const sealed = await sealPushCredential(env, "s", SECRET);
    // Flip a bit of the decoded ciphertext. Rewriting the last base64url
    // characters is not enough: the final character's low bits are padding,
    // so some rewrites decode to the same bytes and the value still opens.
    const cut = sealed.lastIndexOf(":") + 1;
    const ct = Buffer.from(sealed.slice(cut), "base64url");
    ct[0] ^= 0x01;
    const tampered = sealed.slice(0, cut) + ct.toString("base64url");
    expect(tampered).not.toBe(sealed);
    expect((await openPushCredential(env, "s", tampered)).value).toBeNull();
  });

  it("reads a legacy plaintext row and offers to seal it", async () => {
    const env = { REGISTRY_SIGNING_KEY: SEED_A };
    const opened = await openPushCredential(env, "s", SECRET);
    expect(opened.value).toBe(SECRET);
    expect(opened.resealed?.startsWith("enc:v1:")).toBe(true);
  });

  it("refuses to seal without a signing key, so nothing is stored unprotected", async () => {
    await expect(sealPushCredential({}, "s", SECRET)).rejects.toThrow(/not configured/);
  });
});
