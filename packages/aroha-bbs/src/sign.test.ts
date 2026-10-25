// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Sign and Verify against the DIF/IETF reference fixtures.
 *
 * Every `valid: true` fixture must reproduce byte-for-byte — BBS signing is
 * deterministic, so anything less than an exact match means a divergence
 * from the standard somewhere. Every `valid: false` fixture must be
 * rejected, which is the half that catches a verifier that is merely
 * permissive.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { sign, verify, skToPk, octetsToSignature } from "./sign.js";
import { os2ip, utf8 } from "./ciphersuite.js";

interface Fixture {
  caseName: string;
  signerKeyPair: { secretKey: string; publicKey: string };
  header: string;
  messages: string[];
  signature: string;
  result: { valid: boolean; reason?: string };
  trace?: { B: string; domain: string };
}

const vectorDir = join(import.meta.dirname, "../vectors");
const fixtures = readdirSync(vectorDir)
  .filter((f) => f.startsWith("signature"))
  .map((f) => [f, JSON.parse(readFileSync(join(vectorDir, f), "utf8")) as Fixture] as const);

it("found the reference fixtures", () => {
  // Guards against the suite silently passing because it tested nothing.
  expect(fixtures.length).toBeGreaterThanOrEqual(5);
});

describe.each(fixtures)("%s", (_name, fx) => {
  const sk = os2ip(hexToBytes(fx.signerKeyPair.secretKey));
  const pk = hexToBytes(fx.signerKeyPair.publicKey);
  const header = hexToBytes(fx.header);
  const messages = fx.messages.map((m) => hexToBytes(m));

  it(fx.caseName, () => {
    if (fx.result.valid) {
      // Deterministic: the exact octets, not merely something that verifies.
      expect(bytesToHex(sign(sk, pk, messages, { header }))).toBe(fx.signature);
      expect(verify(pk, hexToBytes(fx.signature), messages, { header })).toBe(true);
    } else {
      expect(verify(pk, hexToBytes(fx.signature), messages, { header })).toBe(false);
    }
  });
});

describe("key derivation", () => {
  it("derives the fixture's public key from its secret key", () => {
    const [, fx] = fixtures.find(([, f]) => f.result.valid)!;
    const sk = os2ip(hexToBytes(fx.signerKeyPair.secretKey));
    expect(bytesToHex(skToPk(sk))).toBe(fx.signerKeyPair.publicKey);
  });

  it("refuses a zero secret key", () => {
    expect(() => skToPk(0n)).toThrow();
  });
});

describe("verification rejects tampering", () => {
  const [, fx] = [...fixtures].reverse().find(([, f]) => f.result.valid && f.messages.length > 2)!;
  const sk = os2ip(hexToBytes(fx.signerKeyPair.secretKey));
  const pk = hexToBytes(fx.signerKeyPair.publicKey);
  const header = hexToBytes(fx.header);
  const messages = fx.messages.map((m) => hexToBytes(m));
  const signature = sign(sk, pk, messages, { header });

  it("accepts the untampered case, so the rejections below mean something", () => {
    expect(verify(pk, signature, messages, { header })).toBe(true);
  });

  it("rejects a changed message", () => {
    const tampered = messages.map((m, i) => (i === 1 ? utf8("something else entirely") : m));
    expect(verify(pk, signature, tampered, { header })).toBe(false);
  });

  it("rejects a REORDERED message set", () => {
    // Order is bound by which generator each message is multiplied against;
    // a signature that survived reordering would let a holder swap two
    // attribute values while keeping the issuer's signature intact.
    const swapped = [...messages];
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    expect(verify(pk, signature, swapped, { header })).toBe(false);
  });

  it("rejects a dropped message", () => {
    expect(verify(pk, signature, messages.slice(0, -1), { header })).toBe(false);
  });

  it("rejects an appended message", () => {
    expect(verify(pk, signature, [...messages, utf8("extra")], { header })).toBe(false);
  });

  it("rejects a changed header", () => {
    expect(verify(pk, signature, messages, { header: utf8("a different context") })).toBe(false);
  });

  it("rejects a signature verified under someone else's key", () => {
    expect(verify(skToPk(999n), signature, messages, { header })).toBe(false);
  });

  it("rejects a flipped bit in the signature", () => {
    const bad = Uint8Array.from(signature);
    bad[bad.length - 1] ^= 0x01;
    expect(verify(pk, bad, messages, { header })).toBe(false);
  });
});

describe("malformed input is rejected, not thrown at the caller", () => {
  // verify() answers one question — is this valid — so a malformed input has
  // to be false rather than an exception the caller might catch differently
  // from a genuine verification failure.
  const pk = hexToBytes(fixtures[0][1].signerKeyPair.publicKey);

  it("a truncated signature", () => {
    expect(verify(pk, new Uint8Array(10), [utf8("m")])).toBe(false);
  });

  it("a signature that is not a curve point", () => {
    expect(verify(pk, new Uint8Array(80).fill(0xff), [utf8("m")])).toBe(false);
  });

  it("a public key of the wrong length", () => {
    const sig = sign(42n, skToPk(42n), [utf8("m")]);
    expect(verify(new Uint8Array(48), sig, [utf8("m")])).toBe(false);
  });

  it("but parsing surfaces the reason when asked directly", () => {
    // The strict parser still exists for callers that want the diagnosis.
    expect(() => octetsToSignature(new Uint8Array(10))).toThrow(/80 octets/);
  });
});

describe("round trip on our own keys", () => {
  it("signs and verifies zero messages", () => {
    // A signature over no messages is legal and still binds the header.
    const sk = 7n;
    const pk = skToPk(sk);
    expect(verify(pk, sign(sk, pk, []), [])).toBe(true);
  });

  it("signs and verifies a long message set", () => {
    const sk = 7n;
    const pk = skToPk(sk);
    const messages = Array.from({ length: 32 }, (_, i) => utf8(`attribute ${i}`));
    expect(verify(pk, sign(sk, pk, messages), messages)).toBe(true);
  });

  it("is deterministic — the same inputs give the same octets", () => {
    const sk = 7n;
    const pk = skToPk(sk);
    const messages = [utf8("a"), utf8("b")];
    expect(bytesToHex(sign(sk, pk, messages))).toBe(bytesToHex(sign(sk, pk, messages)));
  });
});
