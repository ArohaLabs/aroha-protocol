// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ProofGen and ProofVerify against the DIF/IETF reference fixtures.
 *
 * The fixtures publish the blinding scalars they used, so a valid case can be
 * reproduced BYTE FOR BYTE by injecting them. That matters more here than it
 * did for signing: a zero-knowledge proof has no observable output to sanity
 * check, so an implementation that is self-consistent and subtly wrong would
 * generate proofs its own verifier accepts and nothing else does — or worse,
 * that leak what they were meant to hide.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { prove, proveWithFixedScalarsForTesting, verifyProof, octetsToProof } from "./proof.js";
import { sign, skToPk } from "./sign.js";
import { os2ip, utf8 } from "./ciphersuite.js";

interface ProofFixture {
  caseName: string;
  signerPublicKey: string;
  signature: string;
  header: string;
  presentationHeader: string;
  messages: string[];
  disclosedIndexes: number[];
  proof: string;
  result: { valid: boolean; reason?: string };
  trace: {
    random_scalars: {
      r1: string; r2: string; e_tilde: string; r1_tilde: string; r3_tilde: string;
      m_tilde_scalars: string[];
    };
  };
}

const vectorDir = join(import.meta.dirname, "../vectors");
const fixtures = readdirSync(vectorDir)
  .filter((f) => f.startsWith("proof"))
  .map((f) => [f, JSON.parse(readFileSync(join(vectorDir, f), "utf8")) as ProofFixture] as const);

/** Replays the fixture's published blinding scalars so the proof is reproducible. */
function fixtureScalars(fx: ProofFixture) {
  const rs = fx.trace.random_scalars;
  const scalars = [rs.r1, rs.r2, rs.e_tilde, rs.r1_tilde, rs.r3_tilde, ...rs.m_tilde_scalars]
    .map((h) => os2ip(hexToBytes(h)));
  return () => scalars;
}

it("found the reference fixtures", () => {
  expect(fixtures.length).toBeGreaterThanOrEqual(4);
});

describe.each(fixtures)("%s", (_name, fx) => {
  const pk = hexToBytes(fx.signerPublicKey);
  const header = hexToBytes(fx.header);
  const presentationHeader = hexToBytes(fx.presentationHeader);
  const messages = fx.messages.map((m) => hexToBytes(m));
  const disclosedMessages = fx.disclosedIndexes.map((i) => messages[i]);

  it(fx.caseName, () => {
    if (fx.result.valid) {
      // Byte-exact, using the fixture's own blinding scalars.
      const produced = proveWithFixedScalarsForTesting(pk, hexToBytes(fx.signature), messages, fx.disclosedIndexes, {
        header, presentationHeader,
      }, fixtureScalars(fx));
      expect(bytesToHex(produced)).toBe(fx.proof);
    }

    // Valid or not, the fixture's own proof octets must get the fixture's
    // own answer.
    expect(
      verifyProof(pk, hexToBytes(fx.proof), disclosedMessages, fx.disclosedIndexes, {
        header, presentationHeader,
      }),
    ).toBe(fx.result.valid);
  });
});

describe("selective disclosure actually discloses selectively", () => {
  const sk = 42n;
  const pk = skToPk(sk);
  const messages = [
    utf8("name=Dana Kowalski"),
    utf8("dob=1990-04-12"),
    utf8("over_18=true"),
    utf8("national_id=AB123456"),
  ];
  const header = utf8("credential-v1");
  const ph = utf8("verifier-nonce-abc");
  const signature = sign(sk, pk, messages, { header });

  it("proves one attribute while revealing nothing else", () => {
    const proof = prove(pk, signature, messages, [2], { header, presentationHeader: ph });
    expect(verifyProof(pk, proof, [messages[2]], [2], { header, presentationHeader: ph })).toBe(true);
  });

  it("the proof octets do not contain the withheld messages", () => {
    // Not a proof of zero-knowledge — that is a property of the maths, not of
    // a substring search — but it does catch the catastrophic version of
    // getting this wrong.
    const proof = prove(pk, signature, messages, [2], { header, presentationHeader: ph });
    const hex = bytesToHex(proof);
    expect(hex).not.toContain(bytesToHex(messages[0]));
    expect(hex).not.toContain(bytesToHex(messages[3]));
  });

  it("two proofs from one signature are unlinkable", () => {
    // Re-randomised per presentation: identical proofs would let two
    // verifiers who compare notes tell they saw the same credential.
    const a = prove(pk, signature, messages, [2], { header, presentationHeader: ph });
    const b = prove(pk, signature, messages, [2], { header, presentationHeader: ph });
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    expect(verifyProof(pk, a, [messages[2]], [2], { header, presentationHeader: ph })).toBe(true);
    expect(verifyProof(pk, b, [messages[2]], [2], { header, presentationHeader: ph })).toBe(true);
  });

  it("discloses nothing at all when asked to", () => {
    const proof = prove(pk, signature, messages, [], { header, presentationHeader: ph });
    expect(verifyProof(pk, proof, [], [], { header, presentationHeader: ph })).toBe(true);
  });

  it("discloses everything when asked to", () => {
    const all = [0, 1, 2, 3];
    const proof = prove(pk, signature, messages, all, { header, presentationHeader: ph });
    expect(verifyProof(pk, proof, messages, all, { header, presentationHeader: ph })).toBe(true);
  });
});

describe("a proof cannot be bent into saying something else", () => {
  const sk = 42n;
  const pk = skToPk(sk);
  const messages = [utf8("role=clerk"), utf8("over_18=true"), utf8("salary=41000")];
  const header = utf8("credential-v1");
  const ph = utf8("nonce-1");
  const signature = sign(sk, pk, messages, { header });
  const proof = prove(pk, signature, messages, [1], { header, presentationHeader: ph });

  it("accepts the honest presentation, so the rejections below mean something", () => {
    expect(verifyProof(pk, proof, [messages[1]], [1], { header, presentationHeader: ph })).toBe(true);
  });

  it("rejects a different claimed value for the revealed message", () => {
    expect(verifyProof(pk, proof, [utf8("over_18=false")], [1], { header, presentationHeader: ph })).toBe(false);
  });

  it("rejects the revealed message claimed at a different index", () => {
    // The index is in the challenge precisely so a value proven at one
    // position cannot be presented as a different attribute.
    expect(verifyProof(pk, proof, [messages[1]], [0], { header, presentationHeader: ph })).toBe(false);
  });

  it("rejects a REPLAY against a different presentation header", () => {
    // The verifier's nonce is the anti-replay measure; without this the same
    // proof works forever.
    expect(verifyProof(pk, proof, [messages[1]], [1], { header, presentationHeader: utf8("nonce-2") })).toBe(false);
  });

  it("rejects a different signature header", () => {
    expect(verifyProof(pk, proof, [messages[1]], [1], { header: utf8("other"), presentationHeader: ph })).toBe(false);
  });

  it("rejects verification under a different issuer key", () => {
    expect(verifyProof(skToPk(43n), proof, [messages[1]], [1], { header, presentationHeader: ph })).toBe(false);
  });

  it("rejects a flipped bit anywhere in the proof", () => {
    for (const index of [0, 100, 200, proof.length - 1]) {
      const bad = Uint8Array.from(proof);
      bad[index] ^= 0x01;
      expect(verifyProof(pk, bad, [messages[1]], [1], { header, presentationHeader: ph })).toBe(false);
    }
  });

  it("rejects a claim of more revealed messages than were proven", () => {
    expect(verifyProof(pk, proof, [messages[1], messages[0]], [1, 0], { header, presentationHeader: ph })).toBe(false);
  });

  it("rejects a repeated disclosed index", () => {
    expect(verifyProof(pk, proof, [messages[1], messages[1]], [1, 1], { header, presentationHeader: ph })).toBe(false);
  });

  it("rejects a truncated proof rather than throwing", () => {
    expect(verifyProof(pk, proof.slice(0, 100), [messages[1]], [1], { header, presentationHeader: ph })).toBe(false);
  });
});

describe("input validation", () => {
  const sk = 42n;
  const pk = skToPk(sk);
  const messages = [utf8("a"), utf8("b")];
  const signature = sign(sk, pk, messages);

  it("refuses to prove an index that does not exist", () => {
    expect(() => prove(pk, signature, messages, [5])).toThrow(/out of range/);
  });

  it("L13: the public prove() refuses caller-supplied blinding scalars", () => {
    const fixed = (n: number) => Array.from({ length: n }, () => 1n);
    expect(() => prove(pk, signature, messages, [0], { unsafeRandomScalars: fixed } as never)).toThrow(/no longer accepted/);
  });

  it("refuses a negative index", () => {
    expect(() => prove(pk, signature, messages, [-1])).toThrow(/out of range/);
  });

  it("normalises duplicate disclosed indexes rather than double-counting them", () => {
    const proof = prove(pk, signature, messages, [0, 0]);
    expect(verifyProof(pk, proof, [messages[0]], [0])).toBe(true);
  });

  it("rejects a proof whose length is not a whole number of scalars", () => {
    expect(() => octetsToProof(new Uint8Array(273))).toThrow(/valid length/);
  });
});
