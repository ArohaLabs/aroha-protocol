// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The primitives, against the DIF/IETF reference fixtures.
 *
 * A round-trip test would pass for an implementation that is internally
 * consistent and wrong — a mis-transcribed DST signs and verifies against
 * itself perfectly while being incompatible with, and potentially weaker
 * than, the actual standard. Only the published vectors can catch that, so
 * they are the first thing built against.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex } from "@noble/hashes/utils";
import { expand_message_xmd as nobleExpand } from "@noble/curves/abstract/hash-to-curve";
import { sha256 } from "@noble/hashes/sha256";
import { createGenerators, P1, P1_HEX, expandMessageXmd, utf8, i2osp, os2ip, bls } from "./ciphersuite.js";

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "../vectors/generators.json"), "utf8"),
) as { P1: string; Q1: string; MsgGenerators: string[] };

describe("create_generators against the reference fixtures", () => {
  it("derives Q_1 exactly as the draft does", () => {
    const [q1] = createGenerators(1);
    expect(bytesToHex(q1.toRawBytes(true))).toBe(vectors.Q1);
  });

  it("derives every message generator in the fixture", () => {
    const count = vectors.MsgGenerators.length;
    const generators = createGenerators(count + 1);
    const messageGenerators = generators.slice(1).map((g) => bytesToHex(g.toRawBytes(true)));
    expect(messageGenerators).toEqual(vectors.MsgGenerators);
  });

  it("is a chain: the first N of a longer run are the same points", () => {
    // Each seed is the expansion of the previous one, so asking for more
    // generators must never renumber the ones already in use.
    const ten = createGenerators(10).map((g) => bytesToHex(g.toRawBytes(true)));
    const three = createGenerators(3).map((g) => bytesToHex(g.toRawBytes(true)));
    expect(ten.slice(0, 3)).toEqual(three);
  });
});

describe("P1", () => {
  it("matches the fixture", () => {
    expect(bytesToHex(P1.toRawBytes(true))).toBe(vectors.P1);
    expect(P1_HEX).toBe(vectors.P1);
  });

  it("is NOT the curve's base point", () => {
    // A nothing-up-my-sleeve point: the draft specifies a separate generator
    // precisely so that no party can know a discrete-log relationship
    // between it and the message generators.
    expect(P1.equals(bls.G1.ProjectivePoint.BASE)).toBe(false);
  });
});

describe("expand_message_xmd (RFC 9380)", () => {
  // Cross-checked against @noble/curves' own independent implementation
  // rather than against pasted constants. Two implementations written from
  // the same RFC agreeing is real evidence; a hex string reproduced from
  // memory is not, and a wrong one here would be invisible — every output
  // downstream is a hash, so it would look like noise either way.
  const DST = utf8("QUUX-V01-CS02-with-expander-SHA256-128");

  for (const [label, msg, len] of [
    ["the empty message", "", 32],
    ["a short message", "abc", 32],
    ["an output spanning several blocks", "abcdef0123456789", 128],
    ["a long multi-block output", "q".repeat(200), 250],
  ] as const) {
    it(`agrees with noble for ${label}`, () => {
      expect(bytesToHex(expandMessageXmd(utf8(msg), DST, len))).toBe(
        bytesToHex(nobleExpand(utf8(msg), DST, len, sha256)),
      );
    });
  }

  it("refuses a DST longer than 255 octets rather than silently truncating", () => {
    expect(() => expandMessageXmd(utf8("x"), utf8("d".repeat(256)), 32)).toThrow();
  });
});

describe("integer conversions", () => {
  it("round-trips", () => {
    expect(os2ip(i2osp(258, 8))).toBe(258n);
  });

  it("refuses a value that does not fit, rather than truncating it", () => {
    // Silently wrapping a length prefix would corrupt every downstream hash.
    expect(() => i2osp(256, 1)).toThrow();
  });
});
