// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { decodeB64, decodeEd25519PublicKey } from "./b64.js";

describe("decodeB64 — one decoder for base64url and base64", () => {
  // Bytes chosen so the two alphabets actually differ (0xfb 0xff → "+/" vs "-_").
  const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x01]);
  const std = Buffer.from(bytes).toString("base64");
  const url = Buffer.from(bytes).toString("base64url");

  it("decodes standard (padded and unpadded) and base64url to the same bytes", () => {
    expect(std).toMatch(/[+/]/);
    expect(url).toMatch(/[-_]/);
    for (const s of [std, std.replace(/=+$/, ""), url]) expect(decodeB64(s)).toEqual(bytes);
  });

  it("rejects malformed input and mixed alphabets", () => {
    for (const s of ["not base64!", "a", "+-", 42, null, "ab=c"]) expect(decodeB64(s)).toBeNull();
  });

  it("accepts only 32-byte keys as Ed25519 public keys", () => {
    expect(decodeEd25519PublicKey(Buffer.alloc(32, 1).toString("base64url"))).toHaveLength(32);
    expect(decodeEd25519PublicKey(Buffer.alloc(31, 1).toString("base64"))).toBeNull();
  });
});
