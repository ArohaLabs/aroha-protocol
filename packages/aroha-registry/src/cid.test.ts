// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { buildCIDv0, buildCIDv0Bytes } from "./cid.js";

describe("buildCIDv0", () => {
  it("produces a base58btc CIDv0 (starts with Qm)", async () => {
    const { cid } = await buildCIDv0({ name: "test-agent" });
    expect(cid).toMatch(/^Qm[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it("is deterministic for identical content", async () => {
    const a = await buildCIDv0({ name: "x", capabilities: ["a", "b"] });
    const b = await buildCIDv0({ name: "x", capabilities: ["a", "b"] });
    expect(a.cid).toBe(b.cid);
  });

  it("differs for different content", async () => {
    const a = await buildCIDv0({ name: "x" });
    const b = await buildCIDv0({ name: "y" });
    expect(a.cid).not.toBe(b.cid);
  });

  it("returns the raw block a gateway would serve", async () => {
    const { block } = await buildCIDv0({ name: "x" });
    expect(block).toBeInstanceOf(Uint8Array);
    expect(block.length).toBeGreaterThan(0);
  });

  it("buildCIDv0Bytes matches buildCIDv0 for the same serialized content", async () => {
    const manifest = { a: 1, b: 2 };
    const viaObject = await buildCIDv0(manifest);
    const viaBytes = await buildCIDv0Bytes(new TextEncoder().encode(JSON.stringify(manifest)));
    expect(viaObject.cid).toBe(viaBytes.cid);
  });
});
