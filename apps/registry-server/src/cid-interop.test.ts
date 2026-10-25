// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-implementation interop: a CID built by @aroha-sdk/registry's real
 * publisher-side code (cid.ts) must verify correctly against this Worker's
 * own read-side decoder (cid-verify.ts) — the same discipline as
 * routes/sar.test.ts's SAR interop check. This is the actual thing that
 * matters for M6: a publisher using the SDK and a registry running this
 * Worker need to agree on the encoding byte for byte, not just each pass
 * its own tests in isolation.
 */

import { describe, it, expect } from "vitest";
import { buildCIDv0 } from "@aroha-sdk/registry";
import { verifyBlock } from "./cid-verify.js";

describe("buildCIDv0 (publisher) -> verifyBlock (registry) interop", () => {
  it("a CID and block built by the SDK verify and decode correctly here", async () => {
    const manifest = { arohaProtocolVersion: "1.0", name: "interop-test-agent", capabilities: [{ id: "web-search" }] };
    const { cid, block } = await buildCIDv0(manifest);

    const result = await verifyBlock(cid, block);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.manifest).toEqual(manifest);
  });

  it("detects tampering even when the CID itself is well-formed", async () => {
    const { cid, block } = await buildCIDv0({ name: "x" });
    const tamperedBlock = new Uint8Array(block);
    tamperedBlock[tamperedBlock.length - 1] ^= 0xff; // flip a byte

    const result = await verifyBlock(cid, tamperedBlock);
    expect(result).toEqual({ ok: false, tampered: true });
  });
});
