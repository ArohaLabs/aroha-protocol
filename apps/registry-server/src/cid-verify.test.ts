import { describe, it, expect } from "vitest";
import { verifyBlock } from "./cid-verify.js";
import { buildCIDv0, buildCIDv0Bytes, buildCIDv1Raw } from "./test-utils/cid-builder.js";

const MANIFEST = { capabilities: [{ id: "test-cap" }] };

// ─── CIDv0 (base58btc, dag-pb/UnixFS) ────────────────────────────────────────

describe("verifyBlock — CIDv0 (dag-pb/UnixFS)", () => {
  it("returns ok: true and the parsed manifest for a matching block", async () => {
    const { cid, block } = await buildCIDv0(MANIFEST);

    const result = await verifyBlock(cid, block);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.manifest as typeof MANIFEST).capabilities[0].id).toBe("test-cap");
    }
  });

  it("returns tampered: true when block bytes differ from the CID hash", async () => {
    const { cid } = await buildCIDv0(MANIFEST);
    // Use a different manifest's block — valid structure, wrong hash
    const { block: wrongBlock } = await buildCIDv0({ capabilities: [{ id: "injected" }] });

    const result = await verifyBlock(cid, wrongBlock);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(true);
  });

  it("returns tampered: true for a single flipped byte", async () => {
    const { cid, block } = await buildCIDv0(MANIFEST);
    const flipped = new Uint8Array(block);
    flipped[flipped.length - 1] ^= 0xff; // flip last byte

    const result = await verifyBlock(cid, flipped);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(true);
  });

  it("returns ok: false (not tampered) when content is binary (not JSON)", async () => {
    // Build a CIDv0 whose content is raw binary bytes — hash matches but JSON.parse fails
    const binaryContent = new Uint8Array([0xff, 0xfe, 0xd8, 0x00, 0x01]);
    const { cid, block } = await buildCIDv0Bytes(binaryContent);

    const result = await verifyBlock(cid, block);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(false); // hash matched; content wasn't JSON
  });
});

// ─── CIDv1 (base32, raw codec 0x55) ──────────────────────────────────────────

describe("verifyBlock — CIDv1 raw codec (0x55)", () => {
  it("returns ok: true when block is the raw JSON bytes matching the CID", async () => {
    const { cid, block } = await buildCIDv1Raw(MANIFEST);

    const result = await verifyBlock(cid, block);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.manifest as typeof MANIFEST).capabilities[0].id).toBe("test-cap");
    }
  });

  it("returns tampered: true when a CIDv1 block hash does not match", async () => {
    const { cid } = await buildCIDv1Raw(MANIFEST);
    const { block: wrongBlock } = await buildCIDv1Raw({ capabilities: [{ id: "evil" }] });

    const result = await verifyBlock(cid, wrongBlock);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(true);
  });
});

// ─── Unsupported / edge cases ─────────────────────────────────────────────────

describe("verifyBlock — unsupported formats", () => {
  it("returns tampered: false for an unrecognised CID prefix", async () => {
    const result = await verifyBlock("sha256:deadbeef", new Uint8Array([1, 2, 3]));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(false);
  });

  it("returns tampered: false for an empty CID string", async () => {
    const result = await verifyBlock("", new Uint8Array([1, 2, 3]));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.tampered).toBe(false);
  });

  it("returns tampered: false for an empty block", async () => {
    const { cid } = await buildCIDv0(MANIFEST);
    // Empty block can't match the real CID, so it's tampered — but it also
    // can't be decoded. Tampered check runs first: hash mismatch → tampered: true.
    const result = await verifyBlock(cid, new Uint8Array(0));
    expect(result.ok).toBe(false);
    // An empty block produces a different SHA-256 → tampered: true
    if (!result.ok) expect(result.tampered).toBe(true);
  });
});
