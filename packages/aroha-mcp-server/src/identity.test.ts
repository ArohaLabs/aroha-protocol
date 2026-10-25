// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** P1/C1: per-install identity — minted once, persisted 0600, signs verifiable envelopes and mandates. */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildEnvelope, validateEnvelope, NonceRegistry, isContentAddressedDid, fromMultibase } from "@aroha-sdk/core";
import { issueTaskMandate, verifyTaskMandate } from "@aroha-sdk/credentials/mandates";
import { loadOrCreateIdentity } from "./identity.js";

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), "aroha-mcp-id-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  // Each path came from mkdtempSync in this test file — never a computed or user path.
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("loadOrCreateIdentity", () => {
  it("mints a content-addressed DID once and reloads the same one", async () => {
    const dir = tempDir();
    const a = await loadOrCreateIdentity(dir);
    const b = await loadOrCreateIdentity(dir);
    expect(isContentAddressedDid(a.did)).toBe(true);
    expect(b.did).toBe(a.did);
    expect(fromMultibase(a.did.slice("did:aroha:".length))).toEqual(a.publicKey);
    if (process.platform !== "win32") {
      expect(statSync(a.keyPath).mode & 0o777).toBe(0o600);
    }
  });

  it("two installs get different identities", async () => {
    const a = await loadOrCreateIdentity(tempDir());
    const b = await loadOrCreateIdentity(tempDir());
    expect(a.did).not.toBe(b.did);
  });

  it("refuses a malformed key file instead of replacing it", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "identity.key"), "{not json");
    await expect(loadOrCreateIdentity(dir)).rejects.toThrow(/unreadable/);
    writeFileSync(join(dir, "identity.key"), JSON.stringify({ v: 1, privateKeyHex: "zz" }));
    await expect(loadOrCreateIdentity(dir)).rejects.toThrow(/malformed/);
  });

  it("signs envelopes and task mandates a conformant verifier accepts", async () => {
    const me = await loadOrCreateIdentity(tempDir());
    const env = await buildEnvelope("ArohaRequest", me.did, "did:aroha:vendor", { capability: "x", params: {} }, "c1", me.privateKey);
    const reg = new NonceRegistry();
    const r = await validateEnvelope(env, me.publicKey, "did:aroha:vendor", reg);
    reg.destroy();
    expect(r.valid).toBe(true);
    expect(Date.parse(env.expires) - Date.parse(env.created)).toBe(300_000);
    const m = await issueTaskMandate(me.did, "did:aroha:vendor", ["x"], {}, me.privateKey);
    expect((await verifyTaskMandate(m.token, me.publicKey, "did:aroha:vendor")).valid).toBe(true);
  });
});
