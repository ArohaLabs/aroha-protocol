// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regression tests for the envelope-validation security fixes:
 * signature-before-nonce, per-sender nonce scoping, `created` future check,
 * max TTL, proof-selected verification method, and FileNonceStore
 * persistence across restarts.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, appendFileSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { buildEnvelope, validateEnvelope, newCorrelationId, type ArohaEnvelope } from "./envelope.js";
import { NonceRegistry, type NonceStore } from "./nonce.js";
import { FileNonceStore } from "./file-nonce-store.js";
import { signMessage } from "../crypto/signing.js";
import { generateDID, rotateDIDKey, toMultibase } from "../identity/did.js";

const ME = "did:aroha:receiver";

async function signedEnvelope(
  from: { did: string; privateKey: Uint8Array },
  overrides: Partial<ArohaEnvelope> = {},
  ttlSeconds = 300
): Promise<ArohaEnvelope> {
  const env = await buildEnvelope("ArohaRequest", from.did, ME, { capability: "x", params: {} }, newCorrelationId(), from.privateKey, ttlSeconds);
  if (Object.keys(overrides).length === 0) return env;
  // Re-sign after applying overrides so only the field under test differs.
  const { proof: _p, ...rest } = { ...env, ...overrides };
  const proof = await signMessage(rest as Record<string, unknown>, from.privateKey, `${from.did}#key-1`);
  return { ...(rest as ArohaEnvelope), proof };
}

function recordingStore(): NonceStore & { keys: string[] } {
  const seen = new Set<string>();
  const keys: string[] = [];
  return {
    keys,
    async setIfAbsent(nonce) {
      keys.push(nonce);
      if (seen.has(nonce)) return false;
      seen.add(nonce);
      return true;
    },
    async evictExpired() {},
  };
}

describe("signature is verified BEFORE the nonce is recorded", () => {
  it("a bad-signature envelope does not consume the nonce", async () => {
    const alice = await generateDID("alice", "http://x");
    const store = recordingStore();
    const reg = new NonceRegistry(60_000, store);

    const legit = await signedEnvelope(alice);
    const forged = { ...legit, proof: { ...legit.proof!, proofValue: "AAAA" } };

    const r1 = await validateEnvelope(forged, alice.publicKey, ME, reg);
    expect(r1.valid).toBe(false);
    expect(store.keys).toHaveLength(0); // nothing written for unauthenticated traffic

    const r2 = await validateEnvelope(legit, alice.publicKey, ME, reg);
    expect(r2.valid).toBe(true);
    reg.destroy();
  });

  it("an envelope signed by the wrong key does not consume the nonce", async () => {
    const alice = await generateDID("alice", "http://x");
    const mallory = await generateDID("mallory", "http://x");
    const reg = new NonceRegistry();
    const legit = await signedEnvelope(alice);
    // Mallory re-signs Alice's envelope (same nonce, same from) with her key.
    const { proof: _p, ...unsigned } = legit;
    const proof = await signMessage(unsigned as Record<string, unknown>, mallory.privateKey, `${alice.did}#key-1`);
    expect((await validateEnvelope({ ...legit, proof }, alice.publicKey, ME, reg)).valid).toBe(false);
    expect((await validateEnvelope(legit, alice.publicKey, ME, reg)).valid).toBe(true);
    reg.destroy();
  });
});

describe("nonces are scoped per sender", () => {
  it("records keys as <from>:<nonce>", async () => {
    const alice = await generateDID("alice", "http://x");
    const store = recordingStore();
    const reg = new NonceRegistry(60_000, store);
    const env = await signedEnvelope(alice);
    await validateEnvelope(env, alice.publicKey, ME, reg);
    expect(store.keys).toEqual([`${alice.did}:${env.nonce}`]);
    reg.destroy();
  });

  it("the same nonce from two different senders does not collide", async () => {
    const alice = await generateDID("alice", "http://x");
    const bob = await generateDID("bob", "http://x");
    const reg = new NonceRegistry();
    const a = await signedEnvelope(alice);
    const b = await signedEnvelope(bob, { nonce: a.nonce });
    expect((await validateEnvelope(a, alice.publicKey, ME, reg)).valid).toBe(true);
    expect((await validateEnvelope(b, bob.publicKey, ME, reg)).valid).toBe(true);
    // ...while a true replay from the same sender is still rejected.
    const replay = await validateEnvelope(a, alice.publicKey, ME, reg);
    expect(replay).toMatchObject({ valid: false, reason: expect.stringMatching(/replay/i) });
    reg.destroy();
  });
});

describe("timestamp checks", () => {
  it("rejects `created` beyond the allowed future skew", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const created = new Date(Date.now() + 120_000);
    const env = await signedEnvelope(alice, {
      created: created.toISOString(),
      expires: new Date(created.getTime() + 60_000).toISOString(),
    });
    const r = await validateEnvelope(env, alice.publicKey, ME, reg);
    expect(r).toMatchObject({ valid: false, reason: expect.stringMatching(/future/) });
    reg.destroy();
  });

  it("accepts `created` slightly ahead (ordinary clock skew)", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const created = new Date(Date.now() + 2_000);
    const env = await signedEnvelope(alice, {
      created: created.toISOString(),
      expires: new Date(created.getTime() + 60_000).toISOString(),
    });
    expect((await validateEnvelope(env, alice.publicKey, ME, reg)).valid).toBe(true);
    reg.destroy();
  });

  it("rejects a lifetime longer than maxTtlMs (default 5 min)", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const env = await signedEnvelope(alice, {}, 30 * 24 * 3600); // 30 days
    const r = await validateEnvelope(env, alice.publicKey, ME, reg);
    expect(r).toMatchObject({ valid: false, reason: expect.stringMatching(/exceeds maximum/) });
    // and does not touch the nonce store
    expect((await validateEnvelope(env, alice.publicKey, ME, reg, { maxTtlMs: 31 * 24 * 3_600_000 })).valid).toBe(true);
    reg.destroy();
  });

  it("the builder's default TTL is within the default max", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const env = await buildEnvelope("ArohaRequest", alice.did, ME, { capability: "x", params: {} }, newCorrelationId(), alice.privateKey);
    expect((await validateEnvelope(env, alice.publicKey, ME, reg)).valid).toBe(true);
    reg.destroy();
  });

  it("rejects unparseable timestamps", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const env = await signedEnvelope(alice, { expires: "not-a-date" });
    expect((await validateEnvelope(env, alice.publicKey, ME, reg)).valid).toBe(false);
    reg.destroy();
  });
});

describe("proof-selected verification method (DID document as sender key)", () => {
  it("verifies against the device key named in the proof", async () => {
    const agent = await generateDID("multi", "http://x");
    const device = await generateDID("device", "http://x");
    agent.document.verificationMethod.push({
      id: `${agent.did}#device-2`,
      type: "Ed25519VerificationKey2020",
      controller: agent.did,
      publicKeyMultibase: toMultibase(device.publicKey),
    });
    const reg = new NonceRegistry();
    const env = await buildEnvelope("ArohaRequest", agent.did, ME, { capability: "x", params: {} }, newCorrelationId(), device.privateKey, { keyId: `${agent.did}#device-2` });
    expect(env.proof!.verificationMethod).toBe(`${agent.did}#device-2`);
    expect((await validateEnvelope(env, agent.document, ME, reg)).valid).toBe(true);

    // Same device signature claimed as #key-1 → verified against the primary key → fails.
    const mislabeled = await buildEnvelope("ArohaRequest", agent.did, ME, { capability: "x", params: {} }, newCorrelationId(), device.privateKey);
    expect((await validateEnvelope(mislabeled, agent.document, ME, reg)).valid).toBe(false);
    reg.destroy();
  });

  it("rejects a proof that names another DID's key", async () => {
    const alice = await generateDID("alice", "http://x");
    const reg = new NonceRegistry();
    const env = await buildEnvelope("ArohaRequest", alice.did, ME, { capability: "x", params: {} }, newCorrelationId(), alice.privateKey, { keyId: "did:aroha:bob#key-1" });
    const r = await validateEnvelope(env, alice.publicKey, ME, reg);
    expect(r).toMatchObject({ valid: false, reason: expect.stringMatching(/different DID/) });
    reg.destroy();
  });

  it("accepts the predecessor key during a rotation cool-down", async () => {
    const agent = await generateDID("rotating", "http://x");
    const rotated = await rotateDIDKey(agent, 24);
    const reg = new NonceRegistry();
    const env = await signedEnvelope(agent); // signed with the OLD key
    expect((await validateEnvelope(env, rotated.document, ME, reg)).valid).toBe(true);
    reg.destroy();
  });
});

describe("FileNonceStore", () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
  function tmpFile(): string {
    const d = mkdtempSync(join(tmpdir(), "aroha-nonce-"));
    dirs.push(d);
    return join(d, "sub", "nonces.jsonl");
  }

  it("survives re-instantiation (a replay after restart is still rejected)", async () => {
    const file = tmpFile();
    const alice = await generateDID("alice", "http://x");
    const env = await signedEnvelope(alice);

    const reg1 = new NonceRegistry(60_000, new FileNonceStore(file));
    expect((await validateEnvelope(env, alice.publicKey, ME, reg1)).valid).toBe(true);
    reg1.destroy();

    // "Restart": brand-new store + registry over the same file.
    const reg2 = new NonceRegistry(60_000, new FileNonceStore(file));
    const r = await validateEnvelope(env, alice.publicKey, ME, reg2);
    expect(r).toMatchObject({ valid: false, reason: expect.stringMatching(/replay/i) });
    reg2.destroy();
  });

  it("skips expired and torn lines on load", async () => {
    const file = tmpFile();
    new FileNonceStore(file); // creates the directory
    writeFileSync(file, JSON.stringify({ k: "old", e: Date.now() - 1000 }) + "\n");
    appendFileSync(file, JSON.stringify({ k: "live", e: Date.now() + 60_000 }) + "\n");
    appendFileSync(file, '{"k":"torn","e":12'); // crash mid-write
    const store = new FileNonceStore(file);
    expect(store.size).toBe(1);
    expect(await store.setIfAbsent("live", Date.now() + 60_000)).toBe(false);
    expect(await store.setIfAbsent("old", Date.now() + 60_000)).toBe(true);
  });

  it("compacts the file after evictions and still remembers live nonces", async () => {
    const file = tmpFile();
    const store = new FileNonceStore(file, { compactAfterEvictions: 1 });
    await store.setIfAbsent("expired", Date.now() - 1);
    await store.setIfAbsent("live", Date.now() + 60_000);
    await store.evictExpired();
    const reloaded = new FileNonceStore(file);
    expect(reloaded.size).toBe(1);
    expect(await reloaded.setIfAbsent("live", Date.now() + 60_000)).toBe(false);
  });

  it("is exported from the package root (apps use it instead of keeping a copy)", async () => {
    const root = await import("../index.js");
    expect(root.FileNonceStore).toBe(FileNonceStore);
  });

  it("is NOT exported from the ./messages subpath, which stays free of Node built-ins", async () => {
    const sub = await import("./index.js") as Record<string, unknown>;
    expect(sub.FileNonceStore).toBeUndefined();
  });

  // POSIX modes only; Windows reports 0o666 for any writable file.
  it.skipIf(process.platform === "win32")("creates the file owner-only (0600), and keeps it so after compaction", async () => {
    const file = tmpFile();
    const store = new FileNonceStore(file, { compactAfterEvictions: 1 });
    await store.setIfAbsent("n", Date.now() + 60_000);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    await store.setIfAbsent("gone", Date.now() - 1);
    await store.evictExpired();
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });
});
