// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { CredentialRegistry, buildRevokeProof, verifyRevokeProof } from "./registry.js";
import { issueHumanCredential, serializeCredential } from "./credentials.js";
import { ArohaRole } from "./types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeIssuer() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: "did:aroha:issuer" };
}

async function makeCred(issuer: Awaited<ReturnType<typeof makeIssuer>>, userId = "user-1") {
  return issueHumanCredential(userId, [ArohaRole.HumanUser], issuer.did, issuer.priv);
}

describe("CredentialRegistry", () => {
  it("registers and resolves a valid credential", async () => {
    const issuer = await makeIssuer();
    const cred = await makeCred(issuer);
    const registry = new CredentialRegistry();

    const ok = await registry.register(cred, issuer.pub);
    expect(ok).toBe(true);

    const resolved = registry.resolve(cred.credentialId);
    expect(resolved).not.toBeNull();
    expect(resolved?.userId).toBe("user-1");
  });

  it("rejects registration with wrong issuer key", async () => {
    const issuer = await makeIssuer();
    const wrongIssuer = await makeIssuer();
    const cred = await makeCred(issuer);
    const registry = new CredentialRegistry();

    const ok = await registry.register(cred, wrongIssuer.pub);
    expect(ok).toBe(false);
    expect(registry.resolve(cred.credentialId)).toBeNull();
  });

  it("registerTrusted bypasses signature check", async () => {
    const issuer = await makeIssuer();
    const cred = await makeCred(issuer);
    const registry = new CredentialRegistry();

    registry.registerTrusted(cred);
    expect(registry.resolve(cred.credentialId)).not.toBeNull();
  });

  it("revokes a credential", async () => {
    const issuer = await makeIssuer();
    const cred = await makeCred(issuer);
    const registry = new CredentialRegistry();

    registry.registerTrusted(cred);
    expect(registry.resolve(cred.credentialId)).not.toBeNull();

    const removed = registry.revoke(cred.credentialId);
    expect(removed).toBe(true);
    expect(registry.resolve(cred.credentialId)).toBeNull();
  });

  it("returns false when revoking a non-existent credential", () => {
    const registry = new CredentialRegistry();
    expect(registry.revoke("nonexistent")).toBe(false);
  });

  it("listForUser returns credentials for that user", async () => {
    const issuer = await makeIssuer();
    const cred1 = await makeCred(issuer, "alice");
    const cred2 = await makeCred(issuer, "bob");
    const registry = new CredentialRegistry();

    registry.registerTrusted(cred1);
    registry.registerTrusted(cred2);

    const aliceList = registry.listForUser("alice");
    expect(aliceList).toHaveLength(1);
    expect(aliceList[0].userId).toBe("alice");
  });

  it("evicts expired credentials", async () => {
    const issuer = await makeIssuer();
    const expired = await issueHumanCredential("user-exp", [ArohaRole.HumanUser], issuer.did, issuer.priv, -1000);
    const registry = new CredentialRegistry();
    registry.registerTrusted(expired);

    const count = registry.evictExpired();
    expect(count).toBe(1);
    expect(registry.size).toBe(0);
  });

  it("returns null on resolve of expired credential (auto-evict)", async () => {
    const issuer = await makeIssuer();
    const expired = await issueHumanCredential("user-exp", [ArohaRole.HumanUser], issuer.did, issuer.priv, -1000);
    const registry = new CredentialRegistry();
    registry.registerTrusted(expired);

    expect(registry.resolve(expired.credentialId)).toBeNull();
    expect(registry.size).toBe(0);
  });
});

describe("buildRevokeProof / verifyRevokeProof", () => {
  it("builds a proof that verifies", async () => {
    const issuer = await makeIssuer();
    const proof = await buildRevokeProof("cred-123", issuer.priv);
    const valid = await verifyRevokeProof("cred-123", proof, issuer.pub);
    expect(valid).toBe(true);
  });

  it("fails verification with wrong public key", async () => {
    const issuer = await makeIssuer();
    const other = await makeIssuer();
    const proof = await buildRevokeProof("cred-456", issuer.priv);
    const valid = await verifyRevokeProof("cred-456", proof, other.pub);
    expect(valid).toBe(false);
  });

  it("fails verification with different credentialId", async () => {
    const issuer = await makeIssuer();
    const proof = await buildRevokeProof("cred-A", issuer.priv);
    const valid = await verifyRevokeProof("cred-B", proof, issuer.pub);
    expect(valid).toBe(false);
  });
});

import type { HumanCredential } from "./types.js";

describe("CredentialStore interface", () => {
  it("MapCredentialStore is exported and usable", async () => {
    const { MapCredentialStore } = await import("./registry.js");
    const store = new MapCredentialStore();
    const cred: HumanCredential = {
      credentialId: "test-id",
      userId: "user-1",
      roles: [ArohaRole.HumanUser],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      issuerDID: "did:aroha:issuer",
      signature: "dummy",
    };
    await store.set(cred.credentialId, cred);
    expect(await store.get(cred.credentialId)).toEqual(cred);
    await store.delete(cred.credentialId);
    expect(await store.get(cred.credentialId)).toBeUndefined();
  });

  it("CredentialRegistry accepts a custom store", async () => {
    const { MapCredentialStore, CredentialRegistry } = await import("./registry.js");
    const store = new MapCredentialStore();
    const reg = new CredentialRegistry(store);
    const cred: HumanCredential = {
      credentialId: "custom-store-id",
      userId: "user-2",
      roles: [ArohaRole.HumanUser],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      issuerDID: "did:aroha:issuer",
      signature: "dummy",
    };
    reg.registerTrusted(cred);
    expect(reg.resolve("custom-store-id")).toEqual(cred);
  });
});
