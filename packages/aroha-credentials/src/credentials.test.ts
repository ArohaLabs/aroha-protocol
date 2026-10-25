// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  issueHumanCredential,
  verifyHumanCredential,
  serializeCredential,
  deserializeCredential,
} from "./credentials.js";
import { ArohaRole } from "./types.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function makeIssuer() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: "did:aroha:issuer" };
}

describe("issueHumanCredential", () => {
  it("issues a credential with correct fields", async () => {
    const issuer = await makeIssuer();
    const cred = await issueHumanCredential(
      "user-123",
      [ArohaRole.HumanUser],
      issuer.did,
      issuer.priv,
      3_600_000,
      "user@example.com"
    );

    expect(cred.userId).toBe("user-123");
    expect(cred.roles).toContain(ArohaRole.HumanUser);
    expect(cred.issuerDID).toBe(issuer.did);
    expect(cred.email).toBe("user@example.com");
    expect(cred.signature).toBeTruthy();
    expect(new Date(cred.expiresAt) > new Date()).toBe(true);
  });
});

describe("verifyHumanCredential", () => {
  it("verifies a valid credential token", async () => {
    const issuer = await makeIssuer();
    const cred = await issueHumanCredential("user-456", [ArohaRole.HumanAdmin], issuer.did, issuer.priv);
    const token = serializeCredential(cred);

    const result = await verifyHumanCredential(token, issuer.pub);
    expect(result.valid).toBe(true);
    expect(result.credential?.userId).toBe("user-456");
  });

  it("rejects a token signed by a different key", async () => {
    const issuer = await makeIssuer();
    const otherIssuer = await makeIssuer();
    const cred = await issueHumanCredential("user-789", [ArohaRole.HumanUser], issuer.did, issuer.priv);
    const token = serializeCredential(cred);

    const result = await verifyHumanCredential(token, otherIssuer.pub);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/invalid/i);
  });

  it("rejects a malformed token", async () => {
    const issuer = await makeIssuer();
    const result = await verifyHumanCredential("not-valid-base64url!!!", issuer.pub);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });

  it("rejects an expired credential", async () => {
    const issuer = await makeIssuer();
    const cred = await issueHumanCredential("user-exp", [ArohaRole.HumanUser], issuer.did, issuer.priv, -1000);
    const token = serializeCredential(cred);

    const result = await verifyHumanCredential(token, issuer.pub);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });
});

describe("serializeCredential / deserializeCredential", () => {
  it("round-trips a credential", async () => {
    const issuer = await makeIssuer();
    const cred = await issueHumanCredential("round-trip", [ArohaRole.HumanReadonly], issuer.did, issuer.priv);
    const token = serializeCredential(cred);
    const decoded = deserializeCredential(token);
    expect(decoded).toEqual(cred);
  });

  it("returns null for garbage input", () => {
    expect(deserializeCredential("!!!")).toBeNull();
  });
});
