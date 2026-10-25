// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// GET /v1/mandates/:id/revoked is signed with the registry key — a verifier
// pinning /.well-known/aroha-registry-keys.json can check the answer was not
// altered or replayed in transit.

import { describe, it, expect, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import { canonicalizeJcs } from "@aroha-sdk/credentials/mandates";
import { issueIntentMandate, mandateRevocationPayload } from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";

let t: TestApp;
beforeEach(async () => { t = await makeApp(); });

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

type Status = {
  mandateId: string; grantor: string; revoked: boolean; revokedAt?: string; revokedBy?: string;
  checkedAt: string; statusSignature: string; statusKeyId: string;
};

async function registryKey(): Promise<{ keyId: string; publicKey: Uint8Array }> {
  const doc = await (await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env)).json() as {
    keys: Array<{ keyId: string; publicKeyB64: string }>;
  };
  return { keyId: doc.keys[0]!.keyId, publicKey: new Uint8Array(Buffer.from(doc.keys[0]!.publicKeyB64, "base64url")) };
}

function signedBytes(s: Status): Uint8Array {
  return new TextEncoder().encode(canonicalizeJcs({
    purpose: "aroha.revocation-status/v1",
    mandateId: s.mandateId,
    grantor: s.grantor,
    revoked: s.revoked,
    ...(s.revokedAt !== undefined ? { revokedAt: s.revokedAt } : {}),
    checkedAt: s.checkedAt,
  }));
}

async function getStatus(mandateId: string, grantor: string) {
  return t.app.request(`/v1/mandates/${encodeURIComponent(mandateId)}/revoked?grantor=${encodeURIComponent(grantor)}`, {}, t.env);
}

describe("signed revocation status", () => {
  it("signs a 'not revoked' and a 'revoked' answer; tampering breaks the signature", async () => {
    const human = await party();
    const agent = await party();
    const m = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 10 }, human.priv);
    const key = await registryKey();

    const before = await getStatus(m.mandate.mandateId, human.did);
    expect(before.status).toBe(200);
    expect(before.headers.get("Cache-Control")).toBe("no-store");
    const s0 = await before.json() as Status;
    expect(s0).toMatchObject({ revoked: false, statusKeyId: key.keyId });
    expect(Math.abs(Date.parse(s0.checkedAt) - Date.now())).toBeLessThan(10_000);
    expect(await ed.verifyAsync(Buffer.from(s0.statusSignature, "base64url"), signedBytes(s0), key.publicKey)).toBe(true);
    // A replayed "not revoked" altered to look like another mandate fails.
    expect(await ed.verifyAsync(
      Buffer.from(s0.statusSignature, "base64url"), signedBytes({ ...s0, mandateId: "other" }), key.publicKey,
    )).toBe(false);

    const revokedAt = new Date().toISOString();
    const sig = await ed.signAsync(new TextEncoder().encode(mandateRevocationPayload(m.mandate.mandateId, revokedAt)), human.priv);
    expect((await t.app.request(`/v1/mandates/${encodeURIComponent(m.mandate.mandateId)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: m.token, revokedAt, revoker: human.did, signature: Buffer.from(sig).toString("base64url") }),
    }, t.env)).status).toBe(200);

    const s1 = await (await getStatus(m.mandate.mandateId, human.did)).json() as Status;
    expect(s1).toMatchObject({ revoked: true, revokedBy: human.did });
    expect(typeof s1.revokedAt).toBe("string");
    expect(await ed.verifyAsync(Buffer.from(s1.statusSignature, "base64url"), signedBytes(s1), key.publicKey)).toBe(true);
    // Flipping the verdict invalidates it.
    expect(await ed.verifyAsync(
      Buffer.from(s1.statusSignature, "base64url"), signedBytes({ ...s1, revoked: false, revokedAt: undefined }), key.publicKey,
    )).toBe(false);
  });

  it("503 when no signing key is configured (fail closed, no unsigned status)", async () => {
    t.env.REGISTRY_SIGNING_KEY = undefined;
    const res = await getStatus("m1", "did:aroha:zabc");
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "Registry signing is not configured on this deployment" });
  });
});
