// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  generateDID,
  generateDid,
  generateContentAddressedDID,
  rotateDIDKey,
  revokeKey,
  verifyRevocation,
  buildDIDDocument,
  extractPublicKey,
  extractEndpoint,
  extractNamespace,
  toMultibase,
  fromMultibase,
  revokeCurrentKey,
  controllerRecoverKey,
  verifyControllerRecovery,
  verifyDIDKeyChange,
  isContentAddressedDid,
  selectVerificationMethod,
} from "./did.js";

describe("toMultibase / fromMultibase", () => {
  it("round-trips a Uint8Array", () => {
    const bytes = new Uint8Array(32).fill(42);
    const encoded = toMultibase(bytes);
    expect(encoded).toMatch(/^z/);
    const decoded = fromMultibase(encoded);
    expect(decoded).toEqual(bytes);
  });

  it("throws on non-base58btc multibase prefix", () => {
    expect(() => fromMultibase("mSomeBase64")).toThrow("Only base58btc");
  });
});

describe("generateDID", () => {
  it("produces a DID with the expected format", async () => {
    const kp = await generateDID("test-agent", "https://example.com/aroha");
    expect(kp.did).toBe("did:aroha:test-agent");
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it("embeds the endpoint in the DID document service", async () => {
    const kp = await generateDID("my-agent", "https://agent.example.com");
    const endpoint = extractEndpoint(kp.document);
    expect(endpoint).toBe("https://agent.example.com");
  });

  it("embeds the public key in the verification method", async () => {
    const kp = await generateDID("key-agent", "https://example.com");
    const extracted = extractPublicKey(kp.document);
    expect(extracted).toEqual(kp.publicKey);
  });

  it("sets @context, authentication, assertionMethod, keyAgreement", async () => {
    const kp = await generateDID("ctx-agent", "https://example.com");
    const doc = kp.document;
    expect(doc["@context"]).toContain("https://www.w3.org/ns/did/v1");
    expect(doc.authentication).toContain(`${kp.did}#key-1`);
    expect(doc.assertionMethod).toContain(`${kp.did}#key-1`);
    expect(doc.keyAgreement).toContain(`${kp.did}#key-1`);
  });
});

describe("generateContentAddressedDID", () => {
  it("produces a did:aroha:<pubkey> DID matching generateDid(publicKey)", async () => {
    const kp = await generateContentAddressedDID("https://example.com/aroha");
    expect(kp.did).toBe(generateDid(kp.publicKey));
    expect(kp.did).toMatch(/^did:aroha:z/);
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it("has no room for an agentId — two calls never collide on that basis", async () => {
    const a = await generateContentAddressedDID("https://example.com");
    const b = await generateContentAddressedDID("https://example.com");
    expect(a.did).not.toBe(b.did);
  });

  it("is self-certifying: the DID's own suffix decodes back to its public key", async () => {
    const kp = await generateContentAddressedDID("https://example.com");
    const suffix = kp.did.slice("did:aroha:".length);
    expect(fromMultibase(suffix)).toEqual(kp.publicKey);
  });

  it("embeds the endpoint and public key exactly as generateDID does", async () => {
    const kp = await generateContentAddressedDID("https://agent.example.com");
    expect(extractEndpoint(kp.document)).toBe("https://agent.example.com");
    expect(extractPublicKey(kp.document)).toEqual(kp.publicKey);
    expect(kp.document.id).toBe(kp.did);
  });

  it("has no namespace (extractNamespace returns null)", async () => {
    const kp = await generateContentAddressedDID("https://example.com");
    expect(extractNamespace(kp.did)).toBeNull();
  });
});

describe("buildDIDDocument", () => {
  it("reconstructs a document from an existing key", async () => {
    const original = await generateDID("rebuild-agent", "https://example.com");
    const doc = buildDIDDocument(
      "rebuild-agent",
      original.publicKey,
      "https://example.com",
      original.document.created
    );
    expect(doc.id).toBe("did:aroha:rebuild-agent");
    expect(extractPublicKey(doc)).toEqual(original.publicKey);
  });
});

describe("extractPublicKey / extractEndpoint", () => {
  it("throws when there are no verification methods", () => {
    const doc = {
      "@context": [],
      id: "did:aroha:empty",
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      keyAgreement: [],
      service: [],
      created: "",
      updated: "",
    };
    expect(() => extractPublicKey(doc)).toThrow("no verification methods");
  });

  it("throws when there is no ArohaEndpoint service", async () => {
    const kp = await generateDID("no-svc", "https://example.com");
    const doc = { ...kp.document, service: [] };
    expect(() => extractEndpoint(doc)).toThrow("no ArohaEndpoint service");
  });
});

describe("rotateDIDKey", () => {
  it("returns a new keypair with a different public key", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    expect(Buffer.from(rotated.publicKey).toString("hex"))
      .not.toBe(Buffer.from(original.publicKey).toString("hex"));
  });

  it("adds a keyHistory entry signed by the predecessor", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    expect(rotated.document.keyHistory).toHaveLength(1);
    const record = rotated.document.keyHistory![0];
    expect(record.rotatedAt).toBeTruthy();
    expect(record.predecessorSignature).toBeTruthy();
  });

  it("rotation record has valid predecessor signature", async () => {
    const { verifyKeyRotation } = await import("./web-did.js");
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original);
    const record = rotated.document.keyHistory![0];
    expect(await verifyKeyRotation(record)).toBe(true);
  });

  it("extractPublicKey returns the new key after rotation (past cool-down)", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original, 0); // 0-hour cool-down for test
    const extracted = extractPublicKey(rotated.document);
    expect(Buffer.from(extracted).toString("hex"))
      .toBe(Buffer.from(rotated.publicKey).toString("hex"));
  });

  // Previously asserted that extractPublicKey THROWS during cool-down, which
  // made the agent unverifiable for 24h after every routine rotation. It now
  // keeps trusting the predecessor until trustAfter.
  it("extractPublicKey returns the predecessor key during cool-down window", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original, 24); // 24-hour cool-down
    expect(extractPublicKey(rotated.document)).toEqual(original.publicKey);
  });

  it("extractPublicKey switches to the new key once trustAfter has passed", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const rotated = await rotateDIDKey(original, 24);
    const later = new Date(Date.now() + 25 * 3_600_000);
    expect(extractPublicKey(rotated.document, undefined, later)).toEqual(rotated.publicKey);
  });

  it("walks back through chained rotations that are all still cooling down", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const r1 = await rotateDIDKey(original, 24);
    const r2 = await rotateDIDKey(r1, 24);
    expect(extractPublicKey(r2.document)).toEqual(original.publicKey);
  });

  it("keeps additional (device) verification methods across rotation", async () => {
    const original = await generateDID("my-agent", "https://example.com");
    const device = await generateDID("device", "https://example.com");
    original.document.verificationMethod.push({
      id: `${original.did}#device-2`,
      type: "Ed25519VerificationKey2020",
      controller: original.did,
      publicKeyMultibase: toMultibase(device.publicKey),
    });
    const rotated = await rotateDIDKey(original, 0);
    expect(rotated.document.verificationMethod).toHaveLength(2);
    expect(extractPublicKey(rotated.document, `${original.did}#device-2`)).toEqual(device.publicKey);
  });
});

import { generateWebAgent, rotateKey, verifyKeyRotation } from "./web-did.js";

describe("resolveWebDID — rotation chain verification", () => {
  it("verifyKeyRotation returns true for a valid rotation", async () => {
    const agent = await generateWebAgent("example.com", "test-agent");
    const rotated = await rotateKey(agent);
    const record = rotated.webDocument.arohaWeb.keyHistory[0];
    expect(await verifyKeyRotation(record)).toBe(true);
  });

  it("verifyKeyRotation returns false for a tampered rotation record", async () => {
    const agent = await generateWebAgent("example.com", "test-agent");
    const rotated = await rotateKey(agent);
    const record = { ...rotated.webDocument.arohaWeb.keyHistory[0] };
    // Tamper with the signature
    record.predecessorSignature = "invalidsignature";
    expect(await verifyKeyRotation(record)).toBe(false);
  });
});

describe("Emergency key revocation", () => {
  it("revokeKey adds revokedKeys entry to DID document", async () => {
    const agent = await generateDID("revoke-test", "http://localhost");
    const revoked = await revokeKey(agent, "Compromised — emergency revocation");
    expect(revoked.document.revokedKeys).toHaveLength(1);
    expect(revoked.document.revokedKeys![0].reason).toBe("Compromised — emergency revocation");
    expect(revoked.document.revokedKeys![0].keyMultibase).toBe(
      agent.document.verificationMethod[0].publicKeyMultibase
    );
  });

  it("extractPublicKey throws when current key is in revokedKeys", async () => {
    const agent = await generateDID("revoke-test-2", "http://localhost");
    // Simulate a document where the active verificationMethod key is itself listed as revoked
    const currentKeyMultibase = agent.document.verificationMethod[0].publicKeyMultibase;
    const docWithRevokedCurrentKey = {
      ...agent.document,
      revokedKeys: [
        {
          keyMultibase: currentKeyMultibase,
          revokedAt: new Date().toISOString(),
          reason: "stolen",
        },
      ],
    };
    expect(() => extractPublicKey(docWithRevokedCurrentKey)).toThrow(/revoked/);
  });

  // SECURITY FIX: this test used to assert the new key was trusted
  // immediately ("no cooldown") — the takeover-by-key-thief bug. revokeKey
  // now stages the new key under the normal cool-down.
  it("revokeKey does NOT give the new key immediate trust", async () => {
    const agent = await generateDID("revoke-test-3", "http://localhost");
    const revoked = await revokeKey(agent, "stolen");
    // Old key revoked, new key cooling down → nothing trusted yet.
    expect(() => extractPublicKey(revoked.document)).toThrow(/revoked|cool-down/i);
    expect(revoked.document.keyHistory).toHaveLength(1);
    const later = new Date(Date.now() + 25 * 3_600_000);
    expect(extractPublicKey(revoked.document, undefined, later)).toEqual(revoked.publicKey);
  });

  it("revokeKey's staged key is accepted by verifyDIDKeyChange only as a cool-down rotation", async () => {
    const agent = await generateDID("revoke-test-5", "http://localhost");
    const revoked = await revokeKey(agent, "stolen");
    const result = await verifyDIDKeyChange(agent.document, revoked.document);
    expect(result).toMatchObject({ accepted: true, kind: "rotation", immediate: false });
  });

  it("revokeCurrentKey removes trust without installing any key", async () => {
    const agent = await generateDID("revoke-only", "http://localhost");
    const doc = await revokeCurrentKey(agent, "lost laptop");
    expect(doc.verificationMethod[0].publicKeyMultibase).toBe(toMultibase(agent.publicKey));
    expect(doc.keyHistory ?? []).toHaveLength(0);
    expect(() => extractPublicKey(doc)).toThrow(/revoked/);
  });

  it("revokeKey signs the revocation with the old key", async () => {
    const agent = await generateDID("revoke-test-4", "http://localhost");
    const revoked = await revokeKey(agent, "test");
    expect(revoked.document.revokedKeys![0].selfSignature).toBeDefined();
    expect(revoked.document.revokedKeys![0].selfSignature!.length).toBeGreaterThan(0);
  });

  it("selfSignature is cryptographically valid — verifyRevocation returns true", async () => {
    const agent = await generateDID("revoke-verify-test", "http://localhost");
    const revoked = await revokeKey(agent, "testing verification");
    const record = revoked.document.revokedKeys![0];
    const isValid = await verifyRevocation(record, agent.publicKey);
    expect(isValid).toBe(true);
  });
});

describe("DID namespacing", () => {
  it("generateDID with namespace produces did:aroha:namespace.agentId", async () => {
    const agent = await generateDID("invoice-processor", "http://localhost", { namespace: "acme-corp" });
    expect(agent.did).toBe("did:aroha:acme-corp.invoice-processor");
    expect(agent.document.id).toBe("did:aroha:acme-corp.invoice-processor");
  });

  it("generateDID without namespace is unchanged (backwards compat)", async () => {
    const agent = await generateDID("invoice-processor", "http://localhost");
    expect(agent.did).toBe("did:aroha:invoice-processor");
  });

  it("generateDID throws on invalid namespace", async () => {
    await expect(generateDID("agent", "http://localhost", { namespace: "UPPER_CASE" }))
      .rejects.toThrow(/Invalid namespace/);
  });

  it("extractNamespace returns null for un-namespaced DID", () => {
    expect(extractNamespace("did:aroha:flight-agent")).toBeNull();
  });

  it("extractNamespace returns the namespace for namespaced DID", () => {
    expect(extractNamespace("did:aroha:acme-corp.invoice-processor")).toBe("acme-corp");
  });
});

describe("base58 decode — general (not fixed 32-byte)", () => {
  it("round-trips inputs of other lengths, including leading zero bytes", () => {
    for (const bytes of [
      new Uint8Array([1, 2, 3]),
      new Uint8Array([0, 0, 7]),
      new Uint8Array(34).fill(9),
      Uint8Array.from([0xed, 0x01, ...new Uint8Array(32).fill(5)]),
      new Uint8Array([0, ...new Uint8Array(32).fill(200)]),
    ]) {
      expect(fromMultibase(toMultibase(bytes))).toEqual(bytes);
    }
  });

  it("no longer pads short input to 32 bytes", () => {
    expect(fromMultibase("z2").length).toBe(1);
  });

  it("round-trips a 32-byte key with a leading zero byte", () => {
    const key = new Uint8Array(32).fill(1);
    key[0] = 0;
    expect(fromMultibase(toMultibase(key))).toEqual(key);
  });
});

describe("isContentAddressedDid", () => {
  it("is true for generateDid / generateContentAddressedDID", async () => {
    const kp = await generateContentAddressedDID("https://example.com");
    expect(isContentAddressedDid(kp.did)).toBe(true);
  });

  it("is false for named DIDs, including ones that start with z", () => {
    expect(isContentAddressedDid("did:aroha:flight-agent")).toBe(false);
    expect(isContentAddressedDid("did:aroha:zebra")).toBe(false);
    expect(isContentAddressedDid("did:aroha:acme.zz")).toBe(false);
    expect(isContentAddressedDid("did:aroha-web:example.com:x")).toBe(false);
  });
});

describe("proof-selected verification method", () => {
  async function multiKeyAgent() {
    const agent = await generateDID("multi", "https://example.com");
    const device = await generateDID("device", "https://example.com");
    agent.document.verificationMethod.push({
      id: `${agent.did}#device-2`,
      type: "Ed25519VerificationKey2020",
      controller: agent.did,
      publicKeyMultibase: toMultibase(device.publicKey),
    });
    return { agent, device };
  }

  it("selects the named method (absolute or relative id)", async () => {
    const { agent, device } = await multiKeyAgent();
    expect(extractPublicKey(agent.document, `${agent.did}#device-2`)).toEqual(device.publicKey);
    expect(extractPublicKey(agent.document, "#device-2")).toEqual(device.publicKey);
  });

  it("falls back to the first method when no id is given", async () => {
    const { agent } = await multiKeyAgent();
    expect(extractPublicKey(agent.document)).toEqual(agent.publicKey);
  });

  it("throws for an id the document does not list (other than legacy #key-1)", async () => {
    const { agent } = await multiKeyAgent();
    expect(() => selectVerificationMethod(agent.document, `${agent.did}#nope`)).toThrow(/no verification method/);
    expect(() => selectVerificationMethod(agent.document, "did:aroha:someone-else#key-1")).toThrow();
  });
});

describe("controller recovery", () => {
  async function controlled() {
    const person = await generateContentAddressedDID("https://person.example");
    const agent = await generateDID("controlled-agent", "https://example.com", { controller: person.did });
    return { person, agent };
  }

  it("controllerRecoverKey installs an immediately-trusted key, verified by verifyDIDKeyChange", async () => {
    const { person, agent } = await controlled();
    const fresh = await generateDID("fresh", "https://example.com");
    const recovered = await controllerRecoverKey(agent.document, fresh.publicKey, person.privateKey, { reason: "laptop stolen" });

    expect(extractPublicKey(recovered)).toEqual(fresh.publicKey);
    expect(recovered.revokedKeys?.[0].keyMultibase).toBe(toMultibase(agent.publicKey));
    expect(await verifyControllerRecovery(agent.did, recovered.controllerRecoveries![0], person.publicKey)).toBe(true);

    const result = await verifyDIDKeyChange(agent.document, recovered, {
      resolveControllerPublicKey: async (did) => (did === person.did ? person.publicKey : null),
    });
    expect(result).toEqual({ accepted: true, kind: "controller-recovery", immediate: true });
  });

  it("overrides a thief's staged revokeKey rotation before its cool-down ends", async () => {
    const { person, agent } = await controlled();
    const thiefStaged = await revokeKey(agent, "thief"); // thief holds agent.privateKey
    const fresh = await generateDID("fresh", "https://example.com");
    const recovered = await controllerRecoverKey(thiefStaged.document, fresh.publicKey, person.privateKey);
    expect(extractPublicKey(recovered)).toEqual(fresh.publicKey);
    // The thief's staged key is revoked by the recovery.
    expect(recovered.revokedKeys!.some((r) => r.keyMultibase === toMultibase(thiefStaged.publicKey))).toBe(true);
  });

  it("a non-controller signature is rejected", async () => {
    const { person, agent } = await controlled();
    const mallory = await generateContentAddressedDID("https://mallory.example");
    const fresh = await generateDID("fresh", "https://example.com");
    const forged = await controllerRecoverKey(agent.document, fresh.publicKey, mallory.privateKey);
    const result = await verifyDIDKeyChange(agent.document, forged, {
      resolveControllerPublicKey: async (did) => (did === person.did ? person.publicKey : null),
    });
    expect(result.accepted).toBe(false);
    expect(await verifyControllerRecovery(agent.did, forged.controllerRecoveries![0], person.publicKey)).toBe(false);
  });

  it("an update that swaps in its own controller is rejected", async () => {
    const { agent } = await controlled();
    const mallory = await generateContentAddressedDID("https://mallory.example");
    const fresh = await generateDID("fresh", "https://example.com");
    const hijacked = await controllerRecoverKey(
      { ...agent.document, controller: mallory.did }, fresh.publicKey, mallory.privateKey
    );
    const result = await verifyDIDKeyChange(agent.document, hijacked, {
      resolveControllerPublicKey: async () => mallory.publicKey,
    });
    expect(result.accepted).toBe(false);
  });

  it("refuses when the document has no distinct controller", async () => {
    const agent = await generateDID("no-controller", "https://example.com");
    const fresh = await generateDID("fresh", "https://example.com");
    await expect(controllerRecoverKey(agent.document, fresh.publicKey, agent.privateKey)).rejects.toThrow(/no controller/);
    await expect(
      controllerRecoverKey({ ...agent.document, controller: agent.did }, fresh.publicKey, agent.privateKey)
    ).rejects.toThrow(/distinct/);
  });

  it("verifyDIDKeyChange rejects a key swap with no rotation or controller record", async () => {
    const agent = await generateDID("swap", "https://example.com");
    const other = await generateDID("other", "https://example.com");
    const swapped = {
      ...agent.document,
      verificationMethod: [{ ...agent.document.verificationMethod[0], publicKeyMultibase: toMultibase(other.publicKey) }],
    };
    const result = await verifyDIDKeyChange(agent.document, swapped);
    expect(result.accepted).toBe(false);
  });

  it("verifyDIDKeyChange rejects a rotation whose cool-down is below the minimum", async () => {
    const agent = await generateDID("short-cool", "https://example.com");
    const rotated = await rotateDIDKey(agent, 0);
    expect((await verifyDIDKeyChange(agent.document, rotated.document)).accepted).toBe(false);
    expect((await verifyDIDKeyChange(agent.document, rotated.document, { minCoolDownHours: 0 })).accepted).toBe(true);
  });
});
