// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * did:aroha-web rotation-chain, DNS-anchoring, multi-key and fail-closed
 * rules (resolveWebDID). Each test names the control it pins; the
 * surrounding rationale is in web-did.ts and spec/web-did.md.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  generateWebAgent,
  rotateKey,
  resolveWebDID,
  dnsTXTValue,
  keyCommitmentHash,
  selectWebDIDKey,
  webDIDPublicKeys,
  verifyKeyRotation,
  checkKeyRotation,
  type WebAgentKeyPair,
  type WebDIDDocument,
} from "./web-did.js";
import { toMultibase, type KeyRotationRecord } from "./did.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const HOUR = 3_600_000;

function serve(doc: unknown) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(doc), { status: 200 })));
}
afterEach(() => { vi.unstubAllGlobals(); });

const quiet = { logger: () => {} };
const dnsFor = (...records: string[]) => async () => records;

function clone<T>(x: T): T { return JSON.parse(JSON.stringify(x)) as T; }

describe("resolveWebDID — DNS anchoring and cool-down", () => {
  it("DNS still names the OLD key: during cool-down only the old (anchored) key is accepted", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    serve(b.webDocument);
    const r = await resolveWebDID(b.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet });
    expect(r.dnsVerified).toBe(true);
    expect(r.keyTrusted).toBe(false);
    expect(webDIDPublicKeys(r)).toEqual([a.publicKey]);
    expect(r.acceptedKeys[0].role).toBe("anchored");
  });

  it("DNS still names the OLD key: after the cool-down the new key is accepted", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    serve(b.webDocument);
    const r = await resolveWebDID(b.did, {
      dnsResolver: dnsFor(a.dnsTXTRecord), now: new Date(Date.now() + 25 * HOUR), ...quiet,
    });
    expect(r.keyTrusted).toBe(true);
    expect(webDIDPublicKeys(r)).toEqual([b.publicKey]);
  });

  it("DNS names the NEW key: both keys are accepted during the cool-down (graceful cutover)", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    serve(b.webDocument);
    const r = await resolveWebDID(b.did, { dnsResolver: dnsFor(b.dnsTXTRecord), ...quiet });
    expect(r.keyTrusted).toBe(false);
    expect(webDIDPublicKeys(r)).toEqual([b.publicKey, a.publicKey]);
    expect(selectWebDIDKey(r)).toEqual(b.publicKey);
  });

  it("stripping keyHistory does not bypass the cool-down: DNS (old key) no longer matches anything", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    const stripped = clone(b.webDocument);
    stripped.arohaWeb.keyHistory = [];
    serve(stripped);
    const r = await resolveWebDID(b.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet });
    expect(r.dnsVerified).toBe(false);
    expect(r.keyTrusted).toBe(false);
    expect(r.acceptedKeys).toEqual([]);
    expect(() => selectWebDIDKey(r)).toThrow(/no accepted key/);
  });

  it("walks a two-rotation chain from the DNS anchor, one cool-down at a time", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    const c = await rotateKey(b, 24);
    serve(c.webDocument);
    const dns = dnsFor(a.dnsTXTRecord);
    const at = (h: number) => resolveWebDID(c.did, { dnsResolver: dns, now: new Date(Date.now() + h * HOUR), ...quiet });
    // Both rotations were made "now", so both cool-downs end together.
    expect(webDIDPublicKeys(await at(1))).toEqual([a.publicKey]);
    const later = await at(25);
    expect(webDIDPublicKeys(later)).toEqual([c.publicKey]);
    expect(later.keyTrusted).toBe(true);
  });

  it("fails closed when DNS names a key outside the chain", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const other = await generateWebAgent("acme.com", "pay");
    serve(a.webDocument);
    const r = await resolveWebDID(a.did, { dnsResolver: dnsFor(other.dnsTXTRecord), ...quiet });
    expect(r.dnsVerified).toBe(false);
    expect(r.acceptedKeys).toEqual([]);
  });

  it("ignores a TXT record for a different path on the same domain", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    serve(a.webDocument);
    const wrongPath = dnsTXTValue("did:aroha-web:acme.com:billing", a.publicKey);
    const r = await resolveWebDID(a.did, { dnsResolver: dnsFor(wrongPath), ...quiet });
    expect(r.dnsVerified).toBe(false);
  });
});

describe("resolveWebDID — rotation chain integrity", () => {
  it("rejects a keyHistory whose newest record does not commit to the current key", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    const swapped = clone(b.webDocument);
    const intruder = await generateWebAgent("acme.com", "pay");
    swapped.verificationMethod[0].publicKeyMultibase = toMultibase(intruder.publicKey);
    swapped.arohaWeb.keyCommitmentHash = keyCommitmentHash(intruder.publicKey);
    serve(swapped);
    await expect(resolveWebDID(b.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet }))
      .rejects.toThrow(/does not commit to the current primary key/);
  });

  it("rejects a chain whose links do not connect", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    const c = await rotateKey(b, 24);
    // Drop the middle link: c's record now claims to follow a's key directly.
    const broken = clone(c.webDocument);
    const unrelated = await rotateKey(await generateWebAgent("acme.com", "pay"), 24);
    broken.arohaWeb.keyHistory = [c.webDocument.arohaWeb.keyHistory[0], unrelated.webDocument.arohaWeb.keyHistory[0]];
    serve(broken);
    await expect(resolveWebDID(c.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet }))
      .rejects.toThrow(/rotation chain is broken|signed for/);
  });

  it("rejects a v2 record lifted from another DID that shares the key", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    // Same keys, served as a DIFFERENT DID on the same domain.
    const otherDid = "did:aroha-web:acme.com:billing";
    const lifted = clone(b.webDocument) as WebDIDDocument;
    lifted.id = otherDid;
    lifted.arohaWeb.path = "billing";
    serve(lifted);
    await expect(resolveWebDID(otherDid, { dnsResolver: dnsFor(dnsTXTValue(otherDid, a.publicKey)), ...quiet }))
      .rejects.toThrow(/signed for did:aroha-web:acme.com:pay/);
  });

  it("rejects a v2 record whose trustAfter was shortened after signing", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await rotateKey(a, 24);
    const edited = clone(b.webDocument);
    edited.arohaWeb.keyHistory[0].trustAfter = edited.arohaWeb.keyHistory[0].rotatedAt;
    serve(edited);
    await expect(resolveWebDID(b.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet }))
      .rejects.toThrow(/invalid predecessor signature/);
  });
});

/** A legacy (v1) rotation record exactly as SDKs before the v2 format signed it. */
async function legacyRotation(from: WebAgentKeyPair, to: WebAgentKeyPair, rotatedAt: Date, trustAfter: Date): Promise<KeyRotationRecord> {
  const predecessorKey = toMultibase(from.publicKey);
  const newKeyHash = keyCommitmentHash(to.publicKey);
  const sig = await ed.signAsync(new TextEncoder().encode(predecessorKey + newKeyHash + rotatedAt.toISOString()), from.privateKey);
  return {
    rotatedAt: rotatedAt.toISOString(),
    trustAfter: trustAfter.toISOString(),
    predecessorKey,
    newKeyHash,
    predecessorSignature: Buffer.from(sig).toString("base64url"),
  };
}

describe("legacy v1 rotation records", () => {
  it("still verify, flagged deprecated", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await generateWebAgent("acme.com", "pay");
    const rec = await legacyRotation(a, b, new Date(), new Date(Date.now() + 24 * HOUR));
    expect(await verifyKeyRotation(rec)).toBe(true);
    expect(await checkKeyRotation(rec, a.did)).toEqual({ valid: true, deprecated: true });
  });

  it("an unsigned, shortened v1 trustAfter cannot shorten the default 24h cool-down", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const b = await generateWebAgent("acme.com", "pay");
    const rotatedAt = new Date(Date.now() - 2 * HOUR);
    const rec = await legacyRotation(a, b, rotatedAt, rotatedAt); // "no cool-down"
    const doc = clone(b.webDocument);
    doc.arohaWeb.keyHistory = [rec];
    serve(doc);
    const logs: string[] = [];
    const r = await resolveWebDID(a.did, { dnsResolver: dnsFor(a.dnsTXTRecord), logger: (m) => logs.push(m) });
    expect(r.deprecatedRotations).toBe(true);
    expect(r.keyTrusted).toBe(false);
    expect(webDIDPublicKeys(r)).toEqual([a.publicKey]);
    expect(logs.some((m) => /legacy v1/.test(m))).toBe(true);
  });
});

describe("multi-key documents", () => {
  async function withDeviceKey() {
    const a = await generateWebAgent("acme.com", "pay");
    const devPriv = ed.utils.randomPrivateKey();
    const devPub = await ed.getPublicKeyAsync(devPriv);
    const doc = clone(a.webDocument);
    doc.verificationMethod.push({
      id: `${a.did}#device-2`, type: "Ed25519VerificationKey2020", controller: a.did, publicKeyMultibase: toMultibase(devPub),
    });
    return { a, devPub, doc };
  }

  it("selects the key the proof's verificationMethod names, when DNS commits to it", async () => {
    const { a, devPub, doc } = await withDeviceKey();
    serve(doc);
    const r = await resolveWebDID(a.did, {
      dnsResolver: dnsFor(a.dnsTXTRecord, dnsTXTValue(a.did, devPub)), ...quiet,
    });
    expect(selectWebDIDKey(r, `${a.did}#device-2`)).toEqual(devPub);
    expect(selectWebDIDKey(r, "#device-2")).toEqual(devPub);
    expect(selectWebDIDKey(r, `${a.did}#key-1`)).toEqual(a.publicKey);
  });

  it("refuses a device key DNS does not commit to", async () => {
    const { a, doc } = await withDeviceKey();
    serve(doc);
    const r = await resolveWebDID(a.did, { dnsResolver: dnsFor(a.dnsTXTRecord), ...quiet });
    expect(() => selectWebDIDKey(r, `${a.did}#device-2`)).toThrow(/no accepted key/);
    expect(selectWebDIDKey(r)).toEqual(a.publicKey);
  });

  it("rotation replaces only the primary key and keeps device methods", async () => {
    const { a, doc } = await withDeviceKey();
    const rotated = await rotateKey({ ...a, document: doc, webDocument: doc }, 24);
    expect(rotated.webDocument.verificationMethod).toHaveLength(2);
    expect(rotated.webDocument.verificationMethod[1].id).toBe(`${a.did}#device-2`);
  });
});

describe("fail closed without DNS", () => {
  it("throws when no DNS resolver is available and allowNoDns is not set", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    serve(a.webDocument);
    await expect(resolveWebDID(a.did, { useSystemDns: false })).rejects.toThrow(/no DNS resolver available/);
  });

  it("allowNoDns resolves HTTPS-only, logged, with dnsVerified false", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    serve(a.webDocument);
    const logs: string[] = [];
    const r = await resolveWebDID(a.did, { allowNoDns: true, useSystemDns: false, logger: (m) => logs.push(m) });
    expect(r.dnsVerified).toBe(false);
    expect(r.keyTrusted).toBe(true);
    expect(selectWebDIDKey(r)).toEqual(a.publicKey);
    expect(logs.some((m) => /HTTPS-only/.test(m))).toBe(true);
  });

  it("(did:aroha) v2 rotation records bind their DID: verifyDIDKeyChange rejects one re-labelled for another DID", async () => {
    const { generateDID, rotateDIDKey, verifyDIDKeyChange } = await import("./did.js");
    const d = await generateDID("bound-a", "http://localhost");
    const rotated = await rotateDIDKey(d, 24);
    expect(rotated.document.keyHistory![0]).toMatchObject({ v: 2, did: d.did });
    expect((await verifyDIDKeyChange(d.document, rotated.document)).accepted).toBe(true);
    const prevOther = { ...clone(d.document), id: "did:aroha:someone-else" };
    const nextOther = { ...clone(rotated.document), id: "did:aroha:someone-else" };
    const res = await verifyDIDKeyChange(prevOther, nextOther);
    expect(res.accepted).toBe(false);
    expect(res.reason).toMatch(/different DID/);
  });

  it("a throwing DNS resolver yields no accepted keys", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    serve(a.webDocument);
    const r = await resolveWebDID(a.did, { dnsResolver: async () => { throw new Error("SERVFAIL"); }, ...quiet });
    expect(r.dnsVerified).toBe(false);
    expect(r.acceptedKeys).toEqual([]);
  });
});
