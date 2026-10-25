// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  generateDid,
  generateDID,
  incept,
  rotateKel,
  revokeAgent,
  recoverAgent,
  generateKelKeyMaterial,
  kelSourceFromLogs,
  InMemoryKelStore,
  verifyKel,
} from "@aroha-sdk/core";
import { buildSar, verifySar, verifySarWithResolver, publicKeyFromDid, hasSarShape } from "./sar.js";

/**
 * Two distinct DID forms exist in @aroha-sdk/core, and they matter here:
 *
 *   - `generateDid(publicKey)` (lowercase) is content-addressed —
 *     did:aroha:<base58btc(publicKey)> — self-certifying, the fast offline
 *     path this file mostly tests.
 *   - `generateDID(agentId, endpoint)` (uppercase) — used by every agent
 *     this repo's own local runtime actually mints (host/identity.ts) — is
 *     did:aroha:<agentId>, a human-readable but NOT content-addressed DID.
 *     Verifying one of those needs an external resolver; that's exactly
 *     verifySarWithResolver's reason to exist as a separate function.
 *
 * Using the wrong one to test the other's code path was the first version
 * of this file's own bug — content-addressed() below exists so that
 * mistake can't happen again.
 */
async function contentAddressed() {
  const kp = await generateKeyPair();
  return { did: generateDid(kp.publicKey), ...kp };
}

async function namespaced(agentId: string) {
  return generateDID(agentId, `http://127.0.0.1/${agentId}`);
}

describe("buildSar / verifySar — offline, self-certifying", () => {
  it("verifies a freshly built SAR with no network call", async () => {
    const a = await contentAddressed();
    const sar = await buildSar({
      did: a.did,
      privateKey: a.privateKey,
      capabilities: ["book-flight"],
      transports: [`http://127.0.0.1/${a.did}`],
    });
    const result = await verifySar(sar);
    expect(result.valid).toBe(true);
  });

  it("round-trips every field", async () => {
    const a = await contentAddressed();
    const sar = await buildSar({
      did: a.did,
      privateKey: a.privateKey,
      capabilities: ["web-search", "web-read"],
      transports: ["https://example.com/agent"],
      settlementRails: ["stripe", "usdc-base"],
      terms: { pricing: { amount: 0.01, currency: "USD" }, sla: { maxResponseMs: 2000, uptime: 0.99 } },
      ttlMs: 30_000,
    });
    expect(sar.capabilities).toEqual(["web-search", "web-read"]);
    expect(sar.settlementRails).toEqual(["stripe", "usdc-base"]);
    expect(sar.terms.pricing).toEqual({ amount: 0.01, currency: "USD" });
    expect(sar.ttl).toBe(30_000);
  });

  it("rejects a tampered capability list — the whole point of signing", async () => {
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["cheap-op"] });
    const tampered = { ...sar, capabilities: ["expensive-op", "drain-wallet"] };
    const result = await verifySar(tampered);
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects a signature from a different key than the DID commits to", async () => {
    const a = await contentAddressed();
    const attacker = await contentAddressed();
    // Sign as the attacker's key but claim to be agent `a`'s DID — the
    // scenario a forged record would actually look like.
    const sar = await buildSar({ did: a.did, privateKey: attacker.privateKey, capabilities: ["x"] });
    const result = await verifySar(sar);
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects an expired record", async () => {
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, ttlMs: 1000 });
    const result = await verifySar(sar, sar.issuedAt + 5000);
    expect(result).toEqual({ valid: false, reason: "expired" });
  });

  it("accepts a record right at the edge of its TTL, not a moment past it", async () => {
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, ttlMs: 1000 });
    expect((await verifySar(sar, sar.issuedAt + 999)).valid).toBe(true);
    expect((await verifySar(sar, sar.issuedAt + 1001)).valid).toBe(false);
  });

  it("rejects a malformed object rather than throwing", async () => {
    expect(await verifySar(null)).toEqual({ valid: false, reason: "bad_shape" });
    expect(await verifySar({})).toEqual({ valid: false, reason: "bad_shape" });
    expect(await verifySar("not an object")).toEqual({ valid: false, reason: "bad_shape" });
    expect(await verifySar({ did: "did:aroha:x", capabilities: [] })).toEqual({ valid: false, reason: "bad_shape" });
  });

  it("does not silently accept a record with an extra unsigned field grafted on", async () => {
    // Every field is part of the signed payload — appending one after
    // signing must invalidate it, not be silently ignored.
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey });
    const grafted = { ...sar, capabilities: [...sar.capabilities, "smuggled-in"] };
    expect((await verifySar(grafted)).valid).toBe(false);
  });
});

describe("publicKeyFromDid", () => {
  it("derives the exact key a content-addressed DID commits to", async () => {
    const a = await contentAddressed();
    const derived = publicKeyFromDid(a.did);
    expect(derived).not.toBeNull();
    expect(Buffer.from(derived!)).toEqual(Buffer.from(a.publicKey));
  });

  it("returns null for a namespaced DID — not content-addressed", async () => {
    const a = await namespaced("acme.research-agent");
    expect(publicKeyFromDid(a.did)).toBeNull();
  });

  it("returns null for a plain agentId DID — also not content-addressed", async () => {
    // This is the form host/identity.ts actually mints for every local
    // runtime agent today (did:aroha:<slug>) — asserting this explicitly so
    // a future change to that minting scheme has to consciously touch this
    // test, not silently change SAR's self-certifying coverage.
    const a = await namespaced("assistant");
    expect(a.did).toBe("did:aroha:assistant");
    expect(publicKeyFromDid(a.did)).toBeNull();
  });

  it("returns null for a non-aroha DID", () => {
    expect(publicKeyFromDid("did:web:example.com")).toBeNull();
  });

  it("returns null for garbage after the did:aroha: prefix", () => {
    expect(publicKeyFromDid("did:aroha:not-valid-multibase-!!!")).toBeNull();
  });
});

describe("verifySar — namespaced DIDs are explicitly out of scope", () => {
  it("refuses to self-certify a namespaced DID even with a technically-valid signature", async () => {
    const a = await namespaced("acme.research-agent");
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey });
    // Regardless of signature validity, a namespaced DID has no committed
    // key to check against — verifySar must say so, not silently pass or
    // silently fail for the wrong reason.
    expect(await verifySar(sar)).toEqual({ valid: false, reason: "not_self_certifying" });
  });
});

describe("verifySarWithResolver — the explicit path for namespaced DIDs", () => {
  it("verifies against a caller-supplied resolver", async () => {
    const a = await namespaced("acme.research-agent");
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey });
    const result = await verifySarWithResolver(sar, async (did) => {
      expect(did).toBe(a.did);
      return a.publicKey;
    });
    expect(result.valid).toBe(true);
  });

  it("rejects when the resolver returns no key", async () => {
    const a = await namespaced("acme.unregistered");
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey });
    const result = await verifySarWithResolver(sar, async () => null);
    expect(result.valid).toBe(false);
  });

  it("still enforces expiry before ever calling the resolver", async () => {
    const a = await namespaced("acme.x");
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, ttlMs: 1000 });
    let resolverCalled = false;
    const result = await verifySarWithResolver(
      sar,
      async () => {
        resolverCalled = true;
        return a.publicKey;
      },
      sar.issuedAt + 5000,
    );
    expect(result).toEqual({ valid: false, reason: "expired" });
    expect(resolverCalled).toBe(false);
  });

  it("also works end-to-end for a content-addressed DID via an explicit resolver", async () => {
    // verifySarWithResolver isn't restricted to namespaced DIDs — it's just
    // that content-addressed ones don't NEED it.
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey });
    const result = await verifySarWithResolver(sar, async () => a.publicKey);
    expect(result.valid).toBe(true);
  });
});

describe("SARs for rotatable E-DIDs", () => {
  it("verifies offline with the KEL attached, against the current key", async () => {
    const agent = await incept({ kind: "agent" });
    const sar = await buildSar({ did: agent.did, privateKey: agent.privateKey, capabilities: ["x"], kel: agent.kel });
    expect(publicKeyFromDid(agent.did)).toBeNull();
    expect(await verifySar(sar)).toMatchObject({ valid: true });
  });

  it("verifies against the ROTATED key, and stops accepting records signed by the old one", async () => {
    const agent = await incept({ kind: "agent" });
    const old = await buildSar({ did: agent.did, privateKey: agent.privateKey, kel: agent.kel });
    const rotated = await rotateKel(agent);

    const fresh = await buildSar({ did: agent.did, privateKey: rotated.privateKey, kel: rotated.kel });
    expect((await verifySar(fresh)).valid).toBe(true);

    // An index attaches the newer log to the old record: it no longer verifies.
    expect(await verifySar({ ...old, kel: rotated.kel })).toMatchObject({ valid: false, reason: "bad_signature" });
    // The log is fetched when not attached; the source's newer log wins over an older attachment.
    const { kel: _k, ...bare } = fresh;
    expect((await verifySar(bare, Date.now(), { kelSource: kelSourceFromLogs(rotated.kel) })).valid).toBe(true);
    expect((await verifySar(old, Date.now(), { kelSource: kelSourceFromLogs(rotated.kel) })).valid).toBe(false);
  });

  it("ignores any key written into the record itself", async () => {
    const agent = await incept({ kind: "agent" });
    const attacker = await generateKeyPair();
    const forged = await buildSar({ did: agent.did, privateKey: attacker.privateKey, kel: agent.kel });
    expect(await verifySar({ ...forged, publicKey: "z" + "1".repeat(43) } as never)).toMatchObject({ valid: false, reason: "bad_signature" });
  });

  it("reports missing, tampered and revoked logs", async () => {
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    const sar = await buildSar({ did: agent.did, privateKey: agent.privateKey });
    expect(await verifySar(sar)).toMatchObject({ valid: false, reason: "kel_unavailable" });

    const other = await incept({ kind: "agent" });
    expect(await verifySar({ ...sar, kel: other.kel })).toMatchObject({ valid: false, reason: "kel_invalid" });

    const r = await revokeAgent(person, agent.kel);
    const src = kelSourceFromLogs(r.agentKel, r.person.kel);
    expect(await verifySar(sar, Date.now(), { kelSource: src })).toMatchObject({ valid: false, reason: "revoked" });
    // The controller-authorised revoke cannot be checked without the person's log.
    expect(await verifySar({ ...sar, kel: r.agentKel })).toMatchObject({ valid: false, reason: "kel_invalid" });
  });

  it("verifies a recovered agent's record against the key the controller installed", async () => {
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    const newDevice = await generateKelKeyMaterial();
    const r = await recoverAgent(person, agent.kel, newDevice);
    const src = kelSourceFromLogs(r.person.kel);
    const sar = await buildSar({ did: agent.did, privateKey: newDevice.privateKey, kel: r.agentKel });
    expect((await verifySar(sar, Date.now(), { kelSource: src })).valid).toBe(true);
    const thief = await buildSar({ did: agent.did, privateKey: agent.privateKey, kel: r.agentKel });
    expect((await verifySar(thief, Date.now(), { kelSource: src })).valid).toBe(false);
  });

  it("with a KelStore, an index serving a rolled-back log cannot revive an old record", async () => {
    const agent = await incept({ kind: "agent" });
    const store = new InMemoryKelStore();
    const old = await buildSar({ did: agent.did, privateKey: agent.privateKey, kel: agent.kel });
    const rotated = await rotateKel(agent);
    const fresh = await buildSar({ did: agent.did, privateKey: rotated.privateKey, kel: rotated.kel });
    expect((await verifySar(fresh, Date.now(), { kelStore: store })).valid).toBe(true);
    expect((await verifySar(old, Date.now(), { kelStore: store })).valid).toBe(false);
  });
});

describe("verifySar — injected E-DID resolution (resolveKel)", () => {
  // The registry server injects its own acceptance path here. The rule that
  // matters — signature against the CURRENT key of the verified state — must
  // stay this module's whatever the resolver is.
  it("checks the signature against the state the resolver returns, not kelSource", async () => {
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const sar = await buildSar({ did: id.did, privateKey: rotated.privateKey });
    const seen: Array<[string, unknown]> = [];
    const resolveKel = async (did: string, attached: unknown) => {
      seen.push([did, attached]);
      return verifyKel(did, rotated.kel);
    };
    const kelSource = async () => {
      throw new Error("kelSource must not be consulted when resolveKel is given");
    };
    expect((await verifySar(sar, Date.now(), { resolveKel, kelSource })).valid).toBe(true);
    expect(seen).toEqual([[id.did, undefined]]);

    // The superseded key fails against the same resolved state.
    const old = await buildSar({ did: id.did, privateKey: id.privateKey });
    expect(await verifySar(old, Date.now(), { resolveKel })).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("maps a null resolution to kel_unavailable and a throwing one to kel_invalid", async () => {
    const id = await incept({ kind: "agent" });
    const sar = await buildSar({ did: id.did, privateKey: id.privateKey, kel: id.kel });
    expect(await verifySar(sar, Date.now(), { resolveKel: async () => null }))
      .toEqual({ valid: false, reason: "kel_unavailable" });
    expect(await verifySar(sar, Date.now(), { resolveKel: async () => { throw new Error("rejected"); } }))
      .toEqual({ valid: false, reason: "kel_invalid" });
  });
});

describe("hasSarShape", () => {
  it("rejects non-string capabilities and null terms, which an index could neither match nor serve", async () => {
    const kp = await generateKeyPair();
    const sar = await buildSar({ did: generateDid(kp.publicKey), privateKey: kp.privateKey, capabilities: ["a"] });
    expect(hasSarShape(sar)).toBe(true);
    expect(hasSarShape({ ...sar, capabilities: [{ id: "a" }] })).toBe(false);
    expect(hasSarShape({ ...sar, terms: null })).toBe(false);
    expect(await verifySar({ ...sar, terms: null })).toEqual({ valid: false, reason: "bad_shape" });
  });
});
