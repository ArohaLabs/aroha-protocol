// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mandate chains rooted in a PERSON (a rotatable did:aroha:E… identity) and
 * verified against Key Event Logs: the root must be a person, every agent in
 * the chain must be unrevoked, and signatures are checked against keys that
 * are current at verification time.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  incept,
  rotateKel,
  revokeAgent,
  revokeKelSelf,
  recoverAgent,
  generateKelKeyMaterial,
  kelSourceFromLogs,
  InMemoryKelStore,
  generateDid,
  type KelEvent,
  type KelIdentity,
  type KelSource,
  type SpendingConstraints,
} from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandateChain,
  createMandateKeyResolver,
  resolveContentAddressedKey,
} from "./mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const ROOT: SpendingConstraints = {
  spendLimitUsd: 500,
  sessionLimitUsd: 200,
  requireHumanApprovalAboveUsd: 100,
  allowedMerchants: ["did:aroha:merchant-a"],
};
const CART: SpendingConstraints = { spendLimitUsd: 100, allowedMerchants: ["did:aroha:merchant-a"] };
const PAY: SpendingConstraints = { spendLimitUsd: 50, allowedMerchants: ["did:aroha:merchant-a"] };

/** A mutable directory of logs — what a registry or peer would serve. */
function directory(...ids: Array<{ did: string; kel: KelEvent[] }>) {
  const logs = new Map(ids.map((i) => [i.did, i.kel]));
  const source: KelSource = async (did) => logs.get(did) ?? null;
  return { source, set: (did: string, kel: KelEvent[]) => logs.set(did, kel) };
}

/** Alice (person) → her shopping agent → a provider agent (controlled by Bob) → payment to a processor agent. */
async function personRootedChain() {
  const alice = await incept({ kind: "person" });
  const bob = await incept({ kind: "person" });
  const shopper = await incept({ kind: "agent", controller: alice.did });
  const provider = await incept({ kind: "agent", controller: bob.did });
  const processor = await incept({ kind: "agent" }); // self-sovereign agent, no controller

  const intent = await issueIntentMandate(alice.did, shopper.did, ROOT, alice.privateKey);
  const cart = await attenuateToCart(intent, provider.did, CART, shopper.privateKey);
  const payment = await attenuateToPayment(cart, processor.did, PAY, provider.privateKey);
  const dir = directory(alice, bob, shopper, provider, processor);
  return { alice, bob, shopper, provider, processor, intent, cart, payment, dir };
}

describe("person-rooted mandate chains", () => {
  it("verifies a chain rooted in a person, with every agent's KEL checked", async () => {
    const c = await personRootedChain();
    const result = await verifyMandateChain(c.payment.token, resolveContentAddressedKey, {
      kelSource: c.dir.source,
      requirePersonRoot: true,
      expectedGrantee: c.processor.did,
    });
    expect(result).toMatchObject({ valid: true, chainVerified: true, rootGrantor: c.alice.did });

    const pinned = await verifyMandateChain(c.payment.token, resolveContentAddressedKey, {
      kelSource: c.dir.source,
      expectedRootPerson: c.alice.did,
    });
    expect(pinned.valid).toBe(true);
  });

  it("issueIntentMandate needs no special casing for a person grantor", async () => {
    const alice = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: alice.did });
    const intent = await issueIntentMandate(alice.did, agent.did, ROOT, alice.privateKey);
    expect(intent.mandate.grantor).toBe(alice.did);
    const result = await verifyMandateChain(intent.token, undefined, {
      kelSource: kelSourceFromLogs(alice.kel, agent.kel),
      requirePersonRoot: true,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a root that is an agent, a legacy z-DID, or the wrong person", async () => {
    const c = await personRootedChain();
    // Agent self-issues its own "intent".
    const selfIssued = await issueIntentMandate(c.shopper.did, c.provider.did, ROOT, c.shopper.privateKey);
    const r1 = await verifyMandateChain(selfIssued.token, undefined, { kelSource: c.dir.source, requirePersonRoot: true });
    expect(r1.valid).toBe(false);
    expect(r1.reason).toMatch(/not a person/);

    // A legacy content-addressed root verifies normally but is not a person.
    const priv = ed.utils.randomPrivateKey();
    const zDid = generateDid(await ed.getPublicKeyAsync(priv));
    const legacy = await issueIntentMandate(zDid, c.shopper.did, ROOT, priv);
    expect((await verifyMandateChain(legacy.token, resolveContentAddressedKey, { kelSource: c.dir.source })).valid).toBe(true);
    const r2 = await verifyMandateChain(legacy.token, resolveContentAddressedKey, { kelSource: c.dir.source, requirePersonRoot: true });
    expect(r2.valid).toBe(false);
    expect(r2.reason).toMatch(/not a person identity/);

    const r3 = await verifyMandateChain(c.payment.token, undefined, { kelSource: c.dir.source, expectedRootPerson: c.bob.did });
    expect(r3.valid).toBe(false);
    expect(r3.reason).toMatch(/expected person/);
  });

  it("requirePersonRoot without a kelSource fails closed", async () => {
    const c = await personRootedChain();
    const r = await verifyMandateChain(c.payment.token, undefined, { requirePersonRoot: true });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/kelSource/);
  });

  it("without a kelSource, E-DIDs are unresolvable by the default resolver (fail closed)", async () => {
    const c = await personRootedChain();
    const r = await verifyMandateChain(c.payment.token);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Cannot resolve public key/);
  });

  it("a revoked root person kills the chain", async () => {
    const c = await personRootedChain();
    c.dir.set(c.alice.did, await revokeKelSelf(c.alice));
    const r = await verifyMandateChain(c.payment.token, undefined, { kelSource: c.dir.source, requirePersonRoot: true });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/revoked/);
  });
});

describe("revoked agents", () => {
  it("a mandate signed by an agent its controller later revoked fails", async () => {
    const c = await personRootedChain();
    // Before: fine.
    expect((await verifyMandateChain(c.cart.token, undefined, { kelSource: c.dir.source })).valid).toBe(true);
    // Alice revokes her shopping agent (device stolen).
    const r = await revokeAgent(c.alice, c.shopper.kel, { reason: "device stolen" });
    c.dir.set(c.alice.did, r.person.kel);
    c.dir.set(c.shopper.did, r.agentKel);

    const after = await verifyMandateChain(c.cart.token, undefined, { kelSource: c.dir.source });
    expect(after.valid).toBe(false);
    expect(after.reason).toMatch(/revoked/);
    // And the payment below it.
    expect((await verifyMandateChain(c.payment.token, undefined, { kelSource: c.dir.source })).valid).toBe(false);
  });

  it("a mandate GRANTED to a revoked agent fails too", async () => {
    const c = await personRootedChain();
    const r = await revokeAgent(c.alice, c.shopper.kel);
    c.dir.set(c.alice.did, r.person.kel);
    c.dir.set(c.shopper.did, r.agentKel);
    const result = await verifyMandateChain(c.intent.token, undefined, { kelSource: c.dir.source });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/grantee .* revoked/);
  });

  it("a registry that withholds the revocation is caught by the controller's seals", async () => {
    const c = await personRootedChain();
    const r = await revokeAgent(c.alice, c.shopper.kel);
    c.dir.set(c.alice.did, r.person.kel); // person's log is current…
    // …but the agent's log is served stale (inception only).
    const result = await verifyMandateChain(c.cart.token, undefined, { kelSource: c.dir.source });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Key Event Log rejected: controller anchored .* ends at 0/);
  });

  it("an agent whose controller's KEL is unavailable fails closed", async () => {
    const c = await personRootedChain();
    const withoutBob: KelSource = async (did) => (did === c.bob.did ? null : c.dir.source(did));
    const r = await verifyMandateChain(c.payment.token, undefined, { kelSource: withoutBob });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/controller .* unavailable/);
  });
});

describe("rotation and recovery", () => {
  it("checks signatures against the key current at verification time", async () => {
    const c = await personRootedChain();
    const rotated = await rotateKel(c.shopper);
    c.dir.set(c.shopper.did, rotated.kel);
    // The cart was signed by the shopper's pre-rotation key: re-issue required.
    expect((await verifyMandateChain(c.cart.token, undefined, { kelSource: c.dir.source })).valid).toBe(false);
    const reissued = await attenuateToCart(c.intent, c.provider.did, CART, rotated.privateKey);
    expect((await verifyMandateChain(reissued.token, undefined, { kelSource: c.dir.source })).valid).toBe(true);
  });

  it("after controller recovery the thief's key can no longer mint mandates", async () => {
    const c = await personRootedChain();
    const thiefKey = c.shopper.privateKey; // stolen with the device
    const newDevice = await generateKelKeyMaterial();
    const r = await recoverAgent(c.alice, c.shopper.kel, newDevice);
    c.dir.set(c.alice.did, r.person.kel);
    c.dir.set(c.shopper.did, r.agentKel);

    const thiefCart = await attenuateToCart(c.intent, c.provider.did, CART, thiefKey);
    expect((await verifyMandateChain(thiefCart.token, undefined, { kelSource: c.dir.source })).valid).toBe(false);

    const ownerCart = await attenuateToCart(c.intent, c.provider.did, CART, newDevice.privateKey);
    const ok = await verifyMandateChain(ownerCart.token, undefined, { kelSource: c.dir.source, requirePersonRoot: true });
    expect(ok.valid).toBe(true);
  });

  it("a KelStore keeps a lagging registry from rolling a rotation back", async () => {
    const c = await personRootedChain();
    const store = new InMemoryKelStore();
    const rotated = await rotateKel(c.shopper);
    c.dir.set(c.shopper.did, rotated.kel);
    const reissued = await attenuateToCart(c.intent, c.provider.did, CART, rotated.privateKey);
    expect((await verifyMandateChain(reissued.token, undefined, { kelSource: c.dir.source, kelStore: store })).valid).toBe(true);
    // Registry rolls back to the pre-rotation log: the stale cart must still fail.
    c.dir.set(c.shopper.did, c.shopper.kel);
    expect((await verifyMandateChain(c.cart.token, undefined, { kelSource: c.dir.source, kelStore: store })).valid).toBe(false);
    expect((await verifyMandateChain(reissued.token, undefined, { kelSource: c.dir.source, kelStore: store })).valid).toBe(true);
  });
});

describe("createMandateKeyResolver", () => {
  it("resolves E via KEL, z from the DID, named via fallback — and never lets the fallback answer for E or z", async () => {
    const person: KelIdentity = await incept({ kind: "person" });
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const zDid = generateDid(pub);
    const bogus = new Uint8Array(32).fill(7);
    const fallbackAsked: string[] = [];
    const resolve = createMandateKeyResolver({
      kelSource: kelSourceFromLogs(person.kel),
      fallback: async (did) => {
        fallbackAsked.push(did);
        return bogus;
      },
    });
    expect(await resolve(person.did)).toEqual(person.publicKey);
    expect(await resolve(zDid)).toEqual(pub);
    expect(await resolve("did:aroha:named-agent")).toEqual(bogus);
    const unknownE = (await incept({ kind: "agent" })).did;
    expect(await resolve(unknownE)).toBeNull();
    expect(fallbackAsked).toEqual(["did:aroha:named-agent"]);
  });

  it("returns null for E-DIDs without a kelSource", async () => {
    const person = await incept({ kind: "person" });
    expect(await createMandateKeyResolver()(person.did)).toBeNull();
  });
});
