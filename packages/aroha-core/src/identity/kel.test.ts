// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import {
  incept,
  rotateKel,
  revokeKelSelf,
  recoverAgent,
  revokeAgent,
  anchorInKel,
  generateKelKeyMaterial,
  verifyKel,
  verifyAgentControlledBy,
  acceptKel,
  InMemoryKelStore,
  KelError,
  kelSourceFromLogs,
  kelKeyResolver,
  resolveKelState,
  isInceptionDid,
  inceptionDigestFromDid,
  didFromInception,
  eventDigest,
  keyDigest,
  keysAtSequence,
  type KelEvent,
  type RotateEvent,
  type RecoverEvent,
  type KelIdentity,
  type InceptionEvent,
} from "./kel.js";
import { migrateLegacyIdentity, verifyLinkage, signIdentityLinkage, type IdentityLinkage } from "./migration.js";
import { generateDID, generateDid, generateContentAddressedDID, isContentAddressedDid, toMultibase } from "./did.js";
import { canonicalizeJcs } from "../crypto/jcs.js";
import { buildEnvelope, validateEnvelope, newCorrelationId } from "../messages/envelope.js";
import { NonceRegistry } from "../messages/nonce.js";

async function expectKelError(p: Promise<unknown>, code: KelError["code"], msg?: RegExp): Promise<void> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(KelError);
    expect((e as KelError).code).toBe(code);
    if (msg) expect((e as KelError).message).toMatch(msg);
    return;
  }
  throw new Error(`expected KelError(${code})`);
}

/** Re-sign a hand-edited event with `priv` (to build forgeries that are validly signed by the WRONG key). */
async function resign<T extends KelEvent>(event: T, priv: Uint8Array): Promise<T> {
  const { sig: _s, ...body } = event as T & { sig?: string };
  const sig = await ed.signAsync(new TextEncoder().encode(canonicalizeJcs(body)), priv);
  return { ...body, sig: Buffer.from(sig).toString("base64url") } as T;
}

async function personAndAgent(): Promise<{ person: KelIdentity; agent: KelIdentity }> {
  const person = await incept({ kind: "person" });
  const agent = await incept({ kind: "agent", controller: person.did });
  return { person, agent };
}

describe("E-form identifiers", () => {
  it("derives the DID from the inception digest and parses it strictly", async () => {
    const id = await incept({ kind: "person" });
    expect(id.did).toMatch(/^did:aroha:E[1-9A-HJ-NP-Za-km-z]{40,44}$/);
    expect(id.did).toBe(didFromInception(id.kel[0] as InceptionEvent));
    expect(isInceptionDid(id.did)).toBe(true);
    expect(inceptionDigestFromDid(id.did)).toHaveLength(32);
  });

  it("keeps the three did:aroha forms mutually exclusive", async () => {
    const e = await incept({ kind: "agent" });
    const z = await generateContentAddressedDID("https://x.example/aroha/v1");
    expect(isContentAddressedDid(e.did)).toBe(false);
    expect(isInceptionDid(z.did)).toBe(false);
    // Named DIDs that merely start with E / z are not self-certifying.
    expect(isInceptionDid("did:aroha:Echo")).toBe(false);
    expect(isInceptionDid("did:aroha:acme.E" + e.did.slice(11))).toBe(false);
    // And a name with the exact shape of either form cannot be minted.
    await expect(generateDID(e.did.slice("did:aroha:".length), "https://x")).rejects.toThrow(/self-certifying/);
    await expect(generateDID(z.did.slice("did:aroha:".length), "https://x")).rejects.toThrow(/self-certifying/);
    await expect(generateDID("Echo", "https://x")).resolves.toBeTruthy();
  });

  it("rejects suffixes that do not decode to exactly 32 bytes", () => {
    expect(isInceptionDid("did:aroha:E" + "2".repeat(43))).toBe(false); // 31 bytes
    expect(isInceptionDid("did:aroha:E" + "z".repeat(50))).toBe(false); // > 32 bytes
    expect(isInceptionDid("did:aroha:E0OIl")).toBe(false); // not base58
  });
});

describe("verifyKel — inception", () => {
  it("verifies an inception-only log with nothing but the inception (zero network)", async () => {
    const id = await incept({ kind: "agent" });
    const state = await verifyKel(id.did, id.kel);
    expect(state.kind).toBe("agent");
    expect(state.sequence).toBe(0);
    expect(state.revoked).toBe(false);
    expect(state.currentKey).toEqual(id.publicKey);
    expect(state.currentKeys).toEqual([toMultibase(id.publicKey)]);
    expect(state.nextKeyDigest).toBe(keyDigest(id.nextPublicKey));
  });

  it("verifies an inception-only agent with a controller without fetching the controller", async () => {
    const { agent } = await personAndAgent();
    const state = await verifyKel(agent.did, agent.kel);
    expect(state.controller).toBeDefined();
    expect(state.controllerState).toBeUndefined();
  });

  it("detects tampering with any inception field (the DID no longer matches)", async () => {
    const id = await incept({ kind: "agent" });
    const other = await generateKelKeyMaterial();
    const tampered = await resign<InceptionEvent>({ ...(id.kel[0] as InceptionEvent), keys: [toMultibase(other.publicKey)] }, other.privateKey);
    await expectKelError(verifyKel(id.did, [tampered]), "invalid", /does not match/);
    const kindSwap: InceptionEvent = { ...(id.kel[0] as InceptionEvent), kind: "person" };
    await expectKelError(verifyKel(id.did, [kindSwap]), "invalid", /does not match/);
  });

  it("detects a DID that names a different inception", async () => {
    const a = await incept({ kind: "agent" });
    const b = await incept({ kind: "agent" });
    await expectKelError(verifyKel(a.did, b.kel), "invalid", /does not match/);
  });

  it("rejects an inception not signed by its own key", async () => {
    const id = await incept({ kind: "agent" });
    const stranger = await generateKelKeyMaterial();
    const badSig = await resign(id.kel[0], stranger.privateKey);
    // Same digest (sig is outside it) but the signature is wrong.
    await expectKelError(verifyKel(id.did, [badSig]), "invalid", /signature/);
  });

  it("rejects a person with a controller and an agent whose controller is not an E-DID", async () => {
    const p = await incept({ kind: "person" });
    await expect(incept({ kind: "person", controller: p.did })).rejects.toThrow();
    await expect(incept({ kind: "agent", controller: "did:aroha:my-boss" })).rejects.toThrow();
  });
});

describe("verifyKel — pre-rotation", () => {
  it("accepts a rotation signed by the pre-committed next key", async () => {
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const state = await verifyKel(id.did, rotated.kel);
    expect(state.sequence).toBe(1);
    expect(state.currentKey).toEqual(id.nextPublicKey);
    expect(state.nextKeyDigest).toBe(keyDigest(rotated.nextPublicKey));
    // Twice.
    const again = await rotateKel(rotated);
    expect((await verifyKel(id.did, again.kel)).currentKey).toEqual(rotated.nextPublicKey);
    expect(keysAtSequence(await verifyKel(id.did, again.kel), 0)).toEqual([toMultibase(id.publicKey)]);
  });

  it("rejects a rotation forged with the stolen CURRENT key", async () => {
    const id = await incept({ kind: "agent" });
    // The thief has id.privateKey only. They mint their own key and try to
    // rotate to it, signing with the key they stole.
    const thief = await generateKelKeyMaterial();
    const forged = await resign<RotateEvent>(
      {
        v: 1, type: "rotate", did: id.did, seq: 1, prior: eventDigest(id.kel[0]),
        at: new Date().toISOString(), keys: [toMultibase(thief.publicKey)], nextKeyDigest: thief.nextKeyDigest, sig: "",
      },
      id.privateKey
    );
    await expectKelError(verifyKel(id.did, [...id.kel, forged]), "invalid", /pre-rotation commitment/);

    // Even naming the committed key, they cannot sign for it.
    const forged2 = await resign<RotateEvent>(
      { ...forged, keys: [toMultibase(id.nextPublicKey)] },
      id.privateKey
    );
    await expectKelError(verifyKel(id.did, [...id.kel, forged2]), "invalid", /not signed by the pre-committed next key/);
  });

  it("rejects broken chaining: wrong seq, wrong prior, wrong did", async () => {
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const ev = rotated.kel[1] as RotateEvent;
    await expectKelError(verifyKel(id.did, [id.kel[0], await resign({ ...ev, seq: 2 }, id.nextPrivateKey)]), "invalid", /seq/);
    await expectKelError(verifyKel(id.did, [id.kel[0], await resign({ ...ev, prior: ev.nextKeyDigest }, id.nextPrivateKey)]), "invalid", /prior/);
    const other = await incept({ kind: "agent" });
    await expectKelError(verifyKel(id.did, [id.kel[0], await resign({ ...ev, did: other.did }, id.nextPrivateKey)]), "invalid", /names DID/);
  });

  it("self-revocation by the next key closes the log", async () => {
    const id = await incept({ kind: "person" });
    const kel = await revokeKelSelf(id, { reason: "retired" });
    const state = await verifyKel(id.did, kel);
    expect(state.revoked).toBe(true);
    expect(state.currentKey).toBeNull();
    expect(state.currentKeys).toEqual([]);
    // Nothing may follow.
    const after = await anchorInKel({ ...id, kel: id.kel }, []);
    const appended = [...kel, { ...(after.kel[1] as object), seq: 2, prior: eventDigest(kel[1]) } as KelEvent];
    await expectKelError(verifyKel(id.did, appended), "invalid", /after revocation/);
  });

  it("a stolen current key cannot self-revoke either", async () => {
    const id = await incept({ kind: "agent" });
    const kel = await revokeKelSelf(id);
    const forged = await resign(kel[1], id.privateKey);
    await expectKelError(verifyKel(id.did, [id.kel[0], forged]), "invalid", /pre-committed next key/);
  });
});

describe("person controller: recover / revoke", () => {
  it("controller recovery installs a new key, verified against the person's anchors", async () => {
    const { person, agent } = await personAndAgent();
    const newDevice = await generateKelKeyMaterial();
    const r = await recoverAgent(person, agent.kel, newDevice);

    const state = await verifyKel(agent.did, r.agentKel, { resolveControllerKel: kelSourceFromLogs(r.person.kel) });
    expect(state.currentKey).toEqual(newDevice.publicKey);
    expect(state.nextKeyDigest).toBe(newDevice.nextKeyDigest);
    expect(state.controllerState?.did).toBe(person.did);

    // The new device can then rotate normally with its own next key.
    const onNewDevice: KelIdentity = { ...agent, ...newDevice, kel: r.agentKel };
    const rotated = await rotateKel(onNewDevice);
    const s2 = await verifyKel(agent.did, rotated.kel, { resolveControllerKel: kelSourceFromLogs(r.person.kel) });
    expect(s2.currentKey).toEqual(newDevice.nextPublicKey);

    const controlled = await verifyAgentControlledBy(agent.did, r.agentKel, person.did, r.person.kel);
    expect(controlled.controlled).toBe(true);
  });

  it("recovery needs the controller's KEL", async () => {
    const { person, agent } = await personAndAgent();
    const r = await recoverAgent(person, agent.kel, await generateKelKeyMaterial());
    await expectKelError(verifyKel(agent.did, r.agentKel), "controller-unavailable");
  });

  it("rejects a recovery anchored by a person who is not the controller", async () => {
    const { person, agent } = await personAndAgent();
    const impostor = await incept({ kind: "person" });
    const newDevice = await generateKelKeyMaterial();
    // Build the recover event as the real controller would, but have the
    // impostor anchor it.
    const genuine = await recoverAgent(person, agent.kel, newDevice);
    const recoverEv = genuine.agentKel[1];
    const impostorAnchored = await anchorInKel(impostor, [{ did: agent.did, seq: 1, digest: eventDigest(recoverEv) }]);
    // The verifier fetches the CONTROLLER named in the inception — the real
    // person, whose log has no such anchor.
    await expectKelError(
      verifyKel(agent.did, genuine.agentKel, { resolveControllerKel: kelSourceFromLogs(person.kel, impostorAnchored.kel) }),
      "invalid",
      /not anchored/
    );
    // recoverAgent itself refuses a non-controller.
    await expect(recoverAgent(impostor, agent.kel, newDevice)).rejects.toThrow(/controller/);
    // And an agent with no controller cannot be recovered at all.
    const lone = await incept({ kind: "agent" });
    const loneRecover: RecoverEvent = {
      v: 1, type: "recover", did: lone.did, seq: 1, prior: eventDigest(lone.kel[0]), at: new Date().toISOString(),
      auth: "controller", keys: [toMultibase(newDevice.publicKey)], nextKeyDigest: newDevice.nextKeyDigest,
    };
    await expectKelError(verifyKel(lone.did, [...lone.kel, loneRecover]), "invalid", /controller/);
  });

  it("rejects a recover event that does not match the anchored digest as INVALID, not duplicity", async () => {
    // A swapped recover is unsigned junk: nothing authorised it. Reporting it
    // as "duplicity" let anyone raise a fork alarm against an agent — and get
    // it refused — by submitting such an event at a sealed position.
    const { person, agent } = await personAndAgent();
    const r = await recoverAgent(person, agent.kel, await generateKelKeyMaterial());
    const thief = await generateKelKeyMaterial();
    const swapped = { ...(r.agentKel[1] as RecoverEvent), keys: [toMultibase(thief.publicKey)] };
    await expectKelError(
      verifyKel(agent.did, [agent.kel[0], swapped], { resolveControllerKel: kelSourceFromLogs(r.person.kel) }),
      "invalid",
      /not anchored/
    );
  });

  it("still reports a genuine fork of SELF-SIGNED events against a controller seal as duplicity", async () => {
    // The controller sealed one rotation; a second, validly self-signed
    // rotation at the same position is a real fork, and stays "duplicity".
    const { person, agent } = await personAndAgent();
    const rotatedA = await rotateKel(agent);
    const rotatedB = await rotateKel(agent);
    const sealedA = await anchorInKel(person, [{ did: agent.did, seq: 1, digest: eventDigest(rotatedA.kel[1]) }]);
    await expectKelError(
      verifyKel(agent.did, rotatedB.kel, { resolveControllerKel: kelSourceFromLogs(sealedA.kel) }),
      "duplicity"
    );
  });

  it("controller revocation makes verifyKel report revoked", async () => {
    const { person, agent } = await personAndAgent();
    const r = await revokeAgent(person, agent.kel, { reason: "device lost" });
    const state = await verifyKel(agent.did, r.agentKel, { resolveControllerKel: kelSourceFromLogs(r.person.kel) });
    expect(state.revoked).toBe(true);
    expect(state.currentKey).toBeNull();
    const controlled = await verifyAgentControlledBy(agent.did, r.agentKel, person.did, r.person.kel);
    expect(controlled.controlled).toBe(false);
  });

  it("a person's seals expose an agent log that withholds the revocation (stale)", async () => {
    const { person, agent } = await personAndAgent();
    const r = await revokeAgent(person, agent.kel);
    // Registry serves the agent's inception only, but the person's log.
    await expectKelError(
      verifyKel(agent.did, agent.kel, { resolveControllerKel: kelSourceFromLogs(r.person.kel) }),
      "stale"
    );
  });

  it("an agent whose controller revoked itself reports controllerRevoked", async () => {
    const { person, agent } = await personAndAgent();
    const personKel = await revokeKelSelf(person);
    const state = await verifyKel(agent.did, agent.kel, { resolveControllerKel: kelSourceFromLogs(personKel) });
    expect(state.revoked).toBe(false);
    expect(state.controllerRevoked).toBe(true);
    expect(await kelKeyResolver(kelSourceFromLogs(agent.kel, personKel), { requireController: true })(agent.did)).toBeNull();
  });

  it("after the person rotates, their superseded key cannot authorise anything in the honest log", async () => {
    const { person, agent } = await personAndAgent();
    const rotatedPerson = await rotateKel(person);
    // Thief holds the person's OLD key and forges an anchor at the next seq.
    const thiefDevice = await generateKelKeyMaterial();
    const recoverEv: RecoverEvent = {
      v: 1, type: "recover", did: agent.did, seq: 1, prior: eventDigest(agent.kel[0]), at: new Date().toISOString(),
      auth: "controller", keys: [toMultibase(thiefDevice.publicKey)], nextKeyDigest: thiefDevice.nextKeyDigest,
    };
    const forgedAnchor = await anchorInKel(
      { ...rotatedPerson, privateKey: person.privateKey },
      [{ did: agent.did, seq: 1, digest: eventDigest(recoverEv) }]
    );
    await expectKelError(verifyKel(person.did, forgedAnchor.kel), "invalid", /current key/);
  });
});

describe("KelStore: duplicity and stale logs", () => {
  it("detects two different events at the same sequence", async () => {
    const id = await incept({ kind: "person" });
    const store = new InMemoryKelStore();
    const a = await rotateKel(id);
    // A fork: same position, different event (both validly signed by the next key).
    const b = await rotateKel(id);
    await acceptKel(id.did, a.kel, store);
    await expectKelError(acceptKel(id.did, b.kel, store), "duplicity");
    expect(await store.getDuplicity(id.did)).toMatchObject({ did: id.did, seq: 1 });
    // From then on the DID is refused, even the log first seen.
    await expectKelError(acceptKel(id.did, a.kel, store), "duplicity");
  });

  it("rejects a shorter log after a longer one was seen, or answers from the stored one", async () => {
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const store = new InMemoryKelStore();
    await acceptKel(id.did, rotated.kel, store);
    await expectKelError(acceptKel(id.did, id.kel, store), "stale");
    const state = await acceptKel(id.did, id.kel, store, { onStale: "use-stored" });
    expect(state.sequence).toBe(1);
    expect(state.currentKey).toEqual(id.nextPublicKey);
  });

  it("does not let an unverifiable log raise a duplicity alarm", async () => {
    const id = await incept({ kind: "agent" });
    const store = new InMemoryKelStore();
    await acceptKel(id.did, (await rotateKel(id)).kel, store);
    const junk = await resign({ ...((await rotateKel(id)).kel[1] as RotateEvent) }, id.privateKey);
    await expectKelError(acceptKel(id.did, [id.kel[0], junk], store), "invalid");
    expect(await store.getDuplicity(id.did)).toBeNull();
  });

  it("stores only the longest verified log", async () => {
    const id = await incept({ kind: "agent" });
    const store = new InMemoryKelStore();
    await acceptKel(id.did, id.kel, store);
    const r = await rotateKel(id);
    await acceptKel(id.did, r.kel, store);
    expect(await store.get(id.did)).toHaveLength(2);
  });

  it("kelKeyResolver keeps answering with the newest key when a source lags", async () => {
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const store = new InMemoryKelStore();
    let served: KelEvent[] = rotated.kel;
    const resolve = kelKeyResolver(async () => served, { store });
    expect(await resolve(id.did)).toEqual(id.nextPublicKey);
    served = id.kel; // source rolls back to the inception
    expect(await resolve(id.did)).toEqual(id.nextPublicKey);
  });

  it("resolveKelState returns null for non-E DIDs and unknown DIDs", async () => {
    const src = kelSourceFromLogs();
    expect(await resolveKelState("did:aroha:named", src)).toBeNull();
    const id = await incept({ kind: "agent" });
    expect(await resolveKelState(id.did, src)).toBeNull();
  });
});

describe("envelope validation with E-DIDs", () => {
  it("resolves the sender key through kelKeyResolver, following rotation", async () => {
    const sender = await incept({ kind: "agent" });
    const myDID = "did:aroha:receiver";
    const reg = new NonceRegistry();
    try {
      let log = sender.kel;
      const resolve = kelKeyResolver(async () => log);

      const env = await buildEnvelope("ArohaRequest", sender.did, myDID, { capability: "x", params: {} }, newCorrelationId(), sender.privateKey);
      const key = await resolve(sender.did, env.proof?.verificationMethod);
      expect(key).not.toBeNull();
      expect((await validateEnvelope(env, key!, myDID, reg)).valid).toBe(true);

      // After rotation the old key no longer verifies new messages; the new one does.
      const rotated = await rotateKel(sender);
      log = rotated.kel;
      const env2 = await buildEnvelope("ArohaRequest", sender.did, myDID, { capability: "x", params: {} }, newCorrelationId(), sender.privateKey);
      const key2 = await resolve(sender.did);
      expect((await validateEnvelope(env2, key2!, myDID, reg)).valid).toBe(false);
      const env3 = await buildEnvelope("ArohaRequest", sender.did, myDID, { capability: "x", params: {} }, newCorrelationId(), rotated.privateKey);
      expect((await validateEnvelope(env3, key2!, myDID, reg)).valid).toBe(true);
    } finally {
      reg.destroy();
    }
  });

  it("returns null for a revoked agent and for non-E DIDs", async () => {
    const { person, agent } = await personAndAgent();
    const r = await revokeAgent(person, agent.kel);
    const resolve = kelKeyResolver(kelSourceFromLogs(r.agentKel, r.person.kel));
    expect(await resolve(agent.did)).toBeNull();
    expect(await resolve(generateDid(agent.publicKey))).toBeNull();
  });
});

describe("migration from a legacy z-DID", () => {
  it("links old and new identities with a two-sided signature", async () => {
    const old = await generateContentAddressedDID("https://x.example/aroha/v1");
    const { identity, linkage } = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent", privateKey: old.privateKey });
    expect(isInceptionDid(identity.did)).toBe(true);
    // Keeping the device key: the new identity's current key is the old one.
    expect(identity.publicKey).toEqual(old.publicKey);

    const result = await verifyLinkage(linkage, identity.kel);
    expect(result).toMatchObject({ valid: true, from: old.did, to: identity.did });

    // Still verifies after the new identity rotates (toSeq pins the signing key).
    const rotated = await rotateKel(identity);
    expect((await verifyLinkage(linkage, rotated.kel)).valid).toBe(true);
  });

  it("rejects one-sided linkages", async () => {
    const old = await generateContentAddressedDID("https://x.example/aroha/v1");
    const { identity, linkage } = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent" });

    // Only the new key signed (claims someone else's history).
    const stranger = await generateContentAddressedDID("https://y.example/aroha/v1");
    const hijack = await signIdentityLinkage(stranger.did, identity.privateKey, identity);
    expect(await verifyLinkage(hijack, identity.kel)).toMatchObject({ valid: false, reason: expect.stringMatching(/old DID/) });

    // Only the old key signed (points anywhere).
    const elsewhere = await incept({ kind: "agent" });
    const pointed: IdentityLinkage = { ...linkage, to: elsewhere.did };
    const repaired = await signIdentityLinkage(old.did, old.privateKey, elsewhere);
    const oneSided: IdentityLinkage = { ...repaired, sigs: { from: repaired.sigs.from, to: linkage.sigs.to } };
    expect((await verifyLinkage(oneSided, elsewhere.kel)).valid).toBe(false);
    expect((await verifyLinkage(pointed, elsewhere.kel)).valid).toBe(false);

    // Missing signature entirely.
    expect((await verifyLinkage({ ...linkage, sigs: { from: linkage.sigs.from, to: "" } }, identity.kel)).valid).toBe(false);
  });

  it("refuses a private key that does not belong to the old DID, and a revoked successor", async () => {
    const old = await generateContentAddressedDID("https://x.example/aroha/v1");
    const other = await generateContentAddressedDID("https://x.example/aroha/v1");
    await expect(migrateLegacyIdentity(old.did, other.privateKey, { kind: "agent" })).rejects.toThrow();
    const { identity, linkage } = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "person" });
    const revoked = await revokeKelSelf(identity);
    expect(await verifyLinkage(linkage, revoked)).toMatchObject({ valid: false, reason: expect.stringMatching(/revoked/) });
  });
});
