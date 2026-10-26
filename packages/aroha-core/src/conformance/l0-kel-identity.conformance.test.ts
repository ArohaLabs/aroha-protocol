// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol Conformance Suite — Layer 0: rotatable identifiers (did:aroha:E…)
 * and Key Event Logs. Normative source: spec did-method.md, "Rotatable
 * identifiers (E-form) and Key Event Logs".
 *
 * Row ids L0-KEL-01..06 are listed in docs/conformance/test-matrix.md.
 *
 * L0-KEL-01 pins exact bytes: Ed25519 signatures are deterministic, so a
 * fixed-seed inception yields a fixed canonical body, signature and DID. Any
 * SDK that reproduces these strings agrees with this one on what a KEL event
 * digest and signature cover.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import {
  incept,
  rotateKel,
  revokeAgent,
  verifyKel,
  acceptKel,
  InMemoryKelStore,
  KelError,
  eventDigest,
  kelSourceFromLogs,
  type RotateEvent,
} from "../identity/kel.js";
import { canonicalizeJcs } from "../crypto/jcs.js";

const NOW = new Date("2026-10-07T00:00:00.000Z");
const seed = (b: number) => new Uint8Array(32).fill(b);

describe("L0-KEL-01 [MUST] E-DID is did:aroha:E + base58btc(sha256(JCS(inception without sig)))", () => {
  it("reproduces the pinned vector", async () => {
    const id = await incept({ kind: "person", privateKey: seed(1), nextPrivateKey: seed(2), now: NOW });
    const { sig, ...body } = id.kel[0];
    expect(canonicalizeJcs(body)).toBe(
      '{"createdAt":"2026-10-07T00:00:00.000Z","keys":["zAKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"],' +
      '"kind":"person","nextKeyDigest":"E89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW","type":"inception","v":1}'
    );
    expect(id.did).toBe("did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ");
    expect(sig).toBe("a-jO6pXYXMBFY3nEhbzzz20MlJ81pxy17L42BgphDMw8ogNyKOeLD_Rg5yMhtv22Rf6kt8d4kpW0VWrdt3TjCw");

    const rotated = await rotateKel(id, { nextPrivateKey: seed(3), now: NOW });
    expect(eventDigest(rotated.kel[1])).toBe("ED3cVEYDPescYcT6jaD4swqCa3PyGvTDUxhhahnYVFTrr");
  });
});

describe("L0-KEL-02 [MUST] an inception-only log verifies with no other input", () => {
  it("verifies", async () => {
    const id = await incept({ kind: "agent" });
    expect((await verifyKel(id.did, id.kel)).currentKey).toEqual(id.publicKey);
  });
});

describe("L0-KEL-03 [MUST] rotation must be signed by the pre-committed next key", () => {
  it("rejects a rotation signed by the current key", async () => {
    const id = await incept({ kind: "agent", privateKey: seed(4), nextPrivateKey: seed(5), now: NOW });
    const honest = (await rotateKel(id, { now: NOW })).kel[1] as RotateEvent;
    // Same event body, signed by the CURRENT key instead of the revealed next key.
    const { sig: _sig, ...body } = honest;
    const thiefSig = await ed.signAsync(new TextEncoder().encode(canonicalizeJcs(body)), id.privateKey);
    const forged: RotateEvent = { ...body, sig: Buffer.from(thiefSig).toString("base64url") };
    await expect(verifyKel(id.did, [id.kel[0], forged])).rejects.toBeInstanceOf(KelError);
    await expect(verifyKel(id.did, [id.kel[0], honest])).resolves.toBeTruthy();
  });
});

describe("L0-KEL-04 [MUST] controller-authorised events are valid only when sealed in the controller's KEL", () => {
  it("accepts with the controller's log and rejects without it", async () => {
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    const r = await revokeAgent(person, agent.kel);
    expect((await verifyKel(agent.did, r.agentKel, { resolveControllerKel: kelSourceFromLogs(r.person.kel) })).revoked).toBe(true);
    await expect(verifyKel(agent.did, r.agentKel)).rejects.toMatchObject({ code: "controller-unavailable" });
  });
});

describe("L0-KEL-05 [MUST] a verifier that has seen a log rejects a fork of it (duplicity)", () => {
  it("raises a duplicity alarm", async () => {
    const id = await incept({ kind: "person" });
    const store = new InMemoryKelStore();
    await acceptKel(id.did, (await rotateKel(id)).kel, store);
    await expect(acceptKel(id.did, (await rotateKel(id)).kel, store)).rejects.toMatchObject({ code: "duplicity" });
  });
});

describe("L0-KEL-06 [SHOULD] a verifier that has seen a log does not accept a shorter one", () => {
  it("rejects as stale", async () => {
    const id = await incept({ kind: "person" });
    const store = new InMemoryKelStore();
    await acceptKel(id.did, (await rotateKel(id)).kel, store);
    await expect(acceptKel(id.did, id.kel, store)).rejects.toMatchObject({ code: "stale" });
  });
});
