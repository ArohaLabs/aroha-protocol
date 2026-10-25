// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consent records are chains of events, each signed by its own actor.
 * These tests pin the properties that design exists for: nobody but the
 * subject can create or alter a "given" event, and only a person who was a
 * room member at the event's epoch can withdraw.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { buildDisclosure } from "../messages/disclosure.js";
import {
  appendConsentEvent, createConsent, effectiveConsent, signRoom, verifyConsent,
  type ConsentRecord, type ConversationKeyResolver, type RoomRecord,
} from "./index.js";

async function person(name: string) {
  const privateKey = ed.utils.randomPrivateKey();
  return { did: `did:aroha:E${name}`, privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
}

async function fixture() {
  const host = await person("host");
  const guest = await person("guest");
  const former = await person("former");
  const keys = new Map([host, guest, former].map((p) => [p.did, p.publicKey]));
  const resolve: ConversationKeyResolver = (did) => (keys.has(did) ? { publicKey: keys.get(did)!, kind: "person" } : null);
  const room: RoomRecord = await signRoom({
    roomId: "r1", threadId: "t1", ownerDid: host.did, epoch: 4,
    members: [
      { did: host.did, kind: "person", displayName: "H", role: "host", joinedEpoch: 0 },
      { did: guest.did, kind: "person", displayName: "G", role: "guest", joinedEpoch: 1, consentRef: "c1" },
      // Joined at 2, left at 3: a member during [2, 3) only.
      { did: former.did, kind: "person", displayName: "F", role: "invited", joinedEpoch: 2, leftEpoch: 3 },
    ],
    historyVisibility: "joined", invocation: "explicit",
    memoryPolicy: { personalRead: false, personalWrite: false, roomMemory: "consented" },
    disclosure: buildDisclosure({ agentDid: "did:aroha:zAgent", principalDid: host.did, principalKind: "person", purpose: "assistant" }),
    updatedAt: "2026-10-15T10:00:00.000Z",
  }, host.privateKey);
  const given = await createConsent({
    recordId: "c1", subjectDid: guest.did, roomId: "r1",
    purposes: ["transcript_retention", "memory_write"], withdrawalRoute: "settings",
    given: { purposes: ["transcript_retention", "memory_write"], at: "2026-10-15T10:00:00.000Z", epoch: 1 },
  }, guest.privateKey);
  return { host, guest, former, resolve, room, given };
}

describe("consent record event chain", () => {
  it("a subject-signed chain with a host withdrawal passes", async () => {
    const { host, resolve, room, given } = await fixture();
    const withdrawn = await appendConsentEvent(given, {
      event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 4, actorDid: host.did,
    }, host.privateKey);
    expect((await verifyConsent(withdrawn, resolve, { room })).ok).toBe(true);
    expect([...effectiveConsent(withdrawn)]).toEqual(["transcript_retention"]);
    // Without the room record a non-subject event cannot be checked: refused.
    expect((await verifyConsent(withdrawn, resolve)).ok).toBe(false);
  });

  it("a forged earlier given event fails, even under a valid later signature", async () => {
    const { host, resolve, room, given } = await fixture();
    const forged: ConsentRecord = JSON.parse(JSON.stringify(given));
    forged.purposes = ["transcript_retention", "memory_write", "provider_processing"];
    forged.events[0].purposes = [...forged.purposes];
    const appended = await appendConsentEvent(forged, {
      event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 4, actorDid: host.did,
    }, host.privateKey);
    const r = await verifyConsent(appended, resolve, { room });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/events\[0\]/);
  });

  it("a given event signed by anyone but the subject fails", async () => {
    const { host, guest, resolve, room } = await fixture();
    await expect(createConsent({
      recordId: "c2", subjectDid: guest.did, roomId: "r1", purposes: ["memory_write"], withdrawalRoute: "x",
      given: { purposes: ["memory_write"], at: "2026-10-15T10:00:00.000Z", epoch: 1 },
    }, host.privateKey).then((c) => verifyConsent(c, resolve, { room }))).resolves.toMatchObject({ ok: false });
  });

  it("a withdrawal by a member who has left fails", async () => {
    const { former, resolve, room, given } = await fixture();
    const late = await appendConsentEvent(given, {
      event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 3, actorDid: former.did,
    }, former.privateKey);
    const r = await verifyConsent(late, resolve, { room });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/not a room member/);
    // While a member (epoch 2) the same person may withdraw.
    const inTime = await appendConsentEvent(given, {
      event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 2, actorDid: former.did,
    }, former.privateKey);
    expect((await verifyConsent(inTime, resolve, { room })).ok).toBe(true);
  });

  it("removing or reordering events breaks the chain", async () => {
    const { host, resolve, room, given } = await fixture();
    const w1 = await appendConsentEvent(given, { event: "withdrawn", purposes: ["memory_write"], at: "2026-10-15T11:00:00.000Z", epoch: 4, actorDid: host.did }, host.privateKey);
    const w2 = await appendConsentEvent(w1, { event: "withdrawn", purposes: ["transcript_retention"], at: "2026-10-15T12:00:00.000Z", epoch: 4, actorDid: host.did }, host.privateKey);
    expect((await verifyConsent(w2, resolve, { room })).ok).toBe(true);
    const dropped = { ...w2, events: [w2.events[0], w2.events[2]] };
    expect((await verifyConsent(dropped, resolve, { room })).ok).toBe(false);
  });
});
