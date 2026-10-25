// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { generateKeyPair, generateDid, generateDID } from "@aroha-sdk/core";
import { buildPresence, verifyPresence, resolveCandidates, type TransportCandidate } from "./presence.js";

async function contentAddressed() {
  const kp = await generateKeyPair();
  return { did: generateDid(kp.publicKey), ...kp };
}

async function namespaced(agentId: string) {
  return generateDID(agentId, `http://127.0.0.1/${agentId}`);
}

const CANDIDATES: TransportCandidate[] = [
  { rung: 2, kind: "lan", address: "192.168.1.42:7777" },
  { rung: 1, kind: "https", address: "https://otter-brass.aroha-labs.app" },
];

describe("buildPresence / verifyPresence — offline, self-certifying (spec §6.4)", () => {
  it("verifies a freshly built presence record with no network call", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });

    const result = await verifyPresence(presence);
    expect(result).toEqual({ valid: true, presence });
  });

  it("rejects an expired presence record", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES, ttlMs: 1000 });

    const result = await verifyPresence(presence, Date.now() + 5000);
    expect(result).toEqual({ valid: false, reason: "expired" });
  });

  it("rejects a namespaced (non-content-addressed) DID — nothing to verify against offline", async () => {
    const kp = await namespaced("agent-a");
    const presence = await buildPresence({ did: kp.did, privateKey: kp.privateKey, candidates: CANDIDATES });

    const result = await verifyPresence(presence);
    expect(result).toEqual({ valid: false, reason: "not_self_certifying" });
  });

  it("rejects a presence record signed by a different key than the DID commits to", async () => {
    const a = await contentAddressed();
    const b = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: b.privateKey, candidates: CANDIDATES });

    const result = await verifyPresence(presence);
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects a tampered candidate list — signature covers the exact address, not just presence of a record", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });

    const tampered = { ...presence, candidates: [{ rung: 2 as const, kind: "lan" as const, address: "10.0.0.1:9999" }] };
    const result = await verifyPresence(tampered);
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects malformed shapes (bad rung/kind on a candidate)", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });

    const badRung = { ...presence, candidates: [{ rung: 3, kind: "lan", address: "x" }] };
    expect((await verifyPresence(badRung)).valid).toBe(false);
  });

  it("defaults to a short TTL (§6.4 'volatile facts')", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });
    expect(presence.ttl).toBeLessThanOrEqual(5 * 60_000);
  });
});

describe("resolveCandidates", () => {
  it("merges presence candidates (rung-ordered) ahead of the static DID-document endpoint", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });

    const merged = resolveCandidates("https://static.example.com/aroha", presence);
    expect(merged).toEqual([
      { rung: 1, kind: "https", address: "https://otter-brass.aroha-labs.app" }, // presence, rung 1 first
      { rung: 2, kind: "lan", address: "192.168.1.42:7777" },                    // presence, rung 2
      { rung: 1, kind: "https", address: "https://static.example.com/aroha" },   // static endpoint last
    ]);
  });

  it("works with presence only (no static endpoint declared)", async () => {
    const a = await contentAddressed();
    const presence = await buildPresence({ did: a.did, privateKey: a.privateKey, candidates: CANDIDATES });
    const merged = resolveCandidates(undefined, presence);
    expect(merged).toHaveLength(2);
  });

  it("works with a static endpoint only (agent never published presence)", () => {
    const merged = resolveCandidates("https://static.example.com/aroha", undefined);
    expect(merged).toEqual([{ rung: 1, kind: "https", address: "https://static.example.com/aroha" }]);
  });

  it("returns an empty list when neither is available", () => {
    expect(resolveCandidates(undefined, undefined)).toEqual([]);
  });
});
