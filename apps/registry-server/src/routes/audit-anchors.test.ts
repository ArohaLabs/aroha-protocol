// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// /v1/audit-anchors and /.well-known/aroha-registry-keys.json — the witness
// contract a runtime anchors its signed audit heads against.

import { describe, it, expect, beforeEach } from "vitest";
import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import { canonicalizeJcs } from "@aroha-sdk/credentials/mandates";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { headPayload } from "./audit-anchors.js";
import { parseSigningSeed, registryKeyId, bytesToB64url } from "../registry-signing.js";

let t: TestApp;
let ipN = 0;
beforeEach(async () => { t = await makeApp(); });

async function install() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

const hashOf = (s: string) => createHash("sha256").update(s).digest("hex");

/** Exactly what the runtime's writeHeadCheckpoint produces: hex signature over headPayload. */
async function checkpoint(inst: { priv: Uint8Array; did: string }, seq: number, signedAt = new Date().toISOString()) {
  const hash = hashOf(`entry-${seq}`);
  const sig = await ed.signAsync(headPayload({ seq, hash, signedAt }), inst.priv);
  return { installDid: inst.did, seq, hash, signedAt, signature: Buffer.from(sig).toString("hex") };
}

function post(body: unknown, ip = `10.1.${(ipN >> 8) & 255}.${ipN++ & 255}`) {
  return t.app.request("/v1/audit-anchors", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify(body),
  }, t.env);
}

type AnchorResponse = {
  anchor: {
    purpose: string; installDid: string; seq: number; hash: string; signedAt: string;
    anchoredAt: string; logIndex: number; prevAnchorHash: string;
  };
  witnessSignature: string;
  witnessKeyId: string;
};

async function publishedKey(): Promise<{ keyId: string; publicKey: Uint8Array }> {
  const res = await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env);
  expect(res.status).toBe(200);
  const doc = await res.json() as { keys: Array<{ keyId: string; publicKeyB64: string; purpose: string[]; retired?: boolean }> };
  const k = doc.keys.find((x) => !x.retired)!;
  return { keyId: k.keyId, publicKey: new Uint8Array(Buffer.from(k.publicKeyB64, "base64url")) };
}

describe("headPayload matches the runtime's live-head checkpoint bytes", () => {
  // The runtime (ArohaLabs/aroha-runtime, src/host/audit-rotate.ts) signs
  // "aroha-audit-head/v1\n" + JSON.stringify([c.seq, c.hash, c.signedAt]).
  // These bytes are the contract between the two; if either side changes,
  // the other must change with it.
  it("is byte-for-byte the runtime's checkpoint expression", () => {
    expect(new TextDecoder().decode(headPayload({ seq: 3, hash: "ab", signedAt: "2026-01-01T00:00:00.000Z" })))
      .toBe(`aroha-audit-head/v1\n[3,"ab","2026-01-01T00:00:00.000Z"]`);
  });
});

describe("GET /.well-known/aroha-registry-keys.json", () => {
  it("publishes the current key with keyId = first 16 hex of sha256(publicKey)", async () => {
    const res = await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env);
    const doc = await res.json() as { keys: Array<Record<string, unknown>> };
    const pub = ed.getPublicKey(parseSigningSeed(t.env.REGISTRY_SIGNING_KEY)!);
    expect(doc.keys).toEqual([
      { keyId: registryKeyId(pub), publicKeyB64: bytesToB64url(pub), purpose: ["audit-anchor", "revocation-status", "ssf-set", "agent-monitoring"] },
    ]);
    expect(registryKeyId(pub)).toBe(createHash("sha256").update(pub).digest("hex").slice(0, 16));
  });

  it("publishes a previous key as retired, and accepts a base64url seed", async () => {
    const prevSeed = new Uint8Array(32).fill(7);
    t.env.REGISTRY_SIGNING_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString("base64url");
    t.env.REGISTRY_SIGNING_KEY_PREVIOUS = Buffer.from(prevSeed).toString("hex");
    const doc = await (await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env)).json() as {
      keys: Array<{ keyId: string; retired?: boolean }>;
    };
    expect(doc.keys).toHaveLength(2);
    expect(doc.keys[0]!.retired).toBeUndefined();
    expect(doc.keys[1]).toMatchObject({ keyId: registryKeyId(ed.getPublicKey(prevSeed)), retired: true });
  });

  it("503 when REGISTRY_SIGNING_KEY is unset or malformed (fail closed)", async () => {
    t.env.REGISTRY_SIGNING_KEY = undefined;
    expect((await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env)).status).toBe(503);
    t.env.REGISTRY_SIGNING_KEY = "not-a-seed";
    expect((await t.app.request("/.well-known/aroha-registry-keys.json", {}, t.env)).status).toBe(503);
    const inst = await install();
    const res = await post(await checkpoint(inst, 1));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "Registry signing is not configured on this deployment" });
  });
});

describe("POST /v1/audit-anchors", () => {
  it("appends, chains, and the witness signature verifies under the published key", async () => {
    const inst = await install();
    const key = await publishedKey();

    const r0 = await post(await checkpoint(inst, 0));
    expect(r0.status).toBe(200);
    const a0 = await r0.json() as AnchorResponse;
    expect(a0.anchor).toMatchObject({
      purpose: "aroha.audit-anchor/v1", installDid: inst.did, seq: 0, logIndex: 0, prevAnchorHash: "",
    });
    expect(a0.witnessKeyId).toBe(key.keyId);
    expect(Number.isNaN(Date.parse(a0.anchor.anchoredAt))).toBe(false);
    expect(await ed.verifyAsync(
      Buffer.from(a0.witnessSignature, "base64url"),
      new TextEncoder().encode(canonicalizeJcs(a0.anchor)),
      key.publicKey,
    )).toBe(true);

    const r1 = await post(await checkpoint(inst, 100));
    expect(r1.status).toBe(200);
    const a1 = await r1.json() as AnchorResponse;
    expect(a1.anchor.logIndex).toBe(1);
    expect(a1.anchor.prevAnchorHash).toBe(createHash("sha256").update(canonicalizeJcs(a0.anchor)).digest("hex"));

    // The listing returns the same signed records, ascending, uncached.
    const list = await t.app.request(`/v1/audit-anchors/${encodeURIComponent(inst.did)}`, {}, t.env);
    expect(list.headers.get("Cache-Control")).toBe("no-store");
    const { anchors } = await list.json() as { anchors: AnchorResponse[] };
    expect(anchors).toEqual([a0, a1]);
    for (const a of anchors) {
      expect(await ed.verifyAsync(
        Buffer.from(a.witnessSignature, "base64url"),
        new TextEncoder().encode(canonicalizeJcs(a.anchor)),
        key.publicKey,
      )).toBe(true);
    }
  });

  it("refuses a seq that does not move forward (409), and keeps the chain intact", async () => {
    const inst = await install();
    expect((await post(await checkpoint(inst, 50))).status).toBe(200);
    const same = await post(await checkpoint(inst, 50));
    expect(same.status).toBe(409);
    expect(await same.json()).toMatchObject({ lastSeq: 50 });
    expect((await post(await checkpoint(inst, 10))).status).toBe(409);
    const { anchors } = await (await t.app.request(`/v1/audit-anchors/${encodeURIComponent(inst.did)}`, {}, t.env))
      .json() as { anchors: AnchorResponse[] };
    expect(anchors.map((a) => a.anchor.seq)).toEqual([50]);
  });

  it("refuses a bad signature (403) and a signature by another install's key", async () => {
    const inst = await install();
    const other = await install();
    const cp = await checkpoint(inst, 1);
    expect((await post({ ...cp, hash: hashOf("tampered") })).status).toBe(403);
    const forged = await checkpoint(other, 1);
    expect((await post({ ...forged, installDid: inst.did })).status).toBe(403);
    expect((await post({ ...cp, signature: "00".repeat(64) })).status).toBe(403);
  });

  it("accepts a base64url signature too", async () => {
    const inst = await install();
    const cp = await checkpoint(inst, 1);
    const res = await post({ ...cp, signature: Buffer.from(cp.signature, "hex").toString("base64url") });
    expect(res.status).toBe(200);
  });

  it("400 for a non-content-addressed DID, malformed fields, or a future signedAt", async () => {
    const inst = await install();
    const cp = await checkpoint(inst, 1);
    expect((await post({ ...cp, installDid: "did:aroha:Eabc" })).status).toBe(400);
    expect((await post({ ...cp, installDid: "did:web:example.com" })).status).toBe(400);
    expect((await post({ ...cp, seq: -1 })).status).toBe(400);
    expect((await post({ ...cp, seq: 1.5 })).status).toBe(400);
    expect((await post({ ...cp, hash: "XYZ" })).status).toBe(400);
    expect((await post({ ...cp, signedAt: "yesterday" })).status).toBe(400);
    const future = await checkpoint(inst, 2, new Date(Date.now() + 3_600_000).toISOString());
    expect((await post(future)).status).toBe(400);
  });

  it("413 for an oversized body", async () => {
    const inst = await install();
    const res = await post({ ...(await checkpoint(inst, 1)), pad: "x".repeat(8 * 1024) });
    expect(res.status).toBe(413);
  });

  it("rate-limits per install DID even across IPs", async () => {
    const inst = await install();
    let limited = false;
    for (let seq = 1; seq <= 25 && !limited; seq++) {
      const res = await post(await checkpoint(inst, seq));
      if (res.status === 429) limited = true;
      else expect(res.status).toBe(200);
    }
    expect(limited).toBe(true);
  });
});

describe("GET /v1/audit-anchors/:installDid", () => {
  it("pages with after= and clamps limit to 1..100", async () => {
    const inst = await install();
    for (const seq of [1, 2, 3, 4]) expect((await post(await checkpoint(inst, seq))).status).toBe(200);
    const did = encodeURIComponent(inst.did);
    const page = async (q: string) =>
      ((await (await t.app.request(`/v1/audit-anchors/${did}${q}`, {}, t.env)).json()) as { anchors: AnchorResponse[] })
        .anchors.map((a) => a.anchor.seq);
    expect(await page("?after=2")).toEqual([3, 4]);
    expect(await page("?limit=2")).toEqual([1, 2]);
    expect(await page("?after=1&limit=0")).toEqual([2]); // clamped up to 1
    expect(await page("?limit=1000")).toEqual([1, 2, 3, 4]);
    expect(await page("")).toEqual([1, 2, 3, 4]);
  });

  it("is empty for an install with no anchors, 400 for a non-z DID", async () => {
    const inst = await install();
    const res = await t.app.request(`/v1/audit-anchors/${encodeURIComponent(inst.did)}`, {}, t.env);
    expect(await res.json()).toEqual({ anchors: [] });
    expect((await t.app.request(`/v1/audit-anchors/did:web:x`, {}, t.env)).status).toBe(400);
  });
});
