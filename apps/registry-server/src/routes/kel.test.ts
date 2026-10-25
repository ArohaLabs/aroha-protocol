// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Rotatable E-DIDs in the registry: /v1/kel, /v1/linkage, and what the rest
// of the registry (agent rows, rotate-key, SARs, personal names) does with
// them. Every log here is built by @aroha-sdk/core's real incept / rotateKel /
// recoverAgent / revokeAgent — the same code a runtime uses — and every
// verdict comes from a real HTTP round trip against SQLite-backed D1.

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import {
  incept,
  rotateKel,
  revokeKelSelf,
  revokeAgent,
  recoverAgent,
  generateKelKeyMaterial,
  generateKeyPair,
  generateDid,
  generateDID,
  migrateLegacyIdentity,
  signIdentityLinkage,
  canonicalizeJcs,
  toMultibase,
  anchorInKel,
  eventDigest,
  type KelEvent,
  type KelIdentity,
  type RotateEvent,
  type RecoverEvent,
} from "@aroha-sdk/core";
import { buildSar, verifySar, derivePersonalLabelForDid } from "@aroha-sdk/registry";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { hashDID } from "./agents.js";
import { postAgent } from "../test-utils/register.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Registration fetches the manifest from IPFS; nothing here cares what it says. */
function stubFetch() {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ capabilities: [] }), { status: 200 }));
}

const toB64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...Array.from(bytes)));

// The KEL endpoints share one per-IP limiter (module state). A fresh address
// per request keeps unrelated tests from spending each other's budget; the
// rate-limit test pins one address on purpose.
let ipCounter = 0;
const freshIp = () => `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter++ & 255}`;

async function postJson(t: TestApp, path: string, body: unknown, headers: Record<string, string> = {}) {
  return t.app.request(
    path,
    {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...headers },
      body: JSON.stringify(body),
    },
    t.env as never,
  );
}

const enc = encodeURIComponent;
const postKel = (t: TestApp, did: string, events: KelEvent[], controllerKel?: KelEvent[]) =>
  postJson(t, `/v1/kel/${enc(did)}`, controllerKel ? { events, controllerKel } : { events });
const getKel = (t: TestApp, did: string) => t.app.request(`/v1/kel/${enc(did)}`, {}, t.env as never);

async function registerEAgent(t: TestApp, did: string, extra: Record<string, unknown> = {}) {
  return postJson(t, "/v1/agents", { did, manifestCID: "QmAbc", ...extra }, { authorization: `Bearer ${t.apiKey}` });
}

async function getAgent(t: TestApp, did: string) {
  return t.app.request(`/v1/agents/${enc(did)}`, { headers: { authorization: `Bearer ${t.apiKey}` } }, t.env as never);
}

/** A controlled agent whose person's log is already in the registry. */
async function personAndAgent(t: TestApp) {
  const person = await incept({ kind: "person" });
  const agent = await incept({ kind: "agent", controller: person.did });
  expect((await postKel(t, person.did, person.kel)).status).toBe(200);
  return { person, agent };
}

// ─── POST /v1/kel/:did ────────────────────────────────────────────────────────

describe("POST /v1/kel/:did", () => {
  it("accepts a valid log with no API key, and a rotation that extends it", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });

    const first = await postKel(t, id.did, id.kel);
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ did: id.did, sequence: 0, revoked: false });

    const rotated = await rotateKel(id);
    const second = await postKel(t, id.did, rotated.kel);
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ did: id.did, sequence: 1, revoked: false });

    // Re-posting the identical log is a no-op, not an error.
    expect((await postKel(t, id.did, rotated.kel)).status).toBe(200);

    const got = await getKel(t, id.did);
    expect(got.status).toBe(200);
    expect(await got.json()).toEqual({ did: id.did, events: rotated.kel, sequence: 1 });
  });

  it("rejects a rotation forged with the CURRENT key (what a device thief holds)", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const honest = (await rotateKel(id)).kel[1] as RotateEvent;
    const { sig: _sig, ...body } = honest;
    const thiefSig = await ed.signAsync(new TextEncoder().encode(canonicalizeJcs(body)), id.privateKey);
    const forged: RotateEvent = { ...body, sig: Buffer.from(thiefSig).toString("base64url") };

    const res = await postKel(t, id.did, [id.kel[0], forged]);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ code: "invalid" });
    expect((await getKel(t, id.did)).status).toBe(404); // nothing stored
  });

  it("rejects a log whose inception does not hash to the DID", async () => {
    const t = await makeApp();
    const a = await incept({ kind: "agent" });
    const b = await incept({ kind: "agent" });
    const res = await postKel(t, a.did, b.kel);
    expect(res.status).toBe(400);
  });

  it("rejects a non-E DID and malformed bodies before any crypto", async () => {
    const t = await makeApp();
    const kp = await generateKeyPair();
    expect((await postKel(t, generateDid(kp.publicKey), [])).status).toBe(400);
    const id = await incept({ kind: "agent" });
    expect((await postJson(t, `/v1/kel/${enc(id.did)}`, { events: [] })).status).toBe(400);
    expect((await postJson(t, `/v1/kel/${enc(id.did)}`, { events: [1, 2] })).status).toBe(400);
    expect((await postJson(t, `/v1/kel/${enc(id.did)}`, { nope: true })).status).toBe(400);
  });

  it("caps the number of events per submission", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const tooMany = Array.from({ length: 257 }, () => id.kel[0]);
    const res = await postKel(t, id.did, tooMany);
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toMatch(/limit is 256/);
  });

  it("caps the request body size", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const res = await postJson(t, `/v1/kel/${enc(id.did)}`, { events: id.kel, pad: "x".repeat(300 * 1024) });
    expect(res.status).toBe(413);
  });

  it("is rate limited per IP", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const ip = { "x-forwarded-for": "192.0.2.77" };
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      statuses.push((await postJson(t, `/v1/kel/${enc(id.did)}`, { events: id.kel }, ip)).status);
    }
    expect(statuses.slice(0, 30).every((s) => s === 200)).toBe(true);
    expect(statuses[30]).toBe(429);
  });

  it("rejects a log shorter than the stored one as stale", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    expect((await postKel(t, id.did, rotated.kel)).status).toBe(200);

    const res = await postKel(t, id.did, id.kel);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ code: "stale" });
    // The longer log is still what is served.
    expect((await (await getKel(t, id.did)).json() as { sequence: number }).sequence).toBe(1);
  });

  it("records a fork as duplicity and refuses the DID from then on", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    // Two different rotations, both signed by the same pre-committed next key:
    // only the holder of that key can produce either, so seeing both proves
    // the key was used twice — a fork.
    const branchA = await rotateKel(id);
    const branchB = await rotateKel(id);
    expect((await postKel(t, id.did, branchA.kel)).status).toBe(200);

    const fork = await postKel(t, id.did, branchB.kel);
    expect(fork.status).toBe(409);
    expect(await fork.json()).toMatchObject({ code: "duplicity" });

    const evidence = await (await t.app.request(`/v1/kel/${enc(id.did)}/duplicity`, {}, t.env as never)).json() as {
      duplicity: { did: string; seq: number; digests: string[] } | null;
    };
    expect(evidence.duplicity).toMatchObject({ did: id.did, seq: 1 });
    expect(evidence.duplicity!.digests).toHaveLength(2);

    // Refused afterwards — even the branch that was accepted first, and even
    // a further extension of it.
    expect((await postKel(t, id.did, branchA.kel)).status).toBe(409);
    expect((await postKel(t, id.did, (await rotateKel(branchA)).kel)).status).toBe(409);
    const served = await getKel(t, id.did);
    expect(served.status).toBe(409);
    expect(await served.json()).toMatchObject({ code: "duplicity" });
  });

  it("reports no duplicity for a DID that has none", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    await postKel(t, id.did, id.kel);
    const res = await t.app.request(`/v1/kel/${enc(id.did)}/duplicity`, {}, t.env as never);
    expect(await res.json()).toEqual({ did: id.did, duplicity: null });
  });
});

// ─── Controllers ──────────────────────────────────────────────────────────────

describe("controller-authorised logs", () => {
  it("requires the controller's KEL before accepting a controlled agent", async () => {
    const t = await makeApp();
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });

    const without = await postKel(t, agent.did, agent.kel);
    expect(without.status).toBe(422);
    expect(await without.json()).toMatchObject({ code: "controller-unavailable" });

    // Supplying it in the same request works — and stores it.
    expect((await postKel(t, agent.did, agent.kel, person.kel)).status).toBe(200);
    expect((await getKel(t, person.did)).status).toBe(200);
  });

  it("accepts a controller revocation once the controller's log anchors it", async () => {
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await postKel(t, agent.did, agent.kel)).status).toBe(200);

    const r = await revokeAgent(person, agent.kel);
    // The agent's revoke is unsigned (it is authorised by the person's seal),
    // so it only verifies against the person's updated log.
    const withoutSeal = await postKel(t, agent.did, r.agentKel);
    expect(withoutSeal.status).toBe(400);

    const ok = await postKel(t, agent.did, r.agentKel, r.person.kel);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ did: agent.did, sequence: 1, revoked: true });
  });

  it("GET refuses to serve an agent log shorter than its controller's seals imply", async () => {
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await postKel(t, agent.did, agent.kel)).status).toBe(200);

    // The person revokes the agent, and only the PERSON's log reaches the
    // registry. Serving the agent's inception-only log now would hand
    // verifiers the pre-revocation key.
    const r = await revokeAgent(person, agent.kel);
    expect((await postKel(t, person.did, r.person.kel)).status).toBe(200);

    const res = await getKel(t, agent.did);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      code: "stale",
      controller: person.did,
      storedSequence: 0,
      sealedSequence: 1,
    });

    // Once the revocation itself arrives, the log is served again.
    expect((await postKel(t, agent.did, r.agentKel)).status).toBe(200);
    const fresh = await getKel(t, agent.did);
    expect(fresh.status).toBe(200);
    expect((await fresh.json() as { sequence: number }).sequence).toBe(1);
  });

  it("records a fork proven by the controller's seal against a self-signed event", async () => {
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await postKel(t, agent.did, agent.kel)).status).toBe(200);

    // The person recovers the agent onto a new device (seq 1 = recover)...
    const replacement = await generateKelKeyMaterial();
    const rec = await recoverAgent(person, agent.kel, replacement);
    expect((await postKel(t, agent.did, rec.agentKel, rec.person.kel)).status).toBe(200);

    // ...and somebody holding the agent's OLD next key publishes a rotation
    // at the same position. That is a genuinely signed second branch.
    const thiefBranch = await rotateKel(agent);
    const res = await postKel(t, agent.did, thiefBranch.kel);
    expect(res.status).toBe(409);
    const evidence = await (await t.app.request(`/v1/kel/${enc(agent.did)}/duplicity`, {}, t.env as never)).json() as {
      duplicity: { seq: number } | null;
    };
    expect(evidence.duplicity).toMatchObject({ seq: 1 });
  });

  it("ignores a FOREIGN person's seals: no duplicity recorded, GET not blocked", async () => {
    const t = await makeApp();
    // A victim agent with no controller, and one controlled by a real person.
    const victim = await rotateKel(await incept({ kind: "agent" }));
    expect((await postKel(t, victim.did, victim.kel)).status).toBe(200);
    const { agent: controlled } = await personAndAgent(t);
    const controlledRotated = await rotateKel(controlled);
    expect((await postKel(t, controlled.did, controlledRotated.kel)).status).toBe(200);

    // A stranger incepts their own person and anchors seals naming both
    // agents: one with a wrong digest at a stored position, one far past
    // the end of the stored logs.
    const stranger = await incept({ kind: "person" });
    const wrong = eventDigest(stranger.kel[0]);
    const anchored = await anchorInKel(stranger, [
      { did: victim.did, seq: 1, digest: wrong },
      { did: victim.did, seq: 9, digest: wrong },
      { did: controlled.did, seq: 1, digest: wrong },
      { did: controlled.did, seq: 9, digest: wrong },
    ]);
    expect((await postKel(t, stranger.did, anchored.kel)).status).toBe(200);

    for (const did of [victim.did, controlled.did]) {
      const evidence = await (await t.app.request(`/v1/kel/${enc(did)}/duplicity`, {}, t.env as never)).json() as {
        duplicity: unknown;
      };
      expect(evidence.duplicity).toBeNull();
      expect((await getKel(t, did)).status).toBe(200);
    }
    // And the victims can still extend their logs.
    expect((await postKel(t, victim.did, (await rotateKel(victim)).kel)).status).toBe(200);
  });

  it("the REAL controller's mismatched seal over a stored self-signed event is recorded as duplicity", async () => {
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    const rotated = await rotateKel(agent); // seq 1: self-signed rotate
    expect((await postKel(t, agent.did, rotated.kel)).status).toBe(200);

    // The controller anchors a DIFFERENT event at seq 1 (here: a recovery
    // built off the inception-only log) — a second branch.
    const rec = await recoverAgent(person, agent.kel, await generateKelKeyMaterial());
    expect((await postKel(t, person.did, rec.person.kel)).status).toBe(200);

    const evidence = await (await t.app.request(`/v1/kel/${enc(agent.did)}/duplicity`, {}, t.env as never)).json() as {
      duplicity: { seq: number } | null;
    };
    expect(evidence.duplicity).toMatchObject({ seq: 1 });
    expect((await getKel(t, agent.did)).status).toBe(409);
  });

  it("does NOT let an unsigned junk event at a sealed position raise a duplicity alarm", async () => {
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    const replacement = await generateKelKeyMaterial();
    const rec = await recoverAgent(person, agent.kel, replacement);
    expect((await postKel(t, person.did, rec.person.kel)).status).toBe(200);

    // Anyone can write an unsigned `recover` — it carries no signature, its
    // authority is the seal. One that differs from the sealed event must be
    // rejected, never recorded as a fork, or a stranger could permanently
    // alarm somebody else's agent.
    const honest = rec.agentKel[1] as RecoverEvent;
    const junkKeys = await generateKelKeyMaterial();
    const junk: RecoverEvent = {
      ...honest,
      keys: [toMultibase(junkKeys.publicKey)],
      nextKeyDigest: junkKeys.nextKeyDigest,
    };
    const res = await postKel(t, agent.did, [agent.kel[0], junk]);
    expect(res.status).not.toBe(200);
    const evidence = await (await t.app.request(`/v1/kel/${enc(agent.did)}/duplicity`, {}, t.env as never)).json() as {
      duplicity: unknown;
    };
    expect(evidence.duplicity).toBeNull();
    // And the honest recovery is still accepted.
    expect((await postKel(t, agent.did, rec.agentKel)).status).toBe(200);
  });
});

// ─── Agent rows follow the KEL ────────────────────────────────────────────────

describe("registered E-DID agents", () => {
  it("registration takes the key from the KEL, and requires one", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });

    const noKel = await registerEAgent(t, id.did);
    expect(noKel.status).toBe(400);
    expect((await noKel.json() as { error: string }).error).toMatch(/Key Event Log/);

    const other = await generateKeyPair();
    const wrongKey = await registerEAgent(t, id.did, { kel: id.kel, publicKeyB64: toB64(other.publicKey) });
    expect(wrongKey.status).toBe(400);

    const ok = await registerEAgent(t, id.did, { kel: id.kel });
    expect(ok.status).toBe(201);
    const row = await (await getAgent(t, id.did)).json() as { publicKeyB64: string; keyVersion: number };
    expect(row.publicKeyB64).toBe(toB64(id.publicKey));
    expect(row.keyVersion).toBe(1);
  });

  it("registration accepts a KEL posted earlier to /v1/kel", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await rotateKel(await incept({ kind: "agent" }));
    expect((await postKel(t, id.did, id.kel)).status).toBe(200);
    expect((await registerEAgent(t, id.did)).status).toBe(201);
    const row = await (await getAgent(t, id.did)).json() as { publicKeyB64: string; keyVersion: number };
    expect(row.publicKeyB64).toBe(toB64(id.publicKey));
    expect(row.keyVersion).toBe(2);
  });

  it("refuses to register a person as an agent", async () => {
    stubFetch();
    const t = await makeApp();
    const person = await incept({ kind: "person" });
    expect((await registerEAgent(t, person.did, { kel: person.kel })).status).toBe(400);
  });

  it("an accepted rotation updates the row's key and version and archives the old key", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);

    const rotated = await rotateKel(id);
    expect((await postKel(t, id.did, rotated.kel)).status).toBe(200);

    const row = await (await getAgent(t, id.did)).json() as { publicKeyB64: string; keyVersion: number };
    expect(row.publicKeyB64).toBe(toB64(rotated.publicKey));
    expect(row.keyVersion).toBe(2);
    const revoked = await (await t.app.request(`/v1/agents/${hashDID(id.did)}/revoked-keys`, {}, t.env as never)).json();
    expect(revoked).toEqual([expect.objectContaining({ publicKeyB64: toB64(id.publicKey), keyVersion: 1 })]);
  });

  it("accepting a self-revocation deactivates the registered agent", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);

    const revoked = await revokeKelSelf(id);
    const res = await postKel(t, id.did, revoked);
    expect(await res.json()).toMatchObject({ revoked: true });
    expect((await getAgent(t, id.did)).status).toBe(404);

    // ...and it cannot be registered again.
    expect((await registerEAgent(t, id.did)).status).toBe(403);
  });

  it("accepting a controller revocation deactivates the registered agent", async () => {
    stubFetch();
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await registerEAgent(t, agent.did, { kel: agent.kel })).status).toBe(201);

    const r = await revokeAgent(person, agent.kel);
    expect((await postKel(t, agent.did, r.agentKel, r.person.kel)).status).toBe(200);
    expect((await getAgent(t, agent.did)).status).toBe(404);
  });

  it("PUT /:didHash/rotate-key refuses an E-DID and points at the KEL", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);

    // A perfectly well-formed, correctly signed registry rotation — refused
    // anyway, because for an E-DID the registry is not the authority.
    const next = await generateKeyPair();
    const didHash = hashDID(id.did);
    const issuedAt = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const message = JSON.stringify({
      action: "rotate-key", didHash, issuedAt, newPublicKeyB64: toB64(next.publicKey), nonce,
    });
    const signature = toB64(await ed.signAsync(new TextEncoder().encode(message), id.privateKey));
    const res = await t.app.request(
      `/v1/agents/${didHash}/rotate-key`,
      {
        method: "PUT",
        headers: { "content-type": "application/json", authorization: `Bearer ${t.apiKey}` },
        body: JSON.stringify({ newPublicKeyB64: toB64(next.publicKey), signature, nonce, issuedAt }),
      },
      t.env as never,
    );
    expect(res.status).toBe(409);
    expect((await res.json() as { error: string }).error).toMatch(/\/v1\/kel\//);
    const row = await (await getAgent(t, id.did)).json() as { publicKeyB64: string };
    expect(row.publicKeyB64).toBe(toB64(id.publicKey));
  });
});

// ─── SARs and personal names for E-DIDs ──────────────────────────────────────

describe("Signed Agent Records for E-DIDs", () => {
  const publish = (t: TestApp, sar: unknown) => postJson(t, "/v1/sar", sar);

  it("verifies against the rotated key, and stops accepting the superseded one", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);

    // Signed with the CURRENT key, log attached.
    const good = await buildSar({ did: id.did, privateKey: rotated.privateKey, capabilities: ["x"], kel: rotated.kel });
    expect((await publish(t, good)).status).toBe(201);

    // Signed with the superseded key: the registry now knows the longer log,
    // so even attaching the OLD log does not help.
    const stale = await buildSar({ did: id.did, privateKey: id.privateKey, kel: id.kel });
    const res = await publish(t, stale);
    expect(res.status).toBe(422);
    expect((await res.json() as { error: string }).error).toMatch(/bad_signature/);
  });

  it("uses the registry's stored log when none is attached, and attaches it on GET", async () => {
    const t = await makeApp();
    const id = await rotateKel(await incept({ kind: "agent" }));
    const bare = await buildSar({ did: id.did, privateKey: id.privateKey, capabilities: ["y"] });

    expect((await publish(t, bare)).status).toBe(422); // no log known yet
    expect((await postKel(t, id.did, id.kel)).status).toBe(200);
    expect((await publish(t, bare)).status).toBe(201);

    const got = await (await t.app.request(`/v1/sar?did=${enc(id.did)}`, {}, t.env as never)).json() as {
      records: Array<{ kel?: KelEvent[] }>;
    };
    expect(got.records).toHaveLength(1);
    expect(got.records[0].kel).toEqual(id.kel);
    // The served record verifies with the reference client, offline.
    expect((await verifySar(got.records[0])).valid).toBe(true);
  });

  it("rejects a revoked identity's record", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const sar = await buildSar({ did: id.did, privateKey: id.privateKey, kel: id.kel });
    expect((await postKel(t, id.did, await revokeKelSelf(id))).status).toBe(200);
    const res = await publish(t, sar);
    expect(res.status).toBe(422);
    expect((await res.json() as { error: string }).error).toMatch(/revoked/);
  });

  it("agrees with @aroha-sdk/registry's verifySar on the same records", async () => {
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    const cases = [
      await buildSar({ did: id.did, privateKey: rotated.privateKey, kel: rotated.kel }),
      { ...(await buildSar({ did: id.did, privateKey: rotated.privateKey, kel: rotated.kel })), capabilities: ["tampered"] },
    ];
    for (const sar of cases) {
      const reference = (await verifySar(sar)).valid;
      const here = (await publish(t, sar)).status === 201;
      expect(here).toBe(reference);
    }
  });
});

describe("personal names for E-DIDs", () => {
  it("mints the inception-derived label, which survives rotation", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);
    const label = derivePersonalLabelForDid(id.did)!;

    const mint = (l: string) =>
      postJson(t, "/v1/personal-names", { did: id.did, label: l }, { authorization: `Bearer ${t.apiKey}` });
    expect((await mint(label)).status).toBe(201);

    // After a rotation the same label is still the agent's — it derives from
    // the inception, not the key.
    expect((await postKel(t, id.did, (await rotateKel(id)).kel)).status).toBe(200);
    expect((await mint(label)).status).toBe(201);
    const resolved = await (await t.app.request(`/v1/personal-names/${label}`, {}, t.env as never)).json();
    expect(resolved).toEqual({ label, did: id.did });
  });

  it("rejects a label derived from the E-DID's key instead of its inception", async () => {
    stubFetch();
    const t = await makeApp();
    const id = await incept({ kind: "agent" });
    expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);
    const keyLabel = derivePersonalLabelForDid(generateDid(id.publicKey))!;
    const res = await postJson(t, "/v1/personal-names", { did: id.did, label: keyLabel }, { authorization: `Bearer ${t.apiKey}` });
    expect(res.status).toBe(422);
  });
});

// ─── Controller cascade ───────────────────────────────────────────────────────
//
// An agent's authority comes from the person its inception names. Revoking
// that person — or the person anchoring a revoke of the agent — must take the
// agent's registry row down even when the agent's own log never reaches the
// registry, and a person must never reach an agent that did not name it.

describe("controller revocation cascade", () => {
  type Row = { did: string };
  const listDids = async (t: TestApp) =>
    ((await (await t.app.request("/v1/agents", { headers: { "x-forwarded-for": freshIp() } }, t.env as never))
      .json()) as Row[]).map((r) => r.did);
  /** Registration puts agents in a discovery cooldown; lift it so list results mean something. */
  const makeDiscoverable = (t: TestApp) =>
    (t.env.DB as { prepare(sql: string): { run(): Promise<unknown> } })
      .prepare(`UPDATE agent_records SET discovery_eligible_at = NULL`)
      .run();
  const revokedKeys = async (t: TestApp, did: string) =>
    (await (await t.app.request(`/v1/agents/${hashDID(did)}/revoked-keys`, {}, t.env as never)).json()) as Array<{
      publicKeyB64: string;
    }>;

  it("a person's self-revocation deactivates every agent it controls, and only those", async () => {
    stubFetch();
    const t = await makeApp();
    const alice = await incept({ kind: "person" });
    const bob = await incept({ kind: "person" });
    expect((await postKel(t, alice.did, alice.kel)).status).toBe(200);
    expect((await postKel(t, bob.did, bob.kel)).status).toBe(200);
    const a1 = await incept({ kind: "agent", controller: alice.did });
    const a2 = await incept({ kind: "agent", controller: alice.did });
    const b1 = await incept({ kind: "agent", controller: bob.did });
    const free = await incept({ kind: "agent" });
    for (const id of [a1, a2, b1, free]) expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);
    await makeDiscoverable(t);
    expect(await listDids(t)).toEqual(expect.arrayContaining([a1.did, a2.did, b1.did, free.did]));

    // Only ALICE's log is posted — none of her agents' logs change.
    const res = await postKel(t, alice.did, await revokeKelSelf(alice));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ revoked: true });

    expect((await getAgent(t, a1.did)).status).toBe(404);
    expect((await getAgent(t, a2.did)).status).toBe(404);
    expect((await getAgent(t, b1.did)).status).toBe(200);
    expect((await getAgent(t, free.did)).status).toBe(200);

    const listed = await listDids(t);
    expect(listed).not.toContain(a1.did);
    expect(listed).not.toContain(a2.did);
    expect(listed).toEqual(expect.arrayContaining([b1.did, free.did]));

    // The agents' own logs are unrevoked; GET says whose revocation killed them.
    expect(await (await getKel(t, a1.did)).json()).toMatchObject({ controller: alice.did, controllerRevoked: true });
    expect(await (await getKel(t, b1.did)).json()).toMatchObject({ controller: bob.did, controllerRevoked: false });
    expect(await (await getKel(t, free.did)).json()).not.toHaveProperty("controllerRevoked");

    // Their final keys are listed as no longer trustworthy, and they cannot
    // be registered again (the registration route sees controllerRevoked).
    expect(await revokedKeys(t, a1.did)).toEqual([expect.objectContaining({ publicKeyB64: toB64(a1.publicKey) })]);
    expect((await registerEAgent(t, a1.did)).status).toBe(403);
  });

  it("a controller-anchored revoke deactivates the agent before the agent's own log is posted", async () => {
    stubFetch();
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await registerEAgent(t, agent.did, { kel: agent.kel })).status).toBe(201);
    await makeDiscoverable(t);
    expect(await listDids(t)).toContain(agent.did);

    // Only the PERSON's log, carrying the seal, reaches the registry.
    const r = await revokeAgent(person, agent.kel);
    expect((await postKel(t, person.did, r.person.kel)).status).toBe(200);

    expect((await getAgent(t, agent.did)).status).toBe(404);
    expect(await listDids(t)).not.toContain(agent.did);
    expect(await revokedKeys(t, agent.did)).toEqual([expect.objectContaining({ publicKeyB64: toB64(agent.publicKey) })]);

    // When the agent's log does arrive it confirms the revoke: still down,
    // for good, and the dead key is archived once, not twice.
    expect((await postKel(t, agent.did, r.agentKel)).status).toBe(200);
    expect((await getAgent(t, agent.did)).status).toBe(404);
    expect(await revokedKeys(t, agent.did)).toHaveLength(1);
    expect((await registerEAgent(t, agent.did)).status).toBe(403);
  });

  it("a controller-anchored RECOVERY suspends the row, and the agent's log brings it back on the new key", async () => {
    // The seal carries only a digest, so the registry cannot tell a recovery
    // from a revoke until the agent's log arrives — but either way the key
    // on the row is superseded, so it must not stay advertised meanwhile.
    stubFetch();
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await registerEAgent(t, agent.did, { kel: agent.kel })).status).toBe(201);

    const replacement = await generateKelKeyMaterial();
    const rec = await recoverAgent(person, agent.kel, replacement);
    expect((await postKel(t, person.did, rec.person.kel)).status).toBe(200);
    expect((await getAgent(t, agent.did)).status).toBe(404);

    expect((await postKel(t, agent.did, rec.agentKel)).status).toBe(200);
    const row = await (await getAgent(t, agent.did)).json() as { publicKeyB64: string; keyVersion: number };
    expect(row.publicKeyB64).toBe(toB64(replacement.publicKey));
    expect(row.keyVersion).toBe(2);
    expect(await revokedKeys(t, agent.did)).toEqual([expect.objectContaining({ publicKeyB64: toB64(agent.publicKey) })]);
  });

  it("an owner's deactivation is never undone by the KEL path", async () => {
    stubFetch();
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await registerEAgent(t, agent.did, { kel: agent.kel })).status).toBe(201);
    const del = await t.app.request(
      `/v1/agents/${hashDID(agent.did)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${t.apiKey}` } },
      t.env as never,
    );
    expect(del.status).toBeLessThan(300);

    const rec = await recoverAgent(person, agent.kel, await generateKelKeyMaterial());
    expect((await postKel(t, agent.did, rec.agentKel, rec.person.kel)).status).toBe(200);
    expect((await getAgent(t, agent.did)).status).toBe(404);
  });

  it("a FOREIGN person can trigger neither cascade: its seals and its own revocation reach no one else's agent", async () => {
    stubFetch();
    const t = await makeApp();
    const { agent: controlled } = await personAndAgent(t);
    const free = await incept({ kind: "agent" });
    for (const id of [controlled, free]) expect((await registerEAgent(t, id.did, { kel: id.kel })).status).toBe(201);
    await makeDiscoverable(t);

    // A stranger anchors seals PAST the end of both agents' stored logs —
    // exactly what the real controller's revoke would look like — and then
    // revokes itself.
    const stranger = await incept({ kind: "person" });
    const anchored = await anchorInKel(stranger, [
      { did: controlled.did, seq: 1, digest: eventDigest(stranger.kel[0]) },
      { did: free.did, seq: 1, digest: eventDigest(stranger.kel[0]) },
    ]);
    expect((await postKel(t, stranger.did, anchored.kel)).status).toBe(200);
    expect((await getAgent(t, controlled.did)).status).toBe(200);
    expect((await getAgent(t, free.did)).status).toBe(200);

    expect((await postKel(t, stranger.did, await revokeKelSelf(anchored))).status).toBe(200);
    expect((await getAgent(t, controlled.did)).status).toBe(200);
    expect((await getAgent(t, free.did)).status).toBe(200);
    expect(await listDids(t)).toEqual(expect.arrayContaining([controlled.did, free.did]));
    expect(await (await getKel(t, controlled.did)).json()).toMatchObject({ controllerRevoked: false });
  });

  it("discovery by SAR and by personal name hides a controller-revoked agent", async () => {
    stubFetch();
    const t = await makeApp();
    const { person, agent } = await personAndAgent(t);
    expect((await registerEAgent(t, agent.did, { kel: agent.kel })).status).toBe(201);
    const sar = await buildSar({ did: agent.did, privateKey: agent.privateKey, capabilities: ["z"] });
    expect((await postJson(t, "/v1/sar", sar)).status).toBe(201);
    const label = derivePersonalLabelForDid(agent.did)!;
    expect((await postJson(t, "/v1/personal-names", { did: agent.did, label }, { authorization: `Bearer ${t.apiKey}` })).status)
      .toBe(201);
    const sarDids = async () =>
      ((await (await t.app.request(`/v1/sar?capability=z`, {}, t.env as never)).json()) as { records: Row[] }).records
        .map((r) => r.did);
    expect(await sarDids()).toEqual([agent.did]);
    expect((await t.app.request(`/v1/personal-names/${label}`, {}, t.env as never)).status).toBe(200);

    expect((await postKel(t, person.did, await revokeKelSelf(person))).status).toBe(200);
    expect(await sarDids()).toEqual([]);
    expect((await t.app.request(`/v1/personal-names/${label}`, {}, t.env as never)).status).toBe(404);
  });
});

// ─── /v1/linkage ──────────────────────────────────────────────────────────────

describe("/v1/linkage", () => {
  async function zIdentity() {
    const kp = await generateKeyPair();
    return { did: generateDid(kp.publicKey), privateKey: kp.privateKey };
  }

  it("stores the first verified linkage and reports it", async () => {
    const t = await makeApp();
    const old = await zIdentity();
    const { identity, linkage } = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent" });

    const res = await postJson(t, "/v1/linkage", { linkage, toKel: identity.kel });
    expect(res.status).toBe(201);

    const got = await (await t.app.request(`/v1/linkage/${enc(old.did)}`, {}, t.env as never)).json();
    expect(got).toMatchObject({ from: old.did, to: identity.did, linkage, conflict: false, conflictCount: 0 });
    // The successor's log entered the KEL store on the way.
    expect((await getKel(t, identity.did)).status).toBe(200);
  });

  it("first wins: a different later linkage is filed as a conflict (409), never followed", async () => {
    const t = await makeApp();
    const old = await zIdentity();
    const first = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent" });
    // The old key signs a second linkage to a DIFFERENT successor — what a
    // thief holding the z key would do.
    const second = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent" });

    expect((await postJson(t, "/v1/linkage", { linkage: first.linkage, toKel: first.identity.kel })).status).toBe(201);
    const res = await postJson(t, "/v1/linkage", { linkage: second.linkage, toKel: second.identity.kel });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ stored: { to: first.identity.did } });

    const got = await (await t.app.request(`/v1/linkage/${enc(old.did)}`, {}, t.env as never)).json();
    expect(got).toMatchObject({ to: first.identity.did, conflict: true, conflictCount: 1 });
  });

  it("re-submitting a linkage to the same successor is idempotent", async () => {
    const t = await makeApp();
    const old = await zIdentity();
    const { identity, linkage } = await migrateLegacyIdentity(old.did, old.privateKey, { kind: "agent" });
    await postJson(t, "/v1/linkage", { linkage, toKel: identity.kel });
    // Re-signed after the successor rotated — same `to`.
    const rotated = await rotateKel(identity);
    const again = await signIdentityLinkage(old.did, old.privateKey, rotated);
    const res = await postJson(t, "/v1/linkage", { linkage: again, toKel: rotated.kel });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ existing: true, linkage });
    const got = await (await t.app.request(`/v1/linkage/${enc(old.did)}`, {}, t.env as never)).json();
    expect(got).toMatchObject({ conflict: false });
  });

  it("rejects a linkage not signed by the old key", async () => {
    const t = await makeApp();
    const old = await zIdentity();
    const imposter = await zIdentity();
    const target = await incept({ kind: "agent" });
    // Signed by the imposter's key but claiming to be from `old`.
    const forged = { ...(await signIdentityLinkage(imposter.did, imposter.privateKey, target)), from: old.did };
    const res = await postJson(t, "/v1/linkage", { linkage: forged, toKel: target.kel });
    expect(res.status).toBe(400);
    expect((await t.app.request(`/v1/linkage/${enc(old.did)}`, {}, t.env as never)).status).toBe(404);
  });

  it("verifies a named (registry-trusted) DID against the key this registry holds for it", async () => {
    stubFetch();
    const t = await makeApp();
    const named = await generateDID("research-agent", "http://127.0.0.1/x", { namespace: "acme" });
    expect((await postAgent(t.app, t.env, t.apiKey, {
      did: named.did, manifestCID: "QmAbc", publicKeyB64: toB64(named.publicKey),
    }, named.privateKey)).status).toBe(201);

    const target: KelIdentity = await incept({ kind: "agent" });
    const linkage = await signIdentityLinkage(named.did, named.privateKey, target);
    expect((await postJson(t, "/v1/linkage", { linkage, toKel: target.kel })).status).toBe(201);

    // A named DID the registry does not hold a key for cannot be linked.
    const unknown = await generateDID("other-agent", "http://127.0.0.1/y", { namespace: "acme" });
    const orphan = await signIdentityLinkage(unknown.did, unknown.privateKey, target);
    expect((await postJson(t, "/v1/linkage", { linkage: orphan, toKel: target.kel })).status).toBe(400);
  });
});
