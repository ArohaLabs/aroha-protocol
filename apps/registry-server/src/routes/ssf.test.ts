// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Shared Signals transmitter: stream management, SETs emitted on mandate and
// KEL revocation, push (RFC 8935) within the request flow, poll (RFC 8936)
// with acknowledgement, cron retry, and SET signatures checked against the
// published JWKS.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, incept, revokeKelSelf } from "@aroha-sdk/core";
import { issueIntentMandate, revokeMandate } from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { sha256hex } from "../auth.js";
import {
  AROHA_DID_REVOKED,
  AROHA_MANDATE_REVOKED,
  CAEP_CREDENTIAL_CHANGE,
  CAEP_SESSION_REVOKED,
  DELIVERY_POLL,
  DELIVERY_PUSH,
  EVENT_VERIFICATION,
  retryPendingPushes,
} from "../ssf.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const RECEIVER = "https://receiver.example/ssf/events";
const ALL_EVENTS = [CAEP_SESSION_REVOKED, CAEP_CREDENTIAL_CHANGE, AROHA_MANDATE_REVOKED, AROHA_DID_REVOKED];

let t: TestApp;
let ip = 0;
let received: Array<{ body: string; headers: Headers; at: number }>;
let receiverStatus: number;

beforeEach(async () => {
  t = await makeApp();
  received = [];
  receiverStatus = 202;
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === RECEIVER) {
      received.push({ body: String(init?.body), headers: new Headers(init?.headers), at: Date.now() });
      return new Response(null, { status: receiverStatus });
    }
    return new Response("not found", { status: 404 });
  });
});
afterEach(() => vi.unstubAllGlobals());

const req = (path: string, init: RequestInit = {}, apiKey: string | null = t.apiKey) => {
  const headers = new Headers(init.headers);
  headers.set("x-forwarded-for", `10.77.${(ip >> 8) & 255}.${ip++ & 255}`);
  if (apiKey) headers.set("authorization", `Bearer ${apiKey}`);
  if (init.body) headers.set("content-type", "application/json");
  return t.app.request(path, { ...init, headers }, t.env as never);
};

/** Routes the credentials SDK's registry calls into the app. */
const appFetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(String(input));
  return req(url.pathname + url.search, init, null);
}) as typeof fetch;

async function createStream(body: Record<string, unknown>, apiKey = t.apiKey) {
  const res = await req("/v1/ssf/streams", { method: "POST", body: JSON.stringify(body) }, apiKey);
  return { status: res.status, json: (await res.json()) as Record<string, any> };
}

function decodeSet(jwt: string) {
  const [h, p] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(h!, "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(p!, "base64url").toString("utf8")),
  };
}

async function verifySet(jwt: string): Promise<boolean> {
  const jwks = (await (await req("/.well-known/jwks.json", {}, null)).json()) as { keys: Array<{ kid: string; x: string }> };
  const [h, p, s] = jwt.split(".");
  const { header } = decodeSet(jwt);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return false;
  return ed.verify(Buffer.from(s!, "base64url"), new TextEncoder().encode(`${h}.${p}`), Buffer.from(jwk.x, "base64url"));
}

async function revokeAnIntentMandate() {
  const priv = ed.utils.randomPrivateKey();
  const human = { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
  const agentDid = generateDid(await ed.getPublicKeyAsync(ed.utils.randomPrivateKey()));
  const intent = await issueIntentMandate(human.did, agentDid, { spendLimitUsd: 10 }, human.priv);
  const started = Date.now();
  await revokeMandate("https://registry.test", intent.token, human.priv, { fetch: appFetch });
  return { intent, human, started, finished: Date.now() };
}

describe("GET /.well-known/ssf-configuration", () => {
  it("publishes SSF 1.0 transmitter metadata with both delivery methods", async () => {
    const res = await req("/.well-known/ssf-configuration", {}, null);
    expect(res.status).toBe(200);
    const cfg = (await res.json()) as Record<string, any>;
    expect(cfg).toMatchObject({
      spec_version: "1_0",
      issuer: "http://localhost",
      jwks_uri: "http://localhost/.well-known/jwks.json",
      configuration_endpoint: "http://localhost/v1/ssf/streams",
      default_subjects: "ALL",
    });
    expect(cfg.delivery_methods_supported).toEqual([DELIVERY_PUSH, DELIVERY_POLL]);
    expect(cfg.events_supported).toEqual(expect.arrayContaining(ALL_EVENTS));
  });

  it("answers 503 without a signing key (fail closed)", async () => {
    delete t.env.REGISTRY_SIGNING_KEY;
    expect((await req("/.well-known/ssf-configuration", {}, null)).status).toBe(503);
    expect((await req("/.well-known/jwks.json", {}, null)).status).toBe(503);
  });
});

describe("streams", () => {
  it("requires an API key, refuses non-https push endpoints, and keeps the authorization header private", async () => {
    expect((await req("/v1/ssf/streams", { method: "POST", body: "{}" }, null)).status).toBe(401);
    const bad = await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: "http://receiver.example/x" }, events_requested: ALL_EVENTS });
    expect(bad.status).toBe(400);
    const ok = await createStream({
      delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER, authorization_header: "Bearer receiver-secret" },
      events_requested: [...ALL_EVENTS, "https://example.com/unsupported"],
    });
    expect(ok.status).toBe(201);
    expect(ok.json.events_delivered).toEqual(ALL_EVENTS);
    expect(JSON.stringify(ok.json)).not.toContain("receiver-secret");
    const read = await req(`/v1/ssf/streams?stream_id=${ok.json.stream_id}`);
    expect(JSON.stringify(await read.json())).not.toContain("receiver-secret");
  });

  it("hides one key's stream from another key (404), and deletes on the owner's request", async () => {
    const { json } = await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: ALL_EVENTS });
    const otherKey = "other-key-" + Math.random().toString(36).slice(2);
    await (t.env.DB as D1Database)
      .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, 'Other', ?, 1)`)
      .bind(await sha256hex(otherKey), Date.now())
      .run();
    expect((await req(`/v1/ssf/streams?stream_id=${json.stream_id}`, {}, otherKey)).status).toBe(404);
    expect((await req(`/v1/ssf/poll/${json.stream_id}`, { method: "POST", body: "{}" }, otherKey)).status).toBe(404);
    expect((await req(`/v1/ssf/streams?stream_id=${json.stream_id}`, { method: "DELETE" }, otherKey)).status).toBe(404);
    expect((await req(`/v1/ssf/streams?stream_id=${json.stream_id}`, { method: "DELETE" })).status).toBe(204);
    expect((await req(`/v1/ssf/streams?stream_id=${json.stream_id}`)).status).toBe(404);
  });
});

describe("mandate revocation → SETs", () => {
  it("pushes CAEP session-revoked and Aroha mandate-revoked within the revoke request, signed with the published key", async () => {
    const { json: stream } = await createStream({
      delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER, authorization_header: "Bearer receiver-secret" },
      events_requested: ALL_EVENTS,
    });
    const { intent, human, started, finished } = await revokeAnIntentMandate();

    expect(received).toHaveLength(2);
    for (const r of received) {
      expect(r.at - started).toBeLessThan(5_000);
      expect(r.at).toBeLessThanOrEqual(finished);
      expect(r.headers.get("content-type")).toBe("application/secevent+jwt");
      expect(r.headers.get("authorization")).toBe("Bearer receiver-secret");
      expect(await verifySet(r.body)).toBe(true);
    }
    const sets = received.map((r) => decodeSet(r.body));
    expect(sets[0]!.header).toMatchObject({ alg: "EdDSA", typ: "secevent+jwt" });
    const subject = { format: "opaque", id: `${human.did}#${intent.mandate.mandateId}` };
    const types = sets.map((s) => Object.keys(s.claims.events)[0]);
    expect(types).toEqual([CAEP_SESSION_REVOKED, AROHA_MANDATE_REVOKED]);
    for (const s of sets) {
      expect(s.claims).toMatchObject({ iss: "http://localhost", aud: stream.aud, sub_id: subject });
      expect(typeof s.claims.jti).toBe("string");
    }
    expect(sets[1]!.claims.events[AROHA_MANDATE_REVOKED]).toMatchObject({
      mandate_id: intent.mandate.mandateId, grantor: human.did, revoked_by: human.did,
    });
    // Same action → same txn.
    expect(sets[0]!.claims.txn).toBe(sets[1]!.claims.txn);

    // The receiver's credential reached it (above) but is not stored in the clear.
    const row = await (t.env as any).DB
      .prepare(`SELECT authorization_header FROM ssf_streams WHERE stream_id = ?`)
      .bind(stream.stream_id)
      .first();
    expect(row.authorization_header).toMatch(/^enc:v1:/);
    expect(row.authorization_header).not.toContain("receiver-secret");
  });

  it("a SET verification fails once the payload is altered", async () => {
    await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [AROHA_MANDATE_REVOKED] });
    await revokeAnIntentMandate();
    const [h, p, s] = received[0]!.body.split(".");
    const claims = JSON.parse(Buffer.from(p!, "base64url").toString("utf8"));
    claims.events[AROHA_MANDATE_REVOKED].revoked_by = "did:aroha:zSomeoneElse";
    const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
    expect(await verifySet(forged)).toBe(false);
  });

  it("delivers only requested event types, and nothing to a paused stream until it is retried enabled", async () => {
    const { json: stream } = await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [AROHA_MANDATE_REVOKED] });
    await req("/v1/ssf/status", { method: "POST", body: JSON.stringify({ stream_id: stream.stream_id, status: "paused" }) });
    await revokeAnIntentMandate();
    expect(received).toHaveLength(0);
    await req("/v1/ssf/status", { method: "POST", body: JSON.stringify({ stream_id: stream.stream_id, status: "enabled" }) });
    expect(await retryPendingPushes(t.env as never)).toBe(1);
    expect(received).toHaveLength(1);
    expect(Object.keys(decodeSet(received[0]!.body).claims.events)).toEqual([AROHA_MANDATE_REVOKED]);
  });

  it("queues a failed push durably and the cron retry delivers the same SET", async () => {
    await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [AROHA_MANDATE_REVOKED] });
    receiverStatus = 503;
    await revokeAnIntentMandate();
    expect(received).toHaveLength(1);
    const first = received[0]!.body;
    const row = await (t.env.DB as D1Database)
      .prepare(`SELECT attempts, delivered_at, last_error FROM ssf_outbox`)
      .first<{ attempts: number; delivered_at: number | null; last_error: string }>();
    expect(row).toMatchObject({ attempts: 1, delivered_at: null, last_error: "HTTP 503" });

    receiverStatus = 202;
    expect(await retryPendingPushes(t.env as never)).toBe(0); // backoff not yet elapsed
    expect(await retryPendingPushes(t.env as never, Date.now() + 120_000)).toBe(1);
    expect(received[1]!.body).toBe(first);
    const after = await (t.env.DB as D1Database).prepare(`SELECT delivered_at FROM ssf_outbox`).first<{ delivered_at: number | null }>();
    expect(after?.delivered_at).not.toBeNull();
  });

  it("a repeated revocation of the same mandate emits nothing new", async () => {
    await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [AROHA_MANDATE_REVOKED] });
    const { intent, human } = await revokeAnIntentMandate();
    await revokeMandate("https://registry.test", intent.token, human.priv, { fetch: appFetch });
    expect(received).toHaveLength(1);
  });
});

describe("poll delivery (RFC 8936)", () => {
  it("returns queued SETs until acknowledged", async () => {
    const { json: stream } = await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: ALL_EVENTS });
    expect(stream.delivery.endpoint_url).toBe(`http://localhost/v1/ssf/poll/${stream.stream_id}`);
    await revokeAnIntentMandate();
    const poll = async (body: unknown) =>
      (await (await req(`/v1/ssf/poll/${stream.stream_id}`, { method: "POST", body: JSON.stringify(body) })).json()) as {
        sets: Record<string, string>; moreAvailable: boolean;
      };
    const first = await poll({ maxEvents: 1 });
    expect(Object.keys(first.sets)).toHaveLength(1);
    expect(first.moreAvailable).toBe(true);
    const all = await poll({});
    expect(Object.keys(all.sets)).toHaveLength(2);
    for (const jwt of Object.values(all.sets)) expect(await verifySet(jwt)).toBe(true);
    const done = await poll({ ack: Object.keys(all.sets) });
    expect(done).toEqual({ sets: {}, moreAvailable: false });
    expect(received).toHaveLength(0); // poll streams are never pushed
  });
});

describe("KEL revocation → SETs", () => {
  it("emits credential-change and did-revoked for the person and every registered agent it controls", async () => {
    const { json: stream } = await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [CAEP_CREDENTIAL_CHANGE, AROHA_DID_REVOKED] });
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    const post = (path: string, body: unknown, auth: string | null = null) => req(path, { method: "POST", body: JSON.stringify(body) }, auth);
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: person.kel })).status).toBe(200);
    expect((await post("/v1/agents", { did: agent.did, manifestCID: "QmAbc", kel: agent.kel }, t.apiKey)).status).toBe(201);

    const revokedLog = await revokeKelSelf(person);
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: revokedLog })).status).toBe(200);
    const res = (await (await req(`/v1/ssf/poll/${stream.stream_id}`, { method: "POST", body: "{}" })).json()) as { sets: Record<string, string> };
    const sets = Object.values(res.sets).map(decodeSet);
    expect(sets).toHaveLength(4);
    const byType = (type: string) => sets.filter((s) => type in s.claims.events);
    expect(byType(CAEP_CREDENTIAL_CHANGE).map((s) => s.claims.sub_id.uri).sort()).toEqual([agent.did, person.did].sort());
    for (const s of byType(CAEP_CREDENTIAL_CHANGE)) {
      expect(s.claims.events[CAEP_CREDENTIAL_CHANGE]).toMatchObject({ credential_type: "aroha-did-key", change_type: "revoke" });
    }
    const cascaded = byType(AROHA_DID_REVOKED).find((s) => s.claims.sub_id.uri === agent.did);
    expect(cascaded?.claims.events[AROHA_DID_REVOKED]).toMatchObject({ reason: "controller-revoked", controller: person.did });

    // Re-posting the same revoked log announces nothing further.
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: revokedLog })).status).toBe(200);
    const again = (await (await req(`/v1/ssf/poll/${stream.stream_id}`, { method: "POST", body: JSON.stringify({ ack: Object.keys(res.sets) }) })).json()) as { sets: Record<string, string> };
    expect(again.sets).toEqual({});
  });
});

describe("visibility of event subjects", () => {
  async function otherKey(): Promise<string> {
    const key = "other-key-" + Math.random().toString(36).slice(2);
    await (t.env.DB as D1Database)
      .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, 'Other', ?, 1)`)
      .bind(await sha256hex(key), Date.now())
      .run();
    return key;
  }
  const post = (path: string, body: unknown, auth: string | null = null, method = "POST") =>
    req(path, { method, body: JSON.stringify(body) }, auth);
  const pollSubjects = async (streamId: string, key: string) => {
    const res = (await (await req(`/v1/ssf/poll/${streamId}`, { method: "POST", body: "{}" }, key)).json()) as { sets: Record<string, string> };
    return Object.values(res.sets).map((j) => decodeSet(j).claims.sub_id.uri as string);
  };

  /** A person, and an agent it controls registered under t.apiKey with the given visibility. */
  async function controlledAgent(visibility: "public" | "private" | "unlisted") {
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: person.kel })).status).toBe(200);
    expect((await post("/v1/agents", { did: agent.did, manifestCID: "QmAbc", kel: agent.kel }, t.apiKey)).status).toBe(201);
    if (visibility !== "public") {
      const { hashDID } = await import("./agents.js");
      expect((await post(`/v1/agents/${hashDID(agent.did)}/visibility`, { visibility }, t.apiKey, "PATCH")).status).toBe(200);
    }
    return { person, agent };
  }

  it("a private agent's cascade event reaches its owner's stream but not an unrelated stream", async () => {
    const other = await otherKey();
    const mine = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] })).json;
    const theirs = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] }, other)).json;
    const { person, agent } = await controlledAgent("private");
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: await revokeKelSelf(person) })).status).toBe(200);
    expect((await pollSubjects(mine.stream_id, t.apiKey)).sort()).toEqual([agent.did, person.did].sort());
    expect(await pollSubjects(theirs.stream_id, other)).toEqual([person.did]);
  });

  it("an unlisted agent is not broadcast either; a grant opens it to the grantee's stream", async () => {
    const other = await otherKey();
    const third = await otherKey();
    const granted = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] }, other)).json;
    const stranger = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] }, third)).json;
    const { person, agent } = await controlledAgent("unlisted");
    const { hashDID } = await import("./agents.js");
    expect((await post("/v1/grants", { resourceDidHash: hashDID(agent.did), resourceType: "agent", granteeApiKey: other }, t.apiKey)).status).toBeLessThan(300);
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: await revokeKelSelf(person) })).status).toBe(200);
    expect(await pollSubjects(granted.stream_id, other)).toContain(agent.did);
    expect(await pollSubjects(stranger.stream_id, third)).toEqual([person.did]);
  });

  it("a public agent's event reaches every stream", async () => {
    const other = await otherKey();
    const theirs = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] }, other)).json;
    const { person, agent } = await controlledAgent("public");
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: await revokeKelSelf(person) })).status).toBe(200);
    expect((await pollSubjects(theirs.stream_id, other)).sort()).toEqual([agent.did, person.did].sort());
  });

  it("a subject made private after queueing is withheld from polls and push retries", async () => {
    const other = await otherKey();
    const theirs = (await createStream({ delivery: { method: DELIVERY_POLL }, events_requested: [AROHA_DID_REVOKED] }, other)).json;
    const pushTheirs = (await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [AROHA_DID_REVOKED] }, other)).json;
    receiverStatus = 503;
    const { person, agent } = await controlledAgent("public");
    expect((await post(`/v1/kel/${encodeURIComponent(person.did)}`, { events: await revokeKelSelf(person) })).status).toBe(200);
    const { hashDID } = await import("./agents.js");
    await (t.env.DB as D1Database).prepare(`UPDATE agent_records SET visibility = 'private' WHERE did_hash = ?`).bind(hashDID(agent.did)).run();
    expect(await pollSubjects(theirs.stream_id, other)).toEqual([person.did]);
    receiverStatus = 202;
    received = [];
    await retryPendingPushes(t.env as never, Date.now() + 120_000);
    expect(received.map((r) => decodeSet(r.body).claims.sub_id.uri)).toEqual([person.did]);
    const withheld = await (t.env.DB as D1Database)
      .prepare(`SELECT COUNT(*) AS n FROM ssf_outbox WHERE last_error = 'subject no longer visible to this stream' AND stream_id IN (?, ?)`)
      .bind(theirs.stream_id, pushTheirs.stream_id)
      .first<{ n: number }>();
    expect(withheld?.n).toBe(2);
  });
});

describe("verification", () => {
  it("queues a verification SET echoing state", async () => {
    const { json: stream } = await createStream({ delivery: { method: DELIVERY_PUSH, endpoint_url: RECEIVER }, events_requested: [] });
    expect((await req("/v1/ssf/verify", { method: "POST", body: JSON.stringify({ stream_id: stream.stream_id, state: "abc" }) })).status).toBe(204);
    expect(received).toHaveLength(1);
    expect(decodeSet(received[0]!.body).claims.events[EVENT_VERIFICATION]).toEqual({ state: "abc" });
  });
});
