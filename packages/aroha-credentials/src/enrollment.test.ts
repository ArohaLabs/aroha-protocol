// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Enrollment: account → DID, proven by the account's login (the server's
 * authenticatedAccountId) and the DID's key over a single-use challenge for
 * this service. Unit tests here; the shared vectors in enrollment-vectors.test.ts.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid, incept, kelSourceFromLogs } from "@aroha-sdk/core";
import {
  ENROLLMENT_PURPOSE,
  InMemoryEnrollmentStore,
  completeEnrollment,
  enrolledDid,
  enrollmentSigningPayload,
  issueEnrollmentChallenge,
  signEnrollment,
  type EnrollmentStore,
} from "./enrollment.js";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp } from "./http-mandate.js";
import { verifyHttpSpendRequest } from "./http-spend.js";
import { issueIntentMandate } from "./mandate.js";
import { MapSpendingLedger } from "./spending-ledger.js";
import * as mandatesEntry from "./mandates.js";
import * as rootEntry from "./index.js";

const AUD = "https://invoices.example.com";

interface Key { priv: Uint8Array; pub: Uint8Array; did: string }
async function key(): Promise<Key> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

let alice: Key, mallory: Key, agent: Key;
beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  [alice, mallory, agent] = await Promise.all([key(), key(), key()]);
});

/** The whole flow: issue for the signed-in account, sign on the device, complete as the signed-in account. */
async function enroll(store: EnrollmentStore, accountId: string, k: Key, over: { signedInAs?: string; audience?: string } = {}) {
  const { challenge } = await issueEnrollmentChallenge(store, { authenticatedAccountId: accountId });
  const proof = await signEnrollment({ accountId, did: k.did, challenge, audience: AUD, privateKey: k.priv });
  return completeEnrollment(store, {
    authenticatedAccountId: over.signedInAs ?? accountId, audience: over.audience ?? AUD, did: k.did, challenge, proof,
  });
}

describe("enrollment", () => {
  it("issues a single-use challenge bound to the account and enrolls the DID", async () => {
    const store = new InMemoryEnrollmentStore();
    const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "acct-1", now: Date.parse("2026-06-01T12:00:00.000Z") });
    expect(c.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(c.expiresAt).toBe("2026-06-01T12:05:00.000Z");
    expect(c.accountId).toBe("acct-1");
    expect(store.pendingChallenges).toBe(1);
    expect(await enrolledDid(store, "acct-1")).toBeUndefined();

    const proof = await signEnrollment({ accountId: "acct-1", did: alice.did, challenge: c.challenge, audience: AUD, privateKey: alice.priv });
    const r = await completeEnrollment(store, {
      authenticatedAccountId: "acct-1", audience: AUD, did: alice.did, challenge: c.challenge, proof, now: Date.parse("2026-06-01T12:04:59.999Z"),
    });
    expect(r).toEqual({ ok: true, accountId: "acct-1", did: alice.did });
    expect(await enrolledDid(store, "acct-1")).toBe(alice.did);
    expect(store.pendingChallenges).toBe(0);
  });

  it("refuses the mutations a hand-written enrollment let through", async () => {
    const store = new InMemoryEnrollmentStore();
    // A challenge issued to A, used by B (with a proof that names B).
    expect(await enroll(store, "acct-A", alice, { signedInAs: "acct-B" })).toMatchObject({ ok: false, code: "CHALLENGE_ACCOUNT_MISMATCH", status: 403 });
    // Skipping the key signature: a proof by another key, or none.
    const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "acct-A" });
    const byMallory = Buffer.from(await ed.signAsync(new TextEncoder().encode(
      enrollmentSigningPayload({ audience: AUD, accountId: "acct-A", did: alice.did, challenge: c.challenge })), mallory.priv)).toString("base64url");
    expect(await completeEnrollment(store, { authenticatedAccountId: "acct-A", audience: AUD, did: alice.did, challenge: c.challenge, proof: byMallory }))
      .toMatchObject({ ok: false, code: "BAD_PROOF", status: 403 });
    const c2 = await issueEnrollmentChallenge(store, { authenticatedAccountId: "acct-A" });
    expect(await completeEnrollment(store, { authenticatedAccountId: "acct-A", audience: AUD, did: alice.did, challenge: c2.challenge, proof: undefined }))
      .toMatchObject({ ok: false, code: "BAD_PROOF" });
    // A proof made for another service.
    expect(await enroll(store, "acct-A", alice, { audience: "https://other.example.com" })).toMatchObject({ ok: false, code: "BAD_PROOF" });
    expect(await enrolledDid(store, "acct-A")).toBeUndefined();
    expect(await enrolledDid(store, "acct-B")).toBeUndefined();
    expect(store.pendingChallenges).toBe(0); // every attempt spent its challenge
  });

  it("spends the challenge whatever the outcome, and refuses expired ones", async () => {
    const store = new InMemoryEnrollmentStore();
    const t0 = Date.now();
    const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a", ttlMs: 1000, now: t0 });
    const proof = await signEnrollment({ accountId: "a", did: alice.did, challenge: c.challenge, audience: AUD, privateKey: alice.priv });
    const done = { authenticatedAccountId: "a", audience: AUD, did: alice.did, challenge: c.challenge, proof };
    expect(await completeEnrollment(store, { ...done, now: t0 + 1000 })).toMatchObject({ ok: false, code: "CHALLENGE_EXPIRED", status: 400 });
    expect(await completeEnrollment(store, { ...done, now: t0 })).toMatchObject({ ok: false, code: "CHALLENGE_UNKNOWN", status: 400 });
  });

  it("a challenge can be completed once, even concurrently", async () => {
    const store = new InMemoryEnrollmentStore();
    const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a" });
    const proof = await signEnrollment({ accountId: "a", did: alice.did, challenge: c.challenge, audience: AUD, privateKey: alice.priv });
    const rs = await Promise.all(Array.from({ length: 5 }, () =>
      completeEnrollment(store, { authenticatedAccountId: "a", audience: AUD, did: alice.did, challenge: c.challenge, proof })));
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
    expect(rs.filter((r) => !r.ok && r.code === "CHALLENGE_UNKNOWN")).toHaveLength(4);
  });

  it("a later enrollment replaces the DID (rotation) and says which one", async () => {
    const store = new InMemoryEnrollmentStore();
    expect(await enroll(store, "a", alice)).toEqual({ ok: true, accountId: "a", did: alice.did });
    const next = await key();
    expect(await enroll(store, "a", next)).toEqual({ ok: true, accountId: "a", did: next.did, replaced: alice.did });
    expect(await enroll(store, "a", next)).toEqual({ ok: true, accountId: "a", did: next.did });
    expect(await enrolledDid(store, "a")).toBe(next.did);
  });

  it("only self-certifying DIDs by default; a custom resolver can vouch for others", async () => {
    const store = new InMemoryEnrollmentStore();
    const named = "did:aroha:alice";
    const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a" });
    const proof = Buffer.from(await ed.signAsync(new TextEncoder().encode(
      enrollmentSigningPayload({ audience: AUD, accountId: "a", did: named, challenge: c.challenge })), alice.priv)).toString("base64url");
    expect(await completeEnrollment(store, { authenticatedAccountId: "a", audience: AUD, did: named, challenge: c.challenge, proof }))
      .toMatchObject({ ok: false, code: "BAD_DID", status: 400 });

    const c2 = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a" });
    const proof2 = Buffer.from(await ed.signAsync(new TextEncoder().encode(
      enrollmentSigningPayload({ audience: AUD, accountId: "a", did: named, challenge: c2.challenge })), alice.priv)).toString("base64url");
    const resolvePublicKey = async (d: string) => (d === named ? alice.pub : null);
    expect(await completeEnrollment(store, { authenticatedAccountId: "a", audience: AUD, did: named, challenge: c2.challenge, proof: proof2, resolvePublicKey }))
      .toMatchObject({ ok: true, did: named });

    const c3 = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a" });
    const throwing = async () => { throw new Error("registry down"); };
    expect(await completeEnrollment(store, { authenticatedAccountId: "a", audience: AUD, did: named, challenge: c3.challenge, proof: proof2, resolvePublicKey: throwing }))
      .toMatchObject({ ok: false, code: "BAD_DID" });
  });

  it("a rotatable did:aroha:E… DID enrolls through a KEL source, and not without one", async () => {
    const person = await incept({ kind: "person" });
    const kelSource = kelSourceFromLogs(person.kel);
    const store = new InMemoryEnrollmentStore();
    const attempt = async (opts: { kelSource?: typeof kelSource }) => {
      const c = await issueEnrollmentChallenge(store, { authenticatedAccountId: "a" });
      const proof = await signEnrollment({ accountId: "a", did: person.did, challenge: c.challenge, audience: AUD, privateKey: person.privateKey });
      return completeEnrollment(store, { authenticatedAccountId: "a", audience: AUD, did: person.did, challenge: c.challenge, proof, ...opts });
    };
    expect(await attempt({})).toMatchObject({ ok: false, code: "BAD_DID" });
    expect(await attempt({ kelSource })).toMatchObject({ ok: true, did: person.did });
  });

  it("a store that throws refuses with 503", async () => {
    const inner = new InMemoryEnrollmentStore();
    const c = await issueEnrollmentChallenge(inner, { authenticatedAccountId: "a" });
    const proof = await signEnrollment({ accountId: "a", did: alice.did, challenge: c.challenge, audience: AUD, privateKey: alice.priv });
    const down: EnrollmentStore = {
      putChallenge: () => {}, consumeChallenge: () => { throw new Error("db"); }, getBinding: () => null, setBinding: () => {},
    };
    expect(await completeEnrollment(down, { authenticatedAccountId: "a", audience: AUD, did: alice.did, challenge: c.challenge, proof }))
      .toMatchObject({ ok: false, code: "STORE_UNAVAILABLE", status: 503 });
    const bindFails: EnrollmentStore = {
      putChallenge: (ch, r, n) => inner.putChallenge(ch, r, n), consumeChallenge: (ch) => inner.consumeChallenge(ch),
      getBinding: () => null, setBinding: async () => { throw new Error("db"); },
    };
    expect(await completeEnrollment(bindFails, { authenticatedAccountId: "a", audience: AUD, did: alice.did, challenge: c.challenge, proof }))
      .toMatchObject({ ok: false, code: "STORE_UNAVAILABLE", status: 503 });
  });

  it("throws on server misconfiguration, never on client input", async () => {
    const store = new InMemoryEnrollmentStore();
    await expect(issueEnrollmentChallenge(store, {} as never)).rejects.toThrow(/authenticatedAccountId/);
    await expect(issueEnrollmentChallenge(undefined as never, { authenticatedAccountId: "a" })).rejects.toThrow(/EnrollmentStore/);
    await expect(issueEnrollmentChallenge(store, { authenticatedAccountId: "a", ttlMs: 0 })).rejects.toThrow(/ttlMs/);
    await expect(issueEnrollmentChallenge(store, { authenticatedAccountId: "a", ttlMs: 2 * 3_600_000 })).rejects.toThrow(/ttlMs/);
    const base = { authenticatedAccountId: "a", audience: AUD, did: alice.did, challenge: "x".repeat(20), proof: "p" };
    await expect(completeEnrollment(store, { ...base, authenticatedAccountId: "" })).rejects.toThrow(/authenticatedAccountId/);
    await expect(completeEnrollment(store, { ...base, audience: undefined as never })).rejects.toThrow(/audience/);
    for (const challenge of [undefined, null, 42, "short", "with space but long enough"]) {
      expect(await completeEnrollment(store, { ...base, challenge })).toMatchObject({ ok: false, code: "MALFORMED", status: 400 });
    }
    await expect(enrolledDid(store, "")).rejects.toThrow(/accountId/);
  });

  it("signEnrollment signs the documented payload and refuses the wrong key", async () => {
    const challenge = "c".repeat(43);
    const proof = await signEnrollment({ accountId: "a", did: alice.did, challenge, audience: AUD, privateKey: alice.priv });
    const payload = enrollmentSigningPayload({ audience: AUD, accountId: "a", did: alice.did, challenge });
    expect(JSON.parse(payload)).toEqual({ purpose: ENROLLMENT_PURPOSE, audience: AUD, accountId: "a", did: alice.did, challenge });
    expect(await ed.verifyAsync(Buffer.from(proof, "base64url"), new TextEncoder().encode(payload), alice.pub)).toBe(true);
    await expect(signEnrollment({ accountId: "a", did: alice.did, challenge, audience: AUD, privateKey: mallory.priv })).rejects.toThrow(/not the key/);
    await expect(signEnrollment({ accountId: "a", did: alice.did, challenge: "bad", audience: AUD, privateKey: alice.priv })).rejects.toThrow(/challenge/);
    await expect(signEnrollment({ accountId: "", did: alice.did, challenge, audience: AUD, privateKey: alice.priv })).rejects.toThrow(/accountId/);
  });

  it("the in-memory store refuses to issue when full, and forgets only expired challenges", async () => {
    const store = new InMemoryEnrollmentStore({ maxChallenges: 2 });
    const t0 = 1_000_000;
    await issueEnrollmentChallenge(store, { authenticatedAccountId: "a", ttlMs: 1000, now: t0 });
    await issueEnrollmentChallenge(store, { authenticatedAccountId: "a", ttlMs: 1000, now: t0 });
    await expect(issueEnrollmentChallenge(store, { authenticatedAccountId: "a", now: t0 + 999 })).rejects.toThrow(/too many/);
    await issueEnrollmentChallenge(store, { authenticatedAccountId: "a", now: t0 + 1000 });
    expect(store.pendingChallenges).toBe(1);
  });

  it("enrolledDid feeds expectedRoot: an unknown customer is ROOT_NOT_PINNED, an enrolled one pins their DID", async () => {
    const store = new InMemoryEnrollmentStore();
    expect((await enroll(store, "cust-1", alice)).ok).toBe(true);
    const grant = await issueIntentMandate(alice.did, agent.did, { spendLimitUsd: 100 }, alice.priv, 600_000);
    const body = '{"customerId":"cust-1","amountUsd":10}';
    const h = (await presentMandateHttp({
      token: grant.token, holderDid: agent.did, holderPrivateKey: agent.priv, audience: AUD, method: "POST", url: `${AUD}/invoices`, body,
    }))[HTTP_MANDATE_HEADER];
    const nonces = new InMemoryHttpPresentationNonces();
    const ledger = new MapSpendingLedger();
    const spend = async (customerId: string) => verifyHttpSpendRequest(h, {
      audience: AUD, method: "POST", url: "/invoices", body, nonces, isRevoked: null, ledger, amountUsd: 10,
      expectedRoot: await enrolledDid(store, customerId),
    });
    expect(await spend("cust-unknown")).toMatchObject({ ok: false, code: "ROOT_NOT_PINNED", status: 403 });
    expect((await enroll(store, "cust-2", mallory)).ok).toBe(true);
    expect(await spend("cust-2")).toMatchObject({ ok: false, code: "MANDATE_INVALID", status: 403 });
    expect((await spend("cust-1")).ok).toBe(true);
  });

  it("is exported from the package root and the Worker-safe /mandates entry", () => {
    for (const mod of [rootEntry, mandatesEntry] as Record<string, unknown>[]) {
      for (const name of ["issueEnrollmentChallenge", "completeEnrollment", "enrolledDid", "signEnrollment", "enrollmentSigningPayload", "InMemoryEnrollmentStore", "ENROLLMENT_PURPOSE"]) {
        expect(mod[name], name).toBeDefined();
      }
    }
  });
});
