// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The store contract: one suite, run against the in-memory reference
 * implementations from @aroha-sdk/credentials, against Postgres
 * (@aroha-sdk/store-postgres) and against Redis (@aroha-sdk/store-redis —
 * whose tests import this file). Anything a durable store must do that the
 * in-memory one cannot (survive a restart, be shared by two clients, fail
 * closed when the backend is down) is gated on the factory saying it can.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  BudgetExhaustedError,
  HTTP_MANDATE_HEADER,
  completeEnrollment,
  enrolledDid,
  issueEnrollmentChallenge,
  issueIntentMandate,
  mandateRedemptionKey,
  presentMandateHttp,
  signEnrollment,
  verifyHttpSpendRequest,
  type EnrollmentStore,
  type HttpPresentationNonceStore,
  type ISpendingLedger,
} from "@aroha-sdk/credentials/mandates";

export interface StoreSet {
  nonces: HttpPresentationNonceStore;
  enrollment: EnrollmentStore;
  ledger: ISpendingLedger;
}

export interface StoreFactory {
  /**
   * Stores over the shared backing storage. `client` picks one of several
   * independent connections (a second process), so concurrency tests spread
   * their calls over real separate clients.
   */
  open(options?: { client?: number }): StoreSet;
  /** An enrollment store bounded to `maxChallenges`, over storage no other test uses. */
  openBounded(maxChallenges: number): Promise<EnrollmentStore>;
  /** How many independent clients `open({ client })` can choose from. */
  clients: number;
  /**
   * Durable implementations: close every client and open new ones over the
   * same storage (an application restart). Absent for in-memory stores.
   */
  restart?: () => Promise<void>;
  /** Stores whose backend connection is closed — every call must reject. */
  broken?: () => Promise<StoreSet>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const uid = () => crypto.randomUUID().replace(/-/g, "");

interface Key { priv: Uint8Array; did: string }
async function key(): Promise<Key> {
  const priv = ed.utils.randomPrivateKey();
  return { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
}

export function runStoreContract(name: string, getFactory: () => StoreFactory): void {
  describe(`${name} — HttpPresentationNonceStore`, () => {
    it("claims a new key once; a second claim of the same key is refused", async () => {
      const { nonces } = getFactory().open();
      const k = `did:aroha:zHolder ${uid()}`;
      const now = Date.now();
      expect(await nonces.claim(k, now + 60_000, now)).toBe(true);
      expect(await nonces.claim(k, now + 60_000, now)).toBe(false);
      expect(await nonces.claim(`${k}x`, now + 60_000, now)).toBe(true);
    });

    it("20 concurrent claims of one key across clients: exactly one wins", async () => {
      const f = getFactory();
      const k = `holder ${uid()}`;
      const now = Date.now();
      const results = await Promise.all(
        Array.from({ length: 20 }, (_, i) => f.open({ client: i % f.clients }).nonces.claim(k, now + 60_000, now)),
      );
      expect(results.filter((r) => r === true)).toHaveLength(1);
    });

    it("forgets an entry once its presentation has expired", async () => {
      const { nonces } = getFactory().open();
      const k = `holder ${uid()}`;
      const t0 = Date.now();
      expect(await nonces.claim(k, t0 + 150, t0)).toBe(true);
      expect(await nonces.claim(k, t0 + 150, Date.now())).toBe(false);
      await sleep(400);
      const t1 = Date.now();
      expect(await nonces.claim(k, t1 + 60_000, t1)).toBe(true);
      expect(await nonces.claim(k, t1 + 60_000, t1)).toBe(false);
    });

    it("remembers a claimed key across a restart", async (ctx) => {
      const f = getFactory();
      if (!f.restart) return ctx.skip();
      const k = `holder ${uid()}`;
      const now = Date.now();
      expect(await f.open().nonces.claim(k, now + 60_000, now)).toBe(true);
      await f.restart();
      expect(await f.open().nonces.claim(k, now + 60_000, now)).toBe(false);
    });
  });

  describe(`${name} — EnrollmentStore`, () => {
    it("consumes a challenge exactly once and returns its record", async () => {
      const { enrollment } = getFactory().open();
      const c = uid();
      const now = Date.now();
      await enrollment.putChallenge(c, { accountId: "acct-1", expiresAtMs: now + 60_000 }, now);
      expect(await enrollment.consumeChallenge(c)).toEqual({ accountId: "acct-1", expiresAtMs: now + 60_000 });
      expect(await enrollment.consumeChallenge(c) ?? null).toBeNull();
      expect(await enrollment.consumeChallenge(uid()) ?? null).toBeNull();
    });

    it("refuses to issue the same challenge twice", async () => {
      const { enrollment } = getFactory().open();
      const c = uid();
      const now = Date.now();
      await enrollment.putChallenge(c, { accountId: "a", expiresAtMs: now + 60_000 }, now);
      await expect(Promise.resolve().then(() => enrollment.putChallenge(c, { accountId: "b", expiresAtMs: now + 60_000 }, now)))
        .rejects.toThrow(/already issued/);
    });

    it("is bounded: refuses new challenges past maxChallenges; expired ones do not count", async () => {
      const enrollment = await getFactory().openBounded(3);
      const now = Date.now();
      for (let i = 0; i < 3; i++) await enrollment.putChallenge(uid(), { accountId: "a", expiresAtMs: now + 1_000 }, now);
      await expect(Promise.resolve().then(() => enrollment.putChallenge(uid(), { accountId: "a", expiresAtMs: now + 1_000 }, now)))
        .rejects.toThrow(/too many outstanding/);
      // Later, the first three have expired: room again.
      await enrollment.putChallenge(uid(), { accountId: "a", expiresAtMs: now + 10_000 }, now + 2_000);
    });

    it("50 concurrent consumes of one challenge across clients: exactly one gets the record", async () => {
      const f = getFactory();
      const c = uid();
      const now = Date.now();
      await f.open().enrollment.putChallenge(c, { accountId: "acct-c", expiresAtMs: now + 60_000 }, now);
      const results = await Promise.all(
        Array.from({ length: 50 }, (_, i) => f.open({ client: i % f.clients }).enrollment.consumeChallenge(c)),
      );
      const records = results.filter((r) => r);
      expect(records).toHaveLength(1);
      expect(records[0]).toEqual({ accountId: "acct-c", expiresAtMs: now + 60_000 });
    });

    it("records, reads and replaces bindings", async () => {
      const { enrollment } = getFactory().open();
      const acct = `acct-${uid()}`;
      expect(await enrollment.getBinding(acct) ?? null).toBeNull();
      await enrollment.setBinding(acct, "did:aroha:zOne");
      expect(await enrollment.getBinding(acct)).toBe("did:aroha:zOne");
      await enrollment.setBinding(acct, "did:aroha:zTwo");
      expect(await enrollment.getBinding(acct)).toBe("did:aroha:zTwo");
    });

    it("keeps challenges and bindings across a restart", async (ctx) => {
      const f = getFactory();
      if (!f.restart) return ctx.skip();
      const c = uid();
      const acct = `acct-${uid()}`;
      const now = Date.now();
      await f.open().enrollment.putChallenge(c, { accountId: acct, expiresAtMs: now + 60_000 }, now);
      await f.open().enrollment.setBinding(acct, "did:aroha:zKept");
      await f.restart();
      expect(await f.open().enrollment.consumeChallenge(c)).toEqual({ accountId: acct, expiresAtMs: now + 60_000 });
      expect(await f.open().enrollment.getBinding(acct)).toBe("did:aroha:zKept");
    });
  });

  describe(`${name} — ISpendingLedger`, () => {
    it("status is null for an unknown budget; init is idempotent", async () => {
      const { ledger } = getFactory().open();
      const id = `m-${uid()}`;
      expect(await ledger.status(id)).toBeNull();
      await ledger.init(id, 500);
      await ledger.init(id, 9_999);
      expect(await ledger.status(id)).toEqual({ mandateId: id, limitUsd: 500, allocatedUsd: 0, remainingUsd: 500, allocationCount: 0 });
    });

    it("allocates, refuses past the limit with BudgetExhaustedError, and releases", async () => {
      const { ledger } = getFactory().open();
      const id = `m-${uid()}`;
      await ledger.init(id, 500);
      const a = await ledger.allocate(id, 300);
      expect(a.remainingUsd).toBe(200);
      const err = await ledger.allocate(id, 200.01).catch((e) => e);
      expect(err).toBeInstanceOf(BudgetExhaustedError);
      expect(err.remainingUsd).toBe(200);
      const b = await ledger.allocate(id, 200);
      expect(b.remainingUsd).toBe(0);
      expect(await ledger.status(id)).toMatchObject({ allocatedUsd: 500, remainingUsd: 0, allocationCount: 2 });
      expect(await ledger.release(id, a.allocationId)).toEqual({ remainingUsd: 300 });
      expect(await ledger.release(id, a.allocationId)).toEqual({ remainingUsd: 300 });
      expect(await ledger.release(id, "no-such-allocation")).toEqual({ remainingUsd: 300 });
      expect(await ledger.release(`m-${uid()}`, a.allocationId)).toEqual({ remainingUsd: 0 });
      expect(await ledger.status(id)).toMatchObject({ allocatedUsd: 200, allocationCount: 1 });
    });

    it("keeps exact integer micro-dollars (0.1 + 0.2 fills a $0.30 budget exactly)", async () => {
      const { ledger } = getFactory().open();
      const id = `m-${uid()}`;
      await ledger.init(id, 0.3);
      await ledger.allocate(id, 0.1);
      expect((await ledger.allocate(id, 0.2)).remainingUsd).toBe(0);
      await expect(ledger.allocate(id, 0.000001)).rejects.toBeInstanceOf(BudgetExhaustedError);
      expect((await ledger.status(id))!.allocatedUsd).toBe(0.3);
    });

    it("handles amounts up to the largest exactly representable figure", async () => {
      const { ledger } = getFactory().open();
      const id = `m-${uid()}`;
      await ledger.init(id, 9_000_000_000); // 9e15 micro-USD, just under 2^53
      expect((await ledger.allocate(id, 8_999_999_999.5)).remainingUsd).toBe(0.5);
      expect((await ledger.allocate(id, 0.499999)).remainingUsd).toBe(0.000001);
      expect(await ledger.status(id)).toMatchObject({ limitUsd: 9_000_000_000, allocatedUsd: 8_999_999_999.999999, remainingUsd: 0.000001 });
    });

    it("refuses an unknown budget (not as exhaustion) and bad amounts", async () => {
      const { ledger } = getFactory().open();
      const unknown = await ledger.allocate(`m-${uid()}`, 1).catch((e) => e);
      expect(unknown).toBeInstanceOf(Error);
      expect(unknown).not.toBeInstanceOf(BudgetExhaustedError);
      const id = `m-${uid()}`;
      await ledger.init(id, 10);
      await expect(ledger.allocate(id, -1)).rejects.toThrow(RangeError);
      await expect(ledger.allocate(id, Number.NaN)).rejects.toThrow(RangeError);
      await expect(ledger.init(`m-${uid()}`, Number.POSITIVE_INFINITY)).rejects.toThrow(RangeError);
    });

    it("refuses allocation after the budget's expiresAt", async () => {
      const { ledger } = getFactory().open();
      const id = `m-${uid()}`;
      await ledger.init(id, 100, Date.now() - 1);
      const err = await ledger.allocate(id, 1).catch((e) => e);
      expect(err).toBeInstanceOf(BudgetExhaustedError);
      expect(err.remainingUsd).toBe(0);
      const live = `m-${uid()}`;
      await ledger.init(live, 100, Date.now() + 60_000);
      expect((await ledger.allocate(live, 1)).remainingUsd).toBe(99);
    });

    it("3 concurrent $200 allocations on a $500 budget across clients: exactly 2 succeed, total $400", async () => {
      const f = getFactory();
      const id = `m-${uid()}`;
      await f.open().ledger.init(id, 500);
      const results = await Promise.allSettled(
        [0, 1, 2].map((i) => f.open({ client: i % f.clients }).ledger.allocate(id, 200)),
      );
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(2);
      const rejected = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");
      expect(rejected).toHaveLength(1);
      expect(rejected[0].reason).toBeInstanceOf(BudgetExhaustedError);
      expect(await f.open().ledger.status(id)).toMatchObject({ allocatedUsd: 400, remainingUsd: 100, allocationCount: 2 });
    });

    it("50 concurrent $10 allocations on a $300 budget: exactly 30 succeed", async () => {
      const f = getFactory();
      const id = `m-${uid()}`;
      await f.open().ledger.init(id, 300);
      const results = await Promise.allSettled(
        Array.from({ length: 50 }, (_, i) => f.open({ client: i % f.clients }).ledger.allocate(id, 10)),
      );
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(30);
      expect(await f.open().ledger.status(id)).toMatchObject({ allocatedUsd: 300, allocationCount: 30 });
    });

    it("concurrent releases of one allocation return the money once", async () => {
      const f = getFactory();
      const id = `m-${uid()}`;
      await f.open().ledger.init(id, 500);
      await f.open().ledger.allocate(id, 100);
      const { allocationId } = await f.open().ledger.allocate(id, 200);
      await Promise.all(Array.from({ length: 10 }, (_, i) => f.open({ client: i % f.clients }).ledger.release(id, allocationId)));
      expect(await f.open().ledger.status(id)).toMatchObject({ allocatedUsd: 100, allocationCount: 1 });
    });

    it("keeps running totals and allocations across a restart", async (ctx) => {
      const f = getFactory();
      if (!f.restart) return ctx.skip();
      const id = `m-${uid()}`;
      await f.open().ledger.init(id, 500);
      const { allocationId } = await f.open().ledger.allocate(id, 450);
      await f.restart();
      const ledger = f.open().ledger;
      expect(await ledger.status(id)).toMatchObject({ allocatedUsd: 450, remainingUsd: 50 });
      await expect(ledger.allocate(id, 100)).rejects.toBeInstanceOf(BudgetExhaustedError);
      expect(await ledger.release(id, allocationId)).toEqual({ remainingUsd: 500 });
    });
  });

  describe(`${name} — fail closed`, () => {
    it("every store call rejects when the backend is unreachable", async (ctx) => {
      const f = getFactory();
      if (!f.broken) return ctx.skip();
      const s = await f.broken();
      const now = Date.now();
      await expect(Promise.resolve().then(() => s.nonces.claim("k", now + 1_000, now))).rejects.toBeTruthy();
      await expect(Promise.resolve().then(() => s.enrollment.putChallenge(uid(), { accountId: "a", expiresAtMs: now + 1_000 }, now))).rejects.toBeTruthy();
      await expect(Promise.resolve().then(() => s.enrollment.consumeChallenge(uid()))).rejects.toBeTruthy();
      await expect(Promise.resolve().then(() => s.enrollment.getBinding("a"))).rejects.toBeTruthy();
      await expect(Promise.resolve().then(() => s.enrollment.setBinding("a", "did:aroha:zX"))).rejects.toBeTruthy();
      await expect(s.ledger.init("m", 1)).rejects.toBeTruthy();
      await expect(s.ledger.allocate("m", 1)).rejects.not.toBeInstanceOf(BudgetExhaustedError);
      await expect(s.ledger.release("m", "a")).rejects.toBeTruthy();
      await expect(s.ledger.status("m")).rejects.toBeTruthy();
    });
  });

  describe(`${name} — end to end: enrollment, then verifyHttpSpendRequest`, () => {
    const AUD = "https://api.example.com";
    const URL_ = "https://api.example.com/v1/invoices";
    const BODY = '{"customer":"c1","amountUsd":200}';
    let human: Key, agent: Key;

    beforeAll(async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      [human, agent] = await Promise.all([key(), key()]);
    });

    async function header(token: string): Promise<string> {
      return (await presentMandateHttp({
        token, holderDid: agent.did, holderPrivateKey: agent.priv, audience: AUD, method: "POST", url: URL_, body: BODY,
      }))[HTTP_MANDATE_HEADER];
    }

    it("enrolls a DID, pins it as root, charges the running total, refuses replays and over-limit spends", async () => {
      const f = getFactory();
      const account = `acct-${uid()}`;
      const s0 = f.open();

      // Enrollment: challenge, sign on the device, complete.
      const ch = await issueEnrollmentChallenge(s0.enrollment, { authenticatedAccountId: account });
      const proof = await signEnrollment({ accountId: account, did: human.did, challenge: ch.challenge, audience: AUD, privateKey: human.priv });
      // A second process completes it (shared store); a replay of the same completion is refused.
      const s1 = f.open({ client: 1 % f.clients });
      expect(await completeEnrollment(s1.enrollment, { authenticatedAccountId: account, audience: AUD, did: human.did, challenge: ch.challenge, proof }))
        .toMatchObject({ ok: true, accountId: account, did: human.did });
      expect(await completeEnrollment(s0.enrollment, { authenticatedAccountId: account, audience: AUD, did: human.did, challenge: ch.challenge, proof }))
        .toMatchObject({ ok: false, code: "CHALLENGE_UNKNOWN" });

      if (f.restart) await f.restart();
      const s = f.open();
      const root = await enrolledDid(s.enrollment, account);
      expect(root).toBe(human.did);

      const m = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 500 }, human.priv, 600_000);
      const opts = (over: { amountUsd?: number; store?: StoreSet } = {}) => ({
        audience: AUD, method: "POST", url: "/v1/invoices", body: BODY,
        nonces: (over.store ?? s).nonces, ledger: (over.store ?? s).ledger,
        expectedRoot: root, isRevoked: null, amountUsd: over.amountUsd ?? 200,
      });

      const h1 = await header(m.token);
      const first = await verifyHttpSpendRequest(h1, opts());
      expect(first).toMatchObject({ ok: true, rootGrantor: human.did });
      // The same request again, at another process: replay.
      const other = f.open({ client: 1 % f.clients });
      expect(await verifyHttpSpendRequest(h1, opts({ store: other }))).toMatchObject({ ok: false, code: "REPLAYED" });

      // Two more $200 spends in parallel at two processes: one fits, one does not.
      const [h2, h3] = await Promise.all([header(m.token), header(m.token)]);
      const [r2, r3] = await Promise.all([verifyHttpSpendRequest(h2, opts()), verifyHttpSpendRequest(h3, opts({ store: other }))]);
      expect([r2, r3].filter((r) => r.ok)).toHaveLength(1);
      expect([r2, r3].find((r) => !r.ok)).toMatchObject({ ok: false, code: "OVER_LIMIT", status: 403 });
      expect(await s.ledger.status(mandateRedemptionKey(m.mandate))).toMatchObject({ allocatedUsd: 400 });

      // Compensation returns the money.
      if (!first.ok) throw new Error("unreachable");
      await first.charge.release();
      expect(await s.ledger.status(mandateRedemptionKey(m.mandate))).toMatchObject({ allocatedUsd: 200 });
    });

    it("maps a store outage to NONCE_STORE_UNAVAILABLE, LEDGER_UNAVAILABLE and STORE_UNAVAILABLE", async (ctx) => {
      const f = getFactory();
      if (!f.broken) return ctx.skip();
      const good = f.open();
      const bad = await f.broken();
      const account = `acct-${uid()}`;

      // Enrollment against a dead store.
      const ch = await issueEnrollmentChallenge(good.enrollment, { authenticatedAccountId: account });
      const proof = await signEnrollment({ accountId: account, did: human.did, challenge: ch.challenge, audience: AUD, privateKey: human.priv });
      expect(await completeEnrollment(bad.enrollment, { authenticatedAccountId: account, audience: AUD, did: human.did, challenge: ch.challenge, proof }))
        .toMatchObject({ ok: false, code: "STORE_UNAVAILABLE", status: 503 });

      const m = await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 500 }, human.priv, 600_000);
      const base = { audience: AUD, method: "POST", url: "/v1/invoices", body: BODY, expectedRoot: human.did, isRevoked: null, amountUsd: 10 };
      expect(await verifyHttpSpendRequest(await header(m.token), { ...base, nonces: good.nonces, ledger: bad.ledger }))
        .toMatchObject({ ok: false, code: "LEDGER_UNAVAILABLE", status: 503 });
      expect(await verifyHttpSpendRequest(await header(m.token), { ...base, nonces: bad.nonces, ledger: good.ledger }))
        .toMatchObject({ ok: false, code: "NONCE_STORE_UNAVAILABLE" });
    });
  });
}
