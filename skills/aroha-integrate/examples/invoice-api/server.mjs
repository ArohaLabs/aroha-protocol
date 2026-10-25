// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// THE INVOICE SERVICE. Two jobs:
//
//   ENROLLMENT — learn, with proof, which DID speaks for which customer.
//     POST /enroll/challenge   (customer's account login) → a single-use challenge
//     POST /enroll             (account login + signature over the challenge
//                               with the DID's key) → customerId ↔ DID recorded
//
//   INVOICING — act only under a customer's signed authorisation.
//     POST /tools/send_invoice { customerId, amountUsd } with an Aroha-Mandate
//     header: the agent's proof + the customer's mandate. The service pins the
//     ENROLLED DID for that customer as the only root it trusts, so a mandate
//     from anyone else — another customer, or a key the agent made up — fails.
//
// What is in memory here and must be durable in production: accounts,
// enrollments, challenges, presentation nonces and the spending ledger.

import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  InMemoryHttpPresentationNonces, MapSpendingLedger,
  InMemoryEnrollmentStore, issueEnrollmentChallenge, completeEnrollment, enrolledDid,
} from "@aroha-sdk/credentials";
import { authoriseSpend } from "./lib/spend.mjs";

/**
 * Build the service. `accounts` maps customerId → that customer's existing
 * account API key (stand-in for your real login). `audience` is how agents
 * address this service — it must match what they sign.
 */
export function createInvoiceService({ accounts, audience, sendInvoice = async () => ({ ok: true }), now = Date.now }) {
  const accountHashes = new Map(Object.entries(accounts).map(([id, key]) => [id, sha256(key)]));
  // Challenges and customerId → DID bindings. A DB-backed EnrollmentStore in production.
  const enrollments = new InMemoryEnrollmentStore();
  const nonces = new InMemoryHttpPresentationNonces();
  const ledger = new MapSpendingLedger();
  const sent = [];

  /** The customer whose account key this request presents, or null. */
  function accountOf(req) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    if (!m) return null;
    const presented = sha256(m[1]);
    for (const [id, hash] of accountHashes) if (hash.length === presented.length && timingSafeEqual(hash, presented)) return id;
    return null;
  }

  async function handle(req, res) {
    const raw = await readBody(req);
    const json = () => { try { return JSON.parse(raw.toString("utf8") || "{}"); } catch { return null; } };

    // Enrollment: the account comes ONLY from this service's own login. The
    // library binds the challenge to it, spends the challenge whatever the
    // outcome, checks the signature with the DID's own key, and binds the
    // proof to this service (audience) so it cannot be replayed elsewhere.
    if (req.method === "POST" && req.url === "/enroll/challenge") {
      const customerId = accountOf(req);
      if (!customerId) return send(res, 401, { error: "sign in to your account first" });
      return send(res, 200, await issueEnrollmentChallenge(enrollments, { authenticatedAccountId: customerId, now: now() }));
    }

    if (req.method === "POST" && req.url === "/enroll") {
      const customerId = accountOf(req);
      const b = json();
      if (!customerId) return send(res, 401, { error: "sign in to your account first" });
      if (!b) return send(res, 400, { error: "body must be JSON" });
      const r = await completeEnrollment(enrollments, {
        authenticatedAccountId: customerId, audience, did: b.did, challenge: b.challenge, proof: b.proof, now: now(),
      });
      if (!r.ok) return send(res, r.status, { error: r.code, reason: r.reason });
      return send(res, 200, { customerId: r.accountId, did: r.did });
    }

    if (req.method === "POST" && req.url === "/tools/send_invoice") {
      const b = json();
      if (!b) return send(res, 400, { error: "body must be JSON" });
      // The customer id only CHOOSES which enrolled DID to pin. A mandate from
      // anyone else fails verification against it; an unknown customer has no
      // DID, which the library refuses as ROOT_NOT_PINNED (403).
      const customerDid = await enrolledDid(enrollments, String(b.customerId ?? ""));
      const r = await authoriseSpend({
        header: req.headers["aroha-mandate"], audience, method: req.method, url: req.url, body: raw,
        nonces, ledger, customerDid, amountUsd: b.amountUsd, now: now(),
      });
      if (!r.ok) return send(res, r.status, { error: r.code, reason: r.reason });
      try {
        const result = await sendInvoice({ customerId: b.customerId, amountUsd: b.amountUsd, agent: r.holder });
        if (!result?.ok) throw new Error("send failed");
      } catch {
        await r.release();                                          // the money was not spent: give it back
        return send(res, 502, { error: "SEND_FAILED" });
      }
      sent.push({ customerId: b.customerId, amountUsd: b.amountUsd, agent: r.holder });
      return send(res, 200, { ok: true, invoice: sent.length });
    }

    return send(res, 404, { error: "not found" });
  }

  return { handle, sent, enrolledDidOf: (id) => enrolledDid(enrollments, id) };
}

function sha256(s) { return createHash("sha256").update(s, "utf8").digest(); }
async function readBody(req) { const chunks = []; for await (const c of req) chunks.push(c); return Buffer.concat(chunks); }
function send(res, status, body) { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); }

/** Start an HTTP server for a service. Resolves with { url, close }. */
export function listen(service, port = 0) {
  const server = createServer((req, res) => {
    service.handle(req, res).catch(() => { if (!res.headersSent) send(res, 500, { error: "INTERNAL" }); });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => {
    const url = `http://127.0.0.1:${server.address().port}`;
    resolve({ url, close: () => new Promise((r) => server.close(r)) });
  }));
}
