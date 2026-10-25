// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Holds test-vectors/http-spend-v1.json (scripts/gen-http-spend-vectors.ts)
 * to the reference: every step reaches the same verdict, code and status,
 * charges the same ledger keys, and every case ends with the same running
 * totals. The Python SDK checks the same file.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { InMemoryHttpPresentationNonces } from "./http-mandate.js";
import { verifyHttpSpendRequest, type HttpSpendRequestResult } from "./http-spend.js";
import { mandateRedemptionKey } from "./redemption.js";
import { MapSpendingLedger } from "./spending-ledger.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../test-vectors/http-spend-v1.json", import.meta.url)), "utf8"));

beforeAll(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("http-spend-v1 vectors", () => {
  it("ledger keys are grantor#mandateId", () => {
    for (const [, m] of Object.entries(V.mandates) as [string, { ledgerKey: string; mandate: { grantor: string; mandateId: string } }][]) {
      expect(m.ledgerKey).toBe(mandateRedemptionKey(m.mandate));
    }
  });

  it("covers the required cases", () => {
    const names = V.cases.map((c: { name: string }) => c.name);
    for (const n of ["within-limit", "over-limit-single", "over-running-total", "sibling-exceeds-parent", "currency-mismatch",
      "merchant", "human-approval", "invalid-amounts", "task-mandate", "root-not-pinned", "mandate-expiry-on-injected-clock"]) expect(names).toContain(n);
  });

  for (const c of V.cases) {
    it(c.name, async () => {
      const ledger = new MapSpendingLedger();
      const nonces = new InMemoryHttpPresentationNonces();
      const results: HttpSpendRequestResult[] = [];
      for (const [i, s] of c.steps.entries()) {
        if ("release" in s) {
          const r = results[s.release];
          if (!r.ok) throw new Error("release of a refused step");
          await r.charge.release();
          results.push(r);
          continue;
        }
        const amountUsd = s.amountFloat !== undefined ? Number(s.amountFloat) : s.amountUsd;
        const r = await verifyHttpSpendRequest(s.headerValue, {
          audience: V.audience, method: s.method ?? "POST", url: V.url, body: V.body, nonces, now: Date.parse(s.now ?? V.now),
          expectedRoot: "expectedRoot" in s ? s.expectedRoot : V.keys.human.did, isRevoked: null, ledger, amountUsd,
          currency: s.currency, merchant: s.merchant, merchantCategory: s.merchantCategory, humanApproved: s.humanApproved,
        });
        results.push(r);
        const got = r.ok ? { ok: true, chargedKeys: r.charge.allocations.map((a) => a.key) } : { ok: false, code: r.code, status: r.status };
        expect(got, `${c.name} step ${i}`).toEqual(s.expected);
      }
      for (const [name, m] of Object.entries(V.mandates) as [string, { ledgerKey: string }][]) {
        const st = await ledger.status(m.ledgerKey);
        expect(st?.allocatedUsd ?? 0, `${c.name} total for ${name}`).toBe(c.expectedTotals[name] ?? 0);
      }
    });
  }
});
