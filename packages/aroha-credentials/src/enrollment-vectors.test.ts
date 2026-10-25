// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Holds test-vectors/enrollment-v1.json (scripts/gen-enrollment-vectors.ts)
 * to the reference. The Python SDK checks the same file.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  ENROLLMENT_PURPOSE,
  InMemoryEnrollmentStore,
  completeEnrollment,
  enrolledDid,
  enrollmentSigningPayload,
  signEnrollment,
} from "./enrollment.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../test-vectors/enrollment-v1.json", import.meta.url)), "utf8"));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

describe("enrollment-v1 vectors", () => {
  it("purpose", () => expect(V.purpose).toBe(ENROLLMENT_PURPOSE));

  it("covers the required cases", () => {
    const names = V.cases.map((c: { name: string }) => c.name);
    for (const n of ["enroll", "challenge-for-another-account", "replayed-challenge", "expired-challenge", "proof-by-a-different-key",
      "wrong-audience", "non-content-addressed-did", "rotation"]) expect(names).toContain(n);
    const codes = new Set(V.cases.flatMap((c: { steps: { expected?: { code?: string } }[] }) => c.steps.map((s) => s.expected?.code)));
    for (const code of ["MALFORMED", "CHALLENGE_UNKNOWN", "CHALLENGE_ACCOUNT_MISMATCH", "CHALLENGE_EXPIRED", "BAD_DID", "BAD_PROOF"]) {
      expect(codes).toContain(code);
    }
  });

  it("signing payloads and proofs are byte-identical", async () => {
    for (const s of V.signatures) {
      expect(enrollmentSigningPayload(s.input)).toBe(s.payload);
      expect(await signEnrollment({ ...s.input, privateKey: fromHex(V.keys[s.signer].privateKeyHex) })).toBe(s.proof);
    }
  });

  for (const c of V.cases) {
    it(c.name, async () => {
      const store = new InMemoryEnrollmentStore();
      for (const [i, s] of c.steps.entries()) {
        if ("seed" in s) {
          store.putChallenge(s.seed.challenge, { accountId: s.seed.accountId, expiresAtMs: Date.parse(s.seed.expiresAt) }, Date.parse(V.now));
        } else if ("enrolled" in s) {
          expect((await enrolledDid(store, s.enrolled)) ?? null, `${c.name} step ${i}`).toBe(s.expected);
        } else {
          const { audience, now, ...rest } = s.complete;
          const r = await completeEnrollment(store, { ...rest, audience: audience ?? V.audience, now: Date.parse(now ?? V.now) });
          const got = r.ok
            ? { ok: true, did: r.did, ...(r.replaced !== undefined ? { replaced: r.replaced } : {}) }
            : { ok: false, code: r.code, status: r.status };
          expect(got, `${c.name} step ${i}`).toEqual(s.expected);
        }
      }
    });
  }
});
