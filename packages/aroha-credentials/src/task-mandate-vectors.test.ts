// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Holds test-vectors/task-mandate-v2.json (scripts/gen-task-mandate-vectors.ts)
 * to the reference: every payload, signature, verdict, reason and code in the
 * file must still be what this package computes. The Go SDK consumes the same
 * file, so a rule change here that is not regenerated fails in both places.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import {
  checkTaskConstraints,
  checkTaskNarrowing,
  taskMandateSigningPayloadV2,
  verifyTaskMandate,
} from "./mandate.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../test-vectors/task-mandate-v2.json", import.meta.url)), "utf8"));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const pub = (name: string) => fromHex(V.keys[name].publicKeyHex);
const body = (name: string) => V.mandates.find((m: { name: string }) => m.name === name).mandate;

describe("task-mandate-v2 vectors", () => {
  it("signing payloads and signatures", async () => {
    for (const m of V.mandates) {
      expect(taskMandateSigningPayloadV2(m.mandate), m.name).toBe(m.expectedSigningPayload);
      const sig = await ed.signAsync(new TextEncoder().encode(m.expectedSigningPayload), fromHex(V.keys[m.signer].privateKeyHex));
      expect(Buffer.from(sig).toString("base64url"), m.name).toBe(m.expectedSignature);
    }
  });

  it("token verdicts", async () => {
    for (const t of V.tokens) {
      const r = await verifyTaskMandate(t.token, pub(t.signer), t.expectedGrantee, { now: Date.parse(t.now) });
      expect({ valid: r.valid, reason: r.reason }, t.name).toEqual({ valid: t.valid, reason: t.reason });
    }
  });

  it("narrowing verdicts", () => {
    for (const n of V.narrowing) {
      expect(checkTaskNarrowing(body(n.parent), n.child) ?? undefined, n.name).toBe(n.reason);
    }
  });

  it("request verdicts", () => {
    for (const q of V.requests) {
      const v = checkTaskConstraints(body(q.mandate), q.request);
      expect(v ? { code: v.code, reason: v.message } : null, q.name).toEqual(q.allowed ? null : { code: q.code, reason: q.reason });
    }
  });
});
