// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Pins test-vectors/task-mandate-v2-cases.json (scripts/gen-task-test-vectors.ts; the Python SDK reads it).
 * test-vectors/task-mandate-v2.json is a second, independently generated set the Go SDK reads
 * (scripts/gen-task-mandate-vectors.ts, pinned by task-mandate-vectors.test.ts):
 * the reference must keep producing what other SDKs (sdks/aroha-py) are
 * checked against. A failure here is a wire or behaviour change for task
 * mandates — regenerate only on purpose.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import type { ArohaTaskMandateBody } from "@aroha-sdk/core";
import {
  checkTaskConstraints,
  checkTaskNarrowing,
  taskMandateSigningPayloadV2,
  verifyTaskMandate,
  type TaskActionRequest,
} from "./mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface TaskVectorFile {
  keys: Record<string, { privateKeyHex: string; publicKeyHex: string; did: string }>;
  mandates: { name: string; signer: string; mandate: ArohaTaskMandateBody; expectedSigningPayload: string; expectedSignature: string }[];
  tokens: { name: string; token: string; signer: string; verifyAt: string; expectedGrantee?: string; expected: { valid: boolean; reason: string | null } }[];
  narrowing: { name: string; parent: ArohaTaskMandateBody; child: ArohaTaskMandateBody; expectedReason: string | null }[];
  actions: { name: string; mandate: string; request: TaskActionRequest; expected: { code: string; message: string } | null }[];
}

const V = JSON.parse(
  readFileSync(fileURLToPath(new URL("../test-vectors/task-mandate-v2-cases.json", import.meta.url)), "utf8")
) as TaskVectorFile;
const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const byName = Object.fromEntries(V.mandates.map((m) => [m.name, m.mandate]));

describe("task-mandate v2 vectors", () => {
  it.each(V.mandates.map((m) => [m.name, m] as const))("signing payload + signature: %s", async (_n, m) => {
    expect(taskMandateSigningPayloadV2(m.mandate)).toBe(m.expectedSigningPayload);
    const sig = await ed.signAsync(new TextEncoder().encode(m.expectedSigningPayload), hex(V.keys[m.signer].privateKeyHex));
    expect(Buffer.from(sig).toString("base64url")).toBe(m.expectedSignature);
  });

  it.each(V.tokens.map((t) => [t.name, t] as const))("token verdict: %s", async (_n, t) => {
    const r = await verifyTaskMandate(t.token, hex(V.keys[t.signer].publicKeyHex), t.expectedGrantee, { now: Date.parse(t.verifyAt) });
    expect({ valid: r.valid, reason: r.reason ?? null }).toEqual(t.expected);
  });

  it.each(V.narrowing.map((n) => [n.name, n] as const))("narrowing: %s", (_n, n) => {
    expect(checkTaskNarrowing(n.parent, n.child)).toBe(n.expectedReason);
  });

  it.each(V.actions.map((a) => [a.name, a] as const))("action: %s", (_n, a) => {
    const v = checkTaskConstraints(byName[a.mandate], a.request);
    expect(v ? { code: v.code, message: v.message } : null).toEqual(a.expected);
  });
});
