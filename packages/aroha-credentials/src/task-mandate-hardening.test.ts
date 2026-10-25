// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * verifyTaskMandate on hostile input: it must RETURN { valid: false } for
 * anything malformed (never throw), reject unparseable or future dates, and
 * refuse structurally wrong bodies even when they are validly signed.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { issueTaskMandate, verifyTaskMandate } from "./mandate.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let priv: Uint8Array;
let pub: Uint8Array;
beforeAll(async () => {
  priv = ed.utils.randomPrivateKey();
  pub = await ed.getPublicKeyAsync(priv);
});

const b64 = (x: unknown) => Buffer.from(JSON.stringify(x)).toString("base64url");

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.fromEntries(
      Object.keys(obj as Record<string, unknown>).sort().map((k) => [k, sortKeys((obj as Record<string, unknown>)[k])])
    );
  }
  return obj;
}

/** Sign an arbitrary (possibly malformed) body exactly as issueTaskMandate signs a good one. */
async function signRaw(mandate: Record<string, unknown>): Promise<string> {
  const sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(mandate))), priv);
  return b64({ mandate, signature: Buffer.from(sig).toString("base64url") });
}

async function goodBody(): Promise<Record<string, unknown>> {
  const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], { reversibleOnly: true }, priv);
  return JSON.parse(JSON.stringify(t.mandate)) as Record<string, unknown>;
}

describe("verifyTaskMandate — malformed tokens return valid:false, never throw", () => {
  const cases: Array<[string, string]> = [
    ["empty string", ""],
    ["not base64 JSON", "%%%"],
    ["JSON null", b64(null)],
    ["JSON number", b64(42)],
    ["JSON array", b64([1, 2])],
    ["object without mandate", b64({ signature: "abc" })],
    ["mandate null", b64({ mandate: null, signature: "abc" })],
    ["signature missing", b64({ mandate: { mandateId: "x" } })],
  ];
  for (const [name, token] of cases) {
    it(name, async () => {
      const r = await verifyTaskMandate(token, new Uint8Array(32));
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/Malformed/);
    });
  }
});

describe("verifyTaskMandate — dates", () => {
  it("rejects a validly-signed mandate whose expiresAt does not parse (used to never expire)", async () => {
    const body = await goodBody();
    body.expiresAt = "not-a-date";
    const r = await verifyTaskMandate(await signRaw(body), pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/expiresAt is not a date/);
  });

  it("rejects issuedAt in the future beyond the clock tolerance", async () => {
    const body = await goodBody();
    body.issuedAt = new Date(Date.now() + 10 * 60_000).toISOString();
    body.expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const r = await verifyTaskMandate(await signRaw(body), pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/in the future/);
  });

  it("tolerates issuedAt within the clock tolerance", async () => {
    const body = await goodBody();
    body.issuedAt = new Date(Date.now() + 5_000).toISOString();
    const r = await verifyTaskMandate(await signRaw(body), pub);
    expect(r.valid).toBe(true);
  });

  it("honours an injected `now`", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv, 60_000);
    expect((await verifyTaskMandate(t.token, pub, undefined, { now: Date.now() + 120_000 })).valid).toBe(false);
  });
});

describe("verifyTaskMandate — shape", () => {
  const mutations: Array<[string, (b: Record<string, unknown>) => void, RegExp]> = [
    ["allowed is not an array", (b) => { b.allowed = "search"; }, /allowed/],
    ["blocked contains a non-string", (b) => { b.blocked = [1]; }, /blocked/],
    ["unknown mandateType", (b) => { b.mandateType = "god-mode"; }, /mandateType/],
    ["unknown mandateTier", (b) => { b.mandateTier = "root"; }, /mandateTier/],
    ["taskConstraints missing", (b) => { delete b.taskConstraints; }, /taskConstraints/],
    ["NaN-ish action limit", (b) => { b.taskConstraints = { actionLimits: { send: "lots" } }; }, /actionLimits/],
    ["negative compute limit", (b) => { b.taskConstraints = { computeLimit: { llmTokens: -1 } }; }, /llmTokens/],
    ["bad dataAccess", (b) => { b.taskConstraints = { dataAccess: { db: "admin" } }; }, /dataAccess/],
    ["hybrid without spendingConstraints", (b) => { b.mandateType = "hybrid"; }, /spendingConstraints/],
    ["grantee missing", (b) => { delete b.grantee; }, /grantee/],
  ];
  for (const [name, mutate, re] of mutations) {
    it(`rejects a validly-signed body with ${name}`, async () => {
      const body = await goodBody();
      mutate(body);
      const r = await verifyTaskMandate(await signRaw(body), pub);
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(re);
    });
  }

  it("still accepts a well-formed v1 task mandate", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {
      actionLimits: { search: 3 }, computeLimit: { llmTokens: 1000 }, dataAccess: { files: "read" },
    }, priv, 60_000, { spendingConstraints: { spendLimitUsd: 10 } });
    const r = await verifyTaskMandate(t.token, pub, "did:aroha:bot");
    expect(r.valid).toBe(true);
    expect(r.mandate?.mandateType).toBe("hybrid");
  });
});
