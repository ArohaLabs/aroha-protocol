// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Task-mandate chains in the JWT form (spec §6.10). A chain is still an array
 * of single-link tokens; each link is now a compact JWS. The chain rules are
 * the ones native chains get.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { attenuateTaskMandate, issueTaskMandate, looksLikeMandateJwt, signMandateJwt } from "@aroha-sdk/credentials";
import { parseTaskMandateToken, staticResolver, verifyTaskMandateChain, TaskMandateTokenError } from "./chain.js";

const HUMAN = "did:aroha:test:kiri";
const ASSISTANT = "did:aroha:test:assistant";
const WORKER = "did:aroha:test:worker";

async function party() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, pub: await ed.getPublicKeyAsync(priv) };
}

describe("verifyTaskMandateChain with JWT-form links", () => {
  it("verifies a two-hop chain of JWTs and reports the narrowed authority", async () => {
    const human = await party(), assistant = await party();
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read", "inbox.archive", "inbox.send"], { maxDelegationDepth: 2, actionLimits: { "inbox.archive": 50 } }, human.priv, 3_600_000, { format: "jwt" });
    const child = await attenuateTaskMandate(root, WORKER, ["inbox.read", "inbox.archive"], { maxDelegationDepth: 1, actionLimits: { "inbox.archive": 10 } }, assistant.priv);
    expect(looksLikeMandateJwt(root.token) && looksLikeMandateJwt(child.token)).toBe(true);

    const r = await verifyTaskMandateChain([root.token, child.token], human.pub, {
      expectedGrantee: WORKER,
      resolvePublicKey: staticResolver({ [ASSISTANT]: assistant.pub }),
    });
    expect(r.valid, r.reason).toBe(true);
    expect(r.depth).toBe(2);
    expect(r.mandate?.allowed).toEqual(["inbox.read", "inbox.archive"]);
    expect(r.mandate?.taskConstraints.actionLimits).toEqual({ "inbox.archive": 10 });
  });

  it("parses a JWT link to the same shape a native link has", async () => {
    const human = await party();
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["research"], {}, human.priv, 3_600_000, { format: "jwt" });
    const parsed = parseTaskMandateToken(root.token);
    expect(parsed.mandate).toEqual(root.mandate);
    expect(parsed.jwt).toBe(root.token);
    expect(parsed.v).toBe(2);
  });

  it("refuses a widened child even though it is a validly signed JWT", async () => {
    const human = await party(), assistant = await party();
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], { maxDelegationDepth: 2 }, human.priv, 3_600_000, { format: "jwt" });
    const honest = await attenuateTaskMandate(root, WORKER, ["inbox.read"], { maxDelegationDepth: 1 }, assistant.priv);
    const widened = await signMandateJwt("task", { ...honest.mandate, allowed: ["inbox.read", "inbox.delete"], mandateId: crypto.randomUUID() } as unknown as Record<string, unknown>, assistant.priv);
    const r = await verifyTaskMandateChain([root.token, widened], human.pub, { resolvePublicKey: staticResolver({ [ASSISTANT]: assistant.pub }) });
    expect(r.valid).toBe(false);
  });

  it("refuses a link signed by the wrong key, a changed link, and a malformed JWT", async () => {
    const human = await party(), assistant = await party(), impostor = await party();
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], { maxDelegationDepth: 2 }, human.priv, 3_600_000, { format: "jwt" });
    const forged = await attenuateTaskMandate(root, WORKER, ["inbox.read"], { maxDelegationDepth: 1 }, impostor.priv);
    const resolvePublicKey = staticResolver({ [ASSISTANT]: assistant.pub });
    expect((await verifyTaskMandateChain([root.token, forged.token], human.pub, { resolvePublicKey })).valid).toBe(false);
    expect((await verifyTaskMandateChain([root.token], impostor.pub)).valid).toBe(false);

    const [h, p, s] = root.token.split(".");
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as { exp: number };
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...claims, exp: claims.exp + 86_400 })).toString("base64url")}.${s}`;
    expect((await verifyTaskMandateChain([tampered], human.pub)).valid).toBe(false);

    expect((await verifyTaskMandateChain(["a.b.c"], human.pub)).valid).toBe(false);
    expect(() => parseTaskMandateToken("a.b.c")).toThrow(TaskMandateTokenError);
    expect(() => parseTaskMandateToken("a.b.c")).toThrow(/^Malformed task mandate token/);
  });
});
