// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Conversation-profile bindings on mandates:
 *   - task mandates: onBehalfOf / roomId kept on every child, enforced
 *     against the request;
 *   - spending mandates: actingFor (PSD3 payer/payee side) declared on the
 *     root, inherited and enforced on every link, absent = legacy bytes.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid, type ArohaSpendingMandateBody } from "@aroha-sdk/core";
import {
  issueTaskMandate, attenuateTaskMandate, checkTaskNarrowing, checkTaskConstraints, enforceTaskConstraints,
  verifyTaskMandate, TaskConstraintViolation, taskMandateSigningPayloadV2,
  issueIntentMandate, attenuateToCart, verifyMandateChain, mandateSigningPayloadV2, type MandateChainLink,
} from "./mandate.js";
import { canonicalizeJcs } from "./jcs.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

const GUEST = "did:aroha:Eguest";
const ROOM = "room-7f3a";

describe("task mandate onBehalfOf / roomId", () => {
  it("a guest grant round-trips and binds requests to the room and member", async () => {
    const host = await party();
    const agent = await party();
    const m = await issueTaskMandate(host.did, agent.did, ["search", "draft-email"],
      { onBehalfOf: GUEST, roomId: ROOM, reversibleOnly: true }, host.priv);
    const v = await verifyTaskMandate(m.token, host.pub, agent.did);
    expect(v.valid).toBe(true);
    expect(v.mandate!.taskConstraints.onBehalfOf).toBe(GUEST);

    const base = { requestedCapability: "search", capabilityReversibility: "full" as const };
    expect(checkTaskConstraints(m.mandate, { ...base, roomId: ROOM, onBehalfOf: GUEST })).toBeNull();
    expect(checkTaskConstraints(m.mandate, { ...base, roomId: "other-room", onBehalfOf: GUEST })?.code).toBe("CONTEXT_MISMATCH");
    expect(checkTaskConstraints(m.mandate, { ...base, roomId: ROOM, onBehalfOf: "did:aroha:Eother" })?.code).toBe("CONTEXT_MISMATCH");
    // Fail closed: a request that names no room is not "any room".
    expect(checkTaskConstraints(m.mandate, base)?.code).toBe("CONTEXT_MISMATCH");

    await expect(enforceTaskConstraints(m.token, host.pub, { ...base, expectedGrantee: agent.did, roomId: "x", onBehalfOf: GUEST }))
      .rejects.toBeInstanceOf(TaskConstraintViolation);
    await expect(enforceTaskConstraints(m.token, host.pub, { ...base, expectedGrantee: agent.did, roomId: ROOM, onBehalfOf: GUEST }))
      .resolves.toMatchObject({ mandateId: m.mandate.mandateId });
  });

  it("a child must keep the parent's onBehalfOf and roomId (omission is widening)", async () => {
    const host = await party();
    const agent = await party();
    const parent = await issueTaskMandate(host.did, agent.did, ["search"], { onBehalfOf: GUEST, roomId: ROOM }, host.priv);
    const child = { allowed: ["search"], taskConstraints: {} };
    expect(checkTaskNarrowing(parent.mandate, child)).toMatch(/onBehalfOf/);
    expect(checkTaskNarrowing(parent.mandate, { ...child, taskConstraints: { onBehalfOf: GUEST } })).toMatch(/roomId/);
    expect(checkTaskNarrowing(parent.mandate, { ...child, taskConstraints: { onBehalfOf: "did:aroha:Eother", roomId: ROOM } })).toMatch(/onBehalfOf/);
    expect(checkTaskNarrowing(parent.mandate, { ...child, taskConstraints: { onBehalfOf: GUEST, roomId: ROOM } })).toBeNull();

    // attenuateTaskMandate inherits the binding when the caller omits it…
    const sub = await party();
    const c = await attenuateTaskMandate(parent, sub.did, ["search"], {}, agent.priv);
    expect(c.mandate.taskConstraints).toMatchObject({ onBehalfOf: GUEST, roomId: ROOM });
    // …and refuses a different one.
    await expect(attenuateTaskMandate(parent, sub.did, ["search"], { roomId: "elsewhere" }, agent.priv)).rejects.toThrow(/roomId/);
  });

  it("a parent without a binding lets a child add one (narrowing)", async () => {
    const host = await party();
    const agent = await party();
    const parent = await issueTaskMandate(host.did, agent.did, ["search"], {}, host.priv);
    expect(checkTaskNarrowing(parent.mandate, { allowed: ["search"], taskConstraints: { roomId: ROOM, onBehalfOf: GUEST } })).toBeNull();
  });

  it("malformed bindings are refused by the shape check", async () => {
    const host = await party();
    const agent = await party();
    const m = await issueTaskMandate(host.did, agent.did, ["search"], {}, host.priv);
    const raw = JSON.parse(Buffer.from(m.token, "base64url").toString("utf8"));
    raw.mandate.taskConstraints.roomId = 42;
    const bad = Buffer.from(JSON.stringify(raw)).toString("base64url");
    const v = await verifyTaskMandate(bad, host.pub);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/roomId/);
  });
});

describe("conversation-v1 vector: task mandate v2 with onBehalfOf / roomId", () => {
  const V = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec-public/vectors/conversation-v1.json", import.meta.url)), "utf8"));
  const tm = V.taskMandateV2;

  it("reproduces the signing payload and verifies the token with the host's key", async () => {
    expect(taskMandateSigningPayloadV2(tm.mandate)).toBe(tm.expectedSigningPayload);
    const hostPub = Uint8Array.from(Buffer.from(V.keys.host.publicKeyHex, "hex"));
    const v = await verifyTaskMandate(tm.token, hostPub, V.keys.agent.did, { now: Date.parse(tm.mandate.issuedAt) + 1000 });
    expect(v.valid).toBe(true);
  });

  it("reaches the vector's verdict for every request", () => {
    for (const { request, allowed, code } of tm.requests) {
      const violation = checkTaskConstraints(tm.mandate, request);
      expect(violation === null).toBe(allowed);
      if (!allowed) expect(violation?.code).toBe(code);
    }
  });
});

describe("spending mandate actingFor", () => {
  it("absent actingFor leaves the signed payload unchanged (no key at all)", async () => {
    const h = await party();
    const a = await party();
    const m = await issueIntentMandate(h.did, a.did, { spendLimitUsd: 10 }, h.priv);
    expect("actingFor" in m.mandate).toBe(false);
    expect(mandateSigningPayloadV2(m.mandate)).not.toContain("actingFor");
  });

  it("is signed, inherited by children, and enforced on every link", async () => {
    const h = await party();
    const a = await party();
    const p = await party();
    const intent = await issueIntentMandate(h.did, a.did, { spendLimitUsd: 100 }, h.priv, undefined, { actingFor: "payer" });
    expect(intent.mandate.actingFor).toBe("payer");
    expect(mandateSigningPayloadV2(intent.mandate)).toBe(canonicalizeJcs({ mandate: intent.mandate, v: 2 }));
    const cart = await attenuateToCart(intent, p.did, { spendLimitUsd: 50 }, a.priv);
    expect(cart.mandate.actingFor).toBe("payer");
    expect((await verifyMandateChain(cart.token)).valid).toBe(true);

    // A hand-built child that flips (or drops) the side is refused by the verifier.
    for (const actingFor of ["payee", undefined] as const) {
      const body: ArohaSpendingMandateBody = {
        ...cart.mandate, mandateId: crypto.randomUUID(),
        ...(actingFor ? { actingFor } : {}),
      };
      if (!actingFor) delete (body as { actingFor?: string }).actingFor;
      const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(body)), a.priv);
      const leaf: MandateChainLink = { v: 2, mandate: body, signature: Buffer.from(sig).toString("base64url") };
      const chain: MandateChainLink[] = [{ v: 2, mandate: intent.mandate, signature: intent.signature }];
      const token = Buffer.from(JSON.stringify({ v: 2, mandate: leaf.mandate, signature: leaf.signature, chain })).toString("base64url");
      const r = await verifyMandateChain(token);
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/actingFor/);
    }
  });

  it("refuses an invalid actingFor value", async () => {
    const h = await party();
    await expect(issueIntentMandate(h.did, "did:aroha:x", { spendLimitUsd: 1 }, h.priv, undefined, { actingFor: "both" as never }))
      .rejects.toThrow(/actingFor/);
  });
});
