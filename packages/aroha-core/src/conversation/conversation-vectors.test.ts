// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Consumes spec-public/vectors/conversation-v1.json — the same file the
 * Python verifiers read — so both implementations are held to one set of
 * bytes and verdicts.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { NonceRegistry } from "../messages/nonce.js";
import { validateEnvelope, type ArohaEnvelope } from "../messages/envelope.js";
import { validateDisclosure } from "../messages/disclosure.js";
import { fromMultibase } from "../identity/did.js";
import type { KelEvent } from "../identity/kel.js";
import {
  consentEventSigningBytes, conversationSigningBytes, effectiveConsent, kelConversationResolver, turnSigningBytes,
  verifyConsent, verifyRoom, verifyTurn, type ConversationKeyResolver, type RoomRecord,
} from "./index.js";
import {
  actionReceiptSigningBytes, parseActionReceipt, verifyActionReceipt, verifyPresentedHash, type ArohaActionReceipt,
} from "../receipts/index.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../../../../spec-public/vectors/conversation-v1.json", import.meta.url)), "utf8"));
const text = (b: Uint8Array) => new TextDecoder().decode(b);

const kelResolve = kelConversationResolver(async (did) => (V.kels[did] as KelEvent[] | undefined) ?? null);
/** Persons from their KEL; the z-form agent from its DID (kind agent by the resolution rule). */
const resolve: ConversationKeyResolver = async (did) => {
  if (did.startsWith("did:aroha:z")) return { publicKey: fromMultibase(did.slice("did:aroha:".length)), kind: "agent" };
  return kelResolve(did);
};
const receiptKey = (did: string) => (did.startsWith("did:aroha:z") ? fromMultibase(did.slice("did:aroha:".length)) : null);

describe("conversation-v1 vectors", () => {
  it("disclosure is valid", () => {
    expect(validateDisclosure(V.disclosure.value).valid).toBe(true);
  });

  it("room: signing payload, valid signature, invalid variants refused", async () => {
    expect(text(conversationSigningBytes(V.room.value))).toBe(V.room.expectedSigningPayload);
    const ok = await verifyRoom(V.room.value, resolve);
    expect(ok.ok).toBe(true);
    for (const bad of V.room.invalid) expect((await verifyRoom(bad.value, resolve)).ok, bad.name).toBe(false);
  });

  it("consent: given and withdrawn versions verify; effective purposes match", async () => {
    const room = V.room.value as RoomRecord;
    for (const k of ["given", "withdrawn"] as const) {
      const c = V.consent[k];
      c.value.events.forEach((_e: unknown, i: number) => {
        expect(text(consentEventSigningBytes(c.value, i))).toBe(c.expectedEventSigningPayloads[i]);
      });
      expect((await verifyConsent(c.value, resolve, { room })).ok).toBe(true);
      expect([...effectiveConsent(c.value)].sort()).toEqual(c.effectivePurposes);
    }
    // A non-subject event needs the room record to check membership.
    expect((await verifyConsent(V.consent.withdrawn.value, resolve)).ok).toBe(false);
    for (const bad of V.consent.invalid) expect((await verifyConsent(bad.value, resolve, { room })).ok, bad.name).toBe(false);
  });

  it("turn: content hash, signing payload, speaker kind from the KEL", async () => {
    const room = V.room.value as RoomRecord;
    expect(text(turnSigningBytes(V.turn.value))).toBe(V.turn.expectedSigningPayload);
    const r = await verifyTurn(V.turn.value, resolve, { room });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.signer.kind).toBe(V.turn.expectedSpeakerKind);
    for (const bad of V.turn.invalid) expect((await verifyTurn(bad.value, resolve, { room })).ok, bad.name).toBe(false);
  });

  it("receipts v1, v2 executed and v2 denied verify; invalid ones are refused", async () => {
    for (const k of ["v1", "v2Executed", "v2Denied"] as const) {
      const r = V.receipts[k];
      expect(text(actionReceiptSigningBytes(r.value))).toBe(r.expectedSigningPayload);
      expect((await verifyActionReceipt(r.value, receiptKey)).ok, k).toBe(true);
    }
    const v2 = V.receipts.v2Executed;
    expect(verifyPresentedHash(v2.value as ArohaActionReceipt, v2.presentedContent)).toBeNull();
    expect(verifyPresentedHash(v2.value as ArohaActionReceipt, v2.mismatchedPresentedContent)).toMatch(/differs/);
    for (const bad of V.receipts.invalid) {
      const parsed = parseActionReceipt(bad.value);
      const verified = await verifyActionReceipt(bad.value, receiptKey);
      expect(parsed === null || !verified.ok, bad.name).toBe(true);
    }
  });

  it("disclosure-bearing envelope verifies under the envelope signature rule", async () => {
    const env = V.envelopeWithDisclosure.value as ArohaEnvelope;
    const key = fromMultibase(env.from.slice("did:aroha:".length));
    const now = Date.parse(env.created) + 1000;
    const realNow = Date.now;
    Date.now = () => now;
    try {
      expect(await validateEnvelope(env, key, env.to, new NonceRegistry())).toEqual({ valid: true });
    } finally {
      Date.now = realNow;
    }
  });
});
