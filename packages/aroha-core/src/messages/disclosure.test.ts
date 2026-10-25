// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, validateEnvelope, newCorrelationId } from "./envelope.js";
import { buildDisclosure, validateDisclosure } from "./disclosure.js";
import { NonceRegistry } from "./nonce.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function keys(id: string) {
  const priv = ed.utils.randomPrivateKey();
  return { did: `did:aroha:${id}`, priv, pub: await ed.getPublicKeyAsync(priv) };
}

describe("ArohaDisclosure", () => {
  it("builds a v1 disclosure with aiGenerated true and hop 0 by default", () => {
    const d = buildDisclosure({ agentDid: "did:aroha:agent", principalDid: "did:aroha:Eperson", principalKind: "person", purpose: "Booking travel" });
    expect(d).toEqual({ v: 1, agentDid: "did:aroha:agent", principalDid: "did:aroha:Eperson", principalKind: "person", purpose: "Booking travel", hop: 0, aiGenerated: true });
    expect(validateDisclosure(d).valid).toBe(true);
  });

  it("refuses malformed disclosures", () => {
    const d = buildDisclosure({ agentDid: "did:aroha:a", principalDid: "did:aroha:p", principalKind: "organization", purpose: "x", hop: 2 });
    expect(validateDisclosure({ ...d, aiGenerated: false }).valid).toBe(false);
    expect(validateDisclosure({ ...d, hop: -1 }).valid).toBe(false);
    expect(validateDisclosure({ ...d, hop: 1.5 }).valid).toBe(false);
    expect(validateDisclosure({ ...d, principalKind: "agent" }).valid).toBe(false);
    expect(validateDisclosure({ ...d, extra: 1 }).valid).toBe(false);
    expect(validateDisclosure({ ...d, v: 2 }).valid).toBe(false);
    expect(validateDisclosure({ ...d, principalDid: "bob" }).valid).toBe(false);
    expect(validateDisclosure(d, { expectedAgentDid: "did:aroha:other" }).valid).toBe(false);
    expect(() => buildDisclosure({ agentDid: "did:aroha:a", principalDid: "did:aroha:p", principalKind: "person", purpose: "" })).toThrow();
  });

  it("is covered by the envelope signature", async () => {
    const s = await keys("sender-disc");
    const me = "did:aroha:receiver";
    const disclosure = buildDisclosure({ agentDid: s.did, principalDid: "did:aroha:Eowner", principalKind: "person", purpose: "Answering on Ana's behalf" });
    const env = await buildEnvelope("ArohaRequest", s.did, me, { capability: "search", params: {} }, newCorrelationId(), s.priv, { disclosure });
    expect(env.disclosure).toEqual(disclosure);
    expect(await validateEnvelope(env, s.pub, me, new NonceRegistry())).toEqual({ valid: true });

    // Editing the disclosure after signing breaks the signature.
    const edited = { ...env, disclosure: { ...disclosure, principalDid: "did:aroha:Eother" } };
    const r1 = await validateEnvelope(edited, s.pub, me, new NonceRegistry());
    expect(r1.valid).toBe(false);
    // So does stripping it.
    const { disclosure: _d, ...stripped } = env;
    const r2 = await validateEnvelope(stripped, s.pub, me, new NonceRegistry());
    expect(r2).toEqual({ valid: false, reason: "Signature verification failed" });
  });

  it("validateEnvelope refuses a disclosure made in another agent's name", async () => {
    const s = await keys("sender-disc2");
    const me = "did:aroha:receiver";
    const disclosure = buildDisclosure({ agentDid: "did:aroha:someone-else", principalDid: "did:aroha:Eowner", principalKind: "person", purpose: "x" });
    const env = await buildEnvelope("ArohaRequest", s.did, me, { capability: "search", params: {} }, newCorrelationId(), s.priv, { disclosure });
    const r = await validateEnvelope(env, s.pub, me, new NonceRegistry());
    expect(r.valid).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/Invalid disclosure/);
  });
});
