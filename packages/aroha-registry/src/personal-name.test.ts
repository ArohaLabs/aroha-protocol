// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  derivePersonalLabel,
  isPersonalLabelFormat,
  verifyPersonalLabel,
  derivePersonalLabelForDid,
  derivePersonalLabelFromInception,
  verifyPersonalLabelForDid,
} from "./personal-name.js";
import { incept, rotateKel, recoverAgent, generateKelKeyMaterial, generateDid, inceptionDigestFromDid } from "@aroha-sdk/core";
import { WORDLIST, WORDLIST_SHA256 } from "./wordlist.js";
import { createHash } from "node:crypto";

function key(seed: number): Uint8Array {
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k[i] = (seed * 31 + i * 17) & 0xff;
  return k;
}

describe("wordlist", () => {
  it("has exactly 2048 unique lowercase-ASCII words", () => {
    expect(WORDLIST.length).toBe(2048);
    expect(new Set(WORDLIST).size).toBe(2048);
    for (const w of WORDLIST) expect(w).toMatch(/^[a-z]+$/);
  });

  it("matches the recorded provenance hash of the canonical source", () => {
    const raw = WORDLIST.join("\n") + "\n";
    expect(createHash("sha256").update(raw).digest("hex")).toBe(WORDLIST_SHA256);
  });
});

describe("derivePersonalLabel", () => {
  it("is deterministic", () => {
    const k = key(1);
    expect(derivePersonalLabel(k)).toBe(derivePersonalLabel(k));
  });

  it("produces exactly 6 hyphen-separated wordlist tokens", () => {
    const label = derivePersonalLabel(key(2));
    const tokens = label.split("-");
    expect(tokens).toHaveLength(6);
    for (const t of tokens) expect(WORDLIST).toContain(t);
  });

  it("produces different labels for different keys", () => {
    const labels = new Set<string>();
    for (let i = 0; i < 25; i++) labels.add(derivePersonalLabel(key(i)));
    expect(labels.size).toBe(25);
  });

  it("is sensitive to every bit of the key (flip one bit -> different label)", () => {
    const a = key(3);
    const b = a.slice();
    b[0] ^= 1;
    expect(derivePersonalLabel(a)).not.toBe(derivePersonalLabel(b));
  });
});

describe("isPersonalLabelFormat", () => {
  it("accepts a genuine derived label", () => {
    expect(isPersonalLabelFormat(derivePersonalLabel(key(4)))).toBe(true);
  });

  it("rejects wrong token counts", () => {
    expect(isPersonalLabelFormat("otter-brass-canyon-vivid-ledger")).toBe(false); // 5
    expect(isPersonalLabelFormat("otter-brass-canyon-vivid-ledger-amber-extra")).toBe(false); // 7
  });

  it("rejects a token not in the wordlist", () => {
    expect(isPersonalLabelFormat("otter-brass-canyon-vivid-ledger-paypal")).toBe(false);
  });

  it("rejects a firm-style name", () => {
    expect(isPersonalLabelFormat("research")).toBe(false);
    expect(isPersonalLabelFormat("research-acme")).toBe(false);
  });

  it("rejects uppercase or malformed tokens", () => {
    expect(isPersonalLabelFormat("Otter-brass-canyon-vivid-ledger-amber")).toBe(false);
    expect(isPersonalLabelFormat("otter--brass-canyon-vivid-ledger-amber")).toBe(false);
  });
});

describe("verifyPersonalLabel", () => {
  it("accepts the correct key for a label", () => {
    const k = key(5);
    const label = derivePersonalLabel(k);
    expect(verifyPersonalLabel(label, k)).toBe(true);
  });

  it("rejects a mismatched key", () => {
    const label = derivePersonalLabel(key(6));
    expect(verifyPersonalLabel(label, key(7))).toBe(false);
  });

  it("rejects a malformed label outright, without attempting derivation", () => {
    expect(verifyPersonalLabel("not-a-real-label", key(8))).toBe(false);
  });

  it("known-vector regression: a fixed key derives a fixed label", () => {
    // Pins the exact wordlist + KDF params together — any future change to
    // any of (salt, N/r/p, dkLen, wordlist) must consciously update this.
    const k = new Uint8Array(32).fill(7);
    expect(derivePersonalLabel(k)).toBe("broccoli-hotel-manual-position-crew-word");
  });
});

describe("personal labels for rotatable E-DIDs", () => {
  it("derives from the inception digest and survives rotation and recovery", async () => {
    const person = await incept({ kind: "person" });
    const agent = await incept({ kind: "agent", controller: person.did });
    const label = derivePersonalLabelForDid(agent.did)!;
    expect(isPersonalLabelFormat(label)).toBe(true);
    expect(label).toBe(derivePersonalLabelFromInception(inceptionDigestFromDid(agent.did)!));

    // Rotate, then lose the device and recover: the DID — and so the name —
    // is the same throughout, while the key changed twice.
    const rotated = await rotateKel(agent);
    const recovered = await recoverAgent(person, rotated.kel, await generateKelKeyMaterial());
    expect(rotated.did).toBe(agent.did);
    expect(recovered.agentKel[0]).toEqual(agent.kel[0]);
    expect(derivePersonalLabelForDid(rotated.did)).toBe(label);
    expect(verifyPersonalLabelForDid(label, agent.did)).toBe(true);

    // It is not the label of the (current or original) key.
    expect(label).not.toBe(derivePersonalLabel(agent.publicKey));
    expect(label).not.toBe(derivePersonalLabel(rotated.publicKey));
  });

  it("keeps the z-DID derivation unchanged and rejects named DIDs", async () => {
    const k = new Uint8Array(32).fill(7);
    const zDid = generateDid(k);
    expect(derivePersonalLabelForDid(zDid)).toBe("broccoli-hotel-manual-position-crew-word");
    expect(verifyPersonalLabelForDid("broccoli-hotel-manual-position-crew-word", zDid)).toBe(true);
    expect(derivePersonalLabelForDid("did:aroha:named-agent")).toBeNull();
    expect(verifyPersonalLabelForDid("broccoli-hotel-manual-position-crew-word", "did:aroha:named-agent")).toBe(false);
  });

  it("does not verify one identity's label against another", async () => {
    const a = await incept({ kind: "agent" });
    const b = await incept({ kind: "agent" });
    expect(verifyPersonalLabelForDid(derivePersonalLabelForDid(a.did)!, b.did)).toBe(false);
  });
});
