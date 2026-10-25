// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Correctness and soundness of the Chaum-Pedersen nullifier scheme. This is
// the actual security boundary of the Sybil-resistance fix — a mistake here
// is a mistake in the thing that's supposed to make identity expensive again.

import { describe, it, expect } from "vitest";
import {
  generateCredentialSecret, scopePoint, proveUniqueness, verifyUniquenessProof,
  type NullifierProof,
} from "./nullifier.js";

describe("completeness — a correctly generated proof always verifies", () => {
  it("verifies a fresh proof", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    expect(verifyUniquenessProof(proof)).toEqual({ ok: true });
  });

  it("verifies across many independent credentials and scopes", () => {
    for (const scope of ["verified-caller", "epoch:2026-08", "arbitrary-scope-string"]) {
      const cred = generateCredentialSecret();
      const proof = proveUniqueness(cred.secret, scope);
      expect(verifyUniquenessProof(proof).ok).toBe(true);
    }
  });

  it("the credential's commitment matches what the proof reports", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    expect(Buffer.from(proof.commitment).equals(Buffer.from(cred.commitment))).toBe(true);
  });
});

describe("soundness — a proof cannot be forged without the secret", () => {
  it("rejects a proof claiming someone else's commitment", () => {
    const victim = generateCredentialSecret();
    const attacker = generateCredentialSecret();

    const forged = proveUniqueness(attacker.secret, "verified-caller");
    forged.commitment = victim.commitment; // attacker doesn't know victim's secret

    const result = verifyUniquenessProof(forged);
    expect(result.ok).toBe(false);
  });

  it("rejects a nullifier that wasn't derived from the proven secret", () => {
    const a = generateCredentialSecret();
    const b = generateCredentialSecret();

    const proofA = proveUniqueness(a.secret, "verified-caller");
    const proofB = proveUniqueness(b.secret, "verified-caller");

    // Splice B's nullifier onto A's otherwise-valid proof.
    const spliced: NullifierProof = { ...proofA, nullifier: proofB.nullifier };
    expect(verifyUniquenessProof(spliced).ok).toBe(false);
  });

  it("rejects a proof replayed against a different scope than it was made for", () => {
    // The verifier recomputes H from proof.scope — swapping the scope string
    // must invalidate the transcript rather than silently reverify.
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    const replayed: NullifierProof = { ...proof, scope: "other-scope" };
    expect(verifyUniquenessProof(replayed).ok).toBe(false);
  });

  it("rejects a tampered response scalar z", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    const tampered = { ...proof, z: new Uint8Array(proof.z).fill(0) };
    expect(verifyUniquenessProof(tampered).ok).toBe(false);
  });

  it("rejects a tampered commitment R1", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    const other = generateCredentialSecret();
    const tampered = { ...proof, r1: other.commitment };
    expect(verifyUniquenessProof(tampered).ok).toBe(false);
  });

  it("rejects malformed / non-curve-point byte strings without throwing", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    const garbage = { ...proof, commitment: new Uint8Array(32).fill(0xff) };
    expect(() => verifyUniquenessProof(garbage)).not.toThrow();
    expect(verifyUniquenessProof(garbage).ok).toBe(false);
  });
});

describe("zero-knowledge — the proof does not leak the secret", () => {
  it("the proof transcript never contains the raw secret bytes", () => {
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    const secretHex = Buffer.from(cred.secret).toString("hex");

    const transcript = JSON.stringify(proof, (_, v) =>
      v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v);

    expect(transcript.includes(secretHex)).toBe(false);
  });

  it("verification never requires or accepts the secret as input", () => {
    // Type-level guarantee mirrored at runtime: verifyUniquenessProof's
    // signature takes only the public transcript.
    const cred = generateCredentialSecret();
    const proof = proveUniqueness(cred.secret, "verified-caller");
    expect(verifyUniquenessProof.length).toBe(1); // arity: (proof) only
    expect(verifyUniquenessProof(proof).ok).toBe(true);
  });
});

describe("nullifier determinism and scope-unlinkability", () => {
  it("the same secret + scope always produces the same nullifier — the actual dedup key", () => {
    const cred = generateCredentialSecret();
    const p1 = proveUniqueness(cred.secret, "verified-caller");
    const p2 = proveUniqueness(cred.secret, "verified-caller");
    expect(Buffer.from(p1.nullifier).equals(Buffer.from(p2.nullifier))).toBe(true);
  });

  it("the same secret produces different nullifiers in different scopes", () => {
    const cred = generateCredentialSecret();
    const p1 = proveUniqueness(cred.secret, "verified-caller");
    const p2 = proveUniqueness(cred.secret, "epoch:2026-08");
    expect(Buffer.from(p1.nullifier).equals(Buffer.from(p2.nullifier))).toBe(false);
  });

  it("different secrets produce different nullifiers in the same scope (no collisions in practice)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const cred = generateCredentialSecret();
      const proof = proveUniqueness(cred.secret, "verified-caller");
      const key = Buffer.from(proof.nullifier).toString("hex");
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });

  it("scopePoint is deterministic and public — anyone can recompute it independently", () => {
    expect(Buffer.from(scopePoint("verified-caller")).equals(Buffer.from(scopePoint("verified-caller")))).toBe(true);
    expect(Buffer.from(scopePoint("a")).equals(Buffer.from(scopePoint("b")))).toBe(false);
  });
});
