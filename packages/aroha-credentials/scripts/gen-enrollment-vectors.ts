// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/enrollment-v1.json.
 *
 *   npx tsx scripts/gen-enrollment-vectors.ts
 *
 * The cross-SDK contract for completeEnrollment / complete_enrollment and
 * signEnrollment / sign_enrollment:
 *
 *   - `signatures`: the exact JCS signing payload and the (deterministic
 *     Ed25519) proof for given inputs — an implementation's signEnrollment
 *     must produce the same bytes.
 *   - `cases`: each starts with an EMPTY store and runs its steps in order.
 *     A step is one of
 *       { seed: { challenge, accountId, expiresAt } }   put a challenge in the store
 *       { complete: {...}, expected }                   completeEnrollment with the top-level
 *                                                       audience and now unless the step gives them
 *       { enrolled: accountId, expected }               enrolledDid → the DID, or null for none
 *     and passes when every step reaches the same verdict, code and status
 *     (and, on success, the same did and replaced).
 *
 * Seeding the store directly (instead of issueEnrollmentChallenge, whose
 * challenges are random) keeps the file deterministic. Keys are RFC 8032
 * §7.1 test keys, so regenerating produces an identical file.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import {
  ENROLLMENT_PURPOSE,
  InMemoryEnrollmentStore,
  completeEnrollment,
  enrolledDid,
  enrollmentSigningPayload,
  signEnrollment,
  type EnrollmentResult,
} from "../src/enrollment.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

// RFC 8032 §7.1 TEST 1, 2 and 3 secret keys — public, well known, test-only.
const KEY_SEEDS = {
  alice: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  mallory: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  aliceNewKey: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
} as const;
type KeyName = keyof typeof KEY_SEEDS;

const AUDIENCE = "https://invoices.example.com";
const OTHER_AUDIENCE = "https://other-service.example.com";
const NOW = "2026-06-01T12:00:00.000Z";
const IN_5_MIN = "2026-06-01T12:05:00.000Z";
const A = "acct-alice";
const B = "acct-bob";
const ch = (n: number) => `enrollment-vector-challenge-${String(n).padStart(4, "0")}`;

type Expect = { ok: true; did: string; replaced?: string } | { ok: false; code: string; status: number };
type Complete = { authenticatedAccountId: string; did: unknown; challenge: unknown; proof: unknown; audience?: string; now?: string };
type Step =
  | { seed: { challenge: string; accountId: string; expiresAt: string } }
  | { complete: Complete; intended: string }
  | { enrolled: string };

async function main() {
  const keys = {} as Record<KeyName, { priv: Uint8Array; pub: Uint8Array; did: string }>;
  for (const [name, seed] of Object.entries(KEY_SEEDS) as [KeyName, string][]) {
    const priv = fromHex(seed);
    const pub = await ed.getPublicKeyAsync(priv);
    keys[name] = { priv, pub, did: generateDid(pub) };
  }
  const alice = keys.alice.did;

  /** Sign with `signer` over the given fields, without signEnrollment's own-key check (for mismatched-key cases). */
  const rawProof = async (signer: KeyName, f: { audience?: string; accountId: string; did: string; challenge: string }) =>
    Buffer.from(await ed.signAsync(new TextEncoder().encode(enrollmentSigningPayload({ audience: AUDIENCE, ...f })), keys[signer].priv)).toString("base64url");
  const proof = (f: { audience?: string; accountId: string; did: string; challenge: string }, signer: KeyName = "alice") => rawProof(signer, f);
  const seed = (challenge: string, accountId = A, expiresAt = IN_5_MIN): Step => ({ seed: { challenge, accountId, expiresAt } });

  const cases: { name: string; description: string; steps: Step[] }[] = [
    {
      name: "enroll",
      description: "A challenge issued to the signed-in account, signed by the DID's key for this service, enrolls the DID.",
      steps: [
        { enrolled: A },
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "ok" },
        { enrolled: A },
        { enrolled: B },
      ],
    },
    {
      name: "challenge-for-another-account",
      description: "Bob, signed in as B, uses a challenge issued to A (with a valid proof naming B): refused, and the challenge is spent, so A cannot use it either.",
      steps: [
        seed(ch(1), A),
        { complete: { authenticatedAccountId: B, did: alice, challenge: ch(1), proof: await proof({ accountId: B, did: alice, challenge: ch(1) }) }, intended: "CHALLENGE_ACCOUNT_MISMATCH" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "CHALLENGE_UNKNOWN" },
        { enrolled: A },
        { enrolled: B },
      ],
    },
    {
      name: "replayed-challenge",
      description: "A challenge is single-use: the identical enrollment sent twice succeeds once.",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "ok" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "CHALLENGE_UNKNOWN" },
      ],
    },
    {
      name: "expired-challenge",
      description: "A challenge is refused at and after its expiry, and is spent by the attempt.",
      steps: [
        seed(ch(1), A, NOW),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "CHALLENGE_EXPIRED" },
        seed(ch(2)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(2), proof: await proof({ accountId: A, did: alice, challenge: ch(2) }), now: "2026-06-01T12:05:00.001Z" }, intended: "CHALLENGE_EXPIRED" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(2), proof: await proof({ accountId: A, did: alice, challenge: ch(2) }) }, intended: "CHALLENGE_UNKNOWN" },
        { enrolled: A },
      ],
    },
    {
      name: "unknown-and-malformed-challenge",
      description: "A challenge that was never issued is unknown; one that is not a 16-128 character base64url string is malformed.",
      steps: [
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(9), proof: await proof({ accountId: A, did: alice, challenge: ch(9) }) }, intended: "CHALLENGE_UNKNOWN" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: 42, proof: "x" }, intended: "MALFORMED" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: "short", proof: "x" }, intended: "MALFORMED" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: "has spaces and is long enough", proof: "x" }, intended: "MALFORMED" },
      ],
    },
    {
      name: "proof-by-a-different-key",
      description: "The proof is signed by Mallory's key, not the key of the DID being enrolled: refused (the key signature is not optional), and the challenge is spent.",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }, "mallory") }, intended: "BAD_PROOF" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "CHALLENGE_UNKNOWN" },
        { enrolled: A },
      ],
    },
    {
      name: "missing-or-garbage-proof",
      description: "No proof, an empty proof, a non-base64url proof, or a signature of the wrong length is refused.",
      steps: [
        seed(ch(1)), { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: null }, intended: "BAD_PROOF" },
        seed(ch(2)), { complete: { authenticatedAccountId: A, did: alice, challenge: ch(2), proof: "" }, intended: "BAD_PROOF" },
        seed(ch(3)), { complete: { authenticatedAccountId: A, did: alice, challenge: ch(3), proof: "not base64url!" }, intended: "BAD_PROOF" },
        seed(ch(4)), { complete: { authenticatedAccountId: A, did: alice, challenge: ch(4), proof: "AAAA" }, intended: "BAD_PROOF" },
        { enrolled: A },
      ],
    },
    {
      name: "wrong-audience",
      description: "A proof made for another service cannot be used at this one.",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ audience: OTHER_AUDIENCE, accountId: A, did: alice, challenge: ch(1) }) }, intended: "BAD_PROOF" },
        seed(ch(2)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(2), audience: OTHER_AUDIENCE, proof: await proof({ accountId: A, did: alice, challenge: ch(2) }) }, intended: "BAD_PROOF" },
      ],
    },
    {
      name: "proof-names-another-account-or-challenge",
      description: "The proof must name the signed-in account and the presented challenge.",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: B, did: alice, challenge: ch(1) }) }, intended: "BAD_PROOF" },
        seed(ch(2)), seed(ch(3)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(2), proof: await proof({ accountId: A, did: alice, challenge: ch(3) }) }, intended: "BAD_PROOF" },
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(3), proof: await proof({ accountId: A, did: alice, challenge: ch(3) }) }, intended: "ok" },
      ],
    },
    {
      name: "proof-for-another-did",
      description: "A proof by Alice's key naming Alice's DID cannot enroll Mallory's DID (and vice versa).",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: keys.mallory.did, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "BAD_PROOF" },
      ],
    },
    {
      name: "non-content-addressed-did",
      description: "Without a resolver or KEL source only content-addressed did:aroha:z… DIDs enroll: a named DID, a look-alike, another method, or a non-string is refused even with a signature by the key it claims.",
      steps: [
        seed(ch(1)), { complete: { authenticatedAccountId: A, did: "did:aroha:alice", challenge: ch(1), proof: await proof({ accountId: A, did: "did:aroha:alice", challenge: ch(1) }) }, intended: "BAD_DID" },
        seed(ch(2)), { complete: { authenticatedAccountId: A, did: "did:aroha:zoo", challenge: ch(2), proof: await proof({ accountId: A, did: "did:aroha:zoo", challenge: ch(2) }) }, intended: "BAD_DID" },
        seed(ch(3)), { complete: { authenticatedAccountId: A, did: "did:web:alice.example", challenge: ch(3), proof: await proof({ accountId: A, did: "did:web:alice.example", challenge: ch(3) }) }, intended: "BAD_DID" },
        seed(ch(4)), { complete: { authenticatedAccountId: A, did: `${alice}x`, challenge: ch(4), proof: await proof({ accountId: A, did: `${alice}x`, challenge: ch(4) }) }, intended: "BAD_DID" },
        seed(ch(5)), { complete: { authenticatedAccountId: A, did: 7, challenge: ch(5), proof: "x" }, intended: "BAD_DID" },
        { enrolled: A },
      ],
    },
    {
      name: "rotation",
      description: "A later enrollment for the same account replaces the DID and reports the one it replaced; re-enrolling the same DID replaces nothing.",
      steps: [
        seed(ch(1)),
        { complete: { authenticatedAccountId: A, did: alice, challenge: ch(1), proof: await proof({ accountId: A, did: alice, challenge: ch(1) }) }, intended: "ok" },
        seed(ch(2)),
        { complete: { authenticatedAccountId: A, did: keys.aliceNewKey.did, challenge: ch(2), proof: await proof({ accountId: A, did: keys.aliceNewKey.did, challenge: ch(2) }, "aliceNewKey") }, intended: "ok" },
        { enrolled: A },
        seed(ch(3)),
        { complete: { authenticatedAccountId: A, did: keys.aliceNewKey.did, challenge: ch(3), proof: await proof({ accountId: A, did: keys.aliceNewKey.did, challenge: ch(3) }, "aliceNewKey") }, intended: "ok" },
      ],
    },
  ];

  const out = [];
  for (const c of cases) {
    const store = new InMemoryEnrollmentStore();
    const steps = [];
    for (const s of c.steps) {
      if ("seed" in s) {
        store.putChallenge(s.seed.challenge, { accountId: s.seed.accountId, expiresAtMs: Date.parse(s.seed.expiresAt) }, Date.parse(NOW));
        steps.push(s);
      } else if ("enrolled" in s) {
        steps.push({ enrolled: s.enrolled, expected: (await enrolledDid(store, s.enrolled)) ?? null });
      } else {
        const { audience, now, ...rest } = s.complete;
        const r: EnrollmentResult = await completeEnrollment(store, {
          ...rest, audience: audience ?? AUDIENCE, now: Date.parse(now ?? NOW),
        });
        const got = r.ok ? "ok" : r.code;
        if (got !== s.intended) throw new Error(`${c.name}: intended ${s.intended}, got ${got}${r.ok ? "" : ` (${r.reason})`}`);
        const expected: Expect = r.ok
          ? { ok: true, did: r.did, ...(r.replaced !== undefined ? { replaced: r.replaced } : {}) }
          : { ok: false, code: r.code, status: r.status };
        steps.push({ complete: s.complete, expected });
      }
    }
    out.push({ name: c.name, description: c.description, steps });
  }

  // Byte-level pins for the signing payload and signEnrollment's output.
  const signatures = [];
  for (const [signer, f] of [
    ["alice", { audience: AUDIENCE, accountId: A, did: alice, challenge: ch(1) }],
    ["aliceNewKey", { audience: OTHER_AUDIENCE, accountId: "ünïcode-account ✓", did: keys.aliceNewKey.did, challenge: ch(2) }],
  ] as [KeyName, { audience: string; accountId: string; did: string; challenge: string }][]) {
    signatures.push({
      signer, input: f, payload: enrollmentSigningPayload(f),
      proof: await signEnrollment({ ...f, privateKey: keys[signer].priv }),
    });
  }

  const doc = {
    description:
      "Cross-SDK vectors for enrollment (account → DID binding). Generated by " +
      "packages/aroha-credentials/scripts/gen-enrollment-vectors.ts; do not edit by hand. " +
      "signatures: signEnrollment must produce `proof` (and the signing payload must equal `payload`). " +
      "cases: each starts with an empty store. {seed} puts a challenge in the store; {complete} calls " +
      "completeEnrollment with the top-level audience and now unless the step gives its own (the server's " +
      "authenticated account is authenticatedAccountId); {enrolled} calls enrolledDid (null = none).",
    purpose: ENROLLMENT_PURPOSE,
    audience: AUDIENCE,
    now: NOW,
    keys: Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, { privateKeyHex: hex(k.priv), publicKeyHex: hex(k.pub), did: k.did }])),
    signatures,
    cases: out,
  };
  const path = fileURLToPath(new URL("../test-vectors/enrollment-v1.json", import.meta.url));
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  console.log(`wrote ${path}: ${out.length} cases, ${out.reduce((n, c) => n + c.steps.length, 0)} steps`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
