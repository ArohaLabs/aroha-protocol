// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { issueTaskMandate, attenuateTaskMandate } from "@aroha-sdk/credentials";
import {
  verifyTaskMandateChain, parseTaskMandateToken, extractEnvelope,
  staticResolver, DELEGATION_CONTEXT_KEY,
} from "./chain.js";

// Identities: root (A/human) → B → C
const A = { did: "did:aroha:test:root" };
const B = { did: "did:aroha:test:orchestrator" };
const C = { did: "did:aroha:test:worker" };

let aKey: Uint8Array, bKey: Uint8Array, cKey: Uint8Array;
let aPub: Uint8Array, bPub: Uint8Array;

beforeAll(async () => {
  aKey = ed.utils.randomPrivateKey();
  bKey = ed.utils.randomPrivateKey();
  cKey = ed.utils.randomPrivateKey();
  aPub = await ed.getPublicKeyAsync(aKey);
  bPub = await ed.getPublicKeyAsync(bKey);
});

async function makeRoot(opts?: { depth?: number; allowed?: string[]; blocked?: string[]; ttlMs?: number }) {
  return issueTaskMandate(
    A.did, B.did,
    opts?.allowed ?? ["research", "summarise", "web-search"],
    { maxDelegationDepth: opts?.depth, actionLimits: { "web-search": 10 } },
    aKey,
    opts?.ttlMs ?? 3_600_000,
    { blocked: opts?.blocked }
  );
}

describe("verifyTaskMandateChain — single link", () => {
  it("accepts a valid root mandate", async () => {
    const root = await makeRoot();
    const r = await verifyTaskMandateChain([root.token], aPub, { expectedGrantee: B.did });
    expect(r.valid).toBe(true);
    expect(r.depth).toBe(1);
    expect(r.mandate?.grantee).toBe(B.did);
  });

  it("rejects the wrong root key", async () => {
    const root = await makeRoot();
    const r = await verifyTaskMandateChain([root.token], bPub);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Invalid signature");
  });

  it("rejects a grantee mismatch", async () => {
    const root = await makeRoot();
    const r = await verifyTaskMandateChain([root.token], aPub, { expectedGrantee: C.did });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("does not match expected");
  });

  it("rejects an expired mandate", async () => {
    const root = await makeRoot({ ttlMs: -1000 });
    const r = await verifyTaskMandateChain([root.token], aPub);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("expired");
  });

  it("rejects a tampered token", async () => {
    const root = await makeRoot();
    const parsed = parseTaskMandateToken(root.token)!;
    parsed.mandate.allowed.push("delete-everything");
    const forged = Buffer.from(JSON.stringify({ mandate: parsed.mandate, signature: parsed.signature })).toString("base64url");
    const r = await verifyTaskMandateChain([forged], aPub);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Invalid signature");
  });

  it("rejects an empty chain and garbage tokens", async () => {
    expect((await verifyTaskMandateChain([], aPub)).valid).toBe(false);
    expect((await verifyTaskMandateChain(["not-a-token"], aPub)).valid).toBe(false);
  });
});

describe("verifyTaskMandateChain — multi-hop custody", () => {
  it("accepts a valid A→B→C chain", async () => {
    const root = await makeRoot({ depth: 2 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], { maxDelegationDepth: 1 }, bKey);
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      expectedGrantee: C.did,
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(true);
    expect(r.depth).toBe(2);
    expect(r.mandate?.allowed).toEqual(["research"]);
  });

  it("rejects a chain without a resolver for intermediate signers", async () => {
    const root = await makeRoot({ depth: 2 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], { maxDelegationDepth: 1 }, bKey);
    const r = await verifyTaskMandateChain([root.token, child.token], aPub);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("resolvePublicKey");
  });

  it("rejects a child signed by the wrong key (impersonated hop)", async () => {
    const root = await makeRoot({ depth: 2 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], { maxDelegationDepth: 1 }, cKey); // C forges B's grant
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Invalid signature");
  });

  it("rejects broken grantor→grantee custody", async () => {
    const root = await makeRoot({ depth: 2 });
    // A second root granted to C directly, then spliced after the B root: grantor(C-link) !== grantee(B-link)
    const stray = await issueTaskMandate(C.did, C.did, ["research"], { maxDelegationDepth: 1 }, cKey, 60_000, {
      parentMandateId: parseTaskMandateToken(root.token)!.mandate.mandateId,
    });
    const r = await verifyTaskMandateChain([root.token, stray.token], aPub, {
      resolvePublicKey: staticResolver({ [C.did]: await ed.getPublicKeyAsync(cKey) }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Broken custody");
  });

  it("rejects a scope widened mid-chain", async () => {
    const root = await makeRoot({ depth: 2, allowed: ["research"] });
    // Forge a child that grants a capability the parent never had
    const forgedChild = await issueTaskMandate(B.did, C.did, ["research", "send-email"], { maxDelegationDepth: 1 }, bKey, 60_000, {
      parentMandateId: parseTaskMandateToken(root.token)!.mandate.mandateId,
    });
    const r = await verifyTaskMandateChain([root.token, forgedChild.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Scope widened");
  });

  it("rejects a dropped blocked capability", async () => {
    const root = await makeRoot({ depth: 2, blocked: ["send-email"] });
    const child = await issueTaskMandate(B.did, C.did, ["research"], { maxDelegationDepth: 1 }, bKey, 60_000, {
      parentMandateId: parseTaskMandateToken(root.token)!.mandate.mandateId,
      // blocked list NOT carried forward
    });
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain('blocked capability "send-email"');
  });
});

describe("verifyTaskMandateChain — delegation depth", () => {
  it("rejects any child under maxDelegationDepth=0", async () => {
    const root = await makeRoot({ depth: 0 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], {}, bKey);
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("forbids sub-delegation");
  });

  it("rejects a child that fails to decrement depth", async () => {
    const root = await makeRoot({ depth: 2 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], { maxDelegationDepth: 2 }, bKey); // must be ≤ 1
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("maxDelegationDepth ≤ 1");
  });

  it("rejects a child that omits depth when the parent bounds it", async () => {
    const root = await makeRoot({ depth: 2 });
    const child = await attenuateTaskMandate(root, C.did, ["research"], {}, bKey);
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("maxDelegationDepth");
  });

  it("allows unlimited chains when the root sets no depth", async () => {
    const root = await makeRoot(); // depth undefined
    const child = await attenuateTaskMandate(root, C.did, ["research"], {}, bKey);
    const r = await verifyTaskMandateChain([root.token, child.token], aPub, {
      resolvePublicKey: staticResolver({ [B.did]: bPub }),
    });
    expect(r.valid).toBe(true);
  });
});

describe("extractEnvelope", () => {
  it("round-trips a valid envelope", () => {
    const env = { v: 1 as const, chain: ["tok"], rootKeyB64: "abc", correlationId: "c1" };
    expect(extractEnvelope({ [DELEGATION_CONTEXT_KEY]: env })).toEqual(env);
  });

  it("returns null for missing/malformed envelopes", () => {
    expect(extractEnvelope(undefined)).toBeNull();
    expect(extractEnvelope({})).toBeNull();
    expect(extractEnvelope({ [DELEGATION_CONTEXT_KEY]: { v: 2, chain: ["t"], rootKeyB64: "k", correlationId: "c" } })).toBeNull();
    expect(extractEnvelope({ [DELEGATION_CONTEXT_KEY]: { v: 1, chain: [], rootKeyB64: "k", correlationId: "c" } })).toBeNull();
  });
});
