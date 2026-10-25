// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Task-mandate v2: purpose-tagged JCS signatures, v1 tokens still
 * verifiable, revocation keyed by (mandateId, grantor) and fail-closed, and
 * enforceTaskConstraints / checkTaskConstraints actually checking dataAccess.
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  issueTaskMandate,
  attenuateTaskMandate,
  verifyTaskMandate,
  verifyTaskMandateSignature,
  taskMandateSigningPayloadV2,
  enforceTaskConstraints,
  checkTaskConstraints,
  TASK_MANDATE_PURPOSE,
  TaskConstraintViolation,
} from "./mandate.js";
import { canonicalizeJcs } from "./jcs.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let priv: Uint8Array;
let pub: Uint8Array;
beforeAll(async () => {
  priv = ed.utils.randomPrivateKey();
  pub = await ed.getPublicKeyAsync(priv);
});

const decode = (token: string) => JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as Record<string, unknown>;

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.fromEntries(Object.keys(obj as object).sort().map((k) => [k, sortKeys((obj as Record<string, unknown>)[k])]));
  }
  return obj;
}

describe("task-mandate v2 token format", () => {
  it("issues v2 tokens whose signature covers the purpose-tagged JCS payload", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv);
    expect(t.v).toBe(2);
    expect(decode(t.token).v).toBe(2);
    expect(TASK_MANDATE_PURPOSE).toBe("aroha.task-mandate/v2");
    expect(taskMandateSigningPayloadV2(t.mandate)).toBe(
      canonicalizeJcs({ mandate: t.mandate, purpose: "aroha.task-mandate/v2", v: 2 })
    );
    const ok = await ed.verifyAsync(
      Buffer.from(t.signature, "base64url"),
      new TextEncoder().encode(taskMandateSigningPayloadV2(t.mandate)),
      pub
    );
    expect(ok).toBe(true);
    expect((await verifyTaskMandate(t.token, pub)).valid).toBe(true);
  });

  it("a v2 signature does not verify as v1, and vice versa (no cross-version replay)", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv);
    const stripped = Buffer.from(JSON.stringify({ mandate: t.mandate, signature: t.signature })).toString("base64url");
    expect((await verifyTaskMandate(stripped, pub)).reason).toBe("Invalid signature");

    const v1sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(t.mandate))), priv);
    const v1 = Buffer.from(JSON.stringify({ mandate: t.mandate, signature: Buffer.from(v1sig).toString("base64url") })).toString("base64url");
    expect((await verifyTaskMandate(v1, pub)).valid).toBe(true); // legacy tokens keep working
    const promoted = Buffer.from(JSON.stringify({ v: 2, mandate: t.mandate, signature: Buffer.from(v1sig).toString("base64url") })).toString("base64url");
    expect((await verifyTaskMandate(promoted, pub)).reason).toBe("Invalid signature");
  });

  it("refuses an unknown token version", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv);
    const v3 = Buffer.from(JSON.stringify({ ...decode(t.token), v: 3 })).toString("base64url");
    expect((await verifyTaskMandate(v3, pub)).reason).toMatch(/Unsupported task mandate token version/);
  });

  it("attenuated children are v2 and verifyTaskMandateSignature reads the version", async () => {
    const root = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search", "read"], {}, priv);
    const childKey = ed.utils.randomPrivateKey();
    const child = await attenuateTaskMandate(root, "did:aroha:sub", ["search"], {}, priv);
    expect(child.v).toBe(2);
    expect(await verifyTaskMandateSignature(child, pub)).toBe(true);
    expect(await verifyTaskMandateSignature({ ...child, v: 1 }, pub)).toBe(false);
    expect(await verifyTaskMandateSignature(child, await ed.getPublicKeyAsync(childKey))).toBe(false);
  });
});

describe("task-mandate revocation", () => {
  it("is keyed by (mandateId, grantor) and refuses a revoked mandate", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv);
    const seen: Array<[string, string]> = [];
    const r = await verifyTaskMandate(t.token, pub, undefined, {
      isRevoked: async (id, grantor) => { seen.push([id, grantor]); return true; },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/has been revoked/);
    expect(seen).toEqual([[t.mandate.mandateId, "did:aroha:alice"]]);
  });

  it("fails closed when the revocation hook throws", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["search"], {}, priv);
    const r = await verifyTaskMandate(t.token, pub, undefined, { isRevoked: async () => { throw new Error("down"); } });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Revocation check failed/);
    await expect(enforceTaskConstraints(t.token, pub, {
      requestedCapability: "search",
      isRevoked: async () => { throw new Error("down"); },
    })).rejects.toMatchObject({ code: "MANDATE_INVALID" });
  });
});

describe("enforceTaskConstraints — dataAccess is enforced", () => {
  it("allows access within the grant and rejects over-scope access", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["query"], {
      dataAccess: { calendar: "read", drafts: "write" },
    }, priv);

    await expect(enforceTaskConstraints(t.token, pub, { requestedCapability: "query", dataAccess: { calendar: "read" } }))
      .resolves.toBeTruthy();
    await expect(enforceTaskConstraints(t.token, pub, { requestedCapability: "query", dataAccess: { drafts: "write" } }))
      .resolves.toBeTruthy();

    for (const dataAccess of [
      { calendar: "write" as const },       // more rights than granted
      { calendar: "read-write" as const },
      { drafts: "read" as const },          // write-only grant never admits a read
      { "customer-db": "read" as const },   // resource not in the map = "none"
    ]) {
      await expect(enforceTaskConstraints(t.token, pub, { requestedCapability: "query", dataAccess }))
        .rejects.toMatchObject({ code: "DATA_ACCESS_VIOLATION" });
    }
  });

  it("a mandate with no dataAccess map imposes no data-access limit (documented semantics)", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["query"], {}, priv);
    expect(checkTaskConstraints(t.mandate, { requestedCapability: "query", dataAccess: { anything: "read-write" } })).toBeNull();
  });

  it("an unknown requested access level fails closed", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["query"], { dataAccess: { calendar: "read-write" } }, priv);
    const v = checkTaskConstraints(t.mandate, { requestedCapability: "query", dataAccess: { calendar: "admin" as never } });
    expect(v).toBeInstanceOf(TaskConstraintViolation);
    expect(v?.code).toBe("DATA_ACCESS_VIOLATION");
  });

  it("humanGates pass only with humanApproved: true", async () => {
    const t = await issueTaskMandate("did:aroha:alice", "did:aroha:bot", ["send"], { humanGates: ["send"] }, priv);
    expect(checkTaskConstraints(t.mandate, { requestedCapability: "send" })?.code).toBe("HUMAN_GATE_REQUIRED");
    expect(checkTaskConstraints(t.mandate, { requestedCapability: "send", humanApproved: true })).toBeNull();
  });
});
