// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Task-mandate v2 in the delegation layer:
 *   - verifyTaskMandateChain: revocation on every link (fail closed), KEL
 *     support for E-DID grantors, the default bounded depth, v1 links still
 *     accepted;
 *   - serving paths (serveDelegated, createDelegationMiddleware) enforce the
 *     leaf's constraints before the handler — the integration claim being
 *     "over-scope data access is rejected".
 */

import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { incept, revokeKelSelf, ArohaErrorCode, type KelEvent, type KelSource, type ArohaEnvelope, type TaskConstraints } from "@aroha-sdk/core";
import { issueTaskMandate, attenuateTaskMandate, type SignedTaskMandate } from "@aroha-sdk/credentials";
import type { ArohaAgent } from "@aroha-sdk/run";
import {
  verifyTaskMandateChain, staticResolver, DEFAULT_TASK_CHAIN_MAX_DEPTH, DELEGATION_CONTEXT_KEY,
  type DelegationEnvelope,
} from "./chain.js";
import { serveDelegated, publicKeyB64, DelegationError } from "./serve-delegated.js";
import { createDelegationMiddleware } from "./server-middleware.js";
import { issueDelegation, callDelegated } from "./client.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface Id { did: string; privateKey: Uint8Array; pub: Uint8Array }
const mk = async (did: string): Promise<Id> => {
  const privateKey = ed.utils.randomPrivateKey();
  return { did, privateKey, pub: await ed.getPublicKeyAsync(privateKey) };
};

let A: Id, B: Id, C: Id;
beforeAll(async () => {
  [A, B, C] = await Promise.all([mk("did:aroha:root-a"), mk("did:aroha:node-b"), mk("did:aroha:node-c")]);
});
afterEach(() => { vi.unstubAllGlobals(); });

/** Build a chain of `links` hops, each with its own key, rooted at A. */
async function longChain(links: number) {
  const ids: Id[] = [A];
  for (let i = 1; i <= links; i++) ids.push(await mk(`did:aroha:hop-${i}`));
  let current: SignedTaskMandate = await issueTaskMandate(A.did, ids[1].did, ["search"], {}, A.privateKey);
  const tokens = [current.token];
  for (let i = 1; i < links; i++) {
    current = await attenuateTaskMandate(current, ids[i + 1].did, ["search"], {}, ids[i].privateKey);
    tokens.push(current.token);
  }
  const keys = Object.fromEntries(ids.map((x) => [x.did, x.pub]));
  return { tokens, leafDid: ids[links].did, resolve: staticResolver(keys) };
}

describe("verifyTaskMandateChain — v2 rules", () => {
  it("caps chain length at 8 by default even when no maxDelegationDepth is set", async () => {
    expect(DEFAULT_TASK_CHAIN_MAX_DEPTH).toBe(8);
    const ok = await longChain(8);
    expect((await verifyTaskMandateChain(ok.tokens, A.pub, { resolvePublicKey: ok.resolve })).valid).toBe(true);

    const tooLong = await longChain(9);
    const r = await verifyTaskMandateChain(tooLong.tokens, A.pub, { resolvePublicKey: tooLong.resolve });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Delegation depth exceeded: chain has 9 links; maximum is 8/);

    const tighter = await verifyTaskMandateChain(ok.tokens, A.pub, { resolvePublicKey: ok.resolve, maxDepth: 3 });
    expect(tighter.reason).toMatch(/maximum is 3/);
  });

  it("checks revocation on every link, keyed by (mandateId, grantor)", async () => {
    const root = await issueTaskMandate(A.did, B.did, ["search"], {}, A.privateKey);
    const child = await attenuateTaskMandate(root, C.did, ["search"], {}, B.privateKey);
    const resolve = staticResolver({ [B.did]: B.pub });
    const seen: string[] = [];
    const ok = await verifyTaskMandateChain([root.token, child.token], A.pub, {
      resolvePublicKey: resolve,
      isRevoked: async (id, grantor) => { seen.push(`${grantor}:${id}`); return false; },
    });
    expect(ok.valid).toBe(true);
    expect(seen).toEqual([`${A.did}:${root.mandate.mandateId}`, `${B.did}:${child.mandate.mandateId}`]);

    // Revoking the ROOT kills the sub-delegation beneath it.
    const r = await verifyTaskMandateChain([root.token, child.token], A.pub, {
      resolvePublicKey: resolve,
      isRevoked: async (id, grantor) => id === root.mandate.mandateId && grantor === A.did,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/has been revoked \(link 0\)/);

    // A reused id under a different grantor is not the revoked mandate.
    const other = await verifyTaskMandateChain([root.token, child.token], A.pub, {
      resolvePublicKey: resolve,
      isRevoked: async (id, grantor) => id === root.mandate.mandateId && grantor === "did:aroha:someone-else",
    });
    expect(other.valid).toBe(true);
  });

  it("fails closed when the revocation hook throws", async () => {
    const root = await issueTaskMandate(A.did, B.did, ["search"], {}, A.privateKey);
    const r = await verifyTaskMandateChain([root.token], A.pub, { isRevoked: async () => { throw new Error("down"); } });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/Revocation check failed/);
  });

  it("still accepts legacy v1 links next to v2 links", async () => {
    const root = await issueTaskMandate(A.did, B.did, ["search"], {}, A.privateKey);
    const sortKeys = (o: unknown): unknown => Array.isArray(o) ? o.map(sortKeys)
      : o && typeof o === "object" ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys((o as Record<string, unknown>)[k])])) : o;
    const sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(root.mandate))), A.privateKey);
    const v1Root = Buffer.from(JSON.stringify({ mandate: root.mandate, signature: Buffer.from(sig).toString("base64url") })).toString("base64url");
    const child = await attenuateTaskMandate(root, C.did, ["search"], {}, B.privateKey);
    const r = await verifyTaskMandateChain([v1Root, child.token], A.pub, { resolvePublicKey: staticResolver({ [B.did]: B.pub }) });
    expect(r.valid).toBe(true);
  });

  describe("KEL support for grantors", () => {
    async function kelWorld() {
      const alice = await incept({ kind: "person" });
      const agent = await incept({ kind: "agent", controller: alice.did });
      const logs = new Map<string, KelEvent[]>([[alice.did, alice.kel], [agent.did, agent.kel]]);
      const kelSource: KelSource = async (did) => logs.get(did) ?? null;
      const root = await issueTaskMandate(alice.did, agent.did, ["search"], {}, alice.privateKey);
      const alicePub = await ed.getPublicKeyAsync(alice.privateKey);
      return { alice, agent, logs, kelSource, root, alicePub };
    }

    it("verifies an E-DID root against its current KEL key", async () => {
      const w = await kelWorld();
      const r = await verifyTaskMandateChain([w.root.token], w.alicePub, { kelSource: w.kelSource, expectedGrantee: w.agent.did });
      expect(r.valid).toBe(true);
    });

    it("refuses a chain whose root person has revoked their identity", async () => {
      const w = await kelWorld();
      w.logs.set(w.alice.did, await revokeKelSelf(w.alice));
      const r = await verifyTaskMandateChain([w.root.token], w.alicePub, { kelSource: w.kelSource });
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(/revoked/);
    });

    it("refuses a root key that is not the KEL's current key, and a missing log", async () => {
      const w = await kelWorld();
      const r = await verifyTaskMandateChain([w.root.token], B.pub, { kelSource: w.kelSource });
      expect(r.reason).toMatch(/does not match the current key/);
      const none = await verifyTaskMandateChain([w.root.token], w.alicePub, { kelSource: async () => null });
      expect(none.reason).toMatch(/no Key Event Log/);
    });
  });
});

// ── Serving paths ─────────────────────────────────────────────────────────────

function mesh(agents: Record<string, ArohaAgent>) {
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const agent = agents[url.host];
    if (!agent) throw new TypeError(`no route to ${url.host}`);
    return agent.fetch(new Request(url, init));
  });
}

const RECORDS: TaskConstraints = { dataAccess: { "customer-db": "read", drafts: "write" } };

describe("serveDelegated enforces the leaf's constraints before the handler", () => {
  async function agent(handler = vi.fn((_ctx: unknown) => "ok")) {
    const b = serveDelegated("b", {
      identity: B,
      trustAnchors: { [A.did]: await publicKeyB64(A.privateKey) },
      // The SERVER decides what a request touches — here, from the message.
      requestScope: (req) => req.message === "export"
        ? { capability: "query", dataAccess: { "customer-db": "read-write" } }
        : { capability: "query", dataAccess: { "customer-db": "read" } },
    }, handler);
    mesh({ "b.localhost": b });
    return { b, handler };
  }

  it("integration: over-scope data access is rejected and the handler never runs", async () => {
    const { handler } = await agent();
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["query"], constraints: RECORDS });
    await expect(callDelegated("http://b.localhost", "export", envelope)).rejects.toThrow(/HTTP 400.*Data access/);
    expect(handler).not.toHaveBeenCalled();

    const ok = await callDelegated("http://b.localhost", "lookup", envelope);
    expect(ok.message).toBe("ok");
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("rejects a capability the leaf does not allow", async () => {
    const { handler } = await agent();
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["other"], constraints: RECORDS });
    await expect(callDelegated("http://b.localhost", "lookup", envelope)).rejects.toThrow(/not in the mandate's allowed list/);
    expect(handler).not.toHaveBeenCalled();
  });

  it("counts actionLimits across requests, and the handler's own assertion of the admitted capability is not double-counted", async () => {
    const b = serveDelegated("b", {
      identity: B, trustAnchors: { [A.did]: A.pub }, requestScope: { capability: "query", reversibility: "full" },
    }, (ctx) => { ctx.assertCapability("query", { reversibility: "full" }); return "ran"; });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["query"], constraints: { actionLimits: { query: 2 } } });
    expect((await callDelegated("http://b.localhost", "1", envelope)).message).toBe("ran");
    expect((await callDelegated("http://b.localhost", "2", envelope)).message).toBe("ran");
    await expect(callDelegated("http://b.localhost", "3", envelope)).rejects.toThrow(/Action limit exceeded/);
  });

  it("an undeterminable scope is refused", async () => {
    const b = serveDelegated("b", { identity: B, trustAnchors: { [A.did]: A.pub }, requestScope: () => null }, () => "never");
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["query"] });
    await expect(callDelegated("http://b.localhost", "x", envelope)).rejects.toThrow(/scope could not be determined/);
  });

  it("ctx.assertCapability enforces reversibleOnly, humanGates and dataAccess per action; ctx.assertDataAccess checks data alone", async () => {
    const outcomes: string[] = [];
    const b = serveDelegated("b", { identity: B, trustAnchors: { [A.did]: A.pub } }, (ctx) => {
      const attempt = (f: () => void) => {
        try { f(); outcomes.push("ok"); } catch (e) { outcomes.push((e as DelegationError).code); }
      };
      attempt(() => ctx.assertCapability("send"));                                   // irreversible by default
      attempt(() => ctx.assertCapability("send", { reversibility: "full" }));        // gated, no approval
      attempt(() => ctx.assertCapability("send", {
        reversibility: "full",
        approval: { sessionId: "s", approvalId: "a", decision: "approve" },
      }));
      attempt(() => ctx.assertCapability("send", {
        reversibility: "full",
        approval: { sessionId: "s", approvalId: "a", decision: "edit" },             // edit is not consent
      }));
      attempt(() => ctx.assertDataAccess("customer-db", "write"));
      attempt(() => ctx.assertDataAccess("customer-db", "read"));
      return "done";
    });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, {
      allowed: ["send"], constraints: { reversibleOnly: true, humanGates: ["send"], dataAccess: { "customer-db": "read" } },
    });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(outcomes).toEqual([
      "REVERSIBILITY_VIOLATION", "HUMAN_GATE_REQUIRED", "ok", "HUMAN_GATE_REQUIRED", "DATA_ACCESS_VIOLATION", "ok",
    ]);
    expect(res.receipts[0].receipt.status).toBe("failed");
  });

  it("ctx.delegate refuses to grow a chain past maxDepth, before signing anything", async () => {
    const outbound = vi.fn();
    const b = serveDelegated("b", { identity: B, trustAnchors: { [A.did]: A.pub }, maxDepth: 1 }, async (ctx) => {
      try {
        await ctx.delegate({ endpoint: "http://c.localhost", did: C.did }, "x", { allowed: ["search"] });
        return "delegated";
      } catch (e) {
        return (e as DelegationError).code;
      }
    });
    mesh({ "b.localhost": b, "c.localhost": { fetch: outbound } as unknown as ArohaAgent });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"] });
    expect((await callDelegated("http://b.localhost", "go", envelope)).message).toBe("DELEGATION_DEPTH_EXCEEDED");
    expect(outbound).not.toHaveBeenCalled();
  });

  it("rejects a revoked mandate when isRevoked is configured", async () => {
    const b = serveDelegated("b", {
      identity: B, trustAnchors: { [A.did]: A.pub }, isRevoked: async () => true,
    }, () => "never");
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"] });
    await expect(callDelegated("http://b.localhost", "go", envelope)).rejects.toThrow(/has been revoked/);
  });
});

describe("createDelegationMiddleware enforces the leaf's constraints before the handler", () => {
  const SERVER = "did:aroha:test:server";

  async function envelopeFor(allowed: string[], constraints: TaskConstraints, capability: string | undefined): Promise<ArohaEnvelope> {
    const root = await issueTaskMandate(A.did, SERVER, allowed, constraints, A.privateKey);
    const delegation: DelegationEnvelope = { v: 1, chain: [root.token], rootKeyB64: Buffer.from(A.pub).toString("base64"), correlationId: "c" };
    return {
      id: "e", type: "ArohaRequest", from: A.did, to: SERVER,
      created: new Date().toISOString(), expires: new Date(Date.now() + 60_000).toISOString(), nonce: "n",
      body: { capability, params: {}, context: { [DELEGATION_CONTEXT_KEY]: delegation } },
    } as unknown as ArohaEnvelope;
  }

  it("integration: over-scope data access is rejected with 403", async () => {
    const mw = createDelegationMiddleware({
      did: SERVER, trustAnchors: { [A.did]: A.pub },
      requestScope: (env) => {
        const body = env.body as unknown as { capability: string; params: { mode?: string } };
        return { capability: body.capability, dataAccess: { "customer-db": body.capability === "export-db" ? "read-write" : "read" } };
      },
    });
    const reject = vi.fn();
    await mw(await envelopeFor(["export-db"], RECORDS, "export-db"), reject);
    expect(reject).toHaveBeenCalledWith(403, "Aroha_DATA_ACCESS_VIOLATION",expect.stringContaining("customer-db"));

    const ok = vi.fn();
    await mw(await envelopeFor(["lookup"], RECORDS, "lookup"), ok);
    expect(ok).not.toHaveBeenCalled();
  });

  it("by default enforces the body's capability against allowed/blocked", async () => {
    const mw = createDelegationMiddleware({ did: SERVER, trustAnchors: { [A.did]: A.pub } });
    const reject = vi.fn();
    await mw(await envelopeFor(["research"], {}, "delete-everything"), reject);
    expect(reject).toHaveBeenCalledWith(403, "Aroha_CAPABILITY_NOT_PERMITTED",expect.any(String));
  });

  it("refuses an envelope whose capability cannot be determined", async () => {
    const mw = createDelegationMiddleware({ did: SERVER, trustAnchors: { [A.did]: A.pub } });
    const reject = vi.fn();
    await mw(await envelopeFor(["research"], {}, undefined), reject);
    expect(reject).toHaveBeenCalledWith(403, "Aroha_SCOPE_UNKNOWN", expect.any(String));
  });

  it("counts actionLimits per mandate", async () => {
    const mw = createDelegationMiddleware({ did: SERVER, trustAnchors: { [A.did]: A.pub } });
    const env = await envelopeFor(["research"], { actionLimits: { research: 1 } }, "research");
    const first = vi.fn();
    await mw(env, first);
    expect(first).not.toHaveBeenCalled();
    const second = vi.fn();
    await mw(env, second);
    expect(second).toHaveBeenCalledWith(403, "Aroha_ACTION_LIMIT_EXCEEDED", expect.any(String));
  });

  it("sends the canonical ArohaErrorCode for a constraint violation", async () => {
    const mw = createDelegationMiddleware({ did: SERVER, trustAnchors: { [A.did]: A.pub } });
    const irreversible = vi.fn();
    await mw(await envelopeFor(["send"], { reversibleOnly: true }, "send"), irreversible);
    expect(irreversible).toHaveBeenCalledWith(403, ArohaErrorCode.ReversibilityViolation, expect.any(String));
    const gated = vi.fn();
    await mw(await envelopeFor(["send"], { humanGates: ["send"] }, "send"), gated);
    expect(gated).toHaveBeenCalledWith(403, ArohaErrorCode.HumanGateRequired, expect.any(String));
  });
});
