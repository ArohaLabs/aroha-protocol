// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * serveDelegated end to end through each agent's fetch handler: chain
 * verification at the door, trust-anchor pinning, capability checks, depth
 * enforcement on ctx.delegate(), and stitched receipts. Downstream hops are
 * reached through a stubbed global fetch that routes to the next agent's
 * handler, so callDelegated's real SSE parsing runs.
 */

import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { serveDelegated, publicKeyB64, DelegationError, type DelegatedContext } from "./serve-delegated.js";
import { issueDelegation, callDelegated } from "./client.js";
import type { ArohaAgent } from "@aroha-sdk/run";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

interface Id { did: string; privateKey: Uint8Array; pub: Uint8Array }
let A: Id, B: Id, C: Id;
beforeAll(async () => {
  const mk = async (did: string): Promise<Id> => {
    const privateKey = ed.utils.randomPrivateKey();
    return { did, privateKey, pub: await ed.getPublicKeyAsync(privateKey) };
  };
  [A, B, C] = await Promise.all([mk("did:aroha:root-a"), mk("did:aroha:node-b"), mk("did:aroha:node-c")]);
});
afterEach(() => { vi.unstubAllGlobals(); });

const keys = () => async (did: string) => (did === A.did ? A.pub : did === B.did ? B.pub : did === C.did ? C.pub : null);

/** Route http://<host>.localhost/v1/run to the matching agent's fetch handler. */
function mesh(agents: Record<string, ArohaAgent>) {
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const agent = agents[url.host];
    if (!agent) throw new TypeError(`no route to ${url.host}`);
    return agent.fetch(new Request(url, init));
  });
}

describe("serveDelegated", () => {
  it("runs the handler with the verified mandate and returns a receipt", async () => {
    const seen: Array<Partial<DelegatedContext>> = [];
    const b = serveDelegated("b", { identity: B, trustAnchors: { [A.did]: await publicKeyB64(A.privateKey) } }, (ctx) => {
      ctx.assertCapability("search");
      ctx.recordAction("search");
      seen.push({ mandate: ctx.mandate, chainDepth: ctx.chainDepth, correlationId: ctx.correlationId });
      return "done";
    });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"], correlationId: "trace-1" });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(res.message).toBe("done");
    expect(seen[0].mandate?.grantee).toBe(B.did);
    expect(seen[0].correlationId).toBe("trace-1");
    expect(res.receipts).toHaveLength(1);
    expect(res.receipts[0].receipt.status).toBe("complete");
  });

  it("rejects a request with no envelope (require defaults to true)", async () => {
    const handler = vi.fn(() => "never");
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, handler);
    const res = await b.fetch(new Request("http://b.localhost/v1/run", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "hi" }),
    }));
    expect(res.status).toBe(400);
    expect(handler).not.toHaveBeenCalled();
  });

  it("rejects a root issuer that is not a trust anchor, and a root key that does not match the anchor", async () => {
    const handler = vi.fn(() => "never");
    const b = serveDelegated("b", { identity: B, trustAnchors: { [C.did]: C.pub } }, handler);
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["x"] });
    await expect(callDelegated("http://b.localhost", "go", envelope)).rejects.toThrow(/Untrusted root issuer/);

    const b2 = serveDelegated("b", { identity: B, trustAnchors: { [A.did]: C.pub } }, handler);
    mesh({ "b.localhost": b2 });
    await expect(callDelegated("http://b.localhost", "go", envelope)).rejects.toThrow(/does not match trust anchor/);
    expect(handler).not.toHaveBeenCalled();
  });

  it("rejects a mandate granted to someone else", async () => {
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, () => "never");
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, C.did, { allowed: ["x"] });
    await expect(callDelegated("http://b.localhost", "go", envelope)).rejects.toThrow(/HTTP 400/);
  });

  it("assertCapability refuses blocked / unlisted capabilities and marks the receipt failed", async () => {
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, (ctx) => {
      ctx.assertCapability("send-email");
      return "sent";
    });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["send-email", "search"], blocked: ["send-email"] });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(res.message).toMatch(/blocked by the mandate/);
    expect(res.receipts[0].receipt.status).toBe("failed");
  });

  it("delegates A → B → C with an attenuated child, stitching C's receipt under B's", async () => {
    let cMandate: DelegatedContext["mandate"];
    let cDepth = 0;
    const c = serveDelegated("c", { identity: C, resolveRootKey: keys(), resolvePublicKey: keys() }, (ctx) => {
      cMandate = ctx.mandate;
      cDepth = ctx.chainDepth;
      return "c-done";
    });
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys(), resolvePublicKey: keys() }, async (ctx) => {
      const r = await ctx.delegate({ endpoint: "http://c.localhost", did: C.did }, "sub-task", { allowed: ["search"] });
      return `b got ${r.message}`;
    });
    mesh({ "b.localhost": b, "c.localhost": c });
    const { envelope } = await issueDelegation(A, B.did, {
      allowed: ["search", "book"], blocked: ["pay"], constraints: { maxDelegationDepth: 2 }, correlationId: "trace-2",
    });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(res.message).toBe("b got c-done");
    expect(cMandate?.allowed).toEqual(["search"]);
    expect(cMandate?.blocked).toEqual(["pay"]);
    expect(cMandate?.taskConstraints.maxDelegationDepth).toBe(1);
    expect(cDepth).toBe(2);
    expect(res.receipts[0].children).toHaveLength(1);
  });

  it("refuses to sub-delegate under maxDelegationDepth=0, before signing anything", async () => {
    const outbound = vi.fn();
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, async (ctx) => {
      try {
        await ctx.delegate({ endpoint: "http://c.localhost", did: C.did }, "x", { allowed: ["search"] });
        return "delegated";
      } catch (e) {
        return e instanceof DelegationError ? e.code : "other";
      }
    });
    mesh({ "b.localhost": b, "c.localhost": { fetch: outbound } as unknown as ArohaAgent });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"], constraints: { maxDelegationDepth: 0 } });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(res.message).toBe("DELEGATION_DEPTH_EXCEEDED");
    expect(outbound).not.toHaveBeenCalled();
  });

  it("refuses to widen capabilities when delegating", async () => {
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, async (ctx) => {
      await ctx.delegate({ endpoint: "http://c.localhost", did: C.did }, "x", { allowed: ["admin"] });
      return "should not get here";
    });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"] });
    const res = await callDelegated("http://b.localhost", "go", envelope);
    expect(res.message).toMatch(/not in parent's allowed list/);
    expect(res.receipts[0].receipt.status).toBe("failed");
  });

  it("a target with no DID is refused", async () => {
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys() }, async (ctx) => {
      try {
        await ctx.delegate({ endpoint: "http://c.localhost" }, "x", { allowed: ["search"] });
        return "?";
      } catch (e) {
        return (e as DelegationError).code;
      }
    });
    mesh({ "b.localhost": b });
    const { envelope } = await issueDelegation(A, B.did, { allowed: ["search"] });
    expect((await callDelegated("http://b.localhost", "go", envelope)).message).toBe("TARGET_UNRESOLVED");
  });

  it("require:false serves un-mandated requests with no mandate on the context", async () => {
    let had: unknown = "unset";
    const b = serveDelegated("b", { identity: B, resolveRootKey: keys(), require: false }, (ctx) => {
      had = ctx.mandate;
      expect(() => ctx.assertCapability("x")).toThrow(DelegationError);
      return "open";
    });
    const res = await b.fetch(new Request("http://b.localhost/v1/run", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "hi" }),
    }));
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("open");
    expect(had).toBeUndefined();
  });
});
