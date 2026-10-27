// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { issueTaskMandate } from "@aroha-sdk/credentials";
import { ArohaErrorCode, type ArohaEnvelope } from "@aroha-sdk/core";
import { createDelegationMiddleware, getVerifiedMandate, type DelegationMiddlewareOptions } from "./server-middleware.js";
import { DELEGATION_CONTEXT_KEY, type DelegationEnvelope } from "./chain.js";

const A = { did: "did:aroha:test:root" };
const SERVER = { did: "did:aroha:test:server" };

let aKey: Uint8Array;
let aPub: Uint8Array;

beforeAll(async () => {
  aKey = ed.utils.randomPrivateKey();
  aPub = await ed.getPublicKeyAsync(aKey);
});

function makeEnvelope(context?: Record<string, unknown>, capability = "research"): ArohaEnvelope {
  return {
    id: "test-envelope",
    type: "request",
    from: A.did,
    to: SERVER.did,
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 60_000).toISOString(),
    nonce: "test-nonce",
    body: { capability, params: {}, context } as unknown,
  } as unknown as ArohaEnvelope;
}

async function makeDelegationEnvelope(opts?: { allowed?: string[] }): Promise<DelegationEnvelope> {
  const root = await issueTaskMandate(
    A.did, SERVER.did,
    opts?.allowed ?? ["research"],
    {}, aKey, 3_600_000,
  );
  return { v: 1, chain: [root.token], rootKeyB64: Buffer.from(aPub).toString("base64"), correlationId: "corr-1" };
}

describe("createDelegationMiddleware", () => {
  it("allows a request carrying a valid mandate chain, and getVerifiedMandate returns it", async () => {
    const middleware = createDelegationMiddleware({ did: SERVER.did, trustAnchors: { [A.did]: aPub } });
    const delegationEnvelope = await makeDelegationEnvelope();
    const envelope = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).not.toHaveBeenCalled();
    const verified = getVerifiedMandate(envelope);
    expect(verified?.valid).toBe(true);
    expect(verified?.mandate?.grantee).toBe(SERVER.did);
  });

  it("rejects with 400 when require:true (default) and no chain is present", async () => {
    const middleware = createDelegationMiddleware({ did: SERVER.did, trustAnchors: { [A.did]: aPub } });
    const envelope = makeEnvelope();

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).toHaveBeenCalledWith(400, expect.any(String), expect.stringContaining("Missing delegation envelope"));
    expect(getVerifiedMandate(envelope)).toBeUndefined();
  });

  it("allows a request with no chain when require:false", async () => {
    const middleware = createDelegationMiddleware({ did: SERVER.did, require: false, trustAnchors: { [A.did]: aPub } });
    const envelope = makeEnvelope();

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).not.toHaveBeenCalled();
    expect(getVerifiedMandate(envelope)).toBeUndefined();
  });

  it("rejects an untrusted root issuer when trustAnchors is set", async () => {
    const otherKey = ed.utils.randomPrivateKey();
    const otherPub = await ed.getPublicKeyAsync(otherKey);
    const middleware = createDelegationMiddleware({
      did: SERVER.did,
      trustAnchors: { [A.did]: otherPub }, // wrong key on purpose
    });
    const delegationEnvelope = await makeDelegationEnvelope();
    const envelope = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).toHaveBeenCalledWith(403, expect.any(String), expect.stringContaining("does not match trust anchor"));
  });

  it("allows a trusted root issuer whose key matches the anchor", async () => {
    const middleware = createDelegationMiddleware({
      did: SERVER.did,
      trustAnchors: { [A.did]: aPub },
    });
    const delegationEnvelope = await makeDelegationEnvelope();
    const envelope = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).not.toHaveBeenCalled();
  });

  it("rejects a tampered chain", async () => {
    const middleware = createDelegationMiddleware({ did: SERVER.did, trustAnchors: { [A.did]: aPub } });
    const delegationEnvelope = await makeDelegationEnvelope();
    delegationEnvelope.chain = ["not-a-real-token"];
    const envelope = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });

    const reject = vi.fn();
    await middleware(envelope, reject);

    expect(reject).toHaveBeenCalledWith(400, expect.any(String), expect.stringContaining("Malformed root mandate token"));
  });

  it("verified results are isolated per envelope instance", async () => {
    const middleware = createDelegationMiddleware({ did: SERVER.did, trustAnchors: { [A.did]: aPub } });
    const delegationEnvelope = await makeDelegationEnvelope();
    const envelope1 = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });
    const envelope2 = makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegationEnvelope });

    await middleware(envelope1, vi.fn());

    expect(getVerifiedMandate(envelope1)).toBeDefined();
    expect(getVerifiedMandate(envelope2)).toBeUndefined();
  });
});

describe("createDelegationMiddleware rejection codes", () => {
  const CANONICAL = new Set<string>(Object.values(ArohaErrorCode));

  async function rejectionOf(options: Partial<DelegationMiddlewareOptions>, envelope: ArohaEnvelope) {
    const middleware = createDelegationMiddleware({ did: SERVER.did, trustAnchors: { [A.did]: aPub }, ...options });
    const reject = vi.fn();
    await middleware(envelope, reject);
    expect(reject).toHaveBeenCalledTimes(1);
    const [status, code] = reject.mock.calls[0] as [number, string];
    return { status, code };
  }
  const withChain = async (chain?: string[], capability?: string) => {
    const delegation = await makeDelegationEnvelope();
    if (chain) delegation.chain = chain;
    return makeEnvelope({ [DELEGATION_CONTEXT_KEY]: delegation }, capability);
  };

  it("sends a canonical ArohaErrorCode, with an unchanged HTTP status, on every rejection path", async () => {
    const otherPub = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
    const roomBound = await issueTaskMandate(A.did, SERVER.did, ["research"], { roomId: "room-1" }, aKey, 3_600_000);
    const forSomeoneElse = await issueTaskMandate(A.did, "did:aroha:test:other", ["research"], {}, aKey, 3_600_000);
    const cases: Array<[string, () => Promise<{ status: number; code: string }>, number, ArohaErrorCode]> = [
      ["no chain", async () => rejectionOf({}, makeEnvelope()), 400, ArohaErrorCode.NoMandate],
      ["malformed root", async () => rejectionOf({}, await withChain(["not-a-real-token"])), 400, ArohaErrorCode.ChainInvalid],
      ["untrusted root", async () => rejectionOf({ trustAnchors: { "did:aroha:test:nobody": aPub } }, await withChain()), 403, ArohaErrorCode.UntrustedRoot],
      ["root key mismatch", async () => rejectionOf({ trustAnchors: { [A.did]: otherPub } }, await withChain()), 403, ArohaErrorCode.RootKeyMismatch],
      ["chain rejected", async () => rejectionOf({}, await withChain([forSomeoneElse.token])), 403, ArohaErrorCode.ChainRejected],
      ["no capability", async () => rejectionOf({}, await withChain(undefined, "")), 403, ArohaErrorCode.ScopeUnknown],
      ["requestScope throws", async () => rejectionOf({ requestScope: () => { throw new Error("boom"); } }, await withChain()), 403, ArohaErrorCode.ScopeUnknown],
      ["room-bound mandate", async () => rejectionOf({}, await withChain([roomBound.token])), 403, ArohaErrorCode.ContextMismatch],
    ];
    for (const [name, run, status, code] of cases) {
      const got = await run();
      expect({ name, ...got }).toEqual({ name, status, code });
      expect(CANONICAL.has(got.code), `${name}: ${got.code}`).toBe(true);
    }
  });
});
