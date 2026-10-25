// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { issueTaskMandate } from "@aroha-sdk/credentials";
import type { ArohaEnvelope } from "@aroha-sdk/core";
import { createDelegationMiddleware, getVerifiedMandate } from "./server-middleware.js";
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
