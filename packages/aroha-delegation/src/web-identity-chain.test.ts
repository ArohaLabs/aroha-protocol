// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Task-mandate chains between web identities (spec §4.7): the chain verifier
 * takes the same resolver the spending verifier does, so an HTTPS URL that
 * publishes its key can delegate a task exactly as a did:aroha identity can.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import {
  attenuateTaskMandate,
  buildWebIdentityDocument,
  createMandateKeyResolver,
  createWebIdentityResolver,
  issueTaskMandate,
} from "@aroha-sdk/credentials";
import { verifyTaskMandateChain } from "./chain.js";

const HUMAN = "https://accounts.example.com/people/kiri";
const ASSISTANT = "https://agents.example.com/assistant";
const WORKER = "https://tools.example.net/agents/inbox-worker";

async function party() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, pub: await ed.getPublicKeyAsync(priv) };
}

/** A fetch serving one identity document per URL, 404 for everything else. */
function serve(identities: Record<string, Uint8Array>) {
  const calls: string[] = [];
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const publicKey = identities[url];
    if (!publicKey) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(buildWebIdentityDocument({ identity: url, publicKey })), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { fetch: impl as typeof fetch, calls };
}

describe("verifyTaskMandateChain with web identities", () => {
  it("verifies a two-hop chain and reports the narrowed authority", async () => {
    const human = await party(), assistant = await party();
    const { fetch } = serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub });
    const resolve = createWebIdentityResolver({ fetch });

    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read", "inbox.archive", "inbox.send"], { maxDelegationDepth: 2, actionLimits: { "inbox.archive": 50 } }, human.priv);
    const child = await attenuateTaskMandate(root, WORKER, ["inbox.read", "inbox.archive"], { maxDelegationDepth: 1, actionLimits: { "inbox.archive": 10 } }, assistant.priv);

    const rootKey = await resolve(root.mandate.grantor);
    expect(rootKey).not.toBeNull();
    const r = await verifyTaskMandateChain([root.token, child.token], rootKey!, { expectedGrantee: WORKER, resolvePublicKey: resolve });
    expect(r.valid, r.reason).toBe(true);
    expect(r.depth).toBe(2);
    expect(r.mandates?.map((m) => m.grantor)).toEqual([HUMAN, ASSISTANT]);
    expect(r.mandate?.allowed).toEqual(["inbox.read", "inbox.archive"]);
    expect(r.mandate?.taskConstraints.actionLimits).toEqual({ "inbox.archive": 10 });
  });

  it("accepts the combined resolver, so one chain can mix did:aroha and web identities", async () => {
    const human = await party(), assistant = await party();
    const { fetch } = serve({ [ASSISTANT]: assistant.pub });
    const resolve = createMandateKeyResolver({ web: { fetch } });
    const root = await issueTaskMandate("did:aroha:test:kiri", ASSISTANT, ["research"], { maxDelegationDepth: 2 }, human.priv);
    const child = await attenuateTaskMandate(root, "did:aroha:test:worker", ["research"], { maxDelegationDepth: 1 }, assistant.priv);
    const r = await verifyTaskMandateChain([root.token, child.token], human.pub, { expectedGrantee: "did:aroha:test:worker", resolvePublicKey: resolve });
    expect(r.valid, r.reason).toBe(true);
  });

  it("refuses the chain when the intermediate identity publishes a different key", async () => {
    const human = await party(), assistant = await party(), impostor = await party();
    const { fetch } = serve({ [HUMAN]: human.pub, [ASSISTANT]: assistant.pub });
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], { maxDelegationDepth: 2 }, human.priv);
    // Signed by a key that ASSISTANT's URL does not publish.
    const forged = await attenuateTaskMandate(root, WORKER, ["inbox.read"], { maxDelegationDepth: 1 }, impostor.priv);
    const r = await verifyTaskMandateChain([root.token, forged.token], human.pub, { resolvePublicKey: createWebIdentityResolver({ fetch }) });
    expect(r.valid).toBe(false);
  });

  it("refuses the chain when the intermediate identity cannot be fetched", async () => {
    const human = await party(), assistant = await party();
    const { fetch, calls } = serve({ [HUMAN]: human.pub });
    const root = await issueTaskMandate(HUMAN, ASSISTANT, ["inbox.read"], { maxDelegationDepth: 2 }, human.priv);
    const child = await attenuateTaskMandate(root, WORKER, ["inbox.read"], { maxDelegationDepth: 1 }, assistant.priv);
    const r = await verifyTaskMandateChain([root.token, child.token], human.pub, { resolvePublicKey: createWebIdentityResolver({ fetch }) });
    expect(r.valid).toBe(false);
    expect(calls).toEqual([ASSISTANT]);
  });
});
