// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The A2A server side, exercised with the bridge's own client over a real
 * HTTP socket: discovery (signed card), SendMessage with a verified mandate,
 * and the refusals (bad mandate, wrong method, unauthenticated caller).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, attenuateToCart, verifyMandateChain } from "@aroha-sdk/credentials";
import {
  arohaMandateExtension, sendMessage, A2AJsonRpcError, type A2AAgentCard, type A2AMessage,
} from "./index.js";
import {
  A2A_RPC_ERROR, AGENT_CARD_WELL_KNOWN_PATH, AROHA_MANDATE_REJECTED_RPC_CODE, createA2aRequestHandler, fetchAgentCard,
  signAgentCard, verifyAgentCardSignature, agentCardSigningPayload, agentCardSigningPayloadAsIs,
} from "./server.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

async function z() {
  const priv = ed.utils.randomPrivateKey();
  return { priv, did: generateDid(await ed.getPublicKeyAsync(priv)) };
}

let server: Server;
let base: string;
let agent: { priv: Uint8Array; did: string };
let human: typeof agent, caller: typeof agent;
let goodToken: string;
const seen: unknown[] = [];

beforeAll(async () => {
  [agent, human, caller] = await Promise.all([z(), z(), z()]);
  const intent = await issueIntentMandate(human.did, caller.did, { spendLimitUsd: 50 }, human.priv);
  goodToken = intent.token;
  server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const card: A2AAgentCard = {
    name: "Aroha test agent", description: "Answers searches", version: "1.0.0",
    supportedInterfaces: [{ url: `${base}/a2a`, protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    capabilities: { extensions: [arohaMandateExtension(true)] },
    defaultInputModes: ["application/json"], defaultOutputModes: ["application/json"],
    skills: [{ id: "search", name: "Search", description: "Search", tags: ["search"] }],
  };
  const handler = await createA2aRequestHandler({
    card, agentDid: agent.did, privateKey: agent.priv,
    // Test transport auth: the caller DID arrives in a header the test controls.
    resolveCaller: (req) => (typeof req.headers["x-test-caller"] === "string" ? req.headers["x-test-caller"] : null),
    mandatePolicy: { verifyMandateChain, expectedRoot: human.did, isRevoked: async () => false },
    handle: (env, ctx) => {
      seen.push({ env, ctx });
      return { ok: true, echoed: env.body, root: ctx.rootGrantor };
    },
  });
  server.on("request", handler);
});

afterAll(() => server.close());

const msg = (): A2AMessage => ({ messageId: crypto.randomUUID(), role: "ROLE_USER", parts: [{ data: { capability: "search", params: { q: "x" } } }] });

describe("A2A server", () => {
  it("serves a signed agent card that the client verifies", async () => {
    const { card, kid } = await fetchAgentCard(base);
    expect(kid).toBe(`${agent.did}#key-1`);
    expect(card.signatures).toHaveLength(1);
    // A tampered card fails.
    expect((await verifyAgentCardSignature({ ...card, name: "Evil" })).ok).toBe(false);
    // A card signed by a different key fails an expectedKid pin.
    const other = await z();
    const resigned = await signAgentCard({ ...card, signatures: undefined }, other.priv, `${other.did}#key-1`);
    expect((await verifyAgentCardSignature(resigned, undefined, { expectedKid: kid })).ok).toBe(false);
    // A card signed by 2.0.0 or earlier (payload = JCS of the card as-is) still verifies.
    const { signatures: _s, ...rest } = card;
    const unsigned: A2AAgentCard = { ...rest, securitySchemes: {} }; // a default-valued field
    expect(agentCardSigningPayloadAsIs(unsigned)).not.toBe(agentCardSigningPayload(unsigned));
    const legacyProtected = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JOSE", kid })).toString("base64url");
    const legacyInput = `${legacyProtected}.${Buffer.from(agentCardSigningPayloadAsIs(unsigned)).toString("base64url")}`;
    const legacySig = Buffer.from(await ed.signAsync(new TextEncoder().encode(legacyInput), agent.priv)).toString("base64url");
    expect((await verifyAgentCardSignature({ ...unsigned, signatures: [{ protected: legacyProtected, signature: legacySig }] })).ok).toBe(true);
    const res = await fetch(base + AGENT_CARD_WELL_KNOWN_PATH);
    expect(res.headers.get("content-type")).toMatch(/application\/json/);
  });

  it("SendMessage with a verified mandate reaches the handler as an Aroha envelope", async () => {
    const r = await sendMessage(`${base}/a2a`, msg(), { mandateToken: goodToken, headers: { "x-test-caller": caller.did } });
    expect(r.kind).toBe("message");
    const data = (r as { message: A2AMessage }).message.parts[0] as { data: Record<string, unknown> };
    expect(data.data).toMatchObject({ ok: true, root: human.did, echoed: { capability: "search" } });
    const last = seen.at(-1) as { env: { from: string; to: string; proof?: unknown } };
    expect(last.env.from).toBe(caller.did);
    expect(last.env.to).toBe(agent.did);
    expect(last.env.proof).toBeUndefined();
  });

  it("refuses a missing or untrusted mandate before the handler runs", async () => {
    const n = seen.length;
    await expect(sendMessage(`${base}/a2a`, msg(), { headers: { "x-test-caller": caller.did } }))
      .rejects.toMatchObject({ code: AROHA_MANDATE_REJECTED_RPC_CODE });
    const stranger = await z();
    const selfRooted = await issueIntentMandate(stranger.did, caller.did, { spendLimitUsd: 50 }, stranger.priv);
    await expect(sendMessage(`${base}/a2a`, msg(), { mandateToken: selfRooted.token, headers: { "x-test-caller": caller.did } }))
      .rejects.toBeInstanceOf(A2AJsonRpcError);
    // A mandate granted to someone else than the authenticated caller.
    const other = await z();
    const cart = await attenuateToCart(await issueIntentMandate(human.did, other.did, { spendLimitUsd: 50 }, human.priv), caller.did, { spendLimitUsd: 10 }, other.priv);
    await expect(sendMessage(`${base}/a2a`, msg(), { mandateToken: cart.token, headers: { "x-test-caller": other.did } }))
      .rejects.toMatchObject({ code: AROHA_MANDATE_REJECTED_RPC_CODE });
    expect(seen.length).toBe(n);
  });

  it("answers JSON-RPC errors for bad requests and 401 for an unauthenticated caller", async () => {
    const post = (body: string, headers: Record<string, string> = { "x-test-caller": caller.did, "a2a-version": "1.0" }) =>
      fetch(`${base}/a2a`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
    const rpc = (method: string, params: unknown = {}) => JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
    expect((await (await post("{")).json()).error.code).toBe(-32700);
    expect((await (await post(rpc("NoSuchMethod"))).json()).error.code).toBe(-32601);
    expect((await (await post(rpc("GetTask"))).json()).error.code).toBe(-32602);
    expect((await (await post(rpc("GetTask", { id: "nope" }))).json()).error.code).toBe(A2A_RPC_ERROR.TASK_NOT_FOUND);
    expect((await (await post(rpc("SendStreamingMessage"))).json()).error.code).toBe(A2A_RPC_ERROR.UNSUPPORTED_OPERATION);
    expect((await (await post(rpc("CreateTaskPushNotificationConfig"))).json()).error.code).toBe(A2A_RPC_ERROR.PUSH_NOTIFICATION_NOT_SUPPORTED);
    expect((await (await post(rpc("SendMessage"))).json()).error.code).toBe(-32602);
    // A2A 1.0 §3.6.2: no A2A-Version header means 0.3, which this server does not speak.
    expect((await (await post(rpc("SendMessage"), { "x-test-caller": caller.did })).json()).error.code).toBe(A2A_RPC_ERROR.VERSION_NOT_SUPPORTED);
    expect((await (await post(rpc("SendMessage"), { "x-test-caller": caller.did, "a2a-version": "0.3" })).json()).error.code).toBe(A2A_RPC_ERROR.VERSION_NOT_SUPPORTED);
    expect((await post("{}", {})).status).toBe(401);
    expect((await fetch(`${base}/a2a`)).status).toBe(405);
  });
});
