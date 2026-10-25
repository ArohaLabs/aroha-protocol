// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Interop with the official A2A JavaScript SDK (@a2a-js/sdk, A2A 1.0), in
 * both directions, over real HTTP sockets on 127.0.0.1 — no network.
 *
 *   (a) the SDK's client  →  an agent served by createA2aRequestHandler
 *   (b) the bridge client →  an agent served by the SDK's DefaultRequestHandler
 *                            behind its Express JSON-RPC and agent-card handlers
 *
 * plus card signatures across implementations (each side verifies the
 * other's JWS), a mandate-carrying call and refused calls in each direction.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, verifyMandateChain } from "@aroha-sdk/credentials";
import {
  Role, TaskState, Message as SdkMessage, AgentCard as SdkAgentCard,
  generateAgentCardSignature, verifyAgentCardSignature as sdkVerifyCard,
} from "@a2a-js/sdk";
import { ClientFactory } from "@a2a-js/sdk/client";
import { A2A_ERROR_CODE } from "@a2a-js/sdk/errors";
import {
  DefaultRequestHandler, InMemoryTaskStore, AgentEvent, type AgentExecutor,
} from "@a2a-js/sdk/server";
import { agentCardHandler, jsonRpcHandler } from "@a2a-js/sdk/server/express";
import {
  AROHA_MANDATE_EXTENSION_URI, AROHA_MANDATE_METADATA_KEY, arohaMandateExtension, sendMessage, getTask, cancelTask,
  verifyA2aMandate, A2AJsonRpcError, type A2AAgentCard, type A2AMessage,
} from "./index.js";
import {
  AROHA_MANDATE_REJECTED_RPC_CODE, contentAddressedCardKey, createA2aRequestHandler, fetchAgentCard,
  signAgentCard, verifyAgentCardSignature,
} from "./server.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

type Id = { priv: Uint8Array; pub: Uint8Array; did: string };
async function z(): Promise<Id> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const privJwk = (k: Id) => ({ kty: "OKP", crv: "Ed25519", x: b64u(k.pub), d: b64u(k.priv) });
/** The SDK's key lookup for a did:aroha:z… kid, using the bridge's resolver for the bytes. */
const sdkKeyForKid = async (kid: string) => {
  const raw = await contentAddressedCardKey(kid);
  if (!raw) throw new Error(`no key for ${kid}`);
  return { kty: "OKP", crv: "Ed25519", x: b64u(raw) };
};

async function listen(server: Server): Promise<string> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const baseCard = (url: string, name: string): A2AAgentCard => ({
  name, description: `${name} (interop test)`, version: "1.0.0",
  supportedInterfaces: [{ url, protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
  capabilities: { streaming: false, pushNotifications: false, extensions: [arohaMandateExtension(true)] },
  defaultInputModes: ["application/json"], defaultOutputModes: ["application/json"],
  skills: [{ id: "search", name: "Search", description: "Search", tags: ["search"] }],
});

let human: Id, caller: Id, stranger: Id, bridgeAgent: Id, sdkAgent: Id;
let goodToken: string, selfRootedToken: string;

beforeAll(async () => {
  [human, caller, stranger, bridgeAgent, sdkAgent] = await Promise.all([z(), z(), z(), z(), z()]);
  goodToken = (await issueIntentMandate(human.did, caller.did, { spendLimitUsd: 50 }, human.priv)).token;
  // Well-formed and correctly signed, but rooted in a key nobody trusts.
  selfRootedToken = (await issueIntentMandate(stranger.did, caller.did, { spendLimitUsd: 50 }, stranger.priv)).token;
});

// ─── Agent card signatures across implementations ───────────────────────────

describe("agent card signatures: bridge ↔ @a2a-js/sdk", () => {
  const card = (): A2AAgentCard => ({
    ...baseCard("http://127.0.0.1:1/a2a", "Sig test"),
    // Fields that hold their proto default: A2A 1.0 §8.4.1 says they are
    // omitted from the signed payload. Optional bools (streaming) stay.
    capabilities: { streaming: false, extensions: [arohaMandateExtension(false), { uri: "urn:x:other", required: true }] },
    securitySchemes: {},
  });

  it("the SDK verifies a card the bridge signed (incl. default-valued fields)", async () => {
    const signed = await signAgentCard(card(), bridgeAgent.priv, `${bridgeAgent.did}#key-1`);
    await expect(sdkVerifyCard(sdkKeyForKid)(signed as never)).resolves.toBeUndefined();
    // Tampering is caught by the SDK too.
    await expect(sdkVerifyCard(sdkKeyForKid)({ ...signed, name: "Evil" } as never)).rejects.toThrow();
  });

  it("the bridge verifies a card the SDK signed, and rejects a tampered or foreign-key one", async () => {
    const kid = `${sdkAgent.did}#key-1`;
    const signed = await generateAgentCardSignature(privJwk(sdkAgent), { alg: "EdDSA", kid, typ: "JOSE" })(
      SdkAgentCard.fromJSON(card()),
    );
    const wire = JSON.parse(JSON.stringify(SdkAgentCard.toJSON(signed))) as A2AAgentCard;
    expect(await verifyAgentCardSignature(wire)).toEqual({ ok: true, kid });
    expect((await verifyAgentCardSignature({ ...wire, description: "changed" })).ok).toBe(false);
    expect((await verifyAgentCardSignature(wire, undefined, { expectedKid: `${stranger.did}#key-1` })).ok).toBe(false);
  });
});

// ─── (a) @a2a-js/sdk client → bridge server ─────────────────────────────────

describe("(a) @a2a-js/sdk client → @aroha-sdk/a2a-bridge server", () => {
  let server: Server;
  let base: string;
  const seen: Array<{ from: string; body: Record<string, unknown> }> = [];
  const canceled: string[] = [];
  const asCaller = { serviceParameters: { "x-test-caller": "" } };

  beforeAll(async () => {
    asCaller.serviceParameters["x-test-caller"] = caller.did;
    server = createServer();
    base = await listen(server);
    const handler = await createA2aRequestHandler({
      card: baseCard(`${base}/a2a`, "Aroha bridge agent"),
      agentDid: bridgeAgent.did, privateKey: bridgeAgent.priv,
      resolveCaller: (req) => (typeof req.headers["x-test-caller"] === "string" ? req.headers["x-test-caller"] : null),
      mandatePolicy: { verifyMandateChain, expectedRoot: human.did, isRevoked: async () => false },
      handle: (env, ctx) => {
        const body = env.body as unknown as Record<string, unknown>;
        seen.push({ from: env.from, body });
        if (body.capability === "long-job" || body.capability === "done-job") {
          const state = body.capability === "long-job" ? "TASK_STATE_WORKING" : "TASK_STATE_COMPLETED";
          return { kind: "task", task: { id: `task-${seen.length}`, contextId: ctx.message.contextId, status: { state } } };
        }
        return { ok: true, root: ctx.rootGrantor, capability: body.capability };
      },
      onCancel: (task) => { canceled.push(task.id); },
    });
    server.on("request", handler);
  });
  afterAll(() => server.close());

  const factory = () => new ClientFactory();
  const sdkMsg = (data: Record<string, unknown>, token?: string) =>
    SdkMessage.fromJSON({
      messageId: crypto.randomUUID(), role: "ROLE_USER",
      parts: [{ data }],
      ...(token ? { metadata: { [AROHA_MANDATE_METADATA_KEY]: token }, extensions: [AROHA_MANDATE_EXTENSION_URI] } : {}),
    });

  it("discovers the agent card and verifies the bridge's signature with the SDK verifier", async () => {
    const client = await factory().createFromUrl(base);
    const card = await client.getAgentCard(undefined, sdkVerifyCard(sdkKeyForKid));
    expect(card.name).toBe("Aroha bridge agent");
    expect(card.capabilities?.extensions.map((e) => e.uri)).toContain(AROHA_MANDATE_EXTENSION_URI);
    // A card signed by someone else's key under the bridge agent's kid fails.
    const forged = await signAgentCard({ ...(SdkAgentCard.toJSON(card) as A2AAgentCard), signatures: undefined }, stranger.priv, `${bridgeAgent.did}#key-1`);
    await expect(sdkVerifyCard(sdkKeyForKid)(forged as never)).rejects.toThrow();
  });

  it("SendMessage with a mandate reaches the Aroha handler and returns a Message", async () => {
    const client = await factory().createFromUrl(base);
    const r = await client.sendMessage({ message: sdkMsg({ capability: "search", params: { q: "x" } }, goodToken) } as never, asCaller);
    expect("role" in r && r.role).toBe(Role.ROLE_AGENT);
    const part = (r as SdkMessage).parts[0].content;
    expect(part?.$case).toBe("data");
    expect(part?.value).toMatchObject({ ok: true, root: human.did, capability: "search" });
    expect(seen.at(-1)).toMatchObject({ from: caller.did, body: { capability: "search", credentialToken: goodToken } });
  });

  it("SendStreamingMessage: the card says streaming=false, so the SDK falls back to SendMessage", async () => {
    const client = await factory().createFromUrl(base);
    const events = [];
    for await (const e of client.sendMessageStream({ message: sdkMsg({ capability: "search" }, goodToken) } as never, asCaller)) events.push(e);
    expect(events).toHaveLength(1);
    // And a raw SendStreamingMessage is refused the way A2A 1.0 §3.3.4 says.
    const res = await fetch(`${base}/a2a`, {
      method: "POST",
      headers: { "content-type": "application/json", "a2a-version": "1.0", "x-test-caller": caller.did },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "SendStreamingMessage", params: { message: SdkMessage.toJSON(sdkMsg({}, goodToken)) } }),
    });
    expect((await res.json()).error.code).toBe(A2A_ERROR_CODE.UNSUPPORTED_OPERATION);
  });

  it("GetTask and CancelTask on a task the bridge agent returned", async () => {
    const client = await factory().createFromUrl(base);
    const r = await client.sendMessage({ message: sdkMsg({ capability: "long-job" }, goodToken) } as never, asCaller);
    expect("status" in r && r.status?.state).toBe(TaskState.TASK_STATE_WORKING);
    const id = (r as { id: string }).id;

    const got = await client.getTask({ id } as never, asCaller);
    expect(got.id).toBe(id);
    expect(got.status?.state).toBe(TaskState.TASK_STATE_WORKING);

    const c = await client.cancelTask({ id } as never, asCaller);
    expect(c.status?.state).toBe(TaskState.TASK_STATE_CANCELED);
    expect(canceled).toContain(id);
    expect((await client.getTask({ id } as never, asCaller)).status?.state).toBe(TaskState.TASK_STATE_CANCELED);

    // Cancelling again is idempotent; a finished task is not cancelable.
    expect((await client.cancelTask({ id } as never, asCaller)).status?.state).toBe(TaskState.TASK_STATE_CANCELED);
    const done = await client.sendMessage({ message: sdkMsg({ capability: "done-job" }, goodToken) } as never, asCaller);
    await expect(client.cancelTask({ id: (done as { id: string }).id } as never, asCaller))
      .rejects.toMatchObject({ envelopeCode: A2A_ERROR_CODE.TASK_NOT_CANCELABLE });

    // Unknown task, and another caller's task: both TaskNotFound.
    await expect(client.getTask({ id: "no-such-task" } as never, asCaller)).rejects.toMatchObject({ envelopeCode: A2A_ERROR_CODE.TASK_NOT_FOUND });
    await expect(client.getTask({ id } as never, { serviceParameters: { "x-test-caller": stranger.did } }))
      .rejects.toMatchObject({ envelopeCode: A2A_ERROR_CODE.TASK_NOT_FOUND });
  });

  it("refuses a missing or untrusted mandate with -32010 before the handler runs", async () => {
    const client = await factory().createFromUrl(base);
    const n = seen.length;
    await expect(client.sendMessage({ message: sdkMsg({ capability: "search" }) } as never, asCaller))
      .rejects.toMatchObject({ envelopeCode: AROHA_MANDATE_REJECTED_RPC_CODE });
    await expect(client.sendMessage({ message: sdkMsg({ capability: "search" }, selfRootedToken) } as never, asCaller))
      .rejects.toMatchObject({ envelopeCode: AROHA_MANDATE_REJECTED_RPC_CODE });
    expect(seen.length).toBe(n);
  });
});

// ─── (b) bridge client → @a2a-js/sdk server ─────────────────────────────────

describe("(b) @aroha-sdk/a2a-bridge client → @a2a-js/sdk server", () => {
  let server: Server;
  let base: string;
  const executed: Array<{ user: string; mandateOk: boolean }> = [];

  beforeAll(async () => {
    server = createServer();
    base = await listen(server);
    const kid = `${sdkAgent.did}#key-1`;
    const card = SdkAgentCard.fromJSON(baseCard(`${base}/a2a`, "SDK agent"));

    // An SDK-hosted agent that understands the Aroha mandate extension and
    // verifies it with the bridge's verifyA2aMandate before acting.
    const executor: AgentExecutor = {
      async execute(ctx, bus) {
        const user = ctx.context.user.userName;
        const wire = SdkMessage.toJSON(ctx.userMessage) as A2AMessage;
        const check = await verifyA2aMandate(wire, {
          verifyMandateChain, expectedRoot: human.did, expectedGrantee: user, isRevoked: async () => false,
        });
        executed.push({ user, mandateOk: check.ok });
        const data = (wire.parts[0] as { data?: Record<string, unknown> }).data ?? {};
        if (!check.ok) {
          bus.publish(AgentEvent.task({
            id: ctx.taskId, contextId: ctx.contextId, artifacts: [], history: [],
            status: { state: TaskState.TASK_STATE_REJECTED, timestamp: new Date().toISOString(), message: SdkMessage.fromJSON({
              messageId: crypto.randomUUID(), role: "ROLE_AGENT", taskId: ctx.taskId, contextId: ctx.contextId, parts: [{ text: check.reason }],
            }) },
            metadata: undefined,
          }));
        } else if (data.capability === "long-job") {
          bus.publish(AgentEvent.task({
            id: ctx.taskId, contextId: ctx.contextId, artifacts: [], history: [],
            status: { state: TaskState.TASK_STATE_WORKING, timestamp: new Date().toISOString(), message: undefined },
            metadata: undefined,
          }));
        } else {
          bus.publish(AgentEvent.message(SdkMessage.fromJSON({
            messageId: crypto.randomUUID(), role: "ROLE_AGENT", contextId: ctx.contextId,
            parts: [{ data: { ok: true, root: check.rootGrantor, capability: data.capability } }],
          })));
        }
        bus.finished();
      },
      async cancelTask(taskId, bus) {
        bus.publish(AgentEvent.statusUpdate({
          taskId, contextId: "", status: { state: TaskState.TASK_STATE_CANCELED, timestamp: new Date().toISOString(), message: undefined }, metadata: undefined,
        } as never));
        bus.finished();
      },
    };

    const requestHandler = new DefaultRequestHandler(
      card, new InMemoryTaskStore(), executor, undefined, undefined, undefined, undefined,
      generateAgentCardSignature(privJwk(sdkAgent), { alg: "EdDSA", kid, typ: "JOSE" }),
    );
    const app = express();
    app.use("/.well-known/agent-card.json", agentCardHandler({ agentCardProvider: requestHandler }));
    app.use("/a2a", jsonRpcHandler({
      requestHandler,
      // Test transport auth: the caller DID arrives in a header the test controls.
      userBuilder: async (req) => {
        const did = req.header("x-test-caller") ?? "";
        return { isAuthenticated: did !== "", userName: did };
      },
    }));
    server.on("request", app);
  });
  afterAll(() => server.close());

  const msg = (data: Record<string, unknown>): A2AMessage => ({ messageId: crypto.randomUUID(), role: "ROLE_USER", parts: [{ data }] });
  const headers = () => ({ "x-test-caller": caller.did });

  it("fetchAgentCard verifies the SDK's EdDSA card signature", async () => {
    const { card, kid } = await fetchAgentCard(base);
    expect(kid).toBe(`${sdkAgent.did}#key-1`);
    expect(card.name).toBe("SDK agent");
    // Pinning a different key fails.
    await expect(fetchAgentCard(base, { expectedKid: `${stranger.did}#key-1` })).rejects.toThrow(/signature rejected/);
  });

  it("sendMessage with a mandate: the SDK agent verifies it and answers with a Message", async () => {
    const r = await sendMessage(`${base}/a2a`, msg({ capability: "search" }), { mandateToken: goodToken, headers: headers() });
    expect(r.kind).toBe("message");
    const m = (r as { message: A2AMessage }).message;
    expect(m.role).toBe("ROLE_AGENT");
    expect((m.parts[0] as { data: unknown }).data).toMatchObject({ ok: true, root: human.did, capability: "search" });
    expect(executed.at(-1)).toEqual({ user: caller.did, mandateOk: true });
  });

  it("an untrusted mandate is refused: the SDK agent answers TASK_STATE_REJECTED", async () => {
    const r = await sendMessage(`${base}/a2a`, msg({ capability: "search" }), { mandateToken: selfRootedToken, headers: headers() });
    expect(r.kind).toBe("task");
    const t = (r as { task: { status: { state: string; message?: A2AMessage } } }).task;
    expect(t.status.state).toBe("TASK_STATE_REJECTED");
    expect((t.status.message?.parts[0] as { text: string }).text).toMatch(/root|trusted|expected/i);
    expect(executed.at(-1)).toEqual({ user: caller.did, mandateOk: false });
  });

  it("getTask and cancelTask against the SDK's task store", async () => {
    const r = await sendMessage(`${base}/a2a`, msg({ capability: "long-job" }), { mandateToken: goodToken, headers: headers() });
    expect(r.kind).toBe("task");
    const id = (r as { task: { id: string } }).task.id;
    expect((await getTask(`${base}/a2a`, id, { headers: headers() })).status.state).toBe("TASK_STATE_WORKING");
    expect((await cancelTask(`${base}/a2a`, id, { headers: headers() })).status.state).toBe("TASK_STATE_CANCELED");
    expect((await getTask(`${base}/a2a`, id, { headers: headers() })).status.state).toBe("TASK_STATE_CANCELED");
    await expect(getTask(`${base}/a2a`, "no-such-task", { headers: headers() }))
      .rejects.toMatchObject({ code: A2A_ERROR_CODE.TASK_NOT_FOUND });
  });

  it("without a mandate the SDK refuses: its card marks the extension required and the bridge only declares it when one is attached", async () => {
    const n = executed.length;
    await expect(sendMessage(`${base}/a2a`, msg({ capability: "search" }), { headers: headers() }))
      .rejects.toMatchObject({ name: "A2AJsonRpcError", code: A2A_ERROR_CODE.EXTENSION_SUPPORT_REQUIRED });
    expect(executed.length).toBe(n);
  });

  it("the SDK server rejects a request without A2A-Version 1.0, which the bridge client always sends", async () => {
    const res = await fetch(`${base}/a2a`, {
      method: "POST", headers: { "content-type": "application/json", ...headers() },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "SendMessage", params: { message: msg({}) } }),
    });
    expect((await res.json()).error.code).toBe(A2A_ERROR_CODE.VERSION_NOT_SUPPORTED);
    await expect(sendMessage(`${base}/a2a`, msg({}), { mandateToken: goodToken, headers: headers() })).resolves.toBeDefined();
  });

  it("a JSON-RPC error from the SDK surfaces as A2AJsonRpcError with the spec code", async () => {
    // An empty messageId is a validation error on the SDK side.
    await expect(sendMessage(`${base}/a2a`, { ...msg({}), messageId: "" }, { mandateToken: goodToken, headers: headers() }))
      .rejects.toBeInstanceOf(A2AJsonRpcError);
  });
});
