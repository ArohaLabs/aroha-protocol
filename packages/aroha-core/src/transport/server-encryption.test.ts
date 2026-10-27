// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ArohaServer's requireEncryption option (design spec §6.1, M9) — real HTTP
 * requests against a real running server, not a mocked handleHttp call.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDID } from "../identity/did.js";
import { buildEnvelope } from "../messages/envelope.js";
import { sealEnvelope } from "./seal.js";
import { ArohaServer } from "./server.js";
import type { ArohaRequestBody } from "../messages/types.js";
import type { Server } from "http";
import type { AddressInfo } from "net";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

let server: ArohaServer | undefined;

afterEach(async () => {
  if (server) {
    await server.stop();
    server = undefined;
  }
});

async function keypair() {
  const privateKey = ed.utils.randomPrivateKey();
  return { privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
}

/** The port the OS assigned to a server started with port: 0. */
function boundPort(s: ArohaServer): number {
  return ((s as unknown as { server: Server }).server.address() as AddressInfo).port;
}

describe("ArohaServer requireEncryption (spec §6.1 — mandatory off-TLS encryption)", () => {
  it("accepts a properly sealed envelope, unseals it, and dispatches the real plaintext to onMessage", async () => {
    const recipient = await generateDID("recipient-agent", "http://127.0.0.1/recipient");
    const sender = await keypair();

    let receivedBody: ArohaRequestBody | undefined;
    server = new ArohaServer({
      agentDID: recipient.did,
      didDocument: recipient.document,
      port: 0,
      requireEncryption: true,
      privateKey: recipient.privateKey,
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async (envelope, respond) => {
        receivedBody = envelope.body as ArohaRequestBody;
        respond(await buildEnvelope("ArohaResponse", recipient.did, envelope.from, { capability: "test", result: {} }, envelope.correlationId, recipient.privateKey));
      },
    });
    await server.start();
    const port = boundPort(server);

    const body: ArohaRequestBody = { capability: "book-flight", params: { origin: "JFK" } };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", recipient.did, body, "corr-1", sender.privateKey);
    const sealed = await sealEnvelope(envelope, recipient.publicKey);

    const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealed),
    });

    expect(res.status).toBe(200);
    expect(receivedBody).toEqual(body); // the server actually saw the real plaintext, not ciphertext
  });

  it("rejects a plaintext (unsealed) envelope on a requireEncryption listener", async () => {
    const recipient = await generateDID("recipient-agent-2", "http://127.0.0.1/recipient");
    const sender = await keypair();

    let dispatched = false;
    server = new ArohaServer({
      agentDID: recipient.did,
      didDocument: recipient.document,
      port: 0,
      requireEncryption: true,
      privateKey: recipient.privateKey,
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async () => { dispatched = true; },
    });
    await server.start();
    const port = boundPort(server);

    const body: ArohaRequestBody = { capability: "book-flight", params: {} };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", recipient.did, body, "corr-1", sender.privateKey);

    // Sent in cleartext — exactly what mandatory encryption must refuse.
    const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(400);
    const json = await res.json() as { code: string };
    expect(json.code).toBe("Aroha_INVALID_PARAMS");
    expect(dispatched).toBe(false);
  });

  it("rejects a sealed envelope encrypted for a different recipient", async () => {
    const recipient = await generateDID("recipient-agent-3", "http://127.0.0.1/recipient");
    const wrongRecipient = await keypair();
    const sender = await keypair();

    let dispatched = false;
    server = new ArohaServer({
      agentDID: recipient.did,
      didDocument: recipient.document,
      port: 0,
      requireEncryption: true,
      privateKey: recipient.privateKey, // the REAL recipient's key
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async () => { dispatched = true; },
    });
    await server.start();
    const port = boundPort(server);

    const body: ArohaRequestBody = { capability: "book-flight", params: {} };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", recipient.did, body, "corr-1", sender.privateKey);
    // Sealed for someone else's public key — recipient.privateKey cannot open this.
    const sealed = await sealEnvelope(envelope, wrongRecipient.publicKey);

    const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealed),
    });

    expect(res.status).toBe(400);
    expect(dispatched).toBe(false);
  });

  it("constructor throws if requireEncryption is set with no privateKey", async () => {
    const recipient = await generateDID("recipient-agent-4", "http://127.0.0.1/recipient");
    expect(() => new ArohaServer({
      agentDID: recipient.did,
      didDocument: recipient.document,
      port: 0,
      requireEncryption: true,
      resolvePublicKey: async () => null,
      onMessage: async () => {},
    })).toThrow(/privateKey or resolvePrivateKey is required/);
  });

  it("an ordinary (requireEncryption unset) server still accepts a plaintext envelope — no behavior change for TLS-fronted deployments", async () => {
    const recipient = await generateDID("recipient-agent-5", "http://127.0.0.1/recipient");
    const sender = await keypair();

    let dispatched = false;
    server = new ArohaServer({
      agentDID: recipient.did,
      didDocument: recipient.document,
      port: 0,
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async (_env, respond) => {
        dispatched = true;
        respond(await buildEnvelope("ArohaResponse", recipient.did, "did:aroha:sender", { capability: "test", result: {} }, "corr-1", recipient.privateKey));
      },
    });
    await server.start();
    const port = boundPort(server);

    const body: ArohaRequestBody = { capability: "book-flight", params: {} };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", recipient.did, body, "corr-1", sender.privateKey);

    const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(200);
    expect(dispatched).toBe(true);
  });
});

describe("ArohaServer resolvePrivateKey (multi-agent listener)", () => {
  it("routes an inbound sealed envelope to the right agent's key by its cleartext `to` field", async () => {
    const agentA = await generateDID("multi-agent-a", "http://127.0.0.1/a");
    const agentB = await generateDID("multi-agent-b", "http://127.0.0.1/b");
    const sender = await keypair();

    const keysByDID = new Map<string, Uint8Array>([
      [agentA.did, agentA.privateKey],
      [agentB.did, agentB.privateKey],
    ]);

    const receivedBy: string[] = [];
    server = new ArohaServer({
      agentDID: agentA.did, // the listener's own "primary" identity for its well-known doc; irrelevant to routing
      didDocument: agentA.document,
      port: 0,
      requireEncryption: true,
      resolvePrivateKey: (recipientDID) => keysByDID.get(recipientDID),
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async (envelope, respond) => {
        receivedBy.push(envelope.to);
        respond(await buildEnvelope("ArohaResponse", envelope.to, envelope.from, { capability: "test", result: {} }, envelope.correlationId, keysByDID.get(envelope.to)!));
      },
    });
    await server.start();
    const port = boundPort(server);

    // A request sealed for agent B — the listener holds agent A's key too, but must not use it here.
    const bodyForB: ArohaRequestBody = { capability: "chat", params: { message: "hi B" } };
    const envelopeForB = await buildEnvelope("ArohaRequest", "did:aroha:sender", agentB.did, bodyForB, "corr-b", sender.privateKey);
    const sealedForB = await sealEnvelope(envelopeForB, agentB.publicKey);

    const resB = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealedForB),
    });
    expect(resB.status).toBe(200);

    // A second request, sealed for agent A instead — same listener, same port.
    const bodyForA: ArohaRequestBody = { capability: "chat", params: { message: "hi A" } };
    const envelopeForA = await buildEnvelope("ArohaRequest", "did:aroha:sender", agentA.did, bodyForA, "corr-a", sender.privateKey);
    const sealedForA = await sealEnvelope(envelopeForA, agentA.publicKey);

    const resA = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealedForA),
    });
    expect(resA.status).toBe(200);

    expect(receivedBy).toEqual([agentB.did, agentA.did]);
  });

  it("rejects an envelope addressed to a DID the resolver doesn't recognize, rather than falling back to any held key", async () => {
    const agentA = await generateDID("multi-agent-c", "http://127.0.0.1/c");
    const sender = await keypair();
    const stranger = await generateDID("multi-agent-stranger", "http://127.0.0.1/stranger");

    let dispatched = false;
    server = new ArohaServer({
      agentDID: agentA.did,
      didDocument: agentA.document,
      port: 0,
      requireEncryption: true,
      resolvePrivateKey: (recipientDID) => (recipientDID === agentA.did ? agentA.privateKey : undefined),
      resolvePublicKey: async () => sender.publicKey,
      onMessage: async () => { dispatched = true; },
    });
    await server.start();
    const port = boundPort(server);

    const body: ArohaRequestBody = { capability: "chat", params: {} };
    const envelope = await buildEnvelope("ArohaRequest", "did:aroha:sender", stranger.did, body, "corr-1", sender.privateKey);
    const sealed = await sealEnvelope(envelope, stranger.publicKey);

    const res = await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sealed),
    });

    expect(res.status).toBe(400);
    expect(dispatched).toBe(false);
  });

  it("constructor accepts resolvePrivateKey in place of privateKey", () => {
    expect(() => new ArohaServer({
      agentDID: "did:aroha:x",
      didDocument: { "@context": [], id: "did:aroha:x", verificationMethod: [] } as never,
      port: 0,
      requireEncryption: true,
      resolvePrivateKey: () => undefined,
      resolvePublicKey: async () => null,
      onMessage: async () => {},
    })).not.toThrow();
  });
});
