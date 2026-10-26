// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import {
  type ArohaClient,
  type ArohaEnvelope,
  buildEnvelope,
  buildUnsignedEnvelope,
  generateDid,
  generateKeyPair,
  verifyMessageSignature,
} from "@aroha-sdk/core";
import { TracingArohaClient } from "./middleware.js";
import { ArohaTracer } from "./tracer.js";

/** A stand-in ArohaClient that records what would go on the wire. */
function recordingClient() {
  const sent: ArohaEnvelope[] = [];
  const inner = {
    send: vi.fn(async (_endpoint: string, envelope: ArohaEnvelope) => {
      sent.push(envelope);
      return null;
    }),
    stream: vi.fn(),
    fetchDIDDocument: vi.fn(),
  } as unknown as ArohaClient;
  return { inner, sent };
}

async function sender() {
  const { privateKey, publicKey } = await generateKeyPair();
  return { privateKey, publicKey, did: generateDid(publicKey) };
}

const TO = "did:aroha:receiver";
const BODY = { capability: "test.echo", input: {} };

describe("TracingArohaClient", () => {
  it("signs the active span's traceparent into the envelope, and the receiver can verify it", async () => {
    const { privateKey, publicKey, did } = await sender();
    const { inner, sent } = recordingClient();
    const span = new ArohaTracer().startSagaSpan("saga-1");
    const client = new TracingArohaClient(inner);
    client.setActiveSpan(span);

    const envelope = await client.buildEnvelope("ArohaRequest", did, TO, BODY as never, "corr-1", privateKey);
    await client.send("https://receiver.example/aroha", envelope);

    const onWire = sent[0]!;
    expect(onWire.traceparent).toBe(span.traceparent());
    expect(await verifyMessageSignature(onWire as unknown as Record<string, unknown>, publicKey)).toBe(true);
  });

  it("never adds a traceparent to an envelope that is already signed", async () => {
    const { privateKey, publicKey, did } = await sender();
    const { inner, sent } = recordingClient();
    const client = new TracingArohaClient(inner);
    client.setActiveSpan(new ArohaTracer().startSagaSpan("saga-2"));

    const signed = await buildEnvelope("ArohaRequest", did, TO, BODY as never, "corr-2", privateKey);
    await client.send("https://receiver.example/aroha", signed);

    expect(sent[0]).toBe(signed);
    expect(sent[0]!.traceparent).toBeUndefined();
    expect(await verifyMessageSignature(sent[0] as unknown as Record<string, unknown>, publicKey)).toBe(true);
  });

  it("documents why: a traceparent added after signing breaks verification", async () => {
    const { privateKey, publicKey, did } = await sender();
    const signed = await buildEnvelope("ArohaRequest", did, TO, BODY as never, "corr-3", privateKey);
    const mutated = { ...signed, traceparent: new ArohaTracer().startSagaSpan("saga-3").traceparent() };
    expect(await verifyMessageSignature(mutated as unknown as Record<string, unknown>, publicKey)).toBe(false);
  });

  it("adds the active span's traceparent to an unsigned (trusted-mesh) envelope", async () => {
    const { did } = await sender();
    const { inner, sent } = recordingClient();
    const span = new ArohaTracer().startSagaSpan("saga-4");
    const client = new TracingArohaClient(inner);
    client.setActiveSpan(span);

    const unsigned = await buildUnsignedEnvelope("ArohaRequest", did, TO, BODY as never, "corr-4");
    await client.send("https://receiver.example/aroha", unsigned);

    expect(sent[0]!.traceparent).toBe(span.traceparent());
    expect(sent[0]!.proof).toBeUndefined();
  });

  it("an explicit traceparent takes precedence over the active span", async () => {
    const { privateKey, publicKey, did } = await sender();
    const { inner } = recordingClient();
    const client = new TracingArohaClient(inner);
    client.setActiveSpan(new ArohaTracer().startSagaSpan("saga-5"));
    const explicit = new ArohaTracer().startSagaSpan("other").traceparent();

    const envelope = await client.buildEnvelope("ArohaRequest", did, TO, BODY as never, "corr-5", privateKey, {
      traceparent: explicit,
    });

    expect(envelope.traceparent).toBe(explicit);
    expect(await verifyMessageSignature(envelope as unknown as Record<string, unknown>, publicKey)).toBe(true);
  });

  it("builds an envelope without a traceparent when no span is active", async () => {
    const { privateKey, did } = await sender();
    const { inner } = recordingClient();
    const client = new TracingArohaClient(inner);

    const envelope = await client.buildEnvelope("ArohaRequest", did, TO, BODY as never, "corr-6", privateKey);

    expect(envelope.traceparent).toBeUndefined();
  });
});
