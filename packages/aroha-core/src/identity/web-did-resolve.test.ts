// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Exercises resolveWebDID's actual HTTPS-fetch + DNS-TXT resolution path —
 * previously covered only indirectly via verifyKeyRotation's signature
 * logic (did.test.ts), never the fetch/DNS plumbing itself. This mocks
 * global fetch (the well-known URL is a hardcoded https://{domain}/...
 * that a local test server can't bind to under its own name) and supplies
 * a custom dnsResolver, exactly the injection point resolveWebDID's own
 * doc comment says Node callers must use.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateWebAgent, resolveWebDID, dnsTXTValue } from "./web-did.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

function mockFetchServing(document: unknown, ok = true) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(document), { status: ok ? 200 : 404 })));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("resolveWebDID", () => {
  it("resolves with both channels verified when HTTPS document and DNS TXT agree", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    mockFetchServing(agent.webDocument);
    const dnsResolver = async () => [agent.dnsTXTRecord];

    const result = await resolveWebDID(agent.did, true, dnsResolver);

    expect(result.document.id).toBe(agent.did);
    expect(result.dnsVerified).toBe(true);
    expect(result.keyTrusted).toBe(true);
  });

  it("dnsVerified is false when the DNS TXT record doesn't match the served document's key", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    const otherAgent = await generateWebAgent("acme.com", "test-agent");
    mockFetchServing(agent.webDocument);
    // A different key's commitment — as if DNS is stale, unset, or an
    // attacker controls the HTTPS endpoint but not DNS.
    const dnsResolver = async () => [dnsTXTValue(agent.did, otherAgent.publicKey)];

    const result = await resolveWebDID(agent.did, true, dnsResolver);
    expect(result.dnsVerified).toBe(false);
  });

  it("dnsVerified is false when the resolver returns no matching records at all", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    mockFetchServing(agent.webDocument);
    const dnsResolver = async () => [];

    const result = await resolveWebDID(agent.did, true, dnsResolver);
    expect(result.dnsVerified).toBe(false);
  });

  it("skips DNS verification entirely when verifyDNS is false (single-channel HTTPS-only mode)", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    mockFetchServing(agent.webDocument);

    const result = await resolveWebDID(agent.did, false);
    expect(result.dnsVerified).toBe(false); // not attempted, not "false because it failed"
    expect(result.document.id).toBe(agent.did);
  });

  it("throws when the HTTPS fetch fails (non-2xx)", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    mockFetchServing(agent.webDocument, false);

    await expect(resolveWebDID(agent.did, false)).rejects.toThrow(/HTTP 404/);
  });

  it("throws when the served document's id doesn't match the requested DID (domain confusion / cache poisoning)", async () => {
    const agent = await generateWebAgent("acme.com", "test-agent");
    const otherAgent = await generateWebAgent("evil.com", "test-agent");
    // Serve a document claiming to be a DIFFERENT identity than what was requested.
    mockFetchServing(otherAgent.webDocument);

    await expect(resolveWebDID(agent.did, false)).rejects.toThrow(/DID mismatch/);
  });

  it("keyTrusted is false during a rotation's cool-down window", async () => {
    const { rotateKey } = await import("./web-did.js");
    const agent = await generateWebAgent("acme.com", "test-agent");
    const rotated = await rotateKey(agent, 24); // 24h cool-down, not yet elapsed
    mockFetchServing(rotated.webDocument);

    const result = await resolveWebDID(rotated.did, false);
    expect(result.keyTrusted).toBe(false);
    expect(result.trustReason).toMatch(/cool-down/);
  });
});
