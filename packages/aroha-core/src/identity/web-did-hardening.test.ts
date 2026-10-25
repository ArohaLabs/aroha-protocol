// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * M1: did:aroha-web resolution only fetches the host the DID names — hostname
 * validation, path grammar, no redirects, bounded document size — and the
 * Node default DNS resolver is used when none is injected.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateWebAgent, resolveWebDID, parseWebDID, wellKnownUrl } from "./web-did.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);
afterEach(() => { vi.unstubAllGlobals(); });

const quiet = { logger: () => {} };

describe("parseWebDID validation", () => {
  it("accepts plain hostnames and the path grammar", () => {
    expect(parseWebDID("did:aroha-web:acme.com:pay:eu")).toEqual({ domain: "acme.com", path: "pay/eu" });
    expect(parseWebDID("did:aroha-web:sub.acme-corp.io")).toEqual({ domain: "sub.acme-corp.io", path: "agent" });
  });

  it("refuses userinfo, ports, IP literals and odd characters in the domain", () => {
    for (const d of [
      "did:aroha-web:evil.com@10.0.0.5:x",
      "did:aroha-web:10.0.0.5:x",
      "did:aroha-web:127.0.0.1",
      "did:aroha-web:[::1]:x",
      "did:aroha-web:acme.com%2F..:x",
      "did:aroha-web:-acme.com:x",
      "did:aroha-web::x",
      "did:aroha-web:acme.123:x",
    ]) {
      expect(() => parseWebDID(d), d).toThrow();
    }
  });

  it("allowIpLiteral admits an IPv4 literal", () => {
    expect(parseWebDID("did:aroha-web:10.0.0.5:x", { allowIpLiteral: true }).domain).toBe("10.0.0.5");
    expect(() => parseWebDID("did:aroha-web:10.0.0.500:x", { allowIpLiteral: true })).toThrow();
  });

  it("refuses paths outside ^[a-z0-9-]+(/[a-z0-9-]+)*$", () => {
    for (const d of ["did:aroha-web:acme.com:..:x", "did:aroha-web:acme.com:a?b", "did:aroha-web:acme.com:A", "did:aroha-web:acme.com:a::b"]) {
      expect(() => wellKnownUrl(d), d).toThrow(/path/);
    }
  });
});

describe("resolveWebDID fetch hardening", () => {
  it("fetches with redirect: 'error'", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const f = vi.fn(async () => new Response(JSON.stringify(a.webDocument)));
    vi.stubGlobal("fetch", f);
    await resolveWebDID(a.did, { dnsResolver: async () => [a.dnsTXTRecord], ...quiet });
    expect((f.mock.calls[0] as unknown[])[1]).toMatchObject({ redirect: "error" });
  });

  it("refuses a document over the size cap, declared or streamed", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    const big = JSON.stringify({ ...a.webDocument, pad: "x".repeat(70_000) });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(big)));
    await expect(resolveWebDID(a.did, { dnsResolver: async () => [a.dnsTXTRecord], ...quiet })).rejects.toThrow(/too large/);
    // A stream with no content-length must still be cut off.
    const stream = new ReadableStream<Uint8Array>({
      start(c) { for (let i = 0; i < 20; i++) c.enqueue(new Uint8Array(8192)); c.close(); },
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(stream)));
    await expect(resolveWebDID(a.did, { dnsResolver: async () => [a.dnsTXTRecord], ...quiet })).rejects.toThrow(/too large/);
  });

  it("uses node:dns resolveTxt when no resolver is injected (E5)", async () => {
    const a = await generateWebAgent("acme.com", "pay");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(a.webDocument))));
    // Builtin ESM namespaces are frozen; patch the CJS object and sync the
    // named exports, which is what the resolver's dynamic import sees.
    const dns = (await import("node:dns/promises")).default;
    const { syncBuiltinESMExports } = await import("node:module");
    const spy = vi.spyOn(dns, "resolveTxt").mockResolvedValue([[a.dnsTXTRecord.slice(0, 10), a.dnsTXTRecord.slice(10)]]);
    syncBuiltinESMExports();
    try {
      const r = await resolveWebDID(a.did, quiet);
      expect(spy).toHaveBeenCalledWith("_aroha.acme.com");
      expect(r.dnsVerified).toBe(true);
    } finally {
      spy.mockRestore();
      syncBuiltinESMExports();
    }
  });
});
