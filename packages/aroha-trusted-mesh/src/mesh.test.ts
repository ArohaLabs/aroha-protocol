// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import type { IncomingMessage } from "node:http";
import { ipInCidr, ipInAnyRange } from "./cidr.js";
import { createTrustedMeshOptions, createTrustedZone, TrustedMeshClient } from "./mesh.js";

// ─── ipInCidr ────────────────────────────────────────────────────────────────

describe("ipInCidr", () => {
  it("matches an IP within a /24 range", () => {
    expect(ipInCidr("192.168.1.50", "192.168.1.0/24")).toBe(true);
  });

  it("rejects an IP outside the /24 range", () => {
    expect(ipInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  it("matches any IP for 0.0.0.0/0", () => {
    expect(ipInCidr("8.8.8.8", "0.0.0.0/0")).toBe(true);
    expect(ipInCidr("10.0.0.1", "0.0.0.0/0")).toBe(true);
  });

  it("matches the exact host IP for /32", () => {
    expect(ipInCidr("10.0.0.5", "10.0.0.5/32")).toBe(true);
    expect(ipInCidr("10.0.0.6", "10.0.0.5/32")).toBe(false);
  });

  it("matches the network address itself", () => {
    expect(ipInCidr("10.0.0.0", "10.0.0.0/8")).toBe(true);
  });

  it("L15: a malformed address never matches; a malformed CIDR throws", () => {
    // These all used to parse to 0 and match 0.0.0.0/8.
    for (const bad of ["garbage", "", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.-4", "::1"]) {
      expect(ipInCidr(bad, "0.0.0.0/8"), bad).toBe(false);
    }
    for (const bad of ["10.0.0.0/33", "10.0.0/8", "x/8", "10.0.0.0/8/1", "10.0.0.0/-1"]) {
      expect(() => ipInCidr("10.0.0.1", bad), bad).toThrow(/Invalid CIDR/);
    }
  });

  it("compares IPv4-mapped IPv6 addresses as IPv4", () => {
    expect(ipInCidr("::ffff:10.1.2.3", "10.0.0.0/8")).toBe(true);
  });

  it("matches IPs across a /8 range", () => {
    expect(ipInCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);
    expect(ipInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
  });

  it("falls back to exact string match when no prefix length", () => {
    expect(ipInCidr("1.2.3.4", "1.2.3.4")).toBe(true);
    expect(ipInCidr("1.2.3.5", "1.2.3.4")).toBe(false);
  });
});

describe("ipInAnyRange", () => {
  it("returns true when IP matches any CIDR in the list", () => {
    expect(ipInAnyRange("10.0.0.1", ["192.168.0.0/16", "10.0.0.0/8"])).toBe(true);
  });

  it("returns false when IP matches none", () => {
    expect(ipInAnyRange("172.16.0.1", ["10.0.0.0/8", "192.168.0.0/16"])).toBe(false);
  });

  it("returns false for an empty range list", () => {
    expect(ipInAnyRange("10.0.0.1", [])).toBe(false);
  });
});

// ─── createTrustedMeshOptions ────────────────────────────────────────────────

/** A request as the server sees it — only the socket address matters here. */
function reqFrom(remoteAddress: string): IncomingMessage {
  return { socket: { remoteAddress } } as unknown as IncomingMessage;
}
const LOCAL = reqFrom("127.0.0.1");

describe("createTrustedMeshOptions", () => {
  it("allows an explicitly listed DID arriving over loopback (the default network)", () => {
    const opts = createTrustedMeshOptions({ trustedDIDs: ["did:aroha:agent-a"] });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:agent-a")).toBe(true);
    expect(opts.bypassSignatureForRequest(reqFrom("::1"), "did:aroha:agent-a")).toBe(true);
  });

  it("refuses an allow-listed DID that arrives from outside the trusted networks", () => {
    // The impersonation this module used to allow: with signatures skipped,
    // `from` is just a string the sender wrote.
    const opts = createTrustedMeshOptions({ trustedDIDs: ["did:aroha:agent-a"] });
    expect(opts.bypassSignatureForRequest(reqFrom("203.0.113.9"), "did:aroha:agent-a")).toBe(false);
  });

  it("does not expose the DID-only bypass at all", () => {
    const opts = createTrustedMeshOptions({ trustedDIDs: ["did:aroha:agent-a"] });
    expect((opts as Record<string, unknown>).bypassSignatureFor).toBeUndefined();
  });

  it("honours named networks, including IPv4 clients on a dual-stack socket", () => {
    const opts = createTrustedMeshOptions({
      trustedDIDs: ["did:aroha:agent-a"],
      trustedNetworks: ["10.0.0.0/8", "fd00::/8"],
    });
    expect(opts.bypassSignatureForRequest(reqFrom("10.1.2.3"), "did:aroha:agent-a")).toBe(true);
    expect(opts.bypassSignatureForRequest(reqFrom("::ffff:10.1.2.3"), "did:aroha:agent-a")).toBe(true);
    expect(opts.bypassSignatureForRequest(reqFrom("fd12::1"), "did:aroha:agent-a")).toBe(true);
    // Loopback is not implied once networks are named.
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:agent-a")).toBe(false);
  });

  it("requires a custom transport check to pass as well", () => {
    const opts = createTrustedMeshOptions({
      trustedDIDs: ["did:aroha:agent-a"],
      isTrustedTransport: () => false,
    });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:agent-a")).toBe(false);
  });

  it("rejects a malformed network entry at construction", () => {
    expect(() => createTrustedMeshOptions({ trustedDIDs: [], trustedNetworks: ["not-an-ip"] })).toThrow(/not an IP/);
  });

  it("rejects a DID not in the allowlist even on a trusted network", () => {
    const opts = createTrustedMeshOptions({ trustedDIDs: ["did:aroha:agent-a"] });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:agent-b")).toBe(false);
  });

  it("allows a DID matching a trusted prefix", () => {
    const opts = createTrustedMeshOptions({
      trustedDIDs: [],
      trustedPrefixes: ["did:aroha:internal:"],
    });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:internal:billing")).toBe(true);
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:external:billing")).toBe(false);
  });

  it("combines allowlist and prefix matching (OR logic)", () => {
    const opts = createTrustedMeshOptions({
      trustedDIDs: ["did:aroha:special-agent"],
      trustedPrefixes: ["did:aroha:svc:"],
    });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:special-agent")).toBe(true);
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:svc:payments")).toBe(true);
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:other")).toBe(false);
  });

  it("returns false for all DIDs when both lists are empty", () => {
    const opts = createTrustedMeshOptions({ trustedDIDs: [] });
    expect(opts.bypassSignatureForRequest(LOCAL, "did:aroha:anyone")).toBe(false);
  });
});

// ─── createTrustedZone ────────────────────────────────────────────────────────

describe("createTrustedZone", () => {
  const DIDS = ["did:aroha:agent-a", "did:aroha:agent-b"];

  it("produces server options that trust all zone members on a trusted network", () => {
    const zone = createTrustedZone(DIDS);
    for (const did of DIDS) {
      expect(zone.serverOptions.bypassSignatureForRequest(LOCAL, did)).toBe(true);
    }
  });

  it("does not trust DIDs outside the zone", () => {
    const zone = createTrustedZone(DIDS);
    expect(zone.serverOptions.bypassSignatureForRequest(LOCAL, "did:aroha:outsider")).toBe(false);
  });

  it("passes zone networks through", () => {
    const zone = createTrustedZone(DIDS, undefined, { trustedNetworks: ["10.0.0.0/8"] });
    expect(zone.serverOptions.bypassSignatureForRequest(reqFrom("10.9.9.9"), DIDS[0])).toBe(true);
    expect(zone.serverOptions.bypassSignatureForRequest(LOCAL, DIDS[0])).toBe(false);
  });

  it("createClient returns a TrustedMeshClient", () => {
    const zone = createTrustedZone(DIDS);
    const client = zone.createClient("did:aroha:agent-a", "did:aroha:agent-b");
    expect(client).toBeInstanceOf(TrustedMeshClient);
  });

  it("supports prefix-based zones", () => {
    const zone = createTrustedZone([], ["did:aroha:mesh:"]);
    expect(zone.serverOptions.bypassSignatureForRequest(LOCAL, "did:aroha:mesh:node-1")).toBe(true);
    expect(zone.serverOptions.bypassSignatureForRequest(LOCAL, "did:aroha:external:node-1")).toBe(false);
  });
});
