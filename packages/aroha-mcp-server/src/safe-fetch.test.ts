// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** Outbound endpoint vetting: no private targets, pinned connection, no redirects, capped bodies. */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { isBlockedAddress, safeFetch, vetEndpoint, EndpointRefusedError, ResponseTooLargeError, type HostLookup } from "./safe-fetch.js";

let server: Server;
let port = 0;
beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === "/redirect") { res.writeHead(302, { Location: "http://169.254.169.254/latest" }); res.end(); return; }
    if (req.url === "/big") { res.writeHead(200); res.end("x".repeat(5000)); return; }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("hello");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const a = server.address();
  port = typeof a === "object" && a ? a.port : 0;
});
afterAll(async () => {
  await new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections?.(); });
});

describe("isBlockedAddress", () => {
  it.each([
    "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254",
    "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:a9fe:a9fe", "224.0.0.1",
  ])("refuses %s", (ip) => expect(isBlockedAddress(ip)).toBe(true));
  it.each(["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])("allows %s", (ip) => expect(isBlockedAddress(ip)).toBe(false));
});

describe("vetEndpoint / safeFetch", () => {
  it("refuses a private-range endpoint, literal or resolved, and a mixed DNS answer", async () => {
    await expect(vetEndpoint(new URL(`http://127.0.0.1:${port}/`))).rejects.toBeInstanceOf(EndpointRefusedError);
    await expect(safeFetch(`http://127.0.0.1:${port}/`)).rejects.toBeInstanceOf(EndpointRefusedError);
    const priv: HostLookup = async () => [{ address: "10.0.0.5", family: 4 }];
    await expect(vetEndpoint(new URL("https://agent.example/"), { lookup: priv })).rejects.toThrow(/non-public/);
    const mixed: HostLookup = async () => [{ address: "93.184.216.34", family: 4 }, { address: "192.168.0.10", family: 4 }];
    await expect(vetEndpoint(new URL("https://agent.example/"), { lookup: mixed })).rejects.toThrow(/non-public/);
    const mapped: HostLookup = async () => [{ address: "::ffff:169.254.169.254", family: 6 }];
    await expect(vetEndpoint(new URL("https://agent.example/"), { lookup: mapped })).rejects.toThrow(/non-public/);
  });

  it("pins the connection: a second (rebinding) DNS answer is never consulted", async () => {
    let calls = 0;
    // First answer is the vetted one; any later answer would point elsewhere.
    const rebinding: HostLookup = async () => (++calls === 1 ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "203.0.113.9", family: 4 }]);
    const r = await safeFetch(`http://rebind.test:${port}/`, {}, { allowPrivate: true, lookup: rebinding, timeoutMs: 5000 });
    expect(r.text).toBe("hello");
    expect(r.address).toBe("127.0.0.1");
    expect(calls).toBe(1);
  });

  it("refuses redirects and caps the body", async () => {
    await expect(safeFetch(`http://127.0.0.1:${port}/redirect`, {}, { allowPrivate: true })).rejects.toThrow();
    await expect(safeFetch(`http://127.0.0.1:${port}/big`, {}, { allowPrivate: true, maxBytes: 1000 })).rejects.toBeInstanceOf(ResponseTooLargeError);
  });
});
