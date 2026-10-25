// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Outbound fetch for URLs the server did not choose itself.
 *
 * Agent endpoints come from registry records — data whoever registered the
 * agent controls. On a hosted, multi-user server an unchecked fetch would let
 * a registrant point the server at internal addresses (cloud metadata,
 * admin ports, the LAN). This helper:
 *
 *   1. resolves the host (all addresses) and refuses the request when ANY of
 *      them is loopback, unspecified, private (RFC 1918), CGNAT (100.64/10),
 *      link-local (169.254/16, fe80::/10), unique-local (fc00::/7),
 *      multicast/reserved, or an IPv4-mapped/compatible form of those —
 *      unless the operator sets `allowPrivate` (AROHA_ALLOW_PRIVATE_ENDPOINTS=1,
 *      development only);
 *   2. pins the connection to the vetted address (the socket's lookup only
 *      ever returns it), so a second DNS answer cannot swap the target;
 *   3. refuses redirects and caps the response size and time.
 */

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP, BlockList } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type HostLookup = (hostname: string) => Promise<ResolvedAddress[]>;

export interface SafeFetchOptions {
  /** DEVELOPMENT ONLY: allow private, loopback and link-local targets. */
  allowPrivate?: boolean;
  /** Response body cap in bytes. Default 1 MiB. */
  maxBytes?: number;
  /** Overall timeout in ms. Default 30 s. */
  timeoutMs?: number;
  /** Abort the request early (task cancellation). */
  signal?: AbortSignal;
  /** DNS resolver (tests). Default: dns.lookup with all addresses. */
  lookup?: HostLookup;
}

export interface SafeResponse {
  status: number;
  ok: boolean;
  headers: Headers;
  text: string;
  /** The address the connection was pinned to. */
  address: string;
}

export class EndpointRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EndpointRefusedError";
  }
}

export class ResponseTooLargeError extends Error {
  constructor(max: number) {
    super(`response exceeded ${max} bytes`);
    this.name = "ResponseTooLargeError";
  }
}

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32], ["64:ff9b::", 96], ["100::", 64], ["2002::", 16],
] as const) blocked.addSubnet(net, prefix, "ipv6");

/** IPv4 embedded in an IPv4-mapped (::ffff:a.b.c.d / ::ffff:xxxx:xxxx) or IPv4-compatible IPv6 address. */
function embeddedIpv4(address: string): string | null {
  const lower = address.toLowerCase();
  const dotted = /^(?:::ffff:|::)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (dotted) return dotted[1];
  const hex = /^(?:::ffff:|::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

/** Whether an IP address is a non-public target. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family === 6) {
    const v4 = embeddedIpv4(address);
    if (v4) return blocked.check(v4, "ipv4");
    return blocked.check(address, "ipv6");
  }
  return true; // not an IP at all: refuse
}

const defaultLookup: HostLookup = async (hostname) =>
  (await dnsLookup(hostname, { all: true, verbatim: true })).map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));

/** Resolve and vet a URL's host. Returns the single address to pin to. */
export async function vetEndpoint(url: URL, opts: Pick<SafeFetchOptions, "allowPrivate" | "lookup"> = {}): Promise<ResolvedAddress> {
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new EndpointRefusedError(`unsupported scheme ${url.protocol}`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  let addresses: ResolvedAddress[];
  const literal = isIP(host);
  if (literal) {
    addresses = [{ address: host, family: literal === 6 ? 6 : 4 }];
  } else {
    try {
      addresses = await (opts.lookup ?? defaultLookup)(host);
    } catch {
      throw new EndpointRefusedError(`cannot resolve ${host}`);
    }
  }
  if (addresses.length === 0) throw new EndpointRefusedError(`cannot resolve ${host}`);
  if (!opts.allowPrivate) {
    // Every answer must be public: a mixed answer is how a resolver steers
    // a later connection to an internal address.
    for (const a of addresses) {
      if (isBlockedAddress(a.address)) throw new EndpointRefusedError(`${host} resolves to a non-public address`);
    }
  }
  return addresses[0];
}

async function readCapped(body: ReadableStream<Uint8Array> | null, max: number): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new ResponseTooLargeError(max);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Fetch `url` with the endpoint vetted and the connection pinned to the vetted address. */
export async function safeFetch(url: string | URL, init: { method?: string; headers?: Record<string, string>; body?: string } = {}, opts: SafeFetchOptions = {}): Promise<SafeResponse> {
  const target = new URL(url);
  const pinned = await vetEndpoint(target, opts);
  opts.signal?.throwIfAborted();
  const agent = new Agent({
    connect: {
      // The socket never resolves the name again: it gets the vetted address.
      lookup: (_hostname: string, options: { all?: boolean } | undefined, cb: (...args: unknown[]) => void) => {
        if (options?.all) cb(null, [{ address: pinned.address, family: pinned.family }]);
        else cb(null, pinned.address, pinned.family);
      },
    } as never,
  });
  try {
    const res = await undiciFetch(target, {
      method: init.method ?? "GET",
      headers: init.headers,
      body: init.body,
      redirect: "error",
      dispatcher: agent,
      signal: opts.signal
        ? AbortSignal.any([opts.signal, AbortSignal.timeout(opts.timeoutMs ?? 30_000)])
        : AbortSignal.timeout(opts.timeoutMs ?? 30_000),
    });
    const text = await readCapped(res.body as ReadableStream<Uint8Array> | null, opts.maxBytes ?? 1_048_576);
    return { status: res.status, ok: res.ok, headers: res.headers as unknown as Headers, text, address: pinned.address };
  } finally {
    await agent.close().catch(() => {});
  }
}
