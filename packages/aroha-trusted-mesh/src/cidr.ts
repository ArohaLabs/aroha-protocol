// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Minimal CIDR matching for trusted mesh IP allowlisting.
 * Supports IPv4 CIDR notation (e.g. "10.0.0.0/8", "192.168.1.0/24").
 *
 * Strict parsing (L15). The old parser ran parseInt on each dot-separated
 * piece and OR-ed the results together, so a malformed address became NaN,
 * NaN became 0 under the bit operators, and "not an IP at all" matched
 * 0.0.0.0/8 — an allowlist decision made on garbage. Now:
 *   - a malformed CIDR (or bit count outside 0–32) THROWS: it is a
 *     configuration error and must surface at once;
 *   - a malformed or non-IPv4 address simply does not match (fail closed),
 *     since remote addresses are input, not configuration.
 * IPv4-mapped IPv6 addresses ("::ffff:10.0.0.1", which Node reports for
 * IPv4 clients on a dual-stack socket) are compared as their IPv4 form.
 */

const OCTET = /^(0|[1-9]\d{0,2})$/;

/** Parse dotted-quad IPv4 into an unsigned 32-bit integer, or null if malformed. */
function parseIPv4(ip: string): number | null {
  const s = ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!OCTET.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

function parseCidr(cidr: string): { network: number; mask: number } {
  const [network, bits, extra] = cidr.split("/");
  const net = network === undefined ? null : parseIPv4(network);
  if (net === null || extra !== undefined) throw new Error(`Invalid CIDR: ${cidr}`);
  if (bits === undefined) return { network: net, mask: 0xffffffff }; // a bare address matches exactly
  if (!/^\d{1,2}$/.test(bits) || Number(bits) > 32) throw new Error(`Invalid CIDR prefix length: ${cidr}`);
  const n = Number(bits);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return { network: net, mask };
}

/**
 * Returns true if the given IP address falls within the CIDR range.
 * Pass "0.0.0.0/0" to allow any IPv4 address. Throws on a malformed CIDR;
 * returns false for a malformed or non-IPv4 address.
 */
export function ipInCidr(ip: string, cidr: string): boolean {
  const { network, mask } = parseCidr(cidr);
  const addr = parseIPv4(ip);
  if (addr === null) return false;
  return ((addr & mask) >>> 0) === ((network & mask) >>> 0);
}

/**
 * Returns true if the IP matches any of the CIDR ranges.
 */
export function ipInAnyRange(ip: string, ranges: string[]): boolean {
  return ranges.some((cidr) => ipInCidr(ip, cidr));
}
