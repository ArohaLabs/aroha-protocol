// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regenerates test-vectors/web-identity-v1.json.
 *
 *   npx vite-node scripts/gen-web-identity-vectors.ts
 *
 * The vectors are the cross-SDK contract for web identities (spec §4.7):
 * which strings are web identities, which IP addresses are special-use, how
 * a key id is derived, and which identity documents resolve to which key.
 * Everything is fixed (public keys from RFC 8032 §7.1; the first is also the
 * RFC 8037 appendix A example, whose RFC 7638 thumbprint is published there),
 * so regenerating must produce an identical file.
 */

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const out = fileURLToPath(new URL("../test-vectors/web-identity-v1.json", import.meta.url));
const hex = {
  k1: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  k2: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  k3: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
};
const x = Object.fromEntries(Object.entries(hex).map(([k, h]) => [k, Buffer.from(h, "hex").toString("base64url")])) as Record<keyof typeof hex, string>;
const thumb = (xv: string) => createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${xv}"}`).digest("base64url");
const jwk = (k: keyof typeof hex, extra: Record<string, unknown> = {}) => ({ kty: "OKP", crv: "Ed25519", x: x[k], kid: thumb(x[k]), use: "sig", alg: "EdDSA", ...extra });

const A = "https://agents.example.com/shopper";
const ok = (body: unknown, headers: Record<string, string> = {}) => ({ status: 200, headers: { "content-type": "application/json", ...headers }, body });

const documents = [
  { name: "inline key set", identity: A, responses: { [A]: ok({ client_id: A, client_name: "Shopper", jwks: { keys: [jwk("k1")] } }) }, expect: { keyHex: hex.k1, kid: thumb(x.k1) } },
  { name: "key set with only the three required JWK members", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: x.k1 }] } }) }, expect: { keyHex: hex.k1 } },
  { name: "alg Ed25519 (RFC 9864 name) is accepted", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [jwk("k1", { alg: "Ed25519" })] } }) }, expect: { keyHex: hex.k1, kid: thumb(x.k1) } },
  { name: "first eligible key wins", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [jwk("k2"), jwk("k1")] } }) }, expect: { keyHex: hex.k2, kid: thumb(x.k2) } },
  {
    name: "keys that cannot verify a mandate are skipped",
    identity: A,
    responses: {
      [A]: ok({
        client_id: A,
        jwks: {
          keys: [
            { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
            jwk("k2", { use: "enc" }),
            jwk("k2", { key_ops: ["sign"] }),
            jwk("k2", { alg: "ES256" }),
            { kty: "OKP", crv: "X25519", x: x.k2 },
            { kty: "OKP", crv: "Ed25519", x: x.k2 + "A" },
            "not a key",
            jwk("k3", { key_ops: ["verify"] }),
          ],
        },
      }),
    },
    expect: { keyHex: hex.k3, kid: thumb(x.k3) },
  },
  {
    name: "key set at jwks_uri",
    identity: A,
    responses: { [A]: ok({ client_id: A, jwks_uri: "https://keys.example.com/shopper/jwks.json?v=2" }), "https://keys.example.com/shopper/jwks.json?v=2": ok({ keys: [jwk("k1")] }) },
    expect: { keyHex: hex.k1, kid: thumb(x.k1) },
  },
  { name: "unknown members are ignored", identity: A, responses: { [A]: ok({ client_id: A, redirect_uris: ["https://agents.example.com/cb"], grant_types: ["authorization_code"], token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [jwk("k1")] } }) }, expect: { keyHex: hex.k1, kid: thumb(x.k1) } },

  { name: "client_id names another URL", identity: A, responses: { [A]: ok({ client_id: "https://agents.example.com/other", jwks: { keys: [jwk("k1")] } }) }, expect: { error: true } },
  { name: "client_id differs only by a trailing slash", identity: A, responses: { [A]: ok({ client_id: A + "/", jwks: { keys: [jwk("k1")] } }) }, expect: { error: true } },
  { name: "client_id missing", identity: A, responses: { [A]: ok({ jwks: { keys: [jwk("k1")] } }) }, expect: { error: true } },
  { name: "both jwks and jwks_uri", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [jwk("k1")] }, jwks_uri: "https://keys.example.com/jwks.json" }) }, expect: { error: true } },
  { name: "no keys published", identity: A, responses: { [A]: ok({ client_id: A }) }, expect: { error: true } },
  { name: "empty key set", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [] } }) }, expect: { error: true } },
  { name: "jwks is not an object with a keys array", identity: A, responses: { [A]: ok({ client_id: A, jwks: [jwk("k1")] }) }, expect: { error: true } },
  { name: "no Ed25519 signing key", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [jwk("k1", { use: "enc" })] } }) }, expect: { error: true } },
  { name: "private key material in the set", identity: A, responses: { [A]: ok({ client_id: A, jwks: { keys: [jwk("k2"), { ...jwk("k1"), d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A" }] } }) }, expect: { error: true } },
  { name: "client secret in the document", identity: A, responses: { [A]: ok({ client_id: A, client_secret: "s3cret", jwks: { keys: [jwk("k1")] } }) }, expect: { error: true } },
  { name: "document is a JSON array", identity: A, responses: { [A]: ok([{ client_id: A, jwks: { keys: [jwk("k1")] } }]) }, expect: { error: true } },
  { name: "document is not JSON", identity: A, responses: { [A]: { status: 200, headers: { "content-type": "text/html" }, bodyText: "<!doctype html><title>Shopper</title>" } }, expect: { error: true } },
  { name: "HTTP 404", identity: A, responses: { [A]: { status: 404, headers: {}, body: { error: "not_found" } } }, expect: { error: true } },
  { name: "HTTP 203 is not 200", identity: A, responses: { [A]: { status: 203, headers: {}, body: { client_id: A, jwks: { keys: [jwk("k1")] } } } }, expect: { error: true } },
  { name: "redirect is not followed", identity: A, responses: { [A]: { status: 302, headers: { location: "https://elsewhere.example.net/shopper" }, body: {} }, "https://elsewhere.example.net/shopper": ok({ client_id: A, jwks: { keys: [jwk("k1")] } }) }, expect: { error: true } },
  { name: "jwks_uri is not https", identity: A, responses: { [A]: ok({ client_id: A, jwks_uri: "http://keys.example.com/jwks.json" }) }, expect: { error: true } },
  { name: "jwks_uri names an IP literal", identity: A, responses: { [A]: ok({ client_id: A, jwks_uri: "https://169.254.169.254/jwks.json" }) }, expect: { error: true } },
  { name: "jwks_uri returns 404", identity: A, responses: { [A]: ok({ client_id: A, jwks_uri: "https://keys.example.com/jwks.json" }), "https://keys.example.com/jwks.json": { status: 404, headers: {}, body: {} } }, expect: { error: true } },
  { name: "jwks_uri redirects", identity: A, responses: { [A]: ok({ client_id: A, jwks_uri: "https://keys.example.com/jwks.json" }), "https://keys.example.com/jwks.json": { status: 301, headers: { location: "https://keys.example.com/v2/jwks.json" }, body: {} } }, expect: { error: true } },
];

const identifiers = [
  ["https://agents.example.com/shopper", true, "host and path"],
  ["https://example.com/agents/shopper.json", true, "nested path"],
  ["https://example.com/a/", true, "trailing slash"],
  ["https://example.com:8443/a", true, "non-default port"],
  ["https://xn--bcher-kva.example/agent", true, "A-label host"],
  ["https://example.com/~bot/%7Eid", true, "unreserved and percent-encoded characters"],
  ["https://example.com/a:b@c", true, "colon and at-sign in the path"],
  ["http://agents.example.com/shopper", false, "http"],
  ["https://example.com", false, "no path"],
  ["https://example.com/", false, "root path"],
  ["https://Example.com/a", false, "upper-case host"],
  ["https://example.com:443/a", false, "default port written out"],
  ["https://example.com:0/a", false, "port 0"],
  ["https://example.com:08443/a", false, "port with a leading zero"],
  ["https://example.com:65536/a", false, "port out of range"],
  ["https://user@example.com/a", false, "user information"],
  ["https://user:pw@example.com/a", false, "user information with password"],
  ["https://example.com/a?x=1", false, "query"],
  ["https://example.com/a?", false, "empty query"],
  ["https://example.com/a#frag", false, "fragment"],
  ["https://example.com/a#", false, "empty fragment"],
  ["https://example.com/a/../b", false, "double-dot segment"],
  ["https://example.com/a/./b", false, "single-dot segment"],
  ["https://example.com/a/%2e%2e/b", false, "percent-encoded double-dot segment"],
  ["https://example.com/a/.%2E/b", false, "half-encoded double-dot segment"],
  ["https://example.com//a", false, "empty segment"],
  ["https://example.com/a//b", false, "empty inner segment"],
  ["https://example.com/a b", false, "space"],
  ["https://example.com/a\\b", false, "backslash"],
  ["https://example.com/%zz", false, "malformed percent-encoding"],
  ["https://example.com/café", false, "non-ASCII path"],
  ["https://bücher.example/agent", false, "U-label host"],
  ["https://192.0.2.1/a", false, "IPv4 literal"],
  ["https://[2001:db8::1]/a", false, "IPv6 literal"],
  ["https://localhost/a", false, "localhost"],
  ["https://agents.localhost/a", false, "a name under localhost"],
  ["https://agents.corp.internal/a", true, "a private-use name is still a name; the address check decides"],
  ["https://intranet/a", false, "single-label host"],
  ["https://example.123/a", false, "numeric top-level label"],
  ["https://example.0x7f/a", false, "hexadecimal top-level label"],
  ["https://example.com./a", false, "trailing dot in host"],
  ["https://-example.com/a", false, "label starting with a hyphen"],
  ["https://exa_mple.com/a", false, "underscore in host"],
  ["HTTPS://example.com/a", false, "upper-case scheme"],
  [" https://example.com/a", false, "leading space"],
  ["https://example.com/a\n", false, "trailing newline"],
  ["did:aroha:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false, "a DID is not a web identity"],
  ["", false, "empty string"],
].map(([id, valid, note]) => ({ id, valid, note }));

const loopbackIdentifiers = [
  ["http://localhost:8787/agent", true, "localhost with a port"],
  ["http://127.0.0.1:8787/agent", true, "IPv4 loopback with a port"],
  ["http://localhost/agent", true, "localhost on the default port"],
  ["http://localhost:80/agent", false, "default port written out"],
  ["https://localhost:8787/agent", false, "loopback over https"],
  ["http://agents.example.com/shopper", false, "http to a public host"],
  ["http://127.0.0.2:8787/agent", false, "another loopback address"],
  ["https://agents.example.com/shopper", true, "an ordinary identity is still accepted"],
].map(([id, valid, note]) => ({ id, valid, note }));

const addresses = [
  ["93.184.215.14", false, "public IPv4"],
  ["8.8.8.8", false, "public IPv4"],
  ["100.63.255.255", false, "just below the shared address space"],
  ["100.128.0.0", false, "just above the shared address space"],
  ["172.15.255.255", false, "just below 172.16/12"],
  ["172.32.0.0", false, "just above 172.16/12"],
  ["192.0.1.1", false, "between the 192.0.0/24 and 192.0.2/24 blocks"],
  ["198.20.0.1", false, "just above the benchmarking block"],
  ["223.255.255.255", false, "last unicast IPv4 address"],
  ["2606:4700:4700::1111", false, "public IPv6"],
  ["2001:4860:4860::8888", false, "public IPv6 above 2001::/23"],
  ["2001:200::1", false, "first address above 2001::/23"],
  ["::ffff:8.8.8.8", false, "IPv4-mapped public address"],
  ["64:ff9b::808:808", false, "NAT64 form of a public address"],
  ["0.0.0.0", true, "unspecified"],
  ["0.1.2.3", true, "this network"],
  ["10.0.0.5", true, "private"],
  ["100.64.0.1", true, "shared address space"],
  ["100.127.255.255", true, "end of the shared address space"],
  ["127.0.0.1", true, "loopback"],
  ["127.255.255.254", true, "loopback"],
  ["169.254.169.254", true, "link-local (cloud metadata)"],
  ["172.16.0.1", true, "private"],
  ["172.31.255.255", true, "private"],
  ["192.0.0.8", true, "IETF protocol assignments"],
  ["192.0.2.1", true, "documentation"],
  ["192.88.99.1", true, "deprecated 6to4 relay"],
  ["192.168.1.1", true, "private"],
  ["198.18.0.1", true, "benchmarking"],
  ["198.19.255.255", true, "benchmarking"],
  ["198.51.100.7", true, "documentation"],
  ["203.0.113.9", true, "documentation"],
  ["224.0.0.1", true, "multicast"],
  ["240.0.0.1", true, "reserved"],
  ["255.255.255.255", true, "broadcast"],
  ["::", true, "unspecified"],
  ["::1", true, "loopback"],
  ["0:0:0:0:0:0:0:1", true, "loopback, written out"],
  ["::10.0.0.5", true, "deprecated IPv4-compatible form"],
  ["::ffff:10.0.0.5", true, "IPv4-mapped private address"],
  ["::ffff:a00:5", true, "IPv4-mapped private address in hexadecimal"],
  ["::ffff:169.254.169.254", true, "IPv4-mapped link-local address"],
  ["::FFFF:127.0.0.1", true, "IPv4-mapped loopback, upper case"],
  ["64:ff9b::a00:5", true, "NAT64 form of a private address"],
  ["64:ff9b:1::1", true, "local-use NAT64"],
  ["100::1", true, "discard-only"],
  ["2001::1", true, "Teredo"],
  ["2001:db8::1", true, "documentation"],
  ["2002:a00:5::1", true, "6to4"],
  ["fc00::1", true, "unique local"],
  ["fd12:3456:789a::1", true, "unique local"],
  ["fe80::1", true, "link-local"],
  ["fe80::1%eth0", true, "link-local with a zone"],
  ["febf::1", true, "end of link-local"],
  ["ff02::1", true, "multicast"],
  ["", true, "empty string"],
  ["example.com", true, "a name, not an address"],
  ["10.0.0", true, "too few octets"],
  ["256.1.1.1", true, "octet out of range"],
  ["08.8.8.8", true, "octet with a leading zero"],
  ["1:2:3:4:5:6:7:8:9", true, "too many groups"],
  ["1::2::3", true, "two compressions"],
  ["12345::1", true, "group too long"],
].map(([address, specialUse, note]) => ({ address, specialUse, note }));

const vectors = {
  description:
    "Web identity conformance vectors (spec section 4.7). `identifiers` are accepted or refused as web identities with default options; `loopbackIdentifiers` with the development-only loopback option. `addresses` are judged special-use (never fetched) or not; text that is not an address counts as special-use. `thumbprints` pin the RFC 7638 key id. Each entry of `documents` lists the HTTP responses a resolver receives (any URL not listed answers 404; `body` is JSON, `bodyText` is sent as is) and either the key it must return or that it must fail. Keys are the public RFC 8032 section 7.1 test keys.",
  version: 1,
  identifiers,
  loopbackIdentifiers,
  addresses,
  thumbprints: (Object.keys(hex) as (keyof typeof hex)[]).map((k) => ({ publicKeyHex: hex[k], x: x[k], thumbprint: thumb(x[k]) })),
  documents,
};
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
console.log("identifiers", identifiers.length, "loopback", loopbackIdentifiers.length, "documents", documents.length);
console.log("k1 x", x.k1, "thumb", thumb(x.k1));
